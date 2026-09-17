// The groundwork every check needs, and the rule that it may only undo what
// it did itself.
//
// The checks build small apps in a real database to attack, and a real
// database is whatever connection string somebody put in KN_DATABASE_URL.
// That will sometimes be a database with things in it.
//
// The first version of all of this ran `CREATE SCHEMA IF NOT EXISTS auth`,
// `CREATE OR REPLACE FUNCTION auth.uid()`, and then `DROP SCHEMA auth CASCADE`
// on the way out - unconditionally. Pointed at a Supabase project that would
// have replaced the customer's own authentication function and then deleted
// their entire auth schema. It was caught by running the checks against a
// database that already had an auth schema and noticing it was gone
// afterwards. The schema happened to be empty. It did not have to be.
//
// So: look first, create only what is missing, and undo exactly that much.

/**
 * Makes sure `auth.uid()` exists, and hands back a way to undo only what was
 * created here.
 */
async function ensureAuth(client) {
  const { rows: schemaRows } = await client.query("SELECT 1 FROM pg_namespace WHERE nspname = 'auth'");
  const madeSchema = schemaRows.length === 0;
  if (madeSchema) await client.query('CREATE SCHEMA auth');

  const { rows: functionRows } = await client.query(
    `SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'auth' AND p.proname = 'uid'`,
  );
  const madeFunction = functionRows.length === 0;
  if (madeFunction) {
    // Written the way Supabase writes it, and only when there is nothing
    // there. Replacing somebody's own auth.uid() is the exact mistake this
    // module exists to stop.
    await client.query(
      'CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ ' +
        "SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid $$",
    );
  }

  await client.query('GRANT USAGE ON SCHEMA auth TO anon, authenticated').catch(() => {});

  return async function undo() {
    if (madeFunction && !madeSchema) {
      await client.query('DROP FUNCTION IF EXISTS auth.uid()').catch(() => {});
    }
    if (madeSchema) {
      await client.query('DROP SCHEMA IF EXISTS auth CASCADE').catch(() => {});
    }
  };
}

/** The two roles PostgREST switches into, created only if they are missing. */
async function ensureRoles(client, schemaName, quote) {
  for (const role of ['anon', 'authenticated']) {
    await client.query(
      'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ' + "'" + role + "'" +
        ') THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    if (schemaName) await client.query('GRANT USAGE ON SCHEMA ' + quote(schemaName) + ' TO ' + role);
  }
}

module.exports = { ensureAuth: ensureAuth, ensureRoles: ensureRoles };
