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

// How old a fixture has to be before it is treated as abandoned. The same six
// hours the product uses for its own copies, and for the same reason: long
// enough that a suite running in another window is never swept out from under
// itself.
const ABANDONED_AFTER = 6 * 60 * 60 * 1000;

/**
 * Drops fixtures an earlier run could not clean up after itself.
 *
 * A check tidies up in a `finally`, and that covers every ordinary failure. It
 * does not cover the process being killed - a mutation run timing out, a
 * dropped connection, somebody pressing ctrl-c - and then the small app it
 * built stays in the database. One turned up four hours after the run that
 * made it, found by the very check that watches for this.
 *
 * The name carries the moment it was made, so its age can be read without
 * asking Postgres, which does not record when a schema was created.
 */
async function sweepOldFixtures(client) {
  let rows = [];
  try {
    ({ rows } = await client.query(
      "SELECT nspname FROM pg_namespace WHERE nspname ~ '^kn_[a-z]+_' ORDER BY 1",
    ));
  } catch (err) {
    return [];
  }

  const dropped = [];
  for (const row of rows) {
    const stamp = /_([0-9a-z]+)$/.exec(row.nspname);
    if (!stamp) continue;
    const made = parseInt(stamp[1], 36);
    if (!Number.isFinite(made) || Date.now() - made < ABANDONED_AFTER) continue;
    try {
      await client.query('DROP SCHEMA IF EXISTS "' + String(row.nspname).split('"').join('""') + '" CASCADE');
      dropped.push(row.nspname);
    } catch (err) {
      // Somebody else's to deal with. Better than failing a run over tidiness.
    }
  }
  return dropped;
}

/**
 * Makes sure `auth.uid()` exists, and hands back a way to undo only what was
 * created here.
 *
 * Every database-backed check calls this before it builds anything, so it is
 * also where the stale fixtures of killed runs get cleared away.
 */
async function ensureAuth(client) {
  await sweepOldFixtures(client);

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

module.exports = {
  ensureAuth: ensureAuth,
  ensureRoles: ensureRoles,
  sweepOldFixtures: sweepOldFixtures,
  ABANDONED_AFTER: ABANDONED_AFTER,
};
