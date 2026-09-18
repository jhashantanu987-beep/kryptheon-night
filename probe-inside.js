// Could the night shift live inside the customer's own database?
//
// Run with:  node probe-inside.js "<connection string>"
//
// The idea: instead of holding somebody's password and connecting from
// outside, ship them one SQL script. The robot lives in their database, runs
// on a schedule there, and posts only the verdict out. Nobody's credential
// ever moves, the laptop can be off, and uninstalling is one line.
//
// That only works if a plain SQL function can do everything the Node code
// does. Six questions, and any single no changes the plan:
//
//   1. Can a function create and drop a schema?
//   2. Can it become `anon` mid-transaction and read as that role?
//   3. Can it put the caller's identity where PostgREST puts it?
//   4. Can it catch its own failures instead of aborting the whole run?
//   5. Can a scheduler (pg_cron) be installed here at all?
//   6. Can the database make an outbound HTTP request (pg_net / http)?
//
// 1 to 4 are plain Postgres and the answers carry to any host. 5 and 6 are the
// platform's choice, so they are measured per host and mean nothing anywhere
// else.

const { Client } = require('pg');

const CONN = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_inside_' + Date.now().toString(36);

let asked = 0;
function record(question, answer, detail) {
  asked += 1;
  console.log('');
  console.log('  ' + question);
  console.log('    -> ' + answer);
  if (detail) console.log('       ' + detail);
}

async function attempt(client, statement) {
  try {
    const r = await client.query(statement);
    return { ok: true, rows: r.rows };
  } catch (err) {
    return { ok: false, why: err.message.split('\n')[0] };
  }
}

(async () => {
  if (!CONN) {
    console.error('\n  node probe-inside.js "<connection string>"\n');
    process.exit(2);
  }
  const c = new Client({ connectionString: CONN });
  await c.connect();
  const q = (t) => '"' + APP + '"."' + t + '"';

  try {
    /* ---------------- what the host will even let us install ------------- */

    const { rows: available } = await c.query(
      `SELECT name, default_version, installed_version
         FROM pg_available_extensions
        WHERE name IN ('pg_cron', 'pg_net', 'http', 'pgsql-http', 'pg_background')
        ORDER BY name`,
    );
    record(
      '5/6. what scheduling and outbound-HTTP extensions does this host offer?',
      available.length ? available.map((r) => r.name + (r.installed_version ? ' (installed)' : '')).join(', ') : 'none of them',
      'pg_cron schedules the nightly run; pg_net or http is how the verdict gets out',
    );

    for (const name of ['pg_cron', 'pg_net', 'http']) {
      if (!available.some((r) => r.name === name)) continue;
      const made = await attempt(c, 'CREATE EXTENSION IF NOT EXISTS ' + name);
      record('   can this connection actually install ' + name + '?', made.ok ? 'yes' : 'no - ' + made.why);
    }

    /* -------------------- what plain SQL can do anywhere ------------------ */

    await c.query('CREATE SCHEMA "' + APP + '"');
    for (const role of ['anon', 'authenticated']) {
      await c.query(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role +
          "') THEN CREATE ROLE " + role + ' NOLOGIN; END IF; END $$;',
      );
      await c.query('GRANT ' + role + ' TO current_user');
      await c.query('GRANT USAGE ON SCHEMA "' + APP + '" TO ' + role);
    }
    await c.query('CREATE TABLE ' + q('customers') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)');
    await c.query('GRANT SELECT ON ' + q('customers') + ' TO anon, authenticated');
    await c.query("INSERT INTO " + q('customers') + " (owner, email) VALUES ('11111111-1111-4111-8111-111111111111', 'a@b.c')");
    await c.query('ALTER TABLE ' + q('customers') + ' ENABLE ROW LEVEL SECURITY');
    await c.query('CREATE POLICY wide_open ON ' + q('customers') + ' FOR SELECT TO anon, authenticated USING (true)');

    // 1. a function that builds and drops a schema of its own
    const builder = await attempt(c,
      'CREATE OR REPLACE FUNCTION ' + q('build_and_drop') + '() RETURNS text LANGUAGE plpgsql AS $fn$ ' +
      'BEGIN ' +
      '  EXECUTE ' + "'CREATE SCHEMA " + APP + '_copy' + "'; " +
      '  EXECUTE ' + "'CREATE TABLE " + APP + '_copy.t (id int)' + "'; " +
      '  EXECUTE ' + "'DROP SCHEMA " + APP + '_copy CASCADE' + "'; " +
      "  RETURN 'built and dropped'; " +
      'END $fn$');
    let built = { ok: false, why: 'not created' };
    if (builder.ok) built = await attempt(c, 'SELECT ' + q('build_and_drop') + '() AS r');
    record(
      '1. can a function build a copy and throw it away?',
      built.ok ? 'YES - ' + built.rows[0].r : 'no - ' + built.why,
      'this is how the copy would be made with nobody connecting from outside',
    );

    // 2 + 3. a function that becomes anon, sets the claims, and reads
    const reader = await attempt(c,
      'CREATE OR REPLACE FUNCTION ' + q('read_as_anon') + '() RETURNS integer LANGUAGE plpgsql AS $fn$ ' +
      'DECLARE n integer; ' +
      'BEGIN ' +
      "  SET LOCAL ROLE anon; " +
      "  PERFORM set_config('request.jwt.claims', '{\"role\":\"anon\"}', true); " +
      '  SELECT count(*) INTO n FROM ' + q('customers') + '; ' +
      "  RESET ROLE; " +
      '  RETURN n; ' +
      'END $fn$');
    let asAnon = { ok: false, why: 'not created' };
    if (reader.ok) asAnon = await attempt(c, 'SELECT ' + q('read_as_anon') + '() AS n');
    record(
      '2/3. can a function become anon and read the way a request does?',
      asAnon.ok ? 'YES - it read ' + asAnon.rows[0].n + ' row(s) as anon' : 'no - ' + asAnon.why,
      'without this the attack cannot run inside the database at all',
    );

    // and the same against a table that should refuse
    await c.query('CREATE TABLE ' + q('locked') + ' (id serial PRIMARY KEY, owner uuid NOT NULL)');
    await c.query('GRANT SELECT ON ' + q('locked') + ' TO anon, authenticated');
    await c.query("INSERT INTO " + q('locked') + " (owner) VALUES ('11111111-1111-4111-8111-111111111111')");
    await c.query('ALTER TABLE ' + q('locked') + ' ENABLE ROW LEVEL SECURITY');
    await c.query('CREATE POLICY own ON ' + q('locked') + ' FOR SELECT TO authenticated USING (owner = auth_uid_stub())')
      .catch(async () => {
        await c.query('CREATE POLICY own ON ' + q('locked') + " FOR SELECT TO authenticated USING (owner::text = current_setting('request.jwt.claims', true)::json->>'sub')");
      });
    const locked = await attempt(c,
      'CREATE OR REPLACE FUNCTION ' + q('read_locked') + '() RETURNS integer LANGUAGE plpgsql AS $fn$ ' +
      'DECLARE n integer; ' +
      'BEGIN ' +
      '  SET LOCAL ROLE authenticated; ' +
      '  PERFORM set_config(' + "'request.jwt.claims'" + ', ' + "'{\"sub\":\"22222222-2222-4222-8222-222222222222\"}'" + ', true); ' +
      '  SELECT count(*) INTO n FROM ' + q('locked') + '; ' +
      '  RESET ROLE; ' +
      '  RETURN n; ' +
      'END $fn$');
    let lockedOut = { ok: false, why: 'not created' };
    if (locked.ok) lockedOut = await attempt(c, 'SELECT ' + q('read_locked') + '() AS n');
    record(
      '   and does a correct rule still refuse it from inside?',
      lockedOut.ok
        ? (lockedOut.rows[0].n === 0 ? 'YES - 0 rows, the rule held' : 'NO - it read ' + lockedOut.rows[0].n + ' rows it should not')
        : 'could not tell - ' + lockedOut.why,
      'the verdicts have to come out the same as they do from outside',
    );

    // 4. can it survive its own failures
    const catcher = await attempt(c,
      'CREATE OR REPLACE FUNCTION ' + q('survives') + '() RETURNS text LANGUAGE plpgsql AS $fn$ ' +
      'BEGIN ' +
      '  BEGIN ' +
      "    EXECUTE 'SELECT 1/0'; " +
      '  EXCEPTION WHEN OTHERS THEN ' +
      "    RETURN 'caught: ' || SQLERRM; " +
      '  END; ' +
      "  RETURN 'nothing went wrong'; " +
      'END $fn$');
    let survived = { ok: false, why: 'not created' };
    if (catcher.ok) survived = await attempt(c, 'SELECT ' + q('survives') + '() AS r');
    record(
      '4. can it catch its own failures instead of losing the whole run?',
      survived.ok ? 'YES - ' + survived.rows[0].r : 'no - ' + survived.why,
      'a table that cannot be seeded must not take the night down with it',
    );

    console.log('');
    console.log('  ' + '-'.repeat(68));
    console.log('  ' + asked + ' questions answered, against ' + (CONN.includes('neon.tech') ? 'Neon' : 'this host') + '.');
    console.log('  1 to 4 are plain Postgres and carry anywhere. 5 and 6 are this host only.');
    console.log('');
  } finally {
    await c.query('DROP SCHEMA IF EXISTS "' + APP + '" CASCADE').catch(() => {});
    await c.query('DROP SCHEMA IF EXISTS "' + APP + '_copy" CASCADE').catch(() => {});
    await c.end();
  }
})().catch((e) => {
  console.error('\n  the probe could not run: ' + (e.message || e));
  process.exit(1);
});
