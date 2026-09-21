// Checks the one promise the whole product is sold on.
// Run with:  node untouched.check.js "<postgres connection string>"
//
//   "We never touch your live app."
//
// Every other check asks whether a verdict is right. This one asks whether we
// had the right to produce it at all. A scanner that reports perfectly and
// quietly alters the database it was pointed at is not a product, it is an
// incident - and the person who bought it finds out from their users.
//
// So: a realistic app is built, with rows in it. Everything outside the
// throwaway copy is photographed - functions, privileges, tables, columns,
// policies, row level security flags, roles, sequences, and the row contents
// themselves. The real scan runs. Everything is photographed again. Any
// difference at all is a failure, and the difference is printed.
//
// The copy schema is always named kn_<something>, so anything matching that is
// excluded from both photographs - and then the absence of any kn_ schema
// afterwards is itself checked, because a copy left behind is also a change.
//
// This check found two things the day it was written:
//   - the copy builder ran CREATE OR REPLACE FUNCTION auth.uid(), overwriting
//     the customer's own authentication function
//   - it ran GRANT USAGE ON SCHEMA auth TO anon, opening a schema the customer
//     had deliberately closed

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_untouched_app_' + Date.now().toString(36);
// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};

// The copy is always kn_<generated>. The app here is deliberately named with
// the same prefix so it is excluded too - what is being watched is the rest of
// the database, plus the app's own rows, which are counted separately.
const MINE = /^kn_/;

/** Everything outside the copy that must come through the night unchanged. */
const PHOTOGRAPHS = {
  functions: `SELECT n.nspname AS schema, p.proname AS name,
                     md5(pg_get_functiondef(p.oid)) AS body
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
               WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                 AND p.prokind = 'f'
               ORDER BY 1, 2, 3`,
  schemaPrivileges: `SELECT nspname AS schema,
                            has_schema_privilege('anon', nspname, 'USAGE') AS anon_usage,
                            has_schema_privilege('authenticated', nspname, 'USAGE') AS auth_usage,
                            has_schema_privilege('anon', nspname, 'CREATE') AS anon_create
                       FROM pg_namespace
                      WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
                      ORDER BY 1`,
  columns: `SELECT table_schema AS schema, table_name AS name, column_name AS col, data_type AS type
              FROM information_schema.columns
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
             ORDER BY 1, 2, 3`,
  tablePrivileges: `SELECT table_schema AS schema, table_name AS name, grantee, privilege_type AS priv
                      FROM information_schema.role_table_grants
                     WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                     ORDER BY 1, 2, 3, 4`,
  policies: `SELECT schemaname AS schema, tablename AS name, policyname AS policy,
                    permissive, cmd, qual, with_check
               FROM pg_policies
              ORDER BY 1, 2, 3`,
  rowSecurity: `SELECT n.nspname AS schema, c.relname AS name,
                       c.relrowsecurity AS on, c.relforcerowsecurity AS forced
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                 ORDER BY 1, 2`,
  roles: "SELECT rolname AS name, rolsuper AS super, rolcanlogin AS login FROM pg_roles ORDER BY 1",
  // Where each sequence stands, not only that it exists.
  //
  // This photographed `sequence_schema, sequence_name` and nothing else, so a
  // scan could call nextval() on the customer's own sequence all night and
  // this check would compare two identical lists of names and pass. It did:
  // a real Supabase project came out of four scans with zero rows in its
  // tables and its sequences at 25, 25 and 14.
  //
  // A photograph of the wrong thing is worse than none, because it is the
  // reason nobody looks again.
  sequences: `SELECT schemaname AS schema, sequencename AS name, last_value
                FROM pg_sequences ORDER BY 1, 2`,
};

/** One photograph of the whole database, with our own schemas left out. */
async function photograph(client) {
  const shot = {};
  for (const [what, sql] of Object.entries(PHOTOGRAPHS)) {
    const { rows } = await client.query(sql);
    shot[what] = rows
      .filter((row) => !MINE.test(String(row.schema || '')))
      .map((row) => JSON.stringify(row));
  }
  return shot;
}

/** Where two photographs differ, in words. */
function differences(before, after) {
  const found = [];
  for (const what of Object.keys(before)) {
    const was = new Set(before[what]);
    const now = new Set(after[what]);
    for (const row of after[what]) if (!was.has(row)) found.push(what + ' APPEARED: ' + row);
    for (const row of before[what]) if (!now.has(row)) found.push(what + ' VANISHED: ' + row);
  }
  return found;
}

/** A Supabase-shaped app with real rows in it and its own auth.uid(). */
async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));

  // The app goes on the search_path, because every real one is.
  //
  // This is the other half of why the promise went unchecked. With the app
  // unreachable by a bare name, Postgres wrote every schema name out, every
  // copied expression pointed where it was meant to, and this check had
  // nothing to find. A real app lives in `public`: its foreign keys came back
  // bare and bound to the customer's tables, and its serial defaults came back
  // as nextval('orders_id_seq') and drew from the customer's sequences.
  //
  // The promise is about real databases, so it is checked against the shape a
  // real database has.
  await client.query('SET search_path TO ' + schema.quote(APP) + ', public');

  for (const role of ['anon', 'authenticated']) {
    await client.query(
      'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ' + "'" + role + "'" +
        ') THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO ' + role);
  }

  // An auth.uid() to compare against afterwards. Created only if the database
  // does not already have one: this check exists to prove nothing outside the
  // copy is altered, and building it by overwriting somebody's authentication
  // function would be the very thing it is meant to catch.
  //
  // Either way the photograph holds the definition's hash, so a replacement
  // shows up whether the function came from here or was already there.
  undoAuth = await fixture.ensureAuth(client);

  await client.query('CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY, email text NOT NULL)');
  await client.query(
    'CREATE TABLE ' + q('customers') +
      ' (id serial PRIMARY KEY, owner uuid NOT NULL, name text NOT NULL, email text NOT NULL)',
  );
  await client.query('CREATE TABLE ' + q('integrations') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, api_key text NOT NULL)');
  for (const t of ['profiles', 'customers', 'integrations']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
  }
  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY own ON ' + q('profiles') + ' FOR SELECT TO authenticated USING (id = auth.uid())');
  await client.query('ALTER TABLE ' + q('customers') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY readable ON ' + q('customers') + ' FOR SELECT TO anon, authenticated USING (true)');

  // Real rows, standing in for real customers. Not one of them may be read,
  // changed, or added to.
  await client.query(
    'INSERT INTO ' + q('profiles') + " VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'real.person@example.com')",
  );
  await client.query(
    'INSERT INTO ' + q('customers') +
      " (owner, name, email) VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'A Real Customer', 'real.customer@example.com')",
  );
  await client.query(
    'INSERT INTO ' + q('integrations') +
      " (owner, api_key) VALUES ('aaaaaaaa-0000-4000-8000-000000000001', 'sk_live_do_not_touch')",
  );
}

/** Every schema that looks like one of ours, so new ones can be spotted. */
async function copySchemas(client) {
  const { rows } = await client.query(
    "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'kn\\_%' AND nspname <> $1 ORDER BY 1",
    [APP],
  );
  return rows.map((row) => row.nspname);
}

/** What is actually in the app's tables, exactly. */
async function contents(client) {
  const out = [];
  for (const table of ['profiles', 'customers', 'integrations']) {
    const { rows } = await client.query(
      'SELECT * FROM ' + schema.quote(APP) + '.' + schema.quote(table) + ' ORDER BY 1',
    );
    out.push(table + ' = ' + JSON.stringify(rows));
  }

  // And where the app's own sequences stand.
  //
  // The photograph cannot see these: the app is named kn_... on purpose, so
  // that it is excluded alongside the copy, and everything of the app's that
  // must be watched has to be watched here instead. Its rows were. Its
  // sequences were not - and that is precisely where the scan was touching a
  // real database, by calling nextval() on the customer's own sequence
  // through a serial default the copy had borrowed.
  //
  // Measured on a real Supabase project: zero rows in every table, sequences
  // at 25, 25 and 14. Nothing this check looked at had moved.
  const { rows: seqs } = await client.query(
    `SELECT sequencename AS name, last_value
       FROM pg_sequences WHERE schemaname = $1 ORDER BY 1`,
    [APP],
  );
  out.push('sequences = ' + JSON.stringify(seqs));
  return out;
}

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node untouched.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  try {
    await buildApp(client);

    const before = await photograph(client);
    const rowsBefore = await contents(client);
    // Compared as a set rather than checked for emptiness: what matters is
    // that the scan leaves nothing NEW behind, whatever was already there.
    const copiesBefore = await copySchemas(client);

    // A scan that throws is this check failing, not this check being unable to
    // run. Left to reach the top-level catch it printed "The check could not
    // run: ..." with no FAIL line anywhere - which reads as a broken harness
    // rather than as a broken product, and which the suite runner treats as a
    // dropped connection and retries three times.
    //
    // It matters most here: the guard that refuses a copy pointing outside
    // itself raises, so the one failure this file exists to catch was the one
    // it reported least clearly.
    let result = { stopped: null, findings: [] };
    let threw = null;
    try {
      result = await scan(client, APP, {
        quiet: true,
        openSession: async () => {
          const extra = new Client({ connectionString: CONNECTION });
          await extra.connect();
          return extra;
        },
      });
    } catch (err) {
      threw = err.message;
    }

    const after = await photograph(client);
    const rowsAfter = await contents(client);

    check('1. the scan actually ran, so the rest of this means something', (() => {
      // A scan that fell over changes nothing either, and would pass every
      // check below for the wrong reason.
      const problems = [];
      if (threw) problems.push('it threw: ' + String(threw).split('\n')[0]);
      if (result.stopped) problems.push('it stopped: ' + String(result.stopped).split('\n')[0]);
      if (!threw && !result.stopped && !result.findings.length) {
        problems.push('it found nothing in an app with a hole in it');
      }
      return problems;
    })());

    check('2. nothing outside the copy changed', (() => {
      const found = differences(before, after);
      return found.length ? found : [];
    })());

check("3. the auth.uid() that was there before is still there afterwards", (() => {
      // Named separately from check 2 even though the photograph would catch
      // it anyway, because this is the one that matters: replacing it breaks
      // a live application, not just a promise.
      const problems = [];
      const was = before.functions.find((row) => /"schema":"auth","name":"uid"/.test(row));
      const now = after.functions.find((row) => /"schema":"auth","name":"uid"/.test(row));
      if (!was) return ['there was no auth.uid() to protect'];
      if (!now) problems.push('auth.uid() is gone entirely');
      else if (was !== now) problems.push('auth.uid() was replaced with a different function');
      return problems;
    })());

    check('4. not one real row was added, changed or removed', (() => {
      const problems = [];
      for (let i = 0; i < rowsBefore.length; i++) {
        if (rowsBefore[i] !== rowsAfter[i]) {
          problems.push('before: ' + rowsBefore[i]);
          problems.push('after:  ' + rowsAfter[i]);
        }
      }
      return problems;
    })());

    const copiesAfter = await copySchemas(client);
    check('5. the copy was deleted, so nothing of it is left behind', (() => {
      const was = new Set(copiesBefore);
      const left = copiesAfter.filter((name) => !was.has(name));
      return left.length ? ['the scan left behind: ' + left.join(', ')] : [];
    })());
  } finally {
    try {
      await client.query('SET search_path TO "$user", public').catch(() => {});
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE');
    } catch (err) {
      console.error('  WARNING: cleanup failed: ' + err.message);
    }
    await client.end();
  }

  console.log('');
  let failures = 0;
  for (const result of results) {
    if (result.problems.length) {
      failures++;
      console.log('FAIL  ' + result.name);
      result.problems.forEach((p) => console.log('      - ' + p));
    } else {
      console.log('PASS  ' + result.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exitCode = 1;
  } else {
    console.log('All ' + results.length + ' promise checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
