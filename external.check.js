// Checks that an app pointing at auth.users can still be scanned.
// Run with:  node external.check.js "<postgres connection string>"
//
// Nearly every Supabase app begins the same way:
//
//   create table profiles (
//     id uuid primary key references auth.users(id),
//     ...
//   )
//
// The copy cannot carry that foreign key as written. Pointed at the real
// auth.users it would make every seeded row a write into the customer's own
// authentication table, which is the one thing this tool may never do. So the
// scan used to stop, and stopping means the product does not work on the
// apps it was built for.
//
// Instead the copy gets its own stand-in for the table it points at: the same
// columns, the same types, nothing else, and two rows in it that this tool put
// there. The foreign key is real, the seeding works, and nothing outside the
// copy is read for anything but its shape.
//
// The stand-in is ours, not theirs, so it must never be attacked and never
// appear in a report.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};
// And the auth.users table, on the same terms.
let madeAuthUsers = false;
const APP = 'kn_external_' + Date.now().toString(36);

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/** A Supabase app as it actually comes out of the box. */
async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  for (const role of ['anon', 'authenticated']) {
    await client.query(
      'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ' + "'" + role + "'" +
        ') THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO ' + role);
  }
  undoAuth = await fixture.ensureAuth(client);

  // The customer own authentication table, with a real person in it.
  //
  // Created only if it is not already there, and remembered so the cleanup
  // can take away exactly what it added. Leaving an auth.users behind in
  // somebody else auth schema would be this check doing the very thing it
  // exists to prove the product never does.
  const { rows: already } = await client.query(
    "SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
      "WHERE n.nspname = 'auth' AND c.relname = 'users'",
  );
  madeAuthUsers = already.length === 0;
  if (madeAuthUsers) {
    await client.query('CREATE TABLE auth.users (id uuid PRIMARY KEY, email text)');
    await client.query(
      "INSERT INTO auth.users VALUES ('dddddddd-0000-4000-8000-00000000000d', 'real.person@example.com')",
    );
  }

  await client.query(
    'CREATE TABLE ' + q('profiles') +
      ' (id uuid PRIMARY KEY REFERENCES auth.users(id), display_name text NOT NULL)',
  );
  await client.query(
    'CREATE TABLE ' + q('notes') +
      ' (id serial PRIMARY KEY, user_id uuid NOT NULL REFERENCES auth.users(id), body text NOT NULL)',
  );
  for (const t of ['profiles', 'notes']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
  }
  // notes is left wide open: this is the finding the scan must still reach.
  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY own ON ' + q('profiles') + ' FOR SELECT TO authenticated USING (id = auth.uid())');
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node external.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  try {
    await buildApp(client);

    const authBefore = (await client.query('SELECT * FROM auth.users ORDER BY id')).rows;

    const result = await scan(client, APP, {
      quiet: true,
      openSession: async () => {
        const extra = new Client({ connectionString: CONNECTION });
        await extra.connect();
        return extra;
      },
    });

    const authAfter = (await client.query('SELECT * FROM auth.users ORDER BY id')).rows;

    check('1. an app that points at auth.users is scanned, not refused', (() => {
      const problems = [];
      if (result.stopped) problems.push('it stopped: ' + String(result.stopped).replace(/\n\s*/g, ' '));
      return problems;
    })());

    check('2. the tables behind that foreign key were really attacked', (() => {
      const problems = [];
      if (result.stopped) return ['the scan never got that far'];
      const missed = (result.notChecked || []).map((m) => m.table);
      for (const table of ['profiles', 'notes']) {
        if (missed.includes(table)) problems.push(table + ' could not be seeded: ' + JSON.stringify(result.notChecked));
        if (!(result.attempted || []).some((key) => key.endsWith(':' + table))) {
          problems.push(table + ' was never attacked: ' + JSON.stringify(result.attempted));
        }
      }
      return problems;
    })());

    check('3. the hole behind the foreign key is still found', (() => {
      const problems = [];
      if (result.stopped) return ['the scan never got that far'];
      const found = result.findings.map((f) => f.table);
      if (!found.includes('notes')) {
        problems.push('a table anyone can read was missed: ' + JSON.stringify(found));
      }
      return problems;
    })());

    check("4. the customer's auth.users was not written to", (() => {
      const problems = [];
      if (JSON.stringify(authBefore) !== JSON.stringify(authAfter)) {
        problems.push('before: ' + JSON.stringify(authBefore));
        problems.push('after:  ' + JSON.stringify(authAfter));
      }
      return problems;
    })());

    check('5. the stand-in table is never reported as the customer\'s own', (() => {
      // It is a table this tool created. Putting it in a report would send
      // somebody looking for a table that does not exist in their app.
      const problems = [];
      for (const item of result.findings || []) {
        if (/^kn_ext/.test(item.table)) problems.push('it reported its own stand-in table: ' + item.table);
      }
      for (const missed of result.notChecked || []) {
        if (/^kn_ext/.test(missed.table)) problems.push('it warned about its own stand-in table: ' + missed.table);
      }
      for (const key of result.attempted || []) {
        if (/kn_ext/.test(key)) problems.push('it counted an attack on its own stand-in table: ' + key);
      }
      return problems;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    if (madeAuthUsers) await client.query('DROP TABLE IF EXISTS auth.users CASCADE').catch(() => {});
    await undoAuth();
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
    console.log('All ' + results.length + ' external-reference checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
