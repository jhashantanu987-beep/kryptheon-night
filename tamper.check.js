// Checks that "a stranger can change your data" is only said when it is true,
// and that saying it costs the data nothing.
// Run with:  node tamper.check.js "<postgres connection string>"
//
// This attack is different from the others in one way that matters: it writes.
// Everything it does is rolled back, and the first case below is not about
// findings at all - it is about proving the tables came out exactly as they
// went in. An attack that leaves a row behind, or removes one, is not an
// attack anybody can be sold.
//
// After that it is the usual shape: mostly about NOT reporting. A SELECT
// policy and nothing else genuinely denies writes, and an app built that way
// must come back clean - telling somebody their table is writable when it is
// not sends them to rewrite rules that were already right.
//
// The apps here are the four that matter, all measured in probe-write.js
// before any of this was written:
//
//   no_rls            nobody switched it on, and the default grants stand
//   read_only_policy  a SELECT rule and nothing else
//   all_true          FOR ALL USING (true) - looks like a rule, stops nothing
//   own_rows          done properly
//   add_only          anyone may insert, nothing else

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');
const tamper = require('./tamper.js');
const finding = require('./finding.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};
const APP = 'kn_tamper_' + Date.now().toString(36);

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

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

  const shape = ' (id serial PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)';
  for (const name of ['no_rls', 'read_only_policy', 'all_true', 'own_rows', 'add_only', 'parent']) {
    await client.query('CREATE TABLE ' + q(name) + shape);
  }

  // A child holding the parent down. Deleting a parent row fails on the
  // foreign key - which is the data model refusing, not the app defending
  // itself, and the difference is the whole point of telling them apart.
  await client.query('CREATE TABLE ' + q('child') +
    ' (id serial PRIMARY KEY, owner uuid NOT NULL, parent_id int NOT NULL REFERENCES ' + q('parent') + '(id))');

  // A table nothing can be seeded into. It is already reported as unchecked;
  // the write attack must not pile a second warning on top of the same fact.
  await client.query('CREATE TABLE ' + q('impossible') +
    ' (id serial PRIMARY KEY, owner uuid NOT NULL, amount int NOT NULL CHECK (amount > 1000000))');

  // What Supabase grants on the public schema by default, which is the whole
  // reason a table with no row level security on it is writable by strangers.
  await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ' +
    schema.quote(APP) + ' TO anon, authenticated');
  await client.query('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ' +
    schema.quote(APP) + ' TO anon, authenticated');

  await client.query('ALTER TABLE ' + q('read_only_policy') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY readable ON ' + q('read_only_policy') +
    ' FOR SELECT TO anon, authenticated USING (true)');

  await client.query('ALTER TABLE ' + q('all_true') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY everything ON ' + q('all_true') +
    ' FOR ALL TO anon, authenticated USING (true)');

  await client.query('ALTER TABLE ' + q('own_rows') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY mine ON ' + q('own_rows') +
    ' FOR ALL TO authenticated USING (owner = auth.uid()) WITH CHECK (owner = auth.uid())');

  await client.query('ALTER TABLE ' + q('add_only') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY anyone_adds ON ' + q('add_only') +
    ' FOR INSERT TO anon, authenticated WITH CHECK (true)');
}

/** Exactly what is in every table, so any change at all shows up. */
async function contents(client, tables) {
  const out = [];
  for (const table of tables) {
    const { rows } = await client.query(
      'SELECT * FROM ' + schema.quote(APP) + '.' + schema.quote(table) + ' ORDER BY id',
    );
    out.push(table + ' = ' + JSON.stringify(rows));
  }
  return out;
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node tamper.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  const names = ['no_rls', 'read_only_policy', 'all_true', 'own_rows', 'add_only', 'parent', 'child'];

  try {
    await buildApp(client);
    const plan = await schema.readSchema(client, APP);
    const sown = await attack.seed(client, APP, plan.tables);

    const before = await contents(client, names);
    const run = await tamper.tamper(client, APP, plan.tables, sown.seeded);
    const after = await contents(client, names);

    const found = new Map(run.findings.map((f) => [f.table + ' / ' + f.who, f]));

    check('1. every table comes out exactly as it went in', (() => {
      // The first thing to be sure of, before any verdict means anything. This
      // attack inserts, updates and deletes; if any of it survived, the product
      // could not be sold whatever else it got right.
      const problems = [];
      for (let i = 0; i < before.length; i++) {
        if (before[i] !== after[i]) {
          problems.push('before: ' + before[i]);
          problems.push('after:  ' + after[i]);
        }
      }
      return problems;
    })());

    check('2. a table with no row level security is reported as writable by anyone', (() => {
      const problems = [];
      const hit = found.get('no_rls / anyone');
      if (!hit) return ['not reported at all: ' + JSON.stringify([...found.keys()])];
      for (const what of ['add', 'change', 'delete']) {
        if (!hit.can.includes(what)) problems.push('it did not prove a stranger can ' + what);
      }
      return problems;
    })());

    check('3. a SELECT policy and nothing else is NOT called writable', (() => {
      // Measured: row level security denies any command it has no policy for,
      // so an app like this is genuinely safe from writes. Reporting it would
      // send somebody to rewrite rules that were already right.
      const problems = [];
      if (found.has('read_only_policy / anyone')) problems.push('a read-only rule was read as a write rule');
      if (found.has('read_only_policy / any customer')) problems.push('same, for a signed-in customer');
      return problems;
    })());

    check('4. FOR ALL with USING (true) is reported', (() => {
      const problems = [];
      const hit = found.get('all_true / anyone');
      if (!hit) return ['a rule that stops nothing was treated as a rule'];
      if (!hit.can.includes('delete')) problems.push('it did not prove a stranger can delete');
      return problems;
    })());

    check('5. a correctly built table is left alone', (() => {
      // Both callers. A customer being able to change their OWN rows is the
      // feature; only reaching somebody else's counts.
      const problems = [];
      if (found.has('own_rows / anyone')) problems.push('reported against a stranger');
      if (found.has('own_rows / any customer')) {
        problems.push('reported against a customer, who can only reach their own rows');
      }
      return problems;
    })());

    check('6. being able only to add is serious, and not the same as being able to delete', (() => {
      const problems = [];
      const adds = found.get('add_only / anyone');
      if (!adds) return ['a table anyone can insert into was not reported'];
      if (adds.can.join(',') !== 'add') problems.push('it claimed more than it proved: ' + adds.can.join(', '));
      const described = finding.describe(adds);
      if (described.severity !== 'HIGH') problems.push('insert-only rated ' + described.severity);
      const wipe = found.get('no_rls / anyone');
      if (wipe && finding.describe(wipe).severity !== 'CRITICAL') {
        problems.push('being able to delete rated ' + finding.describe(wipe).severity);
      }
      return problems;
    })());

    check('7. the report says what was done and that it was undone', (() => {
      const problems = [];
      const hit = found.get('no_rls / anyone');
      if (!hit) return ['nothing to describe'];
      const described = finding.describe(hit);
      if (!/^Anyone can/.test(described.headline)) problems.push('headline: ' + described.headline);
      if (!/delete rows from/.test(described.headline)) problems.push('the headline buries the worst of it');
      if (!/undone straight away/.test(described.body)) problems.push('it does not say the writes were undone');
      if (!/live app was never touched/.test(described.body)) problems.push('it does not repeat the promise');
      if (!/row level security/i.test(described.fixPrompt)) problems.push('the fix does not name the fix');
      if (!/FOR SELECT/.test(described.fixPrompt)) problems.push('the fix does not warn that a read rule is not a write rule');
      return problems;
    })());

    check('8. every table it touched was either answered for or reported', (() => {
      // The same rule as everywhere else: a table nobody could get a verdict
      // on must not pass silently.
      const problems = [];
      const answered = new Set(run.completed.map((key) => key.split(':').slice(1).join(' / ')));
      const stuck = new Set(run.blocked.map((entry) => entry.key.split(':').slice(1).join(' / ')));
      for (const table of names) {
        for (const actor of ['anyone', 'any customer']) {
          const key = table + ' / ' + actor;
          if (!answered.has(key) && !stuck.has(key)) problems.push('no verdict either way for ' + key);
        }
      }
      return problems;
    })());
    check('9. a write the data model refused is not read as the app defending itself', (() => {
      // Deleting a parent row fails on the child foreign key. That error does
      // not mean the rule turned the stranger away - it means the rule let
      // them through and something else caught it. Calling that a refusal
      // would report the table as safe.
      const problems = [];
      const stuck = run.blocked.map((entry) => entry.key);
      if (!stuck.some((key) => key === 'writable:parent:anyone')) {
        problems.push('a foreign key error was taken for a refusal: ' + JSON.stringify(stuck));
      }
      return problems;
    })());

    check('10. a table that could never be seeded is not warned about twice', (() => {
      // It is already reported as a table that could not be checked. A second
      // warning saying the writes could not be tested either is the same fact
      // wearing a hat.
      const problems = [];
      const mentioned = run.completed.concat(run.blocked.map((e) => e.key));
      if (mentioned.some((key) => /:impossible:/.test(key))) {
        problems.push('it reported a table it had nothing to attack: ' + JSON.stringify(mentioned));
      }
      if (run.findings.some((f) => f.table === 'impossible')) problems.push('and claimed a finding on it');
      return problems;
    })());

  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
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
    console.log('All ' + results.length + ' write checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
