// Checks that "this can point at nothing" is only said when it can, and only
// where a foreign key actually belongs.
// Run with:  node orphan.check.js "<postgres connection string>"
//
// This attack tells somebody their schema is missing a constraint, and that is
// a claim about how their app is meant to work, not just about what the
// database did. Being wrong sends them to add a foreign key that breaks
// something - so almost all of this is about the cases where it must say
// nothing at all:
//
//   stripe_id, session_id   point outside this database entirely
//   org_id integer vs orgs.id uuid   the types do not agree
//   audit_log.user_id       keeping a deleted user's id is the whole point
//   orders.user_id with a key already on it
//
// The one it must catch: a column named after a table that is really here,
// of the same type as that table's key, with nothing tying them together.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');
const orphan = require('./orphan.js');
const finding = require('./finding.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_orphan_' + Date.now().toString(36);

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await fixture.ensureRoles(client, APP, schema.quote);
  undoAuth = await fixture.ensureAuth(client);

  await client.query('CREATE TABLE ' + q('users') + ' (id uuid PRIMARY KEY, email text NOT NULL)');
  await client.query('CREATE TABLE ' + q('orgs') + ' (id uuid PRIMARY KEY, name text NOT NULL)');

  // The one that must be found: named after a real table, same type, no key.
  await client.query(
    'CREATE TABLE ' + q('orders') +
      ' (id serial PRIMARY KEY, user_id uuid NOT NULL, total numeric(10,2) NOT NULL)',
  );

  // Already tied down. Nothing to say.
  await client.query(
    'CREATE TABLE ' + q('invoices') +
      ' (id serial PRIMARY KEY, user_id uuid NOT NULL REFERENCES ' + q('users') + '(id), total numeric(10,2) NOT NULL)',
  );

  // Points outside the database. A foreign key here would be wrong.
  await client.query(
    'CREATE TABLE ' + q('payments') +
      ' (id serial PRIMARY KEY, stripe_id text NOT NULL, session_id text NOT NULL, external_id text NOT NULL)',
  );

  // The name matches a table but the types do not, so it points at something
  // else entirely and guessing would be wrong.
  await client.query(
    'CREATE TABLE ' + q('seats') + ' (id serial PRIMARY KEY, org_id integer NOT NULL, label text NOT NULL)',
  );

  // Remembering a deleted person is what an audit row is for.
  await client.query(
    'CREATE TABLE ' + q('audit_log') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL, what text NOT NULL)',
  );

  // A parent that already holds the value the attack uses to mean "nobody".
  // If the attack does not check for that first, its row lands for a
  // perfectly good reason and gets reported as a hole.
  await client.query('CREATE TABLE ' + q('teams') + ' (id uuid PRIMARY KEY, name text NOT NULL)');
  await client.query(
    'INSERT INTO ' + q('teams') + " VALUES ('99999999-9999-4999-8999-999999999999', 'a real team')",
  );
  await client.query('CREATE TABLE ' + q('rosters') + ' (id serial PRIMARY KEY, team_id uuid NOT NULL, note text NOT NULL)');

  // Refused for a reason that has nothing to do with referential integrity.
  // Nothing is learned about whether an orphan can exist here.
  await client.query('CREATE TABLE ' + q('tickets') +
    ' (id serial PRIMARY KEY, user_id uuid NOT NULL, amount integer NOT NULL CHECK (amount > 1000000))');

  for (const t of ['users', 'orgs', 'orders', 'invoices', 'payments', 'seats', 'audit_log', 'teams', 'rosters', 'tickets']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
  }
}

/** Exactly what is in every table, so any leftover row shows up. */
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
    console.error('  node orphan.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  const names = ['users', 'orgs', 'orders', 'invoices', 'payments', 'seats', 'audit_log', 'teams', 'rosters'];

  try {
    await buildApp(client);
    const plan = await schema.readSchema(client, APP);
    const sown = await attack.seed(client, APP, plan.tables);

    const before = await contents(client, names);
    const run = await orphan.orphan(client, APP, plan.tables, sown.seeded);
    const after = await contents(client, names);

    const found = run.findings.map((f) => f.table + '.' + f.column).sort();

    check('1. every table comes out exactly as it went in', (() => {
      // This attack inserts. If any of it survived, nothing else matters.
      const problems = [];
      for (let i = 0; i < before.length; i++) {
        if (before[i] !== after[i]) {
          problems.push('before: ' + before[i]);
          problems.push('after:  ' + after[i]);
        }
      }
      return problems;
    })());

    check('2. a column pointing at a real table with nothing holding it is found', (() => {
      const problems = [];
      if (!found.includes('orders.user_id')) {
        problems.push('it missed the one real case: ' + JSON.stringify(found));
      }
      const hit = run.findings.find((f) => f.table === 'orders');
      if (hit && hit.parent !== 'users') problems.push('it named the wrong parent: ' + hit.parent);
      return problems;
    })());

    check('3. a column that already has a foreign key is left alone', (() => {
      const problems = [];
      if (found.includes('invoices.user_id')) problems.push('it asked for a key that is already there');
      return problems;
    })());

    check('4. a column pointing outside the database is never reported', (() => {
      // Telling somebody to add a foreign key from stripe_id to a table that
      // does not exist would be telling them to break their app.
      const problems = [];
      const considered = orphan.candidates(plan.tables).map((c) => c.table + '.' + c.column);
      for (const outside of ['payments.stripe_id', 'payments.session_id', 'payments.external_id']) {
        if (found.includes(outside)) problems.push('it reported ' + outside);
        // Not even looked at. Considering it means querying a table that is
        // not there, and a line nobody earned saying it could not be checked.
        if (considered.includes(outside)) problems.push('it went looking for a table behind ' + outside);
      }
      return problems;
    })());

    check('5. a name that matches but a type that does not is left alone', (() => {
      // seats.org_id is an integer and orgs.id is a uuid, so whatever it points
      // at, it is not that.
      const problems = [];
      if (found.includes('seats.org_id')) problems.push('it matched on the name and ignored the type');
      if (orphan.candidates(plan.tables).some((c) => c.table === 'seats' && c.column === 'org_id')) {
        problems.push('it considered seats.org_id at all');
      }
      return problems;
    })());

    check('6. an audit table is left alone', (() => {
      // Holding the id of somebody who has since been deleted is what the row
      // is for. A foreign key there would be the bug.
      const problems = [];
      if (found.includes('audit_log.user_id')) problems.push('it wants a foreign key on an audit row');
      return problems;
    })());

    check('7. it reports exactly one thing, and it is the right one', (() => {
      const problems = [];
      if (found.length !== 1) problems.push('reported ' + found.length + ': ' + JSON.stringify(found));
      return problems;
    })());

    check('8. the report says what it costs and the fix names both columns', (() => {
      const problems = [];
      const hit = run.findings.find((f) => f.table === 'orders');
      if (!hit) return ['nothing to describe'];
      const described = finding.describe(hit);
      if (described.severity !== 'HIGH') problems.push('rated ' + described.severity);
      if (!/point at a user that does not exist/.test(described.headline)) {
        problems.push('headline: ' + described.headline);
      }
      if (!/stay behind/.test(described.body)) problems.push('it does not say what happens on a delete');
      if (!/undone straight away/.test(described.body)) problems.push('it does not say the row was undone');
      if (!/"orders"\."user_id"/.test(described.fixPrompt)) problems.push('the fix does not name the column');
      if (!/"users"\."id"/.test(described.fixPrompt)) problems.push('the fix does not name what it points at');
      if (!/ON DELETE/.test(described.fixPrompt)) problems.push('the fix does not make them choose a delete behaviour');
      return problems;
    })());

    check('9. everything it considered got a verdict either way', (() => {
      const problems = [];
      const answered = new Set(run.completed.map((key) => key.split(':').slice(1).join('.')));
      const stuck = new Set(run.notTried.map((entry) => entry.table + '.' + entry.column));
      for (const target of orphan.candidates(plan.tables)) {
        const key = target.table + '.' + target.column;
        if (!answered.has(key) && !stuck.has(key)) problems.push('no verdict either way for ' + key);
      }
      return problems;
    })());
    check('10. a column that already has a key is still attacked, so a fix can be proved', (() => {
      // The same reason the collision attack races columns that are already
      // unique: skip them, and the moment somebody adds the key this asked
      // for, the attack stops running - so the re-check reports the fix it
      // requested as one it could not confirm.
      const problems = [];
      if (!run.completed.includes('orphaned:invoices:user_id')) {
        problems.push('a column with a foreign key was never attacked: ' + JSON.stringify(run.completed));
      }
      if (found.includes('invoices.user_id')) problems.push('and attacking it turned it into a finding');
      return problems;
    })());

    check('11. a refusal is not a hole', (() => {
      // invoices is refused by its own foreign key. Anything that counted a
      // refusal as a finding would report the table that got it right.
      const problems = [];
      if (run.findings.some((f) => f.table === 'invoices')) {
        problems.push('a row that was refused was reported as one that landed');
      }
      return problems;
    })());

    check('12. a refusal that is not about a foreign key is reported as not tried', (() => {
      // tickets has a CHECK no generated row satisfies. The insert fails, but
      // not because anything stopped an orphan - so nothing was learned, and
      // saying nothing at all would read as safe.
      const problems = [];
      const stuck = run.notTried.map((e) => e.table + '.' + e.column);
      if (!stuck.includes('tickets.user_id')) {
        problems.push('a refusal that proved nothing was counted as an answer: ' + JSON.stringify(stuck));
      }
      if (run.completed.includes('orphaned:tickets:user_id')) {
        problems.push('and it was recorded as an attack that ran');
      }
      return problems;
    })());

    check('14. a parent that already holds the test value is not a finding', (() => {
      // teams really does contain the uuid the attack uses to mean nobody, so
      // a row naming it is not an orphan at all. Reporting it would be a hole
      // invented out of a coincidence.
      const problems = [];
      if (found.includes('rosters.team_id')) {
        problems.push('it called a row pointing at a real team an orphan');
      }
      const stuck = run.notTried.map((e) => e.table + '.' + e.column);
      if (!stuck.includes('rosters.team_id')) {
        problems.push('and it did not say it could not test it: ' + JSON.stringify(stuck));
      }
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
    console.log('All ' + results.length + ' interruption checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
