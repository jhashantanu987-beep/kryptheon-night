// Checks that a scan which died halfway does not leave a schema behind.
// Run with:  node orphans.check.js "<postgres connection string>"
//
// The copy is dropped in a `finally`, and that covers every ordinary failure.
// It does not cover the connection dying, because a `finally` needs a
// connection to run the DROP on - and when the link goes, the process goes
// with it. This was found by it happening: a real scan of a real schema lost
// its connection partway through and left kn_mu4ldd1t sitting in the database.
//
// Nobody would ever see a report about that. They would just find schemas in
// their database that they did not make, which is the kind of thing a person
// tells other people about.
//
// So every run sweeps first. The two cases that matter are opposite mistakes:
// leaving the rubbish, and sweeping away a copy that belongs to a scan running
// in another window right now.

const { Client } = require('pg');
const schema = require('./schema.js');
const { sweepOldCopies, ABANDONED_AFTER } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

/** A copy schema named as though it were made at a particular moment. */
function copyNamedFor(when) {
  return 'kn_' + when.toString(36);
}

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

async function exists(client, name) {
  const { rows } = await client.query('SELECT 1 FROM pg_namespace WHERE nspname = $1', [name]);
  return rows.length > 0;
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node orphans.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  const abandoned = copyNamedFor(Date.now() - ABANDONED_AFTER - 60000);
  const running = copyNamedFor(Date.now() - 60000);
  const mine = copyNamedFor(Date.now());
  // Named like a copy but not shaped like one: somebody else's schema that
  // happens to start the same way must not be touched.
  const notOurs = 'kn_someone_elses_' + Date.now().toString(36);

  try {
    for (const name of [abandoned, running, notOurs]) {
      await client.query('CREATE SCHEMA ' + schema.quote(name));
      await client.query('CREATE TABLE ' + schema.quote(name) + '.leftover (id int)');
    }

    const dropped = await sweepOldCopies(client, mine);

    check('1. a copy an earlier run abandoned is cleared away', (() => {
      const problems = [];
      if (!dropped.includes(abandoned)) problems.push('it did not report clearing it: ' + JSON.stringify(dropped));
      return problems;
    })());

    check('2. and it is really gone, tables and all', (async () => [])());
    const stillThere = await exists(client, abandoned);
    if (stillThere) results[results.length - 1].problems.push('the schema is still in the database');

    check('3. a copy young enough to belong to a running scan is left alone', (() => {
      // Two scans at once is not a strange thing to do, and sweeping the other
      // one out from under itself would break a run that was going fine.
      const problems = [];
      if (dropped.includes(running)) problems.push('it dropped a copy made a minute ago');
      return problems;
    })());
    if (!(await exists(client, running))) {
      results[results.length - 1].problems.push('and the schema is gone');
    }

    check('4. a schema that merely starts the same way is not ours to drop', (() => {
      const problems = [];
      if (dropped.includes(notOurs)) problems.push('it dropped a schema it did not make');
      return problems;
    })());
    if (!(await exists(client, notOurs))) {
      results[results.length - 1].problems.push('and the schema is gone');
    }
  } finally {
    for (const name of [abandoned, running, notOurs, mine]) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
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
    console.log('All ' + results.length + ' leftover checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
