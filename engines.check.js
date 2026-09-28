// The same scan, twice, down two engines - compared as a report.
// Run with:  node engines.check.js "<postgres connection string>"
//
// `twin.check.js` compares the engines function by function: what each reads,
// builds, seeds and concludes. That is the right thing and it is not enough.
// Every bug found on 2026-09-21 and 2026-09-22 was at a seam rather than
// inside a function:
//
//   a foreign key written without its schema, which only happens when the app
//     is reachable by a bare name - no fixture was;
//   a serial default doing the same, and drawing the copy's keys from the
//     customer's sequence;
//   `rules` reaching the report from one engine and not the other, because
//     the comparison was of table, who and what got through.
//
// A function-level comparison cannot see any of those, because each function
// is doing exactly what it was asked. So this one runs the whole of `scan()`
// twice against one app - once with the node engine, once with the SQL one -
// and compares what a person would be handed.
//
// The app lives on the search_path, because every real app does, and that one
// condition is what three of this year's worst bugs needed.

// A run this check causes is saved to a scratch store, never the real
// ~/.kryptheon (see store.js).
process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_engines_' + Date.now().toString(36);
let undoAuth = async () => {};

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/**
 * Small, and every table in it is a shape that has changed an answer before.
 *
 * Kept short on purpose: the twin check already spends twelve minutes on the
 * awkward shapes. What is being measured here is the seams, and those show up
 * on an ordinary app as readily as on a strange one.
 */
async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await fixture.ensureRoles(client, APP, schema.quote);
  undoAuth = await fixture.ensureAuth(client);

  // The one line that makes this an app rather than a fixture.
  await client.query('SET search_path TO ' + schema.quote(APP) + ', public');

  // Row level security on, and a rule that lets everyone through. The one the
  // dashboard calls protected.
  await client.query('CREATE TABLE ' + q('profiles') +
    ' (id uuid PRIMARY KEY, email text NOT NULL, phone text)');
  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY everyone ON ' + q('profiles') +
    ' FOR SELECT TO anon, authenticated USING (true)');

  // No row level security at all, a serial key, and a foreign key written
  // without a schema because the app is on the path.
  await client.query('CREATE TABLE ' + q('orders') +
    ' (id serial PRIMARY KEY, owner uuid NOT NULL REFERENCES ' + q('profiles') +
    '(id), amount numeric(10,2) NOT NULL)');

  // A FOR ALL policy, so the report has a rule to name rather than shrug at.
  await client.query('CREATE TABLE ' + q('notes') +
    ' (id serial PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)');
  await client.query('ALTER TABLE ' + q('notes') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY anything ON ' + q('notes') +
    ' FOR ALL TO anon, authenticated USING (true)');

  // An email nothing makes unique, for the collision race.
  await client.query('CREATE TABLE ' + q('waitlist') +
    ' (id serial PRIMARY KEY, email text NOT NULL)');

  for (const t of ['profiles', 'orders', 'notes', 'waitlist']) {
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO anon, authenticated');
  }
  await client.query('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ' +
    schema.quote(APP) + ' TO anon, authenticated');
}

/** What a person is handed, reduced to something two runs can be compared on. */
function asReport(result) {
  return {
    stopped: result.stopped ? String(result.stopped).split('\n')[0] : null,
    attacksRun: result.attacksRun || 0,
    findings: (result.findings || [])
      .map((f) => [f.severity, f.table, f.headline, f.cause].join(' | '))
      .sort(),
    notChecked: (result.notChecked || [])
      .map((m) => m.table + ' | ' + String(m.why).slice(0, 80))
      .sort(),
    attempted: [...(result.attempted || [])].sort(),
  };
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node engines.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  // Both engines race for real, down their own connections, so the collision
  // attack is identical on both sides and any difference is elsewhere.
  const openSession = async () => {
    const extra = new Client({ connectionString: CONNECTION });
    await extra.connect();
    return extra;
  };

  /** Every copy and engine schema in the database right now. */
  const copySchemas = async () => {
    const { rows } = await client.query(
      "SELECT nspname FROM pg_namespace WHERE nspname ~ '^kn_(engine_)?[0-9a-z]+$'",
    );
    return rows.map((r) => r.nspname);
  };
  let copiesBefore = [];
  let copiesAfter = [];

  let byNode = null;
  let bySql = null;
  let nodeThrew = null;
  let sqlThrew = null;

  try {
    await buildApp(client);
    copiesBefore = await copySchemas();

    try {
      byNode = await scan(client, APP, { quiet: true, openSession: openSession });
    } catch (err) {
      nodeThrew = err.message;
    }

    try {
      await sqlengine.withEngine(client, async (target) => {
        bySql = await scan(client, APP, {
          quiet: true,
          openSession: openSession,
          engine: sqlengine.adapterFor(target),
        });
      });
    } catch (err) {
      sqlThrew = err.message;
    }

    copiesAfter = await copySchemas();

    check('1. both engines got through a whole scan', (() => {
      const problems = [];
      if (nodeThrew) problems.push('node threw: ' + nodeThrew);
      if (sqlThrew) problems.push('sql threw: ' + sqlThrew);
      if (byNode && byNode.stopped) problems.push('node stopped: ' + String(byNode.stopped).split('\n')[0]);
      if (bySql && bySql.stopped) problems.push('sql stopped: ' + String(bySql.stopped).split('\n')[0]);
      return problems;
    })());

    check('2. and found something, so the comparison is of something', (() => {
      // Two engines that both found nothing agree perfectly and prove
      // nothing. This app has three holes in it on purpose.
      const problems = [];
      if (!byNode || !byNode.findings.length) problems.push('the node engine found nothing in an app with holes in it');
      if (!bySql || !bySql.findings.length) problems.push('the sql engine found nothing in an app with holes in it');
      return problems;
    })());

    check('3. the two reports are the same report', (() => {
      if (!byNode || !bySql) return ['one of them did not finish, so there is nothing to compare'];
      const a = asReport(byNode);
      const b = asReport(bySql);
      const problems = [];
      for (const part of ['stopped', 'attacksRun', 'findings', 'notChecked', 'attempted']) {
        const left = JSON.stringify(a[part]);
        const right = JSON.stringify(b[part]);
        if (left !== right) {
          problems.push(part + ' differs:\n        node ' + left + '\n        sql  ' + right);
        }
      }
      return problems;
    })());

    check('4. and the reason a write got through survives both', (() => {
      // The seam that was open for half a day: the node engine named the rule
      // and the SQL engine could only say that something had. It compared
      // equal because nothing was comparing it.
      if (!byNode || !bySql) return ['one of them did not finish'];
      const reasons = (r) => r.findings
        .filter((f) => /can (add|change|delete)|add rows|change rows|delete rows/i.test(f.headline))
        .map((f) => f.table + ' | ' + f.cause)
        .sort();
      const problems = [];
      const a = reasons(byNode);
      const b = reasons(bySql);
      if (!a.length) problems.push('no write finding at all, so nothing was measured');
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        problems.push('node: ' + JSON.stringify(a) + '\n        sql:  ' + JSON.stringify(b));
      }
      // And it must be the rule that is named, not the shrug.
      if (a.some((r) => /something let this through anyway/.test(r))) {
        problems.push('a table with a FOR ALL policy was explained with the fallback: ' + JSON.stringify(a));
      }
      return problems;
    })());

    check('5. neither engine left a copy or an engine behind', (() => {
      // What matters is that these two scans left nothing NEW, not that the
      // database is empty. It was not: a twin run that died on a dropped
      // connection half an hour earlier had an engine schema still sitting
      // there, and the first version of this check reported that as a leak by
      // the scans it had just run. `sweepOldCopies` clears those after six
      // hours; this check is not the place to notice them.
      const was = new Set(copiesBefore);
      const left = copiesAfter.filter((name) => !was.has(name));
      return left.length ? ['left behind: ' + left.join(', ')] : [];
    })());
  } finally {
    await client.query('SET search_path TO "$user", public').catch(() => {});
    for (const name of copiesAfter.filter((n) => !copiesBefore.includes(n))) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
    }
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
    console.log('All ' + results.length + ' engine checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
