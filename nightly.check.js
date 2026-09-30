// Checks that what the nightly run last said is read out of the database and
// kept where the kryptheon dashboard reads it - and that the three answers
// that are not "nothing found" stay themselves.
//
//   node nightly.check.js "<postgres connection string>"
//
// The dashboard used to show only the scan last run from this terminal. The
// nightly run, installed inside the database, kept its answer there, and the
// page never showed it.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const fs = require('fs');
const os = require('os');
const path = require('path');
const { Client } = require('pg');
const schema = require('./schema.js');
const installer = require('./installer.js');
const scanner = require('./scan.js');
const store = require('./store.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
// Its own name, so this never touches a real "kryptheon" schema.
const HOME = 'kn_nightly_' + STAMP;
const q = (name) => schema.quote(HOME) + '.' + name;

const results = [];
const check = (name, problems) => results.push({ name, problems });

// A raw finding the way the engine in the database writes one.
const EXPOSED = { kind: 'exposed', table: 'profiles', readable: 2, columns: ['id', 'email'], rlsEnabled: true, isView: false };

async function main() {
  if (!CONNECTION) {
    console.error('\n  node nightly.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    const at = '2026-09-30T10:00:00.000Z';

    check('not installed is said as not installed', (() => {
      const r = scanner.nightlyRecord({ installed: false }, at);
      return r.installed === false && r.readAt === at && !('findings' in r) ? [] : ['got ' + JSON.stringify(r)];
    })());

    check('installed and never run is not "nothing found"', (() => {
      const r = scanner.nightlyRecord({ installed: true, where: { source: 'public', job: { schedule: '0 3 * * *', active: true } }, run: null }, at);
      const problems = [];
      if (r.installed !== true || r.ranAt !== null) problems.push('got ' + JSON.stringify(r));
      if ('findings' in r) problems.push('a night that never ran carries a findings list');
      if (r.scheduled !== '0 3 * * *' || r.active !== true || r.source !== 'public') problems.push('the schedule is lost: ' + JSON.stringify(r));
      return problems;
    })());

    check('a night that ran carries described findings, like a scan', (() => {
      const r = scanner.nightlyRecord({ installed: true, where: { source: 'public', job: null }, run: {
        ran_at: new Date('2026-09-30T03:00:05Z'), source: 'public', stopped: null, attacks_run: 12,
        findings: [EXPOSED], not_checked: [{ table: 'blobs', why: 'seed' }] } }, at);
      const problems = [];
      if (r.ranAt !== '2026-09-30T03:00:05.000Z') problems.push('ranAt ' + r.ranAt);
      if (r.active !== false || r.scheduled !== null) problems.push('a missing job read as scheduled');
      if (r.attacksRun !== 12 || r.notChecked.length !== 1) problems.push('the counts are lost');
      const f = (r.findings || [])[0];
      if (!f || !/can be read by anyone/.test(f.headline) || !f.fixPrompt || f.severity !== 'CRITICAL') problems.push('not described: ' + JSON.stringify(f));
      return problems;
    })());

    check('a night that stopped carries no findings, only why', (() => {
      const r = scanner.nightlyRecord({ installed: true, where: {}, run: { ran_at: new Date(), source: 'public',
        stopped: 'no tables', attacks_run: 0, findings: [EXPOSED], not_checked: [] } }, at);
      return r.stopped === 'no tables' && r.findings.length === 0 ? [] : ['got ' + JSON.stringify(r)];
    })());

    // The database side, on a schema shaped like the installed one.
    const missing = await installer.latestRun(client, { schema: HOME });
    check('with nothing installed, the database says so', (() => {
      return missing.installed === false && missing.run === null ? [] : ['got ' + JSON.stringify(missing)];
    })());

    await client.query('CREATE SCHEMA ' + schema.quote(HOME));
    await client.query('CREATE TABLE ' + q('installed') + ' (id integer PRIMARY KEY DEFAULT 1, installed_at timestamptz NOT NULL DEFAULT now(), ' +
      "source text NOT NULL, made_extensions text[] NOT NULL DEFAULT '{}', made_schema boolean NOT NULL DEFAULT false, jobid bigint)");
    await client.query("INSERT INTO " + q('installed') + " (source, jobid) VALUES ('public', NULL)");
    await client.query('CREATE TABLE ' + q('runs') + " (id bigserial PRIMARY KEY, ran_at timestamptz NOT NULL DEFAULT now(), source text NOT NULL, " +
      "stopped text, attacks_run integer NOT NULL DEFAULT 0, findings jsonb NOT NULL DEFAULT '[]', not_checked jsonb NOT NULL DEFAULT '[]')");

    const empty = await installer.latestRun(client, { schema: HOME });
    check('installed with no runs reads as never run', (() => {
      return empty.installed === true && empty.run === null && empty.where.source === 'public' ? [] : ['got ' + JSON.stringify(empty)];
    })());

    await client.query('INSERT INTO ' + q('runs') + " (ran_at, source, attacks_run) VALUES ('2026-09-28T03:00Z', 'public', 5)");
    await client.query('INSERT INTO ' + q('runs') + " (ran_at, source, attacks_run, findings) VALUES ('2026-09-30T03:00Z', 'public', 9, $1)",
      [JSON.stringify([EXPOSED])]);
    await client.query('INSERT INTO ' + q('runs') + " (ran_at, source, attacks_run) VALUES ('2026-09-29T03:00Z', 'public', 7)");
    const newest = await installer.latestRun(client, { schema: HOME });
    check('the newest night is the one read, whatever order it was written in', (() => {
      const run = newest.run || {};
      return run.attacks_run === 9 && (run.findings || []).length === 1 ? [] : ['got ' + JSON.stringify(run)];
    })());

    // And kept where the dashboard looks: this project's store.
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-nightly-'));
    const was = process.cwd();
    process.chdir(work);
    let file;
    try {
      file = scanner.nightlyFile();
      scanner.saveNightly(file, scanner.nightlyRecord(newest, at));
    } finally {
      process.chdir(was);
    }
    check('it is kept in the store, under the name the dashboard reads', (() => {
      const problems = [];
      if (path.basename(file) !== 'night-nightly.json') problems.push('kept as ' + file);
      if (path.resolve(file) !== path.resolve(store.pathsFor(work).nightNightly)) problems.push('not in this project\'s store: ' + file);
      let kept = null;
      try { kept = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (err) { problems.push('not readable: ' + err.message); }
      if (kept && (kept.findings || []).length !== 1) problems.push('the findings were not kept');
      return problems;
    })());
    fs.rmSync(work, { recursive: true, force: true });
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(HOME) + ' CASCADE').catch(() => {});
    await client.end().catch(() => {});
  }

  let failures = 0;
  for (const r of results) {
    if (r.problems.length) {
      failures++;
      console.log('FAIL  ' + r.name);
      r.problems.forEach((p) => console.log('      - ' + p));
    } else {
      console.log('PASS  ' + r.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exit(1);
  }
  console.log('All ' + results.length + ' nightly-result checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
