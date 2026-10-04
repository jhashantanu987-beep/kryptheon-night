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
const fixture = require('./fixture.js');

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
    await fixture.ensureRoles(client, null, schema.quote);
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

    // Found on a real read-back (NimbusCore, 2026-10-01): the time was UTC and
    // did not say so, "just now" described a run from hours before, two column
    // races were counted as two tables, the prompts lost their owner columns,
    // and the functions anyone can call - found by the terminal scan - were
    // missing, because the engine in the database does not look at them.
    const APP = 'kn_nightly_app_' + STAMP;
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
    await client.query('CREATE TABLE ' + schema.quote(APP) + '.bookings (id serial primary key, phone text)');
    await client.query('CREATE FUNCTION ' + schema.quote(APP) + '.lookup_token(k text) RETURNS text LANGUAGE sql SECURITY DEFINER AS $$ SELECT k $$');
    await client.query('GRANT EXECUTE ON FUNCTION ' + schema.quote(APP) + '.lookup_token(text) TO anon');
    const plan = await schema.readSchema(client, APP);
    const RACE = 'this attack needs two requests at the same instant, and a second connection cannot be opened';
    const night = {
      installed: true, where: { source: APP, job: { schedule: '0 3 * * *', active: true } },
      run: { ran_at: new Date('2026-10-01T03:00:00Z'), source: APP, stopped: null, attacks_run: 9,
        findings: [{ kind: 'exposed', table: 'bookings', readable: 1, columns: ['id', 'phone'], rlsEnabled: false, isView: false }],
        not_checked: [{ table: 'export_jobs', column: 'access_token', why: RACE }, { table: 'users', column: 'email', why: RACE }, { table: 'blobs', why: 'no row could be added' }] },
    };
    const whole = scanner.nightlyRecord(night, at, plan);
    check('a night read back says it was the night, names its column checks, and keeps its tables\' fixes exact', (() => {
      const p = [];
      const bookings = whole.findings.find((f) => f.table === 'bookings');
      if (!bookings) return ['no bookings finding: ' + JSON.stringify(whole.findings.map((f) => f.table))];
      if (/just now/.test(bookings.body) || !/The nightly run did it on a copy/.test(bookings.body)) p.push('the body: ' + bookings.body);
      // This app has no Supabase sign-in, so its fix is not an owner rule -
      // and never the generic one an untagged finding falls back to.
      const prompt = bookings.fixPrompt.replace(/\s+/g, ' ');
      if (!/signs people in its own way/.test(prompt) || /compare the column that says who each row belongs to/.test(prompt)) p.push('the prompt lost what the table needs: ' + prompt.slice(0, 300));
      const untagged = scanner.nightlyRecord(night, at).findings.find((f) => f.table === 'bookings').fixPrompt.replace(/\s+/g, ' ');
      if (untagged === prompt) p.push('the tags made no difference, so this proves nothing');
      const keys = whole.notChecked.map((n) => n.table + ' ' + n.key).sort();
      const want = ['blobs undefined', 'export_jobs.access_token duplicated:export_jobs:access_token', 'users.email duplicated:users:email'];
      if (JSON.stringify(keys) !== JSON.stringify(want)) p.push('not checked: ' + JSON.stringify(keys));
      const said = scanner.missedLines(whole.notChecked).join(' ').replace(/\s+/g, ' ');
      if (!/^1 table was NOT checked, and 2 checks on 2 other tables were NOT run/.test(said.trim())) p.push('the warning: ' + said);
      return p;
    })());

    check('times are said in UTC and in this computer\'s own time', (() => {
      const p = [];
      const when = scanner.bothTimes('2026-10-01T03:00:00Z');
      const local = new Date('2026-10-01T03:00:00Z').toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
      if (when !== '2026-10-01 03:00 UTC (' + local + ' your time)') p.push('bothTimes: ' + when);
      const every = scanner.scheduleTimes('0 3 * * *');
      if (!/^every night at 03:00 UTC \(\d\d:\d\d your time\)$/.test(every)) p.push('scheduleTimes: ' + every);
      if (scanner.scheduleTimes('30 2 * * *').indexOf('02:30 UTC') === -1) p.push('minutes and hours swapped: ' + scanner.scheduleTimes('30 2 * * *'));
      if (scanner.scheduleTimes('*/5 * * * *') !== '*/5 * * * *') p.push('a schedule it cannot read was not left as written');
      return p;
    })());

    check('the functions anyone can call are in it, read now and said to be', (() => {
      const p = [];
      const fn = whole.findings.find((f) => f.kind === 'privileged');
      if (!fn || fn.table !== 'lookup_token' || fn.status !== 'verification required') p.push('no function: ' + JSON.stringify(whole.findings.map((f) => f.kind + ':' + f.table)));
      if (whole.functionsReadAt !== at) p.push('functionsReadAt is ' + whole.functionsReadAt);
      const bare = scanner.nightlyRecord(night, at);
      if (bare.findings.some((f) => f.kind === 'privileged') || bare.functionsReadAt !== null) p.push('without the shape it still claimed to have read functions');
      if (bare.findings.length !== 1) p.push('without the shape the night\'s own findings were lost');
      const stopped = scanner.nightlyRecord({ installed: true, where: {}, run: Object.assign({}, night.run, { stopped: 'no tables' }) }, at, plan);
      if (stopped.findings.length) p.push('a stopped night carries findings: ' + JSON.stringify(stopped.findings.map((f) => f.table)));
      return p;
    })());

    // The real command, reading back a night from a real "kryptheon" schema -
    // made here only if there is none, and taken away again.
    const own = (await client.query("SELECT 1 FROM pg_namespace WHERE nspname = 'kryptheon'")).rows.length === 0;
    let said = null;
    let keptRecord = null;
    if (own) {
      try {
        await client.query('CREATE SCHEMA kryptheon');
        await client.query("CREATE TABLE kryptheon.installed (id integer PRIMARY KEY DEFAULT 1, installed_at timestamptz NOT NULL DEFAULT now(), source text NOT NULL, made_extensions text[] NOT NULL DEFAULT '{}', made_schema boolean NOT NULL DEFAULT false, jobid bigint)");
        await client.query('INSERT INTO kryptheon.installed (source) VALUES ($1)', [APP]);
        await client.query("CREATE TABLE kryptheon.runs (id bigserial PRIMARY KEY, ran_at timestamptz NOT NULL DEFAULT now(), source text NOT NULL, stopped text, attacks_run integer NOT NULL DEFAULT 0, findings jsonb NOT NULL DEFAULT '[]', not_checked jsonb NOT NULL DEFAULT '[]')");
        await client.query('INSERT INTO kryptheon.runs (ran_at, source, attacks_run, findings, not_checked) VALUES ($1, $2, 9, $3, $4)',
          [night.run.ran_at, APP, JSON.stringify(night.run.findings), JSON.stringify(night.run.not_checked)]);
        const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-nightly-cli-'));
        const r = require('child_process').spawnSync(process.execPath, [path.join(__dirname, 'bin', 'kryptheon-night.js'), 'night'], {
          cwd: cwd, encoding: 'utf8', timeout: 60000,
          env: Object.assign({}, process.env, { KN_DATABASE_URL: CONNECTION, TZ: 'Asia/Kolkata' }),
        });
        said = { code: r.status, out: String(r.stdout || '') + String(r.stderr || '') };
        try { keptRecord = JSON.parse(fs.readFileSync(store.pathsFor(cwd).nightNightly, 'utf8')); } catch (err) { keptRecord = null; }
        fs.rmSync(cwd, { recursive: true, force: true });
      } finally {
        await client.query('DROP SCHEMA IF EXISTS kryptheon CASCADE');
      }
    }
    check('"night" says the time in UTC and in the computer\'s own time, and the rest as above', (() => {
      if (!own) return [];
      if (!said) return ['it did not run'];
      const p = [];
      if (!/From the night of 2026-10-01 03:00 UTC \(1 Oct, 08:30 your time\)/.test(said.out)) p.push('the time: ' + said.out.slice(0, 900));
      // No pg_cron here, so there is no job and no schedule line; the
      // schedule's wording is checked on its own above.
      const flat = said.out.replace(/\s+/g, ' ');
      if (!/Functions anyone can call were looked at just now, not overnight/.test(said.out) || !/lookup_token/.test(said.out)) p.push('the function is not there, or not said to be read now');
      if (/just now and got back/.test(flat)) p.push('it still says "just now" about the night');
      if (!/2 checks on 2 other tables were NOT run/.test(flat) || !/export_jobs\.access_token -/.test(flat)) p.push('the untested part: ' + flat.slice(0, 600));
      if (said.code !== 1) p.push('exit ' + said.code);
      if (!keptRecord || !keptRecord.findings.some((f) => f.kind === 'privileged')) p.push('the dashboard\'s copy does not have the function');
      return p;
    })());
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE');
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
