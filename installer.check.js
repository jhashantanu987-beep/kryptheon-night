// Does the installer leave nothing behind?
// Run with:  KN_DATABASE_URL=postgresql://...  npm run check:installer
//
// NOT part of `npm run check`, and that is not laziness. The nightly door
// needs pg_cron and pg_net, Neon has neither, and every other suite here runs
// against Neon. A check that cannot run where the suite runs would either
// fail every night for the wrong reason or learn to skip quietly, and a check
// that skips quietly is the thing this repo is most careful about. So it
// lives on its own and says plainly when it cannot run.
//
// What it is guarding is one sentence: a customer who removes Kryptheon gets
// their database back exactly as it was. That is harder than it sounds and
// fails silently when it fails:
//
//   cron.unschedule bound to the wrong overload and reported success while
//     leaving the job scheduled - measured, before any of this was written;
//   pg_net installs into the customer's own `public` unless told otherwise;
//   and dropping pg_cron on a database that already had it would take every
//     other job in it away too.

const { Client } = require('pg');
const installer = require('./installer.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const SCHEMA = 'kryptheon_check_' + Date.now().toString(36);

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/** Everything about this database that removing us must not change. */
async function photograph(client) {
  const shot = {};
  const shots = {
    extensions: 'SELECT extname, n.nspname AS schema FROM pg_extension e ' +
      'JOIN pg_namespace n ON n.oid = e.extnamespace ORDER BY 1',
    schemas: "SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' ORDER BY 1",
    publicFunctions: "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace " +
      "WHERE n.nspname = 'public' ORDER BY 1",
  };
  for (const [what, sql] of Object.entries(shots)) {
    const { rows } = await client.query(sql);
    shot[what] = rows.map((r) => JSON.stringify(r));
  }
  // The jobs, if there is a pg_cron here at all to have any.
  const jobs = await client.query('SELECT jobname, schedule, command FROM cron.job ORDER BY 1')
    .catch(() => ({ rows: [] }));
  shot.jobs = jobs.rows.map((r) => JSON.stringify(r));
  return shot;
}

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

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  KN_DATABASE_URL=postgresql://...  node installer.check.js');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  // Said out loud rather than skipped. A check nobody ran must never read
  // like a check that passed.
  const net = await installer.extensionState(client, 'pg_net');
  const cron = await installer.extensionState(client, 'pg_cron');
  if (!net.available || !cron.available) {
    console.error('');
    console.error('  This database cannot host the nightly run, so nothing was tested.');
    console.error('');
    console.error('    pg_net available:  ' + net.available);
    console.error('    pg_cron available: ' + cron.available);
    console.error('');
    console.error('  Point KN_DATABASE_URL at a Supabase project. Neon offers pg_cron');
    console.error('  and not pg_net, which is why this is not part of npm run check.');
    console.error('');
    await client.end();
    process.exit(2);
  }

  // Whether they were here before decides what uninstall is allowed to take.
  const netWasHere = net.installed;
  const cronWasHere = cron.installed;

  let before = null;
  let installed = null;
  try {
    before = await photograph(client);

    installed = await installer.install(client, { schema: SCHEMA, source: 'public' });

    check('1. it installs: a schema, an engine in it, and a nightly job', (() => {
      const problems = [];
      if (!installed.jobid) problems.push('no job was scheduled');
      if (installed.schema !== SCHEMA) problems.push('it installed somewhere else: ' + installed.schema);
      return problems;
    })());

    const after = await installer.status(client, { schema: SCHEMA });
    check('2. and what it installed reads back from the database', (() => {
      const problems = [];
      if (!after) return ['nothing is installed according to status()'];
      if (!after.job) problems.push('the job is not in cron.job');
      else {
        if (after.job.schedule !== installer.AT) problems.push('the schedule is ' + after.job.schedule);
        if (after.job.active !== true) problems.push('the job is not active');
      }
      if (after.source !== 'public') problems.push('it recorded the wrong source: ' + after.source);
      return problems;
    })());

    const command = await client.query(
      "SELECT command FROM cron.job WHERE jobname = 'kryptheon_nightly'",
    ).catch(() => ({ rows: [] }));
    check('3. the job runs this install, and runs the night', (() => {
      // A job pointing at a schema that is not there fails every night into a
      // log nobody reads, and the customer gets no answer at all - which from
      // the outside is indistinguishable from nothing having got through.
      const problems = [];
      if (!command.rows.length) return ['there is no job to look at'];
      const sql = String(command.rows[0].command);
      if (!sql.includes(SCHEMA)) problems.push('it does not name this install: ' + sql);
      if (!/\.nightly\(/.test(sql)) problems.push('it does not call nightly(): ' + sql);
      if (!/'public'/.test(sql)) problems.push('it does not say which schema to scan: ' + sql);
      return problems;
    })());

    // Not scheduled and waited for - a check that sleeps until three in the
    // morning is a check nobody runs. What is proved here is that the thing
    // the job would call does work when called.
    const ran = await client.query(
      'SELECT "' + SCHEMA + '".nightly($1) AS id', ['public'],
    ).catch((err) => ({ rows: [], why: err.message }));
    check('4. and calling it produces an answer rather than an error', (() => {
      const problems = [];
      if (!ran.rows.length) return ['nightly() threw: ' + String(ran.why).split('\n')[0]];
      return problems;
    })());

    // The whole point. Everything from here is about taking it away.
    //
    // `uninstall` refuses to carry on when the job outlives it, which is
    // right - and left to reach the top of this file that refusal printed
    // "The check could not run" with no FAIL line anywhere. It reads as a
    // broken harness rather than as a broken product, and the suite runner
    // treats it as a dropped connection. The same mistake was in
    // untouched.check.js this morning, for the same reason: the one failure a
    // file exists to catch is the one it reports worst.
    let removed = { job: false, schema: false, extensions: [] };
    let removeThrew = null;
    try {
      removed = await installer.uninstall(client, { schema: SCHEMA });
    } catch (err) {
      removeThrew = err.message;
    }

    check('5. uninstall takes the job away, and proves it', (() => {
      const problems = [];
      if (removeThrew) problems.push('uninstall threw: ' + String(removeThrew).split('\n')[0]);
      if (!removeThrew && !removed.job) problems.push('it did not report removing the job');
      return problems;
    })());

    const leftJobs = await client.query(
      "SELECT count(*)::int n FROM cron.job WHERE jobname = 'kryptheon_nightly'",
    ).catch(() => ({ rows: [{ n: 0 }] }));
    check('6. and there is really no nightly job left', (() => {
      // The one that would have failed silently. cron.unschedule bound to the
      // name overload returns an error that reads like the job was already
      // gone, so an uninstall that swallowed it would report success.
      return leftJobs.rows[0].n ? ['a kryptheon_nightly job is still scheduled'] : [];
    })());

    const leftSchema = await client.query(
      'SELECT count(*)::int n FROM pg_namespace WHERE nspname = $1', [SCHEMA],
    );
    check('7. and no engine schema left',
      leftSchema.rows[0].n ? ['the schema ' + SCHEMA + ' is still there'] : []);

    check('8. an extension that was here first is still here', (() => {
      // Only remove what you created. Dropping pg_cron on a database that
      // already had it would take every other job in it away, and this is a
      // customer's database.
      const problems = [];
      if (cronWasHere && !(removed.extensions || []).every((e) => e !== 'pg_cron')) {
        problems.push('pg_cron was here before and uninstall removed it');
      }
      if (netWasHere && (removed.extensions || []).includes('pg_net')) {
        problems.push('pg_net was here before and uninstall removed it');
      }
      return problems;
    })());

    const now = await photograph(client);
    check('9. the database is what it was before any of this', (() => {
      return differences(before, now);
    })());
  } finally {
    // Whatever happened above, leave nothing of ours - including when the
    // thing being tested is the part that is broken.
    //
    // Calling uninstall again is not enough: it is what just refused, and it
    // would refuse again and be swallowed, leaving a job scheduled in
    // somebody's database every night for ever. So the job goes by name, with
    // the cast, by hand.
    await installer.uninstall(client, { schema: SCHEMA }).catch(() => {});
    const stragglers = await client.query(
      "SELECT jobid FROM cron.job WHERE jobname = 'kryptheon_nightly'",
    ).catch(() => ({ rows: [] }));
    for (const row of stragglers.rows) {
      await client.query('SELECT cron.unschedule($1::bigint)', [row.jobid]).catch(() => {});
    }
    await client.query('DROP SCHEMA IF EXISTS "' + SCHEMA + '" CASCADE').catch(() => {});

    // And the extensions, on the same rule the installer follows: only the
    // ones that were not here when this started. Whether they were is held in
    // a variable up there, because the installer's own record of it lives in
    // the schema that has just been dropped - and when uninstall is the thing
    // that is broken, that record is gone before it was read.
    //
    // Found by breaking uninstall on purpose: the run failed correctly, and
    // left pg_cron and pg_net installed in somebody's real project.
    for (const [name, wasHere] of [['pg_net', netWasHere], ['pg_cron', cronWasHere]]) {
      if (wasHere) continue;
      const here = await installer.extensionState(client, name);
      if (here.installed) await client.query('DROP EXTENSION IF EXISTS ' + name).catch(() => {});
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
    console.log('All ' + results.length + ' installer checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
