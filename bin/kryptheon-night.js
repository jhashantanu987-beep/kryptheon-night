#!/usr/bin/env node
//
// The front door.
//
//     npx kryptheon-night
//
// No arguments, no environment variable, no flags. It asks for what it needs,
// says what it is about to do, waits to be told yes, and then runs.
//
// `scan.js` is the same program underneath and still takes its connection
// string and schema on the command line - that is the door for scripts and
// for the checks in this repo, and it has not changed. This file exists
// because the person this product is for does not have a command line habit.
// They have a Lovable app, a Supabase project somebody set up for them, and a
// worry that anyone can read their customers table. Everything between them
// and an answer is in this file.
//
// Exit codes are the same three as `scan.js`, because anything that automates
// this reads those and not the words:
//
//     0   every attack that ran, lost
//     1   something got through
//     2   it could not run at all

const path = require('path');
const { Client } = require('pg');

const scanner = require('../scan.js');
const store = require('../store.js');
const recheck = require('../recheck.js');
const intro = require('../intro.js');
const trouble = require('../trouble.js');
const { howToConnect } = require('../connect.js');
const installer = require('../installer.js');
const outside = require('../outside.js');
const schema = require('../schema.js');

const line = (text) => process.stdout.write(text + '\n');
const fail = (text) => process.stderr.write(text + '\n');

function usage() {
  return [
    '',
    '  kryptheon-night - attacks a copy of your database and tells you what got in.',
    '',
    '  There is one command. It asks for what it needs:',
    '',
    '      npx kryptheon-night',
    '',
    '  No connection string? Give it your running app instead. It reads the app',
    '  the way a stranger does and tells you which tables anyone can read -',
    '  counts only, nothing written:',
    '',
    '      npx kryptheon-night https://your-app.example.com',
    '',
    '  Run it again after you fix something and it tells you what is actually',
    '  closed - you do not have to ask it to. It also offers to do the same',
    '  check every night from inside your database, and says so if it already',
    '  is. Nothing below is needed to use this.',
    '',
    '  For scripts, and for people who like knowing:',
    '',
    '      npx kryptheon-night night       read back the last night it ran',
    '      npx kryptheon-night status      is it installed, and is it running',
    '      npx kryptheon-night install     set the nightly run up without being asked',
    '      npx kryptheon-night uninstall   take it all out again',
    '',
    '  The nightly run needs pg_cron and pg_net. Supabase has both. It cannot',
    '  race two requests at once, so it is weaker than this command for the',
    '  "can this exist twice" question, and its report says which columns.',
    '',
    '  Options, none of them necessary:',
    '',
    '      --schema NAME    the part of the database your app lives in.',
    '                       Leave it out; it is "public" for almost everyone',
    '      --yes            skip the "may I?" question. For scripts only',
    '      --recheck        nothing any more - comparing against the last run',
    '                       happens by itself. Kept so scripts do not break',
    '      --help           this',
    '',
    '  The connection string can be put in KN_DATABASE_URL instead of being',
    '  typed in, which is how you would run this on a schedule.',
    '',
  ];
}

// The things this can be asked to do besides scan. Kept to verbs nobody
// names a schema: `public` is the schema almost everybody has, and a bare
// word that is not one of these is still read as a schema so that
// `kryptheon-night public` keeps working.
const VERBS = ['install', 'uninstall', 'status', 'night', 'words'];

/** What was asked for, and what was left to the default. */
function readArgs(argv) {
  const asked = {
    command: 'scan', schema: null, appUrl: null, recheck: false, yes: false, help: false, unknown: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    // An address is the outside attack: the running app, read the way a
    // stranger's browser reads it. Never a schema name - no schema is called
    // https://anything.
    if (/^https?:\/\//i.test(arg) && !asked.appUrl) asked.appUrl = arg;
    else if (arg === '--recheck') asked.recheck = true;
    else if (arg === '--yes' || arg === '-y') asked.yes = true;
    else if (arg === '--help' || arg === '-h') asked.help = true;
    else if (arg === '--schema') asked.schema = argv[++i] || null;
    else if (arg.startsWith('--schema=')) asked.schema = arg.slice('--schema='.length);
    else if (arg.startsWith('-')) asked.unknown.push(arg);
    // The first bare word is a verb if it is one, and otherwise the schema -
    // so that somebody who has read the old instructions and types
    // `kryptheon-night public` is not told off. Anybody whose schema really
    // is called `status` can say so with --schema.
    else if (asked.command === 'scan' && !asked.schema && VERBS.includes(arg)) asked.command = arg;
    else if (!asked.schema) asked.schema = arg;
    else asked.unknown.push(arg);
  }
  return asked;
}

/**
 * Keeps what the nightly run last said where the kryptheon dashboard reads
 * it, so the answer waiting in the database is also on the page - not only
 * what was last run from this terminal. Never fails anything: the person has
 * their answer already, and a folder that cannot be written is not theirs to
 * debug here.
 */
function keepTheNight(record) {
  try {
    scanner.saveNightly(scanner.nightlyFile(), record);
  } catch (err) {
    /* the dashboard keeps its older copy, which carries its own date */
  }
}

/**
 * The night's answer, made whole: its findings told with what their tables
 * need for a right fix, plus the functions anyone can call - both read from
 * the shape now, read only. Without the shape it is still the night's answer,
 * just less exact.
 */
async function nightRecordFrom(client, latest) {
  let plan = null;
  const run = latest && latest.run;
  if (run && !run.stopped) {
    try {
      plan = await schema.readSchema(client, run.source);
    } catch (err) {
      plan = null;
    }
  }
  return scanner.nightlyRecord(latest, new Date().toISOString(), plan);
}

/** Reads and keeps it, for the doors that do not already hold the answer. */
async function readAndKeepTheNight(client) {
  try {
    keepTheNight(await nightRecordFrom(client, await installer.latestRun(client, {})));
  } catch (err) {
    /* as above */
  }
}


/**
 * The three doors that are not a scan.
 *
 * Each returns the exit code, because anything automating this reads those
 * and not the words: 0 for nothing got through or nothing to say, 1 for
 * something did, 2 for could not.
 */
async function runVerb(command, client, target) {
  if (command === 'status') {
    await readAndKeepTheNight(client);
    const where = await installer.status(client, {});
    if (!where) {
      line('  The nightly run is not installed in this database.');
      line('');
      line('  npx kryptheon-night install   would set it up.');
      line('');
      return 0;
    }
    line('  Installed, and watching "' + where.source + '".');
    line('');
    if (where.job) {
      line('    job        ' + where.job.jobname + '   ' + where.job.schedule +
        (where.job.active ? '' : '   (NOT ACTIVE)'));
    } else {
      // The one failure that looks like success from every other angle: the
      // schema is there, the functions are there, and nothing is running.
      line('    job        MISSING - nothing is scheduled, so nothing runs');
    }
    line('    schema     ' + where.schema);
    line('    since      ' + new Date(where.installed_at).toISOString().slice(0, 16).replace('T', ' '));
    line('');
    const { rows } = await client.query(
      'SELECT count(*)::int AS n, max(ran_at) AS last FROM ' +
        '"' + String(where.schema).split('"').join('""') + '".runs',
    ).catch(() => ({ rows: [{ n: 0, last: null }] }));
    line('    runs       ' + rows[0].n +
      (rows[0].last ? '   last ' + new Date(rows[0].last).toISOString().slice(0, 16).replace('T', ' ') : ''));
    line('');
    return where.job ? 0 : 1;
  }

  if (command === 'install') {
    line('  Installing ...');
    const done = await installer.install(client, { source: target });
    line('');
    line('  Installed. It will run at ' + done.at + ', watching "' + done.source + '".');
    line('');
    if (done.made.extensions.length) {
      line('  I had to add: ' + done.made.extensions.join(', ') + '.');
      line('  Removing Kryptheon will take those back out again.');
      line('');
    }
    line('  Tomorrow morning:  npx kryptheon-night night');
    line('  To remove it:      npx kryptheon-night uninstall');
    line('');
    return 0;
  }

  if (command === 'uninstall') {
    const was = await installer.status(client, {});
    if (!was) {
      line('  There is nothing installed here to remove.');
      line('');
      return 0;
    }
    const removed = await installer.uninstall(client, {});
    await readAndKeepTheNight(client);
    line('  Removed.');
    line('');
    line('    the nightly job   ' + (removed.job ? 'gone' : 'there was none'));
    line('    the schema        ' + (removed.schema ? 'gone' : 'left, it was not mine to drop'));
    line('    extensions        ' + (removed.extensions.length
      ? removed.extensions.join(', ') + ' - the ones I added'
      : 'none removed; they were here before me'));
    line('');
    return 0;
  }

  if (command === 'night') {
    const latest = await installer.latestRun(client, {});
    const record = await nightRecordFrom(client, latest);
    keepTheNight(record);
    const where = latest.where;
    if (!where) {
      line('  The nightly run is not installed in this database, so there is');
      line('  nothing to read back.');
      line('');
      line('  npx kryptheon-night          would scan it now.');
      line('  npx kryptheon-night install  would set up the nightly run.');
      line('');
      return 2;
    }
    if (!latest.run) {
      // Installed and never run is not the same as run and found nothing, and
      // saying "nothing got through" here would be the worst sentence in the
      // product printed about a night that never happened.
      line('  It is installed, and it has not run yet.');
      line('');
      line('  It runs ' + scanner.scheduleTimes(where.job ? where.job.schedule : null) + '.');
      line('');
      return 0;
    }
    const run = latest.run;
    line('  From the night of ' + scanner.bothTimes(run.ran_at) + ', on "' + run.source + '".');
    if (where.job) line('  It runs ' + scanner.scheduleTimes(where.job.schedule) + '.');
    // The one part not from the night: the engine inside the database does
    // not look at functions, so they are read now and said to be.
    if (record.functionsReadAt) {
      line('  Functions anyone can call were looked at just now, not overnight.');
    }
    scanner.report({
      stopped: record.stopped,
      attacksRun: record.attacksRun,
      notChecked: record.notChecked || [],
      findings: record.findings || [],
    });
    return run.stopped ? 2 : scanner.exitCodeFor(record);
  }

  throw new Error('there is no command called ' + command);
}

/**
 * After the report: say what the nightly run is doing, or offer it.
 *
 * Three states and each says something different. Installed and running gets
 * one line, because it is working and nobody needs a paragraph about it.
 * Installed with no job is the quiet failure - the schema is there, the
 * functions are there, and nothing runs - so it says so plainly. Not
 * installed gets the offer.
 *
 * Nothing here can make the scan fail. Whatever happens, the person has
 * already been given their answer, and losing it to an error about a nightly
 * job they never asked for would be the tool wasting the only thing it did.
 */
async function offerTheNight(client, target, canAsk) {
  let where = null;
  try {
    where = await installer.status(client, {});
  } catch (err) {
    return;
  }

  if (where && where.job) {
    line('  I am also checking this every night, at ' + where.job.schedule + '.');
    line('  Read the last one with:  npx kryptheon-night night');
    line('');
    return;
  }

  if (where && !where.job) {
    line('  The nightly check is installed here but nothing is scheduled, so it');
    line('  is not running. Setting it up again would fix that:');
    line('');
    line('      npx kryptheon-night install');
    line('');
    return;
  }

  if (!canAsk) {
    // Nobody to ask. Said once, quietly, rather than nagging a log file.
    line('  This can also run every night by itself:  npx kryptheon-night install');
    line('');
    return;
  }

  const can = await installer.extensionState(client, 'pg_net').catch(() => ({ available: false }));
  const cron = await installer.extensionState(client, 'pg_cron').catch(() => ({ available: false }));
  if (!can.available || !cron.available) {
    // Not offered where it cannot happen. An offer that fails when accepted
    // is worse than no offer.
    return;
  }

  line('  One more thing.');
  line('');
  line('  What you just read is true about your app right now. It stops being');
  line('  true the next time anybody changes it - and that is the day nobody');
  line('  runs this. I can do exactly the same check every night, from inside');
  line('  your database, and have the answer waiting.');
  line('');
  const yes = await intro.askYesNo('  Set that up? (y/n) ');
  if (!yes) {
    line('');
    line('  Fine. It is here if you change your mind:');
    line('      npx kryptheon-night install');
    line('');
    return;
  }

  block(intro.installConsentLines(installer.SCHEMA, target, installer.AT));
  const sure = await intro.askYesNo('  Go ahead? (y/n) ');
  if (!sure) {
    line('');
    line('  Left alone. Nothing was installed.');
    line('');
    return;
  }

  try {
    const done = await installer.install(client, { source: target });
    line('');
    line('  Done. It will run at ' + done.at + ', watching "' + done.source + '".');
    if (done.made.extensions.length) {
      line('  I added ' + done.made.extensions.join(' and ') + '; uninstall takes them back out.');
    }
    line('');
    line('  Tomorrow:    npx kryptheon-night night');
    line('  To remove:   npx kryptheon-night uninstall');
    line('');
  } catch (err) {
    // The scan still stands. Say what failed and leave it at that.
    line('');
    line('  I could not set up the nightly run: ' + String(err.message).split('\n')[0]);
    line('');
    line('  The report above is still good. Nothing was left half-installed.');
    line('');
    await installer.uninstall(client, {}).catch(() => {});
  }
}

/**
 * The attack from outside, end to end: find the backend in the app, ask each
 * table as a stranger, say what came back and what could not be tested.
 *
 * Exit codes are the same three as the scan: 1 when a stranger read rows, 0
 * when nothing came back, 2 when it could not run at all.
 */
async function runOutside(appUrl) {
  line('');
  line('  Kryptheon Night Shift - from outside');
  line('  I read your app the way a stranger\'s browser does, and ask your');
  line('  database what it lets a stranger see. Counts only, nothing written.');
  line('');
  line('  Reading ' + appUrl + ' ...');

  let found;
  try {
    found = await outside.discover(appUrl);
  } catch (err) {
    fail('');
    fail('  ' + (err.code ? err.message : 'I could not read ' + appUrl + ': ' + err.message));
    fail('');
    return 2;
  }

  let result;
  try {
    result = await outside.prowl(found);
  } catch (err) {
    fail('');
    fail('  I found your database but could not ask it anything: ' + err.message);
    fail('');
    return 2;
  }

  outside.reportLines(found, result).forEach(line);
  return result.findings.length ? 1 : 0;
}

/** Everything the dashboard needs to say what this command would say. */
function wordsFor(target, connection) {
  const given = String(connection || '').trim();
  const unusable = given ? trouble.readConnectionString(given) : null;
  return {
    help: intro.whereToFindIt(),
    consent: intro.consentLines(target),
    installConsent: intro.installConsentLines(installer.SCHEMA, target, installer.AT),
    // pg_cron reads this in the database's own time zone, which is UTC on
    // Supabase; the dashboard turns it into the person's local time.
    nightlyAt: installer.AT,
    given: Boolean(given),
    unusable: unusable,
    warning: given && !unusable ? trouble.poolerWarning(given) : null,
  };
}

/** Prints a block of plain lines with the indent the rest of the report uses. */
function block(lines, write) {
  (write || line)('');
  for (const text of lines) (write || line)(text ? '  ' + text : '');
  (write || line)('');
}

async function main() {
  const asked = readArgs(process.argv.slice(2));

  if (asked.help) {
    usage().forEach(line);
    return;
  }
  if (asked.unknown.length) {
    fail('');
    fail('  I do not know the option ' + asked.unknown[0] + '.');
    usage().forEach(fail);
    process.exit(2);
  }

  // The words this command says, as JSON, for the kryptheon dashboard to show
  // on its own buttons: the help for finding the string, both consent
  // screens, and - when KN_DATABASE_URL is given - what is wrong with it or
  // worth warning about. Never connects, and never prints the string: the
  // warnings name the host at most, and a string that cannot be used is
  // described, not repeated.
  if (asked.command === 'words') {
    process.stdout.write(JSON.stringify(wordsFor(asked.schema || 'public', process.env.KN_DATABASE_URL || '')) + '\n');
    return;
  }

  // The outside attack. Needs no connection string, no copy and no yes: it
  // only asks the live app what it already answers any visitor, and asks for
  // counts, never rows. So nothing below - the string, the consent screen,
  // the connection - applies to it.
  if (asked.appUrl) {
    process.exitCode = await runOutside(asked.appUrl);
    return;
  }

  line('');
  line('  Kryptheon Night Shift');
  line('  I attack a copy of your database and tell you what got in.');

  // Asking needs somewhere to ask. Piped into a script or run by a scheduler
  // there is no keyboard, and a prompt written to nobody looks exactly like a
  // program that has frozen.
  const canAsk = Boolean(process.stdin.isTTY && process.stdout.isTTY);

  let connection = process.env.KN_DATABASE_URL || '';
  if (!connection) {
    if (!canAsk) {
      fail('');
      fail('  I need a connection string and there is nobody here to ask.');
      fail('');
      fail('  Run me in a terminal window, or set KN_DATABASE_URL first.');
      fail('');
      process.exit(2);
    }
    connection = await intro.askForConnection(line);
  }

  // Everything that can be told from the string alone is told now, before a
  // single packet goes anywhere. These are the mistakes a person makes on
  // their first try, and Postgres describes every one of them badly.
  const unusable = trouble.readConnectionString(connection);
  if (unusable) {
    block(unusable, fail);
    process.exit(2);
  }
  connection = connection.trim().replace(/^["']|["']$/g, '');

  const warning = trouble.poolerWarning(connection);
  if (warning) block(warning);

  const target = asked.schema || 'public';

  // The password is not shown back, but the address is - it is the part a
  // person can check, and seeing their own project name appear is the first
  // sign that any of this is working.
  line('');
  line('  Database: ' + trouble.withoutSecret(connection));

  // Reading does not need permission; changing does. `status` and `night` only
  // read what is already written down, so asking would be ceremony.
  const needsAYes = asked.command === 'scan' || asked.command === 'install';

  if (needsAYes && !asked.yes) {
    if (!canAsk) {
      fail('');
      fail('  I will not connect to your database without being told yes, and');
      fail('  there is nobody here to ask.');
      fail('');
      fail('  Add --yes if you meant to run this unattended.');
      fail('');
      process.exit(2);
    }
    // Two different screens, because they promise different things. The scan's
    // ends "I do not leave anything behind", which is true of a scan and false
    // of an install - and this is the one screen the product cannot be loose on.
    block(asked.command === 'install'
      ? intro.installConsentLines(installer.SCHEMA, target, installer.AT)
      : intro.consentLines(target));
    const yes = await intro.askYesNo('  Go ahead? (y/n) ');
    if (!yes) {
      line('');
      line('  Stopped. Nothing was connected to and nothing was changed.');
      line('');
      process.exit(0);
    }
  }

  // Compared against last time whenever there IS a last time, without being
  // asked.
  //
  // `--recheck` was a flag, and a flag is a thing somebody has to know about.
  // The person this is for fixed what the report told them to fix and typed
  // the same command again - and got a fresh report that said the same number
  // of problems, with no word about which of them they had just closed. The
  // tool knew. It had the file. It waited to be asked.
  //
  // The flag still works, because anything scripted may be passing it, and
  // now it changes nothing: with an earlier run here, this always compares.
  let file;
  try {
    file = scanner.lastRunFile(line);
  } catch (err) {
    // Nowhere to keep this run means nothing to compare the next one against,
    // and a re-check with nothing to compare against is not an answer.
    fail('');
    fail('  Kryptheon keeps its last run for this project in ' + store.dirFor(process.cwd()));
    fail('  and could not write there: ' + err.message);
    fail('  Set KRYPTHEON_HOME to a folder you can write to, and run this again.');
    fail('');
    process.exit(2);
  }
  const before = scanner.loadLastRun(file);
  if (asked.recheck && !before) {
    // Asked for explicitly and impossible, which is worth saying. Arriving
    // here by accident is not: without the flag, no earlier run simply means
    // this is the first one.
    fail('');
    fail('  There is no earlier run in this folder to compare against.');
    fail('');
    fail('  A re-check proves a fix worked by running the same attacks again and');
    fail('  comparing. With nothing to compare against it would report every');
    fail('  problem as new, which would look like an answer and would not be one.');
    fail('');
    fail('  Run it once first, and it will compare by itself from then on.');
    fail('');
    process.exit(2);
  }

  line('');
  line('  Connecting ...');

  let client;
  try {
    client = new Client(howToConnect(connection));
    await client.connect();
  } catch (err) {
    block(trouble.explain(err, connection), fail);
    process.exit(2);
  }

  line('  Connected.');
  line('');

  // The other three doors. Each one ends the command; only `scan` falls
  // through to the attack below.
  if (asked.command !== 'scan') {
    try {
      process.exitCode = await runVerb(asked.command, client, target);
    } catch (err) {
      block(trouble.explain(err, connection), fail);
      process.exitCode = 2;
    } finally {
      await client.end().catch(() => {});
    }
    return;
  }

  try {
    const result = await scanner.scan(client, target, {
      // Two requests arriving at the same instant cannot be faked down one
      // connection, so the collision attack is handed a way to open its own.
      // This is the one attack the nightly installer will never be able to
      // run, and the report says so when it cannot.
      openSession: async () => {
        const extra = new Client(howToConnect(connection));
        await extra.connect();
        return extra;
      },
    });

    if (!before) {
      scanner.report(result);
      scanner.saveRun(file, result);
      process.exitCode = scanner.exitCodeFor(result);
    } else {
      const verdict = recheck.compare(before, result);
      recheck.describe(verdict).forEach(line);
      recheck.badgeLines(verdict, result.attacksRun || 0).forEach(line);
      // The report ends with what was not tested; with nothing left to report
      // that list still has to be printed, or the re-check goes quiet about it.
      if (result.findings.length) scanner.report(result);
      else scanner.notTestedLines(result).forEach(line);
      scanner.saveRun(file, result);
      process.exitCode = result.stopped ? 2 : verdict.allClear ? 0 : 1;
    }

    // And then the only other thing worth doing, offered rather than
    // documented.
    //
    // `install` was a verb, and a verb is a thing somebody has to find out
    // about. Nobody who clicked Deploy in Lovable is going to read a list of
    // subcommands - they will run this once, get their answer, and never
    // think about it again, which is exactly the app that is unprotected
    // three months later. The tool already knows whether the nightly run is
    // there. So it asks.
    // Whatever the nightly run last said is kept for the dashboard too, so
    // the page shows both answers and says which is which.
    await readAndKeepTheNight(client);
    if (!result.stopped) await offerTheNight(client, target, canAsk);
  } catch (err) {
    // Anything that went wrong mid-scan. The copy has already been dropped by
    // the `finally` inside the scan itself, so there is nothing to clean up
    // here - only something to say.
    block(trouble.explain(err, connection), fail);
    process.exitCode = 2;
  } finally {
    await client.end().catch(() => {});
  }
}

// Ctrl-C during the attack leaves a copy behind, because the process dies
// before the `finally` that drops it runs. The next run sweeps it up, but the
// person deserves to know it is there rather than finding it themselves.
process.on('SIGINT', () => {
  line('');
  line('');
  line('  Stopped.');
  line('');
  line('  If I had already made the temporary copy, it is still in your');
  line('  database. Run me again and I will delete it before I start.');
  line('');
  process.exit(130);
});

main().catch((err) => {
  block(trouble.explain(err, process.env.KN_DATABASE_URL || ''), fail);
  process.exit(2);
});
