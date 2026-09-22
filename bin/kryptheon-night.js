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
const recheck = require('../recheck.js');
const intro = require('../intro.js');
const trouble = require('../trouble.js');
const { howToConnect } = require('../connect.js');
const installer = require('../installer.js');
const finding = require('../finding.js');

const line = (text) => process.stdout.write(text + '\n');
const fail = (text) => process.stderr.write(text + '\n');

function usage() {
  return [
    '',
    '  kryptheon-night - attacks a copy of your database and tells you what got in.',
    '',
    '  Run it with nothing and it will ask you for what it needs:',
    '',
    '      npx kryptheon-night',
    '',
    '  Or let it do the same thing every night, from inside your database:',
    '',
    '      npx kryptheon-night install     set up the nightly run',
    '      npx kryptheon-night night       read back the last night it ran',
    '      npx kryptheon-night status      is it installed, and is it running',
    '      npx kryptheon-night uninstall   take it all out again',
    '',
    '  The nightly run needs pg_cron and pg_net. Supabase has both. It cannot',
    '  race two requests at once, so it is weaker than this command for the',
    '  "can this exist twice" question, and its report says which columns.',
    '',
    '  Options, none of them necessary:',
    '',
    '      --recheck        run the same attacks again after a fix, and say',
    '                       which problems are actually closed',
    '      --schema NAME    the part of the database your app lives in.',
    '                       Leave it out; it is "public" for almost everyone',
    '      --yes            skip the "may I?" question. For scripts only',
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
const VERBS = ['install', 'uninstall', 'status', 'night'];

/** What was asked for, and what was left to the default. */
function readArgs(argv) {
  const asked = {
    command: 'scan', schema: null, recheck: false, yes: false, help: false, unknown: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--recheck') asked.recheck = true;
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
 * The three doors that are not a scan.
 *
 * Each returns the exit code, because anything automating this reads those
 * and not the words: 0 for nothing got through or nothing to say, 1 for
 * something did, 2 for could not.
 */
async function runVerb(command, client, target) {
  if (command === 'status') {
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
    const where = await installer.status(client, {});
    if (!where) {
      line('  The nightly run is not installed in this database, so there is');
      line('  nothing to read back.');
      line('');
      line('  npx kryptheon-night          would scan it now.');
      line('  npx kryptheon-night install  would set up the nightly run.');
      line('');
      return 2;
    }
    const quoted = '"' + String(where.schema).split('"').join('""') + '"';
    const { rows } = await client.query(
      'SELECT ran_at, source, stopped, attacks_run, findings, not_checked ' +
        'FROM ' + quoted + '.runs ORDER BY ran_at DESC LIMIT 1',
    );
    if (!rows.length) {
      // Installed and never run is not the same as run and found nothing, and
      // saying "nothing got through" here would be the worst sentence in the
      // product printed about a night that never happened.
      line('  It is installed, and it has not run yet.');
      line('');
      line('  The first run is at ' + (where.job ? where.job.schedule : 'whenever it is scheduled') + '.');
      line('');
      return 0;
    }
    const run = rows[0];
    line('  From the night of ' + new Date(run.ran_at).toISOString().slice(0, 16).replace('T', ' ') +
      ', on "' + run.source + '":');
    scanner.report({
      stopped: run.stopped,
      attacksRun: run.attacks_run,
      notChecked: run.not_checked || [],
      findings: finding.describeAll(run.findings || []),
    });
    return run.stopped ? 2 : (run.findings || []).length ? 1 : 0;
  }

  throw new Error('there is no command called ' + command);
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

  const file = path.resolve(scanner.LAST_RUN);
  const before = asked.recheck ? scanner.loadLastRun(file) : null;
  if (asked.recheck && !before) {
    fail('');
    fail('  There is no earlier run in this folder to compare against.');
    fail('');
    fail('  --recheck proves a fix worked by running the same attacks again and');
    fail('  comparing. With nothing to compare against it would report every');
    fail('  problem as new, which would look like an answer and would not be one.');
    fail('');
    fail('  Run it without --recheck first.');
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
      process.exitCode = result.stopped ? 2 : result.findings.length ? 1 : 0;
      return;
    }

    const verdict = recheck.compare(before, result);
    recheck.describe(verdict).forEach(line);
    recheck.badgeLines(verdict, result.attacksRun || 0).forEach(line);
    if (result.findings.length) scanner.report(result);
    scanner.saveRun(file, result);
    process.exitCode = result.stopped ? 2 : verdict.allClear ? 0 : 1;
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
