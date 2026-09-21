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

/** What was asked for, and what was left to the default. */
function readArgs(argv) {
  const asked = { schema: null, recheck: false, yes: false, help: false, unknown: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--recheck') asked.recheck = true;
    else if (arg === '--yes' || arg === '-y') asked.yes = true;
    else if (arg === '--help' || arg === '-h') asked.help = true;
    else if (arg === '--schema') asked.schema = argv[++i] || null;
    else if (arg.startsWith('--schema=')) asked.schema = arg.slice('--schema='.length);
    else if (arg.startsWith('-')) asked.unknown.push(arg);
    // A bare word is the schema, so that somebody who has read the old
    // instructions and types `kryptheon-night public` is not told off.
    else if (!asked.schema) asked.schema = arg;
    else asked.unknown.push(arg);
  }
  return asked;
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

  if (!asked.yes) {
    if (!canAsk) {
      fail('');
      fail('  I will not connect to your database without being told yes, and');
      fail('  there is nobody here to ask.');
      fail('');
      fail('  Add --yes if you meant to run this unattended.');
      fail('');
      process.exit(2);
    }
    block(intro.consentLines(target));
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
