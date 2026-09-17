// Checks what the person actually sees when they get something wrong.
// Run with:  node usable.check.js "<postgres connection string>"
//
// Every other check assumes the command was typed correctly. This one assumes
// it was not, because most of the time it will not be, and the ways a scanner
// can fail a person are not all findings:
//
//   a typo in the schema name          the worst one, by a long way
//   a connection string that is wrong
//   a schema that is simply empty
//   no permission to build the copy
//
// The first is the one that matters. `node scan.js "..." pubic` finds no
// tables, attacks nothing, and - before this check existed - printed
// "Nothing got through. Your data held." A typo cannot be allowed to produce
// the sentence the entire product is sold on.
//
// Everything here goes through the real command line, because the wording, the
// exit code and the stack trace a person sees are the product.

const { Client } = require('pg');
const { spawnSync } = require('child_process');
const path = require('path');
const schema = require('./schema.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const EMPTY = 'kn_usable_empty_' + Date.now().toString(36);

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/** Runs the command exactly as a person would, and hands back what they see. */
function cli(args, env) {
  const before = process.env.KN_PRELOAD ? ['--require', process.env.KN_PRELOAD] : [];
  const r = spawnSync(process.execPath, before.concat([path.join(__dirname, 'scan.js')], args), {
    cwd: __dirname,
    encoding: 'utf8',
    timeout: 300000,
    env: Object.assign({}, process.env, env || {}),
  });
  return { out: String(r.stdout || '') + String(r.stderr || ''), code: r.status };
}

/** The words that must never appear unless an app was genuinely attacked. */
function claimsSafety(text) {
  return /Nothing got through|Your data held|Kryptheon Verified/.test(text);
}

/** A stack trace is the tool saying "this is not for you". */
function looksLikeACrash(text) {
  return /at [A-Za-z_$][\w$]*\s*\(|node:internal|Error:\s*\n\s+at /.test(text);
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node usable.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  try {
    await client.query('CREATE SCHEMA ' + schema.quote(EMPTY));

    const typo = cli([CONNECTION, 'this_schema_does_not_exist_' + Date.now().toString(36)]);
    check('1. a typo in the schema name never produces an all-clear', (() => {
      // The whole product in one case. Somebody types `pubic`, the scanner
      // finds nothing to attack, and tells them they are safe.
      const problems = [];
      if (claimsSafety(typo.out)) problems.push('it said the app was safe: ' + typo.out.trim().split('\n').join(' | '));
      if (typo.code === 0) problems.push('and exited 0, so a script would treat it as a pass');
      return problems;
    })());

    check('2. and it says what is actually wrong, in one readable line', (() => {
      const problems = [];
      if (looksLikeACrash(typo.out)) problems.push('it printed a stack trace');
      if (!/no schema|does not exist|not find/i.test(typo.out)) {
        problems.push('it does not say the schema was not found: ' + typo.out.trim());
      }
      return problems;
    })());

    const empty = cli([CONNECTION, EMPTY]);
    check('3. a real but empty schema is not an all-clear either', (() => {
      // There is nothing wrong with the database, but nothing was tested, so
      // the honest answer is "there is nothing here" - not "your data held".
      const problems = [];
      if (claimsSafety(empty.out)) problems.push('it claimed safety over a schema with no tables');
      if (!/no tables|nothing to|empty/i.test(empty.out)) {
        problems.push('it does not say the schema is empty: ' + empty.out.trim());
      }
      return problems;
    })());

    const wrongHost = 'postgresql://nobody:nothing@127.0.0.1:1/none';
    const broken = cli([wrongHost, 'public']);
    check('4. a connection that cannot be made is one line, not a stack trace', (() => {
      const problems = [];
      if (looksLikeACrash(broken.out)) problems.push('it printed a stack trace: ' + broken.out.trim().split('\n').slice(0, 3).join(' | '));
      if (claimsSafety(broken.out)) problems.push('it claimed safety having never connected');
      if (broken.code === 0) problems.push('it exited 0 without connecting');
      if (!/could not|cannot|unable/i.test(broken.out)) problems.push('it does not say it could not connect');
      return problems;
    })());

    const noArgs = cli([]);
    check('5. running it with nothing tells you how to run it', (() => {
      const problems = [];
      if (!/scan\.js/.test(noArgs.out)) problems.push('no usage line');
      if (noArgs.code !== 2) problems.push('exit code was ' + noArgs.code + ', expected 2');
      return problems;
    })());

    check('6. the connection string can be given without putting it in shell history', (() => {
      // Typed on the command line it lands in .bash_history and in the process
      // list, where anybody on the machine can read it. It is the credential to
      // the customer's entire database.
      const problems = [];
      const viaEnv = cli([EMPTY], { KN_DATABASE_URL: CONNECTION });
      if (/scan\.js "<connection string>"/.test(viaEnv.out)) {
        problems.push('the environment variable is not accepted, so the only way is the command line');
      }
      if (looksLikeACrash(viaEnv.out)) problems.push('it crashed instead: ' + viaEnv.out.trim().split('\n')[0]);
      return problems;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(EMPTY) + ' CASCADE').catch(() => {});
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
    console.log('All ' + results.length + ' usability checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
