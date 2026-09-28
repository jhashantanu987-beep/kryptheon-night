// The first ninety seconds, which are the only ones most people will give it.
//
// Needs no database. Everything here is either the wording a person reads
// before agreeing to anything, or the gate that wording is attached to -
// checked through the real command, because a consent screen that is printed
// and then not honoured is worse than no consent screen at all.

// A run this check causes is saved to a scratch store, never the real
// ~/.kryptheon (see store.js).
process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const path = require('path');
const { spawnSync } = require('child_process');
const intro = require('./intro.js');

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

const COMMAND = path.join(__dirname, 'bin', 'kryptheon-night.js');

// Well formed, real shape, and nothing is listening. Anything that gets as
// far as connecting fails, which is what makes "did it try to connect" a
// readable answer.
const NOWHERE = 'postgresql://postgres:pw@127.0.0.1:1/postgres';

/**
 * Runs the command the way a scheduler would: no keyboard attached.
 *
 * Deliberately not a TTY. That is what makes the two gates below observable -
 * with nobody to ask, a command that needs an answer has to stop, and a
 * command that stops is one this check can measure.
 */
function cli(args, env) {
  const before = process.env.KN_PRELOAD ? ['--require', process.env.KN_PRELOAD] : [];
  const r = spawnSync(process.execPath, before.concat([COMMAND], args), {
    cwd: __dirname,
    encoding: 'utf8',
    timeout: 120000,
    env: Object.assign({}, process.env, { KN_DATABASE_URL: '' }, env || {}),
  });
  return { out: String(r.stdout || '') + String(r.stderr || ''), code: r.status };
}

/** Words the person this is for has never had to learn. */
const JARGON = /\bschema\b|\bRLS\b|row level security|\bpolic(y|ies)\b|\brollback\b|\btransaction\b|\bDDL\b|\bintrospect|\bpg_|\bSQL\b|\bgrant(s|ed)?\b/i;

function main() {
  /* ---- what is promised, before anything is connected to ---- */

  const consent = intro.consentLines('public');

  check('1. the consent screen makes all four promises, in so many words', (() => {
    // These are the four things somebody is actually frightened of, and each
    // one is a thing the code is built to make true - `untouched.check.js`
    // photographs the whole database and fails if any of it moved.
    const text = consent.join(' ');
    const problems = [];
    const promises = [
      [/do not read your real data|not one customer/i, 'that it does not read real data'],
      [/do not change your real tables/i, 'that it does not change real tables'],
      [/do not send anything anywhere/i, 'that it sends nothing anywhere'],
      [/do not leave anything behind|deleted when I finish/i, 'that it leaves nothing behind'],
      [/stays on this computer/i, 'that the connection string does not travel'],
    ];
    for (const [pattern, what] of promises) {
      if (!pattern.test(text)) problems.push('it does not promise ' + what);
    }
    return problems;
  })());

  check('2. it says what it WILL do before it asks, not only what it will not', (() => {
    const text = consent.join(' ');
    const problems = [];
    if (!/temporary/i.test(text)) problems.push('it does not say it creates anything');
    if (!/fake|made-up/i.test(text)) problems.push('it does not say the people it attacks are invented');
    if (!/attack/i.test(text)) problems.push('it does not say it attacks anything');
    return problems;
  })());

  check('3. the consent screen is in words a non-programmer knows', (() => {
    // The whole reason this file exists. "I will introspect your schema and
    // replay your RLS policies" is a true sentence that tells this person
    // nothing, and asking them to agree to it is not consent.
    const problems = [];
    for (const l of consent) {
      const found = l.match(JARGON);
      if (found) problems.push('jargon "' + found[0] + '" in: ' + l.trim());
    }
    return problems;
  })());

  check('4. it names the part of the database it is about to look at', (() => {
    const problems = [];
    if (!intro.consentLines('shop').join(' ').includes('"shop"')) {
      problems.push('the consent screen does not say which part it will read');
    }
    return problems;
  })());

  check('5. finding the connection string is described as buttons, not concepts', (() => {
    // "Get your database connection string" is not an instruction to
    // somebody who does not know the phrase. Screen names and what to click.
    const text = intro.whereToFindIt().join(' ');
    const problems = [];
    for (const [needle, what] of [
      [/Project Settings/i, 'the Project Settings screen'],
      [/Database/i, 'the Database tab'],
      [/Connection string/i, 'the section it is in'],
      [/URI/i, 'which of the tabs'],
      [/\[YOUR-PASSWORD\]/, 'that the password has to be filled in'],
      [/postgresql:\/\//, 'what it looks like'],
    ]) {
      if (!needle.test(text)) problems.push('it does not name ' + what);
    }
    if (!/Lovable/i.test(text)) problems.push('it does not tell a Lovable user where to go');
    return problems;
  })());

  /* ---- only a yes is a yes ---- */

  check('6. anything that is not a yes is a no', (() => {
    const problems = [];
    for (const yes of ['y', 'Y', 'yes', 'YES', ' yes ', 'Yes']) {
      if (!intro.isYes(yes)) problems.push(JSON.stringify(yes) + ' was not taken as a yes');
    }
    // An empty line is somebody pressing Enter to make the screen go away.
    for (const no of ['', ' ', 'n', 'no', 'maybe', 'ok', 'sure', 'yeah', 'yep', 'k', null, undefined]) {
      if (intro.isYes(no)) problems.push(JSON.stringify(no) + ' was taken as permission to connect');
    }
    return problems;
  })());

  /* ---- and the gate is really a gate ---- */

  const ungated = cli([], { KN_DATABASE_URL: NOWHERE });
  check('7. with nobody to ask and no --yes, it does not connect', (() => {
    // The consent screen is only worth printing if this is true. Checked
    // through the real command, because the gate lives in the command.
    const problems = [];
    if (/Connecting/.test(ungated.out)) problems.push('it tried to connect without being told yes');
    if (ungated.code !== 2) problems.push('exit code was ' + ungated.code + ', expected 2');
    if (!/told yes|--yes/.test(ungated.out)) problems.push('it does not say why it stopped: ' + ungated.out.trim());
    return problems;
  })());

  const gated = cli(['--yes'], { KN_DATABASE_URL: NOWHERE });
  check('8. with --yes it goes ahead, so check 7 is measuring the gate', (() => {
    // Without this, check 7 would pass just as happily on a command that
    // never connects to anything at all.
    const problems = [];
    if (!/Connecting/.test(gated.out)) problems.push('--yes did not get as far as connecting: ' + gated.out.trim());
    return problems;
  })());

  const nothingToAsk = cli(['--yes'], {});
  check('9. no connection string and nobody to ask is said plainly', (() => {
    const problems = [];
    if (!/nobody here to ask|KN_DATABASE_URL/.test(nothingToAsk.out)) {
      problems.push('it does not say what to do: ' + nothingToAsk.out.trim());
    }
    if (nothingToAsk.code !== 2) problems.push('exit code was ' + nothingToAsk.code + ', expected 2');
    return problems;
  })());

  check('10. an unknown option is not silently ignored', (() => {
    // Silently ignoring `--dry-run` would mean running a real scan on
    // somebody who thought they had asked for a rehearsal.
    const problems = [];
    const odd = cli(['--dry-run', '--yes'], { KN_DATABASE_URL: NOWHERE });
    if (/Connecting/.test(odd.out)) problems.push('it ran anyway');
    if (odd.code !== 2) problems.push('exit code was ' + odd.code + ', expected 2');
    if (!/--dry-run/.test(odd.out)) problems.push('it does not name the option it did not understand');
    return problems;
  })());

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
    console.log('All ' + results.length + ' first-run checks passed.');
  }
}

main();
