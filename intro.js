// What the person is asked, and what they are told before anything runs.
//
// This file is the whole difference between a tool for people who write code
// and a tool for people who do not. The engine behind it does not change; the
// first ninety seconds do.
//
// Two things happen here and both are deliberate.
//
// Asking, rather than requiring. `KN_DATABASE_URL=... node scan.js public` is
// three unfamiliar ideas at once: an environment variable, a connection
// string, and a schema. Somebody who has only ever clicked Deploy has met
// none of them. So the command takes no arguments, and asks.
//
// Telling before doing. This tool connects to a person's production database
// with the owner's credential and creates things in it. Nobody should agree
// to that from a package name. What it does, what it does not do, and then a
// yes or no - in that order, before the first statement is sent.

const readline = require('readline');
const trouble = require('./trouble.js');

/**
 * Where the connection string is, said as buttons rather than as concepts.
 *
 * Named screen by screen because "get your connection string" is not an
 * instruction to somebody who does not know the phrase. Supabase first
 * because that is who this is for; Lovable and Bolt build on Supabase, so
 * their users end up on the same page by a different door.
 */
function whereToFindIt() {
  // The session pooler, and said as such: the direct connection answers only
  // over IPv6, which many home networks do not have, and the transaction
  // pooler on 6543 cannot hold these attacks together. The kryptheon
  // dashboard shows these same steps; kryptheon-night words hands them over.
  return [
    'Where to find it:',
    '',
    '  Supabase   1. supabase.com/dashboard -> open your project.',
    '             2. Press "Connect" at the top of the page.',
    '             3. Choose "Session pooler" - the one on port 5432.',
    '             4. Copy the URI. It starts postgresql://',
    '             5. Replace [YOUR-PASSWORD] in it with your database password.',
    '                Forgotten it? Project Settings -> Database -> Reset',
    '                database password.',
    '',
    '             Not port 6543 (the transaction pooler), and not the direct',
    '             db.<project>.supabase.co address - both are warned about.',
    '',
    '  Lovable    your app uses Supabase underneath. Open the Supabase',
    '  and Bolt   project it made for you and follow the lines above.',
    '',
    '  Neon       console.neon.tech -> your project -> Connection Details.',
    '',
    'It is one long line beginning postgresql:// and it ends in /postgres.',
  ];
}

/**
 * What is about to happen, and what is not.
 *
 * The second half matters more than the first. Everybody who runs this is
 * being asked to hand a stranger's program the key to their live database,
 * and the fears they have are specific: will you read my customers, will you
 * send anything anywhere, will you leave a mess. Each of those is answered in
 * its own line, in the words they would use.
 *
 * Nothing here is a promise made only on this screen. Every line is something
 * the code is built to make true and a check in this repo fails if it stops
 * being true - `untouched.check.js` photographs the whole database and
 * compares it afterwards.
 */
function consentLines(target) {
  return [
    'Before I touch anything, here is exactly what I am going to do.',
    '',
    'What I will do:',
    '',
    '  - Look at the shape of your "' + target + '" tables: their names, their',
    '    columns, and the rules about who is allowed to see what.',
    '',
    '  - Make one new temporary space inside your database and rebuild that',
    '    same shape in it. Your real tables are not changed.',
    '',
    '  - Put two made-up people in the copy - fake names, fake emails.',
    '',
    '  - Attack the copy. I try to read those two fake people as a stranger',
    '    would, try to change their rows, try to break them.',
    '',
    '  - Tell you what got through, and delete the copy.',
    '',
    'What I will not do:',
    '',
    '  - I do not read your real data. Not one customer, order or message.',
    '    Every row I read is a row I put there myself a moment earlier.',
    '',
    '  - I do not change your real tables. Only the temporary copy.',
    '',
    '  - I do not send anything anywhere. No account, no upload, no server of',
    '    mine. Your connection string stays on this computer and is not',
    '    written to any file.',
    '',
    '  - I do not leave anything behind. The copy is deleted when I finish,',
    '    and also if I crash.',
    '',
    'This takes two or three minutes.',
  ];
}

/**
 * What staying costs, said before anything is left behind.
 *
 * The scan's consent screen above ends "I do not leave anything behind", and
 * that is true of a scan and false of an install. Reusing it here would be
 * the product lying on the one screen it exists to be honest on, so this is
 * its own text and says the opposite plainly, first.
 *
 * Everything that gets left is named, because "it installs a few things" is
 * the sentence somebody agrees to and then finds a `cron` schema they did not
 * recognise. And the way out is on the screen where they say yes, not in a
 * README they will not read again.
 */
function installConsentLines(schema, source, at) {
  return [
    'This one stays. Everything else this tool does is temporary; this is not.',
    '',
    'What I will leave in your database:',
    '',
    '  - A schema called "' + schema + '", holding the functions that do the',
    '    checking. No data of yours goes in it.',
    '',
    '  - Two Postgres extensions, if they are not already there: pg_cron, which',
    '    runs things on a schedule, and pg_net. Supabase provides both.',
    '',
    '  - One scheduled job, named kryptheon_nightly, set to ' + at + '.',
    '',
    'What it will do, every night:',
    '',
    '  - Exactly what the scan does now - copy the shape of your "' + source + '"',
    '    tables into a temporary space, put two made-up people in it, attack',
    '    that, write down what got through, and delete the copy.',
    '',
    '  - It still never reads your real data, and still sends nothing anywhere.',
    '    Nothing leaves your database, because the checking happens inside it.',
    '',
    'One thing it cannot do:',
    '',
    '  - It cannot race two requests against each other, which is how the',
    '    "can this exist twice" question is answered. That needs two',
    '    connections at the same instant, and nothing living inside a database',
    '    has them. The nightly report names every column it could not race.',
    '    Running the command by hand still tests them properly.',
    '',
    'To take it all away again:  npx kryptheon-night uninstall',
    '',
    'That removes the job, the schema, and any extension I had to add - and',
    'leaves alone anything that was already here.',
  ];
}

/** Asks a question and hands back what was typed. */
function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(String(answer || '').trim());
    });
  });
}

/**
 * Asks for something that must not be echoed.
 *
 * The connection string carries the password to the entire database. Shown on
 * screen it is read by whoever is behind them, and it stays in the scrollback
 * of whatever terminal they are in for as long as that window is open.
 *
 * Nothing is printed as they type - not even stars, because a pasted string
 * of stars is no more checkable than nothing and the character count alone
 * says how long the password is. What they get instead is the address read
 * back to them afterwards, with the password removed, which is the part they
 * would actually want to check.
 */
function askSecret(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let silent = false;
    // readline writes every keystroke back to the screen itself. This replaces
    // that with nothing, but only once the prompt has been written - otherwise
    // the question never appears either.
    rl._writeToOutput = function (text) {
      if (!silent) rl.output.write(text);
    };
    rl.question(question, (answer) => {
      silent = false;
      rl.output.write('\n');
      rl.close();
      resolve(String(answer || '').trim());
    });
    silent = true;
  });
}

/**
 * Was that a yes?
 *
 * The question being answered is "may I connect to your production database",
 * so the rule is that only a yes is a yes. A stray newline, a shrug, an
 * accidental Enter on an empty line - none of those are permission, and the
 * cost of getting this backwards is connecting to somebody's live database
 * without being asked to.
 *
 * Separate from the asking so it can be checked directly. Every form of this
 * that hid inside a prompt went unchecked.
 */
function isYes(answer) {
  const said = String(answer == null ? '' : answer).trim().toLowerCase();
  return said === 'y' || said === 'yes';
}

/** Yes or no, where anything that is not a clear yes is a no. */
async function askYesNo(question) {
  return isYes(await ask(question));
}

/**
 * The connection string, from wherever it can be had.
 *
 * The environment variable is checked first so that anybody scripting this
 * never sees a prompt, and so the string does not have to be retyped on every
 * run. Nothing is saved: asked again next time is the correct behaviour for a
 * credential this powerful, and a file holding it would be the one thing this
 * tool tells people not to do.
 */
async function askForConnection(say) {
  say('');
  say('  I need the connection string for your database.');
  say('');
  say('  It is one line that lets me connect. It contains your database');
  say('  password, so I will not show it on screen as you paste it, and I do');
  say('  not save it anywhere.');
  say('');
  whereToFindIt().forEach((l) => say('  ' + l));
  say('');

  const given = await askSecret('  Paste it here and press Enter: ');
  return given;
}

module.exports = {
  whereToFindIt: whereToFindIt,
  consentLines: consentLines,
  installConsentLines: installConsentLines,
  ask: ask,
  askSecret: askSecret,
  askYesNo: askYesNo,
  isYes: isYes,
  askForConnection: askForConnection,
  // Re-exported so the command has one place to reach for the wording of a
  // failure, rather than two.
  withoutSecret: trouble.withoutSecret,
};
