// What the person sees when it goes wrong before it has even started.
//
// Needs no database, on purpose. Every other suite here needs a real Postgres
// and a connection string, which means none of them can be run by somebody
// who has just cloned this - and the wording of a failure is the part of the
// product most likely to be edited casually.
//
// Two of the cases below are not made up. A connection is genuinely opened to
// a host that does not exist and to a port with nothing behind it, and the
// error object Node actually produced is what gets handed to `explain`.
// Hand-written fakes are how a mapping keyed on `err.code` passes for months
// while the real error arrives with the code somewhere else.

const { Client } = require('pg');
const trouble = require('./trouble.js');
const { howToConnect } = require('./connect.js');

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

const SECRET = 'hunter2SuperSecret';
const GOOD = 'postgresql://postgres:' + SECRET + '@db.abcdefghij.supabase.co:5432/postgres';

/** The shapes of text that mean the tool gave up rather than explained. */
function looksTechnical(lines) {
  const text = lines.join('\n');
  return /\bat [A-Za-z_$][\w$]*\s*\(|node:internal|errno|ECONN|ENOTFOUND|EHOSTUNREACH|\b28P01\b|\b3D000\b/.test(text);
}

/** Every failure has to end with something the person can go and do. */
function saysWhatToDo(lines) {
  const text = lines.join(' ');
  return /Supabase|Replace|Check|check|Use |Try |Close |try again|paste|Copy|add /.test(text);
}

async function realError(connectionString) {
  const client = new Client({ connectionString: connectionString, connectionTimeoutMillis: 8000 });
  try {
    await client.connect();
    await client.end().catch(() => {});
    return null;
  } catch (err) {
    await client.end().catch(() => {});
    return err;
  }
}

async function main() {
  /* ---- reading the string, before anything is connected to ---- */

  check('1. a good Supabase string is accepted', (() => {
    const problems = [];
    if (trouble.readConnectionString(GOOD)) problems.push('a valid string was refused');
    // Quotes survive a copy out of a code block and must not be fatal.
    if (trouble.readConnectionString('"' + GOOD + '"')) problems.push('a quoted string was refused');
    if (trouble.readConnectionString('  ' + GOOD + '  ')) problems.push('a string with spaces round it was refused');
    return problems;
  })());

  check('2. the Supabase password placeholder is named, not sent to Postgres', (() => {
    // The single most common first mistake. Sent on, Postgres answers
    // "password authentication failed", which sends the person off resetting
    // a password that was never wrong.
    const problems = [];
    for (const placeholder of trouble.PLACEHOLDERS) {
      const said = trouble.readConnectionString(
        'postgresql://postgres:' + placeholder + '@db.abc.supabase.co:5432/postgres',
      );
      if (!said) {
        problems.push(placeholder + ' was passed through as if it were a password');
        continue;
      }
      if (!said.join(' ').includes(placeholder)) problems.push(placeholder + ' is not named in the message');
      if (!saysWhatToDo(said)) problems.push(placeholder + ' message does not say what to do');
    }
    return problems;
  })());

  check('3. a project URL is not mistaken for a connection string', (() => {
    const problems = [];
    const said = trouble.readConnectionString('https://abcdefghij.supabase.co');
    if (!said) return ['a https:// address was accepted as a connection string'];
    if (!/web address|project URL/i.test(said.join(' '))) problems.push('it does not say what that is: ' + said.join(' '));
    if (!saysWhatToDo(said)) problems.push('it does not say where the real one is');
    return problems;
  })());

  check('4. an API key is recognised, and the dangerous one is called out', (() => {
    // Both Supabase keys are JWTs and both get pasted here. One of them is
    // the service_role key, which is a more serious thing to have loose than
    // the string being asked for, so the message says so.
    const problems = [];
    const said = trouble.readConnectionString('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.xxx');
    if (!said) return ['a JWT was accepted as a connection string'];
    if (!/API key/i.test(said.join(' '))) problems.push('it does not say it is an API key');
    if (!/service_role/i.test(said.join(' '))) problems.push('it does not warn about the service_role key being exposed');
    return problems;
  })());

  check('5. a string with no password in it is caught here, not by Postgres', (() => {
    const problems = [];
    const said = trouble.readConnectionString('postgresql://postgres@db.abc.supabase.co:5432/postgres');
    if (!said) return ['a passwordless string was accepted'];
    if (!/password/i.test(said.join(' '))) problems.push('it does not mention the password');
    return problems;
  })());

  check('6. something that is not a URL at all is refused readably', (() => {
    const problems = [];
    for (const rubbish of ['', '   ', 'hello', 'postgres db please', 'mysql://root:x@localhost/app']) {
      const said = trouble.readConnectionString(rubbish);
      if (!said) {
        problems.push(JSON.stringify(rubbish) + ' was accepted as a connection string');
        continue;
      }
      if (looksTechnical(said)) problems.push(JSON.stringify(rubbish) + ' produced something technical');
      if (!saysWhatToDo(said)) problems.push(JSON.stringify(rubbish) + ' does not say what to do');
    }
    return problems;
  })());

  check('7. the transaction pooler is warned about, and 5432 is not', (() => {
    // Port 6543 gives every statement a different backend. The attack has to
    // change role and read inside one transaction, so it cannot survive that
    // - and the failure it produces looks like the app defending itself.
    const problems = [];
    const pooled = trouble.poolerWarning('postgresql://postgres.abc:pw@aws-0-ap-south-1.pooler.supabase.com:6543/postgres');
    if (!pooled) problems.push('the transaction pooler was not warned about');
    else if (!/6543|session pooler/i.test(pooled.join(' '))) problems.push('the warning does not say which one to use instead');

    if (trouble.poolerWarning('postgresql://postgres.abc:pw@aws-0-ap-south-1.pooler.supabase.com:5432/postgres')) {
      problems.push('the session pooler was warned about, and it is the one that works');
    }
    if (trouble.poolerWarning(GOOD)) problems.push('a direct connection was warned about');
    return problems;
  })());

  /* ---- the password, which must not come back out ---- */

  check('8. nothing ever prints the password back', (() => {
    const problems = [];
    const shown = trouble.withoutSecret(GOOD);
    if (shown.includes(SECRET)) problems.push('withoutSecret printed the password: ' + shown);
    if (!shown.includes('db.abcdefghij.supabase.co')) problems.push('withoutSecret hid the part worth checking: ' + shown);

    // The catch-all branch is the one that quotes things back, so it is the
    // one that could carry a credential into a screenshot.
    const generic = trouble.explain(new Error('something nobody has mapped yet'), GOOD);
    if (generic.join('\n').includes(SECRET)) problems.push('explain() echoed the password');
    return problems;
  })());

  /* ---- real failures, from a real driver ---- */

  const missing = await realError('postgresql://postgres:pw@no-such-host.invalid:5432/postgres');
  check('9. a server that does not exist (real error from pg)', (() => {
    const problems = [];
    if (!missing) return ['no-such-host.invalid resolved, so nothing was tested'];
    const said = trouble.explain(missing, 'postgresql://postgres:pw@no-such-host.invalid:5432/postgres');
    if (looksTechnical(said)) problems.push('it passed the technical error through: ' + said.join(' | '));
    if (!/could not find|not online|typo/i.test(said.join(' '))) {
      problems.push('it did not recognise ' + missing.code + ': ' + said.join(' | '));
    }
    return problems;
  })());

  const shut = await realError('postgresql://postgres:pw@127.0.0.1:1/postgres');
  check('10. a port with nothing behind it (real error from pg)', (() => {
    const problems = [];
    if (!shut) return ['127.0.0.1:1 accepted a connection, so nothing was tested'];
    const said = trouble.explain(shut, 'postgresql://postgres:pw@127.0.0.1:1/postgres');
    if (looksTechnical(said)) problems.push('it passed the technical error through: ' + said.join(' | '));
    if (!saysWhatToDo(said)) problems.push('it does not say what to do: ' + said.join(' | '));
    return problems;
  })());

  check('11. every canned failure is a sentence, not a code', (() => {
    // Walked rather than listed, so a branch added later is covered without
    // anybody remembering to come back here.
    const problems = [];
    const fakes = [
      { code: '28P01' }, { code: '28000' }, { code: '3D000' }, { code: '42501' },
      { code: '53300' }, { code: '57P03' }, { code: 'ENOTFOUND' }, { code: 'ECONNREFUSED' },
      { code: 'ETIMEDOUT' }, { code: 'EHOSTUNREACH' }, { code: 'ENETUNREACH' }, { code: 'ECONNRESET' },
      { message: 'self-signed certificate in certificate chain' },
      { message: 'timeout expired' },
    ];
    for (const fake of fakes) {
      const said = trouble.explain(fake, GOOD);
      const what = fake.code || fake.message;
      if (!said.length) problems.push(what + ' produced nothing');
      if (looksTechnical(said)) problems.push(what + ' leaked the code into the message: ' + said.join(' | '));
      if (!saysWhatToDo(said)) problems.push(what + ' does not say what to do: ' + said.join(' | '));
    }
    return problems;
  })());

  check('12. an unmapped failure still says something, and keeps the original', (() => {
    // A branch nobody has written yet must not become a blank screen. The
    // server's own words are kept so the person has something to search for.
    const problems = [];
    const said = trouble.explain(new Error('the flux capacitor is misaligned'), GOOD);
    if (!said.join(' ').includes('the flux capacitor is misaligned')) {
      problems.push('the original message was swallowed: ' + said.join(' | '));
    }
    if (!/could not connect/i.test(said.join(' '))) problems.push('it does not say what failed');
    return problems;
  })());

  /* ---- how the connection is actually opened ---- */

  check('13. the password is never sent unencrypted', (() => {
    // `pg` leaves SSL off entirely when the string says nothing about it, so
    // a string copied from somewhere that does not add sslmode would put the
    // credential to somebody's whole database on the wire in the clear.
    const problems = [];
    const plain = howToConnect('postgresql://postgres:pw@db.abc.supabase.co:5432/postgres');
    if (!plain.ssl) problems.push('a string with no sslmode was going to connect unencrypted');
    if (plain.ssl && plain.ssl.rejectUnauthorized !== false) {
      problems.push('it would verify the certificate, which Supabase’s own authority fails');
    }
    // A database on this machine is not crossing a network and usually has no
    // certificate at all.
    if (howToConnect('postgresql://postgres:pw@localhost:5432/postgres').ssl) {
      problems.push('it demanded a certificate from a database on this machine');
    }
    return problems;
  })());

  check('14. the sslmode the hosts hand out is replaced, and a chosen one is not', (() => {
    // Measured: this driver reads sslmode=require as full verification AND
    // prints a nine-line upgrade notice while doing it. Neon's own string
    // ends in ?sslmode=require, so following the instructions on screen put
    // that notice in the middle of a person's security report.
    const problems = [];
    for (const handed of ['require', 'prefer']) {
      const config = howToConnect('postgresql://postgres:pw@db.abc.supabase.co:5432/postgres?sslmode=' + handed);
      if (/sslmode/i.test(config.connectionString)) problems.push('sslmode=' + handed + ' was left in the string');
      if (!config.ssl) problems.push('sslmode=' + handed + ' was dropped without turning encryption on');
    }
    // Somebody who typed one of these meant it, and it is not ours to undo.
    for (const chosen of ['verify-full', 'no-verify', 'disable']) {
      const config = howToConnect('postgresql://postgres:pw@db.abc.supabase.co:5432/postgres?sslmode=' + chosen);
      if (!config.connectionString.includes('sslmode=' + chosen)) {
        problems.push('sslmode=' + chosen + ' was overridden, and it was deliberate');
      }
      if (config.ssl) problems.push('sslmode=' + chosen + ' was overridden with our own setting');
    }
    // Everything else in the string has to survive being taken apart.
    const kept = howToConnect('postgresql://postgres:pw@db.abc.supabase.co:5432/postgres?sslmode=require&application_name=kn');
    if (!kept.connectionString.includes('application_name=kn')) problems.push('another parameter was lost');
    if (!kept.connectionString.includes(':pw@')) problems.push('the password was lost rewriting the string');
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
    console.log('All ' + results.length + ' wording checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
