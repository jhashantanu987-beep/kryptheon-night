// Checks that a read which failed is never mistaken for a table that held.
// Run with:  node blocked.check.js "<postgres connection string>"
//
// This is the quietest way the product can lie. The attack reads a table as a
// stranger and gets nothing back. Two completely different things produce that:
//
//   the rule looked at the request and refused it     -> the app is safe
//   the rule could not be evaluated at all            -> nothing is known
//
// Both come back as zero rows. A policy calling a function the role may not
// execute throws; so does a policy whose expression fails to cast. In every one
// of those the table looks exactly as safe as a table that was genuinely
// defended, and the report used to say so.
//
// Taking USAGE off the auth schema does NOT do it - that was measured, and the
// read still succeeded, because a policy's function reference is resolved when
// the policy is created. Revoking EXECUTE on the function is what actually
// stops the rule being evaluated, and that is what this builds.
//
// One refusal IS an answer and has to stay one: "permission denied for table
// orders" means the caller cannot reach it at all, which is the attack being
// beaten. Calling that "not checked" would flood a well-built app with
// warnings and teach the person to ignore them.
//
// Both apps here are deliberately broken in that specific way, and everything
// is dropped at the end.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};
const STAMP = Date.now().toString(36);

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

async function groundwork(client, name, options) {
  const opts = options || {};
  await client.query('CREATE SCHEMA ' + schema.quote(name));
  for (const role of ['anon', 'authenticated']) {
    await client.query(
      'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ' + "'" + role + "'" +
        ') THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(name) + ' TO ' + role);
  }
  undoAuth = await fixture.ensureAuth(client);

  // The policy below calls a function nobody may execute. It lives in this
  // check's own schema and auth.uid() is never touched.
  //
  // It used to revoke EXECUTE on auth.uid() itself. That was fine only while
  // the checks dropped the auth schema afterwards; the moment they stopped
  // doing that - because dropping somebody's auth schema is unforgivable - the
  // revoke simply stayed behind, poisoning every check that ran later. On a
  // real project it would have taken row level security out for the entire
  // application and left it that way. A check that leaves the database worse
  // than it found it is not a check.
  await client.query(
    'CREATE FUNCTION ' + schema.quote(name) + '.whoami() RETURNS uuid LANGUAGE sql STABLE AS $$ ' +
      "SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid $$",
  );
  if (opts.canCallAuth === false) {
    // Measured, not guessed: taking USAGE off a schema changes nothing,
    // because a policy's function reference is resolved when the policy is
    // created. What actually stops the rule being evaluated is EXECUTE on the
    // function itself, and that is what a locked-down project revokes.
    await client.query(
      'REVOKE EXECUTE ON FUNCTION ' + schema.quote(name) + '.whoami() FROM PUBLIC, anon, authenticated',
    );
  }
}

function openSessionFor(connection) {
  return async () => {
    const extra = new Client({ connectionString: connection });
    await extra.connect();
    return extra;
  };
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node blocked.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  const CANNOT = 'kn_blocked_a_' + STAMP;
  const CLOSED = 'kn_blocked_b_' + STAMP;

  try {
    /* ---- an app whose policies cannot be evaluated by the caller ---- */
    // The policy calls auth.uid() and the roles may not execute it. Every
    // read throws, every table returns nothing, and every table looks
    // perfectly secure.
    await groundwork(client, CANNOT, { canCallAuth: false });
    const qa = (t) => schema.quote(CANNOT) + '.' + schema.quote(t);
    await client.query('CREATE TABLE ' + qa('customers') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)');
    await client.query('GRANT SELECT ON ' + qa('customers') + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + qa('customers') + ' ENABLE ROW LEVEL SECURITY');
    await client.query(
      'CREATE POLICY own ON ' + qa('customers') +
        ' FOR SELECT TO anon, authenticated USING (owner = ' + schema.quote(CANNOT) + '.whoami())',
    );

    const cannot = await scan(client, CANNOT, { quiet: true, openSession: openSessionFor(CONNECTION) });

    check('1. a rule that could not be evaluated is not reported as safe', (() => {
      const problems = [];
      if (cannot.stopped) return ['the scan stopped instead: ' + String(cannot.stopped).split('\n')[0]];
      const missed = (cannot.notChecked || []).map((m) => m.table);
      if (!missed.includes('customers')) {
        problems.push('customers was not flagged as unchecked: ' + JSON.stringify(cannot.notChecked));
      }
      if ((cannot.attempted || []).some((key) => key.endsWith(':customers'))) {
        problems.push('it counted an attack that threw as having run: ' + JSON.stringify(cannot.attempted));
      }
      return problems;
    })());

    check('2. the report says so out loud rather than saying everything held', (() => {
      const problems = [];
      const said = [];
      const originalWrite = process.stdout.write;
      process.stdout.write = (text) => { said.push(String(text)); return true; };
      try {
        require('./scan.js').report(cannot);
      } finally {
        process.stdout.write = originalWrite;
      }
      const text = said.join('');
      if (!/NOT checked/.test(text)) problems.push('the report does not mention it at all');
      if (/Nothing got through/.test(text)) problems.push('it printed the all-clear over a table it could not test');
      if (!/unknown, not as clear/.test(text)) problems.push('it does not say unknown is not the same as clear');
      return problems;
    })());

    check('3. the reason is passed on, not swallowed', (() => {
      const problems = [];
      const entry = (cannot.notChecked || []).find((m) => m.table === 'customers');
      if (!entry) return ['nothing to carry a reason'];
      if (!/permission denied for function whoami/i.test(String(entry.why))) {
        problems.push('the reason does not point at what actually failed: ' + entry.why);
      }
      return problems;
    })());

    /* ---- an app where the table is simply not granted ---- */
    // This one IS an answer. The stranger cannot reach the table at all, which
    // is the attack losing. It must come back clean, with no warning.
    await groundwork(client, CLOSED, {});
    const qb = (t) => schema.quote(CLOSED) + '.' + schema.quote(t);
    await client.query('CREATE TABLE ' + qb('ledger') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, amount numeric(10,2) NOT NULL)');
    // Deliberately no GRANT at all: PostgREST could not read this if it tried.

    const closed = await scan(client, CLOSED, { quiet: true, openSession: openSessionFor(CONNECTION) });

    check('4. a table nobody was granted is a pass, not a warning', (() => {
      const problems = [];
      if (closed.stopped) return ['the scan stopped instead: ' + String(closed.stopped).split('\n')[0]];
      if (closed.findings.length) problems.push('it found a problem in a table nobody can reach');
      const missed = (closed.notChecked || []).map((m) => m.table);
      if (missed.includes('ledger')) {
        problems.push('being refused outright was filed as not checked, which would warn about every correct table');
      }
      if (!(closed.attempted || []).some((key) => key.endsWith(':ledger'))) {
        problems.push('the attack ran and lost, and that was not recorded as having run');
      }
      return problems;
    })());
  } finally {
    for (const name of [CANNOT, CLOSED]) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
    }
    await undoAuth();
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
    console.log('All ' + results.length + ' blocked-read checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
