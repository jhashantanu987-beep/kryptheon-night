// Checks that "the same thing can exist twice" is only ever said when it can.
// Run with:  node collision.check.js "<postgres connection string>"
//
// This one needs a real database on purpose. Whether a column is already
// protected is read out of the Postgres catalogue, and the catalogue's shapes
// are the thing that has gone wrong before - a unique index and a UNIQUE
// constraint are different objects, a composite unique reads nothing like a
// single one, and a partial index carries a WHERE clause. Hand-written
// fixtures would agree with whatever the code believed.
//
// Most of what follows is about NOT reporting. A collision finding says the
// builder's schema is missing something, and being wrong about that is worse
// than being quiet - there is no way to un-say it, and a person who has been
// sent chasing one imaginary problem reads the next report differently.
//
// The app built here has one of every case:
//
//   users        email not unique                     -> report it
//                username has a unique INDEX          -> leave it alone
//                email_hash IS unique, and its name
//                contains "email"                     -> must not make email
//                                                        look protected
//   members      UNIQUE (org_id, email)               -> leave it alone
//                (same email in two orgs is correct)
//   invites      partial unique index on invite_code  -> leave it alone
//   sessions     session_token not unique             -> report it
//   coupons      coupon_code not unique               -> report it, lower
//   customers    email not unique, ambiguous table    -> leave it alone
//   events       token_id, has_token                  -> near-misses, not tokens
//   accounts     email not unique, api_key UNIQUE     -> report email, and the
//                                                        other unique column
//                                                        must not block it
//   tickets      token, plus a CHECK nothing can pass -> could not be tested
//
// Everything is dropped at the end, whatever happened.

const { Client } = require('pg');
const schema = require('./schema.js');
const collision = require('./collision.js');
const finding = require('./finding.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_col_' + Date.now().toString(36);

/** Every shape worth getting right, in one schema. */
async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));

  // email_hash is unique and email is not. The two names overlap, which is the
  // whole point: anything matching on a substring rather than a whole word
  // sees "email" inside "email_hash", decides email is protected, and says
  // nothing about a table anyone can register into twice.
  await client.query(
    'CREATE TABLE ' + q('users') +
      ' (id serial PRIMARY KEY, email text NOT NULL, email_hash text NOT NULL, username text NOT NULL)',
  );
  await client.query('CREATE UNIQUE INDEX users_username_key ON ' + q('users') + ' (username)');
  await client.query('CREATE UNIQUE INDEX users_email_hash_key ON ' + q('users') + ' (email_hash)');

  await client.query(
    'CREATE TABLE ' + q('members') +
      ' (id serial PRIMARY KEY, org_id int NOT NULL, email text NOT NULL, UNIQUE (org_id, email))',
  );

  await client.query(
    'CREATE TABLE ' + q('invites') + ' (id serial PRIMARY KEY, invite_code text NOT NULL, deleted_at timestamptz)',
  );
  await client.query(
    'CREATE UNIQUE INDEX invites_code_key ON ' + q('invites') + ' (invite_code) WHERE deleted_at IS NULL',
  );

  await client.query('CREATE TABLE ' + q('sessions') + ' (id serial PRIMARY KEY, session_token text NOT NULL)');
  await client.query('CREATE TABLE ' + q('coupons') + ' (id serial PRIMARY KEY, coupon_code text NOT NULL)');
  await client.query('CREATE TABLE ' + q('customers') + ' (id serial PRIMARY KEY, email text NOT NULL)');
  await client.query(
    'CREATE TABLE ' + q('events') + ' (id serial PRIMARY KEY, token_id int NOT NULL, has_token boolean NOT NULL)',
  );
  await client.query(
    'CREATE TABLE ' + q('accounts') +
      ' (id serial PRIMARY KEY, email text NOT NULL, api_key text NOT NULL UNIQUE)',
  );
  await client.query(
    'CREATE TABLE ' + q('tickets') +
      ' (id serial PRIMARY KEY, token text NOT NULL, amount int NOT NULL CHECK (amount > 1000000))',
  );

  // Uniqueness enforced by something that is neither a UNIQUE constraint nor a
  // unique index, so the catalogue check cannot see it. The only thing that
  // gets this right is racing the column and counting what actually landed.
  await client.query(
    'CREATE TABLE ' + q('api_clients') +
      ' (id serial PRIMARY KEY, api_key text NOT NULL, EXCLUDE USING btree (api_key WITH =))',
  );
}

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node collision.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  const one = new Client({ connectionString: CONNECTION });
  const two = new Client({ connectionString: CONNECTION });
  await client.connect();
  await one.connect();
  await two.connect();

  try {
    await buildApp(client);
    const plan = await schema.readSchema(client, APP);
    const picked = collision.candidates(plan.tables, plan.indexes);
    const pickedAs = picked.map((p) => p.table + '.' + p.column).sort();
    const openAs = picked.filter((p) => !p.covered).map((p) => p.table + '.' + p.column).sort();

    const raced = await collision.collide(client, one, two, APP, plan.tables, plan.indexes);
    const foundAs = raced.findings.map((f) => f.table + '.' + f.column).sort();
    const triedAs = raced.raced.map((r) => r.table + '.' + r.column).sort();
    const notTriedAs = raced.notTried.map((r) => r.table + '.' + r.column).sort();

    /* ------------------------ what it reports ------------------------ */

    check('1. it reports exactly the columns where a duplicate is a security problem', (() => {
      const problems = [];
      const wanted = ['accounts.email', 'coupons.coupon_code', 'sessions.session_token', 'users.email'];
      const missing = wanted.filter((w) => !foundAs.includes(w));
      const extra = foundAs.filter((p) => !wanted.includes(p));
      if (missing.length) problems.push('it missed ' + missing.join(', '));
      if (extra.length) problems.push('it reported ' + extra.join(', '));
      return problems;
    })());

    check('2. a unique INDEX protects a column just as a constraint does', (() => {
      // The whole reason schema.js learned to copy indexes. An app enforcing
      // uniqueness this way is doing it right and must not be told otherwise.
      const problems = [];
      if (foundAs.includes('users.username')) problems.push('it reported a column with a unique index on it');
      if (!collision.coveredByUnique(plan.tables.find((t) => t.name === 'users'), 'username', plan.indexes)) {
        problems.push('it does not see the unique index at all');
      }
      return problems;
    })());

    check('3. a composite unique is left alone', (() => {
      // UNIQUE (org_id, email) is how multi-tenant apps are meant to work, and
      // the race DOES put two rows in - different orgs, same email. Reporting
      // what the race did without asking whether it was allowed would turn a
      // correct design into a critical finding.
      const problems = [];
      if (foundAs.includes('members.email')) problems.push('it calls a correct multi-tenant design a bug');
      return problems;
    })());

    check('4. a partial unique index is left alone', (() => {
      const problems = [];
      if (foundAs.includes('invites.invite_code')) problems.push('it does not understand a partial unique index');
      return problems;
    })());

    check('5. an ambiguous table name is not guessed at', (() => {
      // A customers table is an account list in half of all apps and a contact
      // list in the other half, where two contacts on one office email is
      // normal. Being wrong half the time is worse than saying nothing.
      const problems = [];
      if (pickedAs.includes('customers.email')) problems.push('it guessed that customers is a login table');
      return problems;
    })());

    check('6. a column that merely looks like a token is not treated as one', (() => {
      const problems = [];
      for (const near of ['events.token_id', 'events.has_token']) {
        if (pickedAs.includes(near)) problems.push('it matched ' + near + ' on a fragment of the name');
      }
      return problems;
    })());

    check('7. racing an unprotected column really does get two rows in', (() => {
      const problems = [];
      for (const open of ['users.email', 'sessions.session_token', 'coupons.coupon_code']) {
        if (!foundAs.includes(open)) problems.push('it did not prove ' + open + ' accepts a duplicate');
      }
      const users = raced.findings.find((f) => f.table === 'users');
      if (users && users.copies < 2) problems.push('it reported a duplicate having created ' + users.copies);
      return problems;
    })());

    check('8. a protected column is still raced, so a fix can be proved', (() => {
      // This is the case that made `covered` stop deciding what gets attacked.
      // Skipping protected columns meant that the moment somebody added the
      // constraint the attack stopped running - and the re-check reported the
      // very fix it had asked for as "could not confirm".
      const problems = [];
      if (!triedAs.includes('users.username')) {
        problems.push('a column with a unique index was never raced, so nobody could ever prove it holds');
      }
      if (!triedAs.includes('invites.invite_code')) problems.push('a partial unique index was never raced');
      if (foundAs.includes('users.username')) problems.push('racing it turned a protected column into a finding');
      return problems;
    })());

    check('9. another unique column elsewhere does not block the attack', (() => {
      // accounts.api_key is UNIQUE. If the two racing rows were identical in
      // every other column, that constraint would refuse the second insert and
      // the refusal would be read as the app defending its email column.
      const problems = [];
      if (!foundAs.includes('accounts.email')) {
        problems.push('a unique column elsewhere in the table made an open column look protected');
      }
      return problems;
    })());

    check('10. a column it could not test is reported, never passed over', (() => {
      // tickets has a CHECK no generated row can satisfy, so the first insert
      // fails and nothing at all is learned. Silence here would read as safe.
      const problems = [];
      if (foundAs.includes('tickets.token')) problems.push('it reported a finding it never proved');
      if (triedAs.includes('tickets.token')) problems.push('it counted a race that never happened as run');
      if (!notTriedAs.includes('tickets.token')) problems.push('it dropped a column it could not test: ' + notTriedAs);
      return problems;
    })());

    check('11. a race that was refused counts as run, not as skipped', (() => {
      // Only the columns it chose are raced, and every one of those either
      // produced a finding or is recorded as tried. A re-check has to be able
      // to tell "attacked and held" from "never attacked".
      const problems = [];
      const accountedFor = triedAs.concat(notTriedAs).sort();
      if (accountedFor.join('|') !== pickedAs.join('|')) {
        problems.push('chosen: ' + pickedAs.join(', ') + '  but accounted for: ' + accountedFor.join(', '));
      }
      return problems;
    })());

    // The rows this attack inserts have to go away, or anything running after
    // it is reading a database the earlier attacks never saw.
    const { rows: leftovers } = await client.query(
      'SELECT count(*)::int AS n FROM ' + schema.quote(APP) + '.' + schema.quote('users') +
        " WHERE email = 'kryptheon-collision'",
    );
    check('12. the copy is left as it was found', (() => {
      const problems = [];
      if (leftovers[0].n !== 0) problems.push('it left ' + leftovers[0].n + ' test rows behind');
      return problems;
    })());

    /* --------------------------- how it reads --------------------------- */

    check('13. the report says what was done, and the fix names the column', (() => {
      const problems = [];
      const described = finding.describeAll(raced.findings);
      const users = described.find((d) => d.table === 'users');
      if (!users) return ['it did not describe the users finding at all'];
      if (!/same email exist twice/.test(users.headline)) problems.push('headline: ' + users.headline);
      if (!/two connections/.test(users.body)) problems.push('the body does not say how it was proved: ' + users.body);
      if (!/at the same moment/.test(users.body)) problems.push('the body does not say they were simultaneous');
      if (!/"users"\."email"/.test(users.fixPrompt)) problems.push('the fix does not name the column: ' + users.fixPrompt);
      if (!/not enough/.test(users.fixPrompt)) problems.push('the fix does not say app-level checking is not enough');
      if (!/cover both columns/.test(users.fixPrompt)) problems.push('the fix does not allow for a legitimate repeat');
      const longest = users.fixPrompt.split('\n').reduce((n, l) => Math.max(n, l.length), 0);
      if (longest > 72) problems.push('the fix wraps at ' + longest + ' characters');
      return problems;
    })());

    check('14. what is reported is what landed, not what the catalogue suggested', (() => {
      // api_clients keeps api_key unique with an exclusion constraint, which is
      // neither a unique index nor a UNIQUE constraint - so it reads as
      // unprotected and gets raced. The race is refused and no second row
      // exists. Anything that reported this was believing the catalogue rather
      // than counting the rows.
      const problems = [];
      if (foundAs.includes('api_clients.api_key')) {
        problems.push('it reported a duplicate that never landed');
      }
      if (!triedAs.includes('api_clients.api_key')) problems.push('it never raced it at all');
      if (notTriedAs.includes('api_clients.api_key')) problems.push('a race that ran and was refused was filed as not run');
      return problems;
    })());

    check('15. a longer column name that contains this one does not protect it', (() => {
      // users has a unique index on email_hash and nothing at all on email.
      // Matching on a substring would see "email" inside "email_hash", call
      // the column protected, and say nothing about a table anyone can
      // register into twice - a real hole reported as safe, which is the one
      // failure that matters.
      const problems = [];
      const users = plan.tables.find((t) => t.name === 'users');
      if (collision.coveredByUnique(users, 'email', plan.indexes)) {
        problems.push('a unique index on email_hash was taken as protecting email');
      }
      if (!collision.coveredByUnique(users, 'email_hash', plan.indexes)) {
        problems.push('it cannot see the unique index on email_hash either');
      }
      if (!foundAs.includes('users.email')) problems.push('so the open column went unreported');
      return problems;
    })());

    check('16. a duplicate credential outranks a duplicate coupon', (() => {
      // Two levels only, and they have to be the right way round: one session
      // token matching two rows is somebody else's account, a coupon redeemed
      // twice is money.
      const problems = [];
      const described = finding.describeAll(raced.findings);
      const token = described.find((d) => d.table === 'sessions');
      const coupon = described.find((d) => d.table === 'coupons');
      if (!token || !coupon) return ['it did not describe both findings'];
      if (token.severity !== 'CRITICAL') problems.push('a duplicate session token is ' + token.severity);
      if (coupon.severity !== 'HIGH') problems.push('a duplicate coupon code is ' + coupon.severity);
      if (described.indexOf(token) > described.indexOf(coupon)) problems.push('the coupon is listed above the token');
      return problems;
    })());
  } finally {
    try {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE');
    } catch (err) {
      console.error('  WARNING: ' + APP + ' could not be dropped: ' + err.message);
    }
    await client.end();
    await one.end();
    await two.end();
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
    console.log('All ' + results.length + ' collision checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
