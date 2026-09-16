// Does plain SQL reproduce what PostgREST does to enforce row level security?
//
// The whole architecture rests on this. The plan is to copy a customer's schema
// and policies into our own Postgres and attack that, without running PostgREST
// in front of it. That is only honest if setting the role and the JWT claims by
// hand enforces policies exactly the way a real request would - otherwise every
// verdict we produce is about a database nobody is actually running.
//
// PostgREST, for an authenticated request, does this before the query:
//
//   SET LOCAL role TO authenticated;
//   SET LOCAL request.jwt.claims TO '{"sub":"<user id>","role":"authenticated"}';
//
// and Supabase's auth.uid() reads the sub out of that setting. So the question
// is whether the same two statements, issued by us, give the same answers.
//
// Two things have to be true, and the second matters more than the first:
//
//   1. A correct policy HOLDS - user A cannot see user B's rows, and a
//      logged-out caller sees nothing. If this fails, our attack would report a
//      break that is not there, and we would be sending people to fix working
//      code.
//
//   2. A missing policy is SEEN - a table left open really does hand over
//      everybody's rows. If this fails, we would tell people they are safe when
//      they are not, which is the worse of the two.
//
// Run with:  node probe-rls.js "<postgres connection string>"
// Nothing is left behind: everything is created inside a temporary schema that
// is dropped at the end, even if a check fails.

const { Client } = require('pg');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

const SCHEMA = 'kn_probe_' + Date.now();
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';

/** What a caller can read, asked the way PostgREST asks it. */
async function readAs(client, role, userId, table) {
  await client.query('BEGIN');
  try {
    // SET LOCAL, so it dies with the transaction exactly as a request does.
    await client.query('SET LOCAL role TO ' + role);
    if (userId) {
      await client.query('SELECT set_config($1, $2, true)', [
        'request.jwt.claims',
        JSON.stringify({ sub: userId, role: role }),
      ]);
    } else {
      await client.query('SELECT set_config($1, $2, true)', ['request.jwt.claims', '', ]);
    }
    const result = await client.query('SELECT id, owner, note FROM ' + SCHEMA + '.' + table + ' ORDER BY note');
    return result.rows;
  } finally {
    // ROLLBACK also puts the role back, which is why the read is wrapped.
    await client.query('ROLLBACK');
  }
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  No database to probe.');
    console.error('');
    console.error('  Pass a Postgres connection string:');
    console.error('    node probe-rls.js "postgresql://user:pass@host/db?sslmode=require"');
    console.error('');
    console.error('  A free Neon database is enough. Nothing is written outside a');
    console.error('  temporary schema, and that schema is dropped at the end.');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  const problems = [];
  const say = (ok, line) => console.log((ok ? 'PASS  ' : 'FAIL  ') + line);

  try {
    // ---- a stand-in for the parts of Supabase the policies depend on ----
    await client.query('CREATE SCHEMA ' + SCHEMA);
    // These roles already exist on a Supabase database; created here only if
    // this is a plain Postgres, so the probe works on either.
    for (const role of ['anon', 'authenticated']) {
      await client.query(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') " +
          "THEN CREATE ROLE " + role + " NOLOGIN; END IF; END $$;",
      );
      await client.query('GRANT USAGE ON SCHEMA ' + SCHEMA + ' TO ' + role);
      // Being able to create a role is not the same as being able to become
      // one. Supabase has a dedicated "authenticator" login that holds
      // membership in anon and authenticated, and PostgREST switches into them
      // from there; without the equivalent, SET ROLE is refused outright. Our
      // copy needs a connection role that can do the same.
      await client.query('GRANT ' + role + ' TO current_user');
    }

    // auth.uid(), defined the way Supabase defines it: read the sub claim.
    await client.query('CREATE SCHEMA IF NOT EXISTS ' + SCHEMA + '_auth');
    await client.query(
      'CREATE OR REPLACE FUNCTION ' + SCHEMA + '_auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ ' +
        "SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid $$",
    );
    await client.query('GRANT USAGE ON SCHEMA ' + SCHEMA + '_auth TO anon, authenticated');

    // ---- a table that is protected, and one that was left open ----
    for (const table of ['guarded', 'open']) {
      await client.query(
        'CREATE TABLE ' + SCHEMA + '.' + table +
          ' (id serial primary key, owner uuid not null, note text not null)',
      );
      await client.query(
        'INSERT INTO ' + SCHEMA + '.' + table + ' (owner, note) VALUES ' +
          "($1, 'belongs to A'), ($2, 'belongs to B')",
        [USER_A, USER_B],
      );
      await client.query('ALTER TABLE ' + SCHEMA + '.' + table + ' ENABLE ROW LEVEL SECURITY');
      await client.query('GRANT SELECT ON ' + SCHEMA + '.' + table + ' TO anon, authenticated');
    }

    // The policy a careful developer writes.
    await client.query(
      'CREATE POLICY owner_reads ON ' + SCHEMA + '.guarded FOR SELECT TO authenticated ' +
        'USING (owner = ' + SCHEMA + '_auth.uid())',
    );
    // And the one an AI writes when it is asked to "make the data readable":
    // row level security is on, so it looks protected, and the policy lets
    // everybody through.
    await client.query(
      'CREATE POLICY anyone_reads ON ' + SCHEMA + '.open FOR SELECT TO anon, authenticated USING (true)',
    );

    console.log('');
    console.log('Probing ' + SCHEMA + ' - does plain SQL enforce policies the way a request does?');
    console.log('');

    // ---- 1. a correct policy has to hold ----
    const aSeesGuarded = await readAs(client, 'authenticated', USER_A, 'guarded');
    const okA = aSeesGuarded.length === 1 && aSeesGuarded[0].note === 'belongs to A';
    say(okA, "a signed-in user reads only their own row  (saw " + aSeesGuarded.length + ")");
    if (!okA) problems.push('a correct policy did not hold: ' + JSON.stringify(aSeesGuarded));

    const bSeesGuarded = await readAs(client, 'authenticated', USER_B, 'guarded');
    const okB = bSeesGuarded.length === 1 && bSeesGuarded[0].note === 'belongs to B';
    say(okB, 'the other user reads only theirs, so the claim is really being read');
    if (!okB) problems.push('the second user saw: ' + JSON.stringify(bSeesGuarded));

    const anonGuarded = await readAs(client, 'anon', null, 'guarded');
    const okAnon = anonGuarded.length === 0;
    say(okAnon, 'a logged-out caller reads nothing  (saw ' + anonGuarded.length + ')');
    if (!okAnon) problems.push('anon read a guarded table: ' + JSON.stringify(anonGuarded));

    // ---- 2. a missing policy has to be visible ----
    const anonOpen = await readAs(client, 'anon', null, 'open');
    const okOpen = anonOpen.length === 2;
    say(okOpen, 'a table left open hands everything to a logged-out caller  (saw ' + anonOpen.length + ')');
    if (!okOpen) {
      problems.push(
        'the open table did not leak, so this probe cannot tell safe from unsafe: ' + JSON.stringify(anonOpen),
      );
    }

    const aSeesOpen = await readAs(client, 'authenticated', USER_A, 'open');
    const okCross = aSeesOpen.length === 2;
    say(okCross, "one customer reads another customer's rows  (saw " + aSeesOpen.length + ')');
    if (!okCross) problems.push('the impersonation case did not reproduce: ' + JSON.stringify(aSeesOpen));

    console.log('');
    if (problems.length) {
      console.log('The assumption does not hold. Details:');
      problems.forEach((p) => console.log('  - ' + p));
      console.log('');
      console.log('Plain SQL is not a stand-in for a real request, so the attack would');
      console.log('have to go through PostgREST or the real API after all.');
      process.exitCode = 1;
    } else {
      console.log('All five hold: setting the role and the claims by hand enforces');
      console.log('policies the way a request does, and a missing policy is visible.');
      console.log('The copy can be attacked with SQL alone - no PostgREST needed.');
    }
  } finally {
    // Always, even when a check failed.
    try {
      await client.query('DROP SCHEMA IF EXISTS ' + SCHEMA + ' CASCADE');
      await client.query('DROP SCHEMA IF EXISTS ' + SCHEMA + '_auth CASCADE');
    } catch (e) {
      console.error('could not drop ' + SCHEMA + ': ' + e.message);
    }
    await client.end();
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The probe could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
