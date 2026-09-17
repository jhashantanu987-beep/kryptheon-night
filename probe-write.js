// Before building the write attack: measure what a stranger can actually do.
//
// The first version of this probe got two things wrong, which is the point of
// running one. A statement that returns without error but changes zero rows is
// a refusal, not a success - row level security filters rows away rather than
// complaining. And sequences need granting after the tables that own them
// exist, or an insert fails for a reason that has nothing to do with security.
//
// Judged by what actually changed in the table afterwards, not by whether the
// query threw.
const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');

const APP = 'kn_probew_' + Date.now().toString(36);
const CONN = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};
const MINE = '11111111-1111-4111-8111-111111111111';
const THEIRS = '22222222-2222-4222-8222-222222222222';

let asked = 0;
function record(question, answer, detail) {
  asked += 1;
  console.log('');
  console.log('  ' + question);
  console.log('    -> ' + answer);
  if (detail) console.log('       ' + detail);
}

/** Runs one statement the way a request runs, and never keeps the result. */
async function asRole(client, role, userId, statement) {
  await client.query('BEGIN');
  try {
    await client.query('SET LOCAL role TO ' + role);
    await client.query('SELECT set_config($1, $2, true)', [
      'request.jwt.claims',
      JSON.stringify(userId ? { sub: userId, role: role } : { role: role }),
    ]);
    const result = await client.query(statement);
    await client.query('ROLLBACK');
    return { ok: true, count: result.rowCount };
  } catch (err) {
    await client.query('ROLLBACK');
    return { ok: false, count: 0, why: err.message };
  }
}

/** What a write actually did, in words that do not overstate it. */
function verdict(result) {
  if (!result.ok) return { got: false, text: 'no - ' + result.why };
  if (!result.count) return { got: false, text: 'no - the statement ran but changed nothing' };
  return { got: true, text: 'YES - ' + result.count + ' row(s)' };
}

(async () => {
  if (!CONN) {
    console.error('set KN_DATABASE_URL');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONN });
  await client.connect();
  const q = (t) => schema.quote(APP) + '.' + schema.quote(t);

  try {
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    for (const role of ['anon', 'authenticated']) {
      await client.query(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role +
          "') THEN CREATE ROLE " + role + ' NOLOGIN; END IF; END $$;',
      );
      await client.query('GRANT ' + role + ' TO current_user');
      await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO ' + role);
    }
    undoAuth = await fixture.ensureAuth(client);

    const shape = ' (id serial PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)';
    const tables = ['no_rls', 'read_only_policy', 'all_true', 'own_rows', 'insert_check'];
    for (const name of tables) await client.query('CREATE TABLE ' + q(name) + shape);

    // Supabase grants these by default on the public schema, which is exactly
    // why the disaster case below is so common. Sequences granted after the
    // tables exist, or an insert fails for a reason that is not about security.
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ' +
      schema.quote(APP) + ' TO anon, authenticated');
    await client.query('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ' +
      schema.quote(APP) + ' TO anon, authenticated');

    // The disaster case: nobody ever switched row level security on.
    await client.query("INSERT INTO " + q('no_rls') + " (owner, body) VALUES ('" + THEIRS + "', 'theirs')");

    // A SELECT policy and nothing else, which is what most people write.
    await client.query('ALTER TABLE ' + q('read_only_policy') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY readable ON ' + q('read_only_policy') +
      ' FOR SELECT TO anon, authenticated USING (true)');
    await client.query("INSERT INTO " + q('read_only_policy') + " (owner, body) VALUES ('" + THEIRS + "', 'theirs')");

    // FOR ALL with USING (true) - looks like a policy, stops nothing.
    await client.query('ALTER TABLE ' + q('all_true') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY everything ON ' + q('all_true') +
      ' FOR ALL TO anon, authenticated USING (true)');
    await client.query("INSERT INTO " + q('all_true') + " (owner, body) VALUES ('" + THEIRS + "', 'theirs')");

    // The correct one.
    await client.query('ALTER TABLE ' + q('own_rows') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY mine ON ' + q('own_rows') +
      ' FOR ALL TO authenticated USING (owner = auth.uid())');
    await client.query("INSERT INTO " + q('own_rows') + " (owner, body) VALUES ('" + MINE + "', 'mine')");

    await client.query('ALTER TABLE ' + q('insert_check') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY only_mine ON ' + q('insert_check') +
      ' FOR INSERT TO authenticated WITH CHECK (owner = auth.uid())');

    /* ------------------------------------------------------------------ */

    const newRow = (t) => 'INSERT INTO ' + q(t) + " (owner, body) VALUES ('" + MINE + "', 'planted by a stranger')";
    const rewrite = (t) => 'UPDATE ' + q(t) + " SET body = 'rewritten' WHERE owner = '" + THEIRS + "'";
    const wipe = (t) => 'DELETE FROM ' + q(t);

    record(
      '1. no row level security at all: can a stranger insert?',
      verdict(await asRole(client, 'anon', null, newRow('no_rls'))).text,
      'Supabase grants anon insert on the public schema by default, so this is the common disaster',
    );
    record(
      '2. no row level security at all: can a stranger rewrite an existing row?',
      verdict(await asRole(client, 'anon', null, rewrite('no_rls'))).text,
    );
    record(
      '3. no row level security at all: can a stranger delete everything?',
      verdict(await asRole(client, 'anon', null, wipe('no_rls'))).text,
    );

    record(
      '4. a SELECT policy and nothing else: can a stranger insert?',
      verdict(await asRole(client, 'anon', null, newRow('read_only_policy'))).text,
      'if this is refused, a read rule is genuinely not a write rule and writes are denied by default',
    );
    record(
      '5. a SELECT policy and nothing else: can a stranger delete?',
      verdict(await asRole(client, 'anon', null, wipe('read_only_policy'))).text,
    );

    record(
      '6. FOR ALL with USING (true): can a stranger insert?',
      verdict(await asRole(client, 'anon', null, newRow('all_true'))).text,
    );
    record(
      '7. FOR ALL with USING (true): can a stranger rewrite somebody else\'s row?',
      verdict(await asRole(client, 'anon', null, rewrite('all_true'))).text,
    );
    record(
      '8. FOR ALL with USING (true): can a stranger delete everything?',
      verdict(await asRole(client, 'anon', null, wipe('all_true'))).text,
    );

    record(
      '9. an owner policy: can a signed-in customer delete another customer\'s row?',
      verdict(await asRole(client, 'authenticated', THEIRS, 'DELETE FROM ' + q('own_rows') +
        " WHERE owner = '" + MINE + "'")).text,
      'this one must come back no, or the attack would libel a correct app',
    );
    record(
      '10. an owner policy with USING and no WITH CHECK: can a row be pushed out of reach?',
      verdict(await asRole(client, 'authenticated', MINE, 'UPDATE ' + q('own_rows') +
        " SET owner = '" + THEIRS + "' WHERE owner = '" + MINE + "'")).text,
      'Postgres reuses USING as the check for UPDATE when no WITH CHECK is given',
    );
    record(
      "11. WITH CHECK on insert: can a customer write a row under somebody else's name?",
      verdict(await asRole(client, 'authenticated', MINE, 'INSERT INTO ' + q('insert_check') +
        " (owner, body) VALUES ('" + THEIRS + "', 'planted')")).text,
    );

    const { rows: left } = await client.query('SELECT count(*)::int AS n FROM ' + q('no_rls'));
    record(
      '12. after all of that, is the table as it was found?',
      left[0].n === 1 ? 'yes - 1 row, nothing kept' : 'NO - ' + left[0].n + ' rows',
      'every write is rolled back, so the attack can be run against a copy without leaving anything',
    );

    console.log('');
    console.log('  ' + '-'.repeat(68));
    console.log('  ' + asked + ' questions answered.');
    console.log('');
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    await undoAuth();
    await client.end();
  }
})().catch((err) => {
  console.error('\n  the probe could not run: ' + (err.message || err));
  process.exit(1);
});
