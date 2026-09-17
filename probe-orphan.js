// Before building the Interruption attack: what can honestly be proven?
//
// Run with:  node probe-orphan.js "<connection string>"
//
// "A request that gets cut off halfway" is mostly a question about the app's
// code - did it wrap its two inserts in a transaction? - and this tool never
// sees the app's code. Guessing would be the lost update all over again.
//
// But there is a database-level half of it that is provable: whether a
// half-finished state can survive at all. An order pointing at a customer who
// does not exist, a payment attached to no order, a row left behind after the
// thing it belonged to was deleted. If the database has a foreign key, none of
// those can persist no matter how badly the app behaves. Without one, they can.
//
// Six questions:
//   1. With no foreign key, is a row pointing at nothing accepted?
//   2. With one, is it refused?
//   3. Deleting a parent with no foreign key - are the children orphaned?
//   4. With a foreign key and no ON DELETE, is the delete refused?
//   5. With ON DELETE CASCADE, do the children go too?
//   6. With ON DELETE SET NULL, what is left?
//
// And the one that decides whether this can be reported at all: can a column
// that points at another table in this schema be told apart from one that
// points at something outside it - a Stripe id, an external key? Getting that
// wrong means telling somebody to add a foreign key to a column that must not
// have one.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');

const APP = 'kn_probeo_' + Date.now().toString(36);
const CONN = process.argv[2] || process.env.KN_DATABASE_URL;
const NOBODY = '99999999-9999-4999-8999-999999999999';

let undoAuth = async () => {};
let asked = 0;
function record(question, answer, detail) {
  asked += 1;
  console.log('');
  console.log('  ' + question);
  console.log('    -> ' + answer);
  if (detail) console.log('       ' + detail);
}

async function attempt(client, statement) {
  try {
    const result = await client.query(statement);
    return { ok: true, count: result.rowCount };
  } catch (err) {
    return { ok: false, why: err.message.split('\n')[0] };
  }
}

(async () => {
  if (!CONN) {
    console.error('\n  node probe-orphan.js "<connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONN });
  await client.connect();
  const q = (t) => schema.quote(APP) + '.' + schema.quote(t);

  try {
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    await fixture.ensureRoles(client, APP, schema.quote);
    undoAuth = await fixture.ensureAuth(client);

    await client.query('CREATE TABLE ' + q('users') + ' (id uuid PRIMARY KEY, email text NOT NULL)');
    await client.query("INSERT INTO " + q('users') + " VALUES ('11111111-1111-4111-8111-111111111111', 'a@b.c')");

    // The same table twice: once with a foreign key, once without.
    await client.query('CREATE TABLE ' + q('loose') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL, total numeric(10,2) NOT NULL)');
    await client.query('CREATE TABLE ' + q('tied') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL REFERENCES ' + q('users') + '(id), total numeric(10,2) NOT NULL)');
    await client.query('CREATE TABLE ' + q('cascading') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL REFERENCES ' + q('users') + '(id) ON DELETE CASCADE, total numeric(10,2) NOT NULL)');
    await client.query('CREATE TABLE ' + q('nulling') + ' (id serial PRIMARY KEY, user_id uuid REFERENCES ' + q('users') + '(id) ON DELETE SET NULL, total numeric(10,2) NOT NULL)');

    const loose = await attempt(client, 'INSERT INTO ' + q('loose') + " (user_id, total) VALUES ('" + NOBODY + "', 10)");
    record(
      '1. no foreign key: is a row pointing at nobody accepted?',
      loose.ok ? 'YES - the row exists and points at a customer who does not' : 'no - ' + loose.why,
    );

    const tied = await attempt(client, 'INSERT INTO ' + q('tied') + " (user_id, total) VALUES ('" + NOBODY + "', 10)");
    record(
      '2. with a foreign key: is it refused?',
      tied.ok ? 'NO - it got in anyway' : 'yes - refused',
      tied.ok ? '' : tied.why,
    );

    // Give every tied table a real row so the deletes below have something.
    for (const t of ['tied', 'cascading', 'nulling']) {
      await client.query('INSERT INTO ' + q(t) + " (user_id, total) VALUES ('11111111-1111-4111-8111-111111111111', 10)");
    }

    const dropParentLoose = await attempt(client, 'DELETE FROM ' + q('users') + " WHERE id = '11111111-1111-4111-8111-111111111111'");
    record(
      '3/4. deleting the customer, with three foreign keys pointing at them:',
      dropParentLoose.ok ? 'allowed' : 'refused - ' + dropParentLoose.why,
      'a plain foreign key with no ON DELETE should refuse it',
    );

    // Now take the plain one out of the way and see what CASCADE and SET NULL do.
    await client.query('DELETE FROM ' + q('tied'));
    const dropAgain = await attempt(client, 'DELETE FROM ' + q('users') + " WHERE id = '11111111-1111-4111-8111-111111111111'");
    const { rows: leftCascading } = await client.query('SELECT count(*)::int n FROM ' + q('cascading'));
    const { rows: leftNulling } = await client.query('SELECT count(*)::int n, count(user_id)::int owned FROM ' + q('nulling'));
    record(
      '5/6. once it is allowed, what happens to the children?',
      dropAgain.ok
        ? 'CASCADE left ' + leftCascading[0].n + ' rows; SET NULL left ' + leftNulling[0].n +
          ' rows of which ' + leftNulling[0].owned + ' still name an owner'
        : 'still refused - ' + dropAgain.why,
    );

    const { rows: orphans } = await client.query(
      'SELECT count(*)::int n FROM ' + q('loose') + ' l WHERE NOT EXISTS (SELECT 1 FROM ' + q('users') + ' u WHERE u.id = l.user_id)',
    );
    record(
      '7. and the table with no foreign key at all?',
      orphans[0].n + ' row(s) pointing at a customer who is not there',
      'nothing in the database will ever notice or clean these up',
    );

    // Can a column that points inside be told from one that points outside?
    await client.query('CREATE TABLE ' + q('payments') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL, stripe_id text NOT NULL, session_id text NOT NULL)');
    const { rows: named } = await client.query(
      `SELECT a.attname AS col, format_type(a.atttypid, a.atttypmod) AS type
         FROM pg_attribute a
        WHERE a.attrelid = format('%I.%I', $1::text, 'payments')::regclass
          AND a.attnum > 0 AND NOT a.attisdropped AND a.attname LIKE '%\\_id'
        ORDER BY a.attnum`,
      [APP],
    );
    const { rows: tables } = await client.query(
      "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r' ORDER BY 1",
      [APP],
    );
    const names = tables.map((r) => r.relname);
    const guessable = named.filter((c) => {
      const stem = c.col.replace(/_id$/, '');
      return names.includes(stem) || names.includes(stem + 's');
    });
    record(
      '8. can a column pointing inside be told from one pointing outside?',
      guessable.map((c) => c.col).join(', ') + '  <- these have a table to match; ' +
        named.filter((c) => !guessable.includes(c)).map((c) => c.col).join(', ') + '  <- these do not',
      'stripe_id and session_id must never be reported: there is no table they could point at',
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
