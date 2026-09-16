// Before writing the Collision attack: does racing two inserts actually work
// the way it is assumed to, and can uniqueness be read and rebuilt faithfully?
//
// Run with:  node probe-collision.js "<connection string>"
//
// Five questions, because getting any of them wrong produces a confident
// report about a database nobody runs:
//
//   1. Does pg_get_indexdef hand back something that can be replayed into the
//      copy, and does the schema name inside it need rewriting the way a
//      constraint definition did?
//   2. With nothing enforcing uniqueness, do two concurrent inserts of the
//      same value really both land?
//   3. With a unique index, does the second one really fail - and does it fail
//      at INSERT or only at COMMIT? The answer decides how the attack has to
//      be sequenced.
//   4. Does a composite unique (org_id, email) let the same email through
//      twice in different orgs? It must, and the attack must not call that a
//      problem - it is how multi-tenant apps are supposed to work.
//   5. Does a partial unique index survive the trip into the copy?
//
// Nothing is assumed. The whole reason schema.js copies grants is that the
// schemas matched and the behaviour did not.

const { Client } = require('pg');
const schema = require('./schema.js');

const SCHEMA = 'probe_col_' + Date.now().toString(36);
const CONN = process.argv[2] || process.env.KN_DATABASE_URL;

const answers = [];
function record(question, answer, detail) {
  answers.push({ question: question, answer: answer, detail: detail });
  console.log('');
  console.log('  ' + question);
  console.log('    -> ' + answer);
  if (detail) console.log('       ' + detail);
}

/**
 * Two inserts of the same value, genuinely at the same time.
 *
 * The sequencing is the delicate part. If a unique index is present the second
 * insert BLOCKS until the first transaction ends, so awaiting both before
 * committing either would simply hang. So: first insert, commit it, and only
 * then wait on the second - which by that point is already queued inside its
 * own open transaction and has been racing all along.
 */
async function race(one, two, statement, values) {
  await one.query('BEGIN');
  await two.query('BEGIN');
  // A pathological lock must not hang the night's run.
  await two.query("SET LOCAL statement_timeout = '15s'");

  const first = await one.query(statement, values).then(
    () => ({ ok: true }),
    (err) => ({ ok: false, why: err.message }),
  );

  // Fired but deliberately not awaited: it has to be in flight while the first
  // transaction is still open, or this is not a race at all.
  const pending = two.query(statement, values).then(
    () => ({ ok: true }),
    (err) => ({ ok: false, why: err.message }),
  );

  await one.query('COMMIT');
  const second = await pending;
  await two.query(second.ok ? 'COMMIT' : 'ROLLBACK');

  return { first: first, second: second };
}

(async () => {
  if (!CONN) {
    console.error('\n  node probe-collision.js "<connection string>"\n');
    process.exit(2);
  }

  const owner = new Client({ connectionString: CONN });
  const one = new Client({ connectionString: CONN });
  const two = new Client({ connectionString: CONN });
  await owner.connect();
  await one.connect();
  await two.connect();

  const q = (t) => schema.quote(SCHEMA) + '.' + schema.quote(t);

  try {
    await owner.query('CREATE SCHEMA ' + schema.quote(SCHEMA));

    // ---- 1. can uniqueness be read back in a replayable form? ----
    await owner.query('CREATE TABLE ' + q('accounts') + ' (id serial PRIMARY KEY, email text NOT NULL)');
    await owner.query('CREATE UNIQUE INDEX accounts_email_key ON ' + q('accounts') + ' (email)');
    await owner.query('CREATE TABLE ' + q('members') + ' (id serial PRIMARY KEY, org_id int NOT NULL, email text NOT NULL)');
    await owner.query('CREATE UNIQUE INDEX members_org_email_key ON ' + q('members') + ' (org_id, email)');
    await owner.query('CREATE TABLE ' + q('invites') + ' (id serial PRIMARY KEY, code text NOT NULL, deleted_at timestamptz)');
    await owner.query(
      'CREATE UNIQUE INDEX invites_code_key ON ' + q('invites') + ' (code) WHERE deleted_at IS NULL',
    );
    await owner.query('CREATE TABLE ' + q('signups') + ' (id serial PRIMARY KEY, email text NOT NULL)');

    const { rows: indexes } = await owner.query(
      `SELECT c.relname AS name,
              i.indisunique AS is_unique,
              t.relname AS table_name,
              pg_get_indexdef(i.indexrelid) AS definition,
              i.indisprimary AS is_primary
         FROM pg_index i
         JOIN pg_class c ON c.oid = i.indexrelid
         JOIN pg_class t ON t.oid = i.indrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND i.indisunique
        ORDER BY t.relname, c.relname`,
      [SCHEMA],
    );
    record(
      '1. what does Postgres hand back for a unique index?',
      indexes.length + ' unique indexes, ' + indexes.filter((r) => r.is_primary).length + ' of them primary keys',
      indexes.map((r) => r.definition).join('\n       '),
    );

    const qualified = indexes.filter((r) => r.definition.includes(SCHEMA + '.')).length;
    record(
      '1b. is the schema name inside the definition, and how is it spelled?',
      qualified + ' of ' + indexes.length + ' mention the schema unquoted',
      'if this is not rewritten the copy builds indexes on the customer real tables',
    );

    // ---- 2. nothing enforcing uniqueness ----
    const open = await race(one, two, 'INSERT INTO ' + q('signups') + ' (email) VALUES ($1)', ['same@example.com']);
    const { rows: openRows } = await owner.query('SELECT count(*)::int AS n FROM ' + q('signups'));
    record(
      '2. no unique index: do two racing inserts both land?',
      open.first.ok && open.second.ok ? 'YES - both accepted, ' + openRows[0].n + ' rows' : 'no',
      'first: ' + (open.first.ok ? 'ok' : open.first.why) + ' | second: ' + (open.second.ok ? 'ok' : open.second.why),
    );

    // ---- 3. a unique index in the way ----
    const guarded = await race(one, two, 'INSERT INTO ' + q('accounts') + ' (email) VALUES ($1)', ['same@example.com']);
    const { rows: guardedRows } = await owner.query('SELECT count(*)::int AS n FROM ' + q('accounts'));
    record(
      '3. unique index present: is the second one refused?',
      guarded.first.ok && !guarded.second.ok ? 'YES - refused, ' + guardedRows[0].n + ' row' : 'NO - both got in',
      'second said: ' + (guarded.second.ok ? '(accepted)' : guarded.second.why),
    );

    // ---- 4. composite unique, same email in two orgs ----
    await owner.query('BEGIN');
    let composite;
    try {
      await owner.query('INSERT INTO ' + q('members') + ' (org_id, email) VALUES (1, $1)', ['same@example.com']);
      await owner.query('INSERT INTO ' + q('members') + ' (org_id, email) VALUES (2, $1)', ['same@example.com']);
      composite = 'YES - both landed, which is correct and must not be reported';
    } catch (err) {
      composite = 'NO - refused: ' + err.message;
    }
    await owner.query('COMMIT');
    record('4. composite unique (org_id, email): same email in two orgs?', composite);

    // ---- 5. does a partial unique index survive being copied? ----
    const copy = SCHEMA + '_copy';
    await owner.query('CREATE SCHEMA ' + schema.quote(copy));
    await owner.query('CREATE TABLE ' + schema.quote(copy) + '.' + schema.quote('invites') +
      ' (id serial PRIMARY KEY, code text NOT NULL, deleted_at timestamptz)');
    const partial = indexes.find((r) => r.definition.includes('WHERE'));
    let replayed;
    try {
      const rewritten = partial.definition
        .split(schema.quote(SCHEMA) + '.').join(schema.quote(copy) + '.')
        .split(SCHEMA + '.').join(copy + '.')
        .split('INDEX ' + partial.name).join('INDEX ' + partial.name + '_c');
      await owner.query(rewritten);
      const { rows: check } = await owner.query(
        `SELECT pg_get_indexdef(i.indexrelid) AS definition
           FROM pg_index i
           JOIN pg_class c ON c.oid = i.indexrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = $1 AND i.indisunique AND NOT i.indisprimary`,
        [copy],
      );
      replayed = 'YES - ' + check.map((r) => r.definition).join(' ; ');
    } catch (err) {
      replayed = 'NO - ' + err.message;
    }
    record('5. can a partial unique index be replayed into the copy?', replayed);

    console.log('');
    console.log('  ' + '-'.repeat(68));
    console.log('  Questions answered: ' + answers.length);
    console.log('');
  } finally {
    await owner.query('DROP SCHEMA IF EXISTS ' + schema.quote(SCHEMA) + ' CASCADE');
    await owner.query('DROP SCHEMA IF EXISTS ' + schema.quote(SCHEMA + '_copy') + ' CASCADE');
    await owner.end();
    await one.end();
    await two.end();
  }
})().catch((err) => {
  console.error('\n  the probe could not run: ' + (err.message || err));
  process.exit(1);
});
