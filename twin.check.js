// Checks that the two engines say exactly the same thing.
// Run with:  node twin.check.js "<postgres connection string>"
//
// The attacks are moving into SQL so that the night shift can run inside the
// customer's own database, with nobody's password ever leaving it. That only
// works if there is ONE engine. Two implementations of the same idea is how
// every bug gets fixed once and survives in the other copy.
//
// So this is the check that keeps them one thing: the same fixture, read by
// both, compared key for key. Not "close enough" - identical. The moment they
// differ, one of them is wrong and there is no way to tell which from the
// outside, which is exactly the position this exists to prevent.
//
// The fixture is deliberately the awkward one. Every shape that has cost a bug
// so far is in it: an enum, an array, a generated column, a domain, a view, a
// unique index, a composite key, a policy with a WITH CHECK, a table that is
// only an id.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_twin_' + Date.now().toString(36);

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/** An app made of everything that has ever been read wrong. */
async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await fixture.ensureRoles(client, APP, schema.quote);
  undoAuth = await fixture.ensureAuth(client);

  await client.query('CREATE TYPE ' + schema.quote(APP) + ".order_status AS ENUM ('new', 'paid', 'shipped')");
  await client.query('CREATE DOMAIN ' + schema.quote(APP) + ".email_address AS text CHECK (VALUE LIKE '%@%')");

  await client.query(
    'CREATE TABLE ' + q('profiles') +
      ' (id uuid PRIMARY KEY, email ' + schema.quote(APP) + '.email_address NOT NULL, full_name text)',
  );
  await client.query(
    'CREATE TABLE ' + q('orders') +
      ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner uuid NOT NULL,' +
      ' status ' + schema.quote(APP) + '.order_status NOT NULL,' +
      ' tags text[] NOT NULL, total numeric(10,2) NOT NULL,' +
      " note text NOT NULL DEFAULT 'none'," +
      // Concatenating text, not casting a number to it: a numeric-to-text cast
      // is only stable, and Postgres refuses a generated column built on
      // anything that could change its mind.
      " label text GENERATED ALWAYS AS (note || '-generated') STORED)",
  );
  await client.query(
    'CREATE TABLE ' + q('members') +
      ' (org_id integer NOT NULL, user_id uuid NOT NULL, role text NOT NULL, PRIMARY KEY (org_id, user_id))',
  );
  await client.query('CREATE TABLE ' + q('flags') + ' (id serial PRIMARY KEY)');
  await client.query('CREATE TABLE ' + q('sessions') + ' (id serial PRIMARY KEY, session_token text NOT NULL)');
  await client.query('CREATE UNIQUE INDEX sessions_token_key ON ' + q('sessions') + ' (session_token)');
  await client.query('CREATE VIEW ' + q('paid_orders') + ' AS SELECT id, owner, total FROM ' + q('orders') + " WHERE status = 'paid'");

  for (const t of ['profiles', 'orders', 'members', 'flags', 'sessions']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
  }
  await client.query('GRANT SELECT ON ' + q('paid_orders') + ' TO anon');

  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('ALTER TABLE ' + q('profiles') + ' FORCE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY own_profile ON ' + q('profiles') +
      ' FOR ALL TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid())',
  );
  await client.query('ALTER TABLE ' + q('orders') + ' ENABLE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY read_orders ON ' + q('orders') + ' FOR SELECT TO anon, authenticated USING (true)',
  );
}

/**
 * Where two shapes differ, said in a way that points at the difference.
 *
 * Walked key by key rather than compared as two blobs of text, because
 * "these two long strings are not equal" is not something anybody can act on.
 */
function differences(mine, theirs, where) {
  const at = where || '';
  if (mine === theirs) return [];
  if (mine === null || theirs === null || typeof mine !== typeof theirs) {
    return [at + ': node had ' + JSON.stringify(mine) + ', sql had ' + JSON.stringify(theirs)];
  }
  if (Array.isArray(mine) || Array.isArray(theirs)) {
    if (!Array.isArray(mine) || !Array.isArray(theirs)) {
      return [at + ': one is a list and the other is not'];
    }
    if (mine.length !== theirs.length) {
      return [at + ': node had ' + mine.length + ' entries, sql had ' + theirs.length];
    }
    const found = [];
    for (let i = 0; i < mine.length; i++) {
      found.push(...differences(mine[i], theirs[i], at + '[' + i + ']'));
    }
    return found;
  }
  if (typeof mine === 'object') {
    const keys = [...new Set(Object.keys(mine).concat(Object.keys(theirs)))].sort();
    const found = [];
    for (const key of keys) {
      found.push(...differences(mine[key], theirs[key], at ? at + '.' + key : key));
    }
    return found;
  }
  return [at + ': node had ' + JSON.stringify(mine) + ', sql had ' + JSON.stringify(theirs)];
}

/** Only the parts of the shape the SQL engine has been taught so far. */
const SO_FAR = ['schema', 'tables', 'policies', 'grants', 'indexes', 'views', 'viewGrants'];

function onlySoFar(shape) {
  const kept = {};
  for (const key of SO_FAR) kept[key] = shape[key] === undefined ? null : shape[key];
  return kept;
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node twin.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  try {
    await buildApp(client);

    const fromNode = await schema.readSchema(client, APP);
    let fromSql = null;
    let installed = null;

    await sqlengine.withEngine(client, async (target) => {
      installed = target;
      fromSql = await sqlengine.readSchema(client, target, APP);
    });

    check('1. the engine installs and answers at all', (() => {
      const problems = [];
      if (!installed) problems.push('it was never installed');
      if (!fromSql) problems.push('it returned nothing');
      return problems;
    })());

    check('2. both engines see the same tables, in the same order', (() => {
      if (!fromSql) return ['nothing to compare'];
      const mine = fromNode.tables.map((t) => t.name);
      const theirs = (fromSql.tables || []).map((t) => t.name);
      return mine.join(',') === theirs.join(',')
        ? []
        : ['node: ' + mine.join(', ') + '   sql: ' + theirs.join(', ')];
    })());

    check('3. and the same shape, key for key', (() => {
      if (!fromSql) return ['nothing to compare'];
      // The one that matters. Not "close enough" - identical, or the two
      // engines have already started to drift and nothing downstream can be
      // trusted to mean the same thing in both.
      return differences(onlySoFar(fromNode), onlySoFar(fromSql));
    })());

    const { rows: left } = await client.query(
      "SELECT nspname FROM pg_namespace WHERE nspname LIKE 'kn\\_engine\\_%'",
    );
    check('4. the engine takes itself away again', (() => {
      // It gets installed into the customer's database to answer one question.
      // Leaving it there is the same litter the scan used to leave.
      return left.length ? ['still there: ' + left.map((r) => r.nspname).join(', ')] : [];
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    await undoAuth();
    await client.end();
  }

  console.log('');
  let failures = 0;
  for (const result of results) {
    if (result.problems.length) {
      failures++;
      console.log('FAIL  ' + result.name);
      result.problems.slice(0, 12).forEach((p) => console.log('      - ' + p));
      if (result.problems.length > 12) {
        console.log('      ... and ' + (result.problems.length - 12) + ' more');
      }
    } else {
      console.log('PASS  ' + result.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exitCode = 1;
  } else {
    console.log('All ' + results.length + ' twin checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
