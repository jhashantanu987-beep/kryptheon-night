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
const attack = require('./attack.js');
const sqlengine = require('./sqlengine.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_twin_' + Date.now().toString(36);
// The table that holds one column of every type the seeder has a rule for.
const EVERYTHING = 'everything';
// A schema the visitor is never given USAGE on. Named the way every
// fixture is, so a run that dies still leaves something the sweep can see.
const PRIVATE = 'kn_locked_' + Date.now().toString(36);
// Any one of the seeded people; which of them is not what is under test.
const SOMEBODY = '11111111-1111-4111-8111-111111111111';

/** What a value the Node side would hand the driver looks like written down. */
function asText(value) {
  if (value === null || value === undefined) return null;
  if (Buffer.isBuffer(value)) return value.toString();
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/** Every row of every table of a copy, as text, in an order that does not vary. */
async function contentsOf(client, where) {
  const { rows: tables } = await client.query(
    'SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace' +
      " WHERE n.nspname = $1 AND c.relkind = 'r' ORDER BY c.relname",
    [where],
  );
  const out = {};
  for (const one of tables) {
    const { rows: cols } = await client.query(
      "SELECT attname FROM pg_attribute WHERE attrelid = format('%I.%I', $1::text, $2::text)::regclass" +
        ' AND attnum > 0 AND NOT attisdropped ORDER BY attnum',
      [where, one.relname],
    );
    const named = cols.map((col) => schema.quote(col.attname) + '::text').join(", ' | ', ");
    const { rows } = await client.query(
      "SELECT concat_ws('', " + named + ') AS line FROM ' +
        schema.quote(where) + '.' + schema.quote(one.relname) + ' ORDER BY 1',
    );
    out[one.relname] = rows.map((r) => r.line);
  }
  return out;
}

/** An app made of everything that has ever been read wrong. */
async function buildApp(client) {
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await fixture.ensureRoles(client, APP, schema.quote);
  undoAuth = await fixture.ensureAuth(client);

  await client.query('CREATE TYPE ' + schema.quote(APP) + ".order_status AS ENUM ('new', 'paid', 'shipped')");
  await client.query('CREATE DOMAIN ' + schema.quote(APP) + ".email_address AS text CHECK (VALUE LIKE '%@%')");
  await client.query('CREATE DOMAIN ' + schema.quote(APP) + '.positive_count AS integer CHECK (VALUE > 0)');
  await client.query('CREATE DOMAIN ' + schema.quote(APP) + '.short_code AS varchar(4)');
  // A domain standing on the app's own enum. Two things only this shape
  // reaches: the types have to be created enum-first or the domain has
  // nothing to stand on, and the domain's base type has to be rewritten to
  // point at the copy's enum rather than the original's.
  await client.query(
    'CREATE DOMAIN ' + schema.quote(APP) + '.settled_status AS ' + schema.quote(APP) + '.order_status' +
      " CHECK (VALUE <> 'new')",
  );

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
      ' settled ' + schema.quote(APP) + '.settled_status,' +
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
  await client.query('CREATE SCHEMA ' + schema.quote(PRIVATE));
  await client.query('CREATE FUNCTION ' + schema.quote(PRIVATE) +
    '.is_allowed(who uuid) RETURNS boolean LANGUAGE sql STABLE AS ' + "$fn$ SELECT true $fn$");
  // Hiding the schema is not enough, which was worth finding out: a policy
  // expression is stored already parsed, with the OID of the function in
  // it, so nothing resolves a name at read time and USAGE on the schema is
  // never checked. Only EXECUTE on the function is, and that is granted to
  // PUBLIC the moment the function is created.
  //
  // Revoked on this run's own function, in this run's own schema, and
  // nowhere else. blocked.check.js learned that the expensive way, by
  // revoking on the customer's auth.uid() and poisoning every later check.
  await client.query('REVOKE ALL ON FUNCTION ' + schema.quote(PRIVATE) +
    '.is_allowed(uuid) FROM PUBLIC');
  await client.query('CREATE TABLE ' + q('locked') +
    ' (id serial PRIMARY KEY, owner uuid NOT NULL)');
  await client.query('ALTER TABLE ' + q('locked') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY through_a_closed_door ON ' + q('locked') +
    ' FOR SELECT TO anon, authenticated USING (' + schema.quote(PRIVATE) +
    '.is_allowed(owner))');
  // A policy granted to a logged-out visitor that calls auth.uid().
  //
  // Without one, the worst bug this product has had cannot be caught here:
  // sending a logged-out visitor with no claims at all makes auth.uid()
  // throw, the read returns nothing, and nothing is exactly what a properly
  // secured table returns. The fixture's other policies are either granted
  // only to authenticated or say USING (true), so neither of them ever
  // reaches auth.uid() as anon.
  await client.query('CREATE TABLE ' + q('receipts') +
    ' (id serial PRIMARY KEY, owner uuid NOT NULL, amount numeric(10,2) NOT NULL)');
  await client.query('ALTER TABLE ' + q('receipts') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY mine_only ON ' + q('receipts') +
    ' FOR SELECT TO anon, authenticated USING (owner = auth.uid())');

  // Granted to nobody at all, so the attack is refused outright. Without
  // one of these, refusal_means is never called and the difference between
  // "the attack lost" and "the attack never ran" is never tested.
  await client.query('CREATE TABLE ' + q('internal') +
    ' (id serial PRIMARY KEY, note text NOT NULL)');

  // And an ungranted materialized view, because Postgres words that refusal
  // differently: "permission denied for materialized view". An alternation
  // that tried `view` first would never reach it.
  await client.query('CREATE MATERIALIZED VIEW ' + q('receipt_totals') +
    ' AS SELECT owner, count(*) AS n FROM ' + q('receipts') + ' GROUP BY owner');
  await client.query('CREATE TABLE ' + q('User Groups') + ' (' + schema.quote('Group Id') + ' integer PRIMARY KEY)');
  await client.query('CREATE TABLE ' + q('memberships') + ' (id serial PRIMARY KEY, ' + schema.quote('Group Id') + ' integer NOT NULL REFERENCES ' + q('User Groups') + ' (' + schema.quote('Group Id') + '))');
  await client.query('ALTER TABLE ' + q('orders') + ' ADD CONSTRAINT orders_owner_fkey FOREIGN KEY (owner) REFERENCES ' + q('profiles') + '(id)');
  await client.query('CREATE TABLE ' + q('carts') + ' (org_id integer, cart_id integer, PRIMARY KEY (org_id, cart_id))');
  await client.query('CREATE TABLE ' + q('cart_items') + ' (id serial PRIMARY KEY, org_id integer NOT NULL, cart_id integer NOT NULL,' + ' FOREIGN KEY (org_id, cart_id) REFERENCES ' + q('carts') + ' (org_id, cart_id))');
  await client.query('CREATE TABLE ' + q('folders') + ' (id integer PRIMARY KEY, parent_id integer REFERENCES ' + q('folders') + '(id))');
  // A varchar CHECK, whose rule Postgres writes through a cast; a value
  // with a comma in it; and a declared width a generated value has to be
  // cut down to. The first two were each written off as a table that could
  // not be checked.
  await client.query(
    'CREATE TABLE ' + q('tickets') +
      ' (id serial PRIMARY KEY, user_id uuid NOT NULL,' +
      " state varchar(12) NOT NULL CHECK (state IN ('open', 'closed, really', 'it''s shut'))," +
      ' code char(4))',
  );
  await client.query('CREATE TABLE ' + q('sessions') + ' (id serial PRIMARY KEY, session_token text NOT NULL)');
  await client.query('CREATE UNIQUE INDEX sessions_token_key ON ' + q('sessions') + ' (session_token)');
  await client.query(
    'CREATE TABLE ' + q('everything') + ' (' +
      'a_uuid uuid, a_int integer, a_big bigint, a_num numeric(10,2), a_real real,' +
      ' a_bool boolean, a_ts timestamptz, a_date date, a_time time, a_interval interval,' +
      ' a_json jsonb, a_inet inet, a_cidr cidr, a_mac macaddr, a_mac8 macaddr8,' +
      ' a_tsv tsvector, a_bytea bytea, a_xml xml, a_bit bit(1), a_point point,' +
      ' a_text text, a_varchar varchar(9), a_char char(3), a_money money,' +
      ' a_enum ' + schema.quote(APP) + '.order_status,' +
      ' a_domain ' + schema.quote(APP) + '.email_address,' +
      ' a_counted ' + schema.quote(APP) + '.positive_count,' +
      ' a_short ' + schema.quote(APP) + '.short_code,' +
      ' a_array text[])',
  );
  await client.query('CREATE VIEW ' + q('paid_orders') + ' AS SELECT id, owner, total FROM ' + q('orders') + " WHERE status = 'paid'");

  for (const t of [
    'profiles', 'orders', 'members', 'flags', 'sessions', 'tickets', 'everything',
    'carts', 'cart_items', 'folders', 'User Groups', 'memberships', 'receipts',
    'locked',
    // internal and receipt_totals are granted to nobody on purpose.
  ]) {
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
const SO_FAR = [
  'schema', 'tables', 'types', 'policies', 'grants', 'indexes', 'views', 'viewGrants', 'external', 'unsupported',
];

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

    /* ---------------- and now the copy each of them builds ---------------- */

    // The reading half agreeing is not enough. What the attacks run against is
    // the copy, so two copies that differ mean two sets of verdicts about two
    // different databases - and nothing outside would say which was which.
    const byNode = APP + '_node';
    const bySql = APP + '_sql';
    let copyDifferences = null;
    const seededDifferences = [];
    // Set when the seeding actually ran. Without it, a copy that fell over
    // before seeding left this check with nothing to report and passing -
    // which is the exact shape of failure this whole file exists to catch,
    // and it was in the check that catches it.
    let seedingRan = false;
    let attackRan = false;
    const verdictDifferences = [];
    let engineForSeeding = null;
    let engineForAttack = null;
    let nodeStatements = null;
    let sqlStatements = null;

    try {
      nodeStatements = await schema.writeSchema(client, fromNode, byNode);

      await sqlengine.withEngine(client, async (target) => {
        sqlStatements = await sqlengine.writeSchema(client, target, fromSql, bySql);
      });

      const readBack = async (where) => {
        const shape = onlySoFar(await schema.readSchema(client, where));
        // Each engine names its copy differently by design, and that name is not
        // only in `schema`: it is inside every index definition, sequence
        // default, column type and view body too. Taken out everywhere, or each
        // of those reads as a difference and the real ones are lost in the noise.
        return JSON.parse(JSON.stringify(shape).split(where).join('<copy>'));
      };
      copyDifferences = differences(await readBack(byNode), await readBack(bySql));

      // And now the rows. Up to here the two engines were asked the same
      // question and their answers compared; a seeder cannot be checked
      // that way, because what matters is not what it says but what ends
      // up in the table the attacks are about to run against.
      const mineSeeded = await attack.seed(client, byNode, fromNode.tables);
      let theirsSeeded = null;
      await sqlengine.withEngine(client, async (target) => {
        engineForSeeding = target;
        const { rows } = await client.query(
          'SELECT ' + schema.quote(target) + '.seed($1, $2::jsonb) AS answer',
          [bySql, JSON.stringify(fromSql.tables)],
        );
        theirsSeeded = rows[0].answer;
      });

      const told = (r) => JSON.stringify({
        seeded: (r.seeded || []).map((s) => s.table + '/' + s.owner + '/' + s.attempt).sort(),
        skipped: (r.skipped || []).map((s) => s.table).sort(),
      });
      if (told(mineSeeded) !== told(theirsSeeded)) {
        seededDifferences.push('the seeders report different things:' +
          '\n        node ' + told(mineSeeded) + '\n        sql  ' + told(theirsSeeded));
      }
      // A table nobody could seed is the one thing that must never differ
      // quietly: it is the difference between a hole examined and a hole
      // written off as unknown.
      const left = await contentsOf(client, byNode);
      const right = await contentsOf(client, bySql);
      for (const table of Object.keys(left)) {
        const a = JSON.stringify(left[table]);
        const b = JSON.stringify(right[table] === undefined ? null : right[table]);
        if (a !== b) {
          seededDifferences.push(table + ' came out different:' +
            '\n        node ' + a + '\n        sql  ' + b);
        }
      }
      seedingRan = true;

      // And the verdict. This is the one a person reads, so it is the one
      // that has to match: everything above it exists to make this
      // comparison mean something.
      // Tables and views, the same list scan.js attacks.
      const asTargets = (plan) => plan.tables.concat((plan.views || []).map((view) => ({
        name: view.name,
        columns: view.columns || [],
        constraints: [],
        rlsEnabled: false,
        isView: true,
      })));
      const mineSaid = await attack.impersonate(client, byNode, asTargets(fromNode));
      let theirsSaid = null;
      await sqlengine.withEngine(client, async (target) => {
        engineForAttack = target;
        const { rows } = await client.query(
          'SELECT ' + schema.quote(target) + '.impersonate($1, $2::jsonb) AS answer',
          [bySql, JSON.stringify(asTargets(fromSql))],
        );
        theirsSaid = rows[0].answer;
      });

      const verdict = (r) => JSON.stringify({
        findings: (r.findings || [])
          .map((f) => f.kind + ':' + f.table + '/' + f.readable + '/' + (f.owner || '-'))
          .sort(),
        completed: [...(r.completed || [])].sort(),
        // Which attacks could not be run at all, and on which table. A
        // table one engine tested and the other could not is the difference
        // between a hole examined and a hole written off as unknown.
        blocked: (r.blocked || []).map((b) => b.key).sort(),
      });
      if (verdict(mineSaid) !== verdict(theirsSaid)) {
        verdictDifferences.push('the two engines said different things:' +
          '\n        node ' + verdict(mineSaid) + '\n        sql  ' + verdict(theirsSaid));
      }
      attackRan = true;
    } catch (err) {
      copyDifferences = ['building a copy fell over: ' + err.message];
    }

    check('5. both engines want to run the same statements', (() => {
      if (!nodeStatements || !sqlStatements) return ['one of them did not get that far'];
      // Compared as a set: the Node side emits sequences per table as it goes
      // and the SQL side does the same, but a difference in what is run is a
      // difference in what gets built.
      const mine = nodeStatements.map((s) => s.replace(new RegExp(byNode, 'g'), '<copy>')).sort();
      const theirs = sqlStatements.map((s) => s.replace(new RegExp(bySql, 'g'), '<copy>')).sort();
      const found = [];
      for (const s of theirs) if (!mine.includes(s)) found.push('only sql runs: ' + s);
      for (const s of mine) if (!theirs.includes(s)) found.push('only node runs: ' + s);
      return found;
    })());

    check('6. and the two copies come out identical', (() => {
      // The one that matters most in this slice. Everything after it - seeding,
      // every attack, every verdict - is about whatever this built.
      return copyDifferences === null ? ['it never ran'] : copyDifferences;
    })());

    /* ------------- and the decisions seeding makes from it ------------- */

    // Before a row can be written, three things have to be decided: who the
    // row belongs to, what a CHECK will actually accept, and how wide a
    // generated value may be. They are decisions taken from the shape and
    // nothing else, so both engines can be asked the same question and their
    // answers compared exactly - which says more than comparing seeded rows,
    // where a disagreement only shows up as a row that looks different.
    let seedingDifferences = null;
    try {
      await sqlengine.withEngine(client, async (target) => {
        engineForSeeding = target;
        const found = [];
        const ask = async (fn, args) => {
          const places = args.map((ignored, i) => '$' + (i + 1)).join(', ');
          const { rows } = await client.query(
            'SELECT ' + schema.quote(target) + '.' + fn + '(' + places + ') AS answer',
            args,
          );
          return rows[0].answer;
        };

        for (const table of fromNode.tables) {
          const mine = attack.ownerColumn(table);
          const theirs = await ask('owner_column', [JSON.stringify(table)]);
          if (mine !== theirs) {
            found.push('owner of ' + table.name + ': node ' + JSON.stringify(mine) +
              ', sql ' + JSON.stringify(theirs));
          }
          for (const column of table.columns) {
            const m = attack.allowedByCheck(table, column.name);
            const t = (await ask('allowed_by_check', [JSON.stringify(table), column.name])) || [];
            if (JSON.stringify(m) !== JSON.stringify(t)) {
              found.push('what a check allows in ' + table.name + '.' + column.name +
                ': node ' + JSON.stringify(m) + ', sql ' + JSON.stringify(t));
            }
          }
        }

        // Widths, including the shapes that declare none and the ones whose
        // brackets hold something that is not a width at all.
        for (const [text, kind] of [
          ['kryptheon test', 'character varying(6)'],
          ['kryptheon test', 'character(4)'],
          ['kryptheon test', 'text'],
          ['kryptheon test', 'numeric(10,2)'],
          ['abc', 'character varying(3)'],
          ['', 'character varying(5)'],
          ['kryptheon', 'timestamp with time zone'],
        ]) {
          const m = attack.fitTo(text, kind);
          const t = await ask('fit_to', [text, kind]);
          if (m !== t) {
            found.push('fitting ' + JSON.stringify(text) + ' to ' + kind +
              ': node ' + JSON.stringify(m) + ', sql ' + JSON.stringify(t));
          }
        }
        // What each table points at, and what has to exist before it can.
        // An order that merely works is not enough: two engines seeding in
        // different orders would build two different copies, and nothing
        // downstream would say which verdict belonged to which.
        for (const table of fromNode.tables) {
          const m = attack.foreignKeys(table);
          const t = (await ask('foreign_keys', [JSON.stringify(table)])) || [];
          if (JSON.stringify(m) !== JSON.stringify(t)) {
            found.push('the keys on ' + table.name + ': node ' + JSON.stringify(m) +
              ', sql ' + JSON.stringify(t));
          }
        }
        {
          const m = attack.dependencyOrder(fromNode.tables).map((one) => one.name);
          const t = ((await ask('dependency_order', [JSON.stringify(fromNode.tables)])) || [])
            .map((one) => one.name);
          if (m.join(' -> ') !== t.join(' -> ')) {
            found.push('the order tables are seeded in: node ' + m.join(' -> ') +
              '   sql ' + t.join(' -> '));
          }
          // And it has to be an order that works, not merely a shared one.
          if (m.indexOf('profiles') > m.indexOf('orders')) {
            found.push('a child is seeded before its parent: ' + m.join(' -> '));
          }
          if (m.indexOf('carts') > m.indexOf('cart_items')) {
            found.push('the composite key comes before what it points at: ' + m.join(' -> '));
          }
        }

        // And the value each engine would put in a column. The Node side
        // hands a value to the driver as a parameter and the SQL side
        // returns the text the insert casts, so they are compared as text:
        // the thing that, put in that column, is the value.
        const everything = fromNode.tables.find((t) => t.name === EVERYTHING);
        for (const column of (everything || { columns: [] }).columns) {
          const moment = /^(timestamp|date)/.test(String(column.base_type || column.type).toLowerCase());
          for (const [distinct, attempt] of [[null, 0], ['2', 0], ['3', 1], ['2', 4], [null, 9]]) {
            const m = asText(attack.valueFor(column, SOMEBODY, distinct, attempt));
            const t = await ask('value_for', [JSON.stringify(column), SOMEBODY, distinct, attempt]);
            // A moment is the one thing that cannot match exactly: each
            // engine reads its own clock. Both have to produce one, though.
            if (moment) {
              if (Number.isNaN(Date.parse(m)) || Number.isNaN(Date.parse(t))) {
                found.push('a moment for ' + column.name + ': node ' + JSON.stringify(m) +
                  ', sql ' + JSON.stringify(t));
              }
              continue;
            }
            if (m !== t) {
              found.push('what goes in ' + column.name + ' (' + column.type + ')' +
                ' with tag ' + JSON.stringify(distinct) + ' on try ' + attempt +
                ': node ' + JSON.stringify(m) + ', sql ' + JSON.stringify(t));
            }
          }
        }

        seedingDifferences = found;
      });
    } catch (err) {
      seedingDifferences = ['asking the two engines fell over: ' + err.message];
    }

    check('9. and reach the same verdict about it', (() => {
      // Agreeing is not the same as being right, and this only asks the
      // first. What the answer OUGHT to be is verdicts.check.js, on an app
      // that declares it up front.
      if (!attackRan) return ['it never ran'];
      return verdictDifferences;
    })());

    check('8. and seed the copy into the same state', (() => {
      // The one the attacks stand on. Two copies seeded differently mean
      // two sets of verdicts about two different databases, and nothing
      // outside would say which was which.
      if (!seedingRan) return ['it never ran: ' + (copyDifferences || ['no copy']).join('; ')];
      return seededDifferences;
    })());

    check('7. both engines decide the same things before seeding a row', (() => {
      return seedingDifferences === null ? ['it never ran'] : seedingDifferences;
    })());

    const { rows: left } = await client.query(
      'SELECT nspname FROM pg_namespace WHERE nspname = ANY($1)',
      [[installed, engineForSeeding, engineForAttack].filter(Boolean)],
    );
    check('4. the engine takes itself away again', (() => {
      // It gets installed into the customer's database to answer one question.
      // Leaving it there is the same litter the scan used to leave.
      //
      // Asked about the engines THIS run installed, by name. Asking whether
      // any engine schema exists anywhere is a question about the whole
      // database: one abandoned hours ago by a killed process made this fail
      // and keep failing, blaming a run that had behaved perfectly.
      return left.length ? ['still there: ' + left.map((r) => r.nspname).join(', ')] : [];
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(PRIVATE) + ' CASCADE').catch(() => {});
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP + '_node') + ' CASCADE').catch(() => {});
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP + '_sql') + ' CASCADE').catch(() => {});
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
