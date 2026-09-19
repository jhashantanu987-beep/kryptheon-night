// The impersonation attack.
//
// Sign in as one person, ask for another person's data, and see what comes
// back. This is the attack a recorded browser flow can never find, because the
// frontend never even tries to ask for somebody else's rows - it only ever
// requests what the signed-in person is supposed to have.
//
// It runs the way a real request runs: become the role PostgREST becomes, put
// the caller's identity where PostgREST puts it, then read. Verified against a
// real database in probe-rls.js before any of this was written.
//
// Two fake people are seeded and nothing else is ever inserted, so a finding is
// always about rows this tool created. No real customer is involved at any
// point, which is the promise the whole product is sold on.

const { quote } = require('./schema.js');

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';

// Two more who own nothing at all. The seeded pair already hold a row each,
// so an attack that inserts under their name collides with the row the seeder
// put there - on a table keyed by the person, that is a primary key clash, and
// it was being read as the app refusing the attack. These are for any attack
// that has to add a row of its own.
const USER_C = '55555555-5555-4555-8555-555555555555';
const USER_D = '66666666-6666-4666-8666-666666666666';

// The names an owner column is actually given, in the order they are worth
// believing. `id` is last and only counts on a table that looks like a profile,
// where the row id IS the person.
const OWNER_NAMES = ['user_id', 'owner_id', 'owner', 'profile_id', 'account_id', 'created_by', 'author_id'];

/** The column that says who a row belongs to, or null if nothing does. */
function ownerColumn(table) {
  const uuids = table.columns.filter((c) => c.type === 'uuid');
  for (const name of OWNER_NAMES) {
    const found = uuids.find((c) => c.name === name);
    if (found) return found.name;
  }
  // A profiles table keyed by the person themselves.
  if (/profile|user|account|member/i.test(table.name)) {
    const id = uuids.find((c) => c.name === 'id');
    if (id) return id.name;
  }
  return null;
}

/** Keeps a generated value inside a declared width like varchar(20). */
function fitTo(text, type) {
  const match = /^[a-z ]*\((\d+)\)$/.exec(String(type).trim());
  if (!match) return text;
  const limit = Number(match[1]);
  return text.length > limit ? text.slice(0, limit) : text;
}

/**
 * Something valid to put in a column, so a row can exist at all.
 *
 * `distinct` is what keeps two seeded rows from being identical. Without it
 * every row carried the same text, so a table with a unique email column
 * refused the second insert and the whole table was reported as "not checked"
 * - a well-built app treated as an unknown one. The tag goes at the front
 * because a narrow varchar truncates the end, and two rows truncated to the
 * same string is that bug all over again.
 */
function valueFor(column, owner, distinct, attempt) {
  // A domain is somebody's own type with a rule bolted on. The rule cannot be
  // guessed at from here, but the type underneath it can be filled in.
  const type = String(column.base_type || column.type).toLowerCase();
  const tag = distinct === undefined || distinct === null ? '' : String(distinct);
  const step = Number(tag) || 0;

  // An enum accepts one of a fixed list and nothing else. Every generated
  // string was rejected, and the table went down as "not checked".
  //
  // Insisting on a real array rather than accepting anything with a length:
  // the labels arrived once as the string "{new,paid,shipped}", whose first
  // element is the character "{", and that is a value the database rejects
  // just as firmly while looking like the code is working.
  if (Array.isArray(column.enum_labels) && column.enum_labels.length) return column.enum_labels[0];
  // Anything at all is allowed in an empty array, whatever the element type.
  if (column.is_array || /\[\]$/.test(type)) return '{}';

  if (type === 'uuid') return owner;
  if (/^(integer|bigint|smallint|numeric|decimal|real|double|money)/.test(type)) return 1 + step;
  if (/^bool/.test(type)) return true;
  if (/^(timestamp|date)/.test(type)) return new Date().toISOString();
  if (/^time/.test(type)) return '12:00:00';
  if (/^interval/.test(type)) return '1 day';
  if (/^json/.test(type)) return '{}';
  if (/^(inet|cidr)/.test(type)) return '192.0.2.' + (1 + step);
  if (/^macaddr8/.test(type)) return '08:00:2b:01:02:03:04:0' + (5 + step);
  if (/^macaddr/.test(type)) return '08:00:2b:01:02:0' + (3 + step);
  if (/^(tsvector|tsquery)/.test(type)) return 'kryptheon';
  if (/^bytea/.test(type)) return Buffer.from('kryptheon');
  if (/^xml/.test(type)) return '<kryptheon/>';
  if (/^bit/.test(type)) return '0';
  if (/^(point|line|lseg|box|path|polygon|circle)/.test(type)) return '(0,0)';

  // Text is where the rules live that cannot be read: a domain that insists on
  // an @, a CHECK on a length, a regex for a product code. Rather than pretend
  // to understand them, the seeder works down a short ladder of shapes and
  // keeps whichever one the database accepts.
  const shapes = [
    tag ? tag + ' kryptheon test' : 'kryptheon test',
    'kryptheon' + (tag || '') + '@example.com',
    'KN' + (tag || '1'),
    String(step + 1),
    'https://example.com/kryptheon',
  ];
  return fitTo(shapes[Math.min(Math.max(attempt || 0, 0), shapes.length - 1)], type);
}

/**
 * Values a CHECK constraint will actually accept for one column.
 *
 * `status text CHECK (status IN ('open','closed'))` is one of the most common
 * things anyone writes, and Postgres stores it as
 * `CHECK ((status = ANY (ARRAY['open'::text, 'closed'::text])))`. Reading the
 * literals back out turns a table that could never be seeded into one that can.
 *
 * Only this one shape is understood, deliberately. A CHECK can contain
 * anything, and pretending to satisfy an arbitrary one would mean inventing
 * rows that the app itself would reject.
 */
function allowedByCheck(table, columnName) {
  const found = [];
  const escaped = String(columnName).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Both spellings of the same rule. On a text column Postgres writes
  //   state = ANY (ARRAY['open'::text, ...])
  // and on a varchar column it writes
  //   (state)::text = ANY ((ARRAY['open'::character varying, ...])::text[])
  // which the first pattern could not cross: it stopped at the bracket that
  // closes the cast. A varchar column with an IN list is an ordinary thing to
  // write, and every table with one was seeded with an invented value, refused
  // by its own constraint, and reported as a table that could not be checked.
  //
  // What may sit between the column and the = is spelled out rather than left
  // to a negated class: anything looser reaches across the next AND and hands
  // one column's allowed values to another.
  const anyOf = new RegExp(
    '\\b' + escaped + '\\b\\)?(?:::[a-z ]+)?\\s*=\\s*ANY\\s*\\(+\\s*ARRAY\\[(.*?)\\]',
    'i',
  );
  for (const constraint of table.constraints || []) {
    if (constraint.kind !== 'c') continue;
    const match = anyOf.exec(String(constraint.definition));
    if (!match) continue;
    // Picked out one at a time rather than split on commas, which came apart
    // in the middle of any value that had a comma in it.
    const literals = /'((?:[^']|'')*)'/g;
    let literal;
    while ((literal = literals.exec(match[1])) !== null) {
      found.push(literal[1].split("''").join("'"));
    }
  }
  return found;
}

/**
 * The foreign keys on a table, read out of Postgres's own wording.
 *
 * Every column of the key, not just the first. A key over (org_id, cart_id)
 * used to be read as though it were only org_id: the second column got an
 * invented value, the pair pointed at no row that existed, and the table was
 * reported as one that could not be checked.
 */
function foreignKeys(table) {
  const keys = [];
  const unquote = (text) => text.trim().split('"').join('');
  for (const constraint of table.constraints || []) {
    if (constraint.kind !== 'f') continue;
    const match = /FOREIGN KEY \(([^)]+)\) REFERENCES ([^(]+)\(([^)]+)\)/i.exec(constraint.definition);
    if (!match) continue;
    keys.push({
      columns: match[1].split(',').map(unquote),
      refTable: unquote(match[2].split('.').pop()),
      refColumns: match[3].split(',').map(unquote),
    });
  }
  return keys;
}

/**
 * Parents before children.
 *
 * Tables come back in alphabetical order, which put `orders` before `profiles`
 * and made every insert fail on the foreign key - on the first real app it was
 * pointed at, because every app has one of these. A cycle is left in whatever
 * order it arrived: it cannot be satisfied anyway, and the table that fails is
 * reported rather than dropped.
 */
function dependencyOrder(tables) {
  const byName = new Map(tables.map((t) => [t.name, t]));
  const ordered = [];
  const done = new Set();
  const visiting = new Set();

  const visit = (table) => {
    if (done.has(table.name) || visiting.has(table.name)) return;
    visiting.add(table.name);
    for (const key of foreignKeys(table)) {
      const parent = byName.get(key.refTable);
      if (parent && parent.name !== table.name) visit(parent);
    }
    visiting.delete(table.name);
    done.add(table.name);
    ordered.push(table);
  };

  for (const table of tables) visit(table);
  return ordered;
}

/**
 * One row that is really in the parent table, so a foreign key is satisfied.
 *
 * The whole row, not one column of it. A composite key has to point at a pair
 * that exists together: borrowing each column from a separate row would build
 * a combination the parent never had.
 */
async function existingRow(client, schema, key) {
  try {
    const columns = key.refColumns.map((name, i) => quote(name) + ' AS v' + i).join(', ');
    const { rows } = await client.query(
      'SELECT ' + columns + ' FROM ' + quote(schema) + '.' + quote(key.refTable) + ' LIMIT 1',
    );
    if (!rows.length) return null;
    return key.refColumns.map((name, i) => rows[0]['v' + i]);
  } catch (err) {
    return null;
  }
}

/**
 * A row that will actually go in.
 *
 * Owner column set to the person, foreign keys pointing at rows that really
 * exist, every NOT NULL column filled, and anything with a default left to
 * supply its own value.
 *
 * `overrides` is what the Collision attack needs: it forces one column to a
 * chosen value while everything else stays distinct, so when two inserts race
 * they collide on that column and on nothing else. Without it a second unique
 * column elsewhere in the table would refuse the insert, and the refusal would
 * be read as the app defending itself.
 */
async function rowFor(client, schema, table, person, distinct, overrides, attempt) {
  const forced = overrides || {};
  const owner = ownerColumn(table);
  const columns = [];
  const values = [];

  // Every column that takes part in a foreign key, and the value it has to
  // hold. Resolved one key at a time so that all of a composite key's columns
  // come from the same parent row.
  const borrowed = new Map();
  for (const key of foreignKeys(table)) {
    const row = await existingRow(client, schema, key);
    if (!row) continue;
    key.columns.forEach((name, i) => {
      if (!borrowed.has(name)) borrowed.set(name, row[i]);
    });
  }
  const partOfKey = new Set();
  for (const key of foreignKeys(table)) key.columns.forEach((name) => partOfKey.add(name));

  for (const column of table.columns) {
    if (Object.prototype.hasOwnProperty.call(forced, column.name)) {
      columns.push(column.name);
      values.push(forced[column.name]);
      continue;
    }
    if (column.name === owner) {
      columns.push(column.name);
      values.push(person);
      continue;
    }
    // A column pointing at another table has to hold something that is
    // actually there, whatever its type would otherwise suggest.
    if (partOfKey.has(column.name)) {
      if (borrowed.has(column.name)) {
        columns.push(column.name);
        values.push(borrowed.get(column.name));
        continue;
      }
      if (column.not_null) throw new Error('nothing to point ' + column.name + ' at');
      continue;
    }
    // A generated column computes itself and refuses to be written to at all.
    //
    // Two halves, and only one of them can be observed. An identity column
    // carries no default_expr, so without the identity half the seeder writes
    // to it and Postgres refuses the row - both engines are caught doing it.
    // A stored generated column keeps its expression IN default_expr, so the
    // line below skips it whether or not this one does: removing the generated
    // half changes nothing any fixture could see. It stays because that is a
    // fact about how readColumns fills the shape, not about Postgres, and the
    // day it changes this is the only thing standing in the way.
    if (column.generated || column.identity) continue;
    // Anything with a default can supply its own value.
    if (column.default_expr) continue;
    if (!column.not_null) continue;
    columns.push(column.name);
    // A CHECK that lists what it will accept beats anything invented here.
    const allowed = allowedByCheck(table, column.name);
    values.push(
      allowed.length
        ? allowed[Math.min(Math.max(attempt || 0, 0), allowed.length - 1)]
        : valueFor(column, person, distinct, attempt),
    );
  }

  return { columns: columns, values: values };
}

/** Puts a built row in. Separate so the same row can be raced against itself. */
function insertRow(client, schema, table, row) {
  const where = 'INSERT INTO ' + quote(schema) + '.' + quote(table);
  // A table of nothing but an id and its defaults leaves no columns to name,
  // and "INSERT INTO t () VALUES ()" is a syntax error. Postgres has a spelling
  // for exactly this, and without it every settings and flags table in the
  // world came back as one that could not be checked.
  if (!row.columns.length) return client.query(where + ' DEFAULT VALUES');
  const placeholders = row.values.map((_, i) => '$' + (i + 1));
  return client.query(
    where + ' (' + row.columns.map(quote).join(', ') + ') VALUES (' + placeholders.join(', ') + ')',
    row.values,
  );
}

// How many differently-shaped values to try before giving up on a table. The
// rules that reject the first attempt - a domain insisting on an @, a CHECK on
// a length - cannot be read out of the catalogue, so the only honest way to
// satisfy them is to offer something else and see.
const SHAPES_TO_TRY = 5;

/**
 * Two rows per table: one belonging to each fake person.
 *
 * Inserted as the owner of the schema, deliberately - seeding is not the
 * attack, and a policy that blocked the seed would leave nothing to attack.
 *
 * A table that cannot be seeded is recorded rather than skipped quietly. An
 * empty table reads as a safe table, so silently failing here would report an
 * app as secure because the tool could not get a row into it.
 */
async function seed(client, schema, tables) {
  const seeded = [];
  const skipped = [];
  for (const table of dependencyOrder(tables)) {
    const owner = ownerColumn(table);

    // A table with nobody's name on it still gets a row. Without one, an open
    // door cannot be told from an empty room: a logged-out stranger reads zero
    // rows either way, and the tool reports the app as safe. Settings tables,
    // waitlists and contact forms are exactly this shape, and exactly the ones
    // that get left open.
    const people = owner ? [USER_A, USER_B] : [USER_A];

    // Each attempt offers a differently-shaped set of values. A table whose
    // rules reject all of them is reported, never quietly passed over.
    let refused = null;
    let landed = false;
    let worked = 0;
    for (let attempt = 0; attempt < SHAPES_TO_TRY && !landed; attempt++) {
      try {
        let nth = 0;
        for (const person of people) {
          nth += 1;
          const row = await rowFor(client, schema, table, person, nth, null, attempt);
          await insertRow(client, schema, table.name, row);
        }
        landed = true;
        worked = attempt;
      } catch (err) {
        refused = err.message;
        // A half-seeded table would make the next attempt collide with its own
        // first row, so anything that did go in is taken back out.
        await client
          .query('DELETE FROM ' + quote(schema) + '.' + quote(table.name))
          .catch(() => {});
      }
    }

    if (landed) {
      // The shape that worked is kept: any later attack that has to insert into
      // this table can use the same one instead of rediscovering it, and be
      // sure a refusal is the app defending itself rather than a CHECK it
      // never satisfied.
      seeded.push({ table: table.name, owner: owner, attempt: worked });
    } else {
      // Recorded, never swallowed. The report has to say this table was not
      // checked rather than let an empty table pass for a safe one.
      skipped.push({ table: table.name, why: refused });
    }
  }
  return { seeded: seeded, skipped: skipped };
}

/** Reads a table the way a request would, as whoever is asking. */
async function readAs(client, schema, table, role, userId) {
  await client.query('BEGIN');
  try {
    await client.query('SET LOCAL role TO ' + role);
    // A logged-out visitor is not "no claims". Supabase hands PostgREST the
    // anon key, which is itself a JWT, so request.jwt.claims arrives as a real
    // JSON object that simply has no `sub` in it.
    //
    // Sending an empty string instead made auth.uid() throw on the cast, and a
    // read that throws returns no rows - which is exactly what a properly
    // secured table returns. Every table whose policy calls auth.uid(), which
    // is nearly every table anyone writes, came back looking safe without the
    // rule ever being evaluated.
    await client.query('SELECT set_config($1, $2, true)', [
      'request.jwt.claims',
      JSON.stringify(userId ? { sub: userId, role: role } : { role: role }),
    ]);
    const result = await client.query('SELECT * FROM ' + quote(schema) + '.' + quote(table));
    return result.rows;
  } catch (err) {
    // A refusal is an answer: the table is not reachable by this caller at all.
    return { blocked: err.message };
  } finally {
    await client.query('ROLLBACK');
  }
}

function rowsOwnedBy(rows, owner, person) {
  if (!Array.isArray(rows)) return 0;
  return rows.filter((r) => String(r[owner]) === person).length;
}

/**
 * A refusal is only an answer when it is the right refusal.
 *
 * "permission denied for table orders" means this caller cannot reach the
 * table at all. That is the attack being defeated, and it is good news worth
 * recording as a pass.
 *
 * Everything else - a schema the policy needs and the role cannot use, a
 * function the policy calls that is not there, a timeout - means the rule was
 * never evaluated. No verdict exists. Both come back as an error and return
 * zero rows, and zero rows is exactly what a perfectly secured table returns,
 * so telling them apart is the difference between "you are safe" and "I could
 * not tell", which is the difference the whole product rests on.
 */
function refusalMeans(message) {
  // The multi-word kinds come first. Postgres says "permission denied for
  // materialized view hits", and an alternation that tried `view` first would
  // never reach it - so a matview nobody had granted was filed as untested
  // rather than as the attack being beaten, and a correct app collected a
  // warning it had not earned.
  const denied = /permission denied for (materialized view|foreign table|partitioned table|table|relation|view|sequence)/i;
  return denied.test(String(message)) ? 'unreachable' : 'untested';
}

/**
 * What each table gives away, and to whom.
 *
 * Two separate findings, because they are two different conversations with the
 * person who has to fix it:
 *
 *   exposed  - a logged-out stranger can read the table. This is the one that
 *              ends up on a news site.
 *   crossed  - a signed-in customer can read another customer's rows. Quieter,
 *              and the one that breaks trust with the people already paying.
 */
async function impersonate(client, schema, tables) {
  const findings = [];
  const completed = [];
  const blocked = [];

  /** Did this read produce a verdict, and if not, why not? */
  const settle = (key, table, answer, as) => {
    if (Array.isArray(answer)) {
      completed.push(key);
      return true;
    }
    if (refusalMeans(answer.blocked) === 'unreachable') {
      // Refused outright. The attack ran and lost, which is the result we want
      // for a table that is properly closed.
      completed.push(key);
      return false;
    }
    blocked.push({ table: table, key: key, why: as + ': ' + answer.blocked });
    return false;
  };

  for (const table of tables) {
    const owner = ownerColumn(table);
    const anon = await readAs(client, schema, table.name, 'anon', null);
    const asA = await readAs(client, schema, table.name, 'authenticated', USER_A);

    if (settle('exposed:' + table.name, table.name, anon, 'as a logged-out visitor') && anon.length > 0) {
      findings.push({
        kind: 'exposed',
        table: table.name,
        readable: anon.length,
        columns: Object.keys(anon[0] || {}),
        rlsEnabled: table.rlsEnabled,
        isView: Boolean(table.isView),
      });
    }

    // Crossed is only ever looked for where a row says who it belongs to, so
    // on a table with no owner there is no attack to record either way.
    if (owner && settle('crossed:' + table.name, table.name, asA, 'as a signed-in customer')) {
      const theirs = rowsOwnedBy(asA, owner, USER_B);
      if (theirs > 0) {
        findings.push({
          kind: 'crossed',
          table: table.name,
          owner: owner,
          readable: theirs,
          columns: Object.keys(asA[0] || {}),
          rlsEnabled: table.rlsEnabled,
        });
      }
    }
  }

  return { findings: findings, completed: completed, blocked: blocked };
}

/** A stable shape for comparing one run against another. */
function summarise(result) {
  const findings = Array.isArray(result) ? result : (result && result.findings) || [];
  return findings
    .map((f) => f.kind + ':' + f.table + ':' + f.readable)
    .sort()
    .join(' | ');
}

module.exports = {
  USER_A: USER_A,
  USER_B: USER_B,
  USER_C: USER_C,
  USER_D: USER_D,
  refusalMeans: refusalMeans,
  ownerColumn: ownerColumn,
  fitTo: fitTo,
  foreignKeys: foreignKeys,
  dependencyOrder: dependencyOrder,
  valueFor: valueFor,
  allowedByCheck: allowedByCheck,
  rowFor: rowFor,
  existingRow: existingRow,
  insertRow: insertRow,
  seed: seed,
  readAs: readAs,
  impersonate: impersonate,
  summarise: summarise,
};
