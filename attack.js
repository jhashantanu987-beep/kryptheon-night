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
function valueFor(column, owner, distinct) {
  const type = String(column.type).toLowerCase();
  const tag = distinct === undefined || distinct === null ? '' : String(distinct);
  const step = Number(tag) || 0;
  if (type === 'uuid') return owner;
  if (/^(integer|bigint|smallint|numeric|decimal|real|double)/.test(type)) return 1 + step;
  if (/^bool/.test(type)) return true;
  if (/^(timestamp|date)/.test(type)) return new Date().toISOString();
  if (/^json/.test(type)) return '{}';
  return fitTo(tag ? tag + ' kryptheon test' : 'kryptheon test', type);
}

/** The foreign keys on a table, read out of Postgres's own wording. */
function foreignKeys(table) {
  const keys = [];
  for (const constraint of table.constraints || []) {
    if (constraint.kind !== 'f') continue;
    const match = /FOREIGN KEY \(([^)]+)\) REFERENCES ([^(]+)\(([^)]+)\)/i.exec(constraint.definition);
    if (!match) continue;
    const refTable = match[2].trim().split('.').pop().split('"').join('');
    keys.push({
      column: match[1].split(',')[0].trim().split('"').join(''),
      refTable: refTable,
      refColumn: match[3].split(',')[0].trim().split('"').join(''),
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

/** A value already present in the parent table, so a foreign key is satisfied. */
async function existingValue(client, schema, key) {
  try {
    const { rows } = await client.query(
      'SELECT ' + quote(key.refColumn) + ' AS v FROM ' + quote(schema) + '.' + quote(key.refTable) + ' LIMIT 1',
    );
    return rows.length ? rows[0].v : null;
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
async function rowFor(client, schema, table, person, distinct, overrides) {
  const forced = overrides || {};
  const owner = ownerColumn(table);
  const pointsAt = new Map(foreignKeys(table).map((k) => [k.column, k]));
  const columns = [];
  const values = [];

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
    const key = pointsAt.get(column.name);
    if (key) {
      const borrowed = await existingValue(client, schema, key);
      if (borrowed !== null) {
        columns.push(column.name);
        values.push(borrowed);
        continue;
      }
      if (column.not_null) throw new Error('nothing in ' + key.refTable + ' to point ' + column.name + ' at');
      continue;
    }
    // Anything with a default can supply its own value.
    if (column.default_expr) continue;
    if (!column.not_null) continue;
    columns.push(column.name);
    values.push(valueFor(column, person, distinct));
  }

  return { columns: columns, values: values };
}

/** Puts a built row in. Separate so the same row can be raced against itself. */
function insertRow(client, schema, table, row) {
  const placeholders = row.values.map((_, i) => '$' + (i + 1));
  return client.query(
    'INSERT INTO ' + quote(schema) + '.' + quote(table) +
      ' (' + row.columns.map(quote).join(', ') + ') VALUES (' + placeholders.join(', ') + ')',
    row.values,
  );
}

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

    try {
      let nth = 0;
      for (const person of people) {
        nth += 1;
        const row = await rowFor(client, schema, table, person, nth);
        await insertRow(client, schema, table.name, row);
      }
      seeded.push({ table: table.name, owner: owner });
    } catch (err) {
      // Recorded, never swallowed. The report has to say this table was not
      // checked rather than let an empty table pass for a safe one.
      skipped.push({ table: table.name, why: err.message });
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
  return /permission denied for (table|relation|view|sequence)/i.test(String(message))
    ? 'unreachable'
    : 'untested';
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
  refusalMeans: refusalMeans,
  ownerColumn: ownerColumn,
  foreignKeys: foreignKeys,
  dependencyOrder: dependencyOrder,
  valueFor: valueFor,
  rowFor: rowFor,
  insertRow: insertRow,
  seed: seed,
  readAs: readAs,
  impersonate: impersonate,
  summarise: summarise,
};
