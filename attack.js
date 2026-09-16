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

/** Something valid to put in a column, so a row can exist at all. */
function valueFor(column, owner) {
  const type = String(column.type).toLowerCase();
  if (type === 'uuid') return owner;
  if (/^(integer|bigint|smallint|numeric|decimal|real|double)/.test(type)) return 1;
  if (/^bool/.test(type)) return true;
  if (/^(timestamp|date)/.test(type)) return new Date().toISOString();
  if (/^json/.test(type)) return '{}';
  return 'kryptheon test';
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

    const keys = foreignKeys(table);
    const pointsAt = new Map(keys.map((k) => [k.column, k]));

    try {
      for (const person of people) {
        const columns = [];
        const values = [];
        for (const column of table.columns) {
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
          values.push(valueFor(column, person));
        }
        const placeholders = values.map((_, i) => '$' + (i + 1));
        await client.query(
          'INSERT INTO ' + quote(schema) + '.' + quote(table.name) +
            ' (' + columns.map(quote).join(', ') + ') VALUES (' + placeholders.join(', ') + ')',
          values,
        );
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
    await client.query('SELECT set_config($1, $2, true)', [
      'request.jwt.claims',
      userId ? JSON.stringify({ sub: userId, role: role }) : '',
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

  for (const table of tables) {
    const owner = ownerColumn(table);
    const anon = await readAs(client, schema, table.name, 'anon', null);
    const asA = await readAs(client, schema, table.name, 'authenticated', USER_A);

    const anonRows = Array.isArray(anon) ? anon.length : 0;
    if (anonRows > 0) {
      findings.push({
        kind: 'exposed',
        table: table.name,
        readable: anonRows,
        columns: Object.keys(anon[0] || {}),
        rlsEnabled: table.rlsEnabled,
      });
    }

    if (owner && Array.isArray(asA)) {
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

  return findings;
}

/** A stable shape for comparing one run against another. */
function summarise(findings) {
  return findings
    .map((f) => f.kind + ':' + f.table + ':' + f.readable)
    .sort()
    .join(' | ');
}

module.exports = {
  USER_A: USER_A,
  USER_B: USER_B,
  ownerColumn: ownerColumn,
  foreignKeys: foreignKeys,
  dependencyOrder: dependencyOrder,
  seed: seed,
  readAs: readAs,
  impersonate: impersonate,
  summarise: summarise,
};
