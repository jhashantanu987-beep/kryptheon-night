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

// A key to Supabase's auth.users as the app wrote it. In the copy it points
// at a stand-in named kn_ext__auth__users, which the table-of-people rule
// below already recognises; this one is for a table itself called users.
const TO_AUTH_USERS = /REFERENCES\s+"?auth"?\s*\.\s*"?users"?\s*\(/i;
// A table that looks like it holds people, keyed by the person.
const PERSON_TABLE = /(profile|user|account|member)/i;

/**
 * The single-column keys from a uuid column, with what they point at. Read
 * from the constraint wording itself, because a key to auth.users and a key
 * to public.users are different things and the schema is part of the words.
 */
function personKeys(table, uuids) {
  const byName = new Set(uuids.map((c) => c.name));
  const keys = [];
  for (const constraint of table.constraints || []) {
    if (constraint.kind !== 'f') continue;
    const definition = String(constraint.definition || '');
    const match = /FOREIGN KEY \(([^)]+)\) REFERENCES ([^(]+)\(([^)]+)\)/i.exec(definition);
    if (!match) continue;
    const columns = match[1].split(',').map((t) => t.trim().split('"').join(''));
    const refColumns = match[3].split(',').map((t) => t.trim().split('"').join(''));
    if (columns.length !== 1 || !byName.has(columns[0])) continue;
    keys.push({
      column: columns[0],
      toAuth: TO_AUTH_USERS.test(definition),
      refTable: match[2].split('.').pop().trim().split('"').join(''),
      refColumn: refColumns[0],
    });
  }
  return keys;
}

/** The column that says who a row belongs to, or null if nothing does. */
function ownerColumn(table) {
  const uuids = table.columns.filter((c) => c.type === 'uuid');
  for (const name of OWNER_NAMES) {
    const found = uuids.find((c) => c.name === name);
    if (found) return found.name;
  }
  // Not named like an owner, but pointing at a person. Found on a blind test:
  // appointments.provider_id -> profiles.id -> auth.users. Judged by name
  // alone it had no owner, so "one provider reads another's patients" - a
  // rule written USING (true) - was never tried, and the worst hole in the
  // app went unreported. `id` first: a table keyed by the person is theirs.
  // Two people on one row - sender_id and recipient_id - and neither is
  // named: whose row it is cannot be told, and guessing would report one
  // person reading a message sent to them as a break. So only one, or none.
  const people = personKeys(table, uuids).filter((k) => k.toAuth ||
    (k.refColumn === 'id' && k.refTable !== table.name && PERSON_TABLE.test(k.refTable)));
  const columns = Array.from(new Set(people.map((k) => k.column)));
  if (columns.includes('id')) return 'id';
  if (columns.length === 1) return columns[0];
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
 * Sets of columns where exactly one may be filled in.
 *
 * Found on a blind test (HelixOps): documents belonged to a work order or to
 * an inspection, never both, written
 *   CHECK ((work_order_id IS NOT NULL)::int + (inspection_id IS NOT NULL)::int = 1)
 * Both parents were there, so the seeder pointed the row at both, the CHECK
 * refused every attempt, and the table was never tested at all.
 *
 * Two spellings are read - that sum, and num_nonnulls(a, b, ...) = 1 - and
 * only when the constraint says nothing else. A CHECK with anything more in it
 * is left alone rather than half understood.
 */
function exactlyOne(table) {
  const groups = [];
  const name = '("(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)';
  const unquote = (text) => (text.charAt(0) === '"' ? text.slice(1, -1).split('""').join('"') : text);
  for (const constraint of table.constraints || []) {
    if (constraint.kind !== 'c') continue;
    const definition = String(constraint.definition || '');
    let columns = [];
    let rest = definition;
    const summed = new RegExp('\\(\\(' + name + ' IS NOT NULL\\)\\)::integer', 'gi');
    let match;
    while ((match = summed.exec(definition)) !== null) columns.push(unquote(match[1]));
    rest = rest.replace(summed, '').replace(/\+/g, '');
    if (!columns.length) {
      const counted = /num_nonnulls\(([^()]*)\)/i.exec(definition);
      if (counted) {
        const listed = new RegExp(name, 'g');
        let one;
        while ((one = listed.exec(counted[1])) !== null) columns.push(unquote(one[1]));
        rest = rest.replace(counted[0], '');
      }
    }
    // Nothing may be left but the CHECK itself, brackets and "= 1".
    if (columns.length < 2 || rest.replace(/[()\s]/g, '').toUpperCase() !== 'CHECK=1') continue;
    groups.push(columns);
  }
  return groups;
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

/** The single-column primary key of a table, or null if it has none. */
function primaryKeyOf(table) {
  for (const constraint of table.constraints || []) {
    if (constraint.kind !== 'p') continue;
    const match = /PRIMARY KEY \(([^)]+)\)/i.exec(constraint.definition);
    if (!match) continue;
    const columns = match[1].split(',').map((name) => name.trim().split('"').join(''));
    // A composite key is not something a single `<thing>_id` column points at.
    return columns.length === 1 ? columns[0] : null;
  }
  return null;
}

/**
 * The table a column named `<thing>_id` is pointing at, if there is one.
 *
 * The name has to match a table that is really here, and the types have to
 * agree. Both, because `stripe_id` matches nothing and `org_id integer` does
 * not point at an `orgs.id` that is a uuid.
 */
function parentFor(column, tables) {
  const stem = /^(.+)_id$/i.exec(column.name);
  if (!stem) return null;
  const wanted = stem[1].toLowerCase();
  const parent = (tables || []).find((table) => {
    const name = table.name.toLowerCase();
    return name === wanted || name === wanted + 's' || name === wanted + 'es';
  });
  if (!parent) return null;

  const key = primaryKeyOf(parent);
  if (!key) return null;
  const keyColumn = (parent.columns || []).find((c) => c.name === key);
  if (!keyColumn || keyColumn.type !== column.type) return null;

  return { table: parent, keyColumn: key, type: keyColumn.type };
}

/**
 * The keys a table would have if it had been given them: a `<thing>_id`
 * column naming a table that is here, with no foreign key on it.
 *
 * Found on a blind test. A production snapshot had no foreign keys at all, so
 * workspace_members.workspace_id was seeded with an invented value that named
 * no workspace. A view joining members to their workspaces then showed
 * nothing, and "anyone can list every workspace and who is in it" - a view
 * granted to logged-out visitors - read as an empty room.
 *
 * Only ever used to pick a value. Nothing is refused for lack of one: the
 * database never promised the parent would be there.
 */
function impliedKeys(table, tables) {
  const tied = new Set();
  for (const key of foreignKeys(table)) key.columns.forEach((name) => tied.add(name));
  const keys = [];
  for (const column of table.columns || []) {
    if (tied.has(column.name)) continue;
    const parent = parentFor(column, tables);
    if (!parent || parent.table.name === table.name) continue;
    keys.push({ columns: [column.name], refTable: parent.table.name, refColumns: [parent.keyColumn] });
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
 *
 * A key the app never declared counts too. A member row seeded before the
 * workspace it names has nothing real to point at.
 */
function dependencyOrder(tables) {
  const byName = new Map(tables.map((t) => [t.name, t]));
  const ordered = [];
  const done = new Set();
  const visiting = new Set();

  const visit = (table) => {
    if (done.has(table.name) || visiting.has(table.name)) return;
    visiting.add(table.name);
    for (const key of foreignKeys(table).concat(impliedKeys(table, tables))) {
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
 *
 * `mine` is the row seeded for the same person, when there is one. Without it
 * both fake people were put in the first workspace - the same team, both as
 * its owner - and every rule written "members of this workspace may read it"
 * let each read the other's rows. Six tables of one blind test were reported
 * as one customer reading another's data, when they were teammates.
 */
async function existingRow(client, schema, key, mine) {
  if (mine) return key.refColumns.map((name) => mine[name]);
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
 *
 * `seeding` is only passed by the seeder: `rows`, the rows already seeded for
 * each person, table by table, so a row points at its own person's parent;
 * and `implied`, the keys the app never declared, so a `workspace_id` with no
 * foreign key still names a workspace that is there.
 */
async function rowFor(client, schema, table, person, distinct, overrides, attempt, seeding) {
  const forced = overrides || {};
  const owner = ownerColumn(table);
  const columns = [];
  const values = [];
  const sown = (seeding && seeding.rows) || new Map();
  const implied = (seeding && seeding.implied) || [];

  // Every column that takes part in a foreign key, and the value it has to
  // hold. Resolved one key at a time so that all of a composite key's columns
  // come from the same parent row. Declared keys first, so a key the app wrote
  // always wins over one guessed from a name.
  const borrowed = new Map();
  for (const key of foreignKeys(table).concat(implied)) {
    const theirs = sown.get(key.refTable);
    const row = await existingRow(client, schema, key, theirs && theirs.get(person));
    if (!row) continue;
    key.columns.forEach((name, i) => {
      if (!borrowed.has(name)) borrowed.set(name, row[i]);
    });
  }
  const partOfKey = new Set();
  for (const key of foreignKeys(table)) key.columns.forEach((name) => partOfKey.add(name));

  // Where exactly one of a set may be filled in: the one already chosen, or
  // else the first that can be - a key needs a parent row to point at. The
  // rest are written as nothing, whatever their default.
  const chosen = (name) => Object.prototype.hasOwnProperty.call(forced, name);
  const onlyOne = new Map();
  for (const group of exactlyOne(table)) {
    const kept = group.find(chosen) || group.find((name) => !partOfKey.has(name) || borrowed.has(name));
    for (const name of group) onlyOne.set(name, name === kept);
  }

  for (const column of table.columns) {
    if (Object.prototype.hasOwnProperty.call(forced, column.name)) {
      columns.push(column.name);
      values.push(forced[column.name]);
      continue;
    }
    if (onlyOne.get(column.name) === false) {
      columns.push(column.name);
      values.push(null);
      continue;
    }
    const mustFill = onlyOne.get(column.name) === true;
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
    // A key nobody declared, pointing at a parent that is there. Filled even
    // where a default or a null would do, because a row that names no real
    // parent is invisible to every rule and view that joins through it.
    if (borrowed.has(column.name)) {
      columns.push(column.name);
      values.push(borrowed.get(column.name));
      continue;
    }
    // Anything with a default can supply its own value. A column that may be
    // empty is left empty - unless it is the one of a set that has to be
    // filled in.
    if (column.default_expr) continue;
    if (!column.not_null && !mustFill) continue;
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

/**
 * Puts a built row in. Separate so the same row can be raced against itself.
 * `back` asks for the row as it landed, defaults and all.
 */
function insertRow(client, schema, table, row, back) {
  const where = 'INSERT INTO ' + quote(schema) + '.' + quote(table);
  const tail = back ? ' RETURNING *' : '';
  // A table of nothing but an id and its defaults leaves no columns to name,
  // and "INSERT INTO t () VALUES ()" is a syntax error. Postgres has a spelling
  // for exactly this, and without it every settings and flags table in the
  // world came back as one that could not be checked.
  if (!row.columns.length) return client.query(where + ' DEFAULT VALUES' + tail);
  const placeholders = row.values.map((_, i) => '$' + (i + 1));
  return client.query(
    where + ' (' + row.columns.map(quote).join(', ') + ') VALUES (' + placeholders.join(', ') + ')' + tail,
    row.values,
  );
}

/**
 * The column that says which organization's a row is, on a table with no
 * person's name on it - or null. Its first key to a table that others point
 * at (an organization, a workspace, a team), where the table itself is not one
 * of those: seeding gives each person their own organization, and a table like
 * this one row, in the first person's. Found on a blind test (HarborLine):
 * integration_secrets(organization_id, access_token) was readable by every
 * signed-in user, and with no person column it was never tried at all.
 */
function tenantKey(table, tables, parents) {
  // A view is not seeded: it shows whatever its tables hold, the second
  // person's own organization included, so a row of it read by them proves
  // nothing. Found on the same test: workspace_health, filtered to the
  // organizations the reader belongs to, came back as a leak.
  if (table.isView || parents.has(table.name)) return null;
  for (const key of foreignKeys(table).concat(impliedKeys(table, tables))) {
    if (key.refTable !== table.name && parents.has(key.refTable) && key.columns.length === 1) return key.columns[0];
  }
  return null;
}

/** Every table some other table points at, by a key it declared or one it implies. */
function parentTables(tables) {
  const parents = new Set();
  for (const table of tables) {
    for (const key of foreignKeys(table).concat(impliedKeys(table, tables))) {
      if (key.refTable !== table.name) parents.add(key.refTable);
    }
  }
  return parents;
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
  // Each person's own rows, table by table, so that what they own points at
  // their own workspace rather than the first one that went in.
  const rows = new Map();
  const parents = parentTables(tables);
  for (const table of dependencyOrder(tables)) {
    const owner = ownerColumn(table);
    const seeding = { rows: rows, implied: impliedKeys(table, tables) };

    // A table with nobody's name on it still gets a row. Without one, an open
    // door cannot be told from an empty room: a logged-out stranger reads zero
    // rows either way, and the tool reports the app as safe. Settings tables,
    // waitlists and contact forms are exactly this shape, and exactly the ones
    // that get left open.
    //
    // One that other tables point at - a workspace, a team, an organisation -
    // gets one for each person, so the two of them are in different teams
    // and a team rule is tested across teams rather than inside one. Some
    // tables only ever hold one row, so a pair that will not go in falls back
    // to the single row it always had.
    const casts = owner ? [[USER_A, USER_B]]
      : parents.has(table.name) ? [[USER_A, USER_B], [USER_A]] : [[USER_A]];

    // Each attempt offers a differently-shaped set of values. A table whose
    // rules reject all of them is reported, never quietly passed over.
    let refused = null;
    let landed = false;
    let worked = 0;
    for (const people of casts) {
      for (let attempt = 0; attempt < SHAPES_TO_TRY && !landed; attempt++) {
        const theirs = new Map();
        try {
          let nth = 0;
          for (const person of people) {
            nth += 1;
            const row = await rowFor(client, schema, table, person, nth, null, attempt, seeding);
            const result = await insertRow(client, schema, table.name, row, true);
            theirs.set(person, result.rows[0]);
          }
          landed = true;
          worked = attempt;
          rows.set(table.name, theirs);
        } catch (err) {
          refused = err.message;
          // A half-seeded table would make the next attempt collide with its own
          // first row, so anything that did go in is taken back out.
          await client
            .query('DELETE FROM ' + quote(schema) + '.' + quote(table.name))
            .catch(() => {});
        }
      }
      if (landed) break;
    }

    if (landed) {
      // The shape that worked is kept: any later attack that has to insert into
      // this table can use the same one instead of rediscovering it, and be
      // sure a refusal is the app defending itself rather than a CHECK it
      // never satisfied.
      const entry = { table: table.name, owner: owner, attempt: worked };
      // A table with nobody's name on it that got a row for each person - an
      // organization's invoices, say - holds the second person's own row too.
      // Which row is the first person's is kept, so a write meant for
      // "somebody else's row" is aimed at it. Found on a blind test
      // (HarborLine): an unscoped UPDATE changed the second person's own
      // invoice, and was reported as any customer changing another's.
      const firstRow = !owner && rows.get(table.name) && rows.get(table.name).get(USER_A);
      const pk = primaryKeyOf(table);
      if (firstRow && rows.get(table.name).size === 2 && pk && firstRow[pk] !== null && firstRow[pk] !== undefined) {
        entry.rowOfA = { column: pk, value: String(firstRow[pk]) };
      }
      seeded.push(entry);
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
 * The table whose rule looks itself up, or null.
 *
 * A rule on organization_members that asks organization_members who is a
 * member has to be checked to be checked, and Postgres stops the request
 * rather than loop. Found on a blind test: every signed-in read touching that
 * table failed, the app was broken for everyone with an account, and the
 * report listed it only as a reason something was not tested. It is a finding
 * in its own right - and it names the table at fault, which is often not the
 * one that was being read.
 */
/**
 * The other shape the same loop takes. When the rule reaches its own table
 * through a helper function rather than directly, Postgres does not see a
 * policy recursing - it runs out of stack - and the message names no table.
 * Found on a blind test: every signed-in read failed with "stack depth limit
 * exceeded", and the report filed each one only as untested.
 */
function tooDeep(message) {
  return /stack depth limit exceeded/i.test(String(message || ''));
}

function recursionIn(message) {
  const found = /infinite recursion detected in policy for relation "([^"]+)"/i.exec(String(message || ''));
  return found ? found[1] : null;
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
  // Rules that looked themselves up, and which read ran into each one.
  const looped = [];

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

  const parents = parentTables(tables);
  for (const table of tables) {
    const owner = ownerColumn(table);
    const tenant = owner ? null : tenantKey(table, tables, parents);
    const anon = await readAs(client, schema, table.name, 'anon', null);
    const asA = await readAs(client, schema, table.name, 'authenticated', USER_A);

    // Looked for on every table, owner or not: a signed-in read of a table
    // with nobody's name on it fails just the same, and it is the same
    // broken page.
    for (const [answer, who] of [[anon, 'anyone'], [asA, 'signed-in']]) {
      if (Array.isArray(answer)) continue;
      const relation = recursionIn(answer.blocked);
      // A loop with no table named is recorded with none; the scan works out
      // which table's rule it is from the rules and helpers it has read.
      if (relation || tooDeep(answer.blocked)) looped.push({ relation: relation || null, table: table.name, who: who });
    }
    // Only a read of the table itself that came back with a verdict, for both
    // callers, shows its rules no longer loop. A read that failed for some
    // other reason shows nothing either way.
    const answered = (answer) => Array.isArray(answer) || refusalMeans(answer.blocked) === 'unreachable';
    if (answered(anon) && answered(asA)) completed.push('recursive:' + table.name);

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

    // A table whose rows are an organization's, not a person's: its one row is
    // the first person's organization's, and the second person - signed in,
    // in an organization of their own - asks for it. What a logged-out
    // stranger can already read is reported as exposed, and not twice.
    if (tenant) {
      const asB = await readAs(client, schema, table.name, 'authenticated', USER_B);
      const open = Array.isArray(anon) && anon.length > 0;
      if (settle('crossed:' + table.name, table.name, asB, 'as a signed-in user in another organization') &&
          asB.length > 0 && !open) {
        findings.push({
          kind: 'crossed',
          table: table.name,
          owner: tenant,
          tenant: true,
          readable: asB.length,
          columns: Object.keys(asB[0] || {}),
          rlsEnabled: table.rlsEnabled,
        });
      }
    }
  }

  return { findings: findings, completed: completed, blocked: blocked, looped: looped };
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
  recursionIn: recursionIn,
  tooDeep: tooDeep,
  ownerColumn: ownerColumn,
  fitTo: fitTo,
  foreignKeys: foreignKeys,
  primaryKeyOf: primaryKeyOf,
  parentFor: parentFor,
  impliedKeys: impliedKeys,
  parentTables: parentTables,
  dependencyOrder: dependencyOrder,
  valueFor: valueFor,
  allowedByCheck: allowedByCheck,
  exactlyOne: exactlyOne,
  rowFor: rowFor,
  existingRow: existingRow,
  insertRow: insertRow,
  seed: seed,
  readAs: readAs,
  impersonate: impersonate,
  summarise: summarise,
};
