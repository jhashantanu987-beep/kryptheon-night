// The interruption attack: can a half-finished write survive?
//
// A request cut off partway is mostly a question about the app's code - were
// the two inserts wrapped in a transaction? - and this tool never sees the
// app's code. Guessing would be the lost update all over again.
//
// But there is a half of it the database answers on its own. A foreign key is
// what makes a half-finished state impossible to keep, no matter how badly the
// app behaves or where the connection drops. Without one, an order can name a
// customer who does not exist, and nothing will ever notice.
//
// So the attack is: put in a row pointing at something that is not there, and
// see whether the database takes it.
//
// WHAT THAT ACTUALLY COSTS SOMEBODY (measured in probe-orphan.js)
//
//   - with no foreign key the row is accepted, and nothing in the database
//     will ever find it again
//   - with one, the insert is refused
//   - with one, deleting the parent is refused too - so "delete my account"
//     really does take the data with it, or fails loudly. Without one, the
//     customer is gone and their rows are still sitting there.
//
// WHAT IS DELIBERATELY NOT REPORTED
//
// A column with no table it could point at. `stripe_id`, `session_id`,
// `external_id` reference something outside this database entirely, and
// telling somebody to add a foreign key to one would be telling them to break
// their app. Only a column whose name matches a real table here, whose type
// matches that table's key, is ever considered.
//
// Log and audit tables are left alone too. Keeping the id of something that
// has since been deleted is the entire point of an audit row, and a foreign
// key there would be the bug.

const { quote } = require('./schema.js');
const attack = require('./attack.js');

// Tables whose job is to remember things after they are gone. A dangling id in
// an audit row is the feature.
const KEEPS_HISTORY = /(^|_)(log|logs|audit|audits|event|events|history|archive|archives|snapshot|snapshots|activity|activities)(_|$)/i;

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

/** Is this column already held down by a foreign key? */
function alreadyTied(table, columnName) {
  return attack.foreignKeys(table).some((key) => key.columns.includes(columnName));
}

/**
 * Every column that looks like it points somewhere, with whether it is already
 * tied down.
 *
 * Tied columns are attacked too, the same way the collision attack races
 * columns that already have a unique index. Skipping them would mean that the
 * moment somebody adds the foreign key this asked for, the attack stops
 * running - and the re-check could no longer watch it be refused, so it would
 * report the fix it requested as "could not confirm".
 *
 * `tied` decides what is reported, never what is attempted.
 */
function candidates(tables) {
  const found = [];
  for (const table of tables || []) {
    if (KEEPS_HISTORY.test(table.name)) continue;
    for (const column of table.columns || []) {
      const parent = parentFor(column, tables);
      if (!parent) continue;
      found.push({
        table: table.name,
        column: column.name,
        parent: parent.table.name,
        parentKey: parent.keyColumn,
        type: parent.type,
        tied: alreadyTied(table, column.name),
      });
    }
  }
  return found;
}

/** A value of the right type that is certainly not in the parent table. */
function nobody(type) {
  const kind = String(type).toLowerCase();
  if (kind === 'uuid') return '99999999-9999-4999-8999-999999999999';
  if (/^(integer|bigint|smallint)/.test(kind)) return 2147480000;
  if (/^(numeric|decimal|real|double)/.test(kind)) return 2147480000;
  return 'kryptheon-nobody';
}

/**
 * Point a row at something that is not there, and see if it is taken.
 *
 * Run as the owner of the schema on purpose. The question is not who is
 * allowed to create an orphan - it is whether the database permits one to
 * exist at all, which is what decides whether a dropped connection can leave
 * one behind.
 *
 * Rolled back, always. Nothing this does survives the statement that did it.
 */
async function orphan(client, schema, tables, seeded) {
  const findings = [];
  const completed = [];
  const notTried = [];
  const shapeFor = new Map((seeded || []).map((entry) => [entry.table, entry.attempt || 0]));
  const byName = new Map((tables || []).map((table) => [table.name, table]));

  for (const target of candidates(tables)) {
    const key = 'orphaned:' + target.table + ':' + target.column;
    const table = byName.get(target.table);
    const missing = nobody(target.type);

    // It only proves anything if the value really is absent from the parent.
    try {
      const { rows } = await client.query(
        'SELECT 1 FROM ' + quote(schema) + '.' + quote(target.parent) +
          ' WHERE ' + quote(target.parentKey) + ' = $1 LIMIT 1',
        [missing],
      );
      if (rows.length) {
        notTried.push({ table: target.table, column: target.column, why: 'the test value was already in ' + target.parent });
        continue;
      }
    } catch (err) {
      notTried.push({ table: target.table, column: target.column, why: 'could not look in ' + target.parent + ': ' + err.message });
      continue;
    }

    const override = {};
    override[target.column] = missing;
    let row;
    try {
      row = await attack.rowFor(client, schema, table, attack.USER_C, 9, override, shapeFor.get(target.table));
    } catch (err) {
      notTried.push({ table: target.table, column: target.column, why: err.message });
      continue;
    }

    await client.query('BEGIN');
    let landed = false;
    let refused = null;
    try {
      await client.query("SET LOCAL statement_timeout = '15s'");
      await attack.insertRow(client, schema, target.table, row);
      landed = true;
    } catch (err) {
      refused = err.message;
    } finally {
      await client.query('ROLLBACK').catch(() => {});
    }

    if (!landed && !/violates foreign key constraint/i.test(String(refused))) {
      // Turned away by something other than referential integrity, so nothing
      // was learned about whether an orphan can exist.
      notTried.push({ table: target.table, column: target.column, why: refused });
      continue;
    }

    completed.push(key);
    // Whether a key is supposedly there does not come into it. What is reported
    // is what landed.
    //
    // There was a `&& !target.tied` here, on the reasoning that a tied column
    // could not produce an orphan anyway. It could not - measured on Neon, a
    // foreign key cannot be quietly switched off: DISABLE TRIGGER ALL is
    // refused because the constraint triggers are system triggers, and DISABLE
    // TRIGGER USER does not touch them. So the guard never fired, and a guard
    // that never fires is one more thing that can be wrong. If a row naming
    // nobody ever does land on a column with a key on it, that is worse news
    // than usual and saying so is right.
    if (landed) {
      findings.push({
        kind: 'orphaned',
        table: target.table,
        column: target.column,
        parent: target.parent,
        parentKey: target.parentKey,
        columns: (table.columns || []).map((c) => c.name),
      });
    }
  }

  return { findings: findings, completed: completed, notTried: notTried };
}

module.exports = {
  KEEPS_HISTORY: KEEPS_HISTORY,
  primaryKeyOf: primaryKeyOf,
  parentFor: parentFor,
  alreadyTied: alreadyTied,
  candidates: candidates,
  nobody: nobody,
  orphan: orphan,
};
