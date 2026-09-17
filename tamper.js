// Can a stranger change your data?
//
// Everything before this asks whether the wrong person can READ. This asks
// whether they can WRITE, and the answer matters more: a leak is bad, but a
// stranger who can delete your customers table has taken something you cannot
// get back.
//
// It is the commonest disaster in a no-code backend, and the reason is that
// nothing looks wrong. Supabase grants anon INSERT, UPDATE and DELETE on the
// public schema by default. Row level security is what takes those back, and
// on a table where nobody ever switched it on, a logged-out stranger can empty
// the table with one request while the dashboard shows nothing at all.
//
// EVERYTHING HERE IS ROLLED BACK. Every write runs inside a transaction that
// is always rolled back, measured afterwards to confirm the table came out as
// it went in. It runs against the copy, and the copy is thrown away - but the
// rollback is what makes it safe to reason about at all.
//
// WHAT WAS MEASURED FIRST (probe-write.js, against a real database)
//
//   - no row level security + the default grants: a stranger can insert,
//     rewrite and delete. Confirmed, all three.
//   - a SELECT policy and nothing else: writes are refused. A read rule is
//     genuinely not a write rule, so an app like this must not be reported.
//   - FOR ALL USING (true): a stranger can do all three.
//   - an owner policy: a signed-in customer cannot touch another customer's
//     rows, and Postgres reuses USING as the check for UPDATE, so a row cannot
//     be pushed out of its owner's reach either.
//
// A statement that returns without error having changed zero rows is a
// refusal, not a success - row level security filters rows away rather than
// complaining. The first version of the probe got that wrong, so every verdict
// here is taken from the number of rows that actually moved.

const { quote } = require('./schema.js');
const attack = require('./attack.js');

/** Who is doing the asking, and what a finding should call them. */
const ACTORS = [
  { who: 'anyone', role: 'anon', identity: null },
  { who: 'any customer', role: 'authenticated', identity: attack.USER_B },
];

/**
 * Runs one write the way a request runs it, and never keeps the result.
 *
 * The rollback is not a tidy-up, it is the safety property. Nothing this
 * attack does survives the statement that did it.
 */
async function tryWrite(client, role, identity, statement, values) {
  await client.query('BEGIN');
  try {
    await client.query("SET LOCAL statement_timeout = '15s'");
    await client.query('SET LOCAL role TO ' + role);
    await client.query('SELECT set_config($1, $2, true)', [
      'request.jwt.claims',
      JSON.stringify(identity ? { sub: identity, role: role } : { role: role }),
    ]);
    const result = await client.query(statement, values || []);
    return { ok: true, count: result.rowCount };
  } catch (err) {
    return { ok: false, count: 0, why: err.message };
  } finally {
    await client.query('ROLLBACK').catch(() => {});
  }
}

/**
 * What a write actually achieved.
 *
 * Three outcomes, and the middle one is the one that matters: a statement can
 * succeed and change nothing, which is row level security doing its job.
 */
function whatHappened(result) {
  if (result.ok) return result.count > 0 ? 'got through' : 'refused';
  // A WITH CHECK turning a write away IS the app defending itself, and it is
  // the single most common way a correct app says no. Reading it as "I could
  // not tell" put a warning on every table that had got it right, and a
  // warning nobody earned is how a report stops being read.
  if (/violates row-level security policy/i.test(String(result.why))) return 'refused';
  return attack.refusalMeans(result.why) === 'unreachable' ? 'refused' : 'untested';
}

/**
 * Every way in, per table, per kind of caller.
 *
 * `seeded` carries the shape of row that worked when the table was seeded, so
 * the insert here is not rejected by some CHECK the seeder already solved.
 */
async function tamper(client, schema, tables, seeded) {
  const findings = [];
  const completed = [];
  const blocked = [];
  const shapeFor = new Map((seeded || []).map((entry) => [entry.table, entry.attempt || 0]));

  for (const table of tables) {
    if (!shapeFor.has(table.name)) continue; // never seeded, so nothing to protect
    const owner = attack.ownerColumn(table);

    for (const actor of ACTORS) {
      const key = 'writable:' + table.name + ':' + actor.who;
      const can = [];
      const changed = {};
      let stuck = null;

      // Rows belonging to the other fake person. Scoped on purpose: a signed-in
      // customer deleting their OWN rows is not a finding, it is the feature,
      // and an unscoped DELETE would report every correctly built app.
      const theirRows = owner
        ? ' WHERE ' + quote(owner) + ' = ' + "'" + attack.USER_A + "'"
        : '';
      const at = quote(schema) + '.' + quote(table.name);

      // Written under a name nobody has used, which is both what makes the
      // row land at all and what makes it the right test: adding a row of
      // your own is the feature, adding one under somebody else name is not.
      const row = await attack.rowFor(client, schema, table, attack.USER_C, 7, null, shapeFor.get(table.name));
      const placeholders = row.values.map((_, i) => '$' + (i + 1));
      const attempts = [
        row.columns.length
          ? {
            what: 'add',
            statement: 'INSERT INTO ' + at + ' (' + row.columns.map(quote).join(', ') + ') VALUES (' +
              placeholders.join(', ') + ')',
            values: row.values,
          }
          : { what: 'add', statement: 'INSERT INTO ' + at + ' DEFAULT VALUES', values: [] },
        { what: 'change', statement: 'UPDATE ' + at + ' SET ' + quote(firstWritable(table)) + ' = ' +
            quote(firstWritable(table)) + theirRows, values: [] },
        { what: 'delete', statement: 'DELETE FROM ' + at + theirRows, values: [] },
      ];

      for (const move of attempts) {
        if (!move.statement) continue;
        const result = await tryWrite(client, actor.role, actor.identity, move.statement, move.values);
        const outcome = whatHappened(result);
        if (outcome === 'got through') {
          can.push(move.what);
          changed[move.what] = result.count;
        } else if (outcome === 'untested') {
          stuck = result.why;
        }
      }

      if (stuck) {
        // Something went wrong that was not the app defending itself, so no
        // verdict exists for this table and saying nothing would read as safe.
        blocked.push({ table: table.name, key: key, why: 'as ' + actor.who + ': ' + stuck });
        continue;
      }

      completed.push(key);
      if (can.length) {
        findings.push({
          kind: 'writable',
          table: table.name,
          who: actor.who,
          can: can,
          changed: changed,
          owner: owner,
          columns: (table.columns || []).map((c) => c.name),
          rlsEnabled: table.rlsEnabled,
        });
      }
    }
  }

  return { findings: findings, completed: completed, blocked: blocked };
}

/**
 * A column an UPDATE can harmlessly set to itself.
 *
 * Setting a column to its own value changes nothing about the row while still
 * proving the write was allowed - so the finding is real and the data is not
 * even momentarily wrong inside the transaction that gets rolled back.
 */
function firstWritable(table) {
  const usable = (table.columns || []).filter((column) => !column.generated && !column.identity);
  const plain = usable.find((column) => !/^(id)$/i.test(column.name));
  return (plain || usable[0] || { name: 'id' }).name;
}

module.exports = {
  ACTORS: ACTORS,
  tryWrite: tryWrite,
  whatHappened: whatHappened,
  firstWritable: firstWritable,
  tamper: tamper,
};
