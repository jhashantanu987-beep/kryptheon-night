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
async function tryWrite(client, role, identity, statement, values, first) {
  await client.query('BEGIN');
  try {
    // Something the copy's owner does first, inside the same transaction, so
    // it is undone with the write: putting a person into a team for one
    // attempt (see teammate below).
    if (first) await client.query(first.statement, first.values || []);
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
async function tamper(client, schema, tables, seeded, policies) {
  const findings = [];
  const completed = [];
  const blocked = [];
  const shapeFor = new Map((seeded || []).map((entry) => [entry.table, entry.attempt || 0]));

  // Which rules each table actually has, so the report can say why a write got
  // through instead of assuming. Without this the report told somebody their
  // rule "covers every command rather than only reading" about a policy
  // written FOR INSERT - the finding was true and the reason was invented,
  // which is the one thing a report cannot do twice.
  //
  // Permissive only. A restrictive policy can narrow what is allowed and
  // never open it, so it is never the reason a write succeeded.
  const rulesFor = new Map();
  for (const policy of policies || []) {
    if (String(policy.permissive || 'PERMISSIVE').toUpperCase() !== 'PERMISSIVE') continue;
    const list = rulesFor.get(policy.table_name) || [];
    const cmd = String(policy.cmd || 'ALL').toUpperCase();
    if (!list.includes(cmd)) list.push(cmd);
    rulesFor.set(policy.table_name, list);
  }

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
      //
      // Unless the owner is a key into one of the app's own tables - provider_id
      // -> profiles.id - where only the two seeded people exist. Found on a
      // blind test: the nameless insert hit the foreign key, and "any provider
      // can add appointments for any other" came back as not tested. The other
      // seeded person is still somebody else's name to the signed-in caller.
      const row = await attack.rowFor(client, schema, table, writeAsFor(table, owner, tables), 7, null, shapeFor.get(table.name));
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
          rules: rulesFor.get(table.name) || [],
        });
      }
    }
  }

  return { findings: findings, completed: completed, blocked: blocked };
}

/**
 * Whose name an insert is written under: nobody's yet (USER_C), unless the
 * owner column is a key into one of the app's own tables, where only the two
 * seeded people exist - then the one who is not the signed-in caller.
 */
function writeAsFor(table, owner, tables) {
  if (!owner) return attack.USER_C;
  const key = attack.foreignKeys(table).find((k) => k.columns.length === 1 && k.columns[0] === owner);
  const inApp = key && (tables || []).some((t) => t.name === key.refTable);
  return inApp ? attack.USER_A : attack.USER_C;
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

/*
 * What the least trusted member of a team can change.
 *
 * Everything above is one customer against another. Found on two blind tests
 * (OrbitDesk, AtlasPay): a rule written "members of this workspace may change
 * it" lets a viewer change it too, and an UPDATE rule that checks the role is
 * undone by a second one beside it that does not - Postgres lets a write
 * through if any permissive rule allows it. Five planted holes of this shape
 * went unreported, because both fake people were the owner of their own team
 * and nobody else was ever in it.
 *
 * So one of them joins the other's team with the lowest role there is, for
 * one attempt at a time, and tries to change what is in it. Whether a viewer
 * may edit is the owner's decision, so this is reported as something to
 * check, never as a confirmed break.
 */

// Labels that say "may only look", tried in this order before falling back
// to the last label that is not plainly in charge.
const LEAST_TRUSTED = [/view/i, /read/i, /guest/i, /observ/i, /audit/i];
const IN_CHARGE = /owner|admin|super|root/i;
// Owner columns that name who made a row rather than who is in it.
const CREATOR = /^(created_by|author_id|owner|owner_id)$/i;

/** The role a viewer has, out of a team's list of roles, or null. */
function lowestRole(labels) {
  for (const pattern of LEAST_TRUSTED) {
    const found = labels.find((label) => pattern.test(label));
    if (found) return found;
  }
  const plain = labels.filter((label) => !IN_CHARGE.test(label));
  return plain.length ? plain[plain.length - 1] : null;
}

/**
 * The column holding a member's role, and its lowest value: named for a role,
 * with a fixed list of values (an enum, or a CHECK listing them).
 */
function roleColumnOf(table) {
  for (const column of table.columns || []) {
    if (!/role/i.test(column.name)) continue;
    const labels = Array.isArray(column.enum_labels) && column.enum_labels.length
      ? column.enum_labels
      : attack.allowedByCheck(table, column.name);
    if (labels.length < 2) continue;
    const lowest = lowestRole(labels);
    if (lowest) return { column: column.name, lowest: lowest };
  }
  return null;
}

/** Whether a column is a key on its own: one row per person, at most. */
function aloneUnique(table, column) {
  return (table.constraints || []).some((constraint) => {
    if (constraint.kind !== 'p' && constraint.kind !== 'u') return false;
    const match = /(?:PRIMARY KEY|UNIQUE) \(([^)]+)\)/i.exec(String(constraint.definition || ''));
    if (!match) return false;
    const columns = match[1].split(',').map((name) => name.trim().split('"').join(''));
    return columns.length === 1 && columns[0] === column;
  });
}

/**
 * The tables saying who is in which team, and as what: a person, a role, and
 * a key to a table of the app's own that is not the person. A table where the
 * person can appear only once (profiles.org_id) is not one: nobody joins a
 * second team there, so there is no one to add.
 */
function memberships(tables) {
  const found = [];
  const names = new Set((tables || []).map((table) => table.name));
  for (const table of tables || []) {
    const person = attack.ownerColumn(table);
    // Whoever made the row is not who is in the team. Found on a blind test:
    // workspace_invites (created_by, role, workspace_id) was taken for the
    // members table, and an invitation made nobody a member of anything.
    if (!person || CREATOR.test(person)) continue;
    const role = roleColumnOf(table);
    if (!role) continue;
    const keys = attack.foreignKeys(table).concat(attack.impliedKeys(table, tables))
      .filter((key) => key.refTable !== table.name && names.has(key.refTable) && !key.columns.includes(person));
    if (!keys.length || aloneUnique(table, person)) continue;
    found.push({ table: table, person: person, role: role.column, lowest: role.lowest, keys: keys });
  }
  // A table named for members first: it is the one a team rule asks.
  const named = (m) => (/member/i.test(m.table.name) ? 0 : 1);
  return found.map((m, i) => [m, i]).sort((a, b) => named(a[0]) - named(b[0]) || a[1] - b[1]).map((pair) => pair[0]);
}

/**
 * For every team table: can a viewer change it?
 *
 * The other fake person joins the first one's team as its lowest role, and
 * every write is tried twice - before joining and after - so only what joining
 * added is counted: a hole open to every customer is already reported above,
 * and a person changing their own rows is the feature. Both rolled back, the
 * joining with them.
 */
async function teammate(client, schema, tables, seeded) {
  const findings = [];
  const completed = [];
  const blocked = [];
  const shapeFor = new Map((seeded || []).map((entry) => [entry.table, entry.attempt || 0]));
  const done = new Set();

  for (const member of memberships(tables)) {
    if (!shapeFor.has(member.table.name)) continue;
    const at = quote(schema) + '.' + quote(member.table.name);
    let theirs = null;
    try {
      theirs = (await client.query('SELECT * FROM ' + at + ' WHERE ' + quote(member.person) + ' = $1 LIMIT 1',
        [attack.USER_A])).rows[0] || null;
    } catch (err) {
      theirs = null;
    }
    if (!theirs) continue;

    // Their team, as the first person's own membership names it.
    const overrides = {};
    overrides[member.role] = member.lowest;
    for (const key of member.keys) {
      key.columns.forEach((name) => { if (name !== member.person) overrides[name] = theirs[name]; });
    }
    const parent = member.keys[0].refTable;
    const as = 'as a "' + member.lowest + '" in ' + member.table.name;
    let join = null;
    let refused = null;
    try {
      const row = await attack.rowFor(client, schema, member.table, attack.USER_B, 9, overrides, shapeFor.get(member.table.name));
      join = {
        statement: 'INSERT INTO ' + at + ' (' + row.columns.map(quote).join(', ') + ') VALUES (' +
          row.values.map((_, i) => '$' + (i + 1)).join(', ') + ')',
        values: row.values,
      };
      // Whether they can be put in the team at all, tried once on its own.
      await client.query('BEGIN');
      try {
        await client.query(join.statement, join.values);
      } finally {
        await client.query('ROLLBACK').catch(() => {});
      }
    } catch (err) {
      refused = err.message;
    }
    if (refused) {
      // Said once, on the table that would not take them: every team table
      // went untested for the same reason.
      blocked.push({ table: member.table.name, key: 'role:' + member.table.name + ':' + member.lowest,
        why: as + ': I could not add one: ' + refused });
      continue;
    }

    for (const table of tables) {
      if (!shapeFor.has(table.name) || done.has(table.name)) continue;
      done.add(table.name);
      const key = 'role:' + table.name + ':' + member.lowest;
      const owner = attack.ownerColumn(table);
      // Never their own rows: changing what you made yourself is not a role
      // question, and the row that put them in the team is theirs.
      const notTheirs = owner ? ' WHERE ' + quote(owner) + " IS DISTINCT FROM '" + attack.USER_B + "'" : '';
      const target = quote(schema) + '.' + quote(table.name);
      const column = quote(firstWritable(table));
      const moves = [
        { what: 'change', statement: 'UPDATE ' + target + ' SET ' + column + ' = ' + column + notTheirs },
        { what: 'delete', statement: 'DELETE FROM ' + target + notTheirs },
      ];
      const can = [];
      const changed = {};
      let stuck = null;
      for (const move of moves) {
        const before = await tryWrite(client, 'authenticated', attack.USER_B, move.statement, []);
        const after = await tryWrite(client, 'authenticated', attack.USER_B, move.statement, [], join);
        const counted = (result) => {
          const outcome = whatHappened(result);
          return outcome === 'untested' ? null : outcome === 'got through' ? result.count : 0;
        };
        const was = counted(before);
        const now = counted(after);
        if (was === null || now === null) {
          stuck = now === null ? after.why : before.why;
        } else if (now > was) {
          can.push(move.what);
          changed[move.what] = now - was;
        }
      }
      if (!can.length && stuck) {
        blocked.push({ table: table.name, key: key, why: as + ': ' + stuck });
        continue;
      }
      completed.push(key);
      if (can.length) {
        findings.push({
          kind: 'role',
          table: table.name,
          who: member.lowest,
          via: member.table.name,
          roleColumn: member.role,
          parent: parent,
          can: can,
          changed: changed,
          columns: (table.columns || []).map((c) => c.name),
          rlsEnabled: table.rlsEnabled,
        });
      }
    }
  }
  return { findings: findings, completed: completed, blocked: blocked };
}

module.exports = {
  ACTORS: ACTORS,
  tryWrite: tryWrite,
  whatHappened: whatHappened,
  firstWritable: firstWritable,
  writeAsFor: writeAsFor,
  tamper: tamper,
  lowestRole: lowestRole,
  roleColumnOf: roleColumnOf,
  memberships: memberships,
  teammate: teammate,
};
