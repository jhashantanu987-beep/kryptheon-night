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
// Columns that hold something a member should not simply be able to read:
// a token, a secret or a key, a password, or the payload a webhook carried.
// Found on a blind test (HelixOps): integration_tokens.token_value and
// webhook_deliveries.payload readable by every member, and api_clients
// (client_key, secret_hash) by a dispatcher. A word on its own between
// underscores, so tokens - a count - and question_key are not taken.
// AtlasPay's webhook deliveries kept theirs as request_body and response_body.
const SECRET_COLUMN = /(^|_)(token|secret|password|passwd|pwd|payload|credentials?|(api|private|access|client|signing|service|encryption|secret|license)_?key|(request|response)_body)(_|$)/i;

/** The columns of a table that look like they hold a secret. */
function secretColumns(table) {
  return (table.columns || []).map((c) => c.name).filter((name) => SECRET_COLUMN.test(name));
}

/** Whether a role's own name says it may only look. */
function lookOnly(role) {
  return LEAST_TRUSTED.some((pattern) => pattern.test(role));
}

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
    // Every role not plainly in charge, the lowest first and then upwards:
    // the order reads are tried in, so the least trusted one that can read a
    // secret is the one named.
    const ladder = [lowest].concat(labels.filter((label) => label !== lowest && !IN_CHARGE.test(label)).reverse());
    if (lowest) return { column: column.name, type: column.type, lowest: lowest, ladder: ladder };
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
    found.push({ table: table, person: person, role: role.column, roleType: role.type, lowest: role.lowest,
      ladder: role.ladder, keys: keys });
  }
  // A table named for members first: it is the one a team rule asks.
  const named = (m) => (/member/i.test(m.table.name) ? 0 : 1);
  return found.map((m, i) => [m, i]).sort((a, b) => named(a[0]) - named(b[0]) || a[1] - b[1]).map((pair) => pair[0]);
}

// What each kind of write is called in a rule.
const COMMAND = { add: 'INSERT', change: 'UPDATE', delete: 'DELETE' };

/**
 * Whether the app's own rules name this role among those allowed to make
 * this kind of write - the way a repository's role rule does it: the role in
 * a list in a permissive rule for that command, has_role(team,
 * ARRAY['owner', 'maintainer', 'developer']), or in a list inside a helper
 * that rule calls (role IN ('owner', 'developer')). A rule written for one
 * role on its own - role = 'analyst', the shape production added in
 * LaunchRail - is not a list of who may write, and stays something to check.
 */
function allowedByRules(rules, table, what, role, type) {
  const escape = (x) => String(x).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const label = "'" + escape(String(role).split("'").join("''")) + "'";
  const typeName = escape(String(type || 'text').split('.').pop().split('"').join(''));
  const inRuleList = new RegExp('ARRAY\\[[^\\]]*' + label + '::("?[A-Za-z0-9_$]+"?\\.)?"?' + typeName + '"?', 'i');
  // The same list written as an array literal - has_role(team,
  // '{owner,admin,member}') - which Postgres keeps as '{...}'::role[].
  const bare = escape(String(role));
  const inRuleLiteral = new RegExp("'\\{([^}']*,)?\"?" + bare + "\"?(,[^}']*)?\\}'::(\"?[A-Za-z0-9_$]+\"?\\.)?\"?" +
    typeName + '"?\\[\\]', 'i');
  const inHelperList = new RegExp('(\\bIN\\s*\\(|ARRAY\\[)[^)\\]]*' + label, 'i');
  const calls = (text, name) => new RegExp('(^|[^A-Za-z0-9_$])"?' + escape(name) + '"?\\s*\\(').test(text);
  const functions = (rules && rules.functions) || [];
  for (const policy of (rules && rules.policies) || []) {
    if (policy.table_name !== table) continue;
    if (String(policy.permissive || 'PERMISSIVE').toUpperCase() !== 'PERMISSIVE') continue;
    const cmd = String(policy.cmd || 'ALL').toUpperCase();
    if (cmd !== 'ALL' && cmd !== COMMAND[what]) continue;
    const text = String(policy.qual || '') + ' ' + String(policy.with_check || '');
    if (inRuleList.test(text) || inRuleLiteral.test(text)) return true;
    if (functions.some((fn) => calls(text, fn.name) && inHelperList.test(String(fn.src || '')))) return true;
  }
  return false;
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
async function teammate(client, schema, tables, seeded, rules) {
  const findings = [];
  const completed = [];
  const blocked = [];
  const shapeFor = new Map((seeded || []).map((entry) => [entry.table, entry.attempt || 0]));
  const done = new Set();
  // What a write or a read achieved, or null when it decided nothing.
  const counted = (result) => {
    const outcome = whatHappened(result);
    return outcome === 'untested' ? null : outcome === 'got through' ? result.count : 0;
  };

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
    const team = {};
    for (const key of member.keys) {
      key.columns.forEach((name) => { if (name !== member.person) team[name] = theirs[name]; });
    }
    const parentKey = member.keys[0];
    const parent = parentKey.refTable;
    // Putting the other person in that team, as one role. Built once a role.
    const joins = new Map();
    const joinAs = async (role) => {
      if (joins.has(role)) return joins.get(role);
      const overrides = Object.assign({}, team);
      overrides[member.role] = role;
      const row = await attack.rowFor(client, schema, member.table, attack.USER_B, 9, overrides, shapeFor.get(member.table.name));
      const join = {
        statement: 'INSERT INTO ' + at + ' (' + row.columns.map(quote).join(', ') + ') VALUES (' +
          row.values.map((_, i) => '$' + (i + 1)).join(', ') + ')',
        values: row.values,
      };
      joins.set(role, join);
      return join;
    };
    const as = (role) => 'as a "' + role + '" in ' + member.table.name;
    let join = null;
    let refused = null;
    try {
      join = await joinAs(member.lowest);
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
        why: as(member.lowest) + ': I could not add one: ' + refused });
      continue;
    }

    for (const table of tables) {
      if (!shapeFor.has(table.name) || done.has(table.name)) continue;
      done.add(table.name);
      const owner = attack.ownerColumn(table);
      // A table that names the team itself, and the team it is to name.
      const toTeam = attack.foreignKeys(table).concat(attack.impliedKeys(table, tables))
        .find((k) => k.refTable === parent && k.columns.length === parentKey.refColumns.length);
      const pointed = {};
      if (toTeam) {
        toTeam.columns.forEach((name, i) => {
          pointed[name] = team[parentKey.columns[parentKey.refColumns.indexOf(toTeam.refColumns[i])]];
        });
      }
      // Never their own rows: changing what you made yourself is not a role
      // question, and the row that put them in the team is theirs. And only
      // the team they joined, where the table says which team a row is in:
      // their own team's rows, which they own, were refused by a foreign key
      // on the way out and left the table untested.
      const where = [];
      if (owner) where.push(quote(owner) + " IS DISTINCT FROM '" + attack.USER_B + "'");
      for (const name of Object.keys(pointed)) {
        where.push(quote(name) + " = '" + String(pointed[name]).split("'").join("''") + "'");
      }
      const notTheirs = where.length ? ' WHERE ' + where.join(' AND ') : '';
      const target = quote(schema) + '.' + quote(table.name);
      const column = quote(firstWritable(table));
      const moves = [
        { what: 'change', statement: 'UPDATE ' + target + ' SET ' + column + ' = ' + column + notTheirs, values: [] },
        { what: 'delete', statement: 'DELETE FROM ' + target + notTheirs, values: [] },
      ];
      // Adding a row to the team, said only of a role whose own name says it
      // may only look: a member adding rows is the feature, a viewer adding
      // them is not. Found on a blind test (HelixOps): any member could add
      // alert subscriptions. Only a table that names the team itself. Written
      // under the other person's name: a rule that lets a member add a row
      // only as themselves - a note they wrote - is a member speaking for
      // themselves, and refuses it (OrbitDesk's internal notes, by design).
      if (toTeam && member.ladder.some(lookOnly)) {
        try {
          const row = await attack.rowFor(client, schema, table, attack.USER_A, 11, pointed, shapeFor.get(table.name));
          moves.unshift({
            what: 'add',
            lookOnly: true,
            statement: row.columns.length
              ? 'INSERT INTO ' + target + ' (' + row.columns.map(quote).join(', ') + ') VALUES (' +
                row.values.map((_, i) => '$' + (i + 1)).join(', ') + ')'
              : 'INSERT INTO ' + target + ' DEFAULT VALUES',
            values: row.values,
          });
        } catch (err) {
          // Nothing to point a new row at: there is no row to add.
        }
      }

      // Every role not in charge, from the lowest up, the way reads are tried:
      // found on a blind test (LaunchRail), where production gave the
      // "analyst" role its own UPDATE rule on feature flags and only the
      // "viewer" below it was ever tried. The first role that can write where
      // the app's own rules do not list it is the one named; a role a rule
      // lists among those allowed to write is the design, and the roles above
      // it are still tried. What each write did before joining is asked once.
      const beforeJoining = new Map();
      for (const move of moves) {
        beforeJoining.set(move.what, await tryWrite(client, 'authenticated', attack.USER_B, move.statement, move.values));
      }
      const below = [];
      for (const role of member.ladder) {
        const key = 'role:' + table.name + ':' + role;
        let joined;
        try {
          joined = await joinAs(role);
        } catch (err) {
          blocked.push({ table: table.name, key: key, why: as(role) + ': I could not add one: ' + err.message });
          break;
        }
        const can = [];
        const changed = {};
        let stuck = null;
        // Whether this role could write where the rules list it: then it is
        // not one that "could not", whatever is said of the roles above it.
        let listed = false;
        for (const move of moves) {
          if (move.lookOnly && !lookOnly(role)) continue;
          // A write the rules list this role for is not asked: whatever it
          // did would not be reported, and a key refusing it on the way out
          // left the table untested (HelixOps' assets, as a dispatcher).
          if (allowedByRules(rules, table.name, move.what, role, member.roleType)) {
            listed = true;
            continue;
          }
          const after = await tryWrite(client, 'authenticated', attack.USER_B, move.statement, move.values, joined);
          const was = counted(beforeJoining.get(move.what));
          const now = counted(after);
          if (was === null || now === null) {
            stuck = now === null ? after.why : beforeJoining.get(move.what).why;
          } else if (now > was) {
            can.push(move.what);
            changed[move.what] = now - was;
          }
        }
        if (!can.length && stuck) {
          blocked.push({ table: table.name, key: key, why: as(role) + ': ' + stuck });
          break;
        }
        completed.push(key);
        if (can.length) {
          findings.push({
            kind: 'role',
            table: table.name,
            who: role,
            via: member.table.name,
            roleColumn: member.role,
            parent: parent,
            can: can,
            changed: changed,
            below: below.slice(),
            columns: (table.columns || []).map((c) => c.name),
            rlsEnabled: table.rlsEnabled,
          });
          break;
        }
        if (!listed) below.push(role);
      }

      // Reading what a member should not see, said only of a table holding a
      // secret. Every role not in charge, from the lowest up; the first that
      // can read is the one named. A member reading their team's ordinary
      // rows is the feature.
      const secrets = secretColumns(table);
      if (!secrets.length) continue;
      const look = 'SELECT 1 FROM ' + target + notTheirs;
      const before = counted(await tryWrite(client, 'authenticated', attack.USER_B, look, []));
      const tried = [];
      for (const role of member.ladder) {
        const readKey = 'teamread:' + table.name + ':' + role;
        let after;
        try {
          after = await tryWrite(client, 'authenticated', attack.USER_B, look, [], await joinAs(role));
        } catch (err) {
          after = { ok: false, count: 0, why: err.message };
        }
        const now = counted(after);
        if (before === null || now === null) {
          blocked.push({ table: table.name, key: readKey, why: as(role) + ': ' + (now === null ? after.why : 'reading it failed before joining') });
          break;
        }
        completed.push(readKey);
        if (now > before) {
          findings.push({
            kind: 'teamread',
            table: table.name,
            who: role,
            via: member.table.name,
            roleColumn: member.role,
            parent: parent,
            readable: now - before,
            secrets: secrets,
            below: tried.slice(),
            columns: (table.columns || []).map((c) => c.name),
            rlsEnabled: table.rlsEnabled,
          });
          break;
        }
        tried.push(role);
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
  allowedByRules: allowedByRules,
  secretColumns: secretColumns,
  lookOnly: lookOnly,
  roleColumnOf: roleColumnOf,
  memberships: memberships,
  teammate: teammate,
};
