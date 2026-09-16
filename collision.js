// The collision attack.
//
// Two requests arriving at the same moment, where only one of them should be
// allowed to win. Impersonation asks "can the wrong person read this". This
// asks "can the same thing exist twice", which is the bug nobody finds by
// clicking through their own app, because one person clicking is never two
// requests at once.
//
// It is run for real: two separate database sessions, both inside open
// transactions, both inserting the same value while the other is still in
// flight. Reading the catalogue and noticing a missing unique index would have
// been easier and would have been a guess - the same shortcut that made the
// copy look right while the grants were missing. So the value is inserted
// twice and the rows are counted afterwards.
//
// WHAT THIS DELIBERATELY DOES NOT REPORT
//
// The lost update - two withdrawals of 100 from a balance of 100 that both
// succeed. It is real, it is common, and it cannot honestly be reported from
// here. Every Postgres database on default isolation behaves that way for a
// read-then-write, so whether an app is actually vulnerable depends on code
// this tool never sees: an atomic UPDATE or a SELECT ... FOR UPDATE makes it
// safe, and nothing in the schema says which was used. Reporting it would mean
// flagging every app that has a number in it. That is the definition of crying
// wolf, and the re-check at the end of the loop is worth exactly as much as
// the first report was believable.
//
// So only what was actually proven gets said: the same value went in twice,
// here is the count.

const { quote } = require('./schema.js');
const attack = require('./attack.js');

/**
 * Columns where two rows holding one value is a security problem rather than
 * an untidy spreadsheet.
 *
 * Anchored on the whole name on purpose. `token` is a credential; `token_id`,
 * `token_expires_at` and `has_token` are not, and matching loosely would put
 * three false alarms on screen for every real one.
 */
const MUST_BE_UNIQUE = [
  {
    // One secret matching two rows opens two different doors.
    expectation: 'credential',
    test: /^(token|auth_token|access_token|refresh_token|reset_token|session_token|session_id|api_key|apikey|access_key|secret_key)$/i,
  },
  {
    // A one-time code that can exist twice can be redeemed twice.
    expectation: 'code',
    test: /^(invite_code|invitation_code|coupon_code|promo_code|promotion_code|referral_code|voucher_code|redemption_code|activation_code|license_key|serial_key)$/i,
  },
  {
    // Two accounts answering to one login make "who is this" ambiguous, and
    // password reset has to pick one of them.
    expectation: 'identity',
    test: /^(email|e_mail|username|user_name|handle|login)$/i,
    accountTablesOnly: true,
  },
];

/**
 * Tables where a duplicate email really is a login problem.
 *
 * `customers` is deliberately absent. In half the apps it is the account
 * table and in the other half it is a contact list, where two contacts sharing
 * an office email is normal and correct. A finding that is wrong half the time
 * is worse than no finding, so the ambiguous name is left alone.
 */
const ACCOUNT_TABLE = /^(users?|profiles?|accounts?|members?|auth_users|app_users|logins?)$/i;

/** Everything on a table that already promises "only one of these". */
function uniquenessTexts(table, indexes) {
  const fromConstraints = (table.constraints || [])
    .filter((c) => c.kind === 'u' || c.kind === 'p')
    .map((c) => c.definition);
  const fromIndexes = (indexes || [])
    .filter((i) => i.table_name === table.name)
    .map((i) => i.definition);
  return fromConstraints.concat(fromIndexes);
}

/**
 * Is this column already protected?
 *
 * Deliberately generous. A composite UNIQUE (org_id, email) counts, because
 * the same email in two different organisations is how multi-tenant apps are
 * supposed to work and calling that a bug would be wrong. A partial index
 * counts, and so does an expression index on lower(email). The cost is that a
 * column merely mentioned in some other index's WHERE clause also counts and
 * gets skipped - an attack not run rather than a false alarm raised, which is
 * the right way round.
 */
function coveredByUnique(table, columnName, indexes) {
  const escaped = String(columnName).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const word = new RegExp('(^|[^A-Za-z0-9_])' + escaped + '([^A-Za-z0-9_]|$)');
  return uniquenessTexts(table, indexes).some((text) => word.test(String(text)));
}

/**
 * Every column worth racing, with whether it is already protected.
 *
 * Protected columns are raced too, and that is deliberate. The first version
 * skipped them, which meant that the moment somebody added the unique
 * constraint the attack stopped running - so the re-check could no longer see
 * it happen, and reported the fix it had asked for as "could not confirm".
 * A fix has to be provable, and the only proof is running the same attack
 * again and watching it be refused.
 *
 * `covered` decides what is reported, never what is attempted. It has to stay,
 * because UNIQUE (org_id, email) genuinely allows the same email twice and
 * calling that a bug would be wrong.
 */
function candidates(tables, indexes) {
  const found = [];
  for (const table of tables || []) {
    for (const column of table.columns || []) {
      const rule = MUST_BE_UNIQUE.find((r) => r.test.test(column.name));
      if (!rule) continue;
      if (rule.accountTablesOnly && !ACCOUNT_TABLE.test(table.name)) continue;
      found.push({
        table: table.name,
        column: column.name,
        expectation: rule.expectation,
        type: column.type,
        covered: coveredByUnique(table, column.name, indexes),
      });
    }
  }
  return found;
}

/** Keeps the colliding value inside a declared width like varchar(12). */
function fitToType(text, type) {
  const match = /^[a-z ]*\((\d+)\)$/.exec(String(type || '').trim());
  if (!match) return text;
  const limit = Number(match[1]);
  return text.length > limit ? text.slice(0, limit) : text;
}

/** The one value both sessions will fight over. */
function collidingValue(target) {
  const type = String(target.type || '').toLowerCase();
  if (type === 'uuid') return '33333333-3333-4333-8333-333333333333';
  if (/^(integer|bigint|smallint|numeric|decimal|real|double)/.test(type)) return 424242;
  return fitToType('kryptheon-collision', target.type);
}

/**
 * Two inserts of the same value, genuinely at the same time.
 *
 * The sequencing is the delicate part, and it was measured rather than assumed
 * (probe-collision.js). When a unique index IS present the second insert
 * blocks until the first transaction ends, so waiting on both before
 * committing either simply hangs for ever. So: run the first, commit it, and
 * only then wait on the second - which has been in flight, inside its own open
 * transaction, the whole time.
 */
async function race(one, two, run) {
  await one.query('BEGIN');
  await two.query('BEGIN');
  // A pathological lock must not hang the night's run.
  await one.query("SET LOCAL statement_timeout = '15s'");
  await two.query("SET LOCAL statement_timeout = '15s'");

  const first = await run(one).then(
    () => ({ ok: true }),
    (err) => ({ ok: false, why: err.message }),
  );

  // Fired and deliberately not awaited: it has to be in flight while the first
  // transaction is still open, or this is not a race at all.
  const pending = run(two).then(
    () => ({ ok: true }),
    (err) => ({ ok: false, why: err.message }),
  );

  await one.query(first.ok ? 'COMMIT' : 'ROLLBACK');
  const second = await pending;
  await two.query(second.ok ? 'COMMIT' : 'ROLLBACK');

  return { first: first, second: second };
}

/**
 * Race every candidate, and say what got through.
 *
 * `notTried` is the half that keeps this honest. If the first insert fails -
 * a constraint the seeding could not satisfy, a column that will not take the
 * value - then nothing was learned about that column, and saying nothing at
 * all would let it read as safe. A table nobody could test is not a table that
 * held.
 */
async function collide(client, one, two, schema, tables, indexes) {
  const findings = [];
  const notTried = [];
  const raced = [];
  const byName = new Map((tables || []).map((t) => [t.name, t]));

  for (const target of candidates(tables, indexes)) {
    const table = byName.get(target.table);
    const value = collidingValue(target);
    const override = {};
    override[target.column] = value;

    let rows;
    try {
      // Numeric tags, so every other generated value differs between the two
      // rows. They have to collide on the column under test and on nothing
      // else, or a refusal elsewhere would be read as the app defending itself.
      rows = [
        await attack.rowFor(client, schema, table, attack.USER_A, 101, override),
        await attack.rowFor(client, schema, table, attack.USER_B, 102, override),
      ];
    } catch (err) {
      if (!target.covered) notTried.push({ table: target.table, column: target.column, why: err.message });
      continue;
    }

    let outcome;
    try {
      let nth = 0;
      outcome = await race(one, two, (session) => {
        const row = rows[nth];
        nth += 1;
        return attack.insertRow(session, schema, target.table, row);
      });
    } catch (err) {
      if (!target.covered) notTried.push({ table: target.table, column: target.column, why: err.message });
      continue;
    }

    if (!outcome.first.ok) {
      // Not a pass. The attack never got off the ground - unless the column
      // is already protected, where the constraint itself is the answer and
      // the race was only ever there to demonstrate it.
      if (!target.covered) notTried.push({
        table: target.table,
        column: target.column,
        why: 'I could not get even one test row in: ' + outcome.first.why,
      });
      continue;
    }

    // Counted rather than inferred from the two answers, because that is the
    // thing a person can be told without hedging: there are now two.
    let copies = 0;
    try {
      const { rows: counted } = await client.query(
        'SELECT count(*)::int AS n FROM ' + quote(schema) + '.' + quote(target.table) +
          ' WHERE ' + quote(target.column) + ' = $1',
        [value],
      );
      copies = counted[0].n;
    } catch (err) {
      if (!target.covered) notTried.push({ table: target.table, column: target.column, why: 'could not count the rows: ' + err.message });
      continue;
    }

    // The race happened and its result is known. Recorded whichever way it
    // went: a refusal is an answer, and the re-check has to be able to tell
    // "attacked and held" from "never attacked".
    raced.push({ table: target.table, column: target.column });

    // A duplicate that landed on a column carrying UNIQUE (org_id, email) is
    // the multi-tenant design working, not a hole.
    if (copies > 1 && !target.covered) {
      findings.push({
        kind: 'duplicated',
        table: target.table,
        column: target.column,
        expectation: target.expectation,
        copies: copies,
        columns: (table.columns || []).map((c) => c.name),
      });
    }

    // Put the copy back as it was found, so anything that runs after this
    // reads the same database the earlier attacks did.
    try {
      await client.query(
        'DELETE FROM ' + quote(schema) + '.' + quote(target.table) + ' WHERE ' + quote(target.column) + ' = $1',
        [value],
      );
    } catch (err) {
      if (!target.covered) notTried.push({
        table: target.table,
        column: target.column,
        why: 'the test rows could not be cleaned up: ' + err.message,
      });
    }
  }

  return { findings: findings, notTried: notTried, raced: raced };
}

module.exports = {
  MUST_BE_UNIQUE: MUST_BE_UNIQUE,
  ACCOUNT_TABLE: ACCOUNT_TABLE,
  uniquenessTexts: uniquenessTexts,
  coveredByUnique: coveredByUnique,
  candidates: candidates,
  collidingValue: collidingValue,
  race: race,
  collide: collide,
};
