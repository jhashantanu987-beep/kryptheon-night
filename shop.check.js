// A Supabase-shaped shop, down both engines.
// Run with:  node shop.check.js "<postgres connection string>"
//
// Written on 2026-09-25 after a test app built to look like an ordinary
// Lovable shop - the one a person would be asked to try by hand - got this
// from 0.1.5:
//
//   "I could not check this app."
//
// because a rule on order_items read the orders table ("items of my orders"),
// and the copy printed that rule naming the copy's orders. Correct - and the
// word-for-word comparison called it "the copy came out changed" and stopped.
// Fixed, the same app then reported four of its five holes as not tested:
// nearly every table in a Supabase app has user_id -> auth.users, and the
// attacks add rows as somebody who was never put in the copy's stand-in for
// auth.users, so the foreign key refused the row before any rule was asked.
//
// And fixing the first one turned up a third, older one: a rule written with
// its schema - FROM kn_app.members - was replayed verbatim, so the copy's rule
// read the customer's table. The comparison had passed it for months, since
// source and copy printed the same words.
//
// So: the same app, every hole where a real one would be, run through both
// engines, and two apps built to break the guard.

// A run this check causes is saved to a scratch store, never the real
// ~/.kryptheon (see store.js).
process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const SHOP = 'kn_shop_' + STAMP;
const MEMBERS = 'kn_shop_members_' + STAMP;
const OUTSIDE = 'kn_shop_outside_' + STAMP;
const ELSEWHERE = 'kn_shop_elsewhere_' + STAMP;
const NOAUTH = 'kn_shop_noauth_' + STAMP;

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

let undoAuth = async () => {};
let undoUsers = async () => {};

/**
 * The shop: the test app a person is handed, on the search_path, with its
 * user_id columns pointing at auth.users the way Supabase's do.
 */
async function buildShop(client) {
  const q = (name) => schema.quote(SHOP) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(SHOP));
  await fixture.ensureRoles(client, SHOP, schema.quote);
  await client.query('SET search_path TO ' + schema.quote(SHOP) + ', public');

  // Anyone can read it: RLS on, the rule lets everybody in.
  await client.query('CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY REFERENCES auth.users (id), full_name text, email text, phone text)');
  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY visible ON ' + q('profiles') + ' FOR SELECT USING (true)');

  // RLS never switched on.
  await client.query('CREATE TABLE ' + q('waitlist') + ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text NOT NULL)');

  // Anyone can place an order, for anyone.
  await client.query('CREATE TABLE ' + q('orders') + ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id uuid REFERENCES auth.users (id), total numeric NOT NULL)');
  await client.query('ALTER TABLE ' + q('orders') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY see_own ON ' + q('orders') + ' FOR SELECT USING (auth.uid() = user_id)');
  await client.query('CREATE POLICY place_any ON ' + q('orders') + ' FOR INSERT WITH CHECK (true)');

  // No foreign key to orders, and a rule that reads orders - the one that
  // stopped the whole scan.
  await client.query('CREATE TABLE ' + q('order_items') + ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, order_id bigint NOT NULL, product text NOT NULL)');
  await client.query('ALTER TABLE ' + q('order_items') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY items_of_mine ON ' + q('order_items') + ' FOR SELECT USING (EXISTS (SELECT 1 FROM ' + q('orders') + ' o WHERE o.id = order_id AND o.user_id = auth.uid()))');

  // Two accounts, one email.
  await client.query('CREATE TABLE ' + q('accounts') + ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id uuid NOT NULL REFERENCES auth.users (id), email text NOT NULL)');
  await client.query('ALTER TABLE ' + q('accounts') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY mine ON ' + q('accounts') + ' FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)');

  // Safe. Nothing may be reported about it.
  await client.query('CREATE TABLE ' + q('notes') + ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner uuid NOT NULL REFERENCES auth.users (id), body text NOT NULL)');
  await client.query('ALTER TABLE ' + q('notes') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY my_notes ON ' + q('notes') + ' FOR ALL USING (auth.uid() = owner) WITH CHECK (auth.uid() = owner)');

  // What Supabase grants every table in public.
  await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ' + schema.quote(SHOP) + ' TO anon, authenticated');
  await client.query('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ' + schema.quote(SHOP) + ' TO anon, authenticated');
  await client.query('SET search_path TO "$user", public');
}

/** An app off the search_path whose rule names its own table with the schema. */
async function buildMembers(client) {
  const q = (name) => schema.quote(MEMBERS) + '.' + schema.quote(name);
  await client.query('CREATE SCHEMA ' + schema.quote(MEMBERS));
  await fixture.ensureRoles(client, MEMBERS, schema.quote);
  await client.query('CREATE TABLE ' + q('members') + ' (org_id int NOT NULL, user_id uuid NOT NULL, PRIMARY KEY (org_id, user_id))');
  await client.query('CREATE TABLE ' + q('documents') + ' (id serial PRIMARY KEY, org_id int NOT NULL, body text NOT NULL)');
  await client.query('GRANT SELECT ON ' + q('documents') + ' TO anon, authenticated');
  await client.query('ALTER TABLE ' + q('documents') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY in_my_org ON ' + q('documents') + ' FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM ' + q('members') + ' m WHERE m.org_id = ' + q('documents') + '.org_id AND m.user_id = auth.uid()))');
}

/** An app whose rule reads a table in a different schema entirely. */
async function buildOutside(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(ELSEWHERE));
  await client.query('CREATE TABLE ' + schema.quote(ELSEWHERE) + '.admins (user_id uuid PRIMARY KEY)');
  await client.query('CREATE SCHEMA ' + schema.quote(OUTSIDE));
  await fixture.ensureRoles(client, OUTSIDE, schema.quote);
  const t = schema.quote(OUTSIDE) + '.reports';
  await client.query('CREATE TABLE ' + t + ' (id serial PRIMARY KEY, body text NOT NULL)');
  await client.query('GRANT SELECT ON ' + t + ' TO anon, authenticated');
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(ELSEWHERE) + ' TO anon, authenticated');
  await client.query('GRANT SELECT ON ' + schema.quote(ELSEWHERE) + '.admins TO anon, authenticated');
  await client.query('ALTER TABLE ' + t + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY admins_only ON ' + t + ' FOR SELECT USING (EXISTS (SELECT 1 FROM ' + schema.quote(ELSEWHERE) + '.admins a WHERE a.user_id = auth.uid()))');
}

function openSessionFor(connection) {
  return async () => {
    const extra = new Client({ connectionString: connection });
    await extra.connect();
    return extra;
  };
}

/** Both engines over one app. Each result is { result, threw }. */
async function bothEngines(client, app, searchPath) {
  const openSession = openSessionFor(CONNECTION);
  const out = {};
  for (const which of ['node', 'sql']) {
    if (searchPath) await client.query('SET search_path TO ' + schema.quote(app) + ', public');
    try {
      if (which === 'node') {
        out.node = { result: await scan(client, app, { quiet: true, openSession: openSession }) };
      } else {
        await sqlengine.withEngine(client, async (target) => {
          out.sql = { result: await scan(client, app, { quiet: true, openSession: openSession, engine: sqlengine.adapterFor(target) }) };
        });
      }
    } catch (err) {
      out[which] = { threw: err.message };
    } finally {
      await client.query('SET search_path TO "$user", public').catch(() => {});
    }
  }
  return out;
}

const headlines = (r) => ((r && r.result && r.result.findings) || []).map((f) => f.severity + ' ' + f.table + ': ' + f.headline);
const stoppedOrThrew = (r) => (r.threw ? 'threw: ' + r.threw : r.result && r.result.stopped ? 'stopped: ' + String(r.result.stopped).split('\n')[0] : null);

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node shop.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    undoAuth = await fixture.ensureAuth(client);
    const users = await fixture.ensureAuthUsers(client, 'id uuid PRIMARY KEY, email text');
    undoUsers = users.undo;

    await buildShop(client);
    const shop = await bothEngines(client, SHOP, true);

    for (const which of ['node', 'sql']) {
      const r = shop[which];
      check('1' + (which === 'node' ? 'a' : 'b') + '. ' + which + ': a rule reading another of the app\'s tables does not stop the scan', (() => {
        const why = stoppedOrThrew(r);
        return why ? [why] : [];
      })());

      check('2' + (which === 'node' ? 'a' : 'b') + '. ' + which + ': nothing is left untested because of a foreign key to auth.users', (() => {
        const untested = ((r.result && r.result.notChecked) || []).map((m) => m.table + ': ' + String(m.why).slice(0, 120));
        return untested.length ? ['untested: ' + untested.join(' | ')] : [];
      })());

      check('3' + (which === 'node' ? 'a' : 'b') + '. ' + which + ': every hole is found, and the safe table is left alone', (() => {
        const found = headlines(r).join('\n');
        const problems = [];
        const want = [
          [/profiles: .*read by anyone/i, 'profiles readable by anyone'],
          [/waitlist: .*read by anyone/i, 'waitlist readable by anyone'],
          [/orders: .*(add rows|can add)/i, 'orders: anyone can add'],
          [/order_items: .*point at/i, 'order_items can point at nothing'],
          [/accounts: .*same email/i, 'accounts: the same email twice'],
        ];
        for (const [pattern, what] of want) if (!pattern.test(found)) problems.push('missing: ' + what);
        if (/ notes: /.test(found)) problems.push('the safe notes table was reported: ' + found.split('\n').filter((l) => / notes: /.test(l)).join(' / '));
        if (problems.length) problems.push('it found:\n        ' + found.split('\n').join('\n        '));
        return problems;
      })());

      check('3' + (which === 'node' ? 'c' : 'd') + '. ' + which + ': with auth.users here, a duplicate email is not called a shared login', (() => {
        // This app signs people in through auth.users, which keeps emails
        // unique. accounts.email is a copy, so the duplicate is real but it
        // does not put two accounts behind one login.
        const dup = ((r.result && r.result.findings) || []).find((f) => f.table === 'accounts' && f.kind === 'duplicated');
        if (!dup) return ['no duplicate finding on accounts to judge'];
        const problems = [];
        if (dup.severity !== 'HIGH') problems.push('severity ' + dup.severity + ', expected HIGH');
        if (!/Signing in is not affected/.test(dup.body)) problems.push('body: ' + dup.body);
        return problems;
      })());
    }

    check('4. both engines hand over the same findings', (() => {
      const a = headlines(shop.node).sort();
      const b = headlines(shop.sql).sort();
      return JSON.stringify(a) === JSON.stringify(b) ? [] : ['node: ' + JSON.stringify(a) + '\n        sql:  ' + JSON.stringify(b)];
    })());

    await buildMembers(client);
    const members = await bothEngines(client, MEMBERS, false);
    for (const which of ['node', 'sql']) {
      check('5' + (which === 'node' ? 'a' : 'b') + '. ' + which + ': a rule naming its own table with the schema reads the copy\'s table, not the customer\'s', (() => {
        const why = stoppedOrThrew(members[which]);
        return why ? [why] : [];
      })());
    }

    await buildOutside(client);
    const outside = await bothEngines(client, OUTSIDE, false);
    for (const which of ['node', 'sql']) {
      check('6' + (which === 'node' ? 'a' : 'b') + '. ' + which + ': a rule reading a table in another schema is refused, out loud', (() => {
        const why = stoppedOrThrew(outside[which]) || '';
        if (!/points outside itself/.test(why)) return ['expected "points outside itself", got: ' + (why || 'a completed scan: ' + headlines(outside[which]).join(' / '))];
        return [];
      })());
    }

    // The other half of 3c/3d: a plain Postgres app with no auth.users, where
    // accounts.email may well be the login itself, keeps the strong claim.
    // Only possible when this run made auth.users and can take it away again;
    // on a database that has its own, the check says it could not run.
    if (users.made) {
      await undoUsers();
      undoUsers = async () => {};
      await client.query('CREATE SCHEMA ' + schema.quote(NOAUTH));
      await client.query('CREATE TABLE ' + schema.quote(NOAUTH) + '.accounts (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text NOT NULL)');
      const plain = await scan(client, NOAUTH, { quiet: true, openSession: openSessionFor(CONNECTION) });
      check('7. without auth.users, a duplicate email in accounts is still called a shared login', (() => {
        const dup = (plain.findings || []).find((f) => f.table === 'accounts' && f.kind === 'duplicated');
        if (!dup) return ['no duplicate finding: ' + (plain.stopped || headlines({ result: plain }).join(' / '))];
        const problems = [];
        if (dup.severity !== 'CRITICAL') problems.push('severity ' + dup.severity + ', expected CRITICAL');
        if (!/same login/.test(dup.body)) problems.push('body: ' + dup.body);
        return problems;
      })());
    } else {
      check('7. without auth.users (could not run: this database has its own auth.users)', ['not run - this is not a pass']);
    }
  } finally {
    await client.query('SET search_path TO "$user", public').catch(() => {});
    for (const name of [SHOP, MEMBERS, OUTSIDE, ELSEWHERE, NOAUTH]) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
    }
    await undoUsers().catch(() => {});
    await undoAuth().catch(() => {});
    await client.end().catch(() => {});
  }

  let failures = 0;
  for (const r of results) {
    if (r.problems.length) {
      failures++;
      console.log('FAIL  ' + r.name);
      r.problems.forEach((p) => console.log('      - ' + p));
    } else {
      console.log('PASS  ' + r.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exit(1);
  }
  console.log('All ' + results.length + ' shop checks passed.');
}

main().catch((err) => {
  console.error('The check could not run: ' + err.message);
  process.exit(2);
});
