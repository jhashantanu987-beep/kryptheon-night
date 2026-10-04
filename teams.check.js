// Checks that the two fake people are seeded into two different teams, so a
// rule written "members of this team may read it" is tested across teams
// rather than inside one - and that a `<thing>_id` with no foreign key still
// names a parent that is really there.
//
//   node teams.check.js "<postgres connection string>"
//
// Found on a blind test (AtlasPay). Both people were put in the first
// workspace, as its owner, so six team tables were reported as one customer
// reading or changing another's data when the two were teammates. And the
// production snapshot had no foreign keys at all: members were seeded naming
// no workspace, and a view granted to logged-out visitors that lists every
// workspace and who is in it came back empty.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');
const sqlengine = require('./sqlengine.js');
const scanner = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
// Three apps: one with its keys declared, one without any, and one with a
// table that only ever holds a single row.
const KEYED = 'kn_teams_' + STAMP;
const BARE = 'kn_teamsbare_' + STAMP;
const SINGLE = 'kn_teamsone_' + STAMP;
const WHO = "nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid";

const results = [];
const check = (name, problems) => results.push({ name, problems });

const at = (app) => (name) => schema.quote(app) + '.' + schema.quote(name);

/** Both engines, the whole scan, on one schema. */
async function bothScans(client, app) {
  const node = await scanner.scan(client, app, { quiet: true });
  const sql = await sqlengine.withEngine(client, (target) =>
    scanner.scan(client, app, { quiet: true, engine: sqlengine.adapterFor(target) }));
  return [['node', node], ['sql', sql]];
}

const named = (result) => (result.findings || []).map((f) => f.kind + ':' + f.table).sort();

/**
 * A team app as people build it: teams, who is in them, and invoices that
 * belong to a team. Named so that a child sorts before its parent, which is
 * the order the seeder must not follow.
 */
async function buildKeyed(client) {
  const q = at(KEYED);
  await client.query('CREATE SCHEMA ' + schema.quote(KEYED));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(KEYED) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('teams') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('members') + ' (team_id uuid NOT NULL REFERENCES ' + q('teams') + '(id),' +
    " user_id uuid NOT NULL, role text NOT NULL CHECK (role IN ('owner', 'viewer')), PRIMARY KEY (team_id, user_id))");
  await client.query('CREATE TABLE ' + q('invoices') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),' +
    ' team_id uuid NOT NULL REFERENCES ' + q('teams') + '(id), created_by uuid NOT NULL, amount numeric NOT NULL)');
  await client.query('CREATE FUNCTION ' + q('is_member') + '(p_team uuid) RETURNS boolean LANGUAGE sql STABLE AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE team_id = p_team AND user_id = ' + WHO + ') $$');
  for (const t of ['teams', 'members', 'invoices']) {
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY reads ON ' + q('teams') + ' FOR SELECT TO authenticated USING (' + q('is_member') + '(id))');
  await client.query('CREATE POLICY reads ON ' + q('members') + ' FOR SELECT TO authenticated USING (user_id = ' + WHO +
    ' OR ' + q('is_member') + '(team_id))');
  await client.query('CREATE POLICY reads ON ' + q('invoices') + ' FOR SELECT TO authenticated USING (' + q('is_member') + '(team_id))');
  await client.query('CREATE POLICY changes ON ' + q('invoices') + ' FOR UPDATE TO authenticated USING (' + q('is_member') +
    '(team_id)) WITH CHECK (' + q('is_member') + '(team_id))');
  await client.query('CREATE POLICY removes ON ' + q('invoices') + ' FOR DELETE TO authenticated USING (' + q('is_member') + '(team_id))');
}

/**
 * The same team, as a production snapshot has it: no foreign keys, and a
 * view anyone can read that runs as its creator.
 */
async function buildBare(client) {
  const q = at(BARE);
  await client.query('CREATE SCHEMA ' + schema.quote(BARE));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(BARE) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('teams') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('members') + ' (team_id uuid NOT NULL, user_id uuid NOT NULL, role text NOT NULL,' +
    ' PRIMARY KEY (team_id, user_id))');
  await client.query('CREATE FUNCTION ' + q('is_member') + '(p_team uuid) RETURNS boolean LANGUAGE sql STABLE AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE team_id = p_team AND user_id = ' + WHO + ') $$');
  for (const t of ['teams', 'members']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY reads ON ' + q('teams') + ' FOR SELECT TO authenticated USING (' + q('is_member') + '(id))');
  await client.query('CREATE POLICY reads ON ' + q('members') + ' FOR SELECT TO authenticated USING (user_id = ' + WHO +
    ' OR ' + q('is_member') + '(team_id))');
  await client.query('CREATE VIEW ' + q('directory') + ' AS SELECT m.team_id AS id, t.name, m.role FROM ' + q('members') +
    ' m JOIN ' + q('teams') + ' t ON t.id = m.team_id');
  await client.query('GRANT SELECT ON ' + q('directory') + ' TO anon, authenticated');
}

/** A table other tables point at that can only ever hold one row. */
async function buildSingle(client) {
  const q = at(SINGLE);
  await client.query('CREATE SCHEMA ' + schema.quote(SINGLE));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(SINGLE) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('settings') + ' (id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1), label text NOT NULL)');
  await client.query('CREATE TABLE ' + q('knobs') + ' (id serial PRIMARY KEY, settings_id integer NOT NULL REFERENCES ' +
    q('settings') + '(id), name text NOT NULL)');
  for (const t of ['settings', 'knobs']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node teams.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await buildKeyed(client);
    await buildBare(client);
    await buildSingle(client);

    // ---------------------------------------------------- what it decides
    const keyed = await schema.readSchema(client, KEYED);
    const bare = await schema.readSchema(client, BARE);
    const single = await schema.readSchema(client, SINGLE);
    let sqlSays = null;
    await sqlengine.withEngine(client, async (target) => {
      const ask = async (fn, args) => {
        const places = args.map((ignored, i) => '$' + (i + 1)).join(', ');
        const { rows } = await client.query('SELECT ' + schema.quote(target) + '.' + fn + '(' + places + ') AS answer', args);
        return rows[0].answer;
      };
      sqlSays = {};
      for (const [label, plan] of [['keyed', keyed], ['bare', bare], ['single', single]]) {
        sqlSays[label] = {
          implied: {},
          parents: ((await ask('parent_tables', [JSON.stringify(plan.tables)])) || []).slice().sort(),
          order: ((await ask('dependency_order', [JSON.stringify(plan.tables)])) || []).map((t) => t.name),
        };
        for (const table of plan.tables) {
          sqlSays[label].implied[table.name] = await ask('implied_keys', [JSON.stringify(table), JSON.stringify(plan.tables)]);
        }
      }
    });
    const nodeSays = {};
    for (const [label, plan] of [['keyed', keyed], ['bare', bare], ['single', single]]) {
      nodeSays[label] = {
        implied: {},
        parents: Array.from(attack.parentTables(plan.tables)).sort(),
        order: attack.dependencyOrder(plan.tables).map((t) => t.name),
      };
      for (const table of plan.tables) nodeSays[label].implied[table.name] = attack.impliedKeys(table, plan.tables);
    }

    check('a `<thing>_id` with no key on it is read as pointing at its table; a declared key is not read twice', (() => {
      const p = [];
      const expected = JSON.stringify([{ columns: ['team_id'], refTable: 'teams', refColumns: ['id'] }]);
      for (const [who, says] of [['node', nodeSays], ['sql', sqlSays]]) {
        if (JSON.stringify(says.bare.implied.members) !== expected) p.push(who + ': bare members ' + JSON.stringify(says.bare.implied.members));
        if (JSON.stringify(says.keyed.implied.members) !== '[]') p.push(who + ': keyed members ' + JSON.stringify(says.keyed.implied.members));
        if (JSON.stringify(says.bare.implied.teams) !== '[]') p.push(who + ': teams points at ' + JSON.stringify(says.bare.implied.teams));
      }
      return p;
    })());

    check('the tables other tables point at are the ones given a row per person, in both engines', (() => {
      const p = [];
      const want = { keyed: '["teams"]', bare: '["teams"]', single: '["settings"]' };
      for (const [who, says] of [['node', nodeSays], ['sql', sqlSays]]) {
        for (const label of Object.keys(want)) {
          if (JSON.stringify(says[label].parents) !== want[label]) p.push(who + ' ' + label + ': ' + JSON.stringify(says[label].parents));
        }
      }
      return p;
    })());

    check('a parent no key names is still seeded before the rows that name it, in both engines', (() => {
      const p = [];
      for (const [who, says] of [['node', nodeSays], ['sql', sqlSays]]) {
        const order = says.bare.order;
        if (order.indexOf('teams') < 0 || order.indexOf('teams') > order.indexOf('members')) p.push(who + ': ' + order.join(' -> '));
      }
      if (nodeSays.bare.order.join() !== sqlSays.bare.order.join()) p.push('node ' + nodeSays.bare.order + ' sql ' + sqlSays.bare.order);
      return p;
    })());

    // ---------------------------------------------------- what goes in
    // Seeded by each engine into a copy of its own, then read back as the
    // owner of the copy: who is in which team, and which team owns what.
    const seededBy = {};
    for (const engine of ['node', 'sql']) {
      const copy = 'kn_teamsseed_' + engine + '_' + STAMP;
      try {
        if (engine === 'node') {
          await schema.writeSchema(client, keyed, copy);
          const copied = await schema.readSchema(client, copy);
          seededBy.node = { told: await attack.seed(client, copy, copied.tables) };
        } else {
          await sqlengine.withEngine(client, async (target) => {
            await sqlengine.writeSchema(client, target, keyed, copy);
            const copied = await sqlengine.readSchema(client, target, copy);
            seededBy.sql = { told: await sqlengine.seed(client, target, copy, copied.tables) };
          });
        }
        const qc = at(copy);
        seededBy[engine].teams = (await client.query('SELECT count(*)::int AS n FROM ' + qc('teams'))).rows[0].n;
        seededBy[engine].members = (await client.query('SELECT user_id::text AS who, team_id::text AS team FROM ' + qc('members'))).rows;
        seededBy[engine].invoices = (await client.query('SELECT created_by::text AS who, team_id::text AS team FROM ' + qc('invoices'))).rows;
      } finally {
        await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(copy) + ' CASCADE').catch(() => {});
      }
    }

    check('each person is in a team of their own, and what they own belongs to that team', (() => {
      const p = [];
      for (const engine of ['node', 'sql']) {
        const s = seededBy[engine];
        if (!s) { p.push(engine + ': never seeded'); continue; }
        if (s.teams !== 2) p.push(engine + ': ' + s.teams + ' teams');
        const teamOf = new Map(s.members.map((m) => [m.who, m.team]));
        const a = teamOf.get(attack.USER_A);
        const b = teamOf.get(attack.USER_B);
        if (!a || !b || a === b) p.push(engine + ': members ' + JSON.stringify(s.members));
        for (const invoice of s.invoices) {
          if (invoice.team !== teamOf.get(invoice.who)) p.push(engine + ': an invoice of ' + invoice.who + ' is in another team');
        }
        if (s.invoices.length !== 2) p.push(engine + ': ' + s.invoices.length + ' invoices');
      }
      return p;
    })());

    // ---------------------------------------------------- what is said
    const scans = await bothScans(client, KEYED);
    check('teammates reading their own team are not reported, and the attack across teams really ran', (() => {
      const p = [];
      for (const [engine, result] of scans) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        const said = named(result).filter((key) => /:(teams|members|invoices)$/.test(key));
        if (said.length) p.push(engine + ' reported ' + JSON.stringify(said));
        for (const key of ['crossed:invoices', 'crossed:members', 'writable:invoices:any customer']) {
          if (!(result.attempted || []).includes(key)) p.push(engine + ': ' + key + ' never ran');
        }
        if ((result.notChecked || []).length) p.push(engine + ' did not check ' + JSON.stringify(result.notChecked));
      }
      return p;
    })());

    // And a rule that really does let any customer in is still caught: the
    // check above means nothing if crossing teams can never be seen.
    await client.query('DROP POLICY reads ON ' + at(KEYED)('invoices'));
    await client.query('CREATE POLICY reads ON ' + at(KEYED)('invoices') + ' FOR SELECT TO authenticated USING (true)');
    const opened = await bothScans(client, KEYED);
    check('an invoice rule open to every customer is reported as one customer reading another\'s', (() => {
      const p = [];
      for (const [engine, result] of opened) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        const said = named(result);
        if (!said.includes('crossed:invoices')) p.push(engine + ' said ' + JSON.stringify(said));
        if (said.some((key) => /:(teams|members)$/.test(key))) p.push(engine + ' blamed a table that holds: ' + JSON.stringify(said));
      }
      return p;
    })());

    const bareScans = await bothScans(client, BARE);
    check('with no keys at all, a view anyone can read that joins members to teams is reported', (() => {
      const p = [];
      for (const [engine, result] of bareScans) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        const view = (result.findings || []).find((f) => f.kind === 'exposed' && f.table === 'directory');
        if (!view) p.push(engine + ' said ' + JSON.stringify(named(result)));
        else if (!/got back 2 rows/.test(String(view.body).replace(/\s+/g, ' '))) p.push(engine + ': ' + view.body);
        if (named(result).some((key) => /^crossed:/.test(key))) p.push(engine + ' reported teammates: ' + JSON.stringify(named(result)));
      }
      return p;
    })());

    const singleScans = await bothScans(client, SINGLE);
    check('a parent that only takes one row is still seeded, with the one row it always had', (() => {
      const p = [];
      for (const [engine, result] of singleScans) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        const unchecked = (result.notChecked || []).map((n) => n.table);
        if (unchecked.length) p.push(engine + ' could not seed ' + JSON.stringify(result.notChecked));
        for (const key of ['exposed:settings', 'exposed:knobs']) {
          if (!(result.attempted || []).includes(key)) p.push(engine + ': ' + key + ' never ran');
        }
      }
      return p;
    })());
  } finally {
    for (const app of [KEYED, BARE, SINGLE]) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(app) + ' CASCADE').catch(() => {});
    }
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
  console.log('All ' + results.length + ' team checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
