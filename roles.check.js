// Checks what the least trusted member of a team can change: that a viewer
// who can edit is found, by both engines, and only what joining the team
// added is counted - a hole open to every customer, a person's own rows and
// a rule that checks the role are not reported.
//
//   node roles.check.js "<postgres connection string>"
//
// Found on two blind tests (OrbitDesk, AtlasPay). Five planted holes went
// unreported: an UPDATE rule that checks the role beside one that does not,
// rules written FOR ALL to any member, and a team's members managed by any
// member. Both fake people were the owner of their own team and nobody else
// was ever in it, so a viewer was never tried.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');
const tamper = require('./tamper.js');
const recheck = require('./recheck.js');
const sqlengine = require('./sqlengine.js');
const scanner = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
// The main app; one whose roles are a CHECK list; one where a person belongs
// to one team only (profiles.org_id); one whose team will not take a second
// member.
const APP = 'kn_roles_' + STAMP;
const LISTED = 'kn_rolesck_' + STAMP;
const SINGLE = 'kn_rolesone_' + STAMP;
const FULL = 'kn_rolesno_' + STAMP;
const WHO = "nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid";

const results = [];
const check = (name, problems) => results.push({ name, problems });
const at = (app) => (name) => schema.quote(app) + '.' + schema.quote(name);

/**
 * A workspace app with every shape the blind tests had, and its decoys:
 *
 *   customers      FOR ALL to any member                     -> reported (change)
 *                  (a deal points at each, so a delete is refused by the key)
 *   tickets        UPDATE for owner/admin, and a second UPDATE
 *                  for any member beside it                    -> reported (change)
 *   squad_members  FOR ALL to any member of the squad's workspace,
 *                  through the squads table                    -> reported (change, delete)
 *   invoices       UPDATE and DELETE for owner/admin only       -> not reported
 *   notes          a person's own notes only                   -> not reported
 *   open_board     FOR ALL USING (true): every customer already -> not a role finding
 *   members        a person may update their own row            -> not reported
 *   access_grants  roles nobody's rule reads, named before members
 *   invites        created_by and a role: an invitation, not a member
 */
async function buildApp(client) {
  const q = at(APP);
  const s = schema.quote(APP);
  await client.query('CREATE SCHEMA ' + s);
  await client.query('GRANT USAGE ON SCHEMA ' + s + ' TO anon, authenticated');
  await client.query('CREATE TYPE ' + s + ".member_role AS ENUM ('owner', 'admin', 'member', 'viewer')");
  await client.query('CREATE TABLE ' + q('workspaces') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('access_grants') + ' (workspace_id uuid NOT NULL REFERENCES ' + q('workspaces') + '(id),' +
    ' user_id uuid NOT NULL, role ' + s + '.member_role NOT NULL, PRIMARY KEY (workspace_id, user_id))');
  await client.query('CREATE TABLE ' + q('members') + ' (workspace_id uuid NOT NULL REFERENCES ' + q('workspaces') + '(id),' +
    ' user_id uuid NOT NULL, role ' + s + '.member_role NOT NULL, PRIMARY KEY (workspace_id, user_id))');
  await client.query('CREATE TABLE ' + q('invites') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), created_by uuid NOT NULL, role ' + s + '.member_role NOT NULL)');
  for (const t of ['customers', 'tickets', 'invoices', 'open_board', 'reports', 'squads']) {
    await client.query('CREATE TABLE ' + q(t) + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
      ' REFERENCES ' + q('workspaces') + '(id), label text NOT NULL)');
  }
  await client.query('CREATE TABLE ' + q('deals') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), customer_id uuid NOT NULL REFERENCES ' + q('customers') + '(id), amount numeric NOT NULL)');
  await client.query('CREATE TABLE ' + q('notes') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), user_id uuid NOT NULL, body text NOT NULL)');
  await client.query('CREATE TABLE ' + q('squad_members') + ' (squad_id uuid NOT NULL REFERENCES ' + q('squads') + '(id),' +
    ' user_id uuid NOT NULL, PRIMARY KEY (squad_id, user_id))');

  // The helpers as an app that works writes them: definer, so the members
  // table is read without its own rule asking again.
  await client.query('CREATE FUNCTION ' + q('is_member') + '(p_workspace uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE workspace_id = p_workspace AND user_id = ' + WHO + ') $$');
  await client.query('CREATE FUNCTION ' + q('has_role') + '(p_workspace uuid, p_roles ' + s + '.member_role[]) RETURNS boolean' +
    ' LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT EXISTS (SELECT 1 FROM ' + q('members') +
    ' WHERE workspace_id = p_workspace AND user_id = ' + WHO + ' AND role = ANY (p_roles)) $$');
  const member = (col) => q('is_member') + '(' + col + ')';
  const staff = (col, roles) => q('has_role') + '(' + col + ", '{" + roles + "}'::" + s + '.member_role[])';

  const tables = ['workspaces', 'access_grants', 'members', 'invites', 'customers', 'tickets', 'invoices', 'open_board',
    'reports', 'squads', 'deals', 'notes', 'squad_members'];
  for (const t of tables) {
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  const policy = (table, name, rest) => client.query('CREATE POLICY ' + name + ' ON ' + q(table) + ' ' + rest);
  await policy('workspaces', 'reads', 'FOR SELECT TO authenticated USING (' + member('id') + ')');
  await policy('workspaces', 'owners', 'FOR UPDATE TO authenticated USING (' + staff('id', 'owner') + ')');
  await policy('members', 'reads', 'FOR SELECT TO authenticated USING (user_id = ' + WHO + ' OR ' + member('workspace_id') + ')');
  await policy('members', 'own_row', 'FOR UPDATE TO authenticated USING (user_id = ' + WHO + ') WITH CHECK (user_id = ' + WHO + ')');
  await policy('invites', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('customers', 'customer_member_write', 'FOR ALL TO authenticated USING (' + member('workspace_id') + ') WITH CHECK (' +
    member('workspace_id') + ')');
  await policy('deals', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('tickets', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('tickets', 'tickets_staff', 'FOR UPDATE TO authenticated USING (' + staff('workspace_id', 'owner,admin') + ') WITH CHECK (' +
    member('workspace_id') + ')');
  await policy('tickets', 'tickets_member', 'FOR UPDATE TO authenticated USING (' + member('workspace_id') + ') WITH CHECK (' +
    member('workspace_id') + ')');
  await policy('tickets', 'tickets_remove', 'FOR DELETE TO authenticated USING (' + staff('workspace_id', 'owner') + ')');
  await policy('invoices', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('invoices', 'changes', 'FOR UPDATE TO authenticated USING (' + staff('workspace_id', 'owner,admin') + ')');
  await policy('invoices', 'removes', 'FOR DELETE TO authenticated USING (' + staff('workspace_id', 'owner,admin') + ')');
  await policy('open_board', 'anything', 'FOR ALL TO authenticated USING (true) WITH CHECK (true)');
  await policy('reports', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('squads', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('notes', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('notes', 'own', 'FOR UPDATE TO authenticated USING (user_id = ' + WHO + ')');
  await policy('notes', 'own_delete', 'FOR DELETE TO authenticated USING (user_id = ' + WHO + ')');
  await policy('squad_members', 'squad_member_manage', 'FOR ALL TO authenticated USING (EXISTS (SELECT 1 FROM ' + q('squads') +
    ' t WHERE t.id = squad_id AND ' + member('t.workspace_id') + '))');
}

/** Roles as a CHECK list rather than an enum. */
async function buildListed(client) {
  const q = at(LISTED);
  await client.query('CREATE SCHEMA ' + schema.quote(LISTED));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(LISTED) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('orgs') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('org_users') + ' (org_id uuid NOT NULL REFERENCES ' + q('orgs') + '(id), user_id uuid NOT NULL,' +
    " role text NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')), PRIMARY KEY (org_id, user_id))");
  await client.query('CREATE TABLE ' + q('docs') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), org_id uuid NOT NULL REFERENCES ' +
    q('orgs') + '(id), body text NOT NULL)');
  await client.query('CREATE FUNCTION ' + q('in_org') + '(p uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('org_users') + ' WHERE org_id = p AND user_id = ' + WHO + ') $$');
  for (const t of ['orgs', 'org_users', 'docs']) {
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY reads ON ' + q('org_users') + ' FOR SELECT TO authenticated USING (user_id = ' + WHO + ')');
  await client.query('CREATE POLICY anything ON ' + q('docs') + ' FOR ALL TO authenticated USING (' + q('in_org') + '(org_id))');
}

/** One team per person, kept on the profile: nobody joins a second one. */
async function buildSingle(client) {
  const q = at(SINGLE);
  await client.query('CREATE SCHEMA ' + schema.quote(SINGLE));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(SINGLE) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('orgs') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY, org_id uuid NOT NULL REFERENCES ' + q('orgs') + '(id),' +
    " role text NOT NULL CHECK (role IN ('admin', 'member')))");
  await client.query('CREATE TABLE ' + q('docs') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), org_id uuid NOT NULL REFERENCES ' +
    q('orgs') + '(id), body text NOT NULL)');
  for (const t of ['orgs', 'profiles', 'docs']) {
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY own ON ' + q('profiles') + ' FOR SELECT TO authenticated USING (id = ' + WHO + ')');
}

/** A team that takes one member and no more, so nobody can be added. */
async function buildFull(client) {
  const q = at(FULL);
  const s = schema.quote(FULL);
  await client.query('CREATE SCHEMA ' + s);
  await client.query('GRANT USAGE ON SCHEMA ' + s + ' TO anon, authenticated');
  await client.query('CREATE TYPE ' + s + ".seat AS ENUM ('owner', 'viewer')");
  await client.query('CREATE TABLE ' + q('teams') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('members') + ' (team_id uuid NOT NULL UNIQUE REFERENCES ' + q('teams') + '(id),' +
    ' user_id uuid NOT NULL, role ' + s + '.seat NOT NULL)');
  for (const t of ['teams', 'members']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
}

/** Every row of every table in a schema, so "nothing changed" can be checked. */
async function contentsOf(client, where) {
  const { rows } = await client.query(
    "SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY tablename", [where]);
  const out = {};
  for (const { tablename } of rows) {
    out[tablename] = (await client.query('SELECT t::text AS r FROM ' + at(where)(tablename) + ' t ORDER BY 1')).rows.map((r) => r.r);
  }
  return out;
}

/** A copy of an app, seeded, by one engine; the teammate attack run on it. */
async function ranked(client, app, engine) {
  const copy = 'kn_rolescopy_' + engine + '_' + STAMP;
  try {
    let answer;
    let before;
    let after;
    if (engine === 'node') {
      const plan = await schema.readSchema(client, app);
      await schema.writeSchema(client, plan, copy);
      const copied = await schema.readSchema(client, copy);
      const sown = await attack.seed(client, copy, copied.tables);
      before = await contentsOf(client, copy);
      answer = await tamper.teammate(client, copy, copied.tables, sown.seeded);
      after = await contentsOf(client, copy);
    } else {
      await sqlengine.withEngine(client, async (target) => {
        const plan = await sqlengine.readSchema(client, target, app);
        await sqlengine.writeSchema(client, target, plan, copy);
        const copied = await sqlengine.readSchema(client, target, copy);
        const sown = await sqlengine.seed(client, target, copy, copied.tables);
        before = await contentsOf(client, copy);
        answer = await sqlengine.teammate(client, target, copy, copied.tables, sown.seeded);
        after = await contentsOf(client, copy);
      });
    }
    return { answer: answer, unchanged: JSON.stringify(before) === JSON.stringify(after) };
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(copy) + ' CASCADE').catch(() => {});
  }
}

const told = (r) => ({
  findings: (r.findings || []).map((f) => f.table + '/' + f.who + '/' + f.via + '.' + f.roleColumn + '/' + f.parent + '/' +
    [...(f.can || [])].sort().join('+') + '/' + JSON.stringify(f.changed)).sort(),
  completed: [...(r.completed || [])].sort(),
  blocked: (r.blocked || []).map((b) => b.key + ' ' + String(b.why).split(':').slice(0, 2).join(':')).sort(),
});

/** Both engines, the whole scan, on one schema. */
async function bothScans(client, app) {
  const node = await scanner.scan(client, app, { quiet: true });
  const sql = await sqlengine.withEngine(client, (target) =>
    scanner.scan(client, app, { quiet: true, engine: sqlengine.adapterFor(target) }));
  return [['node', node], ['sql', sql]];
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node roles.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await buildApp(client);
    await buildListed(client);
    await buildSingle(client);
    await buildFull(client);

    // ------------------------------------------------ what it decides
    const LABELS = [
      ['owner', 'admin', 'member', 'viewer'],
      ['owner', 'finance_admin', 'ops', 'auditor', 'viewer'],
      ['owner', 'auditor', 'ops'],
      ['member', 'admin', 'owner'],
      ['owner', 'admin'],
      ['Owner', 'Read_Only', 'Editor'],
    ];
    const WANT = ['viewer', 'viewer', 'auditor', 'member', null, 'Read_Only'];
    const plans = {};
    for (const app of [APP, LISTED, SINGLE, FULL]) plans[app] = await schema.readSchema(client, app);
    const nodeSays = {
      lowest: LABELS.map((labels) => tamper.lowestRole(labels)),
      memberships: {},
    };
    for (const app of Object.keys(plans)) {
      nodeSays.memberships[app] = tamper.memberships(plans[app].tables).map((m) =>
        m.table.name + ':' + m.person + ':' + m.role + ':' + m.lowest + ':' + m.keys.map((k) => k.refTable).join('+'));
    }
    const sqlSays = { lowest: [], memberships: {} };
    await sqlengine.withEngine(client, async (target) => {
      for (const labels of LABELS) {
        const { rows } = await client.query('SELECT ' + schema.quote(target) + '.lowest_role($1::jsonb) AS answer', [JSON.stringify(labels)]);
        sqlSays.lowest.push(rows[0].answer);
      }
      for (const app of Object.keys(plans)) {
        const { rows } = await client.query('SELECT ' + schema.quote(target) + '.memberships($1::jsonb) AS answer',
          [JSON.stringify(plans[app].tables)]);
        sqlSays.memberships[app] = rows[0].answer.map((m) =>
          m.table.name + ':' + m.person + ':' + m.role + ':' + m.lowest + ':' + m.keys.map((k) => k.refTable).join('+'));
      }
    });

    check('the lowest role is the one that may only look, in both engines', (() => {
      const p = [];
      for (const [who, says] of [['node', nodeSays], ['sql', sqlSays]]) {
        if (JSON.stringify(says.lowest) !== JSON.stringify(WANT)) p.push(who + ': ' + JSON.stringify(says.lowest));
      }
      return p;
    })());

    check('the members table is found by its role, never an invitation or a one-team profile, in both engines', (() => {
      const p = [];
      const want = {};
      want[APP] = ['members:user_id:role:viewer:workspaces', 'access_grants:user_id:role:viewer:workspaces'];
      want[LISTED] = ['org_users:user_id:role:viewer:orgs'];
      want[SINGLE] = [];
      want[FULL] = ['members:user_id:role:viewer:teams'];
      for (const [who, says] of [['node', nodeSays], ['sql', sqlSays]]) {
        for (const app of Object.keys(want)) {
          if (JSON.stringify(says.memberships[app]) !== JSON.stringify(want[app])) {
            p.push(who + ' ' + app + ': ' + JSON.stringify(says.memberships[app]));
          }
        }
      }
      return p;
    })());

    // ------------------------------------------------ what it finds
    const node = await ranked(client, APP, 'node');
    const sql = await ranked(client, APP, 'sql');
    check('a viewer who can change customers, tickets and squad members is found - and nothing else', (() => {
      const p = [];
      const want = [
        'customers/viewer/members.role/workspaces/change/{"change":1}',
        'squad_members/viewer/members.role/workspaces/change+delete/{"change":1,"delete":1}',
        'tickets/viewer/members.role/workspaces/change/{"change":1}',
      ];
      for (const [who, r] of [['node', node], ['sql', sql]]) {
        const said = told(r.answer);
        if (JSON.stringify(said.findings) !== JSON.stringify(want)) p.push(who + ' found ' + JSON.stringify(said.findings));
        if (said.blocked.length) p.push(who + ' could not test ' + JSON.stringify(said.blocked));
      }
      return p;
    })());

    check('every team table was tried, so a rule that checks the role is a pass and not a gap', (() => {
      const p = [];
      for (const [who, r] of [['node', node], ['sql', sql]]) {
        for (const table of ['invoices', 'notes', 'open_board', 'members', 'workspaces', 'reports', 'invites', 'deals']) {
          if (!(r.answer.completed || []).includes('role:' + table + ':viewer')) p.push(who + ': ' + table + ' never tried');
        }
      }
      return p;
    })());

    check('the two engines say exactly the same', (() => {
      const a = JSON.stringify(told(node.answer));
      const b = JSON.stringify(told(sql.answer));
      return a === b ? [] : ['node ' + a, 'sql  ' + b];
    })());

    check('every write, and the joining, is undone', (() => {
      const p = [];
      if (!node.unchanged) p.push('node left the copy changed');
      if (!sql.unchanged) p.push('sql left the copy changed');
      return p;
    })());

    const listedNode = await ranked(client, LISTED, 'node');
    const listedSql = await ranked(client, LISTED, 'sql');
    check('roles written as a CHECK list are read the same way', (() => {
      const p = [];
      for (const [who, r] of [['node', listedNode], ['sql', listedSql]]) {
        const said = told(r.answer).findings;
        if (JSON.stringify(said) !== JSON.stringify(['docs/viewer/org_users.role/orgs/change+delete/{"change":1,"delete":1}'])) {
          p.push(who + ' found ' + JSON.stringify(said));
        }
      }
      return p;
    })());

    const fullNode = await ranked(client, FULL, 'node');
    const fullSql = await ranked(client, FULL, 'sql');
    check('a team that will not take a viewer is said to be untested, never passed', (() => {
      const p = [];
      for (const [who, r] of [['node', fullNode], ['sql', fullSql]]) {
        const said = told(r.answer);
        if (said.findings.length || said.completed.length) p.push(who + ' claimed ' + JSON.stringify(said));
        if (JSON.stringify(said.blocked) !== JSON.stringify(['role:members:viewer as a "viewer" in members: I could not add one'])) {
          p.push(who + ' blocked ' + JSON.stringify(said.blocked));
        }
      }
      return p;
    })());

    // ------------------------------------------------ what is said
    const scans = await bothScans(client, APP);
    check('the whole scan reports them as things to check, worded plainly, in both engines', (() => {
      const p = [];
      for (const [engine, result] of scans) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        const roles = result.findings.filter((f) => f.kind === 'role');
        const names = roles.map((f) => f.table).sort().join(',');
        if (names !== 'customers,squad_members,tickets') p.push(engine + ' reported ' + names);
        for (const f of roles) {
          if (f.status !== 'verification required') p.push(engine + ' ' + f.table + ' is ' + f.status);
          if (f.severity !== 'HIGH') p.push(engine + ' ' + f.table + ' is ' + f.severity);
          if (!/undone straight away/.test(f.body)) p.push(engine + ' ' + f.table + ' never says it was undone');
          if (!/please check it rather than assume it/.test(f.fixPrompt.replace(/\s+/g, ' '))) p.push(engine + ' ' + f.table + ' prompt claims a break');
          if (!/"members"\."role" is "viewer"/.test(f.fixPrompt.replace(/\s+/g, ' '))) p.push(engine + ' ' + f.table + ' prompt: ' + f.fixPrompt);
        }
        const customers = roles.find((f) => f.table === 'customers');
        if (customers && customers.headline !== 'A "viewer" in a workspace can change rows in your customers table.') {
          p.push(engine + ': ' + customers.headline);
        }
        const squad = roles.find((f) => f.table === 'squad_members');
        if (squad && squad.headline !== 'A "viewer" in a workspace can delete rows from and change rows in your squad_members table.') {
          p.push(engine + ': ' + squad.headline);
        }
        if (result.findings.some((f) => f.kind === 'role' && ['open_board', 'invoices', 'notes', 'members'].includes(f.table))) {
          p.push(engine + ' blamed a table that holds');
        }
        if (!result.findings.some((f) => f.kind === 'writable' && f.table === 'open_board')) p.push(engine + ' lost the open board');
        if (scanner.exitCodeFor({ findings: roles }) !== 0) p.push(engine + ': a thing to check alone gives a failing exit code');
        if ((result.notChecked || []).some((n) => /^role:/.test(n.key || ''))) p.push(engine + ' did not check ' + JSON.stringify(result.notChecked));
      }
      return p;
    })());

    check('the report counts them apart, as the owner\'s decision - and never says a viewer was not tried', (() => {
      const printed = (findings) => {
        const said = [];
        const write = process.stdout.write;
        process.stdout.write = (text) => { said.push(String(text)); return true; };
        try {
          scanner.report({ findings: findings, notChecked: [], attacksRun: 1 });
        } finally {
          process.stdout.write = write;
        }
        return said.join('');
      };
      const roles = scans[0][1].findings.filter((f) => f.kind === 'role');
      const fn = require('./finding.js').describe({ kind: 'privileged', fn: 'export_all', table: 'export_all', args: '', columns: [] });
      const p = [];
      const alone = printed(roles);
      if (!/3 things to check - whether each is a problem is your decision\./.test(alone)) p.push(alone.split('\n').slice(0, 4).join(' | '));
      if (/problems? found/.test(alone)) p.push('counted as problems');
      const mixed = printed(roles.concat([fn]));
      if (!/4 things to check - whether each is a problem is your decision\./.test(mixed)) p.push(mixed.split('\n').slice(0, 4).join(' | '));
      const onlyRead = printed([fn]);
      if (!/1 thing to check - I did not attack it, only spotted the risk\./.test(onlyRead)) p.push(onlyRead.split('\n').slice(0, 4).join(' | '));
      return p;
    })());

    const one = await bothScans(client, SINGLE);
    check('a one-team profile is not attacked as a team, and not listed as untested', (() => {
      const p = [];
      for (const [engine, result] of one) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        if ((result.attempted || []).some((k) => /^role:/.test(k))) p.push(engine + ' tried ' + result.attempted.filter((k) => /^role:/.test(k)));
        if ((result.notChecked || []).some((n) => /^role:/.test(n.key || ''))) p.push(engine + ' listed ' + JSON.stringify(result.notChecked));
      }
      return p;
    })());

    // ------------------------------------------------ the nightly door
    let night = null;
    await sqlengine.withEngine(client, async (target) => {
      const { rows } = await client.query('SELECT ' + schema.quote(target) + '.nightly($1) AS id', [APP]);
      night = (await client.query('SELECT * FROM ' + schema.quote(target) + '.runs WHERE id = $1', [rows[0].id])).rows[0];
    });
    check('the nightly run inside the database finds them too', (() => {
      if (!night) return ['no run was written'];
      if (night.stopped) return ['stopped: ' + night.stopped];
      const roles = (night.findings || []).filter((f) => f.kind === 'role').map((f) => f.table).sort().join(',');
      return roles === 'customers,squad_members,tickets' ? [] : ['found ' + roles];
    })());

    // ------------------------------------------------ the re-check
    const before = scans[0][1];
    await client.query('DROP POLICY tickets_member ON ' + at(APP)('tickets'));
    const after = await scanner.scan(client, APP, { quiet: true });
    check('a viewer rule tightened is called fixed by the re-check, and the others still open', (() => {
      const verdict = recheck.compare(before, after);
      const p = [];
      const fixed = verdict.fixed.map(recheck.keyOf);
      const open = verdict.stillOpen.map(recheck.keyOf);
      if (!fixed.includes('role:tickets:viewer')) p.push('fixed ' + JSON.stringify(fixed));
      if (!open.includes('role:customers:viewer')) p.push('still open ' + JSON.stringify(open));
      if (verdict.unverifiable.length) p.push('unverifiable ' + JSON.stringify(verdict.unverifiable.map(recheck.keyOf)));
      return p;
    })());
  } finally {
    for (const app of [APP, LISTED, SINGLE, FULL]) {
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
  console.log('All ' + results.length + ' role checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
