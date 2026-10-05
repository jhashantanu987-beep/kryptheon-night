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
// A team whose lowest role is a plain "member": it may add rows.
const CREW = 'kn_rolesmem_' + STAMP;
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
 *   vault          a secret every member can read                -> reported (read, viewer)
 *   api_keys       a key members and up can read                  -> reported (read, member)
 *   signing_keys   a key only owner and admin can read            -> not reported
 *   comments       any member may add one, but only as themselves -> not reported
 *   projects       owner/admin write; the other team's own rows are
 *                  pointed at by its milestones                  -> tried, not stuck
 *   flags          a role list lets owner/admin/editor change it, and a rule
 *                  of its own lets a "member" (LaunchRail's analyst) -> reported (change, member)
 *   drafts         a role list that names member and editor     -> not reported
 *   chores         a helper whose own list names member         -> not reported
 */
async function buildApp(client) {
  const q = at(APP);
  const s = schema.quote(APP);
  await client.query('CREATE SCHEMA ' + s);
  await client.query('GRANT USAGE ON SCHEMA ' + s + ' TO anon, authenticated');
  await client.query('CREATE TYPE ' + s + ".member_role AS ENUM ('owner', 'admin', 'editor', 'member', 'viewer')");
  await client.query('CREATE TABLE ' + q('workspaces') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('access_grants') + ' (workspace_id uuid NOT NULL REFERENCES ' + q('workspaces') + '(id),' +
    ' user_id uuid NOT NULL, role ' + s + '.member_role NOT NULL, PRIMARY KEY (workspace_id, user_id))');
  await client.query('CREATE TABLE ' + q('members') + ' (workspace_id uuid NOT NULL REFERENCES ' + q('workspaces') + '(id),' +
    ' user_id uuid NOT NULL, role ' + s + '.member_role NOT NULL, PRIMARY KEY (workspace_id, user_id))');
  await client.query('CREATE TABLE ' + q('invites') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), created_by uuid NOT NULL, role ' + s + '.member_role NOT NULL)');
  for (const t of ['customers', 'tickets', 'invoices', 'open_board', 'reports', 'squads', 'projects', 'flags', 'drafts', 'chores', 'boards', 'pins', 'stages']) {
    await client.query('CREATE TABLE ' + q(t) + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
      ' REFERENCES ' + q('workspaces') + '(id), label text NOT NULL)');
  }
  await client.query('CREATE TABLE ' + q('deals') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), customer_id uuid NOT NULL REFERENCES ' + q('customers') + '(id), amount numeric NOT NULL)');
  await client.query('CREATE TABLE ' + q('notes') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), user_id uuid NOT NULL, body text NOT NULL)');
  await client.query('CREATE TABLE ' + q('squad_members') + ' (squad_id uuid NOT NULL REFERENCES ' + q('squads') + '(id),' +
    ' user_id uuid NOT NULL, PRIMARY KEY (squad_id, user_id))');
  // A share link anyone signed in can already read: not a role question.
  await client.query('ALTER TABLE ' + q('open_board') + ' ADD COLUMN share_token text');
  for (const [t, secret] of [['vault', 'secret'], ['api_keys', 'api_key'], ['signing_keys', 'signing_key']]) {
    await client.query('CREATE TABLE ' + q(t) + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
      ' REFERENCES ' + q('workspaces') + '(id), label text NOT NULL, ' + secret + ' text NOT NULL)');
  }
  await client.query('CREATE TABLE ' + q('comments') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), author_id uuid NOT NULL, body text NOT NULL)');
  // A stage a member may do anything to, whose items point at it: deleting
  // one is refused by the key, which is not the member being refused.
  await client.query('CREATE TABLE ' + q('stage_items') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), stage_id uuid NOT NULL REFERENCES ' + q('stages') + '(id), created_by uuid NOT NULL,' +
    ' label text NOT NULL)');
  await client.query('CREATE TABLE ' + q('milestones') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), project_id uuid NOT NULL REFERENCES ' + q('projects') + '(id), created_by uuid NOT NULL,' +
    ' label text NOT NULL)');

  // The helpers as an app that works writes them: definer, so the members
  // table is read without its own rule asking again.
  await client.query('CREATE FUNCTION ' + q('is_member') + '(p_workspace uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE workspace_id = p_workspace AND user_id = ' + WHO + ') $$');
  await client.query('CREATE FUNCTION ' + q('has_role') + '(p_workspace uuid, p_roles ' + s + '.member_role[]) RETURNS boolean' +
    ' LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT EXISTS (SELECT 1 FROM ' + q('members') +
    ' WHERE workspace_id = p_workspace AND user_id = ' + WHO + ' AND role = ANY (p_roles)) $$');
  // A helper that lists, in its own body, who may touch a chore.
  await client.query('CREATE FUNCTION ' + q('can_touch') + '(p_workspace uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE workspace_id = p_workspace AND user_id = ' + WHO +
    " AND role IN ('owner', 'admin', 'member')) $$");
  const member = (col) => q('is_member') + '(' + col + ')';
  const staff = (col, roles) => q('has_role') + '(' + col + ", '{" + roles + "}'::" + s + '.member_role[])';

  const tables = ['workspaces', 'access_grants', 'members', 'invites', 'customers', 'tickets', 'invoices', 'open_board',
    'reports', 'squads', 'deals', 'notes', 'squad_members', 'vault', 'api_keys', 'signing_keys', 'comments', 'projects', 'milestones',
    'flags', 'drafts', 'chores', 'boards', 'pins', 'stages', 'stage_items'];
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
  await policy('vault', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('api_keys', 'reads', 'FOR SELECT TO authenticated USING (' + staff('workspace_id', 'owner,admin,editor,member') + ')');
  await policy('signing_keys', 'reads', 'FOR SELECT TO authenticated USING (' + staff('workspace_id', 'owner,admin') + ')');
  await policy('comments', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('comments', 'own_add', 'FOR INSERT TO authenticated WITH CHECK (' + member('workspace_id') + ' AND author_id = ' + WHO + ')');
  await policy('projects', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('projects', 'staff', 'FOR ALL TO authenticated USING (' + staff('workspace_id', 'owner,admin') + ')');
  await policy('milestones', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  for (const t of ['flags', 'drafts', 'chores']) await policy(t, 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('flags', 'flags_update', 'FOR UPDATE TO authenticated USING (' + staff('workspace_id', 'owner,admin,editor') + ')');
  // Production's own rule for one role, the shape LaunchRail added.
  await policy('flags', 'flag_member_update', 'FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM ' + q('members') +
    " m WHERE m.workspace_id = flags.workspace_id AND m.user_id = " + WHO + " AND m.role = 'member'))");
  await policy('drafts', 'drafts_update', 'FOR UPDATE TO authenticated USING (' + staff('workspace_id', 'owner,admin,editor,member') + ')');
  await policy('chores', 'chores_update', 'FOR UPDATE TO authenticated USING (' + q('can_touch') + '(workspace_id))');
  // A viewer a list names, and a member given a rule of its own: the member
  // is named, and the viewer is not said to have been unable.
  for (const t of ['boards', 'pins']) await policy(t, 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('boards', 'boards_viewers', 'FOR UPDATE TO authenticated USING (' + staff('workspace_id', 'viewer') + ')');
  await policy('boards', 'boards_member', 'FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM ' + q('members') +
    " m WHERE m.workspace_id = boards.workspace_id AND m.user_id = " + WHO + " AND m.role = 'member'))");
  await policy('stages', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  await policy('stages', 'stages_all', 'FOR ALL TO authenticated USING (' + staff('workspace_id', 'owner,admin,member') + ')');
  await policy('stage_items', 'reads', 'FOR SELECT TO authenticated USING (' + member('workspace_id') + ')');
  // Only a member may add a pin: adding is asked of a role that only looks.
  await policy('pins', 'pins_member', 'FOR INSERT TO authenticated WITH CHECK (EXISTS (SELECT 1 FROM ' + q('members') +
    " m WHERE m.workspace_id = pins.workspace_id AND m.user_id = " + WHO + " AND m.role = 'member'))");
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

/** A crew whose roles are owner, admin and member: the lowest may add. */
async function buildCrew(client) {
  const q = at(CREW);
  await client.query('CREATE SCHEMA ' + schema.quote(CREW));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(CREW) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('orgs') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('crew') + ' (org_id uuid NOT NULL REFERENCES ' + q('orgs') + '(id), user_id uuid NOT NULL,' +
    " role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')), PRIMARY KEY (org_id, user_id))");
  await client.query('CREATE TABLE ' + q('tasks') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), org_id uuid NOT NULL REFERENCES ' +
    q('orgs') + '(id), title text NOT NULL)');
  await client.query('CREATE FUNCTION ' + q('in_crew') + '(p uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('crew') + ' WHERE org_id = p AND user_id = ' + WHO + ') $$');
  for (const t of ['orgs', 'crew', 'tasks']) {
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY reads ON ' + q('crew') + ' FOR SELECT TO authenticated USING (user_id = ' + WHO + ')');
  await client.query('CREATE POLICY anything ON ' + q('tasks') + ' FOR ALL TO authenticated USING (' + q('in_crew') + '(org_id))' +
    ' WITH CHECK (' + q('in_crew') + '(org_id))');
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
      answer = await tamper.teammate(client, copy, copied.tables, sown.seeded,
        { policies: copied.policies, functions: copied.functions });
      after = await contentsOf(client, copy);
    } else {
      await sqlengine.withEngine(client, async (target) => {
        const plan = await sqlengine.readSchema(client, target, app);
        await sqlengine.writeSchema(client, target, plan, copy);
        const copied = await sqlengine.readSchema(client, target, copy);
        const sown = await sqlengine.seed(client, target, copy, copied.tables);
        before = await contentsOf(client, copy);
        answer = await sqlengine.teammate(client, target, copy, copied.tables, sown.seeded,
          { policies: copied.policies, functions: copied.functions });
        after = await contentsOf(client, copy);
      });
    }
    return { answer: answer, unchanged: JSON.stringify(before) === JSON.stringify(after) };
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(copy) + ' CASCADE').catch(() => {});
  }
}

const told = (r) => ({
  findings: (r.findings || []).map((f) => f.kind + ':' + f.table + '/' + f.who + '/' + f.via + '.' + f.roleColumn + '/' + f.parent + '/' +
    (f.kind === 'teamread'
      ? 'read ' + f.readable + ' below ' + JSON.stringify(f.below) + ' ' + JSON.stringify(f.secrets)
      : [...(f.can || [])].sort().join('+') + '/' + JSON.stringify(f.changed) +
        ((f.below || []).length ? ' below ' + JSON.stringify(f.below) : ''))).sort(),
  completed: [...(r.completed || [])].sort(),
  blocked: (r.blocked || []).map((b) => b.key + ' ' + String(b.why).split(':').slice(0, 2).join(':')).sort(),
});

// Who a team's rules allow to write: LaunchRail's repository rule, its
// production rule for one role, a helper's own list, and the edges.
const RULE_LIST = { table_name: 'flags', permissive: 'PERMISSIVE', cmd: 'UPDATE',
  qual: "has_project_role(project_id, ARRAY['owner'::kn_x.project_role, 'maintainer'::kn_x.project_role, 'developer'::kn_x.project_role])" };
const RULE_ONE = { table_name: 'flags', permissive: 'PERMISSIVE', cmd: 'UPDATE',
  qual: "(EXISTS ( SELECT 1 FROM projects p JOIN organization_members om ON true WHERE om.role = 'analyst'::org_role))" };
const RULE_HELPER = { table_name: 'docs', permissive: 'PERMISSIVE', cmd: 'ALL', qual: 'can_edit(org_id)' };
const RULE_NARROWS = { table_name: 'docs', permissive: 'RESTRICTIVE', cmd: 'DELETE', qual: "role = ANY (ARRAY['viewer'::text])" };
const FNS = [{ name: 'can_edit', src: "select exists(select 1 from m where role in ('owner', 'editor'))" },
  { name: 'is_admin', src: "select role = 'viewer'" }];
// A list written as an array literal, the way roles.check's own helper calls are.
const RULE_LITERAL = { table_name: 'drafts', permissive: 'PERMISSIVE', cmd: 'UPDATE',
  qual: "kn_x.has_role(workspace_id, '{owner,admin,editor,member}'::kn_x.member_role[])" };
const RULES = { policies: [RULE_LIST, RULE_ONE, RULE_HELPER, RULE_NARROWS, RULE_LITERAL], functions: FNS };
const CASES = [
  { rules: RULES, table: 'flags', what: 'change', role: 'developer', type: 'kn_x.project_role', want: true },
  { rules: RULES, table: 'flags', what: 'change', role: 'developer', type: 'org_role', want: false },
  { rules: RULES, table: 'flags', what: 'change', role: 'analyst', type: 'org_role', want: false },
  { rules: RULES, table: 'flags', what: 'delete', role: 'developer', type: 'project_role', want: false },
  { rules: RULES, table: 'flags', what: 'add', role: 'maintainer', type: 'project_role', want: false },
  { rules: RULES, table: 'docs', what: 'delete', role: 'editor', type: 'text', want: true },
  { rules: RULES, table: 'docs', what: 'delete', role: 'viewer', type: 'text', want: false },
  { rules: RULES, table: 'other', what: 'change', role: 'developer', type: 'project_role', want: false },
  { rules: RULES, table: 'drafts', what: 'change', role: 'member', type: 'kn_x.member_role', want: true },
  { rules: RULES, table: 'drafts', what: 'change', role: 'owner', type: 'member_role', want: true },
  { rules: RULES, table: 'drafts', what: 'change', role: 'mem', type: 'member_role', want: false },
  { rules: RULES, table: 'drafts', what: 'change', role: 'viewer', type: 'member_role', want: false },
  { rules: RULES, table: 'drafts', what: 'change', role: 'member', type: 'org_role', want: false },
];

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
    await buildCrew(client);

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
    for (const app of [APP, LISTED, SINGLE, FULL, CREW]) plans[app] = await schema.readSchema(client, app);
    const nodeSays = {
      lowest: LABELS.map((labels) => tamper.lowestRole(labels)),
      memberships: {},
    };
    for (const app of Object.keys(plans)) {
      nodeSays.memberships[app] = tamper.memberships(plans[app].tables).map((m) =>
        m.table.name + ':' + m.person + ':' + m.role + ':' + m.lowest + ':' + m.keys.map((k) => k.refTable).join('+') + ':' +
          m.ladder.join('>'));
    }
    const nodeAllowed = CASES.map((c) => tamper.allowedByRules(c.rules, c.table, c.what, c.role, c.type));
    const sqlAllowed = [];
    await sqlengine.withEngine(client, async (target) => {
      for (const c of CASES) {
        const { rows } = await client.query('SELECT ' + schema.quote(target) + '.allowed_by_rules($1::jsonb, $2, $3, $4, $5) AS answer',
          [JSON.stringify(c.rules), c.table, c.what, c.role, c.type]);
        sqlAllowed.push(rows[0].answer);
      }
    });
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
          m.table.name + ':' + m.person + ':' + m.role + ':' + m.lowest + ':' + m.keys.map((k) => k.refTable).join('+') + ':' +
          m.ladder.join('>'));
      }
    });

    check('a role a rule lists is allowed, and one given a rule of its own is not, the same in both engines', (() => {
      const p = [];
      const want = CASES.map((c) => c.want);
      for (const [who, said] of [['node', nodeAllowed], ['sql', sqlAllowed]]) {
        if (JSON.stringify(said) !== JSON.stringify(want)) p.push(who + ': ' + JSON.stringify(said) + ' want ' + JSON.stringify(want));
      }
      return p;
    })());

    check('the lowest role is the one that may only look, in both engines', (() => {
      const p = [];
      for (const [who, says] of [['node', nodeSays], ['sql', sqlSays]]) {
        if (JSON.stringify(says.lowest) !== JSON.stringify(WANT)) p.push(who + ': ' + JSON.stringify(says.lowest));
      }
      return p;
    })());

    check('the members table is found by its role, with its roles from the lowest up, never an invitation or a one-team profile, in both engines', (() => {
      const p = [];
      const want = {};
      want[APP] = ['members:user_id:role:viewer:workspaces:viewer>member>editor', 'access_grants:user_id:role:viewer:workspaces:viewer>member>editor'];
      want[LISTED] = ['org_users:user_id:role:viewer:orgs:viewer>editor'];
      want[SINGLE] = [];
      want[FULL] = ['members:user_id:role:viewer:teams:viewer'];
      want[CREW] = ['crew:user_id:role:member:orgs:member'];
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
    check('a viewer who can add or change customers, change tickets and squad members, and read the vault is found, and a member who can read api keys - nothing else', (() => {
      const p = [];
      const want = [
        'role:customers/viewer/members.role/workspaces/add+change/{"add":1,"change":1}',
        'role:flags/member/members.role/workspaces/change/{"change":1} below ["viewer"]',
        'role:boards/member/members.role/workspaces/change/{"change":1}',
        'role:squad_members/viewer/members.role/workspaces/change+delete/{"change":1,"delete":1}',
        'role:tickets/viewer/members.role/workspaces/change/{"change":1}',
        'teamread:api_keys/member/members.role/workspaces/read 1 below ["viewer"] ["api_key"]',
        'teamread:vault/viewer/members.role/workspaces/read 1 below [] ["secret"]',
      ].sort();
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
        for (const table of ['invoices', 'notes', 'open_board', 'members', 'workspaces', 'reports', 'invites', 'deals',
          'comments', 'projects', 'milestones', 'signing_keys']) {
          if (!(r.answer.completed || []).includes('role:' + table + ':viewer')) p.push(who + ': ' + table + ' never tried');
        }
        // A role a list names is passed over, and the roles above it still
        // tried: every rung of drafts and chores, and none of them reported.
        for (const table of ['drafts', 'chores', 'stages']) {
          for (const role of ['viewer', 'member', 'editor']) {
            if (!(r.answer.completed || []).includes('role:' + table + ':' + role)) p.push(who + ': ' + table + ' never tried as ' + role);
          }
        }
        // Nobody in charge is ever tried.
        if ((r.answer.completed || []).some((k) => /^role:.*:(owner|admin)$/.test(k))) p.push(who + ': tried a role in charge');
        // A secret only owner and admin read was asked of every lower role.
        for (const role of ['viewer', 'member']) {
          if (!(r.answer.completed || []).includes('teamread:signing_keys:' + role)) p.push(who + ': signing_keys never read as ' + role);
        }
        // An ordinary table is never read as a role question.
        if ((r.answer.completed || []).some((k) => /^teamread:(reports|customers|tickets):/.test(k))) p.push(who + ': read an ordinary table');
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
        if (JSON.stringify(said) !== JSON.stringify(['role:docs/viewer/org_users.role/orgs/add+change+delete/{"add":1,"change":1,"delete":1}'])) {
          p.push(who + ' found ' + JSON.stringify(said));
        }
      }
      return p;
    })());

    const crewNode = await ranked(client, CREW, 'node');
    const crewSql = await ranked(client, CREW, 'sql');
    check('a plain "member" changing a task is found, but adding one is not counted against them', (() => {
      const p = [];
      for (const [who, r] of [['node', crewNode], ['sql', crewSql]]) {
        const said = told(r.answer).findings;
        if (JSON.stringify(said) !== JSON.stringify(['role:tasks/member/crew.role/orgs/change+delete/{"change":1,"delete":1}'])) {
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
        const roles = result.findings.filter((f) => f.kind === 'role' || f.kind === 'teamread');
        const names = roles.map((f) => f.kind + ':' + f.table).sort().join(',');
        if (names !== 'role:boards,role:customers,role:flags,role:squad_members,role:tickets,teamread:api_keys,teamread:vault') p.push(engine + ' reported ' + names);
        for (const f of roles) {
          if (f.status !== 'verification required') p.push(engine + ' ' + f.table + ' is ' + f.status);
          if (f.severity !== 'HIGH') p.push(engine + ' ' + f.table + ' is ' + f.severity);
          const settled = f.kind === 'teamread' ? /Nothing was changed\./ : /undone straight away/;
          if (!settled.test(f.body)) p.push(engine + ' ' + f.table + ' never says it was undone or untouched');
          if (!/please check it rather than assume it/.test(f.fixPrompt.replace(/\s+/g, ' '))) p.push(engine + ' ' + f.table + ' prompt claims a break');
          if (f.fixPrompt.replace(/\s+/g, ' ').indexOf('"members"."role" is "' + f.who + '"') < 0) p.push(engine + ' ' + f.table + ' prompt: ' + f.fixPrompt);
        }
        const customers = roles.find((f) => f.table === 'customers');
        if (customers && customers.headline !== 'A "viewer" in a workspace can change rows in and add rows to your customers table.') {
          p.push(engine + ': ' + customers.headline);
        }
        const keys = roles.find((f) => f.table === 'api_keys');
        if (keys && keys.headline !== 'A "member" in a workspace can read your api_keys table, which holds api_key.') {
          p.push(engine + ': ' + keys.headline);
        }
        if (keys && !/As "viewer" they could not read it either\. Nothing was changed\./.test(keys.body)) p.push(engine + ': ' + keys.body);
        // A role in the middle, named because the one under it held.
        const flags = roles.find((f) => f.table === 'flags');
        if (!flags) p.push(engine + ': flags not reported');
        else {
          if (flags.headline !== 'A "member" in a workspace can change rows in your flags table.') p.push(engine + ': ' + flags.headline);
          const body = flags.body.replace(/\s+/g, ' ');
          if (body.indexOf('as a "member" - a role in members.role -') < 0) p.push(engine + ' calls it the lowest role: ' + body);
          if (body.indexOf('As "viewer" they could not either, and no rule on this table lists "member" among the roles allowed') < 0) {
            p.push(engine + ' does not say who could not: ' + body);
          }
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
      if (!/5 things to check - whether each is a problem is your decision\./.test(alone)) p.push(alone.split('\n').slice(0, 4).join(' | '));
      if (/problems? found/.test(alone)) p.push('counted as problems');
      const mixed = printed(roles.concat([fn]));
      if (!/6 things to check - whether each is a problem is your decision\./.test(mixed)) p.push(mixed.split('\n').slice(0, 4).join(' | '));
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
      const roles = (night.findings || []).filter((f) => f.kind === 'role' || f.kind === 'teamread').map((f) => f.kind + ':' + f.table).sort().join(',');
      return roles === 'role:boards,role:customers,role:flags,role:squad_members,role:tickets,teamread:api_keys,teamread:vault' ? [] : ['found ' + roles];
    })());

    // ------------------------------------------------ the re-check
    const before = scans[0][1];
    await client.query('DROP POLICY tickets_member ON ' + at(APP)('tickets'));
    await client.query('DROP POLICY reads ON ' + at(APP)('vault'));
    const after = await scanner.scan(client, APP, { quiet: true });
    check('a viewer rule and a secret read tightened are called fixed by the re-check, and the others still open', (() => {
      const verdict = recheck.compare(before, after);
      const p = [];
      const fixed = verdict.fixed.map(recheck.keyOf);
      const open = verdict.stillOpen.map(recheck.keyOf);
      if (!fixed.includes('role:tickets:viewer') || !fixed.includes('teamread:vault:viewer')) p.push('fixed ' + JSON.stringify(fixed));
      if (!open.includes('role:customers:viewer')) p.push('still open ' + JSON.stringify(open));
      if (verdict.unverifiable.length) p.push('unverifiable ' + JSON.stringify(verdict.unverifiable.map(recheck.keyOf)));
      return p;
    })());
  } finally {
    for (const app of [APP, LISTED, SINGLE, FULL, CREW]) {
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
