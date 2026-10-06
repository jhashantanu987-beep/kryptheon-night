// Checks that a member who can put their own id on another member's row -
// taking that member's place, and their role - is found, by both engines, and
// that a team whose rules do not allow it is left alone.
//
//   node takeover.check.js "<postgres connection string>"
//
// Found on a blind test (HarborLine): team_member_update let any member update
// any member row of the organization WITH CHECK (true). Repointing an admin's
// row made a member admin. The role ladder skipped it, because the rule lists
// "member" among the roles allowed to update - and a rule allowing edits is
// not a rule allowing somebody to become somebody else.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const scanner = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const WHO = "nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid";

const results = [];
const check = (name, problems) => results.push({ name, problems });

// Three teams, one rule each on updating a membership.
const APPS = {
  // Any member may update any membership row of their workspace, check true.
  open: { schema: 'kn_take_open_' + STAMP, rule: "my_role(workspace_id) IN ('owner', 'admin', 'member')", check: 'true', report: true },
  // A person may update only their own row, and keep it theirs.
  own: { schema: 'kn_take_own_' + STAMP, rule: 'user_id = ' + WHO, check: 'user_id = ' + WHO, report: false },
  // Only the people who run the team may.
  staff: { schema: 'kn_take_staff_' + STAMP, rule: "my_role(workspace_id) IN ('owner', 'admin')", check: "my_role(workspace_id) IN ('owner', 'admin')", report: false },
};

async function build(client, app) {
  const s = schema.quote(app.schema);
  const q = (n) => s + '.' + schema.quote(n);
  await client.query('CREATE SCHEMA ' + s);
  await client.query('GRANT USAGE ON SCHEMA ' + s + ' TO anon, authenticated');
  await client.query('CREATE TYPE ' + s + ".member_role AS ENUM ('owner', 'admin', 'member', 'viewer')");
  await client.query('CREATE TABLE ' + q('workspaces') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('members') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), workspace_id uuid NOT NULL' +
    ' REFERENCES ' + q('workspaces') + '(id), user_id uuid NOT NULL, role ' + s + '.member_role NOT NULL)');
  // The caller's own role in a workspace, read past the members table's own rule.
  await client.query('CREATE FUNCTION ' + q('my_role') + '(p_workspace uuid) RETURNS ' + s + '.member_role LANGUAGE sql STABLE' +
    ' SECURITY DEFINER SET search_path = ' + s + ' AS $$ SELECT role FROM ' + q('members') +
    ' WHERE workspace_id = p_workspace AND user_id = ' + WHO + ' ORDER BY role LIMIT 1 $$');
  await client.query('CREATE FUNCTION ' + q('is_member') + '(p_workspace uuid) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER' +
    ' SET search_path = ' + s + ' AS $$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE workspace_id = p_workspace AND user_id = ' + WHO + ') $$');
  for (const t of ['workspaces', 'members']) {
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q(t) + ' TO authenticated');
  }
  await client.query('CREATE POLICY reads ON ' + q('workspaces') + ' FOR SELECT TO authenticated USING (' + s + '.is_member(id))');
  await client.query('CREATE POLICY reads ON ' + q('members') + ' FOR SELECT TO authenticated USING (' + s + '.is_member(workspace_id))');
  await client.query('CREATE POLICY updates ON ' + q('members') + ' FOR UPDATE TO authenticated USING (' +
    app.rule.replace(/my_role\(/g, s + '.my_role(') + ') WITH CHECK (' + app.check.replace(/my_role\(/g, s + '.my_role(') + ')');
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node takeover.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    const seen = {};
    for (const [name, app] of Object.entries(APPS)) {
      await build(client, app);
      const node = await scanner.scan(client, app.schema, { quiet: true });
      const sql = await sqlengine.withEngine(client, (target) =>
        scanner.scan(client, app.schema, { quiet: true, engine: sqlengine.adapterFor(target) }));
      seen[name] = [['node', node], ['sql', sql]];
    }

    check('a member who can take another member\'s place is found, in both engines; teams that do not allow it are not', (() => {
      const p = [];
      for (const [name, app] of Object.entries(APPS)) {
        for (const [engine, result] of seen[name]) {
          if (result.stopped) { p.push(name + ' ' + engine + ' stopped: ' + result.stopped); continue; }
          const takeovers = result.findings.filter((f) => f.kind === 'role' && f.takeover);
          const want = app.report ? 1 : 0;
          if (takeovers.length !== want) p.push(name + ' ' + engine + ': ' + takeovers.length + ' takeovers, want ' + want);
          const any = result.findings.filter((f) => f.kind === 'role' && f.table === 'members');
          if (!app.report && any.length) p.push(name + ' ' + engine + ': members reported as ' + JSON.stringify(any.map((f) => f.who + ':' + f.can)));
        }
      }
      return p;
    })());

    check('it names the lowest role that could, the same in both engines', (() => {
      const p = [];
      const shape = (r) => (r.findings || []).filter((f) => f.takeover).map((f) => [f.table, f.who, f.personColumn, (f.can || []).join('+')].join(':')).join(' | ');
      const [[, node], [, sql]] = seen.open;
      if (shape(node) !== shape(sql)) p.push('node ' + shape(node) + ' / sql ' + shape(sql));
      if (shape(node) !== 'members:member:user_id:takeover') p.push('said ' + shape(node));
      return p;
    })());

    check('it is said as taking a member\'s place, and the fix keeps the person column fixed', (() => {
      const p = [];
      for (const [engine, result] of seen.open) {
        const f = (result.findings || []).find((x) => x.takeover);
        if (!f) { p.push(engine + ': no finding'); continue; }
        if (f.headline !== 'A "member" in a workspace can take another member\'s place in your members table - and with it their role.') p.push(engine + ' headline: ' + f.headline);
        if (!/changed members\.user_id on the other person's own membership row to their own id/.test(f.body)) p.push(engine + ' body: ' + f.body);
        const prompt = f.fixPrompt.replace(/\s+/g, ' ');
        if (!/nobody may change "user_id"/.test(prompt) || !/never use WITH CHECK \(true\)/.test(prompt)) p.push(engine + ' prompt: ' + prompt.slice(0, 300));
        if (/undefined/.test(f.headline + f.body + f.fixPrompt)) p.push(engine + ' says "undefined"');
      }
      return p;
    })());
  } finally {
    for (const app of Object.values(APPS)) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(app.schema) + ' CASCADE').catch(() => {});
    }
    await client.end().catch(() => {});
  }

  let failures = 0;
  for (const r of results) {
    if (r.problems.length) {
      failures++;
      console.log('FAIL  ' + r.name);
      r.problems.forEach((x) => console.log('      - ' + x));
    } else {
      console.log('PASS  ' + r.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exit(1);
  }
  console.log('All ' + results.length + ' takeover checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.stack);
  process.exit(1);
});
