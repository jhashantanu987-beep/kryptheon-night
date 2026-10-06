// Checks that a table whose rows belong to an organization rather than a
// person - organization_id and no person column - is tried by a signed-in
// user from another organization, in both engines.
//
//   node tenants.check.js "<postgres connection string>"
//
// Found on a blind test (HarborLine): integration_secrets(organization_id,
// access_token) had a read rule for every signed-in user, and with no person
// column it was never attacked at all - by either engine.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const scanner = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_tenants_' + Date.now().toString(36);
// Written the way a Supabase app writes it, so the prompts treat it as one.
const WHO = 'auth.uid()::text';
const q = (name) => schema.quote(APP) + '.' + schema.quote(name);

const results = [];
const check = (name, problems) => results.push({ name, problems });

// What each table is, and what should be said about it.
const TABLES = {
  open_secrets: 'crossed',   // every signed-in user reads every organization's tokens
  org_labels: 'crossed orphaned', // the same, through a key the table only implies (and no foreign key)
  member_secrets: null,      // members of the row's organization only: right
  public_notes: 'exposed',   // readable logged out: exposed, and not said twice
  // A view of the organizations the reader is in: the second person sees their
  // own, which is right (HarborLine's workspace_health came back as a leak).
  my_orgs: null,
  // One row per organization (lines point at it, so each person gets their
  // own), and members of that organization may edit it: right. Found on
  // HarborLine's invoices, where the second person changed their own
  // organization's row and it was said as changing another customer's.
  ledgers: null,
  ledger_lines: null,
};

async function build(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('organizations') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL)');
  await client.query('CREATE TABLE ' + q('members') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'organization_id uuid NOT NULL REFERENCES ' + q('organizations') + '(id), user_id uuid NOT NULL, role text NOT NULL DEFAULT \'member\')');
  await client.query('CREATE TABLE ' + q('open_secrets') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'organization_id uuid NOT NULL REFERENCES ' + q('organizations') + '(id), access_token text NOT NULL)');
  await client.query('CREATE TABLE ' + q('member_secrets') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'organization_id uuid NOT NULL REFERENCES ' + q('organizations') + '(id), token text NOT NULL)');
  await client.query('CREATE TABLE ' + q('public_notes') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'organization_id uuid NOT NULL REFERENCES ' + q('organizations') + '(id), body text NOT NULL)');
  // No foreign key: the organization is only implied by the column's name.
  await client.query('CREATE TABLE ' + q('org_labels') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'organization_id uuid NOT NULL, label text NOT NULL)');
  await client.query('CREATE TABLE ' + q('ledgers') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'organization_id uuid NOT NULL REFERENCES ' + q('organizations') + '(id), total numeric NOT NULL DEFAULT 0)');
  await client.query('CREATE TABLE ' + q('ledger_lines') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ' +
    'ledger_id uuid NOT NULL REFERENCES ' + q('ledgers') + '(id), amount numeric NOT NULL DEFAULT 0)');
  for (const t of ['organizations', 'members', 'open_secrets', 'member_secrets', 'public_notes', 'org_labels', 'ledgers', 'ledger_lines']) {
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
  }
  await client.query('CREATE POLICY own ON ' + q('members') + ' FOR SELECT TO authenticated USING (user_id::text = ' + WHO + ')');
  await client.query('CREATE POLICY everyone ON ' + q('open_secrets') + ' FOR SELECT TO authenticated USING (true)');
  await client.query('CREATE POLICY everyone ON ' + q('org_labels') + ' FOR SELECT TO authenticated USING (true)');
  await client.query('CREATE POLICY members_only ON ' + q('member_secrets') + ' FOR SELECT TO authenticated USING (' +
    'EXISTS (SELECT 1 FROM ' + q('members') + ' m WHERE m.organization_id = member_secrets.organization_id AND m.user_id::text = ' + WHO + '))');
  await client.query('CREATE POLICY anyone ON ' + q('public_notes') + ' FOR SELECT TO public USING (true)');
  const ownOrg = 'EXISTS (SELECT 1 FROM ' + q('members') + ' m WHERE m.organization_id = ledgers.organization_id AND m.user_id::text = ' + WHO + ')';
  await client.query('GRANT UPDATE ON ' + q('ledgers') + ' TO authenticated');
  await client.query('CREATE POLICY members_read ON ' + q('ledgers') + ' FOR SELECT TO authenticated USING (' + ownOrg + ')');
  await client.query('CREATE POLICY members_edit ON ' + q('ledgers') + ' FOR UPDATE TO authenticated USING (' + ownOrg + ') WITH CHECK (' + ownOrg + ')');
  await client.query('CREATE VIEW ' + q('my_orgs') + ' AS SELECT o.id AS organization_id, o.name FROM ' + q('organizations') + ' o ' +
    'WHERE EXISTS (SELECT 1 FROM ' + q('members') + ' m WHERE m.organization_id = o.id AND m.user_id::text = ' + WHO + ')');
  await client.query('GRANT SELECT ON ' + q('my_orgs') + ' TO authenticated');
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node tenants.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  let undoAuth = null;
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    undoAuth = await fixture.ensureAuth(client);
    await build(client);
    const node = await scanner.scan(client, APP, { quiet: true });
    const sql = await sqlengine.withEngine(client, (target) =>
      scanner.scan(client, APP, { quiet: true, engine: sqlengine.adapterFor(target) }));
    const runs = [['node', node], ['sql', sql]];

    check('a table an organization owns is tried by someone from another organization, in both engines', (() => {
      const p = [];
      for (const [engine, result] of runs) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        for (const [table, want] of Object.entries(TABLES)) {
          const kinds = result.findings.filter((f) => f.table === table).map((f) => f.kind).sort();
          const expect = want ? want.split(' ').sort() : [];
          if (JSON.stringify(kinds) !== JSON.stringify(expect)) p.push(engine + ' ' + table + ': ' + JSON.stringify(kinds) + ', want ' + JSON.stringify(expect));
          if (!['my_orgs', 'ledgers'].includes(table) && !(result.attempted || []).includes('crossed:' + table)) p.push(engine + ': crossed:' + table + ' was never tried');
        }
      }
      return p;
    })());

    // The nightly run's own findings are what reaches the dashboard, with no
    // report in between to drop a duplicate: a table anyone can read is
    // exposed there, and not also an organization's rows read from outside.
    let night = null;
    await sqlengine.withEngine(client, async (target) => {
      const id = (await client.query('SELECT ' + schema.quote(target) + '.nightly($1) AS id', [APP])).rows[0].id;
      night = (await client.query('SELECT findings, stopped FROM ' + schema.quote(target) + '.runs WHERE id = $1', [id])).rows[0];
    });
    check('the nightly run, as the dashboard gets it, says each table once and right', (() => {
      if (!night || night.stopped) return ['the night stopped: ' + (night && night.stopped)];
      const p = [];
      const kinds = (table) => (night.findings || []).filter((f) => f.table === table).map((f) => f.kind).sort().join(',');
      if (kinds('public_notes') !== 'exposed') p.push('public_notes: ' + kinds('public_notes'));
      if (kinds('open_secrets') !== 'crossed') p.push('open_secrets: ' + kinds('open_secrets'));
      const open = (night.findings || []).find((f) => f.table === 'open_secrets');
      if (open && (open.tenant !== true || open.owner !== 'organization_id')) p.push('open_secrets said as ' + JSON.stringify(open));
      if (kinds('ledgers') !== '') p.push('ledgers: ' + kinds('ledgers'));
      return p;
    })());

    check('both engines say the same thing about it', (() => {
      const shape = (result) => (result.findings || []).filter((f) => f.kind === 'crossed')
        .map((f) => [f.table, f.owner, f.tenant, f.readable].join(':')).sort().join(' | ');
      return shape(node) === shape(sql) ? [] : ['node ' + shape(node), 'sql  ' + shape(sql)];
    })());

    check('it is said as one organization reading another\'s, and the fix asks for membership', (() => {
      const p = [];
      for (const [engine, result] of runs) {
        const f = (result.findings || []).find((x) => x.table === 'open_secrets' && x.kind === 'crossed');
        if (!f) { p.push(engine + ': no finding'); continue; }
        if (f.headline !== 'Your open_secrets table lets a signed-in user read another organization\'s rows.') p.push(engine + ' headline: ' + f.headline);
        if (!/different organization/.test(f.body) || !/access tokens and secrets/.test(f.body)) p.push(engine + ' body: ' + f.body);
        const prompt = f.fixPrompt.replace(/\s+/g, ' ');
        if (!/belonging to a different organization/.test(prompt)) p.push(engine + ' prompt cause: ' + prompt.slice(0, 200));
        if (!/belong to an organization \("organization_id"\)/.test(prompt) || !/member of that row's organization/.test(prompt)) p.push(engine + ' prompt fix: ' + prompt.slice(0, 400));
        if (/compare organization_id against the id of the signed-in user/i.test(prompt)) p.push(engine + ' tells them to compare the organization to the user');
        if (f.severity !== 'CRITICAL' && f.severity !== 'HIGH') p.push(engine + ' severity ' + f.severity);
      }
      return p;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    if (undoAuth) await undoAuth().catch(() => {});
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
  console.log('All ' + results.length + ' organization checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.stack);
  process.exit(1);
});
