// Checks that a rule which reaches its own table through a helper function -
// so Postgres runs out of stack instead of naming the loop - is reported as
// the loop it is, on the table at fault.
//
//   node deeploop.check.js "<postgres connection string>"
//
// Found on a blind test (MeridianOps): members_read called is_org_member,
// which reads org_members, whose rule is members_read. Every signed-in read
// failed with "stack depth limit exceeded" and was filed only as untested.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');
const sqlengine = require('./sqlengine.js');
const scanner = require('./scan.js');
const recheck = require('./recheck.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_deep_' + STAMP;
const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
const WHO = "nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid";

const results = [];
const check = (name, problems) => results.push({ name, problems });

async function build(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('members') + ' (org_id uuid NOT NULL, user_id uuid NOT NULL, PRIMARY KEY (org_id, user_id))');
  await client.query('CREATE TABLE ' + q('docs') + ' (id serial PRIMARY KEY, org_id uuid NOT NULL, body text)');
  await client.query('CREATE TABLE ' + q('members_log') + ' (id serial PRIMARY KEY, org_id uuid NOT NULL)');
  await client.query('CREATE FUNCTION ' + q('is_member') + '(p_org uuid) RETURNS boolean LANGUAGE sql STABLE AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE org_id = p_org AND user_id = ' + WHO + ') $$');
  for (const t of ['members', 'docs', 'members_log']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY reads ON ' + q(t) + ' FOR SELECT TO authenticated USING (' + q('is_member') + '(org_id))');
  }
}

// The OrbitDesk shape of the same loop: the helper has no search_path of its
// own and names members bare. Found on a blind test - the copy's helper read
// the original's members, which the scan never seeds, so the loop never
// fired and was not reported.
const BARE = 'kn_deepbare_' + STAMP;
async function buildBare(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(BARE));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(BARE) + ' TO anon, authenticated');
  await client.query('SET search_path TO ' + schema.quote(BARE) + ', public');
  try {
    await client.query('CREATE TABLE members (org_id uuid NOT NULL, user_id uuid NOT NULL, PRIMARY KEY (org_id, user_id))');
    await client.query('CREATE TABLE docs (id serial PRIMARY KEY, org_id uuid NOT NULL, body text)');
    await client.query('CREATE FUNCTION is_member(p_org uuid) RETURNS boolean LANGUAGE sql STABLE AS ' +
      '$$ SELECT EXISTS (SELECT 1 FROM members WHERE org_id = p_org AND user_id = ' + WHO + ') $$');
    for (const t of ['members', 'docs']) {
      await client.query('GRANT SELECT ON ' + t + ' TO anon, authenticated');
      await client.query('ALTER TABLE ' + t + ' ENABLE ROW LEVEL SECURITY');
      await client.query('CREATE POLICY reads ON ' + t + ' FOR SELECT TO authenticated USING (is_member(org_id))');
    }
  } finally {
    await client.query('RESET search_path');
  }
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node deeploop.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await build(client);
    await buildBare(client);

    for (const [engine, run] of [
      ['node', () => scanner.scan(client, BARE, { quiet: true })],
      ['sql', () => sqlengine.withEngine(client, (t) => scanner.scan(client, BARE, { quiet: true, engine: sqlengine.adapterFor(t) }))],
    ]) {
      const result = await run();
      check(engine + ': a loop through a helper that names its table bare is found in the copy', (() => {
        if (result.stopped) return ['stopped: ' + result.stopped];
        const loops = (result.findings || []).filter((f) => f.kind === 'recursive').map((f) => f.table);
        const p = [];
        if (JSON.stringify(loops) !== '["members"]') p.push('loops: ' + JSON.stringify(loops));
        const unrelated = (result.notChecked || []).filter((n) => !/stack depth limit exceeded/.test(String(n.why)));
        if (unrelated.length) p.push('not checked for another reason: ' + JSON.stringify(unrelated));
        return p;
      })());
    }

    check('"stack depth limit exceeded" is read as a loop; other errors are not', (() => {
      const p = [];
      if (!attack.tooDeep('stack depth limit exceeded')) p.push('not recognised');
      if (attack.tooDeep('permission denied for table members')) p.push('a refusal was read as a loop');
      if (attack.tooDeep(undefined)) p.push('no message was read as a loop');
      return p;
    })());

    check('a helper that reaches the table through another helper counts; a longer name is a different table', (() => {
      const p = [];
      const synthetic = {
        tables: [{ name: 'teams' }, { name: 'logs' }, { name: 'logs_archive' }],
        policies: [
          { table_name: 'teams', qual: 'can_see(id)' },
          { table_name: 'logs', qual: 'reads_archive(id)' },
          { table_name: 'logs_archive', qual: 'reads_archive(id)' },
        ],
        functions: [
          { name: 'can_see', src: 'SELECT inner_check(p)' },
          { name: 'inner_check', src: 'SELECT EXISTS (SELECT 1 FROM app.teams WHERE id = p)' },
          { name: 'reads_archive', src: 'SELECT EXISTS (SELECT 1 FROM app.logs_archive WHERE id = p)' },
        ],
      };
      const got = scanner.loopingTables(synthetic);
      if (!got.includes('teams')) p.push('teams, reached through two helpers, was missed');
      if (got.includes('logs')) p.push('logs was blamed for a helper that reads logs_archive');
      if (!got.includes('logs_archive')) p.push('logs_archive was missed');
      return p;
    })());

    const plan = await schema.readSchema(client, APP);
    check('the table at fault is found from the rules and helpers, not guessed', (() => {
      const got = scanner.loopingTables(plan);
      return JSON.stringify(got) === '["members"]' ? [] : ['got ' + JSON.stringify(got)];
    })());

    const first = await scanner.scan(client, APP, { quiet: true });
    const loops = (first.findings || []).filter((f) => f.kind === 'recursive');
    check('the loop is a finding on the table at fault, said as what Postgres said', (() => {
      if (first.stopped) return ['the scan stopped: ' + first.stopped];
      if (loops.length !== 1) return ['expected one loop, got ' + JSON.stringify(loops.map((f) => f.table))];
      const p = [];
      const f = loops[0];
      if (f.table !== 'members') p.push('it named ' + f.table);
      if (!/stack depth limit exceeded/.test(f.body) || /infinite recursion detected/.test(f.body)) p.push('body: ' + f.body);
      if (!/docs/.test(f.body)) p.push('the tables broken with it are not named: ' + f.body);
      if (!/through a helper function/.test(f.fixPrompt.replace(/\s+/g, ' '))) p.push('the prompt does not say the loop goes through a helper');
      if (f.severity !== 'HIGH' || f.status !== 'confirmed') p.push(f.severity + ' / ' + f.status);
      return p;
    })());

    // The engine inside the database records the same loop, with no table
    // named. A rule is only evaluated over rows, so each table gets one.
    const org = '00000000-0000-4000-8000-0000000000cc';
    await client.query('INSERT INTO ' + q('members') + ' VALUES ($1, $2)', [org, attack.USER_A]);
    await client.query('INSERT INTO ' + q('docs') + ' (org_id) VALUES ($1)', [org]);
    let sqlReads = null;
    let night = null;
    await sqlengine.withEngine(client, async (target) => {
      sqlReads = await sqlengine.impersonate(client, target, APP, plan.tables);
      const { rows } = await client.query('SELECT ' + schema.quote(target) + '.nightly($1) AS id', [APP]);
      night = (await client.query('SELECT * FROM ' + schema.quote(target) + '.runs WHERE id = $1', [rows[0].id])).rows[0];
    });
    const nodeReads = await attack.impersonate(client, APP, plan.tables);
    check('both engines record it the same way', (() => {
      const said = (r) => JSON.stringify((r.looped || []).map((l) => l.relation + '<-' + l.table + ':' + l.who).sort());
      return said(nodeReads) === said(sqlReads) && (nodeReads.looped || []).length ? [] : ['node ' + said(nodeReads) + ' sql ' + said(sqlReads) + ' blocked ' + JSON.stringify(nodeReads.blocked) + ' completed ' + JSON.stringify(nodeReads.completed)];
    })());
    const record = scanner.nightlyRecord({ installed: true, where: { source: APP }, run: night }, '2026-10-04T00:00:00.000Z', plan);
    check('read back the next morning, the night\'s loop is put on the table at fault', (() => {
      const f = (record.findings || []).filter((x) => x.kind === 'recursive');
      if (f.length !== 1) return ['got ' + JSON.stringify(f.map((x) => x.table))];
      return f[0].table === 'members' && /stack depth limit exceeded/.test(f[0].body) ? [] : ['got ' + f[0].table + ': ' + f[0].body];
    })());

    // The fix the prompt asks for: the helper becomes SECURITY DEFINER.
    await client.query('ALTER FUNCTION ' + q('is_member') + '(uuid) SECURITY DEFINER SET search_path = pg_catalog');
    const second = await scanner.scan(client, APP, { quiet: true });
    const verdict = recheck.compare(first, second);
    check('once the helper no longer runs the rule again, the re-check calls it fixed', (() => {
      if (second.stopped) return ['the second scan stopped: ' + second.stopped];
      const p = [];
      if (!verdict.fixed.some((f) => f.kind === 'recursive' && f.table === 'members')) p.push('not fixed; unknown ' + JSON.stringify(verdict.unverifiable.map((f) => f.kind + ':' + f.table)));
      if ((second.findings || []).some((f) => f.kind === 'recursive')) p.push('a loop is still reported');
      return p;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(BARE) + ' CASCADE').catch(() => {});
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
  console.log('All ' + results.length + ' deep-loop checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
