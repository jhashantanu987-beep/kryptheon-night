// Checks that a rule which looks its own table up is reported as a problem,
// not only as a reason something went untested.
//
//   node recursion.check.js "<postgres connection string>"
//
// Found on a blind test: a policy on organization_members asked
// organization_members who was a member. Every signed-in read touching it
// failed with "infinite recursion detected in policy", so the app was broken
// for everyone with an account - and the report mentioned it only under
// "What I did not test".
//
// A real database, because the error is Postgres's own and only it decides
// when a policy loops.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');
const { scan, exitCodeFor } = require('./scan.js');
const recheck = require('./recheck.js');
const sqlengine = require('./sqlengine.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_loop_' + STAMP;
const q = (t) => schema.quote(APP) + '.' + schema.quote(t);

const results = [];
const check = (name, problems) => results.push({ name, problems });

const MEMBER_OF = (org) =>
  org + ' IN (SELECT m.org_id FROM ' + q('organization_members') + ' m WHERE m.user_id = auth.uid())';

async function build(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q('organization_members') +
    ' (id serial primary key, org_id int not null, user_id uuid not null, role text)');
  await client.query('CREATE TABLE ' + q('projects') + ' (id serial primary key, org_id int not null, name text)');
  // A table whose rule is fine: it must not be dragged into the finding.
  await client.query('CREATE TABLE ' + q('notes') + ' (id serial primary key, owner_id uuid not null, body text)');
  for (const t of ['organization_members', 'projects', 'notes']) {
    await client.query('GRANT ALL ON ' + q(t) + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY members_read ON ' + q('organization_members') +
    ' FOR SELECT TO authenticated USING (' + MEMBER_OF('org_id') + ')');
  await client.query('CREATE POLICY projects_read ON ' + q('projects') +
    ' FOR SELECT TO authenticated USING (' + MEMBER_OF('org_id') + ')');
  await client.query('CREATE POLICY own ON ' + q('notes') +
    ' FOR SELECT TO authenticated USING (owner_id = auth.uid())');
  // No row can ever be put in it, so the writes never try it: only the reads
  // can see that its rule loops. (A write would see it too - Postgres finds
  // the loop while planning, before it checks any grant.)
  await client.query('CREATE TABLE ' + q('circles') + ' (id serial primary key, org_id int not null CHECK (org_id < 0 AND org_id > 0), user_id uuid not null)');
  await client.query('GRANT SELECT ON ' + q('circles') + ' TO authenticated');
  await client.query('ALTER TABLE ' + q('circles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY circles_read ON ' + q('circles') +
    ' FOR SELECT TO authenticated USING (org_id IN (SELECT c.org_id FROM ' + q('circles') + ' c WHERE c.user_id = auth.uid()))');
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node recursion.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await fixture.ensureAuth(client);

    check('the table at fault is read out of Postgres\'s message', (() => {
      const problems = [];
      const named = attack.recursionIn('infinite recursion detected in policy for relation "organization_members"');
      if (named !== 'organization_members') problems.push('got ' + JSON.stringify(named));
      if (attack.recursionIn('permission denied for table organization_members') !== null) {
        problems.push('a refusal was read as a loop');
      }
      if (attack.recursionIn(undefined) !== null) problems.push('no message was read as a loop');
      return problems;
    })());

    await build(client);

    // The reads alone, with no writes attempted: a rule written only FOR
    // SELECT loops on reading, and that has to be caught by the reads.
    const plan = await schema.readSchema(client, APP);
    const reads = await attack.impersonate(client, APP, plan.tables);
    check('the reads alone find the loop, and who it fails for', (() => {
      const seen = (reads.looped || []).map((l) => l.relation + '<-' + l.table + ':' + l.who).sort();
      const want = [
        'circles<-circles:signed-in',
        'organization_members<-organization_members:signed-in',
        'organization_members<-projects:signed-in',
      ];
      return JSON.stringify(seen) === JSON.stringify(want) ? [] : ['expected ' + JSON.stringify(want) + ', got ' + JSON.stringify(seen)];
    })());

    // The engine that lives in the database has to say the same, or the
    // nightly run files a broken app as merely "not tested".
    let sqlReads = null;
    let nightly = null;
    await sqlengine.withEngine(client, async (target) => {
      sqlReads = await sqlengine.impersonate(client, target, APP, plan.tables);
      const { rows } = await client.query('SELECT ' + schema.quote(target) + '.nightly($1) AS id', [APP]);
      nightly = (await client.query('SELECT stopped, findings FROM ' + schema.quote(target) + '.runs WHERE id = $1',
        [rows[0].id])).rows[0];
    });
    check('the engine in the database finds the same loops', (() => {
      const said = (r) => JSON.stringify({
        looped: (r.looped || []).map((l) => l.relation + '<-' + l.table + ':' + l.who).sort(),
        checked: (r.completed || []).filter((k) => k.startsWith('recursive:')).sort(),
      });
      return said(reads) === said(sqlReads) ? [] : ['node ' + said(reads) + '\n        sql  ' + said(sqlReads)];
    })());
    check('and its nightly run reports each one as a finding', (() => {
      if (!nightly || nightly.stopped) return ['the nightly run stopped: ' + (nightly && nightly.stopped)];
      const got = (nightly.findings || []).filter((f) => f.kind === 'recursive')
        .map((f) => f.table + ' via ' + [...f.reads].sort().join('+') + ' for ' + f.callers.join('+')).sort();
      const want = ['circles via circles for signed-in', 'organization_members via organization_members+projects for signed-in'];
      return JSON.stringify(got) === JSON.stringify(want) ? [] : ['expected ' + JSON.stringify(want) + ', got ' + JSON.stringify(got)];
    })());

    const first = await scan(client, APP, { quiet: true });
    const loops = (first.findings || []).filter((f) => f.kind === 'recursive');

    check('a rule that refers to itself is a finding of its own', (() => {
      if (first.stopped) return ['the scan stopped: ' + first.stopped];
      // circles loops only on reading - nothing may write to it - so it is
      // here only if the scan carries the reads' loops into the report.
      const tables = loops.map((f) => f.table).sort();
      if (JSON.stringify(tables) !== '["circles","organization_members"]') {
        return ['expected circles and organization_members, got ' + JSON.stringify(tables)];
      }
      const problems = [];
      const loop = loops.find((f) => f.table === 'organization_members');
      if (loop.status !== 'confirmed') problems.push('status was ' + loop.status);
      if (loop.severity !== 'HIGH') problems.push('severity was ' + loop.severity + ' - nothing leaked, so HIGH');
      if (!/signed-in users get an error/.test(loop.headline)) problems.push('headline: ' + loop.headline);
      if (/visitors who are not logged in|everyone/.test(loop.headline)) problems.push('anon reads worked, but the headline blames them: ' + loop.headline);
      if (!/projects/.test(loop.body)) problems.push('the body does not say projects is broken too: ' + loop.body);
      if (/notes|circles/.test(loop.body)) problems.push('a table this rule does not break was blamed: ' + loop.body);
      if (!/SECURITY DEFINER/.test(loop.fixPrompt) || !/USING\s+\(true\)/.test(loop.fixPrompt)) {
        problems.push('the fix prompt does not name the helper, or does not forbid opening the table');
      }
      return problems;
    })());

    check('the attacks it stopped are still listed as not tested', (() => {
      const keys = (first.notChecked || []).map((n) => n.key);
      return keys.includes('crossed:organization_members') ? [] : ['not-tested keys: ' + JSON.stringify(keys)];
    })());

    check('only a table that read cleanly counts as checked for a loop', (() => {
      const attempted = first.attempted || [];
      const problems = [];
      if (attempted.includes('recursive:organization_members')) problems.push('the looping table was recorded as checked');
      if (attempted.includes('recursive:projects')) problems.push('projects, whose read failed, was recorded as checked');
      if (!attempted.includes('recursive:notes')) problems.push('notes read cleanly but was not recorded as checked');
      return problems;
    })());

    check('it counts as a problem in the exit code', (() => {
      return exitCodeFor(first) === 1 ? [] : ['exit code was ' + exitCodeFor(first)];
    })());

    // The fix the prompt asks for: the lookup moves into a definer helper
    // that answers only about the caller. The re-check must see the loop gone
    // AND know it looked, so it is fixed rather than "could not confirm".
    await client.query(
      'CREATE FUNCTION ' + q('is_member_of') + '(org int) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER ' +
        'SET search_path = pg_catalog, public AS $$ SELECT EXISTS (SELECT 1 FROM ' + q('organization_members') +
        ' m WHERE m.org_id = org AND m.user_id = auth.uid()) $$',
    );
    await client.query('REVOKE ALL ON FUNCTION ' + q('is_member_of') + '(int) FROM PUBLIC');
    await client.query('GRANT EXECUTE ON FUNCTION ' + q('is_member_of') + '(int) TO authenticated');
    await client.query('DROP POLICY members_read ON ' + q('organization_members'));
    await client.query('CREATE POLICY members_read ON ' + q('organization_members') +
      ' FOR SELECT TO authenticated USING (' + schema.quote(APP) + '.is_member_of(org_id))');
    await client.query('DROP POLICY projects_read ON ' + q('projects'));
    await client.query('CREATE POLICY projects_read ON ' + q('projects') +
      ' FOR SELECT TO authenticated USING (' + schema.quote(APP) + '.is_member_of(org_id))');
    await client.query('DROP POLICY circles_read ON ' + q('circles'));
    await client.query('CREATE POLICY circles_read ON ' + q('circles') +
      ' FOR SELECT TO authenticated USING (user_id = auth.uid())');

    const second = await scan(client, APP, { quiet: true });
    const verdict = recheck.compare(first, second);
    check('the loop, once untangled, is re-checked as fixed', (() => {
      if (second.stopped) return ['the second scan stopped: ' + second.stopped];
      const problems = [];
      const fixed = verdict.fixed.filter((f) => f.kind === 'recursive').map((f) => f.table);
      if (!fixed.includes('organization_members') || !fixed.includes('circles')) {
        problems.push('not fixed: fixed=' + JSON.stringify(fixed) +
          ' unknown=' + JSON.stringify(verdict.unverifiable.map((f) => f.kind + ':' + f.table)));
      }
      if ((second.findings || []).some((f) => f.kind === 'recursive')) problems.push('a loop is still reported');
      if (verdict.newlyBroken.length) problems.push('newly broken: ' + JSON.stringify(verdict.newlyBroken.map((f) => f.kind + ':' + f.table)));
      const said = recheck.describe(verdict).join('\n');
      if (!/a rule that refers to itself\) - I read it again/.test(said)) problems.push('the re-check wording: ' + said);
      return problems;
    })());

    // Dropping the table is not fixing it.
    await client.query('DROP TABLE ' + q('projects'));
    await client.query('DROP FUNCTION ' + q('is_member_of') + '(int) CASCADE');
    await client.query('DROP TABLE ' + q('organization_members'));
    const third = await scan(client, APP, { quiet: true });
    const gone = recheck.compare(first, third);
    check('a dropped table is not credited as an untangled rule', (() => {
      if (third.stopped) return ['the third scan stopped: ' + third.stopped];
      const problems = [];
      const fixed = gone.fixed.filter((f) => f.kind === 'recursive').map((f) => f.table);
      const unknown = gone.unverifiable.filter((f) => f.kind === 'recursive').map((f) => f.table);
      if (fixed.includes('organization_members')) problems.push('credited as fixed');
      if (!unknown.includes('organization_members')) problems.push('not reported as unconfirmed');
      return problems;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
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
  console.log('All ' + results.length + ' recursion checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
