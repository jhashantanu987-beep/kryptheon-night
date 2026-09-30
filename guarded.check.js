// Checks that a definer function which turns the caller away at the door is
// examined but not reported - and that the look-alikes still are.
//
//   node guarded.check.js "<postgres connection string>"
//
// Found on a blind test: create_admin_export opens with
//   if not public.is_org_admin(p_org_id) then raise exception 'admin required';
// and was reported as "anyone on the internet can call it, with full rights".
// A visitor with no account is nobody's admin, so the first line refuses them.
//
// The look-alikes matter more than the real thing. A check made after the
// write, a RAISE NOTICE, a check the wrong way round, "is anybody signed in",
// a helper that answers about whoever the caller names - each of those still
// lets a stranger through, and quieting one of them would hide a real hole.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');
const recheck = require('./recheck.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_guard_' + STAMP;
const S = schema.quote(APP);

const results = [];
const check = (name, problems) => results.push({ name, problems });

// plpgsql throughout, so auth.uid() need not exist when a function is made.
const definer = (name, args, body) =>
  'CREATE OR REPLACE FUNCTION ' + S + '.' + name + '(' + args + ') RETURNS boolean LANGUAGE plpgsql ' +
  'SECURITY DEFINER SET search_path = public AS $$ ' + body + ' $$';

const WRITE = 'INSERT INTO ' + S + '.exports (org) VALUES (org);';
const ADMIN = 'NOT ' + S + '.is_org_admin(org)';

// Every one of these is callable by anon (through PUBLIC) and writes.
const FUNCTIONS = {
  // Guarded: each refuses a stranger before anything runs.
  guarded_export: ['org int', 'BEGIN IF ' + ADMIN + " THEN RAISE EXCEPTION 'admin required'; END IF; " + WRITE + ' RETURN true; END'],
  // An earlier, harmless IF - its END IF must not be read as the start of one.
  guarded_after_if: ['org int', 'BEGIN IF org IS NULL THEN org := 0; END IF; IF ' + ADMIN +
    " THEN RAISE EXCEPTION 'admin required'; END IF; " + WRITE + ' RETURN true; END'],
  guarded_inline: ['org int', 'BEGIN IF NOT EXISTS (SELECT 1 FROM ' + S + '.organization_members m WHERE m.org = org ' +
    "AND m.user_id = auth.uid()::text AND m.role IN ('owner', 'admin')) THEN RAISE EXCEPTION 'admin required'; END IF; " +
    WRITE + ' RETURN true; END'],
  guarded_is_not_true: ['org int', 'BEGIN IF ' + S + ".is_org_admin(org) IS NOT TRUE THEN RAISE 'admin required'; END IF; " +
    WRITE + ' RETURN true; END'],
  // Not guarded.
  late_guard: ['org int', 'BEGIN ' + WRITE + ' IF ' + ADMIN + " THEN RAISE EXCEPTION 'admin required'; END IF; RETURN true; END"],
  notice_only: ['org int', 'BEGIN IF ' + ADMIN + " THEN RAISE NOTICE 'not an admin'; END IF; " + WRITE + ' RETURN true; END'],
  backwards: ['org int', 'BEGIN IF ' + S + ".is_org_admin(org) THEN RAISE EXCEPTION 'admins may not'; END IF; " + WRITE + ' RETURN true; END'],
  anyone_signed_in: ['org int', "BEGIN IF auth.uid() IS NULL THEN RAISE EXCEPTION 'sign in'; END IF; " + WRITE + ' RETURN true; END'],
  // The same, said the refusing way round: still only asks whether anybody
  // is signed in, not who they are.
  anyone_signed_in_too: ['org int', "BEGIN IF NOT (auth.uid() IS NOT NULL) THEN RAISE EXCEPTION 'sign in'; END IF; " + WRITE + ' RETURN true; END'],
  // A helper that answers about whoever the caller names is no guard.
  names_its_own: ['org int, who text', 'BEGIN IF NOT ' + S + ".is_admin_named(org, who) THEN RAISE EXCEPTION 'no'; END IF; " +
    WRITE + ' RETURN true; END'],
  // Two IFs must not be read as one: the first is negated but raises
  // nothing, the second raises but on the wrong answer.
  glued: ['org int', 'BEGIN IF NOT (org > 0) THEN org := 1; END IF; IF ' + S +
    ".is_org_admin(org) THEN RAISE EXCEPTION 'admins may not'; END IF; " + WRITE + ' RETURN true; END'],
  // Hands data back before it checks anything.
  returns_first: ['org int', 'BEGIN RETURN true; IF ' + ADMIN + " THEN RAISE EXCEPTION 'admin required'; END IF; END"],
};
const GUARDED = ['guarded_after_if', 'guarded_export', 'guarded_inline', 'guarded_is_not_true'];
const OPEN = ['anyone_signed_in', 'anyone_signed_in_too', 'backwards', 'glued', 'late_guard', 'names_its_own', 'notice_only', 'returns_first'];

async function build(client) {
  await client.query('CREATE SCHEMA ' + S);
  await client.query('GRANT USAGE ON SCHEMA ' + S + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + S + '.organization_members (id serial primary key, org int not null, user_id text not null, role text not null)');
  await client.query('CREATE TABLE ' + S + '.exports (id serial primary key, org int)');
  // The helper about the caller, the way Supabase apps write it.
  await client.query(definer('is_org_admin', 'org int', 'BEGIN RETURN EXISTS (SELECT 1 FROM ' + S +
    ".organization_members m WHERE m.org = org AND m.user_id = auth.uid()::text AND m.role IN ('owner', 'admin')); END"));
  // The same question about somebody the caller names.
  await client.query(definer('is_admin_named', 'org int, who text', 'BEGIN RETURN EXISTS (SELECT 1 FROM ' + S +
    ".organization_members m WHERE m.org = org AND m.user_id = who AND m.role = 'admin'); END"));
  for (const [name, [args, body]] of Object.entries(FUNCTIONS)) await client.query(definer(name, args, body));
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node guarded.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await build(client);

    const fns = await schema.readAnonDefinerFunctions(client, APP);
    const byName = new Map(fns.map((f) => [f.name, f]));

    check('every function here is callable by anon, so only the guard can quiet it', (() => {
      const missing = GUARDED.concat(OPEN).filter((name) => !(byName.get(name) || {}).callable);
      return missing.length ? ['not callable by anon: ' + JSON.stringify(missing)] : [];
    })());

    check('a function that refuses the caller at the door is read as guarded', (() => {
      const got = fns.filter((f) => f.guarded).map((f) => f.name).sort();
      return JSON.stringify(got) === JSON.stringify(GUARDED)
        ? [] : ['expected ' + JSON.stringify(GUARDED) + ', got ' + JSON.stringify(got)];
    })());

    check('the plain helpers are not guarded by themselves', (() => {
      return ['is_org_admin', 'is_admin_named'].filter((n) => (byName.get(n) || {}).guarded)
        .map((n) => n + ' was read as guarded');
    })());

    check('the reader agrees on the real benchmark shape, schema-qualified and all', (() => {
      const body = "declare v_id uuid := gen_random_uuid();\nbegin\n  if not public.is_org_admin(p_org_id) then raise exception 'admin required'; end if;\n" +
        "  insert into public.audit_events(org_id) values(p_org_id);\n  return jsonb_build_object('id',v_id);\nend;";
      const problems = [];
      if (!schema.guardedAtTheDoor(body, ['is_org_admin'])) problems.push('not guarded with is_org_admin as a helper');
      if (schema.guardedAtTheDoor(body, [])) problems.push('guarded with no helper known - the name alone decided it');
      if (schema.guardedAtTheDoor(body, ['is_org'])) problems.push('a helper whose name is only a prefix counted');
      if (schema.guardedAtTheDoor(body, ['org_admin'])) problems.push('a helper whose name is only a tail counted');
      const quoted = body.replace('public.is_org_admin', '"public"."is_org_admin"');
      if (!schema.guardedAtTheDoor(quoted, ['is_org_admin'])) problems.push('a quoted, qualified call was not seen');
      const eqFalse = body.replace('if not public.is_org_admin(p_org_id) then', 'if public.is_org_admin(p_org_id) = false then');
      if (!schema.guardedAtTheDoor(eqFalse, ['is_org_admin'])) problems.push('"= false" was not read as refusing on no');
      return problems;
    })());

    const first = await scan(client, APP, { quiet: true });
    check('a full scan examines the guarded ones and reports only the rest', (() => {
      if (first.stopped) return ['the scan stopped: ' + first.stopped];
      const problems = [];
      const reported = (first.findings || []).filter((f) => f.kind === 'privileged').map((f) => f.table);
      for (const name of GUARDED) {
        if (reported.includes(name)) problems.push(name + ' was reported');
        if (!(first.attempted || []).includes('privileged:' + name)) problems.push(name + ' was not recorded as examined');
      }
      for (const name of OPEN) if (!reported.includes(name)) problems.push(name + ' was not reported');
      return problems;
    })());

    // Putting the guard in front of the write is the fix, and the re-check
    // has to credit it.
    await client.query(definer('late_guard', 'org int', 'BEGIN IF ' + ADMIN +
      " THEN RAISE EXCEPTION 'admin required'; END IF; " + WRITE + ' RETURN true; END'));
    const second = await scan(client, APP, { quiet: true });
    const verdict = recheck.compare(first, second);
    check('moving the check in front of the write is re-checked as fixed', (() => {
      if (second.stopped) return ['the second scan stopped: ' + second.stopped];
      const problems = [];
      if (!verdict.fixed.some((f) => f.table === 'late_guard')) problems.push('late_guard was not fixed');
      if (!verdict.stillOpen.some((f) => f.table === 'notice_only')) problems.push('notice_only was not still open');
      if (verdict.newlyBroken.length) problems.push('newly broken: ' + JSON.stringify(verdict.newlyBroken.map((f) => f.table)));
      return problems;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + S + ' CASCADE').catch(() => {});
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
  console.log('All ' + results.length + ' guarded-function checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
