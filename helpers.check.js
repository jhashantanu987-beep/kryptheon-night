// Checks that the helpers a rule calls are built inside the copy.
//
//   node helpers.check.js "<postgres connection string>"
//
// Found on a blind test (MeridianOps): a rule called
// has_org_role(org_id, ARRAY[...]::org_role[]). The copy has its own org_role;
// the helper stayed in the original schema, taking the original's; no rule
// could be created and the scan stopped before it began. And a helper left in
// the original answers from the original's tables, not from the copy's.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_help_' + STAMP;
const COPY = 'kn_help_copy_' + STAMP;
const q = (name) => schema.quote(APP) + '.' + schema.quote(name);

const results = [];
const check = (name, problems) => results.push({ name, problems });

async function build(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
  await client.query('CREATE TYPE ' + q('role_t') + " AS ENUM ('owner', 'admin', 'viewer')");
  await client.query('CREATE TABLE ' + q('members') + ' (org_id uuid NOT NULL, user_id uuid NOT NULL, role ' + q('role_t') + ' NOT NULL, PRIMARY KEY (org_id, user_id))');
  await client.query('CREATE TABLE ' + q('docs') + ' (id serial PRIMARY KEY, org_id uuid NOT NULL, body text)');
  await client.query('CREATE TABLE ' + q('notes') + ' (id serial PRIMARY KEY, org_id uuid NOT NULL, body text)');
  // A SQL helper taking the app's enum array, reading members qualified.
  await client.query('CREATE FUNCTION ' + q('has_role') + '(p_org uuid, p_roles ' + q('role_t') + '[]) RETURNS boolean LANGUAGE sql STABLE AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + " m WHERE m.org_id = p_org AND m.user_id = nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid AND m.role = ANY (p_roles)) $$");
  // Called only from is_admin, never from a rule: it comes along only if
  // what the helpers call is followed.
  await client.query('CREATE FUNCTION ' + q('in_org') + '(p_org uuid) RETURNS boolean LANGUAGE sql STABLE AS ' +
    '$$ SELECT EXISTS (SELECT 1 FROM ' + q('members') + ' WHERE org_id = p_org) $$');
  // A PL/pgSQL helper with a pinned search_path, reading members bare, and
  // calling the one above - so it has to come along too.
  await client.query('CREATE FUNCTION ' + q('is_admin') + '(p_org uuid) RETURNS boolean LANGUAGE plpgsql STABLE SET search_path = ' + schema.quote(APP) + ' AS ' +
    "$$ BEGIN RETURN has_role(p_org, ARRAY['owner', 'admin']::role_t[]) AND in_org(p_org); END $$");
  // Closed to anon, as an app might: the copy must keep it closed.
  await client.query('REVOKE ALL ON FUNCTION ' + q('has_role') + '(uuid, ' + q('role_t') + '[]) FROM PUBLIC');
  await client.query('GRANT EXECUTE ON FUNCTION ' + q('has_role') + '(uuid, ' + q('role_t') + '[]) TO authenticated');
  // Not called by any rule: stays out of the copy.
  await client.query('CREATE FUNCTION ' + q('unused') + '() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$');
  for (const t of ['members', 'docs', 'notes']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
    await client.query('ALTER TABLE ' + q(t) + ' ENABLE ROW LEVEL SECURITY');
  }
  await client.query('CREATE POLICY admins ON ' + q('docs') + ' FOR SELECT USING (' + q('has_role') + "(org_id, ARRAY['owner', 'admin']::" + q('role_t') + '[]))');
  await client.query('CREATE POLICY admins ON ' + q('notes') + ' FOR SELECT USING (' + q('is_admin') + '(org_id))');
  await client.query('CREATE POLICY own ON ' + q('members') + " FOR SELECT USING (user_id = nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid)");
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node helpers.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await build(client);
    const plan = await schema.readSchema(client, APP);

    check('only the helpers a rule calls, and what they call, are taken', (() => {
      const got = schema.functionsToCopy(plan).map((f) => f.name).sort();
      return JSON.stringify(got) === '["has_role","in_org","is_admin"]' ? [] : ['copied ' + JSON.stringify(got)];
    })());

    check('a copied helper is named in the copy and looks in the copy first', (() => {
      const p = [];
      const fn = plan.functions.find((f) => f.name === 'is_admin');
      const made = schema.copyFunctionStatement(fn, plan, COPY, ['has_role', 'is_admin']);
      if (!made.startsWith('CREATE FUNCTION "' + COPY + '".is_admin(')) p.push('header: ' + made.split('\n')[0]);
      if (!new RegExp("SET search_path TO '" + COPY + "', '?" + APP).test(made)) p.push('search_path: ' + (made.match(/SET search_path.*/) || ['none'])[0]);
      if (made.includes('CREATE OR REPLACE')) p.push('it could replace something of the same name');
      return p;
    })());

    let built = null;
    let nodeStatements = [];
    try {
      nodeStatements = await schema.writeSchema(client, plan, COPY);
      built = true;
    } catch (err) {
      built = err.message;
    }
    check('a rule calling a helper that takes the app\'s own enum array can be copied', built === true ? [] : ['the copy failed: ' + built]);

    if (built === true) {
      const { rows: deps } = await client.query(
        `SELECT pol.polname, cl.relname, fn.proname, fns.nspname
           FROM pg_depend d
           JOIN pg_policy pol ON pol.oid = d.objid AND d.classid = 'pg_policy'::regclass
           JOIN pg_class cl ON cl.oid = pol.polrelid
           JOIN pg_namespace cn ON cn.oid = cl.relnamespace AND cn.nspname = $1
           JOIN pg_proc fn ON fn.oid = d.refobjid AND d.refclassid = 'pg_proc'::regclass
           JOIN pg_namespace fns ON fns.oid = fn.pronamespace`, [COPY]);
      check('the copy\'s rules call the copy\'s helpers, never the original\'s', (() => {
        const p = [];
        if (!deps.length) p.push('no rule depends on a helper at all');
        for (const d of deps) if (d.nspname !== COPY) p.push(d.relname + '.' + d.polname + ' calls ' + d.nspname + '.' + d.proname);
        return p;
      })());

      // The copy's helper answers from the copy's members: a member written
      // only into the copy is an admin there and nowhere else.
      const user = '00000000-0000-4000-8000-0000000000aa';
      const org = '00000000-0000-4000-8000-0000000000bb';
      await client.query('INSERT INTO ' + schema.quote(COPY) + ".members VALUES ($1, $2, 'admin')", [org, user]);
      await client.query('INSERT INTO ' + schema.quote(COPY) + '.docs (org_id, body) VALUES ($1, $2)', [org, 'x']);
      await client.query('INSERT INTO ' + schema.quote(COPY) + '.notes (org_id, body) VALUES ($1, $2)', [org, 'y']);
      const read = async (table) => {
        await client.query('BEGIN');
        try {
          await client.query('SET LOCAL ROLE authenticated');
          await client.query("SELECT set_config('request.jwt.claims', $1, true)", [JSON.stringify({ sub: user, role: 'authenticated' })]);
          return (await client.query('SELECT * FROM ' + schema.quote(COPY) + '.' + schema.quote(table))).rows.length;
        } catch (err) {
          return 'error: ' + err.message;
        } finally {
          await client.query('ROLLBACK');
        }
      };
      const docs = await read('docs');
      const notes = await read('notes');
      check('a member who exists only in the copy passes the copy\'s rules', (() => {
        const p = [];
        if (docs !== 1) p.push('docs (SQL helper, qualified): ' + docs);
        if (notes !== 1) p.push('notes (PL/pgSQL helper, pinned search_path, bare names): ' + notes);
        return p;
      })());

      const { rows: left } = await client.query(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1 AND p.proname = 'unused'", [COPY]);
      check('a function no rule calls is not copied', left.length ? ['unused was copied'] : []);
      const { rows: acl } = await client.query(
        "SELECT has_function_privilege('anon', p.oid, 'EXECUTE') AS anon, has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authed, " +
        "has_function_privilege('anon', o.oid, 'EXECUTE') AS anon_is_admin " +
        "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = $1 AND p.proname = 'has_role' " +
        "JOIN pg_proc o ON o.pronamespace = n.oid AND o.proname = 'is_admin'", [COPY]);
      check('who may call a copied helper is the same as in the original', (() => {
        const a = acl[0] || {};
        const p = [];
        if (a.anon !== false) p.push('anon can call has_role in the copy, which the original closed to it');
        if (a.authed !== true) p.push('authenticated cannot call has_role in the copy');
        if (a.anon_is_admin !== true) p.push('a helper left at the default lost its default grant');
        return p;
      })());
      await client.query('DROP SCHEMA ' + schema.quote(COPY) + ' CASCADE');
    }

    // The engine that lives in the database builds the same statements.
    let mine = null;
    let theirs = null;
    await sqlengine.withEngine(client, async (target) => {
      // The node engine's own statements for the copy it built above.
      mine = nodeStatements.map((st) => st.split(schema.quote(COPY)).join(schema.quote('<copy>')).split(COPY).join('<copy>'))
        .filter((st) => /^(CREATE FUNCTION|REVOKE ALL ON FUNCTION|GRANT EXECUTE ON FUNCTION)/.test(st));
      const sqlPlan = await sqlengine.readSchema(client, target, APP);
      const statements = await sqlengine.copyStatements(client, target, sqlPlan, '<copy>');
      theirs = statements.filter((s) => /^(CREATE FUNCTION|REVOKE ALL ON FUNCTION|GRANT EXECUTE ON FUNCTION)/.test(s));
    });
    check('the engine in the database copies the same helpers, the same way', (() => {
      const norm = (list) => (list || []).map((s) => s.replace(/\r\n/g, '\n')).sort();
      return JSON.stringify(norm(mine)) === JSON.stringify(norm(theirs))
        ? [] : ['node:\n' + norm(mine).join('\n---\n') + '\n\nsql:\n' + norm(theirs).join('\n---\n')];
    })());

    // And the whole scan runs on it, where before it stopped.
    const r = await scan(client, APP, { quiet: true });
    check('the whole scan runs on such an app', r.stopped ? ['stopped: ' + r.stopped] : []);
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(COPY) + ' CASCADE').catch(() => {});
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
  console.log('All ' + results.length + ' helper-copy checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
