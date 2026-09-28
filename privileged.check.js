// Checks the SECURITY DEFINER function reader: it flags a function an
// anonymous visitor can call that runs past row level security, and - the part
// that matters - it does NOT flag the three things that look similar but are
// not that: a definer function only signed-in users can call, a trigger
// function, and a plain (invoker) function.
//
//   node privileged.check.js "<postgres connection string>"
//
// A real database, because this is entirely about what Postgres reports for
// grants, prosecdef and return type - the things a hand-rolled stand-in would
// get subtly wrong.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_priv_' + STAMP;
const q = (name) => schema.quote(name);

const results = [];
const check = (name, problems) => results.push({ name, problems });

async function build(client) {
  await client.query('CREATE SCHEMA ' + q(APP));
  await client.query('GRANT USAGE ON SCHEMA ' + q(APP) + ' TO anon, authenticated');
  await client.query('CREATE TABLE ' + q(APP) + '.secrets (id serial primary key, body text)');

  // 1. The real thing: definer, writes, granted to anon.
  await client.query(
    'CREATE FUNCTION ' + q(APP) + '.claim(event_key text) RETURNS boolean LANGUAGE sql SECURITY DEFINER AS ' +
      "$$ INSERT INTO " + q(APP) + ".secrets (body) VALUES (event_key); SELECT true $$",
  );
  await client.query('REVOKE ALL ON FUNCTION ' + q(APP) + '.claim(text) FROM PUBLIC');
  await client.query('GRANT EXECUTE ON FUNCTION ' + q(APP) + '.claim(text) TO anon, authenticated');

  // 2. Definer, but only signed-in users can call it: the ordinary RPC
  //    pattern, and NOT a finding - flagging it would bury the real one.
  await client.query(
    'CREATE FUNCTION ' + q(APP) + '.mine() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$',
  );
  await client.query('REVOKE ALL ON FUNCTION ' + q(APP) + '.mine() FROM PUBLIC');
  await client.query('GRANT EXECUTE ON FUNCTION ' + q(APP) + '.mine() TO authenticated');

  // 3. Definer, and reachable by anon only through PUBLIC (the default grant).
  //    Anon can still call it, so it IS a finding - a revoke from anon that
  //    forgets PUBLIC would leave this open, and the check must see it.
  await client.query(
    'CREATE FUNCTION ' + q(APP) + '.viapublic() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$',
  );

  // 4. A trigger function granted to anon. Calling it directly does nothing,
  //    so anon cannot really reach anything - NOT a finding.
  await client.query(
    'CREATE FUNCTION ' + q(APP) + '.ontouch() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS ' +
      '$$ BEGIN RETURN NEW; END $$',
  );
  await client.query('GRANT EXECUTE ON FUNCTION ' + q(APP) + '.ontouch() TO anon');

  // 5. A plain function (SECURITY INVOKER) granted to anon. It runs as the
  //    caller, so the table rules DO apply - NOT a finding.
  await client.query(
    'CREATE FUNCTION ' + q(APP) + '.plain() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$',
  );
  await client.query('GRANT EXECUTE ON FUNCTION ' + q(APP) + '.plain() TO anon');

  // 6. Definer, anon, reads only, and no fixed search_path - a finding, and
  //    one whose wording must say "reads" and must raise the search_path point.
  await client.query(
    'CREATE FUNCTION ' + q(APP) + '.peek() RETURNS setof ' + q(APP) + '.secrets LANGUAGE sql SECURITY DEFINER AS ' +
      '$$ SELECT * FROM ' + q(APP) + '.secrets $$',
  );
  await client.query('GRANT EXECUTE ON FUNCTION ' + q(APP) + '.peek() TO anon');
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node privileged.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, q);
    await build(client);
    const fns = await schema.readAnonDefinerFunctions(client, APP);
    const byName = new Map(fns.map((f) => [f.name, f]));
    const names = fns.map((f) => f.name).sort();

    check('it flags the definer function anon can call', (() => {
      return byName.has('claim') ? [] : ['claim was not flagged; got ' + JSON.stringify(names)];
    })());

    check('a definer function only authenticated can call is left alone', (() => {
      return byName.has('mine') ? ['mine (authenticated-only) was flagged - the RPC pattern is not a finding'] : [];
    })());

    check('reachable through PUBLIC counts as reachable by anon', (() => {
      return byName.has('viapublic') ? [] : ['viapublic (granted via PUBLIC) was missed'];
    })());

    check('a trigger function is not treated as anon-callable', (() => {
      return byName.has('ontouch') ? ['ontouch (a trigger function) was flagged'] : [];
    })());

    check('a plain (invoker) function is not a finding', (() => {
      return byName.has('plain') ? ['plain (security invoker) was flagged'] : [];
    })());

    check('writes vs reads is read from the body', (() => {
      const problems = [];
      const claim = byName.get('claim');
      const peek = byName.get('peek');
      if (claim && claim.writes !== true) problems.push('claim writes but was read as read-only');
      if (peek && peek.writes !== false) problems.push('peek only reads but was read as writing');
      return problems;
    })());

    check('a missing search_path is noticed', (() => {
      const peek = byName.get('peek');
      if (!peek) return ['peek was not flagged at all'];
      return peek.hasFixedSearchPath ? ['peek has no SET search_path but was read as if it had one'] : [];
    })());

    check('exactly the three risky functions are flagged, no more', (() => {
      const want = ['claim', 'peek', 'viapublic'];
      const got = names;
      return JSON.stringify(got) === JSON.stringify(want) ? [] : ['expected ' + JSON.stringify(want) + ', got ' + JSON.stringify(got)];
    })());

    // The reader is one thing; a full scan carrying its output into the report
    // is another. Run the whole thing over this schema and confirm the finding
    // arrives, marked verification-required so it is never counted as proven.
    const result = await scan(client, APP, { quiet: true });
    check('a full scan surfaces the anon function as a verification-required finding', (() => {
      const problems = [];
      if (result.stopped) return ['the scan stopped: ' + result.stopped];
      const priv = (result.findings || []).filter((f) => f.kind === 'privileged');
      const claim = priv.find((f) => f.table === 'claim');
      if (!claim) return ['scan did not surface claim; privileged findings: ' + JSON.stringify(priv.map((f) => f.table))];
      if (claim.status !== 'verification required') problems.push('status was ' + claim.status);
      if (claim.severity === 'CRITICAL') problems.push('a finding that was never executed was marked CRITICAL');
      // It was read again this run, so a later run where the grant is gone can
      // call it fixed rather than "could not confirm".
      if (!(result.attempted || []).includes('privileged:claim')) problems.push('the re-check has no record that this was looked at');
      return problems;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + q(APP) + ' CASCADE').catch(() => {});
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
  console.log('All ' + results.length + ' privileged-function checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
