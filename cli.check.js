// Checks the real front door - bin/kryptheon-night.js - against a real
// database, unattended (--yes, KN_DATABASE_URL), the way a script or an AI
// tool runs it. The other checks drive scan.js; this is the only one that
// proves the command a person actually types gets the same answers.
//
//   node cli.check.js "<postgres connection string>"

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_cli_' + STAMP;
const q = (name) => schema.quote(name);
const BIN = path.join(__dirname, 'bin', 'kryptheon-night.js');

const results = [];
const check = (name, problems) => results.push({ name, problems });

// Its own project folder and its own store: the run is saved like a real
// one, so the second run is a real re-check - and none of it touches the real
// ~/.kryptheon.
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-cli-'));
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'kryptheon-home-'));

function run() {
  const r = spawnSync(process.execPath, [BIN, '--yes', '--schema', APP], {
    cwd: WORK,
    encoding: 'utf8',
    timeout: 300000,
    env: Object.assign({}, process.env, { KN_DATABASE_URL: CONNECTION, KRYPTHEON_HOME: HOME }),
  });
  return { code: r.status, out: String(r.stdout || '') + String(r.stderr || '') };
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node cli.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await client.query('CREATE SCHEMA ' + q(APP));
    await fixture.ensureRoles(client, APP, q);
    // A table that holds: row level security on and no rule, so neither a
    // stranger nor a customer gets anything. Nothing here should be a
    // confirmed finding.
    await client.query('CREATE TABLE ' + q(APP) + '.notes (id serial PRIMARY KEY, body text)');
    await client.query('ALTER TABLE ' + q(APP) + '.notes ENABLE ROW LEVEL SECURITY');
    await client.query('GRANT SELECT, INSERT ON ' + q(APP) + '.notes TO anon, authenticated');
    // And one definer function anyone can call: a thing to verify, not a break.
    await client.query(
      'CREATE FUNCTION ' + q(APP) + '.peek() RETURNS bigint LANGUAGE sql SECURITY DEFINER ' +
        'SET search_path = pg_catalog AS $$ SELECT count(*) FROM ' + q(APP) + '.notes $$',
    );
    await client.query('GRANT EXECUTE ON FUNCTION ' + q(APP) + '.peek() TO anon');

    const first = run();
    check('1. a run whose only finding needs verification exits 0, not "something got through"', (() => {
      const problems = [];
      if (first.code !== 0) problems.push('exit ' + first.code);
      if (!/1 thing to check/.test(first.out)) problems.push('it does not say there is a thing to check');
      if (/problems? found/.test(first.out)) problems.push('it counted the unverified function as a found problem');
      if (!/peek/.test(first.out)) problems.push('the function is not named');
      if (problems.length) problems.push('output:\n' + first.out.slice(-1500));
      return problems;
    })());

    // The owner decides it should not be public and revokes it.
    await client.query('REVOKE EXECUTE ON FUNCTION ' + q(APP) + '.peek() FROM anon, PUBLIC');
    const second = run();
    check('2. the re-check through the real command calls the revoke fixed and still lists its limits', (() => {
      const problems = [];
      if (!/1 problem is fixed/.test(second.out)) problems.push('it did not confirm the revoke as fixed');
      if (/could NOT confirm/.test(second.out)) problems.push('the revoke came back as unconfirmed');
      if (!/What I did not test/.test(second.out)) problems.push('the re-check dropped the list of what it did not test');
      if (problems.length) problems.push('output:\n' + second.out.slice(-1500));
      return problems;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + q(APP) + ' CASCADE').catch(() => {});
    await client.end().catch(() => {});
    fs.rmSync(WORK, { recursive: true, force: true });
    fs.rmSync(HOME, { recursive: true, force: true });
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
  console.log('All ' + results.length + ' command-line checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
