// The whole loop, against a real database, through the real command.
// Run with:  node loop.check.js "<connection string>"
//
//   scan -> a real fix  -> re-check   must say fixed, and hand out the badge
//   scan -> a faked fix -> re-check   must refuse to say fixed
//
// The other check files are about one module at a time and need no database.
// This one is the opposite: nothing is stubbed, scan.js is shelled out to
// exactly as a person would run it, and the verdict is read out of what a
// person would actually see on screen.
//
// The second case is the one that matters. Dropping a table makes the finding
// disappear from the report in exactly the way a real fix does, and a re-check
// that cannot tell those apart is a re-check that will one day hand a badge to
// an app nobody secured.
const { Client } = require('pg');
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const schema = require('./schema.js');
const fixture = require('./fixture.js');

const HERE = __dirname;
const CONN = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};
const SAVED = path.join(HERE, '.kryptheon-last.json');

/** Runs scan.js the way a person does, and hands back what they would see. */
function cli(args) {
  // A preload is honoured only so this can run on a network that blocks 5432
  // outbound, where the driver has to reach Postgres over 443 instead. It
  // swaps the driver underneath and nothing else; every line being checked
  // here is the same one that runs in production.
  const before = process.env.KN_PRELOAD ? ['--require', process.env.KN_PRELOAD] : [];
  const r = spawnSync(process.execPath, before.concat([path.join(HERE, 'scan.js'), CONN], args), {
    cwd: HERE,
    encoding: 'utf8',
    timeout: 300000,
  });
  return { out: String(r.stdout || '') + String(r.stderr || ''), code: r.status };
}

/**
 * A small app, built the way people end up with one: two tables done right,
 * one rule that looks right and lets everybody through, and one table where
 * protection was never switched on at all.
 */
async function buildApp(client, app) {
  const q = (t) => schema.quote(app) + '.' + schema.quote(t);
  await client.query('CREATE SCHEMA ' + schema.quote(app));
  for (const role of ['anon', 'authenticated']) {
    await client.query(
      'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ' +
        "'" + role + "'" +
        ') THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(app) + ' TO ' + role);
  }
  undoAuth = await fixture.ensureAuth(client);

  // profiles is the table that was done properly: its policy is right and its
  // email is unique, so neither attack should have anything to say about it.
  await client.query(
    'CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY, email text NOT NULL UNIQUE, full_name text)',
  );
  await client.query(
    'CREATE TABLE ' + q('customers') +
      ' (id serial PRIMARY KEY, owner uuid NOT NULL, name text NOT NULL, email text NOT NULL, phone text)',
  );
  await client.query(
    'CREATE TABLE ' + q('integrations') +
      ' (id serial PRIMARY KEY, owner uuid NOT NULL, provider text NOT NULL, api_key text NOT NULL)',
  );
  for (const t of ['profiles', 'customers', 'integrations']) {
    await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
  }
  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY own_profile ON ' + q('profiles') + ' FOR SELECT TO authenticated USING (id = auth.uid())',
  );
  // Switched on, then handed to everyone. The dashboard calls this protected.
  await client.query('ALTER TABLE ' + q('customers') + ' ENABLE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY read_customers ON ' + q('customers') + ' FOR SELECT TO anon, authenticated USING (true)',
  );
  // integrations: never switched on at all, and it holds api_key.
}

const problems = [];
function must(condition, what) {
  if (!condition) problems.push(what);
  console.log((condition ? '  ok   ' : '  BAD  ') + what);
}

(async () => {
  if (!CONN) {
    console.error('');
    console.error('  node loop.check.js "<connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONN });
  await client.connect();

  /* ------------------------- 1: a real fix ------------------------- */
  const appA = 'loop_a_' + Date.now().toString(36);
  try {
    try { fs.unlinkSync(SAVED); } catch (err) { /* there was nothing saved */ }
    await buildApp(client, appA);

    console.log('');
    console.log('  --- first scan ---');
    const first = cli([appA]);
    must(first.code === 1, 'the first scan exits non-zero because it found problems');
    must(/customers/.test(first.out), 'it names the table with the rule that lets everyone through');
    must(/integrations/.test(first.out), 'it names the table with no protection at all');
    must(/access tokens/.test(first.out), 'it says an api_key column is access tokens');
    // Both attacks, through one command: the open door and the duplicate.
    must(/exist twice/.test(first.out), 'it ran the collision attack too, not only impersonation');
    must(!/profiles/.test(first.out), 'it reported the table that was done properly');
    must(fs.existsSync(SAVED), 'it saved the run so a re-check has something to compare against');
    const saved = JSON.parse(fs.readFileSync(SAVED, 'utf8'));
    must(saved.findings.length === 3, 'it saved 3 findings, got ' + saved.findings.length);
    must((saved.attempted || []).length > 0, 'it saved which attacks were actually run');
    must(
      (saved.attempted || []).some((key) => /^duplicated:/.test(key)),
      'it saved the collision attacks it ran, not only the impersonation ones',
    );

    // The person does what the pasted prompts told them to do.
    const q = (t) => schema.quote(appA) + '.' + schema.quote(t);
    await client.query('DROP POLICY read_customers ON ' + q('customers'));
    await client.query(
      'CREATE POLICY own_customers ON ' + q('customers') + ' FOR SELECT TO authenticated USING (owner = auth.uid())',
    );
    await client.query('ALTER TABLE ' + q('integrations') + ' ENABLE ROW LEVEL SECURITY');
    await client.query(
      'CREATE POLICY own_integrations ON ' + q('integrations') +
        ' FOR SELECT TO authenticated USING (owner = auth.uid())',
    );
    await client.query('ALTER TABLE ' + q('integrations') + ' ADD CONSTRAINT integrations_api_key_key UNIQUE (api_key)');

    console.log('');
    console.log('  --- re-check after a real fix ---');
    const again = cli([appA, '--recheck']);
    must(again.code === 0, 're-check exits 0 when everything is genuinely closed, got ' + again.code);
    must(/3 problems are fixed/.test(again.out), 'it says all three are fixed');
    must(/Kryptheon Verified/.test(again.out), 'it hands out the badge');
    must(!/could NOT confirm/.test(again.out), 'it does not hedge on a fix it proved');
    must(!/still open/.test(again.out), 'it does not report anything still open');
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(appA) + ' CASCADE');
  }

  /* ------------------------ 2: a faked fix ------------------------ */
  const appB = 'loop_b_' + Date.now().toString(36);
  try {
    try { fs.unlinkSync(SAVED); } catch (err) { /* cleared between apps */ }
    await buildApp(client, appB);

    console.log('');
    console.log('  --- first scan on a second app ---');
    const first = cli([appB]);
    must(first.code === 1, 'it found the same three problems');

    // One table genuinely fixed, the other one deleted rather than secured.
    const q = (t) => schema.quote(appB) + '.' + schema.quote(t);
    await client.query('DROP TABLE ' + q('integrations'));
    await client.query('DROP POLICY read_customers ON ' + q('customers'));
    await client.query(
      'CREATE POLICY own_customers ON ' + q('customers') + ' FOR SELECT TO authenticated USING (owner = auth.uid())',
    );

    console.log('');
    console.log('  --- re-check after a faked fix ---');
    const again = cli([appB, '--recheck']);
    must(again.code !== 0, 'a re-check it could not complete does not exit 0, got ' + again.code);
    must(/could NOT confirm/.test(again.out), 'it says it could not confirm');
    must(/integrations/.test(again.out), 'it names the table it could not confirm');
    must(!/Kryptheon Verified/.test(again.out), 'it withholds the badge');
    must(!/3 problems are fixed/.test(again.out), 'it does not count the dropped table as fixed');
    must(/1 problem is fixed/.test(again.out), 'it still credits the one real fix');
    // Two findings lived on that table - the open door and the duplicate
    // api_key - and dropping it confirms neither.
    must(/2 I could NOT confirm/.test(again.out), 'it does not account for both findings on the dropped table');
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(appB) + ' CASCADE');
    try { fs.unlinkSync(SAVED); } catch (err) { /* already gone */ }
    await undoAuth();
    await client.end();
  }

  console.log('');
  if (problems.length) {
    console.log(problems.length + ' thing(s) wrong.');
    process.exit(1);
  }
  console.log('The loop works end to end, on a real database, through the real command.');
})().catch((err) => {
  console.error('');
  console.error('  The loop check could not run: ' + (err.message || err.code || err));
  console.error('');
  process.exit(1);
});
