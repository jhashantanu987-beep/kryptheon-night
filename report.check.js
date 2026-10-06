// Checks the nightly summary for Pro and Studio: it is sent only when a
// project token was given, it goes only where it was told, and it carries the
// kind and the table of each finding - never a row, a value or a column list.
//
//   node report.check.js "<postgres connection string>"
//
// There is no pg_net here, so a stand-in net.http_post keeps every request it
// is handed in a table, and the check reads exactly what would have been sent.
// What it cannot show is pg_net itself delivering it: that is Supabase's part.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const installer = require('./installer.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_report_' + STAMP;
const ENGINE = 'kn_engine_report_' + STAMP;
const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
const WHO = "nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid";
const TOKEN = 'kp_' + 'T'.repeat(43);
const ENDPOINT = 'https://abcdefgh.supabase.co/functions/v1/ingest';
// A row of the customer's own, which the night never reads and must never send.
const SECRET = 'REAL-CUSTOMER-SECRET-' + STAMP;

const results = [];
const check = (name, problems) => results.push({ name, problems });

async function build(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(APP));
  await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
  // No row level security at all: anyone can read it.
  await client.query('CREATE TABLE ' + q('notes') + ' (id serial PRIMARY KEY, body text NOT NULL)');
  await client.query('GRANT SELECT ON ' + q('notes') + ' TO anon, authenticated');
  // Switched on, then opened to every customer.
  await client.query('CREATE TABLE ' + q('orders') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL, card text NOT NULL)');
  await client.query('GRANT SELECT ON ' + q('orders') + ' TO anon, authenticated');
  await client.query('ALTER TABLE ' + q('orders') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY everyone ON ' + q('orders') + ' FOR SELECT TO authenticated USING (true)');
  // One email each: a race the night cannot run from inside, so it is "not tested".
  await client.query('CREATE TABLE ' + q('accounts') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL DEFAULT ' + WHO + ', email text NOT NULL UNIQUE)');
  await client.query('GRANT SELECT, INSERT ON ' + q('accounts') + ' TO authenticated');
  await client.query('GRANT USAGE ON ALL SEQUENCES IN SCHEMA ' + schema.quote(APP) + ' TO authenticated');
  await client.query('ALTER TABLE ' + q('accounts') + ' ENABLE ROW LEVEL SECURITY');
  await client.query('CREATE POLICY own_read ON ' + q('accounts') + ' FOR SELECT TO authenticated USING (user_id = ' + WHO + ')');
  await client.query('CREATE POLICY own_add ON ' + q('accounts') + ' FOR INSERT TO authenticated WITH CHECK (user_id = ' + WHO + ')');
  await client.query('INSERT INTO ' + q('notes') + ' (body) VALUES ($1)', [SECRET]);
  await client.query('INSERT INTO ' + q('orders') + ' (user_id, card) VALUES ($1, $2)', ['00000000-0000-4000-8000-000000000001', SECRET]);
}

// Standing in for pg_net: the same call, with what it was handed kept.
async function standInNet(client, failing) {
  await client.query('CREATE SCHEMA IF NOT EXISTS net');
  await client.query('CREATE TABLE IF NOT EXISTS net.captured (id bigserial PRIMARY KEY, url text, body jsonb, headers jsonb, timeout int)');
  await client.query(
    'CREATE OR REPLACE FUNCTION net.http_post(url text, body jsonb DEFAULT \'{}\', params jsonb DEFAULT \'{}\', ' +
      'headers jsonb DEFAULT \'{}\', timeout_milliseconds int DEFAULT 5000) RETURNS bigint LANGUAGE plpgsql AS $$ ' +
      'DECLARE id bigint; BEGIN ' +
      (failing ? "RAISE EXCEPTION 'the network is down'; " : '') +
      'INSERT INTO net.captured (url, body, headers, timeout) VALUES (url, body, headers, timeout_milliseconds) RETURNING net.captured.id INTO id; ' +
      'RETURN id; END $$',
  );
}

// The very statement the scheduled job is given, run by hand - or, with
// 'always', the reporting night itself whatever was asked for.
async function night(client, reporting) {
  const command = reporting === 'always'
    ? 'SELECT ' + schema.quote(ENGINE) + ".nightly_and_report('" + APP + "')"
    : installer.jobCommand(ENGINE, APP, reporting);
  const { rows } = await client.query(command + ' AS id');
  const run = (await client.query('SELECT * FROM ' + schema.quote(ENGINE) + '.runs WHERE id = $1', [rows[0].id])).rows[0];
  const captured = (await client.query('SELECT * FROM net.captured ORDER BY id')).rows;
  await client.query('DELETE FROM net.captured');
  return { run: run, captured: captured };
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node report.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  const { rows: hadNet } = await client.query("SELECT 1 FROM pg_namespace WHERE nspname = 'net'");
  if (hadNet.length) {
    console.log('  This database has a net schema of its own (pg_net?), so the stand-in is not put in.');
    await client.end();
    process.exit(2);
  }
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await build(client);
    await sqlengine.install(client, ENGINE);
    await standInNet(client, false);

    // --- no token: nothing is sent ----------------------------------------
    const quiet = await night(client, null);
    const quietAnyway = await night(client, 'always');
    check('with no project token, the night is recorded and nothing is sent', (() => {
      const p = [];
      if (!quiet.run || quiet.run.stopped) p.push('the night did not run: ' + (quiet.run && quiet.run.stopped));
      if (quiet.captured.length) p.push(quiet.captured.length + ' requests sent');
      if (!/\.nightly\(/.test(installer.jobCommand(ENGINE, APP, null))) p.push('the job is not the plain night');
      if (quietAnyway.captured.length) p.push('the reporting night sent ' + quietAnyway.captured.length + ' with no token kept');
      return p;
    })());

    // --- refused set-ups --------------------------------------------------
    const refusals = [];
    for (const [what, reportTo] of [
      ['a token that is not one', { token: 'hello', endpoint: ENDPOINT }],
      ['an http address', { token: TOKEN, endpoint: ENDPOINT.replace('https', 'http') }],
      ['an address that is not the ingest function', { token: TOKEN, endpoint: 'https://abcdefgh.supabase.co/rest/v1/runs' }],
      ['an address with a path after it', { token: TOKEN, endpoint: ENDPOINT + '/../x' }],
    ]) {
      try {
        await installer.configureReporting(client, ENGINE, reportTo);
        refusals.push(what + ' was accepted');
      } catch (err) {
        /* refused, as it should be */
      }
    }
    // And through install itself: the token is looked at before anything is made.
    const UNMADE = ENGINE + '_unmade';
    let installSaid = 'it installed';
    try {
      await installer.install(client, { schema: UNMADE, source: APP, reportTo: { token: 'hello', endpoint: ENDPOINT } });
    } catch (err) {
      installSaid = err.message;
    }
    const unmade = (await client.query('SELECT count(*)::int n FROM pg_namespace WHERE nspname = $1', [UNMADE])).rows[0].n;
    if (!/not a project token/.test(installSaid)) refusals.push('install with a bad token said: ' + installSaid);
    if (unmade) refusals.push('install with a bad token made its schema first');
    const tableAfterRefusals = (await client.query("SELECT to_regclass($1) AS t", [ENGINE + '.reporting'])).rows[0].t;
    check('a bad token or a bad address is refused at install, and nothing is kept', (() => {
      const p = refusals.slice();
      if (tableAfterRefusals) p.push('a reporting table was left behind');
      return p;
    })());

    // --- with a token -----------------------------------------------------
    // The worst case for the token: the engine's schema exposed to the API,
    // and every new table in it handed to anon and authenticated by default -
    // what Supabase does for public. It must still be unreadable.
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(ENGINE) + ' TO anon, authenticated');
    await client.query('ALTER DEFAULT PRIVILEGES IN SCHEMA ' + schema.quote(ENGINE) + ' GRANT ALL ON TABLES TO anon, authenticated');
    const reporting = await installer.configureReporting(client, ENGINE, { token: TOKEN, endpoint: ENDPOINT, engine: 'kryptheon-night 9.9.9' });
    const sent = await night(client, reporting);
    const req = sent.captured[0] || {};
    const body = req.body || {};
    const text = JSON.stringify(req);
    check('with a token, one request goes to the address given, carrying the token', (() => {
      const p = [];
      if (sent.captured.length !== 1) p.push(sent.captured.length + ' requests');
      if (req.url !== ENDPOINT) p.push('sent to ' + req.url);
      if (!req.headers || req.headers.Authorization !== 'Bearer ' + TOKEN) p.push('headers ' + JSON.stringify(req.headers));
      if (!req.headers || req.headers['Content-Type'] !== 'application/json') p.push('no JSON content type');
      return p;
    })());
    check('what is sent is the night\'s findings, by kind and table, and its counts', (() => {
      const p = [];
      if (body.format !== 1) p.push('format ' + body.format);
      if (body.engine !== 'kryptheon-night 9.9.9') p.push('engine ' + body.engine);
      const said = (body.findings || []).map((f) => f.kind + ':' + f.table).sort();
      const found = (sent.run.findings || []).map((f) => f.kind + ':' + (f.table || 'unknown')).sort();
      if (JSON.stringify(said) !== JSON.stringify(found)) p.push('sent ' + JSON.stringify(said) + ', found ' + JSON.stringify(found));
      if (!said.includes('exposed:notes') || !said.some((k) => /:orders$/.test(k))) p.push('the two holes are not in it: ' + JSON.stringify(said));
      if (body.not_tested !== (sent.run.not_checked || []).length) p.push('not_tested ' + body.not_tested);
      if (!(body.not_tested > 0)) p.push('the accounts.email race is not counted as not tested');
      if (body.stopped !== false) p.push('a finished night sent as stopped: ' + body.stopped);
      if (body.attacks_run !== sent.run.attacks_run) p.push('attacks_run ' + body.attacks_run);
      return p;
    })());
    check('and nothing else: no row, no value, no column list, no error text, no connection string', (() => {
      const p = [];
      if (text.includes(SECRET)) p.push('a row of the customer\'s data was sent');
      const keys = new Set((body.findings || []).flatMap((f) => Object.keys(f)));
      for (const k of keys) if (!['kind', 'table', 'column'].includes(k)) p.push('a finding carries "' + k + '"');
      const top = Object.keys(body).sort().join(',');
      if (top !== 'attacks_run,engine,findings,format,not_tested,ran_at,stopped') p.push('top-level keys ' + top);
      if (/card|body/.test(JSON.stringify(body.findings))) p.push('a column name of the app was sent');
      if (/postgres(ql)?:\/\//.test(text)) p.push('a connection string was sent');
      return p;
    })());

    // --- a night that stopped ----------------------------------------------
    // Said as stopped, so the dashboard never shows it as all clear - and the
    // reason is not sent, since it is error text and can quote the schema.
    const REASON = 'could not copy ' + APP + '.accounts';
    await client.query('UPDATE ' + schema.quote(ENGINE) + '.runs SET stopped = $2 WHERE id = $1', [sent.run.id, REASON]);
    const halted = (await client.query('SELECT ' + schema.quote(ENGINE) + '.report_body($1, null) AS b', [sent.run.id])).rows[0].b;
    check('a night that stopped is sent as stopped, without the reason', (() => {
      const p = [];
      if (halted.stopped !== true) p.push('stopped is ' + JSON.stringify(halted.stopped));
      if (JSON.stringify(halted).includes(REASON)) p.push('the reason was sent');
      return p;
    })());

    // --- who can read the token -------------------------------------------
    const reads = {};
    for (const role of ['anon', 'authenticated']) {
      await client.query('BEGIN');
      try {
        await client.query('SET LOCAL ROLE ' + role);
        await client.query('SELECT token FROM ' + schema.quote(ENGINE) + '.reporting');
        reads[role] = 'read it';
      } catch (err) {
        reads[role] = err.message;
      } finally {
        await client.query('ROLLBACK');
      }
    }
    check('the project token cannot be read by anon or authenticated - the roles the app\'s API runs as', (() => {
      const p = [];
      for (const [role, got] of Object.entries(reads)) if (!/permission denied/.test(got)) p.push(role + ': ' + got);
      return p;
    })());

    // --- a network that fails ---------------------------------------------
    await standInNet(client, true);
    const down = await night(client, reporting);
    check('when sending fails, the night is still recorded', (() => {
      const p = [];
      if (!down.run || down.run.stopped) p.push('the night was lost: ' + (down.run && down.run.stopped));
      if (down.captured.length) p.push('something was captured');
      return p;
    })());

    // --- taking the token away ---------------------------------------------
    await standInNet(client, false);
    const none = await installer.configureReporting(client, ENGINE, null);
    // The job an old install left behind still asks for a report: it must find no token.
    const after = await night(client, 'always');
    const afterJob = installer.jobCommand(ENGINE, APP, none);
    const gone = (await client.query('SELECT to_regclass($1) AS t', [ENGINE + '.reporting'])).rows[0].t;
    check('installing again without a token takes it away, and the night sends nothing', (() => {
      const p = [];
      if (gone) p.push('the token is still kept');
      if (/\.nightly_and_report\(/.test(afterJob)) p.push('the job would still be the reporting one: ' + afterJob);
      if (after.captured.length) p.push(after.captured.length + ' requests sent');
      return p;
    })());
  } finally {
    await client.query('DROP SCHEMA IF EXISTS net CASCADE').catch(() => {});
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(ENGINE) + ' CASCADE').catch(() => {});
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
  console.log('All ' + results.length + ' report checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
