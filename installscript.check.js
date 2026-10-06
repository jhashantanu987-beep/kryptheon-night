// The install as one pasted SQL script must leave a database exactly as
// `npx kryptheon-night install` does - same functions, same job, same token
// kept the same way, same record for uninstall - because people who never
// open a terminal get the script, and uninstall reads what install wrote.
//
//   node installscript.check.js "<postgres connection string>"
//
// It makes three databases of its own on that server and drops them after.
// pg_cron and pg_net are Supabase's; a local Postgres has neither, so when
// the server is on this machine and offers neither, small stand-ins are put
// into its extension folder (a cron.job table and cron.schedule; a
// net.http_post that keeps what it is handed). They exist for these checks
// only. What they cannot show is the real pg_cron firing at three in the
// morning, or the real pg_net delivering - that was seen on Supabase itself.

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const fixture = require('./fixture.js');
const installer = require('./installer.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const TOKEN = 'kp_' + 'Q'.repeat(43);
const ENDPOINT = 'https://abcdefgh.supabase.co/functions/v1/ingest';
const SECRET = 'REAL-CUSTOMER-SECRET-' + STAMP;
const UTF8 = " ENCODING 'UTF8' TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'";

const results = [];
const check = (name, problems) => results.push({ name, problems });

const STANDINS = {
  'pg_cron.control': "comment = 'stand-in for pg_cron, for kryptheon-night checks only'\ndefault_version = '1.0'\nrelocatable = false\nsuperuser = true\n",
  'pg_cron--1.0.sql': [
    'CREATE SCHEMA cron;',
    'CREATE TABLE cron.job (jobid bigserial PRIMARY KEY, schedule text NOT NULL, command text NOT NULL, jobname text UNIQUE, active boolean NOT NULL DEFAULT true);',
    'CREATE FUNCTION cron.schedule(job_name text, schedule text, command text) RETURNS bigint LANGUAGE sql AS $$',
    '  INSERT INTO cron.job (jobname, schedule, command) VALUES ($1, $2, $3)',
    '  ON CONFLICT (jobname) DO UPDATE SET schedule = EXCLUDED.schedule, command = EXCLUDED.command RETURNING jobid $$;',
    'CREATE FUNCTION cron.unschedule(job_id bigint) RETURNS boolean LANGUAGE sql AS $$',
    '  WITH gone AS (DELETE FROM cron.job WHERE jobid = $1 RETURNING 1) SELECT count(*) > 0 FROM gone $$;',
    'CREATE FUNCTION cron.unschedule(job_name name) RETURNS boolean LANGUAGE sql AS $$',
    '  WITH gone AS (DELETE FROM cron.job WHERE jobname = $1 RETURNING 1) SELECT count(*) > 0 FROM gone $$;',
    '',
  ].join('\n'),
  'pg_net.control': "comment = 'stand-in for pg_net, for kryptheon-night checks only'\ndefault_version = '1.0'\nrelocatable = false\nsuperuser = true\n",
  'pg_net--1.0.sql': [
    'CREATE SCHEMA net;',
    'CREATE TABLE net.captured (id bigserial PRIMARY KEY, url text, body jsonb, headers jsonb, timeout int);',
    "CREATE FUNCTION net.http_post(url text, body jsonb DEFAULT '{}', params jsonb DEFAULT '{}', headers jsonb DEFAULT '{}', timeout_milliseconds int DEFAULT 5000)",
    '  RETURNS bigint LANGUAGE sql AS $$',
    '  INSERT INTO net.captured (url, body, headers, timeout) VALUES ($1, $2, $4, $5) RETURNING id $$;',
    '',
  ].join('\n'),
};

/** Stand-in pg_cron and pg_net, when the server is this machine's and has neither. */
async function standIns(client) {
  const { rows } = await client.query("SELECT name, default_version, comment FROM pg_available_extensions WHERE name IN ('pg_cron', 'pg_net')");
  const real = rows.filter((r) => !/kryptheon-night checks only/.test(r.comment || ''));
  if (real.length) return 'real';
  if (rows.length === 2) return 'stand-ins';
  const dir = (await client.query("SELECT setting FROM pg_config WHERE name = 'SHAREDIR'")).rows[0].setting;
  const ext = path.join(dir, 'extension');
  if (!fs.existsSync(ext)) return null;
  for (const [file, text] of Object.entries(STANDINS)) fs.writeFileSync(path.join(ext, file), text);
  return 'stand-ins';
}

async function freshDatabase(admin, name) {
  await admin.query('CREATE DATABASE ' + name + UTF8);
  const client = new Client({ connectionString: CONNECTION.replace(/\/[^/?]*(\?|$)/, '/' + name + '$1') });
  await client.connect();
  // Shaped like a new Supabase project, as far as the install cares.
  await fixture.ensureRoles(client, null, (n) => '"' + n + '"');
  await client.query('CREATE SCHEMA extensions');
  await client.query('GRANT USAGE ON SCHEMA public TO anon, authenticated');
  // The worst case for the token: every new table, in any schema, handed to
  // anon and authenticated by default. It must still be unreadable.
  await client.query('ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO anon, authenticated');
  for (const app of ['public', "app's"]) {
    const s = '"' + app.split('"').join('""') + '"';
    if (app !== 'public') {
      await client.query('CREATE SCHEMA ' + s);
      await client.query('GRANT USAGE ON SCHEMA ' + s + ' TO anon, authenticated');
    }
    await client.query('CREATE TABLE ' + s + '.notes (id serial PRIMARY KEY, body text NOT NULL)');
    await client.query('GRANT SELECT ON ' + s + '.notes TO anon, authenticated');
    await client.query('INSERT INTO ' + s + '.notes (body) VALUES ($1)', [SECRET]);
  }
  return client;
}

/** Everything an install leaves behind, in a form two databases can be compared by. */
async function picture(client) {
  const one = async (sql) => (await client.query(sql).catch((e) => ({ rows: [{ error: e.message }] }))).rows;
  return {
    extensions: await one("SELECT extname, n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE extname <> 'plpgsql' ORDER BY 1"),
    schemas: await one("SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema' ORDER BY 1"),
    functions: await one("SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args, md5(p.prosrc) AS body FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'kryptheon' ORDER BY 1, 2"),
    tables: await one("SELECT c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'kryptheon' AND c.relkind IN ('r', 'v') ORDER BY 1"),
    installed: await one('SELECT source, made_extensions, made_schema, jobid IS NOT NULL AS has_job FROM kryptheon.installed'),
    reporting: await one('SELECT endpoint, token, engine FROM kryptheon.reporting'),
    tokenReadable: await one("SELECT r.rolname, has_table_privilege(r.rolname, 'kryptheon.reporting', 'SELECT') AS can FROM pg_roles r WHERE r.rolname IN ('anon', 'authenticated') AND to_regclass('kryptheon.reporting') IS NOT NULL ORDER BY 1"),
    jobs: await one('SELECT jobname, schedule, command FROM cron.job ORDER BY 1'),
  };
}

function differences(a, b) {
  const out = [];
  for (const key of Object.keys(a)) {
    if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) {
      out.push(key + ': CLI ' + JSON.stringify(a[key]).slice(0, 220) + ' / script ' + JSON.stringify(b[key]).slice(0, 220));
    }
  }
  return out;
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node installscript.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const admin = new Client({ connectionString: CONNECTION });
  await admin.connect();
  const extensions = await standIns(admin);
  if (!extensions) {
    console.log('  This server offers neither pg_cron nor pg_net and is not on this machine, so nothing here can be checked.');
    await admin.end();
    process.exit(2);
  }
  const names = { cli: 'kn_is_cli_' + STAMP, script: 'kn_is_script_' + STAMP, refused: 'kn_is_refused_' + STAMP };
  const db = {};
  try {
    for (const [k, n] of Object.entries(names)) db[k] = await freshDatabase(admin, n);
    const engine = 'kryptheon-night ' + require('./package.json').version;

    // --- the template: three markers, each once, each inside one string -----
    const template = installer.installTemplate();
    check('the template carries each of its three markers exactly once, inside a SQL string', (() => {
      const p = [];
      for (const marker of Object.values(installer.SLOTS)) {
        const n = template.split(marker).length - 1;
        if (n !== 1) p.push(marker + ' appears ' + n + ' times');
        else if (template.indexOf("'" + marker + "'") === -1) p.push(marker + ' is not a whole SQL string');
      }
      if (/kp_[A-Za-z0-9_-]{20,}/.test(template)) p.push('a token is written into the template');
      return p;
    })());

    // --- with a token: the CLI's install and the pasted script, side by side --
    const blank = await picture(db.script);
    await installer.install(db.cli, { source: 'public', reportTo: { token: TOKEN, endpoint: ENDPOINT, engine: engine } });
    const pasted = installer.installScript({ source: 'public', reportTo: { token: TOKEN, endpoint: ENDPOINT } });
    const said = await db.script.query(pasted);
    const cli = await picture(db.cli);
    const script = await picture(db.script);
    const lastResult = [].concat(said).find((r) => r.rows && r.rows[0] && 'kryptheon' in r.rows[0]);
    check('with a token, the pasted script leaves the database exactly as the CLI install does', (() => {
      const p = differences(cli, script);
      if (!cli.functions.length) p.push('the CLI install made no functions, so the comparison shows nothing');
      if (!cli.jobs.length || !/nightly_and_report\('public'\)/.test(cli.jobs[0].command)) p.push('the CLI job is ' + JSON.stringify(cli.jobs));
      if (!(cli.installed[0] && cli.installed[0].made_extensions.length === 2)) p.push('the CLI did not record making both extensions: ' + JSON.stringify(cli.installed));
      return p;
    })());
    check('the token is kept where anon and authenticated cannot read it, and the script says what it did', (() => {
      const p = [];
      for (const r of script.tokenReadable) if (r.can) p.push(r.rolname + ' can read the token');
      if (script.tokenReadable.length !== 2) p.push('roles checked: ' + JSON.stringify(script.tokenReadable));
      const message = lastResult && lastResult.rows && lastResult.rows[0] && lastResult.rows[0].kryptheon;
      if (!/^Installed\. Kryptheon will check "public" every night .* sends your Kryptheon dashboard a summary/.test(message || '')) p.push('it said: ' + message);
      return p;
    })());

    // The job, run the way pg_cron runs it: the summary goes out, and no row does.
    await db.script.query(script.jobs[0].command);
    const sent = (await db.script.query('SELECT url, body, headers FROM net.captured')).rows;
    check('the job the script scheduled runs the night and sends only the summary', (() => {
      const p = [];
      if (sent.length !== 1) return [sent.length + ' requests sent'];
      if (sent[0].url !== ENDPOINT) p.push('sent to ' + sent[0].url);
      if (sent[0].headers.Authorization !== 'Bearer ' + TOKEN) p.push('not sent with the token');
      if (sent[0].body.engine !== engine) p.push('engine ' + sent[0].body.engine);
      const found = (sent[0].body.findings || []).map((f) => f.kind + ':' + f.table);
      if (!found.includes('exposed:notes')) p.push('findings ' + JSON.stringify(found));
      if (JSON.stringify(sent).includes(SECRET)) p.push('a row of the app\'s data was sent');
      return p;
    })());

    // --- run again: nothing doubles ------------------------------------------
    await db.script.query(pasted);
    const again = await picture(db.script);
    check('running the script a second time changes nothing', differences(script, again));

    // --- without a token, over the top of one ---------------------------------
    await installer.install(db.cli, { source: "app's" });
    await db.script.query(installer.installScript({ source: "app's" }));
    const cliPlain = await picture(db.cli);
    const scriptPlain = await picture(db.script);
    check('without a token, over an install that had one: the token is gone and the job sends nothing - as the CLI does', (() => {
      const p = differences(cliPlain, scriptPlain);
      if (!/reporting/.test(JSON.stringify(scriptPlain.reporting))) p.push('a reporting table is still there: ' + JSON.stringify(scriptPlain.reporting));
      if (!scriptPlain.jobs.length || scriptPlain.jobs[0].command !== 'SELECT "kryptheon".nightly(\'app\'\'s\')') p.push('job ' + JSON.stringify(scriptPlain.jobs));
      return p;
    })());
    await db.script.query('DELETE FROM net.captured');
    await db.script.query(scriptPlain.jobs[0].command);
    const quiet = (await db.script.query('SELECT count(*)::int AS n FROM net.captured')).rows[0].n;
    // Whether that night finishes is the engine's business (a quote in a schema
    // name trips its copy guard today); what is checked here is that the job
    // the script wrote calls the night on the schema it was given.
    const ran = (await db.script.query('SELECT source FROM kryptheon.runs ORDER BY id DESC LIMIT 1')).rows[0] || {};
    check('that job runs the night on the schema named, and sends nothing', (() => {
      const p = [];
      if (quiet) p.push(quiet + ' requests sent');
      if (ran.source !== "app's") p.push('the last night was for ' + JSON.stringify(ran.source));
      return p;
    })());

    // --- uninstall reads what the script wrote --------------------------------
    const removed = await installer.uninstall(db.script);
    const after = await picture(db.script);
    check('npx kryptheon-night uninstall takes back everything the script made, and only that', (() => {
      const p = differences(blank, after);
      if (!removed.job || !removed.schema) p.push('removed ' + JSON.stringify(removed));
      if ((removed.extensions || []).sort().join() !== 'pg_cron,pg_net') p.push('extensions removed: ' + JSON.stringify(removed.extensions));
      return p;
    })());

    // --- the pasted uninstall -------------------------------------------------
    await db.script.query(pasted);
    await db.script.query(installer.uninstallScript());
    const afterScript = await picture(db.script);
    await db.cli.query(installer.uninstallScript());
    const afterCli = await picture(db.cli);
    check('the pasted uninstall takes back an install made either way, and leaves the database as it was', (() => {
      const p = differences(blank, afterScript).map((d) => 'script install: ' + d);
      // The CLI database started from the same blank shape.
      return p.concat(differences(blank, afterCli).map((d) => 'CLI install: ' + d));
    })());
    let twice = 'it ran';
    try {
      await db.script.query(installer.uninstallScript());
    } catch (err) {
      twice = err.message;
    }
    check('the pasted uninstall on a database without Kryptheon changes nothing and does not fail', (() => {
      const p = differences(blank, afterScript);
      if (twice !== 'it ran') p.push('it failed: ' + twice);
      return p;
    })());

    // Only what it made: a pg_cron that was here first stays, with its own jobs.
    await db.refused.query('CREATE EXTENSION pg_cron');
    await db.refused.query("SELECT cron.schedule('theirs', '0 1 * * *', 'SELECT 1')");
    const theirs = await picture(db.refused);
    await db.refused.query(installer.installScript({}));
    await db.refused.query(installer.uninstallScript());
    const kept = await picture(db.refused);
    check('a pg_cron that was there before stays, with its own job; only pg_net, which Kryptheon added, goes', differences(theirs, kept));
    await db.refused.query("SELECT cron.unschedule('theirs'::name)");
    await db.refused.query('DROP EXTENSION pg_cron');

    // --- refused before anything is made ---------------------------------------
    const before = await picture(db.refused);
    const refusals = [];
    for (const [what, token, endpoint] of [
      ['a token that is not one', 'hello', ENDPOINT],
      ['an http address', TOKEN, ENDPOINT.replace('https', 'http')],
      ['an address that is not the ingest function', TOKEN, 'https://abcdefgh.supabase.co/rest/v1/runs'],
      ['a token with no address', TOKEN, ''],
    ]) {
      // Filled the way a page fills it, past the Node-side check.
      let sql = installer.installTemplate();
      sql = sql.replace(installer.SLOTS.source, () => 'public').replace(installer.SLOTS.token, () => token).replace(installer.SLOTS.endpoint, () => endpoint);
      try {
        await db.refused.query(sql);
        refusals.push(what + ' was installed');
      } catch (err) {
        if (!/^Kryptheon: /.test(err.message)) refusals.push(what + ' failed with: ' + err.message);
      }
    }
    let nodeSide = 'it made a script';
    try {
      installer.installScript({ reportTo: { token: 'hello', endpoint: ENDPOINT } });
    } catch (err) {
      nodeSide = err.message;
    }
    if (!/not a project token/.test(nodeSide)) refusals.push('installScript with a bad token: ' + nodeSide);
    const untouched = await picture(db.refused);
    check('a bad token or address is refused in plain words before anything is made', refusals.concat(differences(before, untouched)));
  } finally {
    for (const c of Object.values(db)) await c.end().catch(() => {});
    for (const n of Object.values(names)) await admin.query('DROP DATABASE IF EXISTS ' + n + ' WITH (FORCE)').catch(() => {});
    await admin.end();
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
  console.log('All ' + results.length + ' install-script checks passed (pg_cron and pg_net: ' + extensions + ').');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.stack);
  process.exit(1);
});
