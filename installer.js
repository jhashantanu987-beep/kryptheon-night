// The second door: the engine stays put, and pg_cron calls it at night.
//
// Down `npx` the engine is installed into a throwaway schema, used, and
// dropped inside one command - the connection string never leaves the
// person's machine, but they have to run it. This door is for the thing they
// will not do every week. The same functions are installed once, pg_cron runs
// `nightly()` at three in the morning, and nothing about it needs a
// credential to move anywhere, because nothing moves: the work happens where
// the data already is.
//
// Everything here is written around one rule, and it is the rule fixture.js
// learned the expensive way: **only remove what you created**. A database
// that already had pg_cron in it before Kryptheon arrived must still have it
// afterwards, and a customer who removes Kryptheon must not be left with a
// nightly job nobody owns. So install writes down what it made, in a table
// inside its own schema, and uninstall reads that list before it drops
// anything.
//
// Measured on a real Supabase project before any of this was written:
//
//   pg_net lands in `public` - the customer's own schema - unless it is told
//     where to go, so it is always told.
//   cron.unschedule is overloaded on (bigint) and (name), and an uncast
//     parameter binds to the name one and fails with "could not find valid
//     entry for job", which reads like the job was already gone.

const sqlengine = require('./sqlengine.js');

// Where the engine lives when it is staying. A fixed name rather than a
// timestamped one: the throwaway copies are named for the moment they were
// made so an abandoned one can be aged and swept, and this is the opposite -
// it is meant to be found again.
const SCHEMA = 'kryptheon';

// Three in the morning, in whatever the database thinks the time is. Late
// enough to be quiet, early enough that the answer is waiting before anybody
// looks.
const AT = '0 3 * * *';

const quote = (name) => '"' + String(name).split('"').join('""') + '"';

/** Is this extension already here, and did we have to put it here? */
async function extensionState(client, name) {
  const { rows } = await client.query(
    'SELECT installed_version FROM pg_available_extensions WHERE name = $1', [name],
  );
  if (!rows.length) return { available: false, installed: false };
  return { available: true, installed: Boolean(rows[0].installed_version) };
}

/**
 * Puts an extension where it belongs, and says whether it had to.
 *
 * `pg_net` installs into whatever the search_path says unless it is told
 * otherwise, and on Supabase that is `public`. Watching it appear in a
 * customer's own schema is what made this function exist rather than a line
 * of SQL.
 */
async function ensureExtension(client, name, into) {
  const state = await extensionState(client, name);
  if (!state.available) {
    throw new Error(
      'this database does not offer ' + name + ', so the nightly run cannot be installed. ' +
      'Supabase has it; a plain Postgres may not.',
    );
  }
  if (state.installed) return { made: false };

  const haveSchema = into
    ? (await client.query('SELECT count(*)::int n FROM pg_namespace WHERE nspname = $1', [into])).rows[0].n > 0
    : false;
  await client.query('CREATE EXTENSION ' + name + (haveSchema ? ' WITH SCHEMA ' + quote(into) : ''));
  return { made: true, into: haveSchema ? into : null };
}

/**
 * Installs the engine, schedules the night, and writes down what it made.
 *
 * Safe to run twice: the engine is CREATE OR REPLACE throughout, and the job
 * is replaced rather than added to, so an upgrade is the same operation as an
 * install.
 */
async function install(client, options) {
  const opts = options || {};
  const schema = opts.schema || SCHEMA;
  const source = opts.source || 'public';
  const at = opts.at || AT;
  const made = { extensions: [], schema: false, jobid: null };

  // A bad project token is refused here, before anything is made, for the
  // same reason as the extensions below.
  if (opts.reportTo) checkReportTo(opts.reportTo);

  // Both asked about before either is made. pg_net used to be created first
  // and pg_cron checked after, so a database offering one and not the other
  // kept a pg_net nobody recorded - and uninstall only removes what the
  // record names. Nothing is created until everything needed is there.
  for (const name of ['pg_net', 'pg_cron']) {
    if (!(await extensionState(client, name)).available) {
      const err = new Error(
        'this database does not offer ' + name + ', so the nightly run cannot be installed. ' +
        'Supabase has it; a plain Postgres may not.',
      );
      err.missingExtension = name;
      throw err;
    }
  }

  // pg_net first: it is the one that lands in the wrong place if nobody
  // says where, and it is easier to take back out before anything depends
  // on it.
  const net = await ensureExtension(client, 'pg_net', 'extensions');
  if (net.made) made.extensions.push('pg_net');

  const cron = await ensureExtension(client, 'pg_cron', null);
  if (cron.made) made.extensions.push('pg_cron');

  const existed = (await client.query(
    'SELECT count(*)::int n FROM pg_namespace WHERE nspname = $1', [schema],
  )).rows[0].n > 0;
  made.schema = !existed;

  await sqlengine.install(client, schema);

  // What this install created, kept where uninstall can find it and nowhere
  // else. In the schema it is about to drop, on purpose: if the schema is
  // gone, so is everything this list describes.
  await client.query(
    'CREATE TABLE IF NOT EXISTS ' + quote(schema) + '.installed (' +
      'id integer PRIMARY KEY DEFAULT 1, ' +
      'installed_at timestamptz NOT NULL DEFAULT now(), ' +
      'source text NOT NULL, ' +
      'made_extensions text[] NOT NULL DEFAULT \'{}\', ' +
      'made_schema boolean NOT NULL DEFAULT false, ' +
      'jobid bigint, ' +
      'CONSTRAINT only_one CHECK (id = 1))',
  );

  // The nightly summary, only if a project token was given.
  const reporting = await configureReporting(client, schema, opts.reportTo || null);

  // Replaced rather than added to. cron.schedule with a name that already
  // exists updates it, but an install that ran twice under two names would
  // attack the same app twice a night for ever.
  const { rows } = await client.query(
    'SELECT cron.schedule($1, $2, $3) AS jobid',
    ['kryptheon_nightly', at, jobCommand(schema, source, reporting)],
  );
  made.jobid = rows[0].jobid;

  await client.query(
    'INSERT INTO ' + quote(schema) + '.installed (id, source, made_extensions, made_schema, jobid) ' +
      'VALUES (1, $1, $2, $3, $4) ' +
      'ON CONFLICT (id) DO UPDATE SET source = EXCLUDED.source, jobid = EXCLUDED.jobid, ' +
      'made_extensions = ' + quote(schema) + '.installed.made_extensions || EXCLUDED.made_extensions, ' +
      'installed_at = now()',
    [source, made.extensions, made.schema, made.jobid],
  );

  return { schema: schema, source: source, at: at, jobid: made.jobid, made: made, reporting: reporting };
}

/** What the scheduled job runs: the night, and the summary only if one was asked for. */
function jobCommand(schema, source, reporting) {
  return 'SELECT ' + quote(schema) + '.' + (reporting ? 'nightly_and_report' : 'nightly') + '(' + literal(source) + ')';
}

// A project token from kryptheon.tech, and the one address it may be sent to.
const TOKEN = /^kp_[A-Za-z0-9_-]{20,100}$/;
const ENDPOINT = /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)+(:443)?\/functions\/v1\/ingest$/i;

/** Throws, in words a person can act on, unless this is a token and an address it may go to. */
function checkReportTo(reportTo) {
  if (!TOKEN.test(String(reportTo.token || ''))) {
    throw new Error('that is not a project token - copy it again from your dashboard on kryptheon.tech');
  }
  if (!ENDPOINT.test(String(reportTo.endpoint || ''))) {
    throw new Error('the report address has to be an https address ending in /functions/v1/ingest');
  }
}

/**
 * Keeps the project token where the nightly job can read it and nobody else
 * can, or takes it away when none is given - so an install without one sends
 * nothing, even if an earlier install was given one.
 *
 * In a table of the engine's own schema, readable by its owner only: anon and
 * authenticated - the roles a Supabase API call runs as - get nothing, so the
 * token never reaches the app's API even if the schema were exposed.
 */
async function configureReporting(client, schema, reportTo) {
  const table = quote(schema) + '.reporting';
  if (!reportTo) {
    await client.query('DROP TABLE IF EXISTS ' + table);
    return null;
  }
  checkReportTo(reportTo);
  await client.query(
    'CREATE TABLE IF NOT EXISTS ' + table + ' (' +
      'id integer PRIMARY KEY DEFAULT 1, endpoint text NOT NULL, token text NOT NULL, engine text, ' +
      'CONSTRAINT only_one CHECK (id = 1))',
  );
  await client.query('REVOKE ALL ON ' + table + ' FROM PUBLIC');
  for (const role of ['anon', 'authenticated']) {
    const { rows } = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role]);
    if (rows.length) await client.query('REVOKE ALL ON ' + table + ' FROM ' + role);
  }
  await client.query(
    'INSERT INTO ' + table + ' (id, endpoint, token, engine) VALUES (1, $1, $2, $3) ' +
      'ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, token = EXCLUDED.token, engine = EXCLUDED.engine',
    [reportTo.endpoint, reportTo.token, reportTo.engine || null],
  );
  return { endpoint: reportTo.endpoint };
}

/** A string, quoted the way Postgres wants it inside another statement. */
function literal(text) {
  return "'" + String(text).split("'").join("''") + "'";
}

/** What is installed, or null. */
async function status(client, options) {
  const schema = (options || {}).schema || SCHEMA;
  const here = (await client.query(
    'SELECT count(*)::int n FROM pg_namespace WHERE nspname = $1', [schema],
  )).rows[0].n > 0;
  if (!here) return null;

  const { rows } = await client.query(
    'SELECT source, installed_at, jobid, made_extensions, made_schema FROM ' +
      quote(schema) + '.installed WHERE id = 1',
  ).catch(() => ({ rows: [] }));
  if (!rows.length) return { schema: schema, source: null, jobid: null, unrecorded: true };

  const job = await client.query(
    'SELECT jobname, schedule, active FROM cron.job WHERE jobid = $1', [rows[0].jobid],
  ).catch(() => ({ rows: [] }));

  return Object.assign({ schema: schema }, rows[0], { job: job.rows[0] || null });
}

/**
 * Takes it all away, and only what was put here.
 *
 * The order matters. The job goes first, because a job whose function has
 * been dropped runs every night and fails every night, and pg_cron keeps
 * every one of those failures in a log nobody reads.
 */
async function uninstall(client, options) {
  const schema = (options || {}).schema || SCHEMA;
  const removed = { job: false, schema: false, extensions: [] };

  const was = await status(client, { schema: schema });
  if (!was) return removed;

  if (was.jobid) {
    // Cast on purpose. cron.unschedule is overloaded on (bigint) and (name),
    // and a parameter sent as text binds to the name overload and goes
    // looking for a job CALLED '1'. It fails with "could not find valid entry
    // for job", which reads exactly like the job having already gone - so the
    // uninstall would have reported success and left the job running.
    await client.query('SELECT cron.unschedule($1::bigint)', [was.jobid]).catch(() => {});
    const left = await client.query(
      'SELECT count(*)::int n FROM cron.job WHERE jobid = $1', [was.jobid],
    ).catch(() => ({ rows: [{ n: 0 }] }));
    if (left.rows[0].n) {
      throw new Error('the nightly job ' + was.jobid + ' is still scheduled, so nothing else was removed');
    }
    removed.job = true;
  }

  if (was.made_schema !== false) {
    await client.query('DROP SCHEMA IF EXISTS ' + quote(schema) + ' CASCADE');
    removed.schema = true;
  } else {
    // The schema was somebody else's before we arrived. Take the engine's own
    // things out of it and leave the schema itself where it was.
    await sqlengine.uninstall(client, schema).catch(() => {});
  }

  // Extensions last, and only ours. A database that had pg_cron before
  // Kryptheon arrived must still have it afterwards - and dropping pg_cron
  // would take every other job in it with it.
  for (const ext of was.made_extensions || []) {
    await client.query('DROP EXTENSION IF EXISTS ' + ext).catch(() => {});
    removed.extensions.push(ext);
  }

  return removed;
}

/**
 * What the nightly run last said, read out of the database: whether it is
 * installed at all, how it is scheduled, and its newest row in runs - or null
 * for a run that has not happened yet. Read only.
 */
async function latestRun(client, options) {
  const where = await status(client, options);
  if (!where) return { installed: false, where: null, run: null };
  const { rows } = await client.query(
    'SELECT ran_at, source, stopped, attacks_run, findings, not_checked FROM ' +
      quote(where.schema) + '.runs ORDER BY ran_at DESC, id DESC LIMIT 1',
  );
  return { installed: true, where: where, run: rows[0] || null };
}

module.exports = {
  SCHEMA: SCHEMA,
  latestRun: latestRun,
  AT: AT,
  install: install,
  uninstall: uninstall,
  status: status,
  extensionState: extensionState,
  configureReporting: configureReporting,
  jobCommand: jobCommand,
};
