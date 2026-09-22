// Can Slice 5 be built here at all, and what does building it cost the
// customer's database?
//
//   KN_DATABASE_URL=postgresql://...  node probe-installer.js
//
// The installer is the second door: the engine's functions stay put, pg_cron
// calls them nightly, and pg_net posts a verdict - so no credential ever
// moves. None of that has been run against anything until now; STATE.md said
// Supabase has the extensions and said it from documentation.
//
// Measured already: on a real Supabase project both extensions exist and the
// `postgres` role can create and drop them without being superuser. And
// pg_net lands in `public` - the customer's own schema - unless it is told
// where to go. That is the sort of thing this whole product exists to object
// to, so it is the first thing checked here.
//
// Everything created is removed again. What this prints is a feasibility
// report, not an installation.

const { Client } = require('pg');
const { howToConnect } = require('./connect.js');

const say = (text) => console.log('  ' + text);

async function main() {
  if (!process.env.KN_DATABASE_URL) {
    console.error('  KN_DATABASE_URL=postgresql://...  node probe-installer.js');
    process.exit(2);
  }
  const client = new Client(howToConnect(process.env.KN_DATABASE_URL));
  await client.connect();

  const installed = async (ext) => {
    const { rows } = await client.query(
      'SELECT installed_version FROM pg_available_extensions WHERE name = $1', [ext],
    );
    return rows.length ? rows[0].installed_version : null;
  };
  const publicFunctions = async () => {
    const { rows } = await client.query(
      `SELECT count(*)::int n FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
        WHERE ns.nspname = 'public'`,
    );
    return rows[0].n;
  };

  const madeHere = [];
  try {
    say('user: ' + (await client.query('SELECT current_user')).rows[0].current_user);
    const before = await publicFunctions();
    say('functions in the customer’s public schema, before: ' + before);
    say('');

    /* ---- 1. where pg_net can be put ---- */
    const hasExtensionsSchema = (await client.query(
      "SELECT count(*)::int n FROM pg_namespace WHERE nspname = 'extensions'",
    )).rows[0].n > 0;
    say('a schema called "extensions" exists: ' + hasExtensionsSchema);

    if (!(await installed('pg_net'))) {
      const into = hasExtensionsSchema ? 'extensions' : null;
      try {
        await client.query('CREATE EXTENSION pg_net' + (into ? ' WITH SCHEMA ' + into : ''));
        madeHere.push('pg_net');
        const where = (await client.query(
          'SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = $1',
          ['pg_net'],
        )).rows[0].nspname;
        say('pg_net installed into "' + where + '"' +
          (where === 'public' ? '   <-- the customer’s own schema' : ''));
        const after = await publicFunctions();
        say('functions in public now: ' + after + (after === before ? '   (unchanged)' : '   <-- CHANGED'));
      } catch (err) {
        say('pg_net refused: ' + String(err.message).split('\n')[0]);
      }
    }

    /* ---- 2. whether pg_cron can actually schedule ---- */
    if (!(await installed('pg_cron'))) {
      try {
        await client.query('CREATE EXTENSION pg_cron');
        madeHere.push('pg_cron');
        say('pg_cron installed');
      } catch (err) {
        say('pg_cron refused: ' + String(err.message).split('\n')[0]);
      }
    }

    if (await installed('pg_cron')) {
      try {
        const { rows } = await client.query(
          "SELECT cron.schedule($1, $2, $3) AS jobid",
          ['kryptheon_probe', '0 3 * * *', 'SELECT 1'],
        );
        say('scheduled a nightly job, id ' + rows[0].jobid);
        const job = (await client.query(
          'SELECT jobname, schedule, active, database, username FROM cron.job WHERE jobid = $1',
          [rows[0].jobid],
        )).rows[0];
        say('   it reads back as: ' + JSON.stringify(job));
        // Cast on purpose. cron.unschedule is overloaded on (bigint) and
        // (name), and node-postgres sends a plain parameter as text - so this
        // bound to the name overload and went looking for a job CALLED '1'.
        // It failed with "could not find valid entry for job", which reads
        // like the job was never there rather than like the wrong function.
        await client.query('SELECT cron.unschedule($1::bigint)', [rows[0].jobid]);
        const still = (await client.query('SELECT count(*)::int n FROM cron.job WHERE jobid = $1', [rows[0].jobid])).rows[0].n;
        say('   unscheduled again; jobs with that id left: ' + still);
      } catch (err) {
        say('pg_cron could not schedule: ' + String(err.message).split('\n')[0]);
      }
    }

    /* ---- 3. what pg_net would need to post anywhere ---- */
    if (await installed('pg_net')) {
      const { rows } = await client.query(
        `SELECT n.nspname || '.' || p.proname AS fn
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE p.proname IN ('http_post', 'http_get') ORDER BY 1`,
      );
      say('pg_net offers: ' + (rows.map((r) => r.fn).join(', ') || 'nothing that looks like http_post'));
    }
  } finally {
    for (const ext of madeHere.reverse()) {
      await client.query('DROP EXTENSION IF EXISTS ' + ext).catch(() => {});
    }
    say('');
    say('removed again: ' + (madeHere.join(', ') || 'nothing was created'));
    const left = await publicFunctions();
    say('functions in the customer’s public schema, after: ' + left);
    await client.end();
  }
}

main().catch((err) => {
  console.error('');
  console.error('  probe failed: ' + err.message);
  console.error('');
  process.exit(1);
});
