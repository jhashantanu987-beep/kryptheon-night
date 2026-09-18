// Can the attack really be written once, in SQL?
//
// Run with:  node probe-plpgsql.js "<connection string>"
//
// probe-inside.js answered the first question: a function can become `anon`,
// read the way a request does, and get the same verdict as the Node code does
// from outside. This asks the harder ones, the ones that decide whether the
// engine can move into SQL at all rather than be written twice.
//
//   1. Can one function switch role over and over, table after table?
//   2. Can it try a write and undo it, and still know what happened?
//      plpgsql has no nested transactions. It has exception blocks, which are
//      subtransactions - so the shape is: do the write, capture the count,
//      raise on purpose, catch it. If that does not work, the tampering
//      attack cannot live in the database.
//   3. Can it read a policy out of the catalogue and build it again somewhere
//      else? That is how the copy gets made.
//   4. Does SECURITY DEFINER change any of it? The installed version will run
//      as its owner, not as whoever the scheduler happens to be.
//   5. Can two sessions be raced from inside? The collision attack needs two
//      requests at the same moment, and a function is one session.
//
// Anything answered no here is not a setback, it is a week saved.

const { Client } = require('pg');

const CONN = process.argv[2] || process.env.KN_DATABASE_URL;
const APP = 'kn_plpg_' + Date.now().toString(36);

let asked = 0;
function record(question, answer, detail) {
  asked += 1;
  console.log('');
  console.log('  ' + question);
  console.log('    -> ' + answer);
  if (detail) console.log('       ' + detail);
}

async function attempt(client, statement, args) {
  try {
    const r = await client.query(statement, args || []);
    return { ok: true, rows: r.rows };
  } catch (err) {
    return { ok: false, why: err.message.split('\n')[0] };
  }
}

(async () => {
  if (!CONN) {
    console.error('\n  node probe-plpgsql.js "<connection string>"\n');
    process.exit(2);
  }
  const c = new Client({ connectionString: CONN });
  await c.connect();
  const S = '"' + APP + '"';

  try {
    await c.query('CREATE SCHEMA ' + S);
    for (const role of ['anon', 'authenticated']) {
      await c.query(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role +
          "') THEN CREATE ROLE " + role + ' NOLOGIN; END IF; END $$;',
      );
      await c.query('GRANT ' + role + ' TO current_user');
      await c.query('GRANT USAGE ON SCHEMA ' + S + ' TO ' + role);
    }

    await c.query('CREATE TABLE ' + S + '.open_table (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)');
    await c.query('CREATE TABLE ' + S + '.shut_table (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)');
    await c.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ' + S + ' TO anon, authenticated');
    await c.query('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ' + S + ' TO anon, authenticated');
    for (const t of ['open_table', 'shut_table']) {
      await c.query("INSERT INTO " + S + '.' + t + " (owner, email) VALUES ('11111111-1111-4111-8111-111111111111', 'a@b.c')");
    }
    await c.query('ALTER TABLE ' + S + '.shut_table ENABLE ROW LEVEL SECURITY');
    await c.query('CREATE POLICY only_mine ON ' + S + '.shut_table FOR ALL TO authenticated ' +
      "USING (owner::text = current_setting('request.jwt.claims', true)::json->>'sub')");

    /* 1. switching role many times in one call */
    await c.query(
      'CREATE FUNCTION ' + S + '.read_everything() RETURNS jsonb LANGUAGE plpgsql AS $fn$ ' +
      'DECLARE t record; n integer; out jsonb := ' + "'{}'::jsonb; " +
      'BEGIN ' +
      "  FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace " +
      "           WHERE ns.nspname = '" + APP + "' AND c.relkind = 'r' ORDER BY 1 LOOP " +
      '    SET LOCAL ROLE anon; ' +
      "    PERFORM set_config('request.jwt.claims', '{\"role\":\"anon\"}', true); " +
      "    EXECUTE format('SELECT count(*) FROM %I.%I', '" + APP + "', t.relname) INTO n; " +
      '    RESET ROLE; ' +
      '    out := out || jsonb_build_object(t.relname, n); ' +
      '  END LOOP; ' +
      '  RETURN out; ' +
      'END $fn$');
    const many = await attempt(c, 'SELECT ' + S + '.read_everything() AS r');
    record(
      '1. can one function switch role table after table?',
      many.ok ? 'YES - ' + JSON.stringify(many.rows[0].r) : 'no - ' + many.why,
      'open_table should show 1 and shut_table 0, which is the right pair of verdicts',
    );

    /* 2. a write that is undone, with the count kept */
    await c.query(
      'CREATE FUNCTION ' + S + '.try_and_undo() RETURNS jsonb LANGUAGE plpgsql AS $fn$ ' +
      'DECLARE moved integer := -1; before_count integer; after_count integer; ' +
      'BEGIN ' +
      '  SELECT count(*) INTO before_count FROM ' + S + '.open_table; ' +
      '  BEGIN ' +
      '    SET LOCAL ROLE anon; ' +
      "    PERFORM set_config('request.jwt.claims', '{\"role\":\"anon\"}', true); " +
      '    DELETE FROM ' + S + '.open_table; ' +
      '    GET DIAGNOSTICS moved = ROW_COUNT; ' +
      '    RESET ROLE; ' +
      "    RAISE EXCEPTION 'kryptheon rollback'; " +
      '  EXCEPTION WHEN OTHERS THEN ' +
      '    RESET ROLE; ' +
      '  END; ' +
      '  SELECT count(*) INTO after_count FROM ' + S + '.open_table; ' +
      "  RETURN jsonb_build_object('rows_the_attack_moved', moved, 'before', before_count, 'after', after_count); " +
      'END $fn$');
    const undone = await attempt(c, 'SELECT ' + S + '.try_and_undo() AS r');
    record(
      '2. can it try a write, keep the count, and undo it?',
      undone.ok ? 'YES - ' + JSON.stringify(undone.rows[0].r) : 'no - ' + undone.why,
      'the count must survive the rollback, and before must equal after',
    );

    /* 3. reading a policy and building it again elsewhere */
    await c.query(
      'CREATE FUNCTION ' + S + '.copy_a_policy() RETURNS text LANGUAGE plpgsql AS $fn$ ' +
      'DECLARE p record; made text := ' + "''; " +
      'BEGIN ' +
      "  EXECUTE 'CREATE SCHEMA " + APP + "_copy'; " +
      "  EXECUTE 'CREATE TABLE " + APP + "_copy.shut_table (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)'; " +
      "  FOR p IN SELECT policyname, cmd, qual, roles FROM pg_policies " +
      "           WHERE schemaname = '" + APP + "' AND tablename = 'shut_table' LOOP " +
      "    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', '" + APP + "_copy', 'shut_table'); " +
      "    EXECUTE format('CREATE POLICY %I ON %I.%I FOR %s TO %s USING (%s)', " +
      "      p.policyname, '" + APP + "_copy', 'shut_table', p.cmd, array_to_string(p.roles, ', '), p.qual); " +
      '    made := made || p.policyname; ' +
      '  END LOOP; ' +
      "  RETURN made; " +
      'END $fn$');
    const copied = await attempt(c, 'SELECT ' + S + '.copy_a_policy() AS r');
    let sameQual = 'n/a';
    if (copied.ok) {
      const { rows } = await c.query(
        "SELECT (SELECT qual FROM pg_policies WHERE schemaname = $1 AND tablename = 'shut_table') AS a," +
        "       (SELECT qual FROM pg_policies WHERE schemaname = $2 AND tablename = 'shut_table') AS b",
        [APP, APP + '_copy'],
      );
      sameQual = rows[0].a === rows[0].b ? 'and it came across word for word' : 'BUT IT CHANGED:\n       ' + rows[0].a + '\n       ' + rows[0].b;
    }
    record(
      '3. can it read a rule from the catalogue and build it again?',
      copied.ok ? 'YES - copied ' + copied.rows[0].r : 'no - ' + copied.why,
      sameQual,
    );

    /* 4. does SECURITY DEFINER change the role switching */
    await c.query(
      'CREATE FUNCTION ' + S + '.as_definer() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER AS $fn$ ' +
      'DECLARE n integer; ' +
      'BEGIN ' +
      '  SET LOCAL ROLE anon; ' +
      '  SELECT count(*) INTO n FROM ' + S + '.open_table; ' +
      '  RESET ROLE; ' +
      '  RETURN n; ' +
      'END $fn$');
    const definer = await attempt(c, 'SELECT ' + S + '.as_definer() AS n');
    record(
      '4. does SECURITY DEFINER get in the way of becoming anon?',
      definer.ok ? 'no - it still read ' + definer.rows[0].n + ' row(s) as anon' : 'YES - ' + definer.why,
      'the installed version runs as its owner, so this had to be asked',
    );

    /* 5. two sessions at once, from inside */
    const dblink = await attempt(c, "SELECT 1 FROM pg_available_extensions WHERE name = 'dblink'");
    record(
      '5. is there any way to open a second session from inside the database?',
      dblink.ok && dblink.rows.length ? 'dblink is available on this host' : 'no dblink here',
      'the collision attack needs two requests at the same moment, and a function is one session',
    );

    console.log('');
    console.log('  ' + '-'.repeat(68));
    console.log('  ' + asked + ' questions answered.');
    console.log('');
  } finally {
    await c.query('DROP SCHEMA IF EXISTS ' + S + ' CASCADE').catch(() => {});
    await c.query('DROP SCHEMA IF EXISTS "' + APP + '_copy" CASCADE').catch(() => {});
    await c.end();
  }
})().catch((e) => {
  console.error('\n  the probe could not run: ' + (e.message || e));
  process.exit(1);
});
