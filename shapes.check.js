// Checks that the scanner copes with the shapes real apps actually have.
// Run with:  node shapes.check.js "<postgres connection string>"
//
// Every other check runs against a schema written to demonstrate a particular
// bug, which means each one agrees with whatever was already believed. This is
// the opposite: twenty-five small apps, each built around a shape that turns
// up in real projects and was in nobody's fixture - an enum, a text[], a
// generated column, a domain type, a composite key, a table that is only an
// id, a foreign key into auth.users.
//
// Each is scanned on its own, so one bad shape cannot hide the others.
//
// A shape passes only if the scan runs, nothing throws, and nothing is
// skipped. Skipped counts as a failure here on purpose: a table that could not
// be seeded is a table that was never tested, and an app full of those gets a
// report full of warnings and never earns a badge.
//
// It was written as a throwaway hunt and found eight bugs on its first run,
// which is why it now lives here and runs with everything else.
const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');

const CONN = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};
// And the auth.users table, on the same terms. fixture.js marks the one it
// makes, so a run that dies here does not strand it for every later run.
let authUsers = { made: false, undo: async () => {} };

/** Each shape is a real thing an app actually has. */
const SHAPES = [
  {
    name: 'identity column instead of serial',
    sql: (q) => [
      'CREATE TABLE ' + q('notes') + ' (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)',
    ],
  },
  {
    name: 'enum type column',
    sql: (q, s) => [
      'CREATE TYPE ' + schema.quote(s) + '.order_status AS ENUM (' + "'new', 'paid', 'shipped'" + ')',
      'CREATE TABLE ' + q('orders') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, status ' + schema.quote(s) + '.order_status NOT NULL)',
    ],
  },
  {
    name: 'array column, NOT NULL',
    sql: (q) => [
      'CREATE TABLE ' + q('posts') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, tags text[] NOT NULL)',
    ],
  },
  {
    name: 'generated stored column',
    sql: (q) => [
      'CREATE TABLE ' + q('people') + " (id serial PRIMARY KEY, owner uuid NOT NULL, first text NOT NULL, last text NOT NULL, full_name text GENERATED ALWAYS AS (first || ' ' || last) STORED)",
    ],
  },
  {
    name: 'composite primary key',
    sql: (q) => [
      'CREATE TABLE ' + q('memberships') + ' (org_id int NOT NULL, user_id uuid NOT NULL, role text NOT NULL, PRIMARY KEY (org_id, user_id))',
    ],
  },
  {
    name: 'self-referencing foreign key',
    sql: (q) => [
      'CREATE TABLE ' + q('comments') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, parent_id int REFERENCES ' + q('comments') + '(id), body text NOT NULL)',
    ],
  },
  {
    name: 'two tables pointing at each other',
    sql: (q) => [
      'CREATE TABLE ' + q('users') + ' (id uuid PRIMARY KEY, primary_org int)',
      'CREATE TABLE ' + q('orgs') + ' (id serial PRIMARY KEY, owner_id uuid NOT NULL REFERENCES ' + q('users') + '(id))',
      'ALTER TABLE ' + q('users') + ' ADD CONSTRAINT users_org_fk FOREIGN KEY (primary_org) REFERENCES ' + q('orgs') + '(id)',
    ],
  },
  {
    name: 'names that need quoting',
    sql: (q) => [
      'CREATE TABLE ' + q('User Profiles') + ' (' + schema.quote('id') + ' serial PRIMARY KEY, ' + schema.quote('owner') + ' uuid NOT NULL, ' + schema.quote('First Name') + ' text NOT NULL, ' + schema.quote('order') + ' int NOT NULL)',
    ],
  },
  {
    name: 'check constraint on a text column',
    sql: (q) => [
      'CREATE TABLE ' + q('tickets') + " (id serial PRIMARY KEY, owner uuid NOT NULL, status text NOT NULL CHECK (status IN ('open', 'closed')))",
    ],
  },
  {
    name: 'defaults: now() and gen_random_uuid()',
    sql: (q) => [
      'CREATE TABLE ' + q('events') + ' (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), owner uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now())',
    ],
  },
  {
    name: 'unique constraint on a nullable column',
    sql: (q) => [
      'CREATE TABLE ' + q('accounts') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email text UNIQUE)',
    ],
  },
  {
    name: 'FORCE row level security',
    sql: (q) => [
      'CREATE TABLE ' + q('secrets') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, value text NOT NULL)',
      'GRANT SELECT ON ' + q('secrets') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('secrets') + ' ENABLE ROW LEVEL SECURITY',
      'ALTER TABLE ' + q('secrets') + ' FORCE ROW LEVEL SECURITY',
      'CREATE POLICY own ON ' + q('secrets') + ' FOR SELECT TO authenticated USING (owner = auth.uid())',
    ],
  },
  {
    name: 'a RESTRICTIVE policy',
    sql: (q) => [
      'CREATE TABLE ' + q('files') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, name text NOT NULL)',
      'GRANT SELECT ON ' + q('files') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('files') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY readable ON ' + q('files') + ' FOR SELECT TO authenticated USING (true)',
      'CREATE POLICY only_owner ON ' + q('files') + ' AS RESTRICTIVE FOR SELECT TO authenticated USING (owner = auth.uid())',
    ],
  },
  {
    name: 'write policies but no read policy',
    sql: (q) => [
      'CREATE TABLE ' + q('submissions') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)',
      'GRANT SELECT, INSERT ON ' + q('submissions') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('submissions') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY anyone_can_write ON ' + q('submissions') + ' FOR INSERT TO anon WITH CHECK (true)',
    ],
  },
  {
    name: 'a view over a table',
    sql: (q) => [
      'CREATE TABLE ' + q('sales') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, total numeric(10,2) NOT NULL)',
      'CREATE VIEW ' + q('sales_summary') + ' AS SELECT owner, sum(total) AS total FROM ' + q('sales') + ' GROUP BY owner',
    ],
  },
  {
    name: 'a materialized view',
    sql: (q) => [
      'CREATE TABLE ' + q('hits') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, path text NOT NULL)',
      'CREATE MATERIALIZED VIEW ' + q('hits_by_path') + ' AS SELECT path, count(*) AS n FROM ' + q('hits') + ' GROUP BY path',
    ],
  },
  {
    // An enum and a view each had a shape of their own here, and both passed.
    // Together they took the whole scan down: pg_get_viewdef writes the
    // literal as 'paid'::app.order_status, the rewrite pointed that at the
    // copy, and the copy had no such type. A great many apps are this shape.
    name: 'a view that mentions an enum',
    sql: (q, s) => [
      'CREATE TYPE ' + schema.quote(s) + ".shipment AS ENUM ('packing', 'sent')",
      'CREATE TABLE ' + q('parcels') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, state ' +
        schema.quote(s) + '.shipment NOT NULL)',
      'CREATE VIEW ' + q('sent_parcels') + ' AS SELECT id, owner FROM ' + q('parcels') +
        " WHERE state = 'sent'",
    ],
  },
  {
    name: 'a BEFORE INSERT trigger',
    sql: (q, s) => [
      'CREATE TABLE ' + q('audit') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, note text NOT NULL)',
      'CREATE FUNCTION ' + schema.quote(s) + '.stamp() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.note := NEW.note; RETURN NEW; END $$',
      'CREATE TRIGGER stamp_audit BEFORE INSERT ON ' + q('audit') + ' FOR EACH ROW EXECUTE FUNCTION ' + schema.quote(s) + '.stamp()',
    ],
  },
  {
    name: 'a domain type',
    sql: (q, s) => [
      'CREATE DOMAIN ' + schema.quote(s) + '.email_address AS text CHECK (VALUE LIKE ' + "'%@%'" + ')',
      'CREATE TABLE ' + q('subscribers') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email ' + schema.quote(s) + '.email_address NOT NULL)',
    ],
  },
  {
    name: 'jsonb NOT NULL with no default',
    sql: (q) => [
      'CREATE TABLE ' + q('configs') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, settings jsonb NOT NULL)',
    ],
  },
  {
    name: 'inet, macaddr, tsvector',
    sql: (q) => [
      'CREATE TABLE ' + q('devices') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, ip inet NOT NULL, mac macaddr NOT NULL, search tsvector NOT NULL)',
    ],
  },
  {
    name: 'narrow varchar and fixed char',
    sql: (q) => [
      'CREATE TABLE ' + q('codes') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, country char(2) NOT NULL, label varchar(5) NOT NULL)',
    ],
  },
  {
    name: 'foreign key into auth.users (the Supabase default)',
    sql: (q) => [
      // Created by the loop below only if it is not already there, and
      // remembered so it can be taken away again. An auth.users left behind in
      // somebody else's auth schema is exactly the litter this whole file
      // exists to catch the product dropping.
      'CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY)',
      'CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY REFERENCES auth.users(id), display_name text NOT NULL)',
    ],
  },
  {
    name: 'forty columns',
    sql: (q) => {
      const cols = [];
      for (let i = 0; i < 37; i++) cols.push('c' + i + ' text');
      return ['CREATE TABLE ' + q('wide') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, ' + cols.join(', ') + ')'];
    },
  },
  {
    name: 'a table that is only an id',
    sql: (q) => ['CREATE TABLE ' + q('flags') + ' (id serial PRIMARY KEY)'],
  },
  {
    name: 'a policy that calls a function',
    sql: (q, s) => [
      'CREATE FUNCTION ' + schema.quote(s) + '.is_admin() RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT false $$',
      'CREATE TABLE ' + q('admin_notes') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)',
      'GRANT SELECT ON ' + q('admin_notes') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('admin_notes') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY admin_only ON ' + q('admin_notes') + ' FOR SELECT TO authenticated USING (' + schema.quote(s) + '.is_admin())',
    ],
  },
];

async function groundwork(client, name) {
  await client.query('CREATE SCHEMA ' + schema.quote(name));
  for (const role of ['anon', 'authenticated']) {
    await client.query(
      'DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ' + "'" + role + "'" +
        ') THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(name) + ' TO ' + role);
  }
  undoAuth = await fixture.ensureAuth(client);
}

(async () => {
  if (!CONN) {
    console.error('set KN_DATABASE_URL');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONN });
  await client.connect();

  authUsers = await fixture.ensureAuthUsers(client, 'id uuid PRIMARY KEY');

  const leads = [];
  let n = 0;

  for (const shape of SHAPES) {
    n += 1;
    const name = 'kn_shape_' + n + '_' + Date.now().toString(36);
    const q = (t) => schema.quote(name) + '.' + schema.quote(t);
    let verdict;
    try {
      await groundwork(client, name);
      for (const statement of shape.sql(q, name)) await client.query(statement);

      // Every table gets granted, or nothing is reachable and everything
      // reads as safe for the wrong reason.
      const { rows: tables } = await client.query(
        "SELECT relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace WHERE ns.nspname = $1 AND c.relkind = 'r'",
        [name],
      );
      for (const t of tables) {
        await client.query('GRANT SELECT ON ' + q(t.relname) + ' TO anon, authenticated');
      }

      const result = await scan(client, name, {
        quiet: true,
        openSession: async () => {
          const extra = new Client({ connectionString: CONN });
          await extra.connect();
          return extra;
        },
      });

      if (result.stopped) {
        verdict = { level: 'STOPPED', detail: result.stopped.split('\n').slice(0, 3).join(' | ') };
      } else if ((result.notChecked || []).length) {
        verdict = {
          level: 'SKIPPED',
          detail: result.notChecked.map((s) => s.table + ': ' + String(s.why).slice(0, 110)).join('  //  '),
        };
      } else {
        verdict = { level: 'ok', detail: result.findings.length + ' findings, ' + result.attacksRun + ' attacks' };
      }
    } catch (err) {
      verdict = { level: 'THREW', detail: String(err.message || err).slice(0, 200) };
    } finally {
      try {
        await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE');
      } catch (err) { /* nothing to drop */ }
    }

    console.log((verdict.level === 'ok' ? 'PASS  ' : 'FAIL  ') + shape.name);
    if (verdict.level !== 'ok') {
      console.log('      - ' + verdict.level + ': ' + verdict.detail);
      leads.push(shape.name + '  ->  ' + verdict.level);
    }
  }

  await authUsers.undo();
  await undoAuth();
  await client.end();

  console.log('');
  if (!leads.length) {
    console.log('All ' + SHAPES.length + ' shape checks passed.');
  } else {
    console.log(leads.length + ' check(s) failed:');
    leads.forEach((l) => console.log('    ' + l));
    process.exitCode = 1;
  }
  console.log('');
})().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + (err.message || err));
  console.error('');
  process.exit(1);
});
