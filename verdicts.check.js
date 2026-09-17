// Checks that the verdict is right, not just that the scan finished.
// Run with:  node verdicts.check.js "<postgres connection string>"
//
// shapes.check.js asks whether every table could be tested. This asks whether
// the answer was correct, which is a harder question and a worse failure:
//
//   a hole reported as nothing   -> the person is told they are safe
//   a correct app reported as broken -> the person is sent chasing a ghost
//
// Neither leaves a warning behind, so neither gets noticed. Every app below
// declares the honest answer up front:
//
//   expect: 'found'  a real hole - it must appear in the findings
//   expect: 'clean'  a correct app - no findings, and nothing skipped
//
// The ones that were wrong when this was written: an owner column that is
// text rather than uuid, which is what Clerk and Firebase ids look like; a
// table whose name happened to start the same way as this tool's own stand-ins;
// a foreign key over two columns; and a view over a locked table, which does
// not just go unreported - it took the whole scan down.
const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const { scan } = require('./scan.js');

const CONN = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};

const SHAPES = [
  {
    name: 'owner column is text, not uuid (Clerk / Firebase ids)',
    expect: 'found',
    where: 'notes',
    sql: (q) => [
      'CREATE TABLE ' + q('notes') + ' (id serial PRIMARY KEY, user_id text NOT NULL, body text NOT NULL)',
      'GRANT SELECT ON ' + q('notes') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'owner column is bigint',
    expect: 'found',
    where: 'invoices',
    sql: (q) => [
      'CREATE TABLE ' + q('invoices') + ' (id serial PRIMARY KEY, owner_id bigint NOT NULL, total numeric(10,2) NOT NULL)',
      'GRANT SELECT ON ' + q('invoices') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'row level security on, no policies at all',
    expect: 'clean',
    sql: (q) => [
      'CREATE TABLE ' + q('vault') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, secret text NOT NULL)',
      'GRANT SELECT ON ' + q('vault') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('vault') + ' ENABLE ROW LEVEL SECURITY',
    ],
  },
  {
    name: 'granted to PUBLIC rather than to anon',
    expect: 'found',
    where: 'leads',
    sql: (q) => [
      'CREATE TABLE ' + q('leads') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)',
      'GRANT SELECT ON ' + q('leads') + ' TO PUBLIC',
    ],
  },
  {
    name: 'a policy FOR ALL, not just SELECT',
    expect: 'found',
    where: 'posts',
    sql: (q) => [
      'CREATE TABLE ' + q('posts') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, body text NOT NULL)',
      'GRANT SELECT ON ' + q('posts') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('posts') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY everything ON ' + q('posts') + ' FOR ALL TO anon, authenticated USING (true)',
    ],
  },
  {
    name: 'a write policy only, so reads are denied',
    expect: 'clean',
    sql: (q) => [
      'CREATE TABLE ' + q('signups') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)',
      'GRANT SELECT, INSERT ON ' + q('signups') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('signups') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY writes ON ' + q('signups') + ' FOR INSERT TO anon WITH CHECK (true)',
    ],
  },
  {
    name: 'a view over a locked table, granted to anon',
    expect: 'found',
    where: 'all_rows',
    sql: (q) => [
      'CREATE TABLE ' + q('private_rows') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, secret text NOT NULL)',
      'ALTER TABLE ' + q('private_rows') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY own ON ' + q('private_rows') + ' FOR SELECT TO authenticated USING (owner = auth.uid())',
      'GRANT SELECT ON ' + q('private_rows') + ' TO authenticated',
      // The view runs as its owner, so the policy above does not apply to it.
      'CREATE VIEW ' + q('all_rows') + ' AS SELECT * FROM ' + q('private_rows'),
      'GRANT SELECT ON ' + q('all_rows') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'table names that are reserved words',
    expect: 'found',
    where: 'user',
    sql: (q) => [
      'CREATE TABLE ' + q('user') + ' (id uuid PRIMARY KEY, email text NOT NULL)',
      'CREATE TABLE ' + q('order') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, "select" text NOT NULL)',
      'GRANT SELECT ON ' + q('user') + ' TO anon, authenticated',
      'GRANT SELECT ON ' + q('order') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'a table named like our own stand-in',
    expect: 'found',
    where: 'kn_ext__auth__users',
    sql: (q) => [
      'CREATE TABLE ' + q('kn_ext__auth__users') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, email text NOT NULL)',
      'GRANT SELECT ON ' + q('kn_ext__auth__users') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'a multi-column foreign key',
    expect: 'found',
    where: 'line_items',
    sql: (q) => [
      'CREATE TABLE ' + q('carts') + ' (org_id int NOT NULL, cart_id int NOT NULL, PRIMARY KEY (org_id, cart_id))',
      'CREATE TABLE ' + q('line_items') + ' (id serial PRIMARY KEY, org_id int NOT NULL, cart_id int NOT NULL, owner uuid NOT NULL, ' +
        'FOREIGN KEY (org_id, cart_id) REFERENCES ' + q('carts') + '(org_id, cart_id))',
      'GRANT SELECT ON ' + q('line_items') + ' TO anon, authenticated',
      'GRANT SELECT ON ' + q('carts') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'a foreign key with ON DELETE CASCADE',
    expect: 'found',
    where: 'comments',
    sql: (q) => [
      'CREATE TABLE ' + q('threads') + ' (id serial PRIMARY KEY, owner uuid NOT NULL)',
      'CREATE TABLE ' + q('comments') + ' (id serial PRIMARY KEY, thread_id int NOT NULL REFERENCES ' + q('threads') +
        '(id) ON DELETE CASCADE, owner uuid NOT NULL, body text NOT NULL)',
      'GRANT SELECT ON ' + q('comments') + ' TO anon, authenticated',
      'GRANT SELECT ON ' + q('threads') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'identity column, generated BY DEFAULT',
    expect: 'found',
    where: 'items',
    sql: (q) => [
      'CREATE TABLE ' + q('items') + ' (id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, owner uuid NOT NULL, label text NOT NULL)',
      'GRANT SELECT ON ' + q('items') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'a deferrable unique constraint',
    expect: 'found',
    where: 'tokens',
    sql: (q) => [
      'CREATE TABLE ' + q('tokens') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, token text NOT NULL, ' +
        'CONSTRAINT tokens_token_key UNIQUE (token) DEFERRABLE INITIALLY DEFERRED)',
      'GRANT SELECT ON ' + q('tokens') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'a trigger that rewrites the value being inserted',
    expect: 'found',
    where: 'audits',
    sql: (q, s) => [
      'CREATE TABLE ' + q('audits') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, api_key text NOT NULL)',
      'CREATE FUNCTION ' + schema.quote(s) + '.rewrite() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ' +
        "NEW.api_key := NEW.api_key || '-x'; RETURN NEW; END $$",
      'CREATE TRIGGER rewrite_audits BEFORE INSERT ON ' + q('audits') +
        ' FOR EACH ROW EXECUTE FUNCTION ' + schema.quote(s) + '.rewrite()',
      'GRANT SELECT ON ' + q('audits') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'two owner-looking columns on one table',
    expect: 'found',
    where: 'tickets',
    sql: (q) => [
      'CREATE TABLE ' + q('tickets') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL, created_by uuid NOT NULL, body text NOT NULL)',
      'GRANT SELECT ON ' + q('tickets') + ' TO anon, authenticated',
    ],
  },
  {
    name: 'a policy that checks membership in another table',
    expect: 'clean',
    sql: (q) => [
      'CREATE TABLE ' + q('members') + ' (org_id int NOT NULL, user_id uuid NOT NULL, PRIMARY KEY (org_id, user_id))',
      'CREATE TABLE ' + q('documents') + ' (id serial PRIMARY KEY, org_id int NOT NULL, body text NOT NULL)',
      'GRANT SELECT ON ' + q('documents') + ' TO anon, authenticated',
      'ALTER TABLE ' + q('documents') + ' ENABLE ROW LEVEL SECURITY',
      'CREATE POLICY in_my_org ON ' + q('documents') + ' FOR SELECT TO authenticated USING (EXISTS (' +
        'SELECT 1 FROM ' + q('members') + ' m WHERE m.org_id = ' + q('documents') + '.org_id AND m.user_id = auth.uid()))',
    ],
  },
  {
    name: 'granted only to service_role',
    expect: 'clean',
    sql: (q) => [
      'CREATE TABLE ' + q('internal') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, note text NOT NULL)',
      "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN; END IF; END $$;",
      'GRANT SELECT ON ' + q('internal') + ' TO service_role',
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

  const leads = [];
  let n = 0;

  for (const shape of SHAPES) {
    n += 1;
    const name = 'kn_hunt2_' + n + '_' + Date.now().toString(36);
    const q = (t) => schema.quote(name) + '.' + schema.quote(t);
    let verdict;
    try {
      await groundwork(client, name);
      for (const statement of shape.sql(q, name)) await client.query(statement);

      const result = await scan(client, name, {
        quiet: true,
        openSession: async () => {
          const extra = new Client({ connectionString: CONN });
          await extra.connect();
          return extra;
        },
      });

      const found = (result.findings || []).map((f) => f.table);
      const skipped = (result.notChecked || []).map((s) => s.table + ': ' + String(s.why).slice(0, 80));

      if (result.stopped) {
        verdict = { bad: 'STOPPED', detail: String(result.stopped).replace(/\n\s*/g, ' ').slice(0, 160) };
      } else if (shape.expect === 'found' && !found.includes(shape.where)) {
        verdict = {
          bad: 'MISSED',
          detail: 'expected a finding on ' + shape.where + '; got [' + found.join(', ') + ']' +
            (skipped.length ? '  skipped: ' + skipped.join(' | ') : ''),
        };
      } else if (shape.expect === 'clean' && found.length) {
        verdict = { bad: 'FALSE ALARM', detail: 'reported ' + found.join(', ') + ' on a correct app' };
      } else if (shape.expect === 'clean' && skipped.length) {
        verdict = { bad: 'SKIPPED', detail: skipped.join(' | ') };
      } else {
        verdict = { ok: found.length ? found.length + ' findings' : 'clean' };
      }
    } catch (err) {
      verdict = { bad: 'THREW', detail: String(err.message || err).slice(0, 200) };
    } finally {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
    }

    console.log((verdict.ok ? 'PASS  ' : 'FAIL  ') + shape.name);
    if (!verdict.ok) {
      console.log('      - ' + verdict.bad + ': ' + verdict.detail);
      leads.push(shape.name + '  ->  ' + verdict.bad);
    }
  }

  await undoAuth();
  await client.end();

  console.log('');
  if (!leads.length) {
    console.log('All ' + SHAPES.length + ' verdict checks passed.');
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
