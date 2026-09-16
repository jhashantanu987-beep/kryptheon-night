// Stands up a realistic app the way a builder ends up with one, then runs the
// real scan against it and prints exactly what the person would see.
const { Client } = require('pg');
const schema = require('./schema.js');
const { scan, report } = require('./scan.js');

const APP = 'app_' + Date.now().toString(36);

(async () => {
  const client = new Client({ connectionString: process.argv[2] });
  await client.connect();
  const q = (t) => schema.quote(APP) + '.' + schema.quote(t);

  try {
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    for (const role of ['anon', 'authenticated']) {
      await client.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role +
        "') THEN CREATE ROLE " + role + " NOLOGIN; END IF; END $$;");
      await client.query('GRANT ' + role + ' TO current_user');
      await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO ' + role);
    }
    await client.query('CREATE SCHEMA IF NOT EXISTS auth');
    await client.query("CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ " +
      "SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub','')::uuid $$");
    await client.query('GRANT USAGE ON SCHEMA auth TO anon, authenticated');

    // A small finance app. Two tables done right, two the way they come out.
    await client.query('CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY, email text NOT NULL, full_name text)');
    await client.query('CREATE TABLE ' + q('orders') + ' (id serial PRIMARY KEY, user_id uuid NOT NULL, total numeric(10,2) NOT NULL)');
    await client.query('CREATE TABLE ' + q('customers') + ' (id serial PRIMARY KEY, owner uuid NOT NULL, name text NOT NULL, email text NOT NULL, phone text)');
    await client.query('CREATE TABLE ' + q('integrations') + ' (id serial PRIMARY KEY, provider text NOT NULL, api_key text NOT NULL)');

    for (const t of ['profiles', 'orders', 'customers', 'integrations']) {
      await client.query('GRANT SELECT ON ' + q(t) + ' TO anon, authenticated');
    }

    await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY own_profile ON ' + q('profiles') + ' FOR SELECT TO authenticated USING (id = auth.uid())');
    await client.query('ALTER TABLE ' + q('orders') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY own_orders ON ' + q('orders') + ' FOR SELECT TO authenticated USING (user_id = auth.uid())');
    // Switched on, then handed to everyone. Dashboard shows this as protected.
    await client.query('ALTER TABLE ' + q('customers') + ' ENABLE ROW LEVEL SECURITY');
    await client.query('CREATE POLICY read_customers ON ' + q('customers') + ' FOR SELECT TO anon, authenticated USING (true)');
    // Never switched on at all.

    console.log('');
    console.log('  $ kryptheon scan   (app: ' + APP + ')');
    console.log('');
    const result = await scan(client, APP, {
      // Two requests at once cannot be faked down one connection, so the
      // collision attack is given a way to open its own.
      openSession: async () => {
        const extra = new Client({ connectionString: process.argv[2] });
        await extra.connect();
        return extra;
      },
    });
    report(result);
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE');
    await client.end();
  }
})();
