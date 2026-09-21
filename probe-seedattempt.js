// Why the two engines seeded the same rows under different keys.
//
// twin.check.js, with the app on the search_path for the first time:
//
//   node ["1 | 1111... | 1 kryptheon test", "2 | 2222... | 2 kryptheon test"]
//   sql  ["3 | 1111... | 1 kryptheon test", "4 | 2222... | 2 kryptheon test"]
//
// Same values, different serial ids - so one engine burned 1 and 2 on an
// attempt that failed and was deleted, and the other did not. The seeder tries
// several row shapes and deletes what landed when one fails, and a DELETE does
// not put a sequence back.
//
// audit_events has no foreign key and no check, so nothing about it explains
// this by reading. This builds only that table, seeds it with each engine in
// turn against its own copy, and prints which attempt each one landed on.
//
//   KN_DATABASE_URL=postgresql://...  node probe-seedattempt.js

const { Client } = require('pg');
const schema = require('./schema.js');
const attack = require('./attack.js');
const fixture = require('./fixture.js');
const sqlengine = require('./sqlengine.js');
const { howToConnect } = require('./connect.js');

const APP = 'kn_attempt_' + Date.now().toString(36);

async function main() {
  if (!process.env.KN_DATABASE_URL) {
    console.error('  KN_DATABASE_URL=postgresql://...  node probe-seedattempt.js');
    process.exit(2);
  }

  const client = new Client(howToConnect(process.env.KN_DATABASE_URL));
  await client.connect();
  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  const made = [];
  let undoAuth = async () => {};

  try {
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    await fixture.ensureRoles(client, APP, schema.quote);
    undoAuth = await fixture.ensureAuth(client);
    await client.query('CREATE TABLE ' + q('audit_events') +
      ' (id serial PRIMARY KEY, profile_id uuid NOT NULL, what text NOT NULL)');
    await client.query('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + q('audit_events') +
      ' TO anon, authenticated');
    await client.query('GRANT USAGE ON ALL SEQUENCES IN SCHEMA ' + schema.quote(APP) +
      ' TO anon, authenticated');

    // The condition twin now runs under, and the only thing that changed.
    await client.query('SET search_path TO ' + schema.quote(APP) + ', public');

    const show = async (label, copy) => {
      const { rows } = await client.query(
        'SELECT id, profile_id, what FROM ' + schema.quote(copy) + '.audit_events ORDER BY id',
      );
      const { rows: seq } = await client.query(
        "SELECT last_value, is_called FROM " + schema.quote(copy) + ".audit_events_id_seq",
      );
      console.log('   rows:     ' + JSON.stringify(rows.map((r) => r.id + ' | ' + r.what)));
      console.log('   sequence: last_value=' + seq[0].last_value + ' is_called=' + seq[0].is_called);
    };

    /* ---- node ---- */
    const byNode = APP + '_node';
    made.push(byNode);
    const nodePlan = await schema.readSchema(client, APP);
    await schema.writeSchema(client, nodePlan, byNode);
    const nodeCopy = await schema.readSchema(client, byNode);
    const nodeSown = await attack.seed(client, byNode, nodeCopy.tables);
    console.log('');
    console.log('NODE');
    console.log('   seeded:   ' + JSON.stringify(nodeSown.seeded));
    console.log('   skipped:  ' + JSON.stringify(nodeSown.skipped));
    await show('node', byNode);

    /* ---- sql ---- */
    const bySql = APP + '_sql';
    made.push(bySql);
    await sqlengine.withEngine(client, async (engine) => {
      const sqlPlan = await sqlengine.readSchema(client, engine, APP);
      await sqlengine.writeSchema(client, engine, sqlPlan, bySql);
      const sqlCopy = await sqlengine.readSchema(client, engine, bySql);
      const { rows } = await client.query(
        'SELECT ' + schema.quote(engine) + '.seed($1, $2::jsonb) AS sown',
        [bySql, JSON.stringify(sqlCopy.tables)],
      );
      console.log('');
      console.log('SQL');
      console.log('   seeded:   ' + JSON.stringify(rows[0].sown.seeded));
      console.log('   skipped:  ' + JSON.stringify(rows[0].sown.skipped));
    });
    await show('sql', bySql);

    /* ---- what each engine thought the column was ---- */
    console.log('');
    console.log('what each engine read the columns as:');
    const nodeCols = (nodeCopy.tables.find((t) => t.name === 'audit_events') || {}).columns || [];
    console.log('   node: ' + JSON.stringify(nodeCols.map((c) => c.name + ':' + c.type +
      (c.identity ? ' identity' : '') + (c.default_expr ? ' default=' + c.default_expr : ''))));
    await sqlengine.withEngine(client, async (engine) => {
      const sqlCopy = await sqlengine.readSchema(client, engine, bySql);
      const cols = (sqlCopy.tables.find((t) => t.name === 'audit_events') || {}).columns || [];
      console.log('   sql:  ' + JSON.stringify(cols.map((c) => c.name + ':' + c.type +
        (c.identity ? ' identity' : '') + (c.default_expr ? ' default=' + c.default_expr : ''))));
    });
  } finally {
    await client.query('SET search_path TO "$user", public').catch(() => {});
    for (const name of made.concat([APP])) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
    }
    await undoAuth();
    console.log('');
    console.log('cleaned up.');
    await client.end();
  }
}

main().catch((err) => {
  console.error('');
  console.error('  probe failed: ' + err.message);
  console.error('');
  process.exit(1);
});
