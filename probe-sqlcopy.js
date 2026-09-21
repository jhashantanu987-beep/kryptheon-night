// Does the SQL engine borrow the customer's tables too?
//
// The Node engine did, on every app that lives in a schema that is on the
// search_path - which is every real app, and no fixture in this repo. Fixed
// today in schema.js. engine.sql has the same two rewrites and, read rather
// than run, appears to have neither the bare-reference qualification nor the
// guard that catches what a rewrite misses.
//
// Reading is not deciding. This builds a copy with the SQL engine from a
// schema that IS on the search_path, and asks pg_constraint where it ended up
// pointing - the same question that exposed the Node one.
//
//   KN_DATABASE_URL=postgresql://...  node probe-sqlcopy.js

const { Client } = require('pg');
const schema = require('./schema.js');
const sqlengine = require('./sqlengine.js');
const { howToConnect } = require('./connect.js');

const APP = 'kn_sqlprobe_' + Date.now().toString(36);

async function main() {
  if (!process.env.KN_DATABASE_URL) {
    console.error('  KN_DATABASE_URL=postgresql://...  node probe-sqlcopy.js');
    process.exit(2);
  }

  const client = new Client(howToConnect(process.env.KN_DATABASE_URL));
  await client.connect();

  const q = (name) => schema.quote(APP) + '.' + schema.quote(name);
  const madeCopies = [];

  try {
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    await client.query('CREATE TABLE ' + q('parents') + ' (id uuid PRIMARY KEY, email text NOT NULL)');
    await client.query('CREATE TABLE ' + q('children') +
      ' (id bigserial PRIMARY KEY, owner uuid NOT NULL REFERENCES ' + q('parents') +
      '(id), body text NOT NULL)');

    // The one line that makes this a real app rather than a fixture. With the
    // app's schema on the path, pg_get_constraintdef stops writing the schema
    // name and the rewrites have nothing to rewrite.
    await client.query('SET search_path TO ' + schema.quote(APP) + ', public');

    const where = async (copy) => {
      const { rows } = await client.query(
        `SELECT con.conname, rn.nspname AS points_at
           FROM pg_constraint con
           JOIN pg_class cl ON cl.oid = con.conrelid
           JOIN pg_namespace cn ON cn.oid = cl.relnamespace
           JOIN pg_class rc ON rc.oid = con.confrelid
           JOIN pg_namespace rn ON rn.oid = rc.relnamespace
          WHERE con.contype = 'f' AND cn.nspname = $1`,
        [copy],
      );
      return rows;
    };

    /* ---- the node engine, which was fixed today ---- */
    const byNode = 'kn_node_' + Date.now().toString(36);
    madeCopies.push(byNode);
    const nodePlan = await schema.readSchema(client, APP);
    console.log('');
    console.log('what the node engine read the foreign key as:');
    for (const table of nodePlan.tables) {
      for (const c of (table.constraints || []).filter((x) => x.kind === 'f')) {
        console.log('   ' + table.name + ': ' + c.definition);
      }
    }
    await schema.writeSchema(client, nodePlan, byNode);
    console.log('');
    console.log('NODE engine copy points at:');
    for (const row of await where(byNode)) {
      console.log('   ' + row.conname.padEnd(22) + ' -> ' + row.points_at +
        (row.points_at === byNode ? '   (inside the copy)' : '   <-- OUTSIDE'));
    }

    /* ---- the sql engine, which has not been ---- */
    const bySql = 'kn_sql_' + Date.now().toString(36);
    madeCopies.push(bySql);
    await sqlengine.withEngine(client, async (engine) => {
      const sqlPlan = await sqlengine.readSchema(client, engine, APP);
      await sqlengine.writeSchema(client, engine, sqlPlan, bySql);
    });
    console.log('');
    console.log('SQL engine copy points at:');
    for (const row of await where(bySql)) {
      console.log('   ' + row.conname.padEnd(22) + ' -> ' + row.points_at +
        (row.points_at === bySql ? '   (inside the copy)' : '   <-- OUTSIDE'));
    }
  } finally {
    await client.query('SET search_path TO "$user", public').catch(() => {});
    for (const name of madeCopies.concat([APP])) {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE').catch(() => {});
    }
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
