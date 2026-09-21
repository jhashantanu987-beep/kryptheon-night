// Why two tables out of four went unseeded on a real Supabase project.
//
// The report said:
//
//   notes  - insert or update on table "notes" violates foreign key
//            constraint "notes_owner_fkey"
//   orders - insert or update on table "orders" violates foreign key
//            constraint "orders_user_id_fkey"
//
// and both of those are the seed step, not an attack. `profiles` seeded fine -
// two rows came back to a stranger - so the parents those children point at
// existed. Which leaves the order they were seeded in.
//
// The same shape seeds without complaint on Neon, so nothing can be concluded
// from reading `dependencyOrder`. This builds the copy the way `scan.js` does
// and prints what actually happened, table by table.
//
//   KN_DATABASE_URL=postgresql://...  node probe-seedorder.js [schema]

const { Client } = require('pg');
const schema = require('./schema.js');
const attack = require('./attack.js');
const { howToConnect } = require('./connect.js');

const TARGET = process.argv[2] || 'public';

async function main() {
  if (!process.env.KN_DATABASE_URL) {
    console.error('  KN_DATABASE_URL=postgresql://...  node probe-seedorder.js [schema]');
    process.exit(2);
  }

  const client = new Client(howToConnect(process.env.KN_DATABASE_URL));
  await client.connect();
  const copyName = 'kn_' + Date.now().toString(36);

  try {
    const plan = await schema.readSchema(client, TARGET);
    console.log('');
    console.log('schema: ' + TARGET + '   tables: ' + plan.tables.length +
      '   policies: ' + plan.policies.length);
    console.log('external references replaced by stand-ins: ' +
      ((plan.external || []).map((e) => e.stub).join(', ') || 'none'));

    await schema.writeSchema(client, plan, copyName);
    const copyPlan = await schema.readSchema(client, copyName);

    const standIns = new Set((plan.external || []).map((entry) => entry.stub));
    const theirs = copyPlan.tables.filter((table) => !standIns.has(table.name));

    console.log('');
    console.log('what seed() is handed, in the order it reads them:');
    console.log('   ' + theirs.map((t) => t.name).join(', '));

    console.log('');
    console.log('the order it actually seeds in:');
    const ordered = attack.dependencyOrder ? attack.dependencyOrder(theirs) : null;
    if (!ordered) {
      console.log('   (dependencyOrder is not exported - add it to attack.js to see this)');
    } else {
      console.log('   ' + ordered.map((t) => t.name).join('  ->  '));
    }

    console.log('');
    console.log('who each table points at:');
    for (const table of theirs) {
      const refs = (table.constraints || [])
        .filter((c) => /FOREIGN KEY/i.test(String(c.definition || '')))
        .map((c) => String(c.definition).replace(/\s+/g, ' '));
      console.log('   ' + table.name.padEnd(10) + (refs.length ? refs.join(' ; ') : '(nothing)'));
      console.log('   ' + ' '.repeat(10) + 'owner column: ' + (attack.ownerColumn(table) || '(none)'));
    }

    const sown = await attack.seed(client, copyName, theirs);

    console.log('');
    console.log('seeded:');
    for (const entry of sown.seeded) {
      const { rows } = await client.query(
        'SELECT count(*)::int AS n FROM ' + schema.quote(copyName) + '.' + schema.quote(entry.table),
      );
      console.log('   ' + entry.table.padEnd(10) + rows[0].n + ' rows   (shape ' + entry.attempt + ')');
    }
    console.log('');
    console.log('NOT seeded:');
    for (const entry of sown.skipped) {
      console.log('   ' + entry.table.padEnd(10) + String(entry.why).replace(/\s+/g, ' '));
    }

    // What the children were actually asked to point at, against what the
    // parent has. This is the comparison the failure is about.
    console.log('');
    console.log('the two fake people:');
    console.log('   USER_A = ' + attack.USER_A);
    console.log('   USER_B = ' + attack.USER_B);
    for (const parent of ['profiles']) {
      if (!theirs.some((t) => t.name === parent)) continue;
      const { rows } = await client.query(
        'SELECT * FROM ' + schema.quote(copyName) + '.' + schema.quote(parent),
      );
      console.log('   ' + parent + ' holds: ' + JSON.stringify(rows.map((r) => r.id)));
    }
  } finally {
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(copyName) + ' CASCADE').catch(() => {});
    console.log('');
    console.log('copy deleted.');
    await client.end();
  }
}

main().catch((err) => {
  console.error('');
  console.error('  probe failed: ' + err.message);
  console.error('');
  process.exit(1);
});
