// Checks that a copy of a backend is the backend.
// Run with:  node schema.check.js "<postgres connection string>"
//
// Everything the night shift reports is a statement about a copy. If the copy
// differs from the original in any way that matters, every verdict is about a
// database nobody is running - and the failure is silent, because a wrong
// answer looks exactly like a right one.
//
// So the last case is the one that counts: the same attack is run against the
// original and against the copy, and the two have to agree exactly. Comparing
// the schemas is not enough on its own. Two schemas can look alike and behave
// differently, and behaviour is what is being sold.
//
// A small app is built here on purpose, with two tables done properly and two
// done the way they come out when nobody checked:
//
//   profiles     policy: id = auth.uid()          correct
//   orders       policy: user_id = auth.uid()     correct
//   customers    row level security ON, policy USING (true)
//                - looks protected in the dashboard, open to the world
//   app_settings row level security never switched on, granted to anon
//
// Nothing survives the run: both schemas are dropped at the end, whatever
// happened.

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const attack = require('./attack.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

// Undoes only the auth schema this run created, and only if it created it.
let undoAuth = async () => {};

const SOURCE = 'kn_src_' + Date.now();
const COPY = 'kn_copy_' + Date.now();

const TABLES_EXPECTED_BAD = ['customers', 'app_settings'];
const TABLES_EXPECTED_SAFE = ['profiles', 'orders'];

/** The app a builder ends up with after a few weeks of shipping fast. */
async function buildSourceApp(client) {
  await client.query('CREATE SCHEMA ' + schema.quote(SOURCE));

  for (const role of ['anon', 'authenticated']) {
    await client.query(
      "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') " +
        'THEN CREATE ROLE ' + role + ' NOLOGIN; END IF; END $$;',
    );
    await client.query('GRANT ' + role + ' TO current_user');
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(SOURCE) + ' TO ' + role);
  }

  // The auth.uid() a real Supabase project has, so the policies below are
  // written exactly as a real one would write them.
  undoAuth = await fixture.ensureAuth(client);

  const q = (name) => schema.quote(SOURCE) + '.' + schema.quote(name);

  await client.query(
    'CREATE TABLE ' + q('profiles') + ' (id uuid PRIMARY KEY, email text NOT NULL, full_name text)',
  );
  await client.query(
    'CREATE TABLE ' + q('orders') +
      ' (id serial PRIMARY KEY, user_id uuid NOT NULL REFERENCES ' + q('profiles') + '(id),' +
      ' total numeric(10,2) NOT NULL,' +
      " status text NOT NULL DEFAULT 'new')",
  );
  await client.query(
    'CREATE TABLE ' + q('customers') +
      ' (id serial PRIMARY KEY, owner uuid NOT NULL, name text NOT NULL, email text NOT NULL, phone text)',
  );
  await client.query(
    'CREATE TABLE ' + q('app_settings') + ' (id serial PRIMARY KEY, key text NOT NULL, value text)',
  );

  for (const table of ['profiles', 'orders', 'customers', 'app_settings']) {
    await client.query('GRANT SELECT ON ' + q(table) + ' TO anon, authenticated');
  }

  // Done properly.
  await client.query('ALTER TABLE ' + q('profiles') + ' ENABLE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY own_profile ON ' + q('profiles') + ' FOR SELECT TO authenticated USING (id = auth.uid())',
  );
  await client.query('ALTER TABLE ' + q('orders') + ' ENABLE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY own_orders ON ' + q('orders') + ' FOR SELECT TO authenticated USING (user_id = auth.uid())',
  );

  // Switched on, and then handed to everybody. The dashboard shows a green
  // shield next to this table.
  await client.query('ALTER TABLE ' + q('customers') + ' ENABLE ROW LEVEL SECURITY');
  await client.query(
    'CREATE POLICY read_customers ON ' + q('customers') + ' FOR SELECT TO anon, authenticated USING (true)',
  );

  // Never switched on at all.
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  No database to check against.');
    console.error('    node schema.check.js "postgresql://user:pass@host/db?sslmode=require"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();

  const results = [];
  // Each case is run inside its own guard. A case that throws used to take
  // the whole run with it - results are printed at the end, so one bad line
  // in the last check discarded the seven before it and the output was a
  // single "could not run". A crash is a failure of that case, not of the run.
  const record = (name, run) => {
    let problems;
    try {
      problems = run();
    } catch (err) {
      problems = ['it threw: ' + err.message];
    }
    results.push({ name: name, problems: problems });
  };

  try {
    await buildSourceApp(client);

    // ---- read, copy, and compare ----
    const plan = await schema.readSchema(client, SOURCE);
    record('1. the app is read: four tables, three policies, nothing unsupported', () => {
      const problems = [];
      if (plan.tables.length !== 4) problems.push('read ' + plan.tables.length + ' tables, expected 4');
      if (plan.policies.length !== 3) problems.push('read ' + plan.policies.length + ' policies, expected 3');
      if (plan.unsupported.length) problems.push('could not handle: ' + plan.unsupported.join('; '));
      // The shapes that matter to the attack.
      const open = plan.tables.find((t) => t.name === 'app_settings');
      if (open && open.rlsEnabled) problems.push('app_settings should have row level security off');
      const guarded = plan.tables.find((t) => t.name === 'orders');
      if (guarded && !guarded.rlsEnabled) problems.push('orders should have row level security on');
      return problems;
    });

    const statements = await schema.writeSchema(client, plan, COPY);
    const copyPlan = await schema.readSchema(client, COPY);

    record('2. the copy is the original, policy for policy', () => {
      const differences = schema.diffSchemas(plan, copyPlan);
      return differences.length ? differences : [];
    });

    record('3. nothing was copied that should not have been', () => {
      const problems = [];
      // Data is never copied. That is the promise, so it is checked, not assumed.
      const written = statements.join(' ').toUpperCase();
      if (written.includes('INSERT INTO')) problems.push('the copy carried data across');
      if (written.includes('COPY ')) problems.push('the copy used COPY, which moves data');

      // Nothing in the copy may point back at the app. A foreign key came
      // across unrewritten once, because Postgres writes a schema name
      // unquoted when it can - and the copy was created holding a live
      // reference into the customer's real tables. Postgres would then have
      // checked their data on every insert, which is the promise broken in
      // the one direction nobody would notice.
      const pointsHome = statements.filter((line) => line.includes(SOURCE));
      if (pointsHome.length) {
        problems.push('the copy references the app it was copied from:' + String.fromCharCode(10) + '      ' + pointsHome.join(String.fromCharCode(10) + '      '));
      }
      return problems;
    });

    // ---- seed both, attack both ----
    const sownSource = await attack.seed(client, SOURCE, plan.tables);
    const sownCopy = await attack.seed(client, COPY, copyPlan.tables);

    const runSource = await attack.impersonate(client, SOURCE, plan.tables);
    const runCopy = await attack.impersonate(client, COPY, copyPlan.tables);
    const onSource = runSource.findings;
    const onCopy = runCopy.findings;

    record('4. the attack finds the two broken tables, and only those', () => {
      const problems = [];
      const named = [...new Set(onSource.map((f) => f.table))].sort();
      for (const bad of TABLES_EXPECTED_BAD) {
        if (!named.includes(bad)) problems.push(bad + ' is broken and was not found');
      }
      for (const safe of TABLES_EXPECTED_SAFE) {
        if (named.includes(safe)) {
          const why = onSource.filter((f) => f.table === safe).map((f) => f.kind).join(', ');
          problems.push(safe + ' is correct and was reported anyway (' + why + ')');
        }
      }
      return problems;
    });

    record('5. one customer reading another customer is seen, not just the open door', () => {
      const problems = [];
      const crossed = onSource.filter((f) => f.kind === 'crossed').map((f) => f.table);
      if (!crossed.includes('customers')) {
        problems.push('nobody noticed one customer can read another: ' + JSON.stringify(onSource, null, 1));
      }
      const exposed = onSource.filter((f) => f.kind === 'exposed').map((f) => f.table).sort();
      if (!exposed.includes('app_settings')) problems.push('a table with no row level security was not reported');
      return problems;
    });

    record('6. the copy gives the same verdict as the original', () => {
      const a = attack.summarise(runSource);
      const b = attack.summarise(runCopy);
      if (a === b) return [];
      return [
        'the copy behaves differently, so every finding would be about the wrong database:',
        '  original: ' + (a || '(nothing)'),
        '  copy    : ' + (b || '(nothing)'),
      ];
    });

    record('7. a correct policy still holds on the copy', () => {
      // The inverse of case 6: it would be easy to make both agree by breaking
      // both. The copy has to protect what the original protects.
      const problems = [];
      const copyNamed = [...new Set(onCopy.map((f) => f.table))];
      for (const safe of TABLES_EXPECTED_SAFE) {
        if (copyNamed.includes(safe)) problems.push(safe + ' is protected on the original but not on the copy');
      }
      if (!onCopy.length) problems.push('the copy reported nothing at all, so it is not being attacked');
      return problems;
    });
    record('8. the comparison itself notices a difference when there is one', () => {
      // Case 2 asks the comparison whether the copy is faithful, and believes
      // the answer. A comparison that always said "no differences" would sail
      // through it - and through every future copy, for ever. So it is asked
      // about copies that are known to be wrong.
      const problems = [];
      // Cloned from the source, deliberately, not from the copy. This case
      // asks whether the comparison can see a difference at all - if it drew
      // its material from the copy, then breaking the copy would leave it
      // with nothing to break, and it would crash instead of reporting.
      const clone = () => JSON.parse(JSON.stringify(plan));

      const check = (label, breakIt) => {
        const broken = clone();
        breakIt(broken);
        // A test that breaks nothing proves nothing, and reads as a pass. The
        // first version of this rewrote a policy's rule to `true` - and picked
        // the one table whose rule was already `true`, so it changed nothing
        // and reported the comparison as blind.
        if (JSON.stringify(broken) === JSON.stringify(clone())) {
          problems.push('the case for "' + label + '" altered nothing, so it tested nothing');
          return;
        }
        if (!schema.diffSchemas(plan, broken).length) {
          problems.push('it did not notice ' + label);
        }
      };

      check('a policy whose rule was rewritten', (s) => {
        const policy = s.policies.find((p) => p.qual && p.qual !== 'true');
        policy.qual = 'true';
      });
      check('a policy that went missing', (s) => {
        s.policies.pop();
      });
      check('a policy renamed', (s) => {
        s.policies[0].name = s.policies[0].name + '_x';
      });
      check('row level security switched off', (s) => {
        const table = s.tables.find((t) => t.rlsEnabled);
        table.rlsEnabled = false;
      });
      check('a table that went missing', (s) => {
        s.tables.pop();
      });
      check('a column with a different type', (s) => {
        s.tables[0].columns[0].type = 'text';
      });
      check('a policy handed to a different role', (s) => {
        const policy = s.policies[0];
        policy.roles = '{anon,authenticated,service_role}';
      });

      // And the other half: an honest copy must not be reported as different,
      // or every run would cry wolf and nobody would look at the real ones.
      const untouched = schema.diffSchemas(plan, clone());
      if (untouched.length) {
        problems.push('it reported differences in an identical copy: ' + untouched.join(' | '));
      }
      return problems;
    });
    record('9. every table was actually seeded, on both sides', () => {
      // A table with no row in it reads as a safe table. If seeding ever
      // starts failing quietly, every check above would still pass while the
      // scan reported an app as clear without having tried it.
      const problems = [];
      for (const [label, sown] of [["the app", sownSource], ["the copy", sownCopy]]) {
        if (sown.skipped.length) {
          problems.push(label + ' skipped ' + sown.skipped.map((s2) => s2.table + ' (' + s2.why + ')').join(', '));
        }
        if (sown.seeded.length !== 4) {
          problems.push(label + ' seeded ' + sown.seeded.length + ' tables, expected 4');
        }
      }
      return problems;
    });
  } finally {
    for (const name of [COPY, SOURCE]) {
      try {
        await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(name) + ' CASCADE');
      } catch (e) {
        console.error('could not drop ' + name + ': ' + e.message);
      }
    }
    await undoAuth();
    await client.end();
  }

  console.log('');
  let failures = 0;
  for (const result of results) {
    if (result.problems.length) {
      failures++;
      console.log('FAIL  ' + result.name);
      result.problems.forEach((p) => console.log('      - ' + p));
    } else {
      console.log('PASS  ' + result.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exitCode = 1;
  } else {
    console.log('All ' + results.length + ' copy checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
