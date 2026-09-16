// Checks the report never says more than the attack saw.
// Run with:  node finding.check.js
//
// Overstating is the failure that matters here. A report that says "customer
// names, emails and phone numbers" about a table holding two integers is caught
// once and then believed never again - and the re-check at the end of the loop
// is worth exactly as much as the first report was honest.
//
// So most of what is checked below is restraint: no invented columns, no
// invented severity, no "personal details" where there are none.
//
// No database needed. Everything here is the shape the attack hands over.

const finding = require('./finding.js');

/** What attack.js produces, for a table holding real personal details. */
const CUSTOMERS_OPEN = {
  kind: 'exposed',
  table: 'customers',
  readable: 2,
  columns: ['id', 'owner', 'name', 'email', 'phone'],
  rlsEnabled: true,
};

/** The same shape, but nothing personal in it. */
const COUNTERS_OPEN = {
  kind: 'exposed',
  table: 'page_counters',
  readable: 4,
  columns: ['id', 'slug', 'views'],
  rlsEnabled: false,
};

const ORDERS_CROSSED = {
  kind: 'crossed',
  table: 'orders',
  owner: 'user_id',
  readable: 1,
  columns: ['id', 'user_id', 'total', 'status'],
  rlsEnabled: true,
};

const CREDENTIALS_OPEN = {
  kind: 'exposed',
  table: 'integrations',
  readable: 3,
  columns: ['id', 'provider', 'api_key'],
  rlsEnabled: false,
};

const cases = [
  {
    name: '1. an open table naming what is actually in it',
    run: () => {
      const d = finding.describe(CUSTOMERS_OPEN);
      const problems = [];
      if (d.severity !== 'CRITICAL') problems.push('severity is ' + d.severity);
      if (!/can be read by anyone/.test(d.headline)) problems.push('headline: ' + d.headline);
      if (!/customers/.test(d.headline)) problems.push('the headline does not name the table');
      if (!/without logging in/.test(d.body)) problems.push('it does not say no account was needed');
      for (const said of ['names', 'email addresses', 'phone numbers']) {
        if (!d.body.includes(said)) problems.push('it does not mention ' + said + ': ' + d.body);
      }
      if (!/2 rows/.test(d.body)) problems.push('it does not say how much came back: ' + d.body);
      return problems;
    },
  },
  {
    name: '2. nothing personal in the table, so nothing personal is claimed',
    run: () => {
      const d = finding.describe(COUNTERS_OPEN);
      const problems = [];
      // This is the one that matters. Inventing detail here is how a report
      // stops being believed.
      for (const invented of ['email', 'phone', 'name', 'address', 'password', 'personal']) {
        if (new RegExp(invented, 'i').test(d.body)) {
          problems.push('it claimed "' + invented + '" about a table of counters: ' + d.body);
        }
      }
      if (d.severity !== 'HIGH') problems.push('a table of view counts was rated ' + d.severity);
      if (!/4 rows/.test(d.body)) problems.push('it does not say what it read: ' + d.body);
      return problems;
    },
  },
  {
    name: '3. one customer reading another is described as that, not as a public leak',
    run: () => {
      const d = finding.describe(ORDERS_CROSSED);
      const problems = [];
      if (!/lets one customer read another/.test(d.headline)) problems.push('headline: ' + d.headline);
      if (/without logging in/.test(d.body)) {
        problems.push('it described a signed-in attack as a logged-out one: ' + d.body);
      }
      if (!/Signed in as one customer/.test(d.body)) problems.push('body: ' + d.body);
      if (!/Every customer you have can do this/.test(d.body)) {
        problems.push('it does not say this applies to everybody');
      }
      return problems;
    },
  },
  {
    name: '4. credentials are called credentials',
    run: () => {
      const d = finding.describe(CREDENTIALS_OPEN);
      const problems = [];
      if (d.severity !== 'CRITICAL') problems.push('an exposed api_key was rated ' + d.severity);
      if (!/access tokens/.test(d.body)) problems.push('it does not say tokens were readable: ' + d.body);
      return problems;
    },
  },
  {
    name: '5. the reason is the right one, and the two reasons differ',
    run: () => {
      const problems = [];
      // Switched on but permissive: the dashboard shows this table as green,
      // which is why saying so matters.
      const looksProtected = finding.describe(CUSTOMERS_OPEN);
      if (!/looks protected/.test(looksProtected.cause)) problems.push('cause: ' + looksProtected.cause);
      if (!/dashboard/.test(looksProtected.cause)) {
        problems.push('it does not explain why nothing flagged it: ' + looksProtected.cause);
      }
      // Never switched on at all is a different conversation.
      const neverOn = finding.describe(COUNTERS_OPEN);
      if (!/never been switched on/.test(neverOn.cause)) problems.push('cause: ' + neverOn.cause);
      if (looksProtected.cause === neverOn.cause) problems.push('both causes read the same');
      return problems;
    },
  },
  {
    name: '6. the fix can be pasted somewhere else and still make sense',
    run: () => {
      const prompt = finding.fixPromptFor(ORDERS_CROSSED);
      const problems = [];
      if (!prompt.includes('"orders"')) problems.push('it does not name the table:\n' + prompt);
      if (!prompt.includes('"user_id"')) problems.push('it does not name the owner column:\n' + prompt);
      if (!/same mistake on every other table/.test(prompt)) {
        problems.push('it does not ask for the rest of the app to be checked');
      }
      // It is read by an assistant that has seen none of this, so it cannot
      // lean on anything said elsewhere.
      for (const leaning of ['above', 'the finding', 'as mentioned', 'this report']) {
        if (prompt.toLowerCase().includes(leaning)) problems.push('it refers to context it does not carry: ' + leaning);
      }
      if (prompt.length > 700) problems.push('it is ' + prompt.length + ' characters, too long to read');

      // A table with no owner column still has to produce a usable prompt.
      const noOwner = finding.fixPromptFor(COUNTERS_OPEN);
      if (/undefined|null|""/.test(noOwner)) problems.push('an unnamed owner leaked through:\n' + noOwner);
      return problems;
    },
  },
  {
    name: '7. the worst thing is first',
    run: () => {
      const all = finding.describeAll([COUNTERS_OPEN, ORDERS_CROSSED, CUSTOMERS_OPEN, CREDENTIALS_OPEN]);
      const problems = [];
      if (all.length !== 4) problems.push('described ' + all.length + ' of 4');
      if (all[0].severity !== 'CRITICAL') problems.push('the first thing shown is ' + all[0].severity);
      if (all[all.length - 1].severity !== 'HIGH') problems.push('the last thing shown is not the least bad');
      // Among equals, the one open to the whole internet comes before the one
      // that needs an account.
      const criticals = all.filter((d) => d.severity === 'CRITICAL');
      const firstCrossed = criticals.findIndex((d) => d.kind === 'crossed');
      const lastExposed = criticals.map((d) => d.kind).lastIndexOf('exposed');
      if (firstCrossed !== -1 && firstCrossed < lastExposed) {
        problems.push('a signed-in leak was shown above a public one');
      }
      return problems;
    },
  },
  {
    name: '8. a clean run says so, rather than saying nothing',
    run: () => {
      const lines = finding.allClearLines(340).join('\n');
      const problems = [];
      if (!/Nothing got through/.test(lines)) problems.push('it does not say the app held: ' + lines);
      if (!/340 attacks/.test(lines)) problems.push('it does not say how much work was done: ' + lines);
      if (!finding.allClearLines(1).join('\n').includes('1 attack')) problems.push('it says "1 attacks"');
      // Silence on a quiet night is how a subscription starts feeling like
      // nothing is happening.
      if (!lines.trim()) problems.push('it printed nothing at all');
      return problems;
    },
  },
  {
    name: '9. it describes only what it was given',
    run: () => {
      // A table of two meaningless columns, to catch anything hardcoded.
      const bare = finding.describe({
        kind: 'exposed',
        table: 'widgets',
        readable: 1,
        columns: ['a', 'b'],
        rlsEnabled: false,
      });
      const problems = [];
      const contents = finding.readContents(['a', 'b']);
      if (contents.identity.length || contents.secrets.length || contents.money.length) {
        problems.push('it found meaning in columns called a and b: ' + JSON.stringify(contents));
      }
      if (!/1 row\b/.test(bare.body)) problems.push('it did not say "1 row": ' + bare.body);
      if (/rows,/.test(bare.body)) problems.push('it pluralised a single row: ' + bare.body);
      if (!bare.proof.includes('widgets')) problems.push('the proof does not name the table: ' + bare.proof);
      return problems;
    },
  },
  {
    name: '10. a column that merely looks like a word is not mistaken for one',
    run: () => {
      const problems = [];
      // `renamed_at` contains "name", `tokenised` contains "token". Matching on
      // fragments would turn a timestamp into a privacy incident.
      const contents = finding.readContents(['renamed_at', 'tokenised_flag', 'emailed']);
      if (contents.identity.length) problems.push('renamed_at was read as a name: ' + JSON.stringify(contents));
      if (contents.secrets.length) problems.push('tokenised_flag was read as a token: ' + JSON.stringify(contents));
      // And the real ones still match.
      const real = finding.readContents(['email', 'full_name', 'api_key']);
      if (real.identity.length !== 2) problems.push('it missed real identity columns: ' + JSON.stringify(real));
      if (real.secrets.length !== 1) problems.push('it missed a real secret: ' + JSON.stringify(real));
      return problems;
    },
  },
  {
    name: '11. a table open to everyone is reported once, not twice',
    run: () => {
      // The attack legitimately returns both: anyone can read it, and one
      // customer can read another. For a reader they are one problem.
      const both = [
        { kind: 'exposed', table: 'customers', readable: 2, columns: ['id', 'owner', 'email'], rlsEnabled: true },
        { kind: 'crossed', table: 'customers', owner: 'owner', readable: 1, columns: ['id', 'owner', 'email'], rlsEnabled: true },
      ];
      const all = finding.describeAll(both);
      const problems = [];
      if (all.length !== 1) problems.push('the same table was listed ' + all.length + ' times');
      if (all.length && all[0].kind !== 'exposed') problems.push('it kept the weaker of the two');
      // But it must still say the customer-to-customer part out loud.
      if (all.length && !/each other/.test(all[0].body)) {
        problems.push('it dropped the fact without saying it: ' + all[0].body);
      }
      // A crossed finding on its own is untouched.
      const alone = finding.describeAll([both[1]]);
      if (alone.length !== 1) problems.push('a lone crossed finding was swallowed');
      if (alone.length && /each other/.test(alone[0].body)) problems.push('it added the merge note with nothing to merge');
      return problems;
    },
  },
  {
    name: '12. the headline reads properly whatever the table is called',
    run: () => {
      const problems = [];
      for (const table of ['customers', 'orders', 'rows', 'data']) {
        const d = finding.describe({
          kind: 'crossed', table: table, owner: 'owner', readable: 1, columns: ['owner'], rlsEnabled: true,
        });
        // "another customer's customers" was the line this replaced.
        if (/customer's customers|another one's rows in/.test(d.headline)) {
          problems.push('it reads badly for ' + table + ': ' + d.headline);
        }
        // Two wrong rules preceded this one. Counting how often the table name
        // appears failed on a table called `rows`, and so did looking for it
        // after a possessive - because "another one's rows" ends in a fixed
        // word, not in the table name. The property that actually holds is
        // simpler: the name is substituted in exactly one place, at the front,
        // and the old broken shape never comes back.
        if (d.headline.indexOf('Your ' + table + ' table') !== 0) {
          problems.push('the table is not named at the front: ' + d.headline);
        }
        if (d.headline.includes("customer's " + table)) {
          problems.push('the table name landed in the possessive: ' + d.headline);
        }
      }
      return problems;
    },
  },
  {
    name: '13. nothing in the fix is too wide to read',
    run: () => {
      const problems = [];
      for (const f of [CUSTOMERS_OPEN, ORDERS_CROSSED, COUNTERS_OPEN]) {
        const long = finding.fixPromptFor(f)
          .split(String.fromCharCode(10))
          .filter((l) => l.length > 78);
        if (long.length) {
          problems.push(f.table + ' has ' + long.length + ' line(s) over 78 characters: ' + long[0]);
        }
      }
      // And wrapping must not have broken the content.
      const prompt = finding.fixPromptFor(ORDERS_CROSSED);
      if (!prompt.includes('"orders"')) problems.push('wrapping lost the table name');
      if (!prompt.includes('"user_id"')) problems.push('wrapping lost the owner column');
      return problems;
    },
  },
];

let failures = 0;
for (const c of cases) {
  let problems;
  try {
    problems = c.run();
  } catch (err) {
    problems = ['it threw: ' + err.message];
  }
  if (problems.length) {
    failures++;
    console.log('FAIL  ' + c.name);
    problems.forEach((p) => console.log('      - ' + p));
  } else {
    console.log('PASS  ' + c.name);
  }
}

console.log('');
if (failures) {
  console.log(failures + ' check(s) failed.');
  process.exit(1);
}
console.log('All ' + cases.length + ' report checks passed.');
