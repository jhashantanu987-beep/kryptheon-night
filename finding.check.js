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
    // Blind test (StudyNest): profiles readable by anyone, holding
    // display_name, is_admin and a moderator_code added in production - and
    // the report said only "got back 2 rows".
    name: '10b. a code that grants something, who is an admin, and compound names are named, with their columns',
    run: () => {
      const problems = [];
      const d = finding.describe({
        kind: 'exposed', table: 'profiles', readable: 2, rlsEnabled: true,
        columns: ['id', 'display_name', 'bio', 'is_admin', 'created_at', 'moderator_code'],
      });
      if (d.severity !== 'CRITICAL') problems.push('severity ' + d.severity + ' - a readable moderator_code is someone becoming a moderator');
      for (const said of ['secret codes (moderator_code)', 'who is an admin (is_admin)', 'names (display_name)']) {
        if (!d.body.includes(said)) problems.push('the body does not say "' + said + '": ' + d.body);
      }
      // Codes that grant nothing, and look-alikes of the admin flag.
      const plain = finding.readContents(['zip_code', 'country_code', 'postal_code', 'promo_code', 'status_code', 'error_code', 'code', 'product_name', 'admin_notes', 'roles_updated_at', 'emailed_admin']);
      if (plain.secrets.length) problems.push('an ordinary code was read as a secret: ' + JSON.stringify(plain.secrets));
      if (plain.privilege.length) problems.push('a look-alike was read as the admin flag: ' + JSON.stringify(plain.privilege));
      if (plain.identity.length) problems.push('product_name was read as a person\'s name: ' + JSON.stringify(plain.identity));
      // Who is an admin, alone, is said but does not make a table CRITICAL.
      const flags = finding.describe({ kind: 'exposed', table: 'flags', readable: 1, rlsEnabled: true, columns: ['id', 'is_admin'] });
      if (flags.severity !== 'HIGH') problems.push('a table holding only is_admin was ' + flags.severity);
      if (!/who is an admin \(is_admin\)/.test(flags.body)) problems.push('is_admin alone was not named: ' + flags.body);
      const otp = finding.readContents(['otp', 'reset_code', 'user_invite_code']);
      if (otp.secrets.length !== 1 || !/otp, reset_code, user_invite_code/.test(otp.secrets[0])) problems.push('real codes missed: ' + JSON.stringify(otp.secrets));
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
  {
    name: '14. why a write got through is read off the rules, not assumed',
    run: () => {
      // Found on a real database. A waitlist whose only policy was written
      // FOR INSERT was described as having a rule that "covers every command
      // rather than only reading - so the same rule that lets people see the
      // rows also lets them change them". It covered one command, and no rule
      // let anybody read anything. The attack was real; the explanation was
      // invented, which is the failure this whole file exists to catch.
      const writable = (rules, can) => ({
        kind: 'writable',
        table: 'waitlist',
        who: 'anyone',
        can: can || ['add'],
        changed: { add: 1 },
        owner: null,
        columns: ['id', 'email'],
        rlsEnabled: true,
        rules: rules,
      });
      const problems = [];

      const insertOnly = finding.causeOf(writable(['INSERT']));
      if (/every command/i.test(insertOnly.short + insertOnly.long)) {
        problems.push('a FOR INSERT policy was described as covering every command');
      }
      if (/see the rows|read/i.test(insertOnly.long)) {
        problems.push('a write-only policy was described as letting people read: ' + insertOnly.long);
      }
      if (!/adding rows/.test(insertOnly.short)) {
        problems.push('it does not name which rule let the write through: ' + insertOnly.short);
      }

      // FOR ALL genuinely does cover reads and writes, and must still say so.
      const forAll = finding.causeOf(writable(['ALL'], ['add', 'change', 'delete']));
      if (!/every command|FOR ALL/i.test(forAll.short + forAll.long)) {
        problems.push('a FOR ALL policy was not described as covering every command');
      }

      // Only the commands that actually got through are named. A rule for
      // deleting is not the reason an insert landed.
      const two = finding.causeOf(writable(['INSERT', 'DELETE'], ['add']));
      if (/deleting rows/.test(two.short)) {
        problems.push('it blamed a rule for a write that never got through: ' + two.short);
      }

      // Nothing on the table names this write, so there is no rule to blame
      // and none may be invented.
      for (const rules of [[], ['SELECT']]) {
        const nothing = finding.causeOf(writable(rules));
        if (/the rule you wrote|every command/i.test(nothing.short + nothing.long)) {
          problems.push('with rules ' + JSON.stringify(rules) + ' it invented a rule: ' + nothing.short);
        }
      }

      // A restrictive policy can only narrow what is allowed, so it is never
      // the reason a write succeeded - it must never be blamed for one.
      const restrictive = finding.causeOf(writable([]));
      if (/lets everybody through/.test(restrictive.short)) {
        problems.push('a table with no permissive rule was said to have one');
      }

      // And with row level security off, none of this applies at all.
      const off = finding.causeOf(Object.assign(writable([]), { rlsEnabled: false }));
      if (!/never switched on/.test(off.short)) {
        problems.push('row level security being off was not given as the reason: ' + off.short);
      }
      return problems;
    },
  },
  {
    name: 'an anon-callable definer function is reported as verification-required, never as proven',
    run: () => {
      const problems = [];
      const writes = finding.describe({ kind: 'privileged', fn: 'claim', args: 'k text', writes: true, hasFixedSearchPath: true, columns: [] });
      const reads = finding.describe({ kind: 'privileged', fn: 'peek', args: '', writes: false, hasFixedSearchPath: false, columns: [] });
      if (writes.status !== 'verification required') problems.push('status was ' + writes.status);
      if (writes.severity !== 'HIGH') problems.push('severity was ' + writes.severity + ', expected HIGH (never CRITICAL - it was not run)');
      if (writes.table !== 'claim') problems.push('the function name is not the headline subject: ' + writes.table);
      // Never claim it was executed.
      if (/\bI (ran|called|inserted|read)\b/.test(writes.body)) problems.push('the body claims it did something: ' + writes.body);
      if (!/did not call/.test(writes.proof)) problems.push('the proof does not say it was not executed: ' + writes.proof);
      // Writes vs reads changes the words, not the verdict.
      if (!/writes to your data/.test(writes.body)) problems.push('a writing function does not say so');
      if (/writes to your data/.test(reads.body)) problems.push('a read-only function was said to write');
      // The missing search_path is raised only when it is missing.
      if (!/search_path/.test(reads.body)) problems.push('a function with no fixed search_path did not mention it');
      if (/search_path/.test(writes.body)) problems.push('a function with a fixed search_path was warned about it anyway');
      // The fix names the revoke and includes PUBLIC, not just anon.
      if (!/REVOKE EXECUTE ON FUNCTION "claim"/.test(writes.fixPrompt)) problems.push('the fix does not name the revoke');
      if (!/FROM anon, PUBLIC/.test(writes.fixPrompt)) problems.push('the fix revokes from anon but forgets PUBLIC');
      if (!/service_role/.test(writes.fixPrompt)) problems.push('the fix does not point at service_role');
      if (!/check it rather than assume/.test(writes.fixPrompt)) problems.push('the prompt does not tell the assistant to verify first');
      return problems;
    },
  },
  {
    name: 'a run whose only finding needs verification does not exit as "something got through"',
    run: () => {
      const { exitCodeFor } = require('./scan.js');
      const problems = [];
      const toCheck = { status: 'verification required' };
      const proven = { status: 'confirmed' };
      if (exitCodeFor({ stopped: null, findings: [toCheck] }) !== 0) problems.push('only a to-check item exited non-zero');
      if (exitCodeFor({ stopped: null, findings: [toCheck, proven] }) !== 1) problems.push('a confirmed break next to a to-check item did not exit 1');
      if (exitCodeFor({ stopped: null, findings: [] }) !== 0) problems.push('a clean run did not exit 0');
      if (exitCodeFor({ stopped: 'could not connect', findings: [] }) !== 2) problems.push('a run that could not happen did not exit 2');
      return problems;
    },
  },
  {
    name: 'a definer finding does not crowd out or get crowded out by a real one',
    run: () => {
      const all = finding.describeAll([
        { kind: 'privileged', fn: 'claim', args: '', writes: true, hasFixedSearchPath: true, columns: [] },
        CUSTOMERS_OPEN,
      ]);
      const problems = [];
      const priv = all.find((d) => d.kind === 'privileged');
      const open = all.find((d) => d.kind === 'exposed');
      if (!priv || !open) return ['one of the two findings was dropped: ' + JSON.stringify(all.map((d) => d.kind))];
      // The proven, public leak ranks above the unproven reach.
      if (all.indexOf(open) > all.indexOf(priv)) problems.push('the verification-required item was listed above a confirmed leak');
      return problems;
    },
  },
  {
    name: 'a duplicate email where sign-in happens elsewhere is not called a shared login',
    run: () => {
      const problems = [];
      const dup = (extra) => finding.describe(Object.assign({
        kind: 'duplicated', table: 'profiles', column: 'email', copies: 2,
        expectation: 'identity', columns: ['id', 'email'],
      }, extra));
      const copy = dup({ loginElsewhere: true });
      const login = dup({ loginElsewhere: false });
      if (copy.severity !== 'HIGH') problems.push('with auth.users present it said ' + copy.severity);
      if (/same login|password reset/i.test(copy.body)) problems.push('it still claims a shared login: ' + copy.body);
      if (!/Signing in is not affected/.test(copy.body)) problems.push('it does not say sign-in is unaffected');
      // Without auth.users this column may really be the login, and the
      // stronger claim stays.
      if (login.severity !== 'CRITICAL') problems.push('without auth.users it said ' + login.severity);
      if (!/same login/.test(login.body)) problems.push('the login cost disappeared where it applies');
      return problems;
    },
  },
  {
    name: 'the duplicate fix prompt protects existing data and the flows that write the column',
    run: () => {
      const problems = [];
      const make = (expectation, extra) => finding.describe(Object.assign({
        kind: 'duplicated', table: 't', column: expectation === 'identity' ? 'email' : 'token',
        copies: 2, expectation: expectation, columns: ['id'],
      }, extra)).fixPrompt.replace(/\s+/g, ' ');
      const identity = make('identity', { loginElsewhere: true });
      const credential = make('credential');
      for (const [name, p] of [['identity', identity], ['credential', credential]]) {
        const find = p.indexOf('find the rows that already share a value');
        const add = p.search(/add a unique (constraint|index)/i);
        if (find === -1) problems.push(name + ': it never asks for existing duplicates first');
        else if (add !== -1 && find > add) problems.push(name + ': it asks for the constraint before checking existing rows');
        if (!/Do not delete or merge/.test(p)) problems.push(name + ': it does not forbid deleting rows to make it pass');
        if (!/trigger or function/.test(p)) problems.push(name + ': it does not send the assistant to what writes the column');
        if (!/sign up a brand-new account/.test(p)) problems.push(name + ': it asks for no test afterwards');
      }
      if (!/lower\("email"\)/.test(identity)) problems.push('an email is not made case-insensitive');
      if ((identity.match(/add a unique/gi) || []).length !== 1) problems.push('the identity prompt asks for more than one rule');
      if (/lower\(/.test(credential)) problems.push('a credential was lower-cased - tokens are case-sensitive');
      if (!/only a copy of the email/.test(identity)) problems.push('it does not say the column copies auth.users');
      return problems;
    },
  },
  {
    // Six CRITICAL findings for two rules, on a real app: read by strangers,
    // written by strangers, written by customers - all one FOR ALL USING (true).
    name: 'one table, one finding: read and write proofs of one rule are said once, and kept inside',
    run: () => {
      const problems = [];
      const cols = ['id', 'email', 'password_hash', 'name'];
      const all = finding.describeAll([
        { kind: 'exposed', table: 'users', readable: 1, columns: cols, rlsEnabled: true },
        { kind: 'writable', table: 'users', who: 'anyone', can: ['add', 'change', 'delete'], changed: { change: 1, delete: 1 }, columns: cols, rlsEnabled: true, rules: ['ALL'] },
        { kind: 'writable', table: 'users', who: 'signed-in', can: ['add', 'change', 'delete'], changed: { change: 1, delete: 1 }, columns: cols, rlsEnabled: true, rules: ['ALL'] },
        { kind: 'exposed', table: 'bookings', readable: 2, columns: ['phone'], rlsEnabled: true },
        COUNTERS_OPEN,
      ]);
      const users = all.filter((f) => f.table === 'users');
      if (users.length !== 1) return ['users reported ' + users.length + ' times, expected once'];
      const u = users[0];
      if ((u.members || []).length !== 3) problems.push('users keeps ' + (u.members || []).length + ' proofs, expected 3');
      if (u.severity !== 'CRITICAL') problems.push('severity ' + u.severity);
      if (!/read/.test(u.headline) || !/delete/.test(u.headline)) problems.push('headline does not say read and delete: ' + u.headline);
      if (!/Signed-in customers can do the same/.test(u.body)) problems.push('the customers part is not said: ' + u.body);
      if (u.fixPrompt.split('My app has a security problem').length !== 2) problems.push('more than one prompt in one');
      // A table with one proof is left as it was, and other tables stay apart.
      const bookings = all.filter((f) => f.table === 'bookings');
      if (bookings.length !== 1 || bookings[0].members) problems.push('a single-proof table was grouped: ' + JSON.stringify(bookings.map((b) => b.members)));
      if (all.length !== 3) problems.push('expected 3 findings (users, bookings, counters), got ' + all.length);
      return problems;
    },
  },
  {
    name: 'grouping keeps the worst severity, and leaves apart what is not the same rule',
    run: () => {
      const problems = [];
      // Only adding is HIGH on its own; the read leaks an API key, which is CRITICAL.
      const keys = finding.describeAll([
        CREDENTIALS_OPEN,
        { kind: 'writable', table: 'integrations', who: 'anyone', can: ['add'], changed: {}, columns: CREDENTIALS_OPEN.columns, rlsEnabled: false },
      ]);
      if (keys.length !== 1 || keys[0].severity !== 'CRITICAL') problems.push('an API-key leak grouped with an add-only write is not CRITICAL: ' + JSON.stringify(keys.map((k) => k.severity)));
      // One customer reading another's rows is a different rule from strangers writing.
      const orders = finding.describeAll([
        ORDERS_CROSSED,
        { kind: 'writable', table: 'orders', who: 'signed-in', can: ['change'], changed: { change: 1 }, columns: ORDERS_CROSSED.columns, rlsEnabled: true },
      ]);
      if (orders.length !== 2 || orders.some((o) => o.members)) problems.push('a crossed read was grouped with a write: ' + orders.length + ' findings');
      // A table that only gives away its row count is said on its own terms.
      const counted = finding.describeAll([
        Object.assign({}, COUNTERS_OPEN, { countOnly: true }),
        { kind: 'writable', table: 'page_counters', who: 'anyone', can: ['change'], changed: { change: 1 }, columns: COUNTERS_OPEN.columns, rlsEnabled: false },
      ]);
      if (counted.length !== 2 || counted.some((o) => o.members)) problems.push('a count-only read was grouped with a write: ' + counted.length + ' findings');
      return problems;
    },
  },
  {
    name: 'an app uses Supabase sign-in if any table keys to auth.users or any rule asks auth.uid() - and then every table does',
    run: () => {
      const problems = [];
      const expect = (label, plan, want) => {
        const ties = finding.authTiesOf(plan);
        for (const t of Object.keys(want)) if (ties.get(t) !== want[t]) problems.push(label + ': ' + t + ' is ' + ties.get(t) + ', expected ' + want[t]);
      };
      // The blind test's shape: appointments -> profiles -> auth.users.
      expect('keyed', {
        tables: [
          { name: 'profiles', constraints: [{ kind: 'f', definition: 'FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE' }] },
          { name: 'appointments', constraints: [{ kind: 'f', definition: 'FOREIGN KEY (provider_id) REFERENCES profiles(id)' }] },
        ],
        policies: [{ table_name: 'appointments', qual: 'true', with_check: null }],
      }, { profiles: true, appointments: true });
      expect('asked', {
        tables: [{ name: 'posts', constraints: [] }, { name: 'tags', constraints: [] }],
        policies: [{ table_name: 'posts', qual: '(author = auth.uid())', with_check: null }],
      }, { posts: true, tags: true });
      // Its own login: users.id bigint, and a key to public.users is not auth.users.
      expect('own', {
        tables: [
          { name: 'bookings', constraints: [{ kind: 'f', definition: 'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL' }] },
          { name: 'users', constraints: [{ kind: 'p', definition: 'PRIMARY KEY (id)' }] },
        ],
        policies: [{ table_name: 'users', qual: 'true', with_check: 'true' }],
      }, { bookings: false, users: false });
      return problems;
    },
  },
  {
    // Found on an app with its own login (users.id bigint, no auth.users): the
    // prompt said to compare the owner to the signed-in user - impossible
    // there, and an assistant doing it locks the app out of its own table.
    name: 'a table not tied to Supabase sign-in gets a fix that does not rely on auth.uid()',
    run: () => {
      const problems = [];
      const base = { table: 'bookings', columns: ['phone'], rlsEnabled: true, rules: ['ALL'] };
      const own = [
        Object.assign({ kind: 'exposed', readable: 1, authTied: false }, base),
        Object.assign({ kind: 'writable', who: 'anyone', can: ['add'], changed: {}, authTied: false }, base),
      ];
      const prompts = {
        single: finding.fixPromptFor(own[1]),
        read: finding.fixPromptFor(own[0]),
        group: finding.describeAll(own)[0].fixPrompt,
      };
      for (const k of Object.keys(prompts)) {
        const p = prompts[k].replace(/\s+/g, ' ');
        if (!/service_role/.test(p)) problems.push(k + ': does not say to use service_role from the server');
        if (/WITH CHECK comparing/.test(p)) problems.push(k + ': still asks for an owner rule');
        if (!/never in the browser/.test(p)) problems.push(k + ': does not say to keep the key out of the browser');
      }
      // Tied, or unknown: the owner rule is the fix.
      const tied = finding.fixPromptFor(Object.assign({ kind: 'writable', who: 'anyone', can: ['add'], changed: {}, owner: 'user_id', authTied: true }, base)).replace(/\s+/g, ' ');
      if (!/WITH CHECK comparing "user_id"/.test(tied)) problems.push('a tied table lost its owner rule');
      // Found on the blind test's fix: only WITH CHECK was asked for, so an
      // update left USING (true) - anyone could take another provider's
      // appointment and rewrite it as their own.
      if (!/For update and delete, add USING/.test(tied)) problems.push('the fix does not close USING on update and delete');
      if (/service_role/.test(tied)) problems.push('a tied table was told to use service_role');
      // Supabase sign-in, but no column saying whose row it is (a waitlist):
      // there is nothing for an owner rule to compare, so the same way out.
      const ownerless = finding.fixPromptFor(Object.assign({ kind: 'writable', who: 'anyone', can: ['add'], changed: {}, authTied: true, owned: false }, base)).replace(/\s+/g, ' ');
      if (!/no column that says whose row it is/.test(ownerless) || !/service_role/.test(ownerless)) problems.push('an ownerless table was not given the server-only fix');
      if (/signs people in its own way/.test(ownerless)) problems.push('an ownerless table in a Supabase app was told it has its own login');
      const unknown = finding.fixPromptFor(Object.assign({ kind: 'writable', who: 'anyone', can: ['add'], changed: {} }, base)).replace(/\s+/g, ' ');
      if (/service_role/.test(unknown)) problems.push('a table of unknown ties was told to use service_role');
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
