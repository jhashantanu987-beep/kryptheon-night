// Checks that "fixed" is only ever said when it is true.
// Run with:  node recheck.check.js
//
// The re-check is the thing people pay for, and it is worth nothing unless the
// word "fixed" can be relied on. Anyone can print it. Printing it only when the
// attack was genuinely run again and genuinely refused is the entire product.
//
// So almost every case below is about refusing to say it: a table that could
// not be tested, a table that was dropped, a run that fell over. In all of
// those the problem stops appearing in the list, and in none of them has the
// person been made safe.
//
// No database needed - these are the two shapes scan.js hands back.

const recheck = require('./recheck.js');

const CUSTOMERS = {
  kind: 'exposed',
  table: 'customers',
  severity: 'CRITICAL',
  headline: 'Your customers table can be read by anyone.',
};
const ORDERS = {
  kind: 'crossed',
  table: 'orders',
  severity: 'CRITICAL',
  headline: 'Your orders table lets one customer read another one\'s rows.',
};

/** A first run that found both problems. */
const BEFORE = {
  stopped: null,
  findings: [CUSTOMERS, ORDERS],
  checked: ['customers', 'orders', 'profiles'],
  notChecked: [],
  attacksRun: 6,
};

/** A second run, described by what it managed to try. */
function after(options) {
  const opts = options || {};
  return {
    stopped: opts.stopped || null,
    findings: opts.findings || [],
    checked: opts.checked || ['customers', 'orders', 'profiles'],
    notChecked: opts.notChecked || [],
    attacksRun: 6,
  };
}

const cases = [
  {
    name: '1. a problem that was attacked again and refused is fixed',
    run: () => {
      const r = recheck.compare(BEFORE, after({ findings: [ORDERS] }));
      const problems = [];
      if (r.fixed.length !== 1) problems.push('fixed ' + r.fixed.length + ', expected 1');
      if (r.fixed.length && r.fixed[0].table !== 'customers') problems.push('fixed the wrong one');
      if (r.stillOpen.length !== 1) problems.push('still open ' + r.stillOpen.length + ', expected 1');
      if (r.allClear) problems.push('it went green with one problem still open');
      const said = recheck.describe(r).join('\n');
      if (!/ran the same attack again and it was refused/.test(said)) {
        problems.push('it does not say the attack was re-run: ' + said);
      }
      return problems;
    },
  },
  {
    name: '2. a table that could not be tested is NOT called fixed',
    run: () => {
      // The finding is gone from the list, exactly as it would be if the fix
      // had worked. The only difference is that nothing was attacked.
      const r = recheck.compare(
        BEFORE,
        after({
          findings: [ORDERS],
          checked: ['orders', 'profiles'],
          notChecked: [{ table: 'customers', why: 'a new constraint blocked the test row' }],
        }),
      );
      const problems = [];
      if (r.fixed.length) problems.push('it claimed ' + r.fixed.map((f) => f.table) + ' was fixed without testing it');
      if (r.unverifiable.length !== 1) problems.push('unverifiable ' + r.unverifiable.length + ', expected 1');
      if (r.allClear) problems.push('it went green over a table it never tried');
      const said = recheck.describe(r).join('\n');
      if (!/could NOT confirm/.test(said)) problems.push('it does not flag the untested table: ' + said);
      if (!/not fixed and not broken/.test(said)) problems.push('it does not say what unknown means');
      // The reason has to be the one the scan actually gave. Falling back to
      // a generic "it was not there" would tell the person to go looking for a
      // table that is sitting right in front of them.
      if (r.unverifiable.length && !/constraint blocked the test row/.test(String(r.unverifiable[0].why))) {
        problems.push('it gives the wrong reason: ' + r.unverifiable[0].why);
      }
      if (!/a new constraint blocked the test row/.test(said)) {
        problems.push('the report does not pass on the reason the scan gave');
      }
      if (/customers - I ran the same attack/.test(said)) problems.push('it listed the untested table as fixed');
      return problems;
    },
  },
  {
    name: '3. a table that is no longer there is not quietly counted as a fix',
    run: () => {
      // Dropping the table does remove the exposure, but it is not what the
      // person was asked to do, and saying "fixed" would hide that they lost
      // a table.
      const r = recheck.compare(BEFORE, after({ findings: [ORDERS], checked: ['orders', 'profiles'] }));
      const problems = [];
      if (r.fixed.length) problems.push('a table that vanished was called fixed');
      if (r.unverifiable.length !== 1) problems.push('unverifiable ' + r.unverifiable.length + ', expected 1');
      if (r.unverifiable.length && !/not there to test/.test(r.unverifiable[0].why)) {
        problems.push('it does not say why: ' + r.unverifiable[0].why);
      }
      return problems;
    },
  },
  {
    name: '4. everything fixed, nothing skipped: green, and a badge',
    run: () => {
      const r = recheck.compare(BEFORE, after({ findings: [] }));
      const problems = [];
      if (r.fixed.length !== 2) problems.push('fixed ' + r.fixed.length + ', expected 2');
      if (!r.allClear) problems.push('everything was fixed and it did not go green');
      const badge = recheck.badgeLines(r, 6).join('\n');
      if (!/Kryptheon Verified/.test(badge)) problems.push('no badge on a clean re-check');
      if (!/6 checks passed/.test(badge)) problems.push('the badge does not say how much was checked');
      if (!/Nothing was left untested/.test(badge)) problems.push('the badge does not claim what it should');
      return problems;
    },
  },
  {
    name: '5. no badge unless every single thing was tried',
    run: () => {
      const problems = [];
      // Both problems really are fixed - but a third table could not be tested.
      // That is not a verified app.
      const r = recheck.compare(
        BEFORE,
        after({ findings: [], notChecked: [{ table: 'invoices', why: 'could not seed it' }] }),
      );
      if (r.fixed.length !== 2) problems.push('fixed ' + r.fixed.length + ', expected 2');
      if (r.allClear) problems.push('it went green while a table went untested');
      if (recheck.badgeLines(r, 6).length) problems.push('it issued a badge with a table untested');
      return problems;
    },
  },
  {
    name: '6. a fix that breaks something else is reported',
    run: () => {
      const INVOICES = {
        kind: 'exposed',
        table: 'invoices',
        severity: 'CRITICAL',
        headline: 'Your invoices table can be read by anyone.',
      };
      const r = recheck.compare(
        BEFORE,
        after({ findings: [INVOICES], checked: ['customers', 'orders', 'profiles', 'invoices'] }),
      );
      const problems = [];
      if (r.fixed.length !== 2) problems.push('fixed ' + r.fixed.length + ', expected 2');
      if (r.newlyBroken.length !== 1) problems.push('new ' + r.newlyBroken.length + ', expected 1');
      if (r.allClear) problems.push('it went green having just opened a new hole');
      const said = recheck.describe(r).join('\n');
      if (!/NEW problem/.test(said)) problems.push('it does not call out the new problem: ' + said);
      if (!/A fix can open something else/.test(said)) problems.push('it does not explain why it looked');
      return problems;
    },
  },
  {
    name: '7. a re-check that fell over confirms nothing',
    run: () => {
      const r = recheck.compare(BEFORE, after({ stopped: 'the copy did not come out identical' }));
      const problems = [];
      if (r.fixed.length) problems.push('it confirmed fixes from a run that failed');
      if (r.allClear) problems.push('it went green off a failed run');
      if (r.unverifiable.length !== 2) problems.push('it did not mark both as unconfirmed');
      if (recheck.badgeLines(r, 6).length) problems.push('it issued a badge off a failed run');
      const said = recheck.describe(r).join('\n');
      if (!/nothing is confirmed fixed/.test(said)) problems.push('it does not say nothing is confirmed: ' + said);
      return problems;
    },
  },
  {
    name: '8. the same problem still there is not mistaken for a new one',
    run: () => {
      const r = recheck.compare(BEFORE, after({ findings: [CUSTOMERS, ORDERS] }));
      const problems = [];
      if (r.stillOpen.length !== 2) problems.push('still open ' + r.stillOpen.length + ', expected 2');
      if (r.newlyBroken.length) problems.push('it called an old problem new');
      if (r.fixed.length) problems.push('it fixed something nobody touched');
      return problems;
    },
  },
  {
    name: '9. two attacks on one table are told apart',
    run: () => {
      // A table can be both publicly readable and customer-to-customer. Closing
      // one does not close the other, and the identity has to carry the attack.
      const BOTH = {
        stopped: null,
        findings: [CUSTOMERS, { kind: 'crossed', table: 'customers', headline: 'x', severity: 'CRITICAL' }],
        checked: ['customers'],
        notChecked: [],
        attacksRun: 2,
      };
      const r = recheck.compare(BOTH, after({ findings: [CUSTOMERS], checked: ['customers'] }));
      const problems = [];
      if (r.fixed.length !== 1) problems.push('fixed ' + r.fixed.length + ', expected 1');
      if (r.fixed.length && r.fixed[0].kind !== 'crossed') problems.push('it closed the wrong attack');
      if (r.stillOpen.length !== 1) problems.push('still open ' + r.stillOpen.length + ', expected 1');
      if (recheck.keyOf(CUSTOMERS) === recheck.keyOf(r.fixed[0])) problems.push('both attacks share one identity');
      return problems;
    },
  },
  {
    name: '10. a first run that found nothing has nothing to re-check',
    run: () => {
      const clean = { stopped: null, findings: [], checked: ['customers'], notChecked: [], attacksRun: 2 };
      const r = recheck.compare(clean, after({ findings: [] }));
      const problems = [];
      if (r.fixed.length || r.stillOpen.length || r.unverifiable.length) problems.push('it invented history');
      const said = recheck.describe(r).join('\n');
      if (!/Nothing to re-check/.test(said)) problems.push('it says nothing at all: ' + JSON.stringify(said));
      return problems;
    },
  },
  {
    name: '11. one unconfirmed table alone is enough to withhold green',
    run: () => {
      // Nothing is still open and nothing new broke - the only blemish is one
      // table that could not be tested. That on its own has to stop the badge,
      // and it is the case where a weak green would be easiest to miss.
      const r = recheck.compare(
        BEFORE,
        after({ findings: [], checked: ['orders', 'profiles'] }),
      );
      const problems = [];
      if (r.stillOpen.length) problems.push('nothing was still open');
      if (r.newlyBroken.length) problems.push('nothing new broke');
      if (r.unverifiable.length !== 1) problems.push('unverifiable ' + r.unverifiable.length + ', expected 1');
      if (r.allClear) problems.push('it went green with one table unconfirmed');
      if (recheck.badgeLines(r, 6).length) problems.push('it issued a badge with one table unconfirmed');
      return problems;
    },
  },
  {
    name: '12. every problem lands in exactly one place',
    run: () => {
      // Green is decided by the other buckets being empty, which is only the
      // same as "all of them were fixed" while this holds. If a finding could
      // fall through all three, an app would go green with it unaccounted for.
      const r = recheck.compare(
        BEFORE,
        after({
          findings: [ORDERS],
          checked: ['orders'],
          notChecked: [{ table: 'customers', why: 'could not seed it' }],
        }),
      );
      const problems = [];
      const landed = r.fixed.concat(r.stillOpen, r.unverifiable).map(recheck.keyOf);
      const wanted = BEFORE.findings.map(recheck.keyOf);
      if (landed.length !== wanted.length) {
        problems.push('2 problems went in, ' + landed.length + ' came out');
      }
      for (const key of wanted) {
        const times = landed.filter((k) => k === key).length;
        if (times !== 1) problems.push(key + ' appears ' + times + ' times, expected 1');
      }
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
console.log('All ' + cases.length + ' re-check checks passed.');
