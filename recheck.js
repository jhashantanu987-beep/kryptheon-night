// Did the fix actually work?
//
// This is the smallest piece of the product and the one people pay for. The
// loop only closes if somebody can paste a fix, run this, and be told the hole
// is shut - and that sentence is worth exactly as much as it is trustworthy.
// Anyone can print "Fixed". Printing it only when it is true is the whole job.
//
// One rule sits under everything here:
//
//   A problem that disappeared is not the same as a problem that was fixed.
//
// A finding vanishes from the second run for several reasons, and only one of
// them is good news. The table might have been fixed. It might also have become
// impossible to test - a new constraint that seeding cannot satisfy, a renamed
// column, a table dropped outright. In every one of those the finding is gone
// from the list, and in none of them has anybody been made safe.
//
// So this compares the two runs against what the second run actually managed to
// try, not against what it happened to report.

/**
 * A finding's identity across runs: the attack, and what it was against.
 *
 * The column is part of it wherever there is one. A users table can accept a
 * duplicate email AND a duplicate username; without the column those two share
 * an identity, and adding a unique constraint to one of them would be read as
 * having fixed both.
 */
function keyOf(item) {
  return item.kind + ':' + item.table + (item.column ? ':' + item.column : '');
}

/**
 * What the second run says about the first.
 *
 * `unverifiable` is the category that earns this module. Without it every
 * untestable table would land in `fixed`, and a green badge would be handed to
 * an app nobody checked.
 */
function compare(before, after) {
  const was = (before && before.findings) || [];
  const now = (after && after.findings) || [];

  // The second run failed outright. Nothing can be claimed about anything.
  if (after && after.stopped) {
    return {
      stopped: after.stopped,
      fixed: [],
      stillOpen: was,
      unverifiable: was,
      newlyBroken: [],
      allClear: false,
    };
  }

  const nowByKey = new Map(now.map((item) => [keyOf(item), item]));

  // What the second run actually attempted, named the same way a finding is.
  // Per attack rather than per table, because one table can be attacked three
  // different ways: a table that was seeded and read is not thereby a table
  // whose unique columns were raced. Keyed by table alone, a collision attack
  // that never ran would have looked like a collision that was refused.
  const attempted = new Set((after && after.attempted) || []);
  const skipped = (after && after.notChecked) || [];
  const reasons = new Map();
  for (const entry of skipped) {
    if (entry.key) reasons.set(entry.key, entry.why);
    if (entry.table && !reasons.has(entry.table)) reasons.set(entry.table, entry.why);
  }
  const tablesTouched = new Set(
    Array.from(attempted).map((key) => String(key).split(':')[1]).filter(Boolean),
  );

  const fixed = [];
  const stillOpen = [];
  const unverifiable = [];

  for (const item of was) {
    const key = keyOf(item);
    if (nowByKey.has(key)) {
      stillOpen.push(item);
      continue;
    }
    // Gone from the list. Now the only question that matters: was it tried?
    if (!attempted.has(key)) {
      unverifiable.push(
        Object.assign({}, item, {
          why:
            reasons.get(key) ||
            reasons.get(item.table) ||
            // Not attempted and no reason offered. Either the table is gone or
            // that particular attack did not run. Said as what it is rather
            // than folded into "fixed", because deleting a table and securing
            // one are different acts and only one is what was asked for.
            (tablesTouched.has(item.table)
              ? 'this particular check did not run this time'
              : 'the table was not there to test this time'),
        }),
      );
      continue;
    }
    fixed.push(item);
  }

  const wasByKey = new Set(was.map(keyOf));
  const newlyBroken = now.filter((item) => !wasByKey.has(keyOf(item)));

  return {
    stopped: null,
    fixed: fixed,
    stillOpen: stillOpen,
    unverifiable: unverifiable,
    newlyBroken: newlyBroken,
    // Green is the strictest thing this program says, so it is the hardest to
    // earn: everything that was wrong is now provably right, nothing new broke,
    // and nothing at all was left untested.
    //
    // Every old finding lands in exactly one of fixed / stillOpen /
    // unverifiable, so "the other two are empty" already means "all of them
    // were fixed" - stating that a third time as a count only made each guard
    // able to cover for the others, which is how a broken guard stays hidden.
    allClear:
      !stillOpen.length &&
      !unverifiable.length &&
      !newlyBroken.length &&
      !((after && after.notChecked) || []).length,
  };
}

/** The badge, which only a genuinely clean re-check is allowed to produce. */
function badgeLines(result, attacksRun) {
  if (!result.allClear) return [];
  const when = new Date().toISOString().slice(0, 10);
  return [
    '',
    '  [ Kryptheon Verified ]  ' + attacksRun + ' checks passed  ' + when,
    '',
    '  Every problem I found is closed, and I proved it by running the same',
    '  attacks again. Nothing was left untested.',
    '',
  ];
}

/** What the re-check says, in the order it matters. */
function describe(result) {
  const lines = [''];

  if (result.stopped) {
    lines.push('  I could not re-check this app, so nothing is confirmed fixed.');
    lines.push('');
    lines.push('  ' + result.stopped);
    lines.push('');
    return lines;
  }

  if (result.fixed.length) {
    lines.push('  ' + result.fixed.length + (result.fixed.length === 1 ? ' problem is' : ' problems are') + ' fixed:');
    lines.push('');
    for (const item of result.fixed) {
      lines.push('    ' + item.table + ' - I ran the same attack again and it was refused.');
    }
    lines.push('');
  }

  if (result.stillOpen.length) {
    lines.push('  ' + result.stillOpen.length + ' still open:');
    lines.push('');
    for (const item of result.stillOpen) {
      lines.push('    ' + item.table + ' - ' + item.headline);
    }
    lines.push('');
  }

  // Deliberately not under "fixed", and deliberately not silent. This is the
  // one a person would otherwise read as good news.
  if (result.unverifiable.length) {
    lines.push('  ' + result.unverifiable.length + ' I could NOT confirm:');
    lines.push('');
    for (const item of result.unverifiable) {
      lines.push('    ' + item.table + ' - ' + item.why);
    }
    lines.push('');
    lines.push('  These are not fixed and not broken - they are unknown. The problem');
    lines.push('  stopped showing up, but not because the attack was refused.');
    lines.push('');
  }

  if (result.newlyBroken.length) {
    lines.push('  ' + result.newlyBroken.length + ' NEW ' +
      (result.newlyBroken.length === 1 ? 'problem' : 'problems') + ' that were not there before:');
    lines.push('');
    for (const item of result.newlyBroken) {
      lines.push('    ' + item.table + ' - ' + item.headline);
    }
    lines.push('');
    lines.push('  A fix can open something else. This is why the re-check looks at the');
    lines.push('  whole app again and not only at what it was asked about.');
    lines.push('');
  }

  if (!result.fixed.length && !result.stillOpen.length && !result.unverifiable.length && !result.newlyBroken.length) {
    lines.push('  Nothing to re-check - there was nothing open.');
    lines.push('');
  }

  return lines;
}

module.exports = {
  keyOf: keyOf,
  compare: compare,
  describe: describe,
  badgeLines: badgeLines,
};
