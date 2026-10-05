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
  // A third part when there is one: the column for a duplicate, or who the
  // caller was for a write. Closing a table to strangers does not close it to
  // signed-in customers, and sharing one identity would report the second as
  // fixed the moment the first was.
  const detail = item.column || item.who || '';
  return item.kind + ':' + item.table + (detail ? ':' + detail : '');
}

/**
 * What the second run says about the first.
 *
 * `unverifiable` is the category that earns this module. Without it every
 * untestable table would land in `fixed`, and a green badge would be handed to
 * an app nobody checked.
 */
/**
 * A report shows one finding per table, but each one keeps the proofs it was
 * made of. Those are what get compared: closing a table to strangers' writes
 * while it stays readable is one proof fixed and one still open, not "the
 * table's finding" either fixed or not. Reports saved before findings were
 * grouped have no members, and are read as they are.
 */
function proofsOf(list) {
  return (list || []).reduce((all, item) => all.concat(item.members && item.members.length ? item.members : [item]), []);
}

/*
 * Whether the earlier run was on this database at all.
 *
 * Found on a blind test (HelixOps): the repository's database was scanned,
 * then the production one from the same folder, and the re-check reported the
 * six differences as "NEW problems" and said "A fix can open something else".
 * Nothing had been fixed; it was another database. A run now says where it
 * was; one saved before that is judged by the tables it attacked.
 */

// Attacks named for a table, as opposed to a function or a bucket.
const ON_A_TABLE = /^(exposed|crossed|writable|recursive|orphaned|duplicated|role|teamread):/;

/** The tables a run looked at: as it said, or else as its attacks name them. */
function tablesOf(run, said) {
  if (said) return run.where.tables;
  return Array.from(new Set(((run && run.attempted) || []).filter((key) => ON_A_TABLE.test(String(key)))
    .map((key) => String(key).split(':')[1])));
}

/** A database, said the way a person would recognise it. */
function placeOf(where) {
  if (!where) return null;
  return '"' + where.database + '"' + (where.host ? ' on ' + where.host + (where.port ? ':' + where.port : '') : '') +
    (where.schema && where.schema !== 'public' ? ', schema "' + where.schema + '"' : '');
}

function elsewhereOf(before, after) {
  const was = before && before.where;
  const now = after && after.where;
  const said = Boolean(was && now && Array.isArray(was.tables) && Array.isArray(now.tables));
  const a = new Set(tablesOf(before, said));
  const b = new Set(tablesOf(after, said));
  const onlyBefore = Array.from(a).filter((t) => !b.has(t)).sort();
  const onlyNow = Array.from(b).filter((t) => !a.has(t)).sort();
  const union = new Set(Array.from(a).concat(Array.from(b))).size;
  const shared = union - onlyBefore.length - onlyNow.length;
  const otherDatabase = Boolean(was && now) && (was.database !== now.database ||
    (was.host || null) !== (now.host || null) || (was.port || null) !== (now.port || null) || was.schema !== now.schema);
  // Fewer than half the tables in common: not the same app any more. Only
  // said when both runs name tables: a run that names none says nothing.
  const otherShape = a.size > 0 && b.size > 0 && shared * 2 < union;
  if (!otherDatabase && !otherShape) return null;
  return { otherDatabase: otherDatabase, otherShape: otherShape, was: placeOf(was), now: placeOf(now),
    onlyBefore: onlyBefore, onlyNow: onlyNow };
}

function compare(before, after) {
  const was = proofsOf(before && before.findings);
  const now = proofsOf(after && after.findings);

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
  const elsewhere = elsewhereOf(before, after);

  return {
    stopped: null,
    // Set when the earlier run was on another database, or on a very
    // different set of tables: then this is a comparison, not a re-check.
    elsewhere: elsewhere,
    fixed: fixed,
    stillOpen: stillOpen,
    unverifiable: unverifiable,
    newlyBroken: newlyBroken,
    // Carried so the re-check can say why there is no green light when the
    // only thing standing in the way is what could not be tested.
    untested: skipped,
    // Green is the strictest thing this program says, so it is the hardest to
    // earn: everything that was wrong is now provably right, nothing new broke,
    // and nothing at all was left untested.
    //
    // Every old finding lands in exactly one of fixed / stillOpen /
    // unverifiable, so "the other two are empty" already means "all of them
    // were fixed" - stating that a third time as a count only made each guard
    // able to cover for the others, which is how a broken guard stays hidden.
    // And never from two different databases: nothing was fixed between them.
    allClear:
      !elsewhere &&
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

/**
 * Which proof a line is about. One table can have several - strangers reading
 * it, strangers writing to it - and "waitlist, waitlist" under "fixed" would
 * not say which one was closed.
 */
function whatOf(item) {
  if (item.kind === 'exposed') return 'read by anyone';
  if (item.kind === 'crossed') return "customers reading each other's rows";
  if (item.kind === 'writable') return item.who === 'anyone' ? 'written by anyone' : 'written by any signed-in customer';
  if (item.kind === 'duplicated') return 'the same ' + (item.column || 'value') + ' twice';
  if (item.kind === 'orphaned') return 'rows left pointing at nothing';
  if (item.kind === 'privileged') return 'a function anyone can call';
  if (item.kind === 'role') return 'changed by a "' + (item.who || 'viewer') + '"';
  if (item.kind === 'teamread') return 'read by a "' + (item.who || 'viewer') + '"';
  if (item.kind === 'bucket') return 'a public storage bucket';
  if (item.kind === 'recursive') return 'a rule that refers to itself';
  return item.kind;
}

/** Wraps one paragraph for the screen, indented the way these lines are. */
function wrapped(text) {
  const out = [];
  let current = '';
  for (const word of String(text).split(/\s+/)) {
    if ((current + ' ' + word).trim().length > 70) {
      out.push('  ' + current.trim());
      current = word;
    } else {
      current = (current + ' ' + word).trim();
    }
  }
  if (current) out.push('  ' + current.trim());
  return out;
}

/** Up to eight names, and how many more. */
function someOf(names) {
  const shown = names.slice(0, 8).join(', ');
  return names.length > 8 ? shown + ' and ' + (names.length - 8) + ' more' : shown;
}

/**
 * Said first when the earlier run was somewhere else: which two databases,
 * and how their tables differ - so nothing after it reads as a fix.
 */
function elsewhereLines(elsewhere) {
  const lines = [];
  const tables = (n) => n + (n === 1 ? ' table' : ' tables');
  lines.push('  This is not a re-check of the same database.');
  lines.push('');
  const where = elsewhere.otherDatabase
    ? 'The earlier run kept for this folder was on ' + elsewhere.was + ', and this one is on ' + elsewhere.now + '.'
    : 'The earlier run kept for this folder looked at a very different set of tables.';
  wrapped(where + ' So what follows compares two databases: nothing in it means a fix worked, ' +
    'and nothing in it means a fix broke something.').forEach((l) => lines.push(l));
  lines.push('');
  const shape = [];
  if (elsewhere.onlyBefore.length) shape.push(tables(elsewhere.onlyBefore.length) + ' only in the earlier one (' + someOf(elsewhere.onlyBefore) + ')');
  if (elsewhere.onlyNow.length) shape.push(tables(elsewhere.onlyNow.length) + ' only in this one (' + someOf(elsewhere.onlyNow) + ')');
  wrapped(shape.length ? 'How their tables differ: ' + shape.join('; ') + '.' : 'Both have the same tables.')
    .forEach((l) => lines.push(l));
  lines.push('');
  return lines;
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

  const elsewhere = result.elsewhere;
  if (elsewhere) elsewhereLines(elsewhere).forEach((l) => lines.push(l));

  if (result.fixed.length) {
    const n = result.fixed.length;
    lines.push(elsewhere
      ? '  ' + n + ' found in the earlier run and not here:'
      : '  ' + n + (n === 1 ? ' problem is' : ' problems are') + ' fixed:');
    lines.push('');
    for (const item of result.fixed) {
      // A function is never called, only read - so its fix is said as what
      // was seen, not as an attack that was refused. Found on a fix test.
      const how = item.kind === 'privileged'
        ? (elsewhere ? 'I looked here, and a visitor with no account cannot call it.'
          : 'I looked again, and a visitor with no account can no longer call it.')
        : item.kind === 'bucket'
        ? (elsewhere ? 'I looked here, and the bucket is not public.' : 'I looked again, and the bucket is no longer public.')
        : item.kind === 'recursive'
        ? (elsewhere ? 'I read it here, and its rules answered.'
          : 'I read it again, and its rules answered instead of stopping with an error.')
        : (elsewhere ? 'I ran the same attack here and it was refused.' : 'I ran the same attack again and it was refused.');
      lines.push('    ' + item.table + ' (' + whatOf(item) + ') - ' + how);
    }
    lines.push('');
  }

  if (result.stillOpen.length) {
    lines.push('  ' + result.stillOpen.length + (elsewhere ? ' found in both:' : ' still open:'));
    lines.push('');
    for (const item of result.stillOpen) {
      lines.push('    ' + item.table + ' - ' + item.headline);
    }
    lines.push('');
  }

  // Deliberately not under "fixed", and deliberately not silent. This is the
  // one a person would otherwise read as good news.
  if (result.unverifiable.length) {
    lines.push('  ' + result.unverifiable.length + (elsewhere ? ' I could NOT compare:' : ' I could NOT confirm:'));
    lines.push('');
    for (const item of result.unverifiable) {
      lines.push('    ' + item.table + ' (' + whatOf(item) + ') - ' + item.why);
    }
    lines.push('');
    if (elsewhere) {
      lines.push('  These were found in the earlier run, and the same attack did not run');
      lines.push('  here, so whether they are here too is unknown.');
    } else {
      lines.push('  These are not fixed and not broken - they are unknown. The problem');
      lines.push('  stopped showing up, but not because the attack was refused.');
    }
    lines.push('');
  }

  if (result.newlyBroken.length) {
    const n = result.newlyBroken.length;
    lines.push(elsewhere
      ? '  ' + n + ' found here and not in the earlier run:'
      : '  ' + n + ' NEW ' + (n === 1 ? 'problem' : 'problems') + ' that were not there before:');
    lines.push('');
    for (const item of result.newlyBroken) {
      lines.push('    ' + item.table + ' - ' + item.headline);
    }
    lines.push('');
    if (elsewhere) {
      lines.push('  These are differences between the two databases, not something a fix');
      lines.push('  opened.');
    } else {
      lines.push('  A fix can open something else. This is why the re-check looks at the');
      lines.push('  whole app again and not only at what it was asked about.');
    }
    lines.push('');
  }

  if (!result.fixed.length && !result.stillOpen.length && !result.unverifiable.length && !result.newlyBroken.length) {
    lines.push(elsewhere ? '  Neither run found anything open.' : '  Nothing to re-check - there was nothing open.');
    lines.push('');
  }

  // Found on a real app: "1 problem is fixed", nothing else, and a non-zero
  // exit with no word about why. The reason was parts of the app that could
  // not be tested - which has to be said, or the exit code reads as a bug.
  const untested = result.untested || [];
  if (untested.length) {
    lines.push('  No green light yet: ' + untested.length + ' ' +
      (untested.length === 1 ? 'part of your app was' : 'parts of your app were') +
      ' not tested this time, so I cannot');
    lines.push('  call it clear. They are listed at the end, with the reason for each.');
    lines.push('');
  }

  return lines;
}

module.exports = {
  keyOf: keyOf,
  elsewhereOf: elsewhereOf,
  compare: compare,
  describe: describe,
  badgeLines: badgeLines,
};
