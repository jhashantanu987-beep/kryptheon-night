// One night's work, end to end.
//
//   read the app's shape  ->  rebuild it somewhere safe  ->  seed two fake
//   people  ->  attack the copy  ->  say what got through  ->  delete the copy
//
// The live app is read and never written to. Nothing is copied except the
// shape: no rows, no customers, no orders. Every row the attack reads is a row
// this tool put there itself, which is what makes the report safe to send.
//
// Run with:
//   node scan.js "<connection string>" <schema>
//   node scan.js "<connection string>" <schema> --recheck

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const schema = require('./schema.js');
const attack = require('./attack.js');
const finding = require('./finding.js');
const collision = require('./collision.js');
const recheck = require('./recheck.js');

// Where the last run is kept so the next one has something to compare against.
// Beside the person's own project, not in a temp folder, because a re-check a
// week later has to find it.
const LAST_RUN = '.kryptheon-last.json';

const line = (text) => process.stdout.write(text + '\n');

/**
 * Runs the whole thing and hands back what got through.
 *
 * The copy is dropped in a `finally`, so a crash halfway does not leave a
 * database behind with somebody's schema in it.
 */
async function scan(client, sourceSchema, options) {
  const opts = options || {};
  const copyName = 'kn_' + Date.now().toString(36);
  const say = opts.quiet ? () => {} : line;

  say('  Reading the shape of ' + sourceSchema + ' ...');
  const plan = await schema.readSchema(client, sourceSchema);

  if (plan.unsupported.length) {
    // Attacking a copy that is missing pieces would produce verdicts about a
    // database nobody runs, so this stops rather than guesses.
    return {
      stopped: 'Parts of this app could not be copied faithfully:\n    ' + plan.unsupported.join('\n    '),
      findings: [],
    };
  }

  say('  ' + plan.tables.length + ' tables, ' + plan.policies.length + ' rules. Building a copy ...');

  try {
    await schema.writeSchema(client, plan, copyName);
    const copyPlan = await schema.readSchema(client, copyName);

    // The copy has to be the app, or nothing that follows means anything.
    const differences = schema.diffSchemas(plan, copyPlan);
    if (differences.length) {
      return {
        stopped: 'The copy did not come out identical, so nothing was attacked:\n    ' + differences.join('\n    '),
        findings: [],
      };
    }

    say('  Copy matches. Seeding two people and attacking it ...');
    const sown = await attack.seed(client, copyName, copyPlan.tables);
    const impersonation = await attack.impersonate(client, copyName, copyPlan.tables);

    // Every attack genuinely run, named the way a finding is named. The
    // re-check needs this: a finding that disappears because its attack never
    // ran this time is not a finding that was fixed, and without this list the
    // two are indistinguishable.
    //
    // Two conditions, both required. The read has to have produced a verdict,
    // AND the table has to have had a row in it - because a table nothing
    // could be seeded into returns nothing to a stranger for a reason that has
    // nothing to do with being secure.
    const sownTables = new Set(sown.seeded.map((entry) => entry.table));
    const attempted = impersonation.completed.filter((key) => sownTables.has(key.split(':')[1]));

    // Surfaced, not swallowed. A table with no row in it reads as a safe
    // table, so the one thing that must never happen is reporting an app as
    // clear when part of it was never actually tried.
    const notChecked = sown.skipped.slice();

    // A read that errored for any reason other than the table being closed to
    // that role decided nothing at all, and zero rows back from a failed query
    // looks exactly like zero rows back from a table that held.
    for (const stuck of impersonation.blocked) {
      if (!sownTables.has(stuck.table)) continue;
      notChecked.push({ table: stuck.table, key: stuck.key, why: stuck.why });
    }

    let collisions = { findings: [], notTried: [], raced: [] };
    if (opts.openSession) {
      say('  Racing two requests against each other ...');
      const one = await opts.openSession();
      const two = await opts.openSession();
      try {
        collisions = await collision.collide(client, one, two, copyName, copyPlan.tables, copyPlan.indexes);
      } finally {
        await one.end().catch(() => {});
        await two.end().catch(() => {});
      }
      for (const raced of collisions.raced) {
        attempted.push('duplicated:' + raced.table + ':' + raced.column);
      }
      for (const missed of collisions.notTried) {
        notChecked.push({
          table: missed.table + '.' + missed.column,
          key: 'duplicated:' + missed.table + ':' + missed.column,
          why: missed.why,
        });
      }
    } else {
      // Two requests at once needs two connections. Without them the attack
      // cannot happen at all, and a report that quietly omits it reads exactly
      // like a report that ran it and found nothing.
      for (const target of collision.candidates(copyPlan.tables, copyPlan.indexes).filter((t) => !t.covered)) {
        notChecked.push({
          table: target.table + '.' + target.column,
          key: 'duplicated:' + target.table + ':' + target.column,
          why: 'racing two requests needs a second connection, and none was available',
        });
      }
    }

    return {
      stopped: null,
      attacksRun: attempted.length,
      notChecked: notChecked,
      attempted: attempted,
      findings: finding.describeAll(impersonation.findings.concat(collisions.findings)),
    };
  } finally {
    try {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(copyName) + ' CASCADE');
      say('  Copy deleted.');
    } catch (err) {
      line('  WARNING: the copy ' + copyName + ' could not be deleted: ' + err.message);
    }
  }
}

/** The last run, or null if there has not been one worth keeping. */
function loadLastRun(file) {
  try {
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    return saved && Array.isArray(saved.findings) ? saved : null;
  } catch (err) {
    return null;
  }
}

/**
 * Keeps a run so the next one can be measured against it.
 *
 * A run that stopped is never saved. Overwriting a real list of problems with
 * an empty one from a run that fell over would quietly lose every finding, and
 * the re-check after that would have nothing to hold anybody to.
 */
function saveRun(file, result) {
  if (result.stopped) return;
  try {
    fs.writeFileSync(file, JSON.stringify(result, null, 2));
  } catch (err) {
    line('  WARNING: I could not save this run to ' + file + ', so tomorrow I');
    line('  will have nothing to compare against: ' + err.message);
  }
}

/** The report, as the person reads it in the morning. */
function report(result) {
  if (result.stopped) {
    line('');
    line('  I could not check this app.');
    line('');
    line('  ' + result.stopped);
    line('');
    return;
  }

  // Said before anything else, and said even on a clean night. "Everything
  // held" is only true about the tables that were actually tried, and a table
  // no row could be put into looks exactly like a table nothing got out of.
  const notChecked = result.notChecked || [];
  const sayWhatWasMissed = () => {
    if (!notChecked.length) return;
    line('');
    line('  ' + notChecked.length + (notChecked.length === 1 ? ' table was' : ' tables were') + ' NOT checked:');
    line('');
    for (const missed of notChecked) {
      line('    ' + missed.table + ' - ' + missed.why);
    }
    line('');
    line('  I could not get a test row into ' + (notChecked.length === 1 ? 'it' : 'them') +
      ', so I cannot say whether');
    line('  ' + (notChecked.length === 1 ? 'it is' : 'they are') + ' safe. Treat ' +
      (notChecked.length === 1 ? 'it' : 'them') + ' as unknown, not as clear.');
  };

  if (!result.findings.length) {
    if (notChecked.length) {
      sayWhatWasMissed();
      line('');
      line('  Everything I could try, held.');
      line('');
    } else {
      finding.allClearLines(result.attacksRun).forEach(line);
    }
    return;
  }

  sayWhatWasMissed();

  const count = result.findings.length;
  line('');
  line('  ' + count + (count === 1 ? ' problem' : ' problems') + ' found.');

  for (const item of result.findings) {
    line('');
    line('  ' + '-'.repeat(68));
    line('  ' + item.severity + '   ' + item.table);
    line('');
    line('  ' + item.headline);
    line('');
    for (const paragraph of [item.body, item.cause]) {
      wrap(paragraph, 70).forEach((l) => line('  ' + l));
      line('');
    }
    line('  Paste this into Lovable, Claude or Cursor:');
    line('');
    item.fixPrompt.split('\n').forEach((l) => line('    ' + l));
  }

  line('');
  line('  ' + '-'.repeat(68));
  line('  Nothing here touched your live app. I built a copy, attacked the copy,');
  line('  and deleted it. Not one real customer was involved.');
  line('');
}

/** Wraps at a width a person can read without their eyes sliding off. */
function wrap(text, width) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > width) {
      lines.push(current.trim());
      current = word;
    } else {
      current = (current + ' ' + word).trim();
    }
  }
  if (current) lines.push(current.trim());
  return lines;
}

async function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== '--recheck');
  const again = process.argv.includes('--recheck');
  const connection = args[0];
  const target = args[1];
  if (!connection || !target) {
    console.error('');
    console.error('  node scan.js "<connection string>" <schema> [--recheck]');
    console.error('');
    process.exit(2);
  }

  const file = path.resolve(LAST_RUN);
  const before = again ? loadLastRun(file) : null;
  if (again && !before) {
    // Running a fresh scan and calling it a re-check would report every
    // problem as new and confirm nothing, which reads like an answer.
    console.error('');
    console.error('  There is no earlier run here to compare against.');
    console.error('');
    console.error('  Run it without --recheck first, fix what it finds, then come back.');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: connection });
  await client.connect();
  try {
    const result = await scan(client, target, {
      // Two requests arriving together cannot be faked down one connection, so
      // the collision attack is handed a way to open its own.
      openSession: async () => {
        const extra = new Client({ connectionString: connection });
        await extra.connect();
        return extra;
      },
    });

    if (!before) {
      report(result);
      saveRun(file, result);
      process.exitCode = result.findings.length ? 1 : 0;
      return;
    }

    const verdict = recheck.compare(before, result);
    recheck.describe(verdict).forEach(line);
    recheck.badgeLines(verdict, result.attacksRun || 0).forEach(line);
    // The verdict says what changed; this says what to do about what did not.
    if (result.findings.length) report(result);
    saveRun(file, result);
    process.exitCode = verdict.allClear ? 0 : 1;
  } finally {
    await client.end();
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('');
    console.error('  The scan could not run: ' + err.message);
    console.error('');
    process.exit(1);
  });
}

module.exports = { scan: scan, report: report, wrap: wrap, loadLastRun: loadLastRun, saveRun: saveRun };
