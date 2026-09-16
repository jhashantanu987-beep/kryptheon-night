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

const { Client } = require('pg');
const schema = require('./schema.js');
const attack = require('./attack.js');
const finding = require('./finding.js');

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
    const raw = await attack.impersonate(client, copyName, copyPlan.tables);

    return {
      stopped: null,
      attacksRun: sown.seeded.length * 2,
      // Surfaced, not swallowed. A table with no row in it reads as a safe
      // table, so the one thing that must never happen is reporting an app
      // as clear when part of it was never actually tried.
      notChecked: sown.skipped,
      findings: finding.describeAll(raw),
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
  const connection = process.argv[2];
  const target = process.argv[3];
  if (!connection || !target) {
    console.error('');
    console.error('  node scan.js "<connection string>" <schema>');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: connection });
  await client.connect();
  try {
    const result = await scan(client, target);
    report(result);
    process.exitCode = result.findings.length ? 1 : 0;
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

module.exports = { scan: scan, report: report, wrap: wrap };
