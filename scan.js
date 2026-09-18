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
//   KN_DATABASE_URL=postgresql://...   node scan.js <schema>
//   KN_DATABASE_URL=postgresql://...   node scan.js <schema> --recheck

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const schema = require('./schema.js');
const attack = require('./attack.js');
const finding = require('./finding.js');
const collision = require('./collision.js');
const tamper = require('./tamper.js');
const orphan = require('./orphan.js');
const recheck = require('./recheck.js');

// Where the last run is kept so the next one has something to compare against.
// Beside the person's own project, not in a temp folder, because a re-check a
// week later has to find it.
const LAST_RUN = '.kryptheon-last.json';

const line = (text) => process.stdout.write(text + '\n');

// How long a copy has to be lying around before it is treated as abandoned.
// Long enough that a scan running in another window is never swept out from
// under itself; short enough that nobody finds week-old schemas in their
// database.
const ABANDONED_AFTER = 6 * 60 * 60 * 1000;

/**
 * Drops copies an earlier run left behind.
 *
 * The copy's name carries the moment it was made, so its age can be read
 * without asking Postgres - which does not record when a schema was created.
 * Anything younger than a few hours is left strictly alone: it may well belong
 * to a scan that is running right now.
 */
async function sweepOldCopies(client, mine) {
  const dropped = [];
  let rows = [];
  try {
    ({ rows } = await client.query(
      // Copies, and the engine schemas the SQL door installs. A copy is
      // kn_<moment>; an engine is kn_engine_<moment>. The engine used to be
      // outside this pattern entirely, so one abandoned by a dropped
      // connection sat in the customer's database for ever - which is the
      // one thing this product promises never to do.
      "SELECT nspname FROM pg_namespace WHERE nspname ~ '^kn_(engine_)?[0-9a-z]+$' AND nspname <> $1",
      [mine],
    ));
  } catch (err) {
    return dropped;
  }

  for (const row of rows) {
    // The moment is whatever follows the last underscore, which is the
    // whole name after kn_ for a copy and the tail for an engine.
    const parts = String(row.nspname).split('_');
    const made = parseInt(parts[parts.length - 1], 36);
    if (!Number.isFinite(made) || Date.now() - made < ABANDONED_AFTER) continue;
    try {
      await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(row.nspname) + ' CASCADE');
      dropped.push(row.nspname);
    } catch (err) {
      // Not ours to force. Better to leave it than to fail somebody's scan.
    }
  }
  return dropped;
}

/**
 * Every schema in the database, and how many tables are in each.
 *
 * Nothing filtered out. The first version left out anything named like one of
 * our copies, which made the scan refuse to look at a schema whose name merely
 * began the same way - and that took the entire shapes suite down a minute
 * after this function was written. What to hide is a question for the
 * suggestion below, not for whether a schema exists.
 */
async function schemasWithTables(client) {
  const { rows } = await client.query(
    `SELECT n.nspname AS schema, count(c.oid) FILTER (WHERE c.relkind = 'r')::int AS tables
       FROM pg_namespace n
       LEFT JOIN pg_class c ON c.relnamespace = n.oid
      WHERE n.nspname NOT LIKE 'pg\\_%'
        AND n.nspname <> 'information_schema'
      GROUP BY 1
      ORDER BY 2 DESC, 1`,
  );
  return rows;
}

/**
 * What to try instead.
 *
 * A person who mistyped a schema name is about to mistype it again. Listing
 * what is actually there costs one query and saves the second attempt - but
 * not the throwaway copies, which are ours and about to be deleted.
 */
function suggest(schemas) {
  const worth = schemas.filter((entry) => entry.tables > 0 && !/^kn_[0-9a-z]+$/.test(entry.schema));
  if (!worth.length) return '\n    This database has no schema with tables in it.';
  return '\n    Schemas in this database with tables in them: ' +
    worth.map((entry) => entry.schema + ' (' + entry.tables + ')').join(', ');
}

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

  // Anything an earlier run could not clean up after itself. The copy is
  // dropped in a `finally`, but a `finally` needs a connection: when the link
  // dies mid-scan the process goes with it and the copy is simply left in the
  // customer's database. Found by exactly that happening on a real schema.
  const swept = await sweepOldCopies(client, copyName);
  if (swept.length) say('  Cleared ' + swept.length + ' copy left by an earlier run.');

  // Is there anything here at all?
  //
  // Typed `pubic` instead of `public`, this used to read a schema that does
  // not exist, find no tables, attack none of them, and print "Nothing got
  // through. Your data held." A typo produced the one sentence the entire
  // product is sold on, and exited 0 so a script would call it a pass.
  const elsewhere = await schemasWithTables(client);
  const here = elsewhere.find((entry) => entry.schema === sourceSchema);
  if (!here) {
    return {
      stopped: 'There is no schema called "' + sourceSchema + '" in this database.' +
        suggest(elsewhere),
      findings: [],
    };
  }

  say('  Reading the shape of ' + sourceSchema + ' ...');
  const plan = await schema.readSchema(client, sourceSchema);

  if (!plan.tables.length) {
    // Nothing wrong with the database, but nothing was tested either, and
    // those are not the same answer.
    return {
      stopped: 'The schema "' + sourceSchema + '" has no tables in it, so there was nothing to attack.' +
        suggest(elsewhere.filter((entry) => entry.schema !== sourceSchema)),
      findings: [],
    };
  }

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
    // The stand-ins built for tables outside the schema belong to this tool,
    // not to the customer. Attacking them would produce findings about a table
    // that does not exist in their app.
    // Named one by one from what was actually built, not matched on a prefix.
    // A customer table whose name merely looked like ours used to be dropped
    // from every attack, and a table nobody attacks has nothing to report.
    const standIns = new Set((plan.external || []).map((entry) => entry.stub));
    const theirs = copyPlan.tables.filter((table) => !standIns.has(table.name));
    const sown = await attack.seed(client, copyName, theirs);

    // Views are read but never seeded: they have no rows of their own, they
    // show the rows of the tables underneath. That is exactly why they matter
    // - a view runs with its creator's rights unless it says otherwise, so one
    // over a protected table hands out every row in it while the policy sits
    // there intact and the dashboard stays green.
    const views = (copyPlan.views || []).map((view) => ({
      name: view.name,
      columns: view.columns || [],
      constraints: [],
      rlsEnabled: false,
      isView: true,
    }));
    const impersonation = await attack.impersonate(client, copyName, theirs.concat(views));

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
    // A view counts as tested once anything underneath it has rows, since that
    // is what it has to show.
    const viewNames = new Set(views.map((view) => view.name));
    const attempted = impersonation.completed.filter((key) => {
      const name = key.split(':')[1];
      return sownTables.has(name) || (viewNames.has(name) && sown.seeded.length > 0);
    });

    // Surfaced, not swallowed. A table with no row in it reads as a safe
    // table, so the one thing that must never happen is reporting an app as
    // clear when part of it was never actually tried.
    const notChecked = sown.skipped.slice();

    // A read that errored for any reason other than the table being closed to
    // that role decided nothing at all, and zero rows back from a failed query
    // looks exactly like zero rows back from a table that held.
    for (const stuck of impersonation.blocked) {
      if (!sownTables.has(stuck.table) && !viewNames.has(stuck.table)) continue;
      notChecked.push({ table: stuck.table, key: stuck.key, why: stuck.why });
    }

    // Can a stranger change any of it? Every write here is rolled back, so the
    // copy comes out of this exactly as it went in and anything running after
    // reads the same database the earlier attacks did.
    say('  Trying to change data that is not ours ...');
    const writes = await tamper.tamper(client, copyName, theirs, sown.seeded);
    for (const key of writes.completed) attempted.push(key);
    for (const stuck of writes.blocked) {
      notChecked.push({ table: stuck.table, key: stuck.key, why: stuck.why });
    }

    // Can a half-finished write survive? Rolled back like the writes above.
    say('  Looking for rows that could point at nothing ...');
    const stranded = await orphan.orphan(client, copyName, theirs, sown.seeded);
    for (const key of stranded.completed) attempted.push(key);
    for (const missed of stranded.notTried) {
      notChecked.push({
        table: missed.table + '.' + missed.column,
        key: 'orphaned:' + missed.table + ':' + missed.column,
        why: missed.why,
      });
    }

    let collisions = { findings: [], notTried: [], raced: [] };
    if (opts.openSession) {
      say('  Racing two requests against each other ...');
      const one = await opts.openSession();
      const two = await opts.openSession();
      try {
        collisions = await collision.collide(client, one, two, copyName, theirs, copyPlan.indexes);
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
      for (const target of collision.candidates(theirs, copyPlan.indexes).filter((t) => !t.covered)) {
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
      findings: finding.describeAll(
        impersonation.findings.concat(writes.findings, stranded.findings, collisions.findings),
      ),
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

  // The connection string is the key to the customer's whole database, and
  // typed on the command line it goes into shell history and into the process
  // list where anybody on the machine can read it. The environment variable is
  // the way it should be given; the argument still works because taking it
  // away would break anyone already using it.
  const fromEnvironment = process.env.KN_DATABASE_URL;
  const connection = args.length > 1 ? args[0] : fromEnvironment;
  const target = args.length > 1 ? args[1] : args[0];

  if (!connection || !target) {
    console.error('');
    console.error('  KN_DATABASE_URL=postgresql://...   node scan.js <schema> [--recheck]');
    console.error('  node scan.js "<connection string>" <schema> [--recheck]');
    console.error('');
    console.error('  <schema> is usually "public".');
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
      // Three answers, three codes: 0 clean, 1 problems found, 2 could not
      // run. A scan that stopped used to exit 0 with no findings, which is
      // what any script watching it would read as a pass.
      process.exitCode = result.stopped ? 2 : result.findings.length ? 1 : 0;
      return;
    }

    const verdict = recheck.compare(before, result);
    recheck.describe(verdict).forEach(line);
    recheck.badgeLines(verdict, result.attacksRun || 0).forEach(line);
    // The verdict says what changed; this says what to do about what did not.
    if (result.findings.length) report(result);
    saveRun(file, result);
    process.exitCode = result.stopped ? 2 : verdict.allClear ? 0 : 1;
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

module.exports = {
  scan: scan,
  report: report,
  wrap: wrap,
  loadLastRun: loadLastRun,
  saveRun: saveRun,
  sweepOldCopies: sweepOldCopies,
  ABANDONED_AFTER: ABANDONED_AFTER,
};
