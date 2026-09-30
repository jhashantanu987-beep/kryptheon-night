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
const store = require('./store.js');

// Where the last run is kept so the next one has something to compare against:
// the project's store under ~/.kryptheon, not a temp folder, because a
// re-check a week later has to find it - and not the project, because a saved
// run lists one app's tables and exactly where it is weak, which is the last
// thing that should ever be committed. It used to be .kryptheon-last.json in
// the project; the store moves one it finds there, once, and says so.
//
// Throws when the store cannot be made: a run that could not be saved would
// leave the next re-check nothing to hold anyone to.
function lastRunFile(say) {
  const opened = store.open(process.cwd());
  const lines = store.migrationLines(opened);
  if (lines.length && say) {
    say('');
    lines.forEach(say);
  }
  return opened.nightLast;
}

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
 * The engine, as six operations, so the scan does not know which one it has.
 *
 * `scan.js` named `schema.js`, `attack.js`, `tamper.js` and `orphan.js`
 * directly, which meant the SQL engine could only ever be reached by the twin
 * check. Two engines and one of them never on the real path is how the unused
 * one rots however good the comparison is.
 *
 * Deliberately not included: the collision race. It needs two requests in
 * flight at once, which needs two connections, and no credential ever moves
 * into the database - so the SQL engine cannot have it and says so. The scan
 * keeps racing for real down `openSession` whichever engine it is given, and
 * the report says what could not be raced when there is no second connection.
 * That is the one place the two doors are honestly not the same, and it is
 * named rather than papered over.
 */
function nodeEngine() {
  return {
    name: 'node',
    readSchema: (client, target) => schema.readSchema(client, target),
    writeSchema: (client, plan, into) => schema.writeSchema(client, plan, into),
    seed: (client, into, tables) => attack.seed(client, into, tables),
    impersonate: (client, into, tables) => attack.impersonate(client, into, tables),
    tamper: (client, into, tables, seeded, policies) =>
      tamper.tamper(client, into, tables, seeded, policies),
    orphan: (client, into, tables, seeded) => orphan.orphan(client, into, tables, seeded),
  };
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
  // Whichever engine the caller handed over, or the one built in.
  const engine = opts.engine || nodeEngine();

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
  const plan = await engine.readSchema(client, sourceSchema);

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
    await engine.writeSchema(client, plan, copyName);
    const copyPlan = await engine.readSchema(client, copyName);

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
    const sown = await engine.seed(client, copyName, theirs);

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
    const impersonation = await engine.impersonate(client, copyName, theirs.concat(views));

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
      // Whether a rule loops needs no rows: Postgres finds the loop while
      // planning the read, before it looks at a single row. A table nothing
      // could be seeded into has still been checked for that.
      if (key.startsWith('recursive:')) return true;
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
    // The copy's own policies, not the app's - they are the same rules, and
    // the copy is what was actually attacked. The report needs them to say
    // which rule let a write through rather than assuming one.
    const writes = await engine.tamper(client, copyName, theirs, sown.seeded, copyPlan.policies);
    for (const key of writes.completed) attempted.push(key);
    for (const stuck of writes.blocked) {
      notChecked.push({ table: stuck.table, key: stuck.key, why: stuck.why });
    }

    // Can a half-finished write survive? Rolled back like the writes above.
    say('  Looking for rows that could point at nothing ...');
    const stranded = await engine.orphan(client, copyName, theirs, sown.seeded);
    for (const key of stranded.completed) attempted.push(key);
    for (const missed of stranded.notTried) {
      notChecked.push({
        table: missed.table + '.' + missed.column,
        key: 'orphaned:' + missed.table + ':' + missed.column,
        why: missed.why,
      });
    }

    // A rule that looks itself up. The attacks it stopped stay in the list of
    // what was not tested - they did not run - but the loop is also a finding
    // of its own: every signed-in request that touches the table fails, so the
    // app is broken for the people using it. One finding per table at fault,
    // named from Postgres's own message, however many reads ran into it.
    const loops = new Map();
    const loopedInto = (relation, table, who) => {
      if (!loops.has(relation)) loops.set(relation, { kind: 'recursive', table: relation, reads: [], callers: [], columns: [] });
      const entry = loops.get(relation);
      if (!entry.reads.includes(table)) entry.reads.push(table);
      if (!entry.callers.includes(who)) entry.callers.push(who);
    };
    for (const hit of impersonation.looped || []) loopedInto(hit.relation, hit.table, hit.who);
    for (const stuck of writes.blocked) {
      const relation = attack.recursionIn(stuck.why);
      if (relation) loopedInto(relation, stuck.table, /^as anyone:/.test(stuck.why) ? 'anyone' : 'signed-in');
    }
    const recursive = Array.from(loops.values());

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

    // Where people actually sign in decides how bad a duplicate email is. On
    // Supabase that is auth.users, which keeps emails unique; a public table's
    // email column is then a copy. Only read, never written.
    const loginElsewhere = (await client.query("select to_regclass('auth.users') is not null as found")).rows[0].found;
    const raced = collisions.findings.map((f) =>
      f.expectation === 'identity' ? Object.assign({}, f, { loginElsewhere: loginElsewhere }) : f,
    );

    // Functions an anonymous visitor can call that run past the rules. Read
    // from the shape, not attacked: nothing is executed, because whether such
    // a function is meant to be public is a question only the owner answers.
    //
    // Every definer function read this run counts as examined, whether or not
    // anon can call it. That is what lets the re-check call a revoked grant
    // fixed: the function was looked at again and the reach was gone. The first
    // version recorded only the flagged ones, so a revoke made the function
    // vanish from both lists and the fix came back as "could not confirm".
    for (const fn of plan.anonFunctions || []) attempted.push('privileged:' + fn.name);
    // Quiet: a yes/no about the caller, and a function that turns the caller
    // away before it does anything (schema.guardedAtTheDoor).
    const privileged = (plan.anonFunctions || []).filter((fn) => fn.callable && !fn.aboutCaller && !fn.guarded).map((fn) => ({
      kind: 'privileged',
      fn: fn.name,
      table: fn.name,
      args: fn.args,
      writes: fn.writes,
      hasFixedSearchPath: fn.hasFixedSearchPath,
      columns: [],
    }));

    // Whether each table is tied to Supabase's sign-in decides what its fix
    // can be. Read from the original schema: the copy points auth.users keys
    // at a stand-in, and would call every table untied.
    const ties = finding.authTiesOf(plan);
    // And whether a row says whose it is: with no such column, no rule can
    // tie it to the person asking. Read from the copy, the way seeding did.
    // The column's name travels too: a team's table that also says who made
    // each row needs it for its prompt, even on a finding that is not about
    // owners at all.
    const owned = new Map(theirs.map((table) => [table.name, attack.ownerColumn(table)]));
    const tagged = (f) => Object.assign({}, f,
      ties.has(f.table) ? { authTied: ties.get(f.table) } : {},
      owned.has(f.table) ? { owned: Boolean(owned.get(f.table)) } : {},
      owned.get(f.table) ? { ownedBy: owned.get(f.table) } : {});

    return {
      stopped: null,
      attacksRun: attempted.length,
      notChecked: notChecked,
      attempted: attempted,
      findings: finding.describeAll(
        impersonation.findings.concat(writes.findings, stranded.findings, raced, privileged, recursive).map(tagged),
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

/**
 * The exit code of a first run: 2 could not run, 1 something got through, 0
 * every attack lost. Only confirmed findings count as "got through" - a
 * function flagged for verification was never executed, and a script reading
 * 1 would act on a break nobody demonstrated.
 */
function exitCodeFor(result) {
  if (result.stopped) return 2;
  return (result.findings || []).some((f) => f.status !== 'verification required') ? 1 : 0;
}

/** Where the nightly run's last answer is kept for the dashboard. */
function nightlyFile() {
  return store.open(process.cwd()).nightNightly;
}

/**
 * The nightly run's last answer, in the shape the dashboard reads: the same
 * described findings a scan saves, and the three states that are not the same
 * as "nothing found" - not installed, installed and never run, and stopped -
 * said as themselves. `latest` is installer.latestRun's answer.
 */
function nightlyRecord(latest, readAt) {
  const at = (value) => (value ? new Date(value).toISOString() : null);
  if (!latest || !latest.installed) return { readAt: readAt, installed: false };
  const where = latest.where || {};
  const record = {
    readAt: readAt,
    installed: true,
    scheduled: where.job ? where.job.schedule : null,
    active: Boolean(where.job && where.job.active),
    source: where.source || null,
    ranAt: null,
  };
  const run = latest.run;
  if (!run) return record;
  return Object.assign(record, {
    ranAt: at(run.ran_at),
    source: run.source,
    stopped: run.stopped || null,
    attacksRun: run.attacks_run || 0,
    notChecked: run.not_checked || [],
    findings: run.stopped ? [] : finding.describeAll(run.findings || []),
  });
}

/** Kept for the dashboard. A failure here never touches the run itself. */
function saveNightly(file, record) {
  try {
    fs.writeFileSync(file, JSON.stringify(record, null, 2));
    return true;
  } catch (err) {
    return false;
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

/**
 * The last thing on the screen: what was not tested, and why.
 *
 * A report that ends on "nothing got through" is read as "I am safe", and the
 * distance between those two sentences is the whole product. So the last
 * words are always the limits of the answer, not the answer.
 *
 * It is printed even when nothing was missed, because "I tested all of it"
 * and "I did not tell you what I skipped" look identical when the section is
 * simply absent, and only one of them is good news.
 */
function notTestedLines(result) {
  const notChecked = result.notChecked || [];
  const lines = ['', '  ' + '-'.repeat(68), '  What I did not test', ''];

  if (!notChecked.length) {
    lines.push('    Every table I could reach was attacked, and every attack I have');
    lines.push('    finished, ran.');
  } else {
    for (const missed of notChecked) {
      lines.push('    ' + missed.table + ' - ' + missed.why);
    }
    lines.push('');
    lines.push('    These are unknown, not clear. An attack that never ran comes back');
    lines.push('    looking exactly like an attack that was refused.');
  }

  // Said every time, whether or not the collision attack ran. It is the one
  // limit that is structural rather than circumstantial, and a person
  // deciding how far to trust this deserves to know it is there.
  lines.push('');
  lines.push('    One thing is never reported, on purpose: the lost update - two');
  lines.push('    withdrawals of 100 from a balance of 100 that both go through.');
  lines.push('    Every Postgres database behaves that way unless the app asks it');
  lines.push('    not to, so whether yours is affected depends on code I never see.');
  lines.push('    Flagging it would mean flagging every app with a number in it.');
  lines.push('');

  return lines;
}

/**
 * The warning above the verdict: how much went untested, counted honestly.
 *
 * Every entry used to be counted as a table. Found on a benchmark: one
 * column's duplicate test did not run, and the top line said "1 table was
 * NOT checked" about a table every other attack had covered - and a table
 * with two attacks stuck was counted as two tables. An entry with no attack
 * named is a whole table nothing could be put into; one with an attack named
 * is part of a table.
 */
function missedLines(notChecked) {
  const tableOf = (entry) => String(entry.table).split('.')[0];
  const whole = new Set(notChecked.filter((entry) => !entry.key).map(tableOf));
  const parts = notChecked.filter((entry) => entry.key && !whole.has(tableOf(entry)));
  const partly = new Set(parts.map(tableOf));
  const tables = (n) => n + (n === 1 ? ' table' : ' tables');
  const said = [];
  if (whole.size) said.push(tables(whole.size) + (whole.size === 1 ? ' was' : ' were') + ' NOT checked');
  if (parts.length) {
    said.push(parts.length + (parts.length === 1 ? ' check' : ' checks') + ' on ' +
      (whole.size ? tables(partly.size).replace(/ table/, ' other table') : tables(partly.size)) +
      (parts.length === 1 ? ' was' : ' were') + ' NOT run');
  }
  const it = notChecked.length === 1 ? 'it' : 'them';
  return wrap(said.join(', and ') + '. Whatever this report says next is not about ' + it + '. Treat ' +
    it + ' as unknown, not as clear - the list, and why, is at the end.', 68).map((l) => '  ' + l);
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
  // Said before the verdict, and again in full at the very end. The warning
  // has to come first or "everything held" is read before the reason it might
  // not mean anything; the list has to come last or it is the first thing
  // scrolled past. The two are not the same sentence twice - this one is
  // whether to trust the verdict, and the one at the end is what to go and
  // look at.
  const sayWhatWasMissed = () => {
    if (!notChecked.length) return;
    line('');
    missedLines(notChecked).forEach(line);
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
    notTestedLines(result).forEach(line);
    return;
  }

  sayWhatWasMissed();

  // Confirmed breaks and things that only need a look are not the same claim,
  // so they are counted apart. Saying "3 problems" when one of them was never
  // executed is the kind of overstatement that costs the next report its trust.
  const confirmed = result.findings.filter((f) => f.status !== 'verification required');
  const toVerify = result.findings.filter((f) => f.status === 'verification required');
  line('');
  if (confirmed.length) {
    line('  ' + confirmed.length + (confirmed.length === 1 ? ' problem' : ' problems') + ' found.');
  }
  if (toVerify.length) {
    line('  ' + toVerify.length + ' thing' + (toVerify.length === 1 ? '' : 's') +
      ' to check - I did not attack ' + (toVerify.length === 1 ? 'it' : 'them') + ', only spotted the risk.');
  }

  for (const item of result.findings) {
    line('');
    line('  ' + '-'.repeat(68));
    line('  ' + item.severity + '   ' + item.table +
      (item.status === 'verification required' ? '   (verification required)' : ''));
    line('');
    line('  ' + item.headline);
    line('');
    for (const paragraph of [item.body, item.cause].filter(Boolean)) {
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

  notTestedLines(result).forEach(line);
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

  let file;
  try {
    file = lastRunFile(line);
  } catch (err) {
    // 2, not 1: nothing was attacked, so nothing "got through".
    console.error('');
    console.error('  There is nowhere to keep this run (' + err.message + ').');
    console.error('  Set KRYPTHEON_HOME to a folder you can write to, and run this again.');
    console.error('');
    process.exit(2);
  }
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
      process.exitCode = exitCodeFor(result);
      return;
    }

    const verdict = recheck.compare(before, result);
    recheck.describe(verdict).forEach(line);
    recheck.badgeLines(verdict, result.attacksRun || 0).forEach(line);
    // The verdict says what changed; this says what to do about what did not.
    if (result.findings.length) report(result);
    else notTestedLines(result).forEach(line);
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
  missedLines: missedLines,
  wrap: wrap,
  loadLastRun: loadLastRun,
  saveRun: saveRun,
  nightlyFile: nightlyFile,
  nightlyRecord: nightlyRecord,
  saveNightly: saveNightly,
  sweepOldCopies: sweepOldCopies,
  notTestedLines: notTestedLines,
  lastRunFile: lastRunFile,
  exitCodeFor: exitCodeFor,
  ABANDONED_AFTER: ABANDONED_AFTER,
};
