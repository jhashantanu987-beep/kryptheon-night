// Checks that the checks are guests.
// Run with:  node guests.check.js "<postgres connection string>"
//
// KN_DATABASE_URL is whatever connection string somebody typed, and that will
// sometimes be a database with things in it. So the rule for every check is
// the same as for the product: look first, create only what is missing, and
// undo exactly that much.
//
// That rule had a hole. "Only remove what you created" is decided at the start
// of a run, so a run that dies between creating auth.users and dropping it
// leaves a table every later run reads as "already there, not mine" - for
// ever. One did exactly that, and it took a watcher on a throwaway branch to
// prove the live suite was not the one leaking.
//
// The fix is a mark: a check writes a comment on the auth.users it makes, and
// a later run sweeps only a table carrying that mark and old enough that no
// run in another window could still be using it. The point of this file is
// that the mark is read correctly in both directions - our own litter goes,
// and a customer's table is never touched.

const { Client } = require('pg');
const fixture = require('./fixture.js');
const fs = require('fs');
const path = require('path');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;

// The same words fixture.js writes. Spelled out again on purpose: if somebody
// changes the mark there and not here, this stops passing, which is the point.
const MARK = 'made by the kryptheon checks, ';

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

async function present(client) {
  const { rows } = await client.query(
    'SELECT count(*)::int n FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace' +
      " WHERE ns.nspname = 'auth' AND c.relname = 'users'",
  );
  return rows[0].n > 0;
}

/** An auth.users of our own, wearing whatever comment we want to test. */
async function plant(client, comment) {
  await client.query('DROP TABLE IF EXISTS auth.users CASCADE');
  await client.query('CREATE TABLE auth.users (id uuid PRIMARY KEY, email text)');
  if (comment !== null) {
    await client.query("COMMENT ON TABLE auth.users IS '" + comment.split("'").join("''") + "'");
  }
}

async function main() {
  if (!CONNECTION) {
    console.error('');
    console.error('  node guests.check.js "<postgres connection string>"');
    console.error('');
    process.exit(2);
  }

  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  const undoAuth = await fixture.ensureAuth(client);
  // Whether this run planted an auth.users of its own. The cleanup below
  // must never be allowed to run on a table it did not make - which is the
  // very mistake this file exists to catch, and it was in this file first.
  let plantedOurOwn = false;

  try {
    // This file has to create and remove auth.users to test any of it, and it
    // will not do that to somebody's real one. Said out loud rather than
    // skipped quietly: a check nobody ran must not read like a check that
    // passed.
    if (await present(client)) {
      check('0. there is room here to test this at all', [
        'this database already has an auth.users, and it is not this run\'s to create or remove.',
        'Nothing was touched. Point the checks at a database without one, or remove that table' +
          ' yourself if it is a leftover.',
      ]);
    } else {
      plantedOurOwn = true;
      const old = Date.now() - fixture.ABANDONED_AFTER - 60 * 60 * 1000;

      await plant(client, MARK + old.toString(36));
      await fixture.sweepOldFixtures(client);
      check('1. a stranded one of ours, old enough, is swept away', (await present(client))
        ? ['it is still there'] : []);

      await plant(client, MARK + Date.now().toString(36));
      await fixture.sweepOldFixtures(client);
      check('2. a fresh one of ours is left alone', (await present(client))
        // Two suites at once is not a strange thing to do, and sweeping the
        // other one out from under itself would break a run going fine.
        ? [] : ['it swept away a table a run in another window could be using']);

      // A fixture schema whose word has a digit in it. kn_hunt2_ is real and
      // the sweep pattern did not match it, so it was never cleared away.
      const stale = 'kn_hunt2_9_' + old.toString(36);
      await client.query('CREATE SCHEMA "' + stale + '"');
      await fixture.sweepOldFixtures(client);
      check('3. a fixture whose name has a digit in it is swept too', await (async () => {
        const { rows } = await client.query('SELECT 1 FROM pg_namespace WHERE nspname = $1', [stale]);
        if (!rows.length) return [];
        await client.query('DROP SCHEMA IF EXISTS "' + stale + '" CASCADE').catch(() => {});
        return ['it is still there: ' + stale];
      })());

      await plant(client, null);
      await fixture.sweepOldFixtures(client);
      check("4. a table with no mark on it is the customer's, and is never touched",
        (await present(client)) ? [] : ['it dropped a table it did not make']);

      await plant(client, 'our real users table, do not delete');
      await fixture.sweepOldFixtures(client);
      check('5. nor is one whose comment simply is not ours',
        (await present(client)) ? [] : ['it dropped a table it did not make']);

      await client.query('DROP TABLE IF EXISTS auth.users CASCADE');
      let fellOver = null;
      try {
        await fixture.sweepOldFixtures(client);
      } catch (err) {
        fellOver = err.message;
      }
      check('6. and it does not fall over where there is no such table at all',
        fellOver ? [fellOver] : []);

      const made = await fixture.ensureAuthUsers(client, 'id uuid PRIMARY KEY, email text');
      check('7. one is created where there is none, and marked as ours', await (async () => {
        const problems = [];
        if (!made.made) problems.push('it did not say it made one');
        if (!(await present(client))) problems.push('and there is no table there');
        const { rows } = await client.query(
          "SELECT obj_description('auth.users'::regclass, 'pg_class') AS mark",
        );
        if (!String(rows[0].mark || '').startsWith(MARK)) {
          problems.push('the mark fixture.js writes is not the one this file looks for: ' +
            JSON.stringify(rows[0].mark));
        }
        return problems;
      })());

      const again = await fixture.ensureAuthUsers(client, 'id uuid PRIMARY KEY');
      check('8. a second caller never touches one that is already there', await (async () => {
        const problems = [];
        if (again.made) problems.push('it claimed to have made one');
        await again.undo();
        if (!(await present(client))) problems.push("and its undo removed a table it did not make");
        return problems;
      })());

      await made.undo();
      check('9. while the caller that did make it takes it away',
        (await present(client)) ? ['it is still there'] : []);
    }
    // Needs no database, and is the one that stops this happening again. A
    // fixture named outside what the sweep looks for is not swept, and a
    // sweep that finds nothing to do looks exactly like a clean database.
    check('10. every fixture the suite builds is one the sweep can see', (() => {
      const problems = [];
      // Named but never created as a schema: it is handed to the CLI
      // precisely because nothing of that name exists.
      const neverBuilt = ['this_schema_does_not_exist_'];
      const sweeps = /^kn_[a-z0-9]+_/;
      // Read off the suite itself rather than off the directory. A guard
      // that walks an empty list reports no problems and passes - the same
      // shape as the sweep it is here to defend - so what it must read is
      // fixed by what npm actually runs, and a file it could not read is a
      // failure rather than one fewer thing to look at.
      const suite = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
      const runs = String(suite.scripts.check).match(new RegExp('[a-z0-9]+\\.check\\.js', 'g')) || [];
      if (runs.length < 2) problems.push('the suite in package.json lists no checks to read');
      // Counted, not assumed. Reading none of them and reporting nothing
      // wrong is the failure this whole file is about.
      let read = 0;
      for (const file of runs) {
        let text;
        try {
          text = fs.readFileSync(path.join(__dirname, file), 'utf8');
          read++;
        } catch (err) {
          problems.push('the suite runs ' + file + ', and it is not here to read');
          continue;
        }
        const wanted = new RegExp("'([a-z_][a-z0-9_]*_)'\\s*\\+\\s*(?:n\\s*\\+\\s*'_'\\s*\\+\\s*)?Date\\.now\\(\\)\\.toString\\(36\\)", 'g');
        let found;
        while ((found = wanted.exec(text)) !== null) {
          const prefix = found[1];
          if (neverBuilt.includes(prefix)) continue;
          if (!sweeps.test(prefix)) {
            problems.push(file + ' builds ' + prefix + '... , which no sweep will ever clear away');
          }
        }
      }
      if (read !== runs.length) {
        problems.push('it read ' + read + ' of the ' + runs.length + ' checks the suite runs');
      }
      return problems;
    })());

  } finally {
    if (plantedOurOwn) {
      await client.query('DROP TABLE IF EXISTS auth.users CASCADE').catch(() => {});
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
    console.log('All ' + results.length + ' guest checks passed.');
  }
}

main().catch((err) => {
  console.error('');
  console.error('  The check could not run: ' + err.message);
  console.error('');
  process.exit(1);
});
