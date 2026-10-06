// Checks that a Supabase Storage bucket switched to public is reported when a
// read rule on it says it was meant to be private - by both engines, from the
// bucket's settings and rules alone, never a file.
//
//   node buckets.check.js "<postgres connection string>"
//
// Found on two blind tests (OrbitDesk, AtlasPay): a bucket of exports and one
// of settlement evidence were public, and storage was never looked at.
//
// Where the database has no Supabase Storage, a small stand-in is built for
// the run and taken away after it. Where it has one, only buckets and rules
// named for this run are added, and only those are removed.

process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const { Client } = require('pg');
const schema = require('./schema.js');
const fixture = require('./fixture.js');
const recheck = require('./recheck.js');
const sqlengine = require('./sqlengine.js');
const scanner = require('./scan.js');

const CONNECTION = process.argv[2] || process.env.KN_DATABASE_URL;
const STAMP = Date.now().toString(36);
const APP = 'kn_buckets_' + STAMP;
const WHO = "(current_setting('request.jwt.claims', true)::json->>'sub')";
const id = (name) => 'kn-' + name + '-' + STAMP;

const results = [];
const check = (name, problems) => results.push({ name, problems });

// What each bucket is, and whether it should be reported.
const BUCKETS = [
  // Public, and a rule lets in only the people a file belongs to.
  { name: 'exports', public: true, rule: { cmd: 'SELECT', to: 'public', extra: true }, report: true },
  // Public, and the rule says signed-in people only.
  { name: 'members', public: true, rule: { cmd: 'SELECT', to: 'authenticated', extra: false }, report: true },
  // A FOR ALL rule reads as well as writes.
  { name: 'everything', public: true, rule: { cmd: 'ALL', to: 'public', extra: true }, report: true },
  // Public, and the rule lets everyone in anyway: it was meant to be public.
  { name: 'avatars', public: true, rule: { cmd: 'SELECT', to: 'public', extra: false }, report: false },
  // Public, with no rule at all: nothing says it was meant to be private.
  { name: 'plain', public: true, rule: null, report: false },
  // Public, no rule, and a name that says what it holds (HarborLine's
  // customer-exports, whose one rule had failed to load).
  { name: 'backups', public: true, rule: null, report: true, noRule: true },
  // Private: what the rule says is what happens.
  { name: 'private', public: false, rule: { cmd: 'SELECT', to: 'public', extra: true }, report: false },
  // Public, and the only rule is about removing files, not reading them.
  { name: 'removals', public: true, rule: { cmd: 'DELETE', to: 'authenticated', extra: true }, report: false },
];

let builtStorage = false;

/** A stand-in for Supabase Storage, shaped as it is, when there is none. */
async function ensureStorage(client) {
  const { rows } = await client.query("SELECT to_regclass('storage.buckets') IS NOT NULL AS here");
  if (rows[0].here) return;
  builtStorage = true;
  await client.query('CREATE SCHEMA storage');
  await client.query('GRANT USAGE ON SCHEMA storage TO anon, authenticated');
  await client.query('CREATE TABLE storage.buckets (id text PRIMARY KEY, name text NOT NULL, public boolean DEFAULT false)');
  await client.query('CREATE TABLE storage.objects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), bucket_id text' +
    ' REFERENCES storage.buckets(id), name text, owner uuid)');
  await client.query('ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY');
  await client.query('GRANT SELECT ON storage.objects, storage.buckets TO anon, authenticated');
}

async function addBuckets(client) {
  for (const b of BUCKETS) {
    await client.query('INSERT INTO storage.buckets (id, name, public) VALUES ($1, $1, $2)', [id(b.name), b.public]);
    if (!b.rule) continue;
    const test = "bucket_id = '" + id(b.name) + "'" + (b.rule.extra ? ' AND name LIKE ' + WHO + " || '/%'" : '');
    const clause = b.rule.cmd === 'INSERT' ? 'WITH CHECK (' + test + ')' : 'USING (' + test + ')';
    await client.query('CREATE POLICY ' + schema.quote(id(b.name)) + ' ON storage.objects FOR ' + b.rule.cmd +
      ' TO ' + b.rule.to + ' ' + clause);
  }
}

async function removeBuckets(client) {
  if (builtStorage) {
    await client.query('DROP SCHEMA IF EXISTS storage CASCADE').catch(() => {});
    return;
  }
  for (const b of BUCKETS) {
    await client.query('DROP POLICY IF EXISTS ' + schema.quote(id(b.name)) + ' ON storage.objects').catch(() => {});
    await client.query('DELETE FROM storage.buckets WHERE id = $1', [id(b.name)]).catch(() => {});
  }
}

/** Only this run's buckets: a real project has its own. */
const ours = (list) => (list || []).filter((b) => String(b.id).endsWith('-' + STAMP));

/** Both engines, the whole scan, on one schema. */
async function bothScans(client, app) {
  const node = await scanner.scan(client, app, { quiet: true });
  const sql = await sqlengine.withEngine(client, (target) =>
    scanner.scan(client, app, { quiet: true, engine: sqlengine.adapterFor(target) }));
  return [['node', node], ['sql', sql]];
}

async function main() {
  if (!CONNECTION) {
    console.error('\n  node buckets.check.js "<postgres connection string>"\n');
    process.exit(2);
  }
  const client = new Client({ connectionString: CONNECTION });
  await client.connect();
  try {
    await fixture.ensureRoles(client, null, schema.quote);
    await client.query('CREATE SCHEMA ' + schema.quote(APP));
    await client.query('GRANT USAGE ON SCHEMA ' + schema.quote(APP) + ' TO anon, authenticated');
    await client.query('CREATE TABLE ' + schema.quote(APP) + '.notes (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), body text NOT NULL)');
    await client.query('ALTER TABLE ' + schema.quote(APP) + '.notes ENABLE ROW LEVEL SECURITY');

    // ---------------------------------------- a database with no storage
    const { rows: present } = await client.query("SELECT to_regclass('storage.buckets') IS NOT NULL AS here");
    if (!present[0].here) {
      const node = await schema.readBuckets(client);
      let sql = null;
      await sqlengine.withEngine(client, async (target) => {
        sql = (await client.query('SELECT ' + schema.quote(target) + '.read_buckets() AS answer')).rows[0].answer;
      });
      // And inside a transaction, where a failed query would break the next.
      let inside = null;
      await client.query('BEGIN');
      try {
        await schema.readBuckets(client);
        inside = (await client.query('SELECT 1 AS one')).rows[0].one;
      } catch (err) {
        inside = err.message;
      } finally {
        await client.query('ROLLBACK').catch(() => {});
      }
      check('a database with no Supabase Storage has no buckets, and is not an error, in both engines', (() => {
        const p = [];
        if (JSON.stringify(node) !== '[]') p.push('node: ' + JSON.stringify(node));
        if (JSON.stringify(sql) !== '[]') p.push('sql: ' + JSON.stringify(sql));
        if (inside !== 1) p.push('looking broke the transaction it was asked in: ' + inside);
        return p;
      })());
    } else {
      console.log('NOTE  this database has Supabase Storage already; the no-storage case is checked where it has none');
    }

    await ensureStorage(client);
    await addBuckets(client);
    const objectsBefore = (await client.query('SELECT count(*)::int AS n FROM storage.objects')).rows[0].n;

    // ---------------------------------------- what is read
    const fromNode = await schema.readSchema(client, APP);
    let fromSql = null;
    await sqlengine.withEngine(client, async (target) => {
      fromSql = await sqlengine.readSchema(client, target, APP);
    });
    check('both engines read the same buckets and rules, key for key', (() => {
      const a = JSON.stringify(ours(fromNode.buckets));
      const b = JSON.stringify(ours(fromSql.buckets));
      const p = a === b ? [] : ['node ' + a, 'sql  ' + b];
      if (ours(fromNode.buckets).length !== BUCKETS.length) p.push('node read ' + ours(fromNode.buckets).length + ' buckets');
      const removals = ours(fromNode.buckets).find((b2) => b2.id === id('removals'));
      if (!removals || removals.readRules.length) p.push('a rule for removing files was read as a read rule: ' + JSON.stringify(removals));
      return p;
    })());

    check('a public bucket is reported only when a rule says it was meant to be private', (() => {
      const said = scanner.bucketsOf({ buckets: ours(fromNode.buckets) }).map((f) => f.bucket).sort();
      const want = BUCKETS.filter((b) => b.report).map((b) => id(b.name)).sort();
      return JSON.stringify(said) === JSON.stringify(want) ? [] : ['said ' + JSON.stringify(said), 'want ' + JSON.stringify(want)];
    })());

    // ---------------------------------------- what is said
    const scans = await bothScans(client, APP);
    check('the whole scan reports them as things to check, worded plainly, in both engines', (() => {
      const p = [];
      for (const [engine, result] of scans) {
        if (result.stopped) { p.push(engine + ' stopped: ' + result.stopped); continue; }
        const found = result.findings.filter((f) => f.kind === 'bucket' && String(f.table).endsWith(STAMP));
        const names = found.map((f) => f.table).sort();
        const want = BUCKETS.filter((b) => b.report).map((b) => id(b.name)).sort();
        if (JSON.stringify(names) !== JSON.stringify(want)) p.push(engine + ' reported ' + JSON.stringify(names));
        for (const f of found) {
          if (f.status !== 'verification required') p.push(engine + ' ' + f.table + ' is ' + f.status);
          if (f.severity !== 'HIGH') p.push(engine + ' ' + f.table + ' is ' + f.severity);
          const prompt = f.fixPrompt.replace(/\s+/g, ' ');
          if (!/please check it rather than assume it/.test(prompt)) p.push(engine + ' prompt claims a break');
          if (prompt.indexOf("UPDATE storage.buckets SET public = false WHERE id = '" + f.table + "'") < 0) p.push(engine + ' prompt: ' + prompt);
          if (!/createSignedUrl/.test(prompt)) p.push(engine + ' never says the links will need signing');
          if (!/I did not open or list any file/.test(f.body)) p.push(engine + ' body: ' + f.body);
        }
        const backups = found.find((f) => f.table === id('backups'));
        if (backups && backups.headline !== 'Your ' + id('backups') + ' storage bucket is public, and its name says its files are not for everyone.') {
          p.push(engine + ': ' + backups.headline);
        }
        if (backups && !/no rule on storage\.objects says who may read it/.test(backups.fixPrompt.replace(/\s+/g, ' '))) p.push(engine + ' no-rule prompt: ' + backups.fixPrompt);
        const exports = found.find((f) => f.table === id('exports'));
        if (exports && exports.headline !== 'Your ' + id('exports') + ' storage bucket is public, but a rule says only some people may read it.') {
          p.push(engine + ': ' + exports.headline);
        }
        for (const b of BUCKETS) {
          if (!(result.attempted || []).includes('bucket:' + id(b.name))) p.push(engine + ': ' + b.name + ' not counted as looked at');
        }
        if (scanner.exitCodeFor({ findings: found }) !== 0) p.push(engine + ': a bucket alone gives a failing exit code');
      }
      return p;
    })());

    const objectsAfter = (await client.query('SELECT count(*)::int AS n FROM storage.objects')).rows[0].n;
    const stillPublic = (await client.query('SELECT count(*)::int AS n FROM storage.buckets WHERE public AND id LIKE $1', ['%-' + STAMP])).rows[0].n;
    check('reading the buckets changed nothing in storage', [].concat(
      objectsAfter !== objectsBefore ? ['objects ' + objectsBefore + ' -> ' + objectsAfter] : [],
      stillPublic !== BUCKETS.filter((b) => b.public).length ? ['public buckets now ' + stillPublic] : [],
    ));

    // ---------------------------------------- the nightly run, inside the database
    let nightBuckets = null;
    await sqlengine.withEngine(client, async (target) => {
      const runId = (await client.query('SELECT ' + schema.quote(target) + '.nightly($1) AS id', [APP])).rows[0].id;
      const row = (await client.query('SELECT findings FROM ' + schema.quote(target) + '.runs WHERE id = $1', [runId])).rows[0];
      nightBuckets = (row.findings || []).filter((f) => f.kind === 'bucket' && String(f.table).endsWith(STAMP));
    });
    check('the nightly run inside the database reports the same buckets, the same way', (() => {
      const canon = (list) => JSON.stringify(list.map((f) => Object.keys(f).sort().reduce((o, k) => { o[k] = f[k]; return o; }, {})).sort((a, b) => (a.table < b.table ? -1 : 1)));
      const cli = scanner.bucketsOf({ buckets: ours(fromNode.buckets) });
      return canon(nightBuckets || []) === canon(cli) ? [] : ['nightly ' + canon(nightBuckets || []), 'cli     ' + canon(cli)];
    })());

    // ---------------------------------------- the nightly read-back
    const record = scanner.nightlyRecord(
      { installed: true, where: { job: { schedule: '0 3 * * *', active: true }, source: APP },
        run: { ran_at: new Date().toISOString(), source: APP, attacks_run: 1, findings: [], not_checked: [] } },
      new Date().toISOString(), fromNode);
    check('the nightly read-back reads the buckets when it is asked', (() => {
      const said = (record.findings || []).filter((f) => f.kind === 'bucket' && String(f.table).endsWith(STAMP)).map((f) => f.table).sort();
      const want = BUCKETS.filter((b) => b.report).map((b) => id(b.name)).sort();
      return JSON.stringify(said) === JSON.stringify(want) ? [] : ['said ' + JSON.stringify(said)];
    })());

    // ---------------------------------------- the re-check
    const before = scans[0][1];
    await client.query('UPDATE storage.buckets SET public = false WHERE id = $1', [id('exports')]);
    const after = await scanner.scan(client, APP, { quiet: true });
    check('a bucket made private is called fixed by the re-check, and the others still open', (() => {
      const verdict = recheck.compare(before, after);
      const p = [];
      const fixed = verdict.fixed.map(recheck.keyOf);
      const open = verdict.stillOpen.map(recheck.keyOf);
      if (!fixed.includes('bucket:' + id('exports'))) p.push('fixed ' + JSON.stringify(fixed));
      if (!open.includes('bucket:' + id('members'))) p.push('still open ' + JSON.stringify(open));
      if (verdict.unverifiable.length) p.push('unverifiable ' + JSON.stringify(verdict.unverifiable.map(recheck.keyOf)));
      const said = recheck.describe(verdict).join('\n');
      if (!/no longer public/.test(said)) p.push(said);
      return p;
    })());
  } finally {
    await removeBuckets(client);
    await client.query('DROP SCHEMA IF EXISTS ' + schema.quote(APP) + ' CASCADE').catch(() => {});
    await client.end().catch(() => {});
  }

  let failures = 0;
  for (const r of results) {
    if (r.problems.length) {
      failures++;
      console.log('FAIL  ' + r.name);
      r.problems.forEach((p) => console.log('      - ' + p));
    } else {
      console.log('PASS  ' + r.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exit(1);
  }
  console.log('All ' + results.length + ' bucket checks passed.');
}

main().catch((err) => {
  console.error('  the check itself could not run: ' + err.message);
  process.exit(1);
});
