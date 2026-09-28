// Checks the outside attack: the one that needs only what a browser is handed.
// Run with:  node outside.check.js
//
// Two halves, both against real behaviour, neither against a real app.
//
//   Discovery is pure string work over a fetch that hands back a fixed page and
//   bundle, so it needs no network: the values it must pull out are known, and
//   a service_role key planted in the same bundle must NOT be the one it picks.
//
//   The read itself runs against a local server that answers like PostgREST -
//   200 with a count for a table anyone may read, 401 for one row level
//   security protects, 404 for one that is not exposed - and it refuses any
//   request that arrives without the key, so a run that still finds the open
//   table has proved the key was sent.
//
// This file sits outside anything Playwright or pg would pick up and is run on
// its own.

// A run this check causes is saved to a scratch store, never the real
// ~/.kryptheon (see store.js).
process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawn } = require('child_process');
const outside = require('./outside.js');
const finding = require('./finding.js');

const CLI = path.join(__dirname, 'bin', 'kryptheon-night.js');

const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

// A Supabase anon key in JWT form, and a service_role key in the same shape,
// so the check can prove the public one is chosen and the powerful one left.
function jwt(role) {
  const body = Buffer.from(JSON.stringify({ role: role, iss: 'supabase' })).toString('base64url');
  return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + body + '.' + 'x'.repeat(20);
}

const ANON = jwt('anon');
const SERVICE = jwt('service_role');

const HTML = '<!doctype html><html><head>' +
  '<script type="module" src="/assets/index-abc123.js"></script>' +
  '</head><body><div id="root"></div></body></html>';

// A bundle shaped like a built Vite app: the address, both keys, and the table
// calls the client makes.
const BUNDLE = [
  'const SUPABASE_URL="https://abcd1234.supabase.co";',
  // The service_role key is placed FIRST on purpose: whichever JWT comes first
  // in the text is the one a careless picker would grab, so choosing the anon
  // key here proves the role is actually being read, not the order.
  '// a service_role key that should never have been shipped, but is:',
  'const ADMIN="' + SERVICE + '";',
  'const SUPABASE_ANON_KEY="' + ANON + '";',
  'createClient(SUPABASE_URL,SUPABASE_ANON_KEY);',
  'sb.from("bookings").select("*");',
  'sb.from("profiles").insert(x);',
  'sb.from("secrets").select("token");',
  'sb.from(`missing_table`).select();',
].join('\n');

// A fetch that answers only these two addresses, for the discovery half.
function pageFetch(url) {
  const body = url.endsWith('.js') ? BUNDLE : HTML;
  return Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve(body),
  });
}

// The PostgREST stand-in for the read half. Requires the key, and answers each
// table the way a real project would.
function startServer() {
  const server = http.createServer((req, res) => {
    // The app itself: its page and its bundle, the way a browser gets them.
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(server.noBackend ? '<html><body>just a page</body></html>' : HTML);
      return;
    }
    if (req.url.startsWith('/assets/')) {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end(BUNDLE);
      return;
    }
    const hasKey = req.headers.apikey === ANON || req.headers.authorization === 'Bearer ' + ANON;
    if (!hasKey) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"message":"No API key found in request"}');
      return;
    }
    const table = req.url.split('?')[0].replace('/rest/v1/', '');
    if (table === 'bookings') {
      res.writeHead(200, { 'content-range': '*/3', 'content-type': 'application/json' });
      res.end('[]'); // limit=0, so no row ever leaves
    } else if (table === 'profiles') {
      res.writeHead(200, { 'content-range': '*/0', 'content-type': 'application/json' });
      res.end('[]');
    } else if (table === 'secrets') {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end('{"message":"permission denied for table secrets"}');
    } else {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"message":"Not Found"}');
    }
  });
  return new Promise((resolve) => server.listen(0, () => resolve(server)));
}

// Runs the real command. The bundle names https://abcd1234.supabase.co, which
// does not exist, so a preload loaded only into this child sends those
// requests to the stand-in instead. The command itself is untouched: it reads
// the page, finds the address and the key, and asks - exactly as it would a
// real app.
let preload = null;
function runCli(appUrl) {
  const origin = new URL(appUrl).origin;
  if (!preload) {
    preload = path.join(os.tmpdir(), 'kn-outside-redirect-' + process.pid + '.js');
    fs.writeFileSync(preload, [
      'const real = global.fetch;',
      'global.fetch = (url, init) => real(String(url).replace("https://abcd1234.supabase.co", process.env.KN_STANDIN), init);',
    ].join('\n'), 'utf8');
  }
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--require', preload, CLI, appUrl], {
      env: Object.assign({}, process.env, { KN_STANDIN: origin, KN_DATABASE_URL: '' }),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (out += c));
    const timer = setTimeout(() => child.kill(), 60000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code, out: out.replace(/\r\n/g, '\n') });
    });
  });
}

(async () => {
  // ---- discovery, no network ----
  const found = await outside.discover('https://my-app.example.com', { fetch: pageFetch });
  check('1. the Supabase address, the public key and the tables are read from the app', (() => {
    const problems = [];
    if (found.supabaseUrl !== 'https://abcd1234.supabase.co') problems.push('address: ' + found.supabaseUrl);
    if (found.key !== ANON) problems.push('key was not the anon key: ' + String(found.key).slice(0, 12));
    const want = ['bookings', 'profiles', 'secrets', 'missing_table'];
    if (JSON.stringify(found.tables.sort()) !== JSON.stringify(want.sort())) problems.push('tables: ' + found.tables.join(', '));
    return problems;
  })());

  check('2. a service_role key in the same bundle is never chosen', (() => {
    return found.key === SERVICE ? ['it picked the service_role key'] : [];
  })());

  check('3. an app with no backend in it is a clear message, not a crash', await (async () => {
    try {
      await outside.discover('https://plain-site.example.com', {
        fetch: () => Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve('<html><body>hi</body></html>') }),
      });
      return ['it did not object to an app with no Supabase in it'];
    } catch (err) {
      return err.code === 'no-backend' ? [] : ['wrong error: ' + err.message];
    }
  })());

  // ---- the read, against the PostgREST stand-in ----
  const server = await startServer();
  const origin = 'http://127.0.0.1:' + server.address().port;
  try {
    const report = await outside.prowl({ supabaseUrl: origin, key: ANON, tables: ['bookings', 'profiles', 'secrets', 'missing_table'] });

    check('4. a table anyone can read is found, with its row count', (() => {
      const problems = [];
      const b = report.findings.find((f) => f.table === 'bookings');
      if (!b) problems.push('bookings, which anyone can read, was not found: ' + JSON.stringify(report.findings.map((f) => f.table)));
      else {
        if (b.readable !== 3) problems.push('the count was ' + b.readable + ', not 3');
        if (b.kind !== 'exposed' || b.who !== 'anyone') problems.push('the finding was the wrong shape: ' + JSON.stringify(b));
        if (!b.countOnly) problems.push('the finding did not record that it was count-only');
      }
      return problems;
    })());

    check('5. a 200 with zero rows is NOT called a leak - from outside it cannot be told from good security', (() => {
      const problems = [];
      // profiles answers 200 with count 0. A properly protected table returns
      // exactly this to a stranger, so claiming a leak here would be crying
      // wolf. It goes to the "could not tell" bucket, not to findings.
      if (report.findings.some((f) => f.table === 'profiles')) problems.push('an empty 200 was reported as a leak');
      if (!report.emptyTables.includes('profiles')) problems.push('the could-not-tell table was not carried through: ' + JSON.stringify(report.emptyTables));
      return problems;
    })());

    check('6. a protected table is not a finding, and a table that is not exposed is not either', (() => {
      const problems = [];
      if (report.findings.some((f) => f.table === 'secrets')) problems.push('a protected table was reported as open');
      if (!report.protectedTables.includes('secrets')) problems.push('the protected table was not noted as protected');
      if (report.findings.some((f) => f.table === 'missing_table')) problems.push('a table that 404s was reported as open');
      if (!report.absent.includes('missing_table')) problems.push('the absent table was not noted');
      return problems;
    })());

    check('7. the key really is sent - the stand-in refuses every request without it', (() => {
      // The server 401s anything with no key. bookings being found at all is
      // the proof the key went with the request.
      return report.findings.some((f) => f.table === 'bookings') ? [] : ['no finding, so the key may not have been sent'];
    })());

    check('8. the report says it counted, never that it pulled the rows out', (() => {
      const problems = [];
      const b = report.findings.find((f) => f.table === 'bookings');
      if (!b) return ['bookings was not found as a finding, so its wording could not be checked'];
      const described = finding.describe(b);
      if (/got back \d+ rows/.test(described.body)) problems.push('it claimed to have pulled rows: ' + described.body);
      if (!/asked your live app as a stranger/.test(described.body)) problems.push('it did not say it only asked: ' + described.body);
      if (!/never pulled a row/.test(described.body)) problems.push('it did not say it pulled nothing');
      if (described.severity !== 'CRITICAL' && described.severity !== 'HIGH') problems.push('severity: ' + described.severity);
      if (!/only read their own rows/i.test(described.fixPrompt)) problems.push('the fix does not say to lock reads to the owner: ' + described.fixPrompt.slice(0, 120));
      if (described.fixPrompt.indexOf(b.table) === -1) problems.push('the fix does not name the table');
      return problems;
    })());

    // ---- the real command, end to end, against the leaky stand-in app ----
    const leaky = await runCli(origin + '/');
    check('9. the real command finds the leak from nothing but the app\'s address', (() => {
      const problems = [];
      // The report wraps at 70 columns, so a sentence can span two lines. Read
      // it as a person does: the words in order, not where the breaks fell.
      const out = leaky.out.replace(/[ \t]*\n[ \t]*/g, ' ').replace(/ {2,}/g, ' ') + '\n' + leaky.out;
      if (leaky.code !== 1) problems.push('exit was ' + leaky.code + ', not 1 for a leak');
      if (!/Your bookings table can be read by anyone/.test(out)) problems.push('the leak was not reported');
      if (!/there are 3 rows/.test(out)) problems.push('the row count was not said');
      if (!/never pulled a row out/.test(out)) problems.push('it did not say it pulled nothing');
      if (!/Could not tell: profiles/.test(out)) problems.push('the empty table was not called undecided');
      if (!/Refused a stranger outright: secrets/.test(out)) problems.push('the protected table was not listed');
      if (!/npx kryptheon-night\n/.test(out)) problems.push('it did not point at the deep scan for what it could not test');
      if (/connection string\?|Paste your connection|nobody here to ask/i.test(out)) problems.push('it asked for a connection string');
      if (/\bis safe\b|your data is safe|no problems/i.test(out)) problems.push('it claimed safety: ' + (out.match(/.*safe.*/i) || [''])[0]);
      return problems;
    })());

    server.noBackend = true;
    const plain = await runCli(origin + '/');
    server.noBackend = false;
    check('10. an app with no database: a plain sentence and exit 2, no prompt, no stack trace', (() => {
      const problems = [];
      if (plain.code !== 2) problems.push('exit was ' + plain.code);
      if (!/could not find a Supabase address/.test(plain.out)) problems.push('not the plain message: ' + plain.out.slice(-300));
      if (/\n\s+at .+\(.+:\d+:\d+\)/.test(plain.out)) problems.push('a stack trace reached the person');
      if (/nobody here to ask/.test(plain.out)) problems.push('it went looking for a connection string');
      return problems;
    })());

    check('11. with nothing found, it still says what it could not test - never that the app is safe', (() => {
      const lines = outside.reportLines(
        { appUrl: 'https://x.example.com', supabaseUrl: 'https://abcd1234.supabase.co' },
        { findings: [], attempted: ['orders'], protectedTables: ['orders'], emptyTables: [], absent: [], unclear: [] },
      ).join('\n');
      const problems = [];
      if (!/What I could NOT test from outside/.test(lines)) problems.push('the not-tested section is missing');
      if (!/one signed-in customer can read another/.test(lines)) problems.push('it did not name the attacks it cannot run');
      if (/\bis safe\b|your data is safe/i.test(lines)) problems.push('it claimed safety');
      return problems;
    })());
  } finally {
    server.close();
  }

  console.log('');
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
    // exitCode, not exit(): let the just-closed server's handles finish
    // closing, or libuv aborts on Windows.
    process.exitCode = 1;
  } else {
    console.log('All ' + results.length + ' outside-attack checks passed.');
  }
})().catch((err) => {
  console.error('the check itself could not run: ' + (err && err.stack ? err.stack : err));
  process.exitCode = 1;
});
