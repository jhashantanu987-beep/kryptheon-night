// Checks `kryptheon-night words` - the command's own words, as JSON, for the
// kryptheon dashboard to show on its buttons. Run with:  node words.check.js
//
// The dashboard shows the same help, the same consent screens and the same
// warnings the terminal shows, by asking this command for them rather than
// keeping a copy that could drift. So this has to hold: it says exactly what
// the command says, it never connects, and it never prints the string.

const path = require('path');
const { spawnSync } = require('child_process');
const intro = require('./intro.js');
const installer = require('./installer.js');

const BIN = path.join(__dirname, 'bin', 'kryptheon-night.js');
const SECRET = 'Zq7-never-shown-9Xw';

const results = [];
const check = (name, problems) => results.push({ name, problems });

function words(args, connection, extra) {
  const env = Object.assign({}, process.env);
  delete env.KN_DATABASE_URL;
  delete env.KRYPTHEON_PROJECT_TOKEN;
  delete env.KRYPTHEON_REPORT_URL;
  if (connection !== undefined) env.KN_DATABASE_URL = connection;
  Object.assign(env, extra || {});
  const started = Date.now();
  const r = spawnSync(process.execPath, [BIN, 'words'].concat(args || []), { encoding: 'utf8', env: env, timeout: 30000 });
  let json = null;
  try { json = JSON.parse(r.stdout); } catch (err) { json = null; }
  return { code: r.status, out: String(r.stdout || '') + String(r.stderr || ''), json: json, ms: Date.now() - started };
}

const plain = words(['--schema', 'shop']);
check('1. it prints the same help and consent screens the command shows, as JSON', (() => {
  const p = [];
  if (plain.code !== 0 || !plain.json) return ['exit ' + plain.code + ', output: ' + plain.out.slice(0, 300)];
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  if (!same(plain.json.help, intro.whereToFindIt())) p.push('the help differs from the terminal\'s');
  if (!same(plain.json.consent, intro.consentLines('shop'))) p.push('the consent screen differs, or is not for the schema asked about');
  if (!same(plain.json.installConsent, intro.installConsentLines(installer.SCHEMA, 'shop', installer.AT))) p.push('the nightly consent differs');
  if (plain.json.nightlyAt !== installer.AT) p.push('nightlyAt is ' + plain.json.nightlyAt);
  if (plain.json.given !== false || plain.json.warning !== null || plain.json.unusable !== null) p.push('with no string it still judged one');
  return p;
})());

const TOKEN = 'kp_' + 'Wq'.repeat(20);
const reporting = words(['--schema', 'shop'], undefined, {
  KRYPTHEON_PROJECT_TOKEN: TOKEN, KRYPTHEON_REPORT_URL: 'https://abc.supabase.co/functions/v1/ingest',
});
check('1b. with a project token in the environment, the nightly consent is the one that says what it sends', (() => {
  const p = [];
  if (!reporting.json) return ['exit ' + reporting.code + ', output: ' + reporting.out.slice(0, 300)];
  const want = intro.installConsentLines(installer.SCHEMA, 'shop', installer.AT, { endpoint: 'x' });
  if (JSON.stringify(reporting.json.installConsent) !== JSON.stringify(want)) p.push('the nightly consent is not the reporting one');
  if (JSON.stringify(plain.json && plain.json.installConsent) === JSON.stringify(want)) p.push('without a token it is the reporting one too');
  if (reporting.out.includes(TOKEN)) p.push('the token was printed');
  return p;
})());

check('2. it defaults to "public"', (() => {
  const r = words([]);
  return r.json && JSON.stringify(r.json.consent) === JSON.stringify(intro.consentLines('public')) ? [] : ['consent was not for public'];
})());

// An address nothing answers: if this connected, it would hang, not return.
const pooled = words([], 'postgresql://postgres.abc:' + SECRET + '@10.255.255.1:6543/postgres');
check('3. a 6543 string is warned about, without connecting', (() => {
  const p = [];
  if (!pooled.json || !pooled.json.warning || !/6543/.test(pooled.json.warning.join(' '))) p.push('no 6543 warning: ' + pooled.out.slice(0, 300));
  if (pooled.ms > 10000) p.push('it took ' + pooled.ms + 'ms - it tried to connect');
  if (/Connecting/.test(pooled.out)) p.push('it said it was connecting');
  return p;
})());

const direct = words([], 'postgresql://postgres:' + SECRET + '@db.abcdefghij.supabase.co:5432/postgres');
check('4. the direct db.* address is warned about', (() => {
  return direct.json && direct.json.warning && /IPv6/.test(direct.json.warning.join(' ')) ? [] : ['no direct warning: ' + direct.out.slice(0, 300)];
})());

const broken = words([], 'postgresql://postgres@aws-0-x.pooler.supabase.com:6543/postgres');
check('5. a string that cannot work says why, and is not also warned about', (() => {
  const p = [];
  if (!broken.json || !broken.json.unusable || !/no password/.test(broken.json.unusable.join(' '))) p.push('unusable not said: ' + broken.out.slice(0, 300));
  if (broken.json && broken.json.warning) p.push('warned about a string it already refused');
  return p;
})());

check('6. the password never comes back out, whatever the string', (() => {
  return [pooled, direct].filter((r) => r.out.includes(SECRET)).map(() => 'the password was printed');
})());

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
console.log('All ' + results.length + ' words checks passed.');
