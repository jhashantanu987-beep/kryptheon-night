// The attack that needs nothing but what the app already hands every visitor.
//
// The deep scan (scan.js) needs the database connection string - the password
// to the whole database - and copies the database so it can attack the copy.
// Most people building on Lovable, Bolt, v0 or a bare Supabase project never
// have that string: the platform keeps it. What they DO ship, to every browser
// that opens the app, is the database's public address and its "publishable"
// (anon) key. Those two are all a real attacker outside has, and they are all
// this needs.
//
// So this becomes that attacker. With the anon key, for each table the app
// talks to, it asks PostgREST one question: can a stranger read this table? It
// asks for the COUNT only - never a row - so it learns "anyone can read your
// bookings table, and there are 3,412 of them" without ever pulling a
// customer's name or email out of the live database. Reading real rows to
// prove a leak would be committing the leak.
//
// WHAT THIS DELIBERATELY DOES NOT DO
//
// It never writes. It never signs in as one customer to read another's rows,
// never races two writes, never deletes a row to see if it can. Those all
// change data, and this runs against the live app, not a copy. They are the
// copy-based scan's job, and they need the connection string. What this cannot
// reach, the report says out loud - so a quiet result is never mistaken for a
// safe app.

const finding = require('./finding.js');

// Wraps one paragraph to a width that reads in a terminal and a chat box, the
// same width the deep scan's report uses.
function wrap(text, width) {
  const words = String(text).split(/\s+/).filter(Boolean);
  const out = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > (width || 70)) {
      out.push(current.trim());
      current = word;
    } else {
      current = (current + ' ' + word).trim();
    }
  }
  if (current) out.push(current.trim());
  return out;
}

// PostgREST answers a count-only request with an empty body and the total in a
// Content-Range header. `limit=0` is what makes the body empty: the query
// returns no rows at all, so not one leaves the database, and count=exact
// still fills in the total.

/** The REST base for a Supabase project URL. */
function restBase(supabaseUrl) {
  return String(supabaseUrl || '').replace(/\/+$/, '') + '/rest/v1';
}

/**
 * The Supabase address, the publishable key, and the tables the app talks to,
 * read out of the app's own JavaScript - exactly what a browser is handed.
 *
 * Given `{ supabaseUrl, key, tables }` already, it trusts them and does no
 * fetching. Otherwise it needs the running app's address and reads the rest
 * from there.
 */
async function discover(input, options) {
  const opts = options || {};
  const doFetch = opts.fetch || fetch;

  if (input && input.supabaseUrl && input.key) {
    return {
      supabaseUrl: input.supabaseUrl,
      key: input.key,
      tables: dedupe(input.tables || []),
      from: 'given',
    };
  }

  const appUrl = typeof input === 'string' ? input : input && input.appUrl;
  if (!appUrl) throw problem('no-app', 'I need the address of your running app, e.g. https://your-app.example.com');

  const html = await getText(doFetch, appUrl);
  const scripts = scriptUrls(html, appUrl);
  // The HTML itself sometimes carries the values (server-rendered apps do), so
  // it is searched too, before the bundles.
  let text = html;
  for (const src of scripts) {
    text += '\n' + await getText(doFetch, src).catch(() => '');
  }

  const supabaseUrl = firstMatch(text, /https?:\/\/[a-z0-9-]+\.supabase\.co/i);
  const key = firstMatch(text, /sb_publishable_[A-Za-z0-9_-]{10,}/) || anonJwt(text);
  if (!supabaseUrl || !key) {
    throw problem(
      'no-backend',
      'I could not find a Supabase address and public key in ' + appUrl + '. ' +
        'If this app has no database, there is nothing here to read; if it does, ' +
        'point me at the page that actually loads it.',
    );
  }
  return { supabaseUrl: supabaseUrl, key: key, tables: tableNames(text), from: 'app', appUrl: appUrl };
}

/**
 * Can a stranger read this table? Asked for the count alone, so no row is ever
 * pulled out of the live database.
 *
 * Readable, protected, absent, or unclear - never guessed. A 200 means the
 * anon key was allowed to read it; a 401 or 403 means row level security
 * turned it away; a 404 means the table is not exposed through the API at all.
 */
async function readable(restUrl, key, table, options) {
  const opts = options || {};
  const doFetch = opts.fetch || fetch;
  const url = restUrl + '/' + encodeURIComponent(table) + '?select=*&limit=0';
  let res;
  try {
    res = await doFetch(url, {
      method: 'GET',
      headers: { apikey: key, Authorization: 'Bearer ' + key, Prefer: 'count=exact' },
    });
  } catch (err) {
    return { table: table, status: 0, verdict: 'unclear', why: 'the request could not be made: ' + err.message };
  }
  // The body is read and dropped without being kept, so even a server that
  // ignores the count-only request never leaves a customer's row in memory
  // here longer than it takes to throw it away.
  await res.text().catch(() => '');

  // The one distinction that matters, and the one it is easy to get wrong.
  //
  //   200 with a count above zero  ->  a stranger really did read real rows.
  //                                    Proven. This is the finding.
  //   200 with a count of zero     ->  a stranger was allowed to ask, and got
  //                                    nothing. That is ALSO exactly what a
  //                                    correctly protected table returns to a
  //                                    stranger - row level security filters the
  //                                    rows, it does not refuse the request. So
  //                                    an empty answer proves nothing either way,
  //                                    and must never be reported as a leak.
  //   401 or 403                   ->  the table's own grants turned the key
  //                                    away before any rule ran.
  //   404                          ->  not exposed through the API at all.
  if (res.status === 200 || res.status === 206) {
    const count = rangeCount(res.headers);
    if (count && count > 0) return { table: table, status: res.status, verdict: 'readable', count: count };
    // Allowed to ask, nothing came back. Cannot be told from good security
    // with no rows in the table. The deep scan, which seeds its own rows,
    // settles it; from outside it stays open.
    return { table: table, status: res.status, verdict: 'empty', count: count == null ? 0 : count };
  }
  if (res.status === 401 || res.status === 403) {
    return { table: table, status: res.status, verdict: 'protected' };
  }
  if (res.status === 404) {
    return { table: table, status: res.status, verdict: 'absent' };
  }
  return { table: table, status: res.status, verdict: 'unclear' };
}

/**
 * Every table the app names, asked the one question, turned into the same kind
 * of finding scan.js produces - so `finding.describeAll` reports both the same
 * way. The count-only proof is carried through so the wording never claims a
 * row was pulled that was not.
 */
async function prowl(target, options) {
  const opts = options || {};
  const tables = dedupe(target.tables || []);
  if (!tables.length) {
    return {
      findings: [], attempted: [], protectedTables: [], emptyTables: [], absent: [], unclear: [],
      note: 'the app did not name any tables I could find, so I had nothing to ask about',
    };
  }
  const restUrl = restBase(target.supabaseUrl);
  const findings = [];
  const attempted = [];
  const protectedTables = [];
  const emptyTables = [];
  const absent = [];
  const unclear = [];

  for (const table of tables) {
    const seen = await readable(restUrl, target.key, table, opts);
    attempted.push(table);
    if (seen.verdict === 'readable') {
      findings.push({
        kind: 'exposed',
        table: table,
        readable: seen.count,
        countOnly: true, // read over the network, count only - see finding.js
        columns: [], //     no row was pulled, so nothing is claimed about contents
        who: 'anyone',
        rlsEnabled: null,
      });
    } else if (seen.verdict === 'protected') {
      protectedTables.push(table);
    } else if (seen.verdict === 'empty') {
      // Allowed to ask, nothing came back. Not proof of a leak, and not proof
      // of safety either - carried separately so the report can say plainly
      // that this one could not be settled from outside.
      emptyTables.push(table);
    } else if (seen.verdict === 'absent') {
      absent.push(table);
    } else {
      unclear.push({ table: table, why: seen.why || ('the server answered ' + seen.status) });
    }
  }
  return {
    findings: findings, attempted: attempted, protectedTables: protectedTables,
    emptyTables: emptyTables, absent: absent, unclear: unclear,
  };
}

/* -------------------------------------------------------------------------- */

function problem(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

async function getText(doFetch, url) {
  const res = await doFetch(url, { headers: { 'user-agent': 'kryptheon-night' } });
  if (!res.ok) throw problem('unreachable', 'I could not read ' + url + ' (it answered ' + res.status + ')');
  return res.text();
}

// <script src="/assets/index-xxxx.js"> and the module-preload links, made
// absolute against the app's own address.
function scriptUrls(html, appUrl) {
  const out = [];
  const re = /(?:src|href)\s*=\s*["']([^"']+\.js)["']/gi;
  let m;
  while ((m = re.exec(html))) {
    try {
      out.push(new URL(m[1], appUrl).href);
    } catch (err) {
      /* a src that is not a URL is not a script we can read */
    }
  }
  return dedupe(out);
}

function firstMatch(text, re) {
  const m = String(text).match(re);
  return m ? m[0] : null;
}

// A Supabase anon key in the older JWT form: three base64url parts, the middle
// one decoding to a payload whose role is "anon". Checked, not assumed, so a
// service_role key that leaked into a bundle is never sent as if it were the
// public one.
function anonJwt(text) {
  const re = /eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g;
  let m;
  while ((m = re.exec(text))) {
    try {
      const payload = JSON.parse(Buffer.from(m[0].split('.')[1], 'base64').toString('utf8'));
      if (payload && payload.role === 'anon') return m[0];
    } catch (err) {
      /* not a JWT we can read */
    }
  }
  return null;
}

// The tables the app talks to, from the Supabase client calls the bundle is
// full of: .from("bookings"), .from('profiles').
function tableNames(text) {
  const out = [];
  const re = /\.from\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]*)["'`]\s*\)/g;
  let m;
  while ((m = re.exec(text))) out.push(m[1]);
  return dedupe(out);
}

function dedupe(list) {
  return Array.from(new Set((list || []).filter(Boolean)));
}

// PostgREST returns the total in a Content-Range header shaped "0-0/1234", or
// "*/0" when there is nothing. Null when the server did not send one.
function rangeCount(headers) {
  const range = headers && typeof headers.get === 'function' ? headers.get('content-range') : null;
  if (!range) return null;
  const m = String(range).match(/\/(\d+)\s*$/);
  return m ? Number(m[1]) : null;
}

/**
 * The report, as lines. Its own, not the deep scan's: that one says "I built a
 * copy and attacked the copy", which is not what happened here, and a report
 * that describes a different attack than the one that ran is lying about
 * where its limits are.
 *
 * The part that matters most is at the end: what could not be tested from
 * outside. A stranger's view settles one question - can anyone read this - and
 * only for tables that have rows in them. Everything else needs a copy of the
 * database, and a quiet result here must never be read as "the app is safe".
 */
function reportLines(found, result) {
  const out = [];
  const say = (text) => out.push(text === '' ? '' : '  ' + text);
  const rule = () => say('-'.repeat(68));
  const findings = finding.describeAll(result.findings || []);
  const asked = (result.attempted || []).length;

  say('');
  say('App:       ' + (found.appUrl || '(given directly)'));
  say('Database:  ' + found.supabaseUrl);
  say('Tables I found in your app\'s code: ' + (asked ? (result.attempted || []).join(', ') : 'none'));

  if (!asked) {
    say('');
    say('Your app\'s code does not name any table I could find, so there was');
    say('nothing to ask about. This does NOT mean your data is safe - only that');
    say('I could not see which tables to test from outside.');
  } else if (findings.length) {
    say('');
    say(findings.length + (findings.length === 1 ? ' problem' : ' problems') + ' found.');
    for (const item of findings) {
      say('');
      rule();
      say(item.severity + '   ' + item.table);
      say('');
      say(item.headline);
      say('');
      for (const paragraph of [item.body, item.cause]) {
        wrap(paragraph, 70).forEach((l) => say(l));
        say('');
      }
      say('Paste this into Cursor, Claude, Windsurf or your AI tool:');
      say('');
      item.fixPrompt.split('\n').forEach((l) => out.push('    ' + l));
    }
  } else {
    say('');
    say('A stranger could not read rows from any table that had rows in it.');
  }

  const empty = result.emptyTables || [];
  const shut = result.protectedTables || [];
  const unclear = result.unclear || [];

  say('');
  rule();
  say('How this was done');
  say('');
  wrap(
    'Over the internet, as a stranger, with only the public key your app ' +
    'already hands every visitor. I asked each table for a count and nothing ' +
    'else, so no customer\'s row was pulled out, and nothing was written.',
    70,
  ).forEach((l) => say(l));

  say('');
  rule();
  say('What I could NOT test from outside');
  say('');
  if (empty.length) {
    wrap(
      'Could not tell: ' + empty.join(', ') + '. A stranger was allowed to ask ' +
      'and got no rows back - which is what a well protected table looks like, ' +
      'and also what an open but empty one looks like. From outside there is ' +
      'no way to tell them apart.',
      70,
    ).forEach((l) => say(l));
    say('');
  }
  if (unclear.length) {
    say('Got an answer I could not read: ' + unclear.map((u) => u.table).join(', ') + '.');
    say('');
  }
  if (shut.length) {
    say('Refused a stranger outright: ' + shut.join(', ') + '.');
    say('');
  }
  wrap(
    'Whether one signed-in customer can read another\'s rows, whether anyone ' +
    'can add, change or delete rows, and whether the same thing can be saved ' +
    'twice at once. Those change data, so they are only ever done on a copy of ' +
    'your database. For that, and to settle the tables above:',
    70,
  ).forEach((l) => say(l));
  say('');
  say('    npx kryptheon-night');
  say('');
  wrap(
    'It asks for your database connection string (Supabase: Project Settings, ' +
    'Database). Lovable Cloud does not hand that string out.',
    70,
  ).forEach((l) => say(l));
  say('');
  return out;
}

module.exports = {
  reportLines: reportLines,
  restBase: restBase,
  discover: discover,
  readable: readable,
  prowl: prowl,
  // exported for the checks
  scriptUrls: scriptUrls,
  tableNames: tableNames,
  anonJwt: anonJwt,
  rangeCount: rangeCount,
};
