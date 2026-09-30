// Everything that can go wrong before a single attack runs, said in words a
// person who has never opened a terminal can act on.
//
// The person this is for clicked "Deploy" in Lovable and has a database
// because Supabase gave them one. They did not choose Postgres, they do not
// know what a connection string is, and they will never read a stack trace.
// A message like
//
//     Error: getaddrinfo ENOTFOUND db.abcdefgh.supabase.co
//         at GetAddrInfoReqWrap.onlookupall [as oncomplete] (node:dns:120:26)
//
// tells them only that the tool is not for them. Every branch below turns one
// of those into a sentence that names what is wrong and what to do next.
//
// Two rules hold this file together:
//
//   1. Never guess out loud. If the cause cannot be told apart from another
//      cause, say both, rather than picking the likelier one confidently.
//   2. Never print the connection string back. It carries the password to
//      the whole database, and a person pasting a report into a chat window
//      would paste the credential with it.

/** The bits of a connection string that are safe to show somebody. */
function withoutSecret(text) {
  // The password lives between the first colon after the scheme and the @.
  // Anything else in the string - host, port, database, user - is not a
  // secret and is exactly what the person needs to see to spot their typo.
  try {
    const url = new URL(text);
    const user = url.username ? url.username + '@' : '';
    return url.protocol + '//' + user + url.host + url.pathname;
  } catch (err) {
    return '(unreadable)';
  }
}

// The placeholder Supabase puts in the string it shows you. Copying the line
// without replacing this is the single most common first mistake, and the
// error Postgres gives back for it is "password authentication failed",
// which sends people off changing their password instead of reading the line
// they pasted.
const PLACEHOLDERS = [
  '[YOUR-PASSWORD]',
  '[YOUR_PASSWORD]',
  '[PASSWORD]',
  '[DB-PASSWORD]',
  'YOUR-PASSWORD',
  '[your-password]',
];

/**
 * Is this a connection string at all?
 *
 * Checked before connecting, because the failures here are the ones a person
 * can fix in five seconds if told plainly, and the ones Postgres describes
 * worst if they are allowed to reach it.
 *
 * Returns null when the string is usable, or the lines to print when it is
 * not.
 */
function readConnectionString(raw) {
  const text = String(raw == null ? '' : raw).trim();

  if (!text) {
    return [
      'I did not get a connection string.',
      '',
      'It is the line Supabase shows under Project Settings -> Database ->',
      'Connection string. It starts with postgresql://',
    ];
  }

  // A wrapping pair of quotes survives a copy out of a code block and makes
  // the URL unparseable for a reason nobody would ever guess from the error.
  const unquoted = text.replace(/^["']|["']$/g, '');

  for (const placeholder of PLACEHOLDERS) {
    if (unquoted.includes(placeholder)) {
      return [
        'That string still has ' + placeholder + ' in it.',
        '',
        'Supabase shows you the line with a blank left in it for your database',
        'password. Replace ' + placeholder + ' - square brackets and all - with',
        'the password, then paste it again.',
        '',
        'If you do not know the password: Supabase dashboard -> Project Settings',
        '-> Database -> Database password -> Reset database password. Resetting it',
        'will break anything already using the old one, so check first.',
      ];
    }
  }

  if (/^https?:\/\//i.test(unquoted)) {
    return [
      'That is a web address, not a database connection string.',
      '',
      'The one beginning https://...supabase.co is your project URL - the one',
      'your app uses through the Supabase library. I need the database itself.',
      '',
      'Supabase dashboard -> Project Settings -> Database -> Connection string',
      '-> URI. It begins postgresql:// and has a password in it.',
    ];
  }

  // The anon key and the service role key are both JWTs, and both get pasted
  // here. The service_role key is a far more dangerous thing to have in a
  // clipboard than the one being asked for, so this says so.
  if (/^eyJ[A-Za-z0-9_-]+\./.test(unquoted)) {
    return [
      'That is one of your API keys, not a database connection string.',
      '',
      'If it was the service_role key, treat it as leaked now that it has been',
      'in a terminal: Supabase dashboard -> Project Settings -> API -> Rotate.',
      '',
      'What I need is under Project Settings -> Database -> Connection string',
      '-> URI. It begins postgresql://',
    ];
  }

  let url;
  try {
    url = new URL(unquoted);
  } catch (err) {
    return [
      'I could not read that as a connection string.',
      '',
      'It should be one line, no spaces, beginning postgresql:// - like',
      'postgresql://postgres:PASSWORD@db.something.supabase.co:5432/postgres',
      '',
      'If you copied it out of a web page, check that the whole line came with',
      'it and that it did not get broken in half.',
    ];
  }

  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    return [
      'That does not look like a Postgres connection string.',
      '',
      'It begins "' + url.protocol + '//" and I need one beginning',
      '"postgresql://". Supabase dashboard -> Project Settings -> Database ->',
      'Connection string -> URI.',
    ];
  }

  if (!url.hostname) {
    return [
      'That connection string has no server name in it.',
      '',
      'There should be a name between the @ and the : near the end, like',
      '@db.something.supabase.co:5432. Copy the whole line again.',
    ];
  }

  if (!url.password) {
    return [
      'That connection string has no password in it.',
      '',
      'The password goes between the colon and the @, like',
      'postgresql://postgres:PASSWORD@db.something.supabase.co:5432/postgres',
      '',
      'Supabase leaves a blank there when it shows you the line, so it has to',
      'be filled in before it will work.',
    ];
  }

  return null;
}

/**
 * Supabase hands out three connection strings and two of them will not do.
 *
 * This is a warning rather than a refusal: the shapes are recognised by their
 * host names, those names have changed before, and refusing to run on a
 * string that would have worked is worse than saying something and trying.
 */
function poolerWarning(raw) {
  let url;
  try {
    url = new URL(String(raw).trim().replace(/^["']|["']$/g, ''));
  } catch (err) {
    return null;
  }

  // The transaction pooler hands a different backend to every statement.
  // The whole attack is "become another role inside one transaction and try
  // to read", which needs the statements to stay together on one connection.
  if (url.port === '6543') {
    return [
      'That is the transaction pooler (port 6543). It gives every statement a',
      'different connection, and these attacks have to stay on one.',
      '',
      'Use the session pooler instead: Supabase -> Connect -> Session pooler,',
      'the one whose port is 5432.',
    ];
  }

  // The direct connection answers only over IPv6 now. On a network without
  // it the name does not resolve, and the failure reads like a typo. It works
  // where IPv6 does, so this warns rather than refuses.
  if (/^db\.[a-z0-9]+\.supabase\.(co|com)$/i.test(url.hostname)) {
    return [
      'That is Supabase\'s direct connection (db.' + url.hostname.split('.')[1] + '.supabase.co). It',
      'answers only over IPv6, and many home and office networks have none - it',
      'then fails as if the address were wrong.',
      '',
      'If it does, use the session pooler: Supabase -> Connect -> Session pooler,',
      'port 5432.',
    ];
  }

  return null;
}

// Postgres says why it refused in a five character code. The message beside
// it is written for whoever is holding the database, not for whoever is
// holding the app, so the code is what gets read here and the message is not.
const BY_CODE = {
  // password authentication failed
  '28P01': [
    'The server answered, but the password was wrong.',
    '',
    'Everything else in the string was right - the address found a real',
    'database. It is only the part between the colon and the @.',
    '',
    'Supabase dashboard -> Project Settings -> Database -> Database password.',
    'If you never set one, reset it there and paste the new one here.',
  ],
  // invalid_authorization_specification - usually the user name
  '28000': [
    'The server answered, but it would not let that user in.',
    '',
    'Check the name between // and the colon. For Supabase it is "postgres"',
    'on a direct connection, and "postgres.something" on a pooled one - the',
    'two are not interchangeable.',
  ],
  // invalid_catalog_name
  '3D000': [
    'The server answered, but there is no database by that name on it.',
    '',
    'That is the word after the last slash. On Supabase it is "postgres" -',
    'not the name of your project.',
  ],
  // insufficient_privilege
  '42501': [
    'I connected, but this user is not allowed to do what I need.',
    '',
    'I have to create one temporary schema, copy the shape of your tables',
    'into it, and delete it again. This user cannot create a schema.',
    '',
    'Use the connection string from Project Settings -> Database rather than',
    'one you made yourself - that one is the owner and can.',
  ],
  // too_many_connections
  '53300': [
    'Your database is already at its connection limit, so it turned me away.',
    '',
    'This is about how busy the database is, not about anything being wrong',
    'with it. Close anything else that is connected - a SQL editor tab, a',
    'running app - and try again in a minute.',
  ],
  // cannot_connect_now - the server is starting up
  '57P03': [
    'The database is awake but not ready yet.',
    '',
    'Free Supabase projects go to sleep when nobody uses them, and take a few',
    'seconds to come back. Try again in half a minute.',
  ],
};

// Node's own failures, which happen before Postgres has said anything at all.
const BY_SYSCALL = {
  ENOTFOUND: [
    'I could not find that server.',
    '',
    'Either there is a typo in the address, or this computer is not online.',
    '',
    'The address is the part between the @ and the : near the end. Compare it',
    'with the one in Supabase -> Project Settings -> Database. If your project',
    'was paused or deleted, its address stops existing too.',
  ],
  ECONNREFUSED: [
    'That server is there, but nothing is listening on that port.',
    '',
    'The port is the number after the last colon, before the slash. Supabase',
    'uses 5432 for a direct or session connection.',
  ],
  ETIMEDOUT: [
    'I reached the network but the database never answered.',
    '',
    'This is almost always a firewall between you and it - office wifi, a',
    'company laptop, or a VPN. Databases talk on port 5432 and many networks',
    'block it outright.',
    '',
    'Try again on a home connection or a phone hotspot. Nothing is wrong with',
    'your app.',
  ],
  EHOSTUNREACH: [
    'This computer has no route to that server.',
    '',
    'Supabase direct connections answer on IPv6 only, and a lot of home and',
    'office networks have no IPv6 at all. The session pooler answers on IPv4.',
    '',
    'Supabase dashboard -> Project Settings -> Database -> Connection string,',
    'and take the "Session pooler" one instead.',
  ],
  ENETUNREACH: [
    'This computer has no route to that server.',
    '',
    'Supabase direct connections answer on IPv6 only, and a lot of home and',
    'office networks have no IPv6 at all. The session pooler answers on IPv4.',
    '',
    'Supabase dashboard -> Project Settings -> Database -> Connection string,',
    'and take the "Session pooler" one instead.',
  ],
  // Not an SSL problem, whatever it looks like: this command turns encryption
  // on for every connection that is not to this machine. An earlier draft of
  // this message told people to add ?sslmode=require, which would have made
  // things worse - the driver reads that as full certificate verification and
  // refuses Supabase's own certificate authority outright.
  ECONNRESET: [
    'The connection was cut while I was opening it.',
    '',
    'Usually this is the network rather than the database - a VPN, a captive',
    'wifi portal, or a free Supabase project waking up.',
    '',
    'Try it again. If it happens twice in a row, try it on a different',
    'network, such as a phone hotspot.',
  ],
};

/**
 * Is this Supabase's direct connection, and if so whose?
 *
 * `db.<ref>.supabase.co` is the direct connection. Supabase stopped giving it
 * an IPv4 address, so today it resolves to an AAAA record and nothing else -
 * and on a machine with no IPv6 the name does not resolve at all. The failure
 * that produces is ENOTFOUND: not "unreachable", which would at least hint at
 * the network, but "no such name", which reads as a typo.
 *
 * Measured on a real project: A = ENODATA, AAAA = 2406:da1c:..., and no
 * global IPv6 on the machine. The scan said "there is a typo in the address,
 * or this computer is not online... if your project was paused or deleted",
 * and all three of those were false. That sends somebody to reset a password
 * or rebuild a project that was never broken.
 *
 * The ref is handed back so the pooler string can be spelled out with their
 * own project in it rather than as a shape to fill in.
 */
function supabaseDirectRef(raw) {
  try {
    const host = new URL(String(raw).trim().replace(/^["']|["']$/g, '')).hostname;
    const match = /^db\.([a-z0-9]+)\.supabase\.(co|com)$/i.exec(host);
    return match ? match[1] : null;
  } catch (err) {
    return null;
  }
}

/**
 * One failure, in plain English.
 *
 * Always returns something. A branch that has not been written yet is worse
 * than a generic sentence, but a generic sentence with the original message
 * kept underneath is not a dead end - somebody can search for it. What never
 * survives is the stack: the person cannot use it and it makes the tool look
 * like it broke rather than like it has something to tell them.
 */
function explain(err, raw) {
  const code = err && err.code ? String(err.code) : '';

  // Checked before the general ENOTFOUND, because for this one address the
  // general answer is wrong in every one of its three guesses.
  const ref = code === 'ENOTFOUND' ? supabaseDirectRef(raw) : null;
  if (ref) {
    return [
      'I could not find that server. There are two likely reasons.',
      '',
      'Most likely: that address is Supabase’s direct connection, and it now',
      'answers only over IPv6. Plenty of home and office networks have no IPv6',
      'at all, and on those the name does not resolve to anything.',
      '',
      // A ref with one letter wrong fails exactly the same way, and blaming
      // only IPv6 would send somebody to change networks over a typo.
      'Or the address is mistyped. Check that "' + ref + '" matches the project',
      'ref in Supabase -> Project Settings -> General; one wrong letter fails',
      'exactly the same way.',
      '',
      'Your password has not been tried yet, so it is not the problem. Use the',
      'session pooler instead, which answers over the ordinary internet:',
      '',
      '  Supabase dashboard -> Project Settings -> Database ->',
      '  Connection string -> URI -> and pick "Session pooler".',
      '',
      'It looks like this, with your password in the middle:',
      '',
      '  postgresql://postgres.' + ref + ':PASSWORD@aws-0-REGION.pooler.supabase.com:5432/postgres',
      '',
      'Take the port 5432 one. The other pooler, on 6543, hands every statement',
      'a different connection and these attacks have to stay on one.',
    ];
  }

  if (BY_CODE[code]) return BY_CODE[code].slice();
  if (BY_SYSCALL[code]) return BY_SYSCALL[code].slice();

  const message = err && err.message ? String(err.message) : String(err);

  // Certificate failures arrive with several different codes depending on
  // which part of the chain gave up, so they are recognised by their wording.
  if (/self[- ]signed certificate|unable to verify|CERT_|certificate/i.test(message)) {
    return [
      'The database offered a security certificate I could not check.',
      '',
      'This is normal for some hosts and not for others, so I stopped rather',
      'than trusting it quietly.',
      '',
      'If this is your own database and you expected it, add ?sslmode=no-verify',
      'to the end of the connection string.',
    ];
  }

  if (/timeout|timed out/i.test(message)) {
    return BY_SYSCALL.ETIMEDOUT.slice();
  }

  if (/password|authentication/i.test(message)) {
    return BY_CODE['28P01'].slice();
  }

  // The install refused because the database cannot schedule or post. It had
  // connected - the line above this on screen says "Connected." - and falling
  // through to "I could not connect" sent people checking a password that
  // was fine. Measured on a plain Postgres 18.
  const missing = /does not offer (pg_[a-z_]+)/.exec(message);
  if (missing) {
    return [
      'This database cannot run the nightly check.',
      '',
      'It does not offer ' + missing[1] + ', which the nightly run needs (pg_cron to',
      'wake itself at night, pg_net to report). Supabase has both; a plain',
      'Postgres or Neon may not. Nothing was installed.',
      '',
      'The scan itself does not need either, and works here:',
      '',
      '  npx kryptheon-night',
    ];
  }

  // Nothing matched. Say what happened and where, without pretending to know
  // why, and without the stack.
  const lines = [
    'I could not connect to the database.',
    '',
    'The server said: ' + message,
  ];
  if (raw) {
    lines.push('');
    lines.push('I was trying to reach: ' + withoutSecret(raw));
    lines.push('(your password is not shown, and was not written anywhere)');
  }
  return lines;
}

module.exports = {
  readConnectionString: readConnectionString,
  poolerWarning: poolerWarning,
  explain: explain,
  supabaseDirectRef: supabaseDirectRef,
  withoutSecret: withoutSecret,
  PLACEHOLDERS: PLACEHOLDERS,
};
