// How to open a connection, which is not the same as the string a person
// pasted.
//
// In its own file because the decision is worth checking directly, and the
// command it is used from runs the moment it is required.

// Long enough for a Supabase project that has gone to sleep to wake up - free
// projects pause after a week and take the better part of half a minute to
// come back - and short enough that a blocked port does not look like a hang.
// Without this the connection simply never returns and the person is left
// watching a cursor with nothing to read.
const CONNECT_TIMEOUT = 30000;

// The two SSL modes the hosting companies put in the string themselves.
// Nobody chose these; they came with the copy button.
//
// Measured: `pg` 8.23 reads both of them as full certificate verification,
// and prints a nine-line upgrade notice to the screen while doing it. Neon
// hands out a string ending `?sslmode=require`, so a person following the
// instructions gets that notice in the middle of their security report - and
// on Supabase's own certificate authority, verify-full fails outright.
//
// So these two are dropped and replaced with what `sslmode=require` means
// everywhere else: encrypted, certificate not verified. Everything else -
// verify-full, verify-ca, no-verify, disable - is somebody who went and typed
// it, and is left exactly as they wrote it.
const HANDED_OUT = /^(require|prefer)$/i;

/** A database on this machine is not crossing a network. */
function isLocal(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '';
}

function howToConnect(connectionString) {
  let url;
  try {
    url = new URL(connectionString);
  } catch (err) {
    // Unparseable strings never get this far - readConnectionString stops
    // them - but connecting and failing is better than throwing from here.
    return { connectionString: connectionString, connectionTimeoutMillis: CONNECT_TIMEOUT };
  }

  const mode = url.searchParams.get('sslmode');
  if (mode && !HANDED_OUT.test(mode)) {
    return { connectionString: connectionString, connectionTimeoutMillis: CONNECT_TIMEOUT };
  }
  if (mode) url.searchParams.delete('sslmode');

  const config = { connectionString: url.toString(), connectionTimeoutMillis: CONNECT_TIMEOUT };
  if (isLocal(url.hostname)) return config;

  config.ssl = { rejectUnauthorized: false };
  return config;
}

module.exports = {
  howToConnect: howToConnect,
  CONNECT_TIMEOUT: CONNECT_TIMEOUT,
};
