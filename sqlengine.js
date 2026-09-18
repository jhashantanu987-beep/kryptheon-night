// Reaching the SQL engine from Node.
//
// engine.sql holds the work. This is only the door: put the functions
// somewhere, call them, take them away again.
//
// Two doors lead to the same engine, and this is the one the command line
// uses. The other is the installer, where the same functions stay put and
// pg_cron calls them nightly - so anything that happens here must be a thing
// the scheduler could do too. No cleverness in Node that the database cannot
// do on its own, or the two doors stop leading to the same place.

const fs = require('fs');
const path = require('path');

// The token engine.sql carries wherever its own schema name belongs. A token
// rather than the word "kryptheon" so that replacing it cannot quietly hit a
// comment or a string that happened to say the same thing.
const PLACEHOLDER = '__KN__';

/** The engine, with its functions addressed to one schema. */
function engineFor(target) {
  const source = fs.readFileSync(path.join(__dirname, 'engine.sql'), 'utf8');
  if (!source.includes(PLACEHOLDER)) {
    throw new Error('engine.sql has no ' + PLACEHOLDER + ' in it, so it cannot be addressed anywhere');
  }
  return source.split(PLACEHOLDER).join(quote(target));
}

function quote(name) {
  return '"' + String(name).split('"').join('""') + '"';
}

/**
 * Puts the engine somewhere it can be called from.
 *
 * `CREATE OR REPLACE` throughout, so installing twice is not an error and an
 * upgrade is the same operation as an install.
 */
async function install(client, target) {
  await client.query(engineFor(target));
  return target;
}

/** Takes it away again, functions and all. */
async function uninstall(client, target) {
  await client.query('DROP SCHEMA IF EXISTS ' + quote(target) + ' CASCADE');
}

/** What the engine says the shape of an app is. */
async function readSchema(client, target, source) {
  const { rows } = await client.query('SELECT ' + quote(target) + '.read_schema($1) AS shape', [source]);
  return rows[0].shape;
}

/**
 * Installs the engine, does something with it, and takes it away.
 *
 * The schema is named for the moment it was made, the same as the copy is, so
 * that one abandoned by a dropped connection can be recognised and swept later
 * rather than sitting there for ever.
 */
async function withEngine(client, work) {
  const target = 'kn_engine_' + Date.now().toString(36);
  await install(client, target);
  try {
    return await work(target);
  } finally {
    await uninstall(client, target).catch(() => {});
  }
}

module.exports = {
  PLACEHOLDER: PLACEHOLDER,
  engineFor: engineFor,
  install: install,
  uninstall: uninstall,
  readSchema: readSchema,
  withEngine: withEngine,
};
