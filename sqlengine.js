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
 * What the engine would run to rebuild one schema as another.
 *
 * Handed back without running any of it, so the guard can look at every
 * statement before one of them touches the database - and so a check can read
 * what would have happened without anything happening.
 */
async function copyStatements(client, target, plan, into) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.copy_statements($1::jsonb, $2) AS statements',
    [JSON.stringify(plan), into],
  );
  return rows[0].statements;
}

/** Builds the copy, and hands back every statement it ran. */
async function writeSchema(client, target, plan, into) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.write_schema($1::jsonb, $2) AS statements',
    [JSON.stringify(plan), into],
  );
  return rows[0].statements;
}

/*
 * The attacks.
 *
 * Thin on purpose: each one hands the engine the same arguments its Node twin
 * takes and gives back the same shape, so a caller can be pointed at either
 * without knowing which it has. `twin.check.js` has been calling these through
 * raw SQL since they were written; they are functions here so that `scan.js`
 * can reach them too, which is what makes the two doors one engine rather than
 * one on paper.
 */

/** Puts two fake people in the copy, and says what it could not seed. */
async function seed(client, target, into, tables) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.seed($1, $2::jsonb) AS answer',
    [into, JSON.stringify(tables)],
  );
  return rows[0].answer;
}

/** Can the wrong person read this? */
async function impersonate(client, target, into, tables) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.impersonate($1, $2::jsonb) AS answer',
    [into, JSON.stringify(tables)],
  );
  return rows[0].answer;
}

/** Can a stranger change it? Every write rolled back inside the engine. */
async function tamper(client, target, into, tables, seeded, policies) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.tamper($1, $2::jsonb, $3::jsonb, $4::jsonb) AS answer',
    [into, JSON.stringify(tables), JSON.stringify(seeded), JSON.stringify(policies || [])],
  );
  return rows[0].answer;
}

/** What the least trusted member of a team can change. Rolled back inside the engine. */
async function teammate(client, target, into, tables, seeded) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.teammate($1, $2::jsonb, $3::jsonb) AS answer',
    [into, JSON.stringify(tables), JSON.stringify(seeded)],
  );
  return rows[0].answer;
}

/** Can a half-finished row survive? */
async function orphan(client, target, into, tables, seeded) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.orphan($1, $2::jsonb, $3::jsonb) AS answer',
    [into, JSON.stringify(tables), JSON.stringify(seeded)],
  );
  return rows[0].answer;
}

/**
 * Can the same thing exist twice?
 *
 * Inside the database this one cannot actually race anything - two requests at
 * the same instant need two connections, and no credential ever moves - so it
 * comes back with every column it would have tried in `notTried`, with the
 * reason. That is deliberate and is the honest answer: reporting nothing at
 * all would read as safety.
 */
async function collide(client, target, into, tables, indexes) {
  const { rows } = await client.query(
    'SELECT ' + quote(target) + '.collide($1, $2::jsonb, $3::jsonb) AS answer',
    [into, JSON.stringify(tables), JSON.stringify(indexes)],
  );
  return rows[0].answer;
}

/**
 * The same seven operations `scan.js` asks of an engine, done in SQL.
 *
 * Handed an engine schema that is already installed, because installing and
 * removing it is the caller's business - `withEngine` below - and a scan
 * should not have to know that this engine needs putting somewhere first.
 *
 * `collide` is not among them. The scan races two real requests down two real
 * connections, which is something no engine living inside the database can do;
 * that is measured and written up in STATE.md, and the report names what it
 * could not race rather than leaving it out.
 */
function adapterFor(target) {
  return {
    name: 'sql',
    readSchema: (client, source) => readSchema(client, target, source),
    writeSchema: (client, plan, into) => writeSchema(client, target, plan, into),
    seed: (client, into, tables) => seed(client, target, into, tables),
    impersonate: (client, into, tables) => impersonate(client, target, into, tables),
    tamper: (client, into, tables, sown, policies) =>
      tamper(client, target, into, tables, sown, policies),
    orphan: (client, into, tables, sown) => orphan(client, target, into, tables, sown),
    teammate: (client, into, tables, sown) => teammate(client, target, into, tables, sown),
  };
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
  copyStatements: copyStatements,
  writeSchema: writeSchema,
  seed: seed,
  impersonate: impersonate,
  tamper: tamper,
  orphan: orphan,
  teammate: teammate,
  collide: collide,
  adapterFor: adapterFor,
  withEngine: withEngine,
};
