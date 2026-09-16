# Running the checks

Two suites. Run them after every change, not at the end.

    set KN_DATABASE_URL=postgresql://...
    npm run check

`finding.check.js` needs no database and takes a second. `schema.check.js`
builds a small app in Postgres, copies it, attacks both, and drops everything
it made.

## What each one is guarding

**finding.check.js** - the report never says more than the attack saw. Most of
it is restraint: no invented columns, no invented severity, no "personal
details" about a table of view counts. A report that overstates once is
believed never again, and the re-check at the end of the loop is worth exactly
as much as the first report was honest.

**schema.check.js** - the copy is the app. The case that matters is not the
schema comparison but the one after it: the same attack is run against the
original and against the copy, and the verdicts have to match. Two schemas can
look identical and behave differently. Missing grants proved that - the schemas
matched and the behaviour did not.

## The failure that matters

A false green. Every other bug is recoverable; telling someone their customer
data is safe when it is not, is not. That is why:

- a table that could not be seeded is reported as **not checked**, never as safe
- the copy is verified against the original before anything is attacked
- nothing in the copy may reference the app it was copied from

## Bugs these caught

- tables with no owner column were never seeded, so an open door could not be
  told from an empty room
- the copy's foreign keys pointed back into the real schema, because Postgres
  writes a schema name unquoted when it can
- foreign keys were created before the primary keys they point at
- children were seeded before parents, so every real app failed at the first insert
