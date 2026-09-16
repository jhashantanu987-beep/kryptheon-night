# Running the checks

Four suites. Run them after every change, not at the end.

    set KN_DATABASE_URL=postgresql://...
    npm run check

| | needs a database | what it is about |
|---|---|---|
| `finding.check.js` | no | the report never says more than the attack saw |
| `recheck.check.js` | no | "fixed" is only ever said when it is true |
| `schema.check.js` | yes | the copy behaves like the app, not just looks like it |
| `loop.check.js` | yes | the whole thing, through the real command |

The two that need a database build a small app in Postgres, use it, and drop
everything they made.

## What each one is guarding

**finding.check.js** - the report never says more than the attack saw. Most of
it is restraint: no invented columns, no invented severity, no "personal
details" about a table of view counts. A report that overstates once is
believed never again, and the re-check at the end of the loop is worth exactly
as much as the first report was honest.

**recheck.check.js** - almost every case is about refusing to say "fixed". A
finding disappears from the second run for several reasons and only one of them
is good news: the table might have been secured, or it might have become
impossible to test, or it might have been dropped outright. In all three it is
gone from the list, and in only one has anybody been made safe.

**schema.check.js** - the copy is the app. The case that matters is not the
schema comparison but the one after it: the same attack is run against the
original and against the copy, and the verdicts have to match. Two schemas can
look identical and behave differently. Missing grants proved that - the schemas
matched and the behaviour did not.

**loop.check.js** - nothing stubbed. It builds an app with two real holes in
it, shells out to `scan.js` the way a person would, applies the fix the report
told them to apply, re-checks, and reads the verdict off the screen. Then it
does the whole thing again with one table *deleted* rather than secured, which
makes the finding disappear exactly as a real fix does, and requires the badge
to be withheld.

If your network blocks outbound 5432, set `KN_PRELOAD` to a module that swaps
the driver for one reaching Postgres over 443. It changes the driver and
nothing else.

## The failure that matters

A false green. Every other bug is recoverable; telling someone their customer
data is safe when it is not, is not. That is why:

- a table that could not be seeded is reported as **not checked**, never as safe
- the copy is verified against the original before anything is attacked
- nothing in the copy may reference the app it was copied from
- a re-check that could not test a table calls it **unconfirmed**, never fixed
- the badge needs every problem closed *and* nothing at all left untested
- a run that fell over never overwrites the saved one, so its findings survive

## Bugs these caught

- tables with no owner column were never seeded, so an open door could not be
  told from an empty room
- the copy's foreign keys pointed back into the real schema, because Postgres
  writes a schema name unquoted when it can
- foreign keys were created before the primary keys they point at
- children were seeded before parents, so every real app failed at the first insert
- `allClear` had two overlapping guards, so breaking either one alone changed
  nothing and no check noticed

## Mutation testing

A check that still passes when the thing it guards is broken is not a check, so
every guard here has been removed one at a time to confirm a check fails. Two
survivors in `recheck.js` are what turned up the overlapping `allClear` guards
above - reading the code had not.
