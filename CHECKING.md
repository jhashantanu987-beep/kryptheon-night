# Running the checks

Five suites. Run them after every change, not at the end.

    set KN_DATABASE_URL=postgresql://...
    npm run check

| | needs a database | what it is about |
|---|---|---|
| `finding.check.js` | no | the report never says more than the attack saw |
| `recheck.check.js` | no | "fixed" is only ever said when it is true |
| `schema.check.js` | yes | the copy behaves like the app, not just looks like it |
| `collision.check.js` | yes | "this can happen twice" is only said when it can |
| `loop.check.js` | yes | the whole thing, through the real command |

The three that need a database build a small app in Postgres, use it, and drop
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

**collision.check.js** - mostly about *not* reporting. Saying a schema is
missing a constraint when it is not cannot be un-said, and somebody sent
chasing one imaginary problem reads the next report differently. So the fixture
holds one of every shape that looks like a hole and is not: a unique index
rather than a constraint, a composite `UNIQUE (org_id, email)` where the same
email in two organisations is correct, a partial index, a column whose name
only contains a credential word, and a table name ambiguous enough to leave
alone. The verdict is taken from counting rows after the race, never from the
catalogue - one table keeps its column unique with an exclusion constraint that
the catalogue check cannot see at all, and it must still not be reported.

**loop.check.js** - nothing stubbed. It builds an app with real holes in it,
shells out to `scan.js` the way a person would, applies the fixes the report
told them to apply, re-checks, and reads the verdict off the screen. Then it
does the whole thing again with one table *deleted* rather than secured, which
makes the findings disappear exactly as a real fix does, and requires the badge
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
- a re-check that could not run an attack calls it **unconfirmed**, never fixed
- coverage is tracked per attack, not per table: a table that was seeded and
  read is not a table whose unique columns were raced
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
- every seeded row carried identical text, so a table with a unique email column
  refused the second insert and a well-built app was reported as "not checked"
- the collision attack skipped columns that were already protected, so the
  moment somebody added the constraint the attack stopped running - and the
  re-check reported the very fix it had asked for as "could not confirm"
- unique indexes were not copied at all, which would have reported every app
  that enforces uniqueness with `CREATE UNIQUE INDEX` as broken for getting it
  right

## What is deliberately not reported

The lost update - two withdrawals of 100 from a balance of 100 that both
succeed. It is real and it is common, and it cannot honestly be reported from
here: every Postgres database on default isolation behaves that way for a
read-then-write, so whether an app is actually vulnerable depends on code this
tool never sees. An atomic `UPDATE` or `SELECT ... FOR UPDATE` makes it safe,
and nothing in the schema says which was used. Reporting it would mean flagging
every app that has a number in it.

## Mutation testing

A check that still passes when the thing it guards is broken is not a check, so
every guard here is removed one at a time to confirm a check fails. The
scratchpad runners assert each anchor matches exactly once first, because a
mutation that quietly changed nothing looks exactly like a check that passed.

Two survivors in `recheck.js` are what turned up the overlapping `allClear`
guards above; reading the code had not. A survivor in `collision.js` showed the
fixture had no table where one column's name sits inside another unique
column's name, so loosening the word-boundary match was invisible - that table
is in the fixture now.
