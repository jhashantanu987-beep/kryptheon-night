# Running the checks

Twelve suites. Run them after every change, not at the end.

    set KN_DATABASE_URL=postgresql://...
    npm run check

| | needs a database | what it is about |
|---|---|---|
| `finding.check.js` | no | the report never says more than the attack saw |
| `recheck.check.js` | no | "fixed" is only ever said when it is true |
| `untouched.check.js` | yes | nothing outside the copy is changed, at all |
| `blocked.check.js` | yes | a read that failed is not a table that held |
| `orphans.check.js` | yes | a scan that died leaves nothing behind |
| `external.check.js` | yes | an app pointing at `auth.users` can be scanned |
| `schema.check.js` | yes | the copy behaves like the app, not just looks like it |
| `collision.check.js` | yes | "this can happen twice" is only said when it can |
| `tamper.check.js` | yes | "a stranger can change this" is only said when it can |
| `shapes.check.js` | yes | every shape a real app has can be tested at all |
| `verdicts.check.js` | yes | the answer is right, not merely produced |
| `loop.check.js` | yes | the whole thing, through the real command |

The ones that need a database build small apps in Postgres, use them, and take
away exactly what they created - see **The checks are guests** below.

## What each one is guarding

**finding.check.js** - the report never says more than the attack saw. Most of
it is restraint: no invented columns, no invented severity, no "personal
details" about a table of view counts. A report that overstates once is
believed never again.

**recheck.check.js** - almost every case is about refusing to say "fixed". A
finding disappears from the second run for several reasons and only one of them
is good news: the table was secured, or it became impossible to test, or it was
dropped outright. In all three it is gone from the list, and in only one has
anybody been made safe.

**untouched.check.js** - the promise. It photographs functions, privileges,
tables, columns, policies, row level security flags, roles, sequences and the
app's own row contents, runs the real scan, photographs again, and fails on any
difference at all. It found the copy builder replacing the customer's
`auth.uid()` and opening their `auth` schema to `anon`.

**blocked.check.js** - a read that threw returns zero rows, and zero rows is
what a properly secured table returns. One refusal genuinely is an answer -
`permission denied for table orders` means the caller cannot reach it - and
everything else is now reported as not checked, with the reason.

**orphans.check.js** - the copy is dropped in a `finally`, and a `finally`
needs a connection. When the link dies mid-scan the process goes with it and
the copy stays in the customer's database. Every run now sweeps abandoned
copies first, and must not sweep one that belongs to a scan running right now.

**external.check.js** - nearly every Supabase app starts with
`references auth.users(id)`, and the scan used to refuse all of them. The copy
builds its own stand-in for the outside table instead.

**schema.check.js** - the copy is the app. The case that matters is not the
schema comparison but the one after it: the same attack is run against the
original and against the copy, and the verdicts have to agree. Missing grants
proved that - the schemas matched and the behaviour did not.

**collision.check.js** - mostly about *not* reporting. The fixture holds one of
every shape that looks like a hole and is not: a unique index rather than a
constraint, a composite `UNIQUE (org_id, email)`, a partial index, a column
whose name merely contains a credential word, and a table name ambiguous enough
to leave alone. The verdict comes from counting rows after the race, never from
the catalogue.

**tamper.check.js** - this is the attack that writes, so its first case is not
about findings at all: every table must come out exactly as it went in. After
that it is restraint again - a `SELECT` policy and nothing else genuinely
denies writes, and an app built that way must come back clean.

**shapes.check.js** - twenty-five small apps, each built around a shape real
projects have and no fixture did: an enum, a `text[]`, a generated column, a
domain type, a composite key, a table that is only an id. Skipped counts as a
failure here on purpose.

**verdicts.check.js** - seventeen apps that each declare the honest answer up
front, because a hole reported as nothing and a correct app reported as broken
both leave no warning behind to notice.

**loop.check.js** - nothing stubbed. Build an app with real holes, shell out to
`scan.js` the way a person would, apply the fixes the report asked for,
re-check, and read the verdict off the screen. Then again with a table
*deleted* rather than secured, which makes the findings disappear exactly as a
real fix does, and requires the badge withheld.

If your network blocks outbound 5432, set `KN_PRELOAD` to a module that swaps
the driver for one reaching Postgres over 443. It changes the driver and
nothing else.

## The checks are guests

`KN_DATABASE_URL` is whatever connection string somebody typed, and that will
sometimes be a database with things in it. So the rule for every check is the
same as for the product: look first, create only what is missing, and undo
exactly that much. `fixture.js` is where that lives.

Three separate versions of this got it wrong, all found by pointing the suite
at a database that already had an `auth` schema:

- every check ran `DROP SCHEMA auth CASCADE` on the way out. On a real project
  that is the entire authentication schema, gone.
- every check ran `CREATE OR REPLACE FUNCTION auth.uid()`, which is the same
  bug the product had - fixed there, still live in the tests.
- `blocked.check.js` revoked EXECUTE on `auth.uid()` to build its scenario.
  That was invisible while the schema was being dropped afterwards; the moment
  it stopped being dropped, the revoke stayed and poisoned every later check.
  On a real project it would have taken row level security out for the whole
  application and left it that way. It now builds its own function to revoke.

## The failure that matters

A false green. Every other bug is recoverable; telling someone their customer
data is safe when it is not, is not. That is why:

- a table that could not be seeded is reported as **not checked**, never as safe
- a read that failed for any reason but a closed door is **not checked**
- the copy is verified against the original before anything is attacked
- nothing in the copy may reference the app it was copied from
- coverage is tracked per attack, not per table: a table that was seeded and
  read is not a table whose unique columns were raced
- the badge needs every problem closed *and* nothing at all left untested
- a run that fell over never overwrites the saved one, so its findings survive

## Bugs these caught

- the copy builder replaced the customer's own `auth.uid()` and opened their
  `auth` schema to `anon` - on their live database, while every check was green
- a logged-out visitor was sent empty claims instead of a real JWT body, so
  `auth.uid()` threw and every table whose policy calls it came back looking
  safe without the rule ever being evaluated
- a read that threw was indistinguishable from a table that held
- a foreign key into `auth.users` stopped the scan outright - the Supabase
  default, so the product did not work on the apps it was built for
- a stored generated column crashed the copy
- enums, arrays, `inet`, `macaddr`, `tsvector`, domains and `CHECK ... IN (...)`
  columns could not be seeded, so those tables were never tested
- a table of nothing but an id produced `INSERT INTO t () VALUES ()`
- `array_agg` over `enumlabel` arrived as the string `{new,paid,shipped}`, whose
  first "label" is the character `{` - exactly what `pg_policies.roles` did
- a view over a locked table took the scan down, and then turned out to be a
  hole nobody was looking at
- a customer table whose name began like our stand-ins was dropped from every
  attack
- a foreign key over two columns could not be seeded
- the collision and write attacks inserted under the seeded people's names, so
  on a table keyed by the person the clash was read as the app refusing
- tables with no owner column were never seeded, so an open door could not be
  told from an empty room
- the copy's foreign keys pointed back into the real schema
- foreign keys were created before the primary keys they point at
- children were seeded before parents
- `allClear` had two overlapping guards, so breaking either one alone changed
  nothing
- every seeded row carried identical text, so a table with a unique email
  column was reported as "not checked"
- the collision attack skipped columns that were already protected, so adding
  the constraint it asked for made it report the fix as "could not confirm"
- unique indexes were not copied at all
- a `WITH CHECK` turning a write away was filed as "could not test", putting a
  warning on every table that had got it right

## What is deliberately not reported

The lost update - two withdrawals of 100 from a balance of 100 that both
succeed. Every Postgres database on default isolation behaves that way for a
read-then-write, so whether an app is actually vulnerable depends on code this
tool never sees. Reporting it would mean flagging every app that has a number
in it.

## Mutation testing

A check that still passes when the thing it guards is broken is not a check, so
every guard is removed one at a time to confirm a check fails. The scratchpad
runners assert each anchor matches exactly once first, because a mutation that
quietly changed nothing looks exactly like a check that passed.

Survivors have been worth more than the passes. Two in `recheck.js` turned up
the overlapping `allClear` guards. One in `collision.js` showed the fixture had
no table whose column name sits inside another unique column's name. Three in
`tamper.js` turned up a `WITH CHECK` refusal being read as an untested table.
