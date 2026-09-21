# Running the checks

Fourteen suites. Run them after every change, not at the end.

    set KN_DATABASE_URL=postgresql://...
    npm run check

| | needs a database | what it is about |
|---|---|---|
| `finding.check.js` | no | the report never says more than the attack saw |
| `recheck.check.js` | no | "fixed" is only ever said when it is true |
| `untouched.check.js` | yes | nothing outside the copy is changed, at all |
| `blocked.check.js` | yes | a read that failed is not a table that held |
| `usable.check.js` | yes | what a person sees when they get the command wrong |
| `orphans.check.js` | yes | a scan that died leaves nothing behind, copy or engine |
| `guests.check.js` | yes | a check that died leaves nothing behind either |
| `external.check.js` | yes | an app pointing at `auth.users` can be scanned |
| `schema.check.js` | yes | the copy behaves like the app, not just looks like it |
| `collision.check.js` | yes | "this can happen twice" is only said when it can |
| `tamper.check.js` | yes | "a stranger can change this" is only said when it can |
| `orphan.check.js` | yes | "this can point at nothing" is only said where a key belongs |
| `twin.check.js` | yes | the two engines are one engine, and stay one |
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

**usable.check.js** - six ways of getting the command wrong, all through the
real command line. A misspelled schema name used to find no tables, attack
none of them, print the all-clear and exit 0. A typo cannot be allowed to
produce the sentence the product is sold on.

**orphan.check.js** - the interruption attack tells somebody their schema is
missing a constraint, which is a claim about how their app is meant to work.
So eleven of its thirteen cases are about saying nothing: a column pointing at
Stripe, a name that matches a table whose key is a different type, an audit
row whose whole job is to remember somebody who has been deleted.

**guests.check.js** - the rule below, tested rather than asserted. Its
eight cases are four pairs of opposite mistakes: sweeping away a table a
run in another window is using, and leaving one a dead run stranded;
dropping a customer's auth.users, and failing to drop our own. It refuses
to run at all where an auth.users is already sitting, and says so as a
failure, because a check nobody ran must not read like one that passed.

**twin.check.js** - the attacks are moving into SQL so the night shift can
run inside the customer's own database and no password ever leaves it. That
only works if there is one engine. Two implementations of the same idea is
how a bug gets fixed once and survives in the other copy. So: one awkward
fixture, read by both, compared key for key - and then the two copies they
build compared as well, because the copy is what the attacks actually run
against. Not close enough. Identical.

It earned itself on its first run, on a list of role names that arrived as
a string in one engine and a list in the other. It later caught a copy whose
columns still pointed at the original's enum type.

It now compares all four attacks, on one app, end to end: what each engine
reads, what each builds, what each seeds, and what each concludes. Eleven
checks, and the last three are the ones a person would recognise - who can
read this, who can write to it, and can a half-finished row survive.

It also compares the decisions seeding makes before it writes a row:
who a row belongs to, what a CHECK will actually accept, and how wide a
generated value may be. Those are decisions taken from the shape and
nothing else, so both engines can be asked the same question and their
answers compared exactly - which says more than comparing seeded rows,
where a disagreement only shows up as a row that looks different.

Its own check that the engine takes itself away used to ask whether any
engine schema existed anywhere. An engine abandoned hours earlier by a
killed process made it fail, and keep failing, blaming a run that had
behaved perfectly. It now asks about the engines that run installed, by
name - the same rule as everything else here: know your own litter.

**shapes.check.js** - twenty-eight small apps, each built around a shape real
projects have and no fixture did: an enum, a `text[]`, a generated column, a
domain type, a composite key, a table that is only an id, a view that
mentions an enum, a CHECK on a varchar column, a CHECK whose values have
commas in them. Skipped counts as a
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

A fourth was found later, and it was in the rule itself. "Only remove what
you created" is decided at the start of a run, so a run that dies between
creating `auth.users` and dropping it leaves a table every later run reads
as "already there, not mine" - for ever, by design. One turned up on the
live database after a suite that was, in fact, clean.

Proving which run leaked it needed a measurement, not an argument: a Neon
branch, the table moved aside there, and a watcher polling every two seconds
while the whole suite ran. It named both checks and cleared both of them -
`external.check.js` at +269s, `shapes.check.js` at +1564s, each removing its
own within the minute. The leftover predated all of it.

So a check now writes a comment on the `auth.users` it makes, and a later
run sweeps only a table carrying that mark and old enough that no run in
another window could still be using it. A customer's table has no such
comment, so there is nothing to guess at - and guessing at it by its columns
is the same mistake wearing a different hat. `guests.check.js` is what keeps
that honest in both directions.

## What the sweep could not see

Three times now, something was named outside the pattern that clears it
away, and each time the sweep looked as though it had nothing to do -
which is indistinguishable from a clean database.

- `loop.check.js` built its apps as `loop_a_` and `loop_b_`, outside the
  `kn_` prefix anything sweeps. One stranded by a dropped connection was
  found sitting on the live database.
- the fixture sweep read `^kn_[a-z]+_`, which never matched `kn_hunt2_`:
  it could not see its own fixtures.
- the product sweep read `^kn_[0-9a-z]+$`, which matches a copy but not
  the `kn_engine_<moment>` the SQL door installs into the customer's own
  database. One left by a dropped connection would have stayed there for
  good - and nothing left behind is the whole promise.

Each is guarded by a pair of opposite mistakes rather than a single case,
because a sweep has two ways to be wrong: leaving the rubbish, and taking
away something a run in another window is using right now.

## The copy was not the app, three times

Every attack runs against the copy, so anything the copy fails to carry
is a hole nobody looks in - and it fails quietly, because a refused attack
and a defended one look identical from outside.

- **the types.** Enums and domains were borrowed from the original rather
  than built in the copy. A view that mentions an enum then took the whole
  scan down, because pg_get_viewdef writes the literal as
  `'paid'::app.order_status` and the copy had no such type.

- **the grants on the sequences.** Supabase grants anon USAGE on every
  sequence in public. The copy replayed the table grants and not those, so
  every insert came back `permission denied for sequence` - which reads as
  the attack being beaten. "A stranger can add rows to your table" was
  never reported on any table with a serial key, which is most tables. The
  table was still reported for change and delete, so nothing looked wrong.

- **the ownership of those sequences.** `serial` makes the sequence belong
  to its column, and that link in pg_depend is how the grants on it are
  found again. The copy created its sequences loose, so the grants were
  replayed onto them and then read back as absent. The copy now does
  `ALTER SEQUENCE ... OWNED BY`, which also means the sequence goes when
  the copy's table goes.

## What the SQL engine cannot do, and says so

The collision attack needs two requests at the same instant: the second
insert has to be in flight while the first transaction is still open. A
plpgsql function is one session, so it needs a second one from inside the
database. Measured rather than assumed - `dblink` is available and this
role may even create it, but it cannot connect back to its own database
without a password:

    dbname only    -> password or GSSAPI delegated credentials required
    empty conninfo -> the same
    a local socket -> the same

The only way to open that second session is to hold a credential, and the
whole reason the SQL engine exists is that no credential ever moves. So it
does not run that attack - and every column it would have raced comes back
named, in `notTried`, with the reason. Reporting nothing is the one answer
that reads as safety.

The candidates are still worked out in full, identically to the other
engine, so the two can be compared: what was considered has to match even
where what was concluded cannot. The npx door still races them for real,
because Node has two connections and can.

## Two shapes of the same rule

Postgres writes a constraint back in its own words, and its own words are
not always the same words. `CHECK (state IN (...))` on a **text** column is
stored as

    state = ANY (ARRAY['open'::text, 'closed'::text])

and on a **varchar** column as

    (state)::text = ANY ((ARRAY['open'::character varying, ...])::text[])

Only the first was understood. The second could not be read, so the column
was seeded with an invented value, refused by its own constraint, and the
whole table reported as one that could not be checked - on an app with
nothing unusual about it. The text spelling had a shape in the checks and
passed; nobody had written the varchar one.

The allowed values were also split on commas, which took `packed, sealed`
apart into two halves that fit nothing. They are picked out one at a time
now.

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
- a typo in the schema name printed the all-clear and exited 0
- a run that stopped exited 0, so a script would have read it as a pass
- the connection string could only be given on the command line, where it
  lands in shell history and the process list
- hiding our own copies from the suggestion list also hid them from the
  existence check, so the scan refused every schema whose name began the same
  way - which was all 25 shape fixtures, a minute after the fix landed

## What is deliberately not reported

Whether a request that was cut off halfway left the app inconsistent. That
depends on whether the code wrapped its writes in a transaction, and this tool
never sees the code. What it can answer is the database half: whether a
half-finished state is allowed to survive at all, which is what a foreign key
decides. So the interruption attack reports orphans and says nothing about
transactions.

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

The runner itself had the disease it exists to find. It counted "the check
did not exit 0" as caught, and a dropped connection does not exit 0 either:
one mutation was reported caught twice while it was in fact alive and
untested. A catch now has to be shown - a FAIL line naming the check that
noticed - a dropped connection is retried, and anything else is NOT KNOWN
rather than a pass or a catch.

Stopping a mutation run is not free either. Killing the process skips the
`finally` that puts the file back, so a mutation can be left in the working
tree; it happened, and a loose `grep -c` for a string that appears in more
than one place said the tree was clean when it was not. Every anchor is
checked by name now.

The interruption attack is the clearest case of why. Its first run caught 3 of
10, and every survivor was a real gap. The checks were asking what got
reported and never what got considered, so a column pointing at Stripe was
quietly producing a "could not check" line nobody had earned. Three survived
only because the fixture had no table that could catch them: no candidate that
gets refused, none refused for a reason other than a foreign key, and no
parent already holding the value the attack uses to mean nobody. That last one
would have invented a hole out of a coincidence.

The twin fixture is the clearest record of that. Nobody designed it: every
shape in it was asked for by a mutation that lived through the whole check,
and every one of them is a shape some real app has.

| shape | the mutation that asked for it |
| --- | --- |
| a domain over integer, and one over varchar(4) | breaking the lookup of the type underneath a domain changed nothing, because a domain over text lands on the same value text does |
| a foreign key between quoted names | every name was lowercase, so Postgres wrote every key without a quote and the code that unquotes them never ran |
| a policy granted to anon that calls auth.uid() | sending a logged-out visitor with no claims makes auth.uid() throw, and a read that throws returns nothing - which is what a secured table returns |
| a table granted to nobody, and an ungranted materialized view | without a refusal, `refusal_means` was never called at all |
| a read that fails for a reason other than permission | "the attack lost" and "the attack could not run" were indistinguishable |
| write privileges, and USAGE on the sequences | the fixture granted only SELECT, so every write was refused before it began and six mutations to the write attack changed nothing |
| a column that can really be orphaned | the attack considered nothing, so both engines agreed about nothing |
| a `_id` column whose type does not match its table | pointing at a table by name alone would tell somebody to break their app |
| a row refused for a reason other than a key | a refusal that teaches nothing was being counted as the database holding |
| a table whose first writable-looking column is an identity column | every other table had an ordinary column first, so skipping generated ones could be removed unnoticed |

Survivors have been worth more than the passes. Two in `recheck.js` turned up
the overlapping `allClear` guards. One in `collision.js` showed the fixture had
no table whose column name sits inside another unique column's name. Three in
`tamper.js` turned up a `WITH CHECK` refusal being read as an untested table.
