# Running the checks

Twenty suites. Run them after every change, not at the end.

    set KN_DATABASE_URL=postgresql://...
    npm run check

Five of them need nothing but Node, and those are worth running on their own
every time a word of the product is edited:

    npm run check:dry

| | needs a database | what it is about |
|---|---|---|
| `package.check.js` | no | what npm hands a stranger actually runs |
| `trouble.check.js` | no | every failure is a sentence, not a stack trace |
| `intro.check.js` | no | the consent screen is honest, and honoured |
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
| `engines.check.js` | yes | and the same report comes out of either |
| `shapes.check.js` | yes | every shape a real app has can be tested at all |
| `verdicts.check.js` | yes | the answer is right, not merely produced |
| `shop.check.js` | yes | a Supabase-shaped shop is attacked whole, by both engines |
| `teams.check.js` | yes | the two fake people are in different teams, by both engines |
| `roles.check.js` | yes | what a team's lowest role can change is found, by both engines |
| `buckets.check.js` | yes | a public storage bucket with a private-looking read rule is reported |
| `loop.check.js` | yes | the whole thing, through the real command |

And one that is deliberately **not** in `npm run check`:

| | needs | what it is about |
|---|---|---|
| `installer.check.js` | a **Supabase** project | removing the nightly door gives the database back |

    KN_DATABASE_URL=postgresql://...  npm run check:installer

The nightly door needs `pg_cron` and `pg_net`. Neon offers the first and not
the second, and every other suite here runs against Neon - so a check that
cannot run where the suite runs would either fail every night for the wrong
reason or learn to skip quietly. It lives on its own and says plainly when it
cannot run.

The ones that need a database build small apps in Postgres, use them, and take
away exactly what they created - see **The checks are guests** below.

## What each one is guarding

**installer.check.js** - a customer who removes Kryptheon gets their database
back exactly as it was. Harder than it sounds, and it fails silently when it
fails. Three things were measured on a real Supabase project before a line of
the installer was written: `pg_net` installs into the customer's own `public`
unless it is told where to go; `cron.unschedule` is overloaded on `(bigint)`
and `(name)`, so an uncast parameter binds to the name one and fails with
"could not find valid entry for job", which reads exactly like the job having
already gone; and dropping `pg_cron` on a database that already had it would
take every other job in it away.

Its own cleanup follows the same rule as the installer, and for a reason found
by breaking uninstall on purpose: the run failed correctly and left `pg_cron`
and `pg_net` installed in a real project. A check that cannot tidy up after
the thing it is testing is broken is not finished.

**engines.check.js** - the same scan, twice, down two engines, compared as a
report rather than function by function. `twin.check.js` compares what each
function decides, which is right and is not enough: every bug found on the
21st and 22nd of September was at a seam rather than inside a function. A
foreign key written without its schema, a serial default drawing the copy's
keys from the customer's sequence, and `rules` reaching the report from one
engine and not the other - each one had every function doing exactly what it
was asked.

Its app sits on the search_path, because every real app does and no fixture
here did. It is short on purpose: the awkward shapes are twin's twelve
minutes, and a seam shows up on an ordinary app as readily as on a strange
one.

**package.check.js** - the only check that tests the thing a customer receives
rather than the thing in this folder. It runs `npm pack`, installs the tarball
into an empty directory that has never seen this repo, and runs the command
from there. The sibling project shipped a broken `kryptheon@0.1.8` precisely
this way: green in the repo, `Cannot find module` for everybody who installed
it, and no suite could have known. It follows the `require` graph from the bin
rather than trusting the `files` list, because trusting the list is the bug.
It needs no database, so `prepublishOnly` can run it.

**trouble.check.js** - the wording of every failure that happens before a
single attack runs. Most of them are one person's first ninety seconds: the
Supabase line pasted with `[YOUR-PASSWORD]` still in it, the project URL
pasted instead of the connection string, an API key pasted instead of either.
Two of the cases are not invented - a connection is really opened to a host
that does not exist and to a port with nothing behind it, and the error object
`pg` actually produced is what gets explained. A mapping keyed on `err.code`
passes for months against hand-written fakes.

It has already caught one real fault: the message for a dropped connection
told people to add `?sslmode=require`, which this version of the driver reads
as full certificate verification and which Supabase's own certificate
authority then fails.

**intro.check.js** - the consent screen, and whether it is a gate or a
decoration. Checks 7 and 8 are a pair: with nobody to ask and no `--yes` the
command must not connect, and with `--yes` it must - without the second, the
first would pass just as happily on a command that never connects to anything.
Check 3 is a jargon blocklist. "I will introspect your schema and replay your
RLS policies" is a true sentence that tells this person nothing, and agreement
to a sentence nobody understood is not consent.

**finding.check.js** - the report never says more than the attack saw. Most of
it is restraint: no invented columns, no invented severity, no "personal
details" about a table of view counts. A report that overstates once is
believed never again.

**recheck.check.js** - almost every case is about refusing to say "fixed". A
finding disappears from the second run for several reasons and only one of them
is good news: the table was secured, or it became impossible to test, or it was
dropped outright. In all three it is gone from the list, and in only one has
anybody been made safe. And an earlier run on another database - the
repository's, then production's, from the same folder (HelixOps) - is said to
be a comparison of two databases, with how their tables differ, never as a fix
or as something a fix opened, and never earns a badge. cli.check.js proves the
same through the real command and its exit code.

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

**shapes.check.js** - thirty-three small apps, each down both engines, each built around a shape real
projects have and no fixture did: an enum, a `text[]`, a generated column, a
domain type, a composite key, a table that is only an id, a view that
mentions an enum, a CHECK on a varchar column, a CHECK whose values have
commas in them, exactly one of two parents set (HelixOps' documents, as a
sum of IS NOT NULL and as num_nonnulls), and a sum that asks for both. Skipped
counts as a
failure here on purpose.

**verdicts.check.js** - seventeen apps that each declare the honest answer up
front, because a hole reported as nothing and a correct app reported as broken
both leave no warning behind to notice.

**shop.check.js** - the test app a person is handed to try by hand, as a
check. Written on 2026-09-25, when that app got "I could not check this app"
from 0.1.5 because a rule on `order_items` read `orders`; then, once that was
fixed, four of its five holes came back as not tested, because nearly every
table's `user_id` points at `auth.users` and the attacks acted as somebody
never put in the copy's stand-in. Fixing the first turned up an older one: a
rule written with its schema was replayed verbatim, so the copy's rule read
the customer's table - the word-for-word comparison had passed it, since both
sides printed the same words. Now the rule guard asks `pg_depend`, and a rule
reading a table in another schema is refused out loud. Both engines, every
hole, the safe table left alone. Seven mutations, each caught.

**teams.check.js** - a team rule is tested across teams, not inside one. Found
on a blind test (AtlasPay): both fake people were seeded into the first
workspace, as its owner, so six team tables were reported as one customer
reading or changing another's data when the two were teammates. Now a table
other tables point at gets a row per person, and each person's rows point at
their own parent. And a `<thing>_id` with no foreign key still names a real
parent: the production snapshot had no keys at all, members named no
workspace, and a view open to logged-out visitors listing every workspace and
who is in it came back empty. Both engines; the open invoice rule is still
caught; a parent that only takes one row keeps the one it had. Sixteen
mutations, each caught.

**roles.check.js** - what the least trusted member of a team can change. Found
on two blind tests (OrbitDesk, AtlasPay): five holes - an UPDATE rule that
checks the role beside one that does not, rules written FOR ALL to any member,
a team's members managed by any member - went unreported, because nobody but
the owner was ever in a team. One fake person joins the other's team with the
lowest role, and every write is tried before joining and after; only what
joining added counts, so an open table, a person's own rows and a rule that
checks the role stay quiet. Reported as something to check, never a break.
An invitation is not a members table, a one-team profile is not attacked, a
team that will not take a viewer is said to be untested, and every write and
the joining are undone. Both engines, the nightly run and the re-check.

Round 9 (HelixOps) added what a member can read and add. A table holding a
token, key, secret, password or payload is read as every role not in charge,
from the lowest up, and the first that can read it is named - a "dispatcher"
reading API client keys, a "viewer" reading integration tokens or webhook
payloads. A role whose name says it only looks ("viewer") adding a row to the
team, written under someone else's name, is reported too; a member adding a
note as themselves is not. Where a table names its team, writes and reads stay
inside the team joined. Forty-nine mutations across both rounds, each caught.

**buckets.check.js** - a Supabase Storage bucket switched to public, with a
read rule saying only some people may have its files: probably meant to be
private, so reported as something to check. Found on the same two blind tests.
Only the bucket's settings and the rules on storage.objects are read, never a
file. A rule open to everyone, a private bucket, a public one with no rule and
a rule for removing files are not reported. Builds a stand-in for Storage
where there is none and takes it away. Thirteen mutations, each caught.

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
