# Where this is, and how it got here

A handover note. If you are an assistant picking this up cold, read this
first: it says what exists, what was measured rather than assumed, and what
was tried and did not work. Everything in it was checked against a real
database, not read off the code.

---

## Two folders, one product

Kryptheon is **one product being upgraded**, not two products. Both halves
answer the same question - *your assistant said done; is it?* - one by
looking at the screen, the other by looking at the database.

| | `C:\Users\jhash\code\kryptheon-v1` | `C:\Users\jhash\code\kryptheon-night` |
| --- | --- | --- |
| what it is | the shipping CLI | the night shift |
| npm | **published**, `kryptheon` 0.1.12 | **published**, `kryptheon-night` 0.1.0 |
| github | `jhashantanu987-beep/kryptheon-cli` | `jhashantanu987-beep/kryptheon-night` (private) |
| commits | 3 | 21 |
| built on | Playwright | Postgres |
| commands | `record` `check` `accept` `remove` `setup-ai` | `npx kryptheon-night`, and `node scan.js` underneath it |

They share **no code**. Checked: `kryptheon-v1` contains nothing about row
level security or policies; `kryptheon-night` contains nothing about browsers.

`C:\Users\jhash\OneDrive\Desktop\kryptheon-v1` is an empty shell - only
`.claude/skills`. The real repos are under `C:\Users\jhash\code\`.

### What v1 does

`kryptheon record` opens the browser, you click through one flow, it writes a
real Playwright spec into `tests/`. Passwords typed during recording are
scrubbed out and replaced with `process.env.KRYPTHEON_PASSWORD`. You let your
assistant change the code. `kryptheon check` replays the flow and says in
plain English what broke: which step, what it was looking for, when it last
passed (`kryptheon-history.jsonl`), and which console errors are *new* since
the last good run. `kryptheon accept` takes a deliberate change as the new
baseline. `setup-ai` writes a rule into `.cursorrules`, `AGENTS.md` and
`CLAUDE.md` so the assistant checks before it says done.

### What the night shift does

Reads the shape of a Postgres database - tables, columns, constraints,
whether row level security is on, the policies themselves, grants, unique
indexes, views, enums, domains. **Never the data.** Rebuilds that shape in a
throwaway schema in the same database, seeds two fake people into it, and
attacks the copy as a logged-out visitor and as a signed-in stranger:

- **impersonation** - can the wrong person read this?
- **tampering** - can a stranger change it? (every write rolled back)
- **collision** - can the same thing exist twice?
- **interruption** - can a half-finished row survive?

Then a report in plain English with a paste-able fix, and `--recheck`, which
attacks again and only says "fixed" when it watched the attack lose.

---

## The architecture, and why

One engine, in SQL, two doors.

- **`npx`** - installs the engine into a throwaway schema, runs, drops it.
  The credential stays on the customer's machine.
- **the installer** - the same functions stay put, `pg_cron` runs them
  nightly, `pg_net` posts a verdict. **No credential ever moves.**

That second door is the whole point: a vibecoder will not paste a production
connection string into a stranger's dashboard, and most would not know what
one is. So the engine had to move into the database.

`engine.sql` is 2186 lines, 60 functions, addressed to `__KN__` which
`sqlengine.js` replaces with the schema name. **Nothing is SECURITY DEFINER**
and nothing can be: Postgres refuses to let a security-definer function change
role, and changing role is the attack.

---

## What is done

| slice | | state |
| --- | --- | --- |
| 1 | reading the schema, in SQL | done |
| 2 | building the copy, in SQL | done |
| 3 | seeding + impersonation, in SQL | done |
| 4 | tampering + interruption + collision, in SQL | done |
| 5 | the installer (`pg_cron` + `pg_net`) | **not started** |

**Important and easy to misread: nothing in the engine has changed.** `scan.js`
still runs the Node engine. The only thing that uses `sqlengine.js` is
`twin.check.js`. Four slices of work are foundation; no user has seen a
difference from any of them.

### The front door, which is new

There is now a command. `npx kryptheon-night`, no arguments, no environment
variable: it asks for the connection string, says what it is about to do and
what it will not do, waits to be told yes, and runs. `scan.js` is untouched as
a door and is still what the checks drive.

This was built because of the measurement at the bottom of this file - nobody
is using the other half either, and the problem was never the engine. A
vibecoder with a Lovable app has no command line habit, has never heard the
phrase "connection string", and will not read a stack trace. Everything
between them and an answer now lives in four files:

| | |
| --- | --- |
| `bin/kryptheon-night.js` | the command: arguments, the gate, the exit codes |
| `intro.js` | what is asked, and the consent screen |
| `trouble.js` | every failure before the first attack, in sentences |
| `connect.js` | how a connection is actually opened, and its SSL |

Three things about it are load-bearing rather than decorative:

- **It will not connect without a yes.** With no keyboard attached and no
  `--yes`, it stops. `intro.check.js` checks 7 and 8 are a pair - without the
  second, the first would pass on a command that never connects to anything.
- **Nothing found is never reported as safety.** The all-clear used to end
  "Your data held". It now says these attacks lost, which is the only thing
  the program knows.
- **Every report ends with what was not tested**, including the collision
  columns and the lost update. A section that is simply absent reads exactly
  like nothing having been skipped.

It is a separate npm package, not a subcommand of `kryptheon`. Three reasons,
in order: v1's users would otherwise carry a Postgres driver they have no use
for; v1's `prepublishOnly` guard is the thing that caught the corrupted 0.1.8
publish and adding eleven files to its list means editing it; and `npx
kryptheon-night` is already one command with no install step.

### The next decision

Two orders are possible and the choice matters:

- **A. make `scan.js` use the SQL engine.** Two engines exist and only one is
  used; the unused one rots however good the twin check is. This is what makes
  both doors *actually* one engine rather than one on paper. Expect a
  decision here: `scan.js` passes `openSession` for the collision race, which
  the SQL engine cannot have (see below).
- **B. build the installer.** Needs a real Supabase project - it cannot be
  tested on Neon, measured below.

A before B was the recommendation, so that a problem in the SQL engine is
found once rather than in two places.

---

## Measured, not assumed

Every line here came from running something.

**Collision cannot run inside the database.** It needs two requests at the
same instant - the second insert in flight while the first transaction is
still open. `dblink` is available on Neon and a non-superuser may even create
it, but it cannot connect back to its own database without a password:
`dbname` alone, an empty conninfo and a local socket all answer *"password or
GSSAPI delegated credentials required"*. The only way is to hold a credential,
and no credential ever moves. So the SQL engine does not run it, and names
every column it would have raced in `notTried`, with the reason. **Reporting
nothing is the one answer that reads as safety.** The npx door still races
them for real. This means the nightly installer is strictly weaker than the
command line for exactly one attack, and that has to be said in the report.

**Neon has no `pg_net`.** `pg_cron` and `dblink` are offered; `pg_net`,
`pg_background` and `http` are not. So Slice 5 cannot be built or tested on
Neon at all. A Supabase project is needed.

**Anything the attack needs must be in hand before it changes role.** Once a
function does `SET LOCAL ROLE anon` it can no longer call anything in the
engine schema - anon has no USAGE on it - and the refusal, *"permission denied
for schema kn_engine_..."*, looks exactly like the app defending itself. Every
crossed attack came back untested until both queries were written out before
the switch.

**The copy was not the app, three times**, and each time an attack lost
quietly and it read as safety:
- enums and domains were borrowed from the original, so a view mentioning an
  enum took the whole scan down;
- sequence grants were not replayed, so every insert failed on the sequence
  and *"a stranger can add rows"* was never reported on any serial-keyed table;
- the copy's sequences did not belong to their columns, so replayed grants
  read back as absent (that link in `pg_depend` is how they are found).

**A policy expression is stored already parsed**, with the function's OID in
it. No name is resolved at read time, so schema USAGE is never checked - only
EXECUTE, which goes to PUBLIC when a function is created. Hiding a schema does
not stop a policy; revoking EXECUTE does.

**`pg` sends the password in the clear unless told not to, and being told
badly is worse.** Given a string with no `sslmode`, `pg` 8.23 leaves SSL off
entirely. Putting `sslmode=require` in the string instead is not the fix: this
version of `pg-connection-string` reads `require` and `prefer` as
`verify-full`, which fails against Supabase's own certificate authority, and
prints nine lines of upgrade notice to the screen while it does it. Neon hands
out a string ending `?sslmode=require`, so following the instructions on
screen put that notice in the middle of a security report. `connect.js`
replaces those two modes with encryption on and no certificate check - which
is what `sslmode=require` means everywhere else - and leaves `verify-full`,
`no-verify` and `disable` exactly as somebody typed them.

**Outbound 5432 was open on this network today.** The note at the bottom of
this file saying it is blocked was true when it was written and was not true
on 2026-09-21: a throwaway Neon database answered a plain `pg` connection on
5432 in 2.7 seconds, no preload involved. Test it before assuming either way;
`KN_PRELOAD` is still there for when it is blocked again.

**The database is 340 ms away, and that is the whole reason a suite takes
twenty minutes.** Measured over ten round trips to Neon in `us-east-2` from
here. `shapes.check.js` makes thousands of queries, so it spends nineteen of
its twenty minutes waiting rather than working. `neon claim create` has no
region flag, so this cannot be improved from the CLI. It matters because a
slow suite looks exactly like a hung one - and acting on that guess killed a
run that was working perfectly.

**npm downloads are not users.** 1253 last month, but every spike lands
exactly on a publish day and 20 of 30 days are zero. That is mirrors reacting
to publishes. **Nobody is using it.** The problem is distribution, not the
product.

---

## How the work is done here

These are the user's standing rules. They are not style preferences; every one
of them was bought with a bug.

- **Reply in points, not paragraphs**, in Hinglish.
- **Decide from real output, never from reading the code.** Every bug found in
  this project was found by running, not by reasoning.
- **Verify through the real path** - the real CLI, the real config, a real
  database. Never a scratch harness that proves something else works.
- **Mutation-test every check.** Break the guard, confirm the check fails. A
  check that still passes when its guard is broken is not a check.
- **A false green is the only unrecoverable failure.** Telling somebody their
  data is safe when it is not is worse than crashing.
- **Do not create new bugs while fixing bugs.**
- Do not rotate the Neon connection string.

### The traps this environment has

- **Heredocs eat one backslash of every pair**, even with a quoted delimiter.
  It is the transport, not bash. Write files containing backslashes with the
  Write tool.
- **`String.replace` reads `$$`, `$&`, `` $` `` and `$'` in the replacement
  string as instructions.** `$$` became `$` and stopped `engine.sql` from
  installing at all; `'$' + (i+1)` pasted the rest of the file in. Use a
  replacer function. `scratchpad/swap.js` does.
- **Stopping a mutation run leaves the mutation in the file.** Killing the
  process skips the `finally` that restores it. Verify each anchor by name -
  a loose `grep -c` on a string that appears twice said the tree was clean
  when it was not.
- **A dropped connection is not a failing check.** It has happened six times
  on long runs. `npm run check`'s `&&` cannot tell them apart;
  `scratchpad/suite-retry.sh` runs each check separately and retries. The
  mutation runner had the same disease and reported a live mutation as caught,
  twice - a catch has to show a FAIL line now.
- **npm printing a file name is not npm writing a file.** `npm publish
  --dry-run` runs `prepublishOnly`, which runs `package.check.js`, which runs
  `npm pack` - and npm gives its settings to child processes as `npm_config_*`
  variables, so that pack inherited `npm_config_dry_run` and packed nothing.
  It printed the file name anyway. The check then installed a tarball that was
  not there and reported six failures full of `Cannot find module`, which
  reads like a broken product. The variable is cleared before the child runs,
  and the tarball is now checked on disk.
- **`npx <path-to-tarball>` silently does nothing** and exits 0. Use `npx -y
  --package="<tarball>" -- kryptheon-night`, or install it first.
- **Killing a run leaves its connections and its schemas behind.** Stopping
  the wrapper does not stop the `node` it spawned: two backends sat idle on
  the database and four `kn_*` schemas stayed in it. It is the same disease as
  the mutation runner - a `finally` that never runs - and it is what
  `orphans.check.js` and `guests.check.js` exist for. Sweep before blaming
  anything else.
- **`guests.check.js` fails on purpose if an `auth.users` from an earlier run
  is still there.** It has to create and drop that table to test anything, it
  will not touch one that might belong to a suite in another window, and it
  says so rather than skipping quietly. Running the suite twice inside six
  hours is enough to trigger it. Drop the marked table once nothing is
  running, then run it again.
- Outbound 5432 was blocked on this network when this file was first written
  and was open on 2026-09-21. `KN_PRELOAD` still takes a `--require` preload
  that swaps `pg` for Neon's WebSocket driver over 443, for when it is blocked
  again. Test rather than assume.

---

## The checks

Nineteen suites, five of which need no database at all. `npm run check` for
all of them, `npm run check:dry` for the five.

Those five - `package`, `trouble`, `intro`, `finding`, `recheck` - are what
npm hands a stranger, the wording of every failure, the consent screen, the
report and the re-check. Sixty-three checks, about two minutes, no connection
string, which makes them the only ones somebody who has just cloned this can
run. Run them after every change to a word of the product, because the wording
is the product.

`package.check.js` is the only check that tests what a customer receives
rather than what is in this folder: it packs the real tarball, installs it
into an empty directory that has never seen this repo, and runs the command
from there. It follows the `require` graph out of the bin rather than trusting
the `files` list, because trusting that list is the bug that shipped
`kryptheon@0.1.8`.

`twin.check.js` is the important one. Two implementations of the same idea is
how a bug gets fixed once and survives in the other copy, so it builds one
deliberately awkward app, runs both engines against it, and compares them
eleven ways - what each reads, builds, seeds, and concludes about all four
attacks.

**Its fixture was not designed.** Every shape in it was asked for by a
mutation that lived through the whole check: a domain over integer, a foreign
key between quoted names, a policy granted to anon that calls `auth.uid()`, a
table granted to nobody, an ungranted materialized view, a read that fails for
a reason other than permission, write privileges and sequence grants, a column
that can really be orphaned, a `_id` column whose type does not match, a row
refused for a reason other than a key, and a table whose first
writable-looking column is an identity column. Each names a shape some real
app has. `CHECKING.md` has the table.

Two checks were found to be checking nothing: check 10 passed because the
fixture granted only SELECT, so every write was refused before it began; check
11 passed because no `_id` column matched a table with a single-column key of
the same type. Both now assert they reached something before comparing
anything.

---

## Open, and needing the user

- **A Supabase project.** Needed twice over now. Slice 5 cannot be built or
  tested anywhere else, and the front door has never been run against one:
  every Supabase-specific decision in `trouble.js` and `connect.js` - the
  session pooler, IPv6 on direct connections, the certificate authority - is
  reasoned from documentation rather than measured. Free tier is enough.
- **Nothing, to publish.** Done on 2026-09-21. `kryptheon-night@0.1.0`,
  fourteen files, 60 kB, shasum `e9523618` - the same shasum the dry run
  showed, so what is on the registry is the artifact the guard checked.
  Installed from npm into an empty folder it runs end to end in 2m20s.
- **Where the nightly verdict goes.** The design is that `pg_net` posts only
  *news*, never data - "Kryptheon found 3 things, run `kryptheon night` to see
  them" - no table names, nothing. That still needs somewhere to post to;
  Render is already in use for the site.
- **The site claims a feature that does not exist.** `kryptheon.tech` and the
  Instagram posts describe "causal chain analysis" / root-cause mapping.
  Checked: the string `causal`, `root cause`, `domino` and `bug family` appear
  nowhere in `kryptheon-v1`. The whole positioning rests on being honest
  ("nothing leaves your machine", "the spec is yours to read"), and a feature
  that is not there spends that.
