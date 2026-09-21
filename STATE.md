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
| npm | **published**, `kryptheon` 0.1.12 | not published |
| github | `jhashantanu987-beep/kryptheon-cli` | `jhashantanu987-beep/kryptheon-night` (private) |
| commits | 3 | 17 |
| built on | Playwright | Postgres |
| commands | `record` `check` `accept` `remove` `setup-ai` | `node scan.js`, not yet a `kryptheon` command |

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

**Important and easy to misread: nothing in the shipped product has changed.**
`scan.js` still runs the Node engine. The only thing that uses `sqlengine.js`
is `twin.check.js`. Four slices of work are foundation; no user has seen a
difference yet.

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
- Outbound 5432 is blocked on this network; everything goes through a `--require`
  preload that swaps `pg` for Neon's WebSocket driver over 443.

---

## The checks

Sixteen suites, all live against a real database. `npm run check`, or
`scratchpad/suite-retry.sh branch` which retries dropped connections.

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

- **A Supabase project** for Slice 5. Free tier is enough. Neon cannot host it.
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
