# Kryptheon Night Shift

Attacks a copy of your database and tells you, in plain English, what got in.

```
npx kryptheon-night
```

That is the whole thing. No account, no signup, no config file. It asks you
for one line from your Supabase dashboard, tells you exactly what it is about
to do, waits for you to say yes, and then takes two or three minutes.

**It never touches your live app.** It reads the *shape* of your database —
table names, columns, and the rules about who may see what — rebuilds that
shape in a temporary space, puts two made-up people in it, and attacks *that*.
Not one of your rows is read, changed or copied. The temporary space is
deleted when it finishes, and also if it crashes.

Your connection string stays on your computer. Nothing is uploaded anywhere.
There is no server on our side to upload it to.

## What you need

One line from Supabase, called the connection string.

**Supabase** — supabase.com/dashboard → your project → the gear icon
(Project Settings) at the bottom left → Database → scroll to
"Connection string" → the **URI** tab → Copy. Then replace `[YOUR-PASSWORD]`
in it with your database password, which is on that same page.

**Lovable, Bolt, v0** — your app is running on Supabase underneath. Open the
Supabase project it made for you and follow the lines above.

**Neon** — console.neon.tech → your project → Connection Details.

If you paste the wrong thing — the project URL, an API key, the line with
`[YOUR-PASSWORD]` still in it — it says so and tells you where the right one
is. It does not just fail.

## No connection string? Check your app from outside

```
npx kryptheon-night https://your-app.example.com
```

Give it your running app instead. It reads the app the way a stranger's
browser does — the Supabase address and public key every visitor is already
handed — and asks each table your app uses one question: can a stranger read
this? It asks for a **count only**, so no customer's row is ever pulled out,
and it writes nothing. About ten seconds, no password, no yes to give.

It is a narrower check than the full scan, and it says so:

- It only proves a leak when a stranger actually gets rows back. A table that
  answers with none looks the same whether it is well protected or open and
  empty, so it is reported as "could not tell", never as safe.
- One customer reading another's rows, adding or deleting rows, and the same
  thing saved twice at once all change data, so they are only ever tried on
  a copy — the full scan above.

## What you get back

Four questions, asked against the copy:

| attack | the question |
|---|---|
| **Impersonation** | can a stranger, or another customer, read this? |
| **Tampering** | can a stranger add, change or delete your data? |
| **Collision** | can the same thing exist twice? |
| **Interruption** | can a half-finished write survive? |

And three things it says are **yours to check**, because only you know
whether they are meant:

| check | the question |
|---|---|
| **Lowest role** | can a viewer in a team change what is in it? (tried on the copy, undone) |
| **Storage** | is a bucket public although a rule says who may read it? (settings only, never a file) |
| **Open functions** | can a visitor with no account call a function that skips the rules? |

These are listed apart from problems and do not change the exit code.

A problem reads like this:

    CRITICAL   customers

    Your customers table can be read by anyone.

    Anyone on the internet, without logging in and without an account, can
    read this table. I did it myself just now and got back 2 rows,
    including email addresses, phone numbers and names.

    The table has row level security switched on, so it looks protected,
    but the rule attached to it allows every request. That is why nothing
    in your dashboard flags it.

    Paste this into Lovable, Claude or Cursor:

      My app has a security problem.
      ...

And every report ends with **what was not tested, and why** — because an
attack that never ran comes back looking exactly like an attack that was
refused, and only one of those is good news.

Nothing found is never reported as "you are safe". It is reported as *these
attacks, this time, lost*.

## Prove the fix worked

Paste the fix into Lovable or Cursor, let it deploy, then run the same command
again:

```
npx kryptheon-night
```

It compares by itself — there is no flag to remember. A problem that
*disappeared* is not the same as a problem that was *fixed*: if a table could
not be tested this time, or is no longer there, it says so rather than
crediting you with a fix. Close everything, with nothing left untested, and it
hands out a badge.

## Or let it run every night, on its own

You do not have to go looking for this — the command above offers it once the
report is on the screen, and tells you if it is already running. If you would
rather just say so:

```
npx kryptheon-night install
```

This one **stays**, and it tells you so before it does anything. It puts the
checking functions into a schema called `kryptheon`, adds `pg_cron` and
`pg_net` if they are not already there, and schedules one job at 3am. Then
every night it does what the command above does — copies the shape of your
tables, attacks the copy, writes down what got through, deletes the copy.

```
npx kryptheon-night night       read back the last night it ran
npx kryptheon-night status      is it installed, and is it running
npx kryptheon-night uninstall   take it all out again
```

**Nothing leaves your database**, because the checking happens inside it — the
connection string is not stored anywhere and nothing is uploaded. It is also
much faster for the same reason: on a real project the command line took 2
minutes 16 seconds and the nightly run took 1 second, and both found the same
five problems.

**One thing it cannot do.** Racing two requests against each other — the "can
this exist twice" question — needs two connections at the same instant, and
nothing living inside a database has them. The nightly report names every
column it could not race. Running the command by hand still tests them
properly.

`uninstall` removes the job, the schema, and any extension it had to add, and
leaves alone anything that was already there.

## Three answers, three exit codes

| exit | meaning |
|---|---|
| `0` | every attack that ran, lost |
| `1` | something got through |
| `2` | it could not run — wrong string, wrong schema name, nothing to attack |

## Running it unattended

```
KN_DATABASE_URL="postgresql://..."  npx kryptheon-night --yes
```

`--yes` skips the "may I?" question, and is only for scripts. With no
keyboard attached and no `--yes`, it stops rather than connecting: the consent
screen is not worth printing if it is not honoured.

Other options, none of them necessary:

    --schema NAME    the part of the database your app lives in. Leave it
                     out; it is "public" for almost everyone
    --recheck        run the same attacks again and say what is really fixed
    --help

## Deliberately not reported

The **lost update** — two withdrawals of 100 from a balance of 100 that both
go through. Every Postgres database behaves that way unless the app asks it
not to, so whether yours is affected depends on code this tool never sees.
Flagging it would mean flagging every app with a number in it.

## The promise, and how it is kept

> We never touch your live app.

Not a policy — a structural guard. `writeSchema` refuses to run any statement
that does not name the throwaway copy, so nothing outside it can be written
even by accident. `untouched.check.js` photographs every function, privilege,
table, column, policy, role and row in the database, runs a real scan, and
fails if a single one changed.

It found two real violations the day it was written: the copy builder was
replacing the customer's own `auth.uid()` function, and opening their `auth`
schema to `anon`. Both on a live database, while every other check was green.

## Working on it

```
npm install
npm run check:dry                                      # no database needed
KN_DATABASE_URL="postgresql://..."  npm run check      # all of it
```

`check:dry` is the packaging, the wording of every failure, the consent
screen, the report and the re-check — sixty checks that need nothing but
Node. `npm run check` adds fourteen suites that each run against a real
Postgres.

See [CHECKING.md](CHECKING.md) — what each suite is guarding, the bugs they
caught, and why a check that leaves the database different from how it found
it is not a check.

`scan.js` is the same engine with the arguments on the command line
(`node scan.js "<connection string>" public`). That is the door the checks use
and it has not changed.

If your network blocks outbound 5432, set `KN_PRELOAD` to a module that swaps
the driver for one reaching Postgres over 443.
