# Kryptheon Night Shift

A robot that attacks a copy of your backend while you sleep, and tells you in
the morning what got through — in plain English, with something you can paste
into Lovable, Claude or Cursor to fix it.

**It never touches your live app.** It reads the shape of your database —
tables, columns, rules — rebuilds that shape in a throwaway schema, puts two
fake people in it, and attacks *that*. Not one of your rows is read, changed or
copied. The throwaway is deleted when it finishes.

## Run it

    KN_DATABASE_URL="postgresql://..."  node scan.js public

`public` is the schema your app lives in. It is `public` for almost everyone —
if you guess wrong, the scan tells you what is actually there instead of
pretending everything is fine.

The connection string can go on the command line instead
(`node scan.js "postgresql://..." public`), but the environment variable is
better: a command line ends up in your shell history and in the process list,
where it is the key to your whole database.

Where to find the connection string:

- **Supabase** — Project Settings → Database → Connection string → URI
- **Lovable** — it uses Supabase underneath, so the same place
- **Neon** — Dashboard → Connection Details

## What it tells you

Three answers, and three exit codes so a script can tell them apart:

| exit | meaning |
|---|---|
| `0` | everything it tried, held |
| `1` | it found problems |
| `2` | it could not run — wrong schema name, no connection, nothing to attack |

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

## Prove the fix worked

Paste the fix, then:

    KN_DATABASE_URL="postgresql://..."  node scan.js public --recheck

It runs the same attacks again and compares. A problem that *disappeared* is
not the same as a problem that was *fixed* — if a table could not be tested
this time, or is no longer there, it says so rather than crediting you with a
fix. Close everything, with nothing left untested, and it hands out a badge.

## What it looks for

| attack | the question |
|---|---|
| **Impersonation** | can a stranger, or another customer, read this? |
| **Collision** | can the same thing exist twice? |
| **Tampering** | can a stranger add, change or delete your data? |
| **Interruption** | can a half-finished write survive? |

Tampering writes, and every write is rolled back inside the transaction that
made it — the tables come out exactly as they went in, and that is checked.

Deliberately **not** reported: the lost update (two withdrawals of 100 from a
balance of 100 that both succeed). Every Postgres database behaves that way on
default isolation, so whether your app is actually vulnerable depends on code
this tool never sees. Flagging it would mean flagging every app with a number
in it.

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

    npm install
    KN_DATABASE_URL="postgresql://..."  npm run check

Fourteen suites, every one of them against a real Postgres. See
[CHECKING.md](CHECKING.md) — what each is guarding, the bugs they caught, and
why a check that leaves the database different from how it found it is not a
check.

If your network blocks outbound 5432, set `KN_PRELOAD` to a module that swaps
the driver for one reaching Postgres over 443.
