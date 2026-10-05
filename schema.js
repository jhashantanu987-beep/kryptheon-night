// Reading a backend's shape, and rebuilding it somewhere safe.
//
// The night shift never touches the live app. It reads the shape - tables,
// columns, constraints, whether row level security is on, and the policies
// themselves - rebuilds that shape in a throwaway database, seeds fake people
// into it, and attacks that.
//
// The thing to be careful about is not the copying. It is that a copy which
// differs from the original, even slightly, produces verdicts about a database
// nobody is running. A policy that comes across subtly changed is worse than no
// copy at all: it looks like a real answer. So everything here is built to fail
// loudly rather than to produce an approximate copy quietly - see
// `unsupported` below, which is checked by the caller and is not advisory.
//
// What is deliberately not copied: data. None of it, ever - that is the whole
// promise. Also not copied: triggers and functions.
//
// What IS copied, each because leaving it out changed an answer:
//
//   unique indexes - they decide whether the same thing can exist twice. An
//     app that enforces uniqueness with CREATE UNIQUE INDEX rather than a
//     UNIQUE constraint would arrive at the copy with none of it, and be
//     reported as broken for having got it right.
//   views - a view runs with its creator's rights unless it says otherwise,
//     so one over a protected table hands out every row in it. Skipping them
//     meant never looking at that door.
//   enums and domains - the app's own types. Borrowed from the original,
//     they made the copy depend on it; and a view that mentions an enum took
//     the scan down outright.

/* --------------------------------------------------------------------------
   Reading.
-------------------------------------------------------------------------- */

/** Every table in a schema, with whether row level security is switched on. */
async function readTables(client, schema) {
  const { rows } = await client.query(
    `SELECT c.relname AS name,
            c.relrowsecurity AS rls_enabled,
            c.relforcerowsecurity AS rls_forced
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relkind = 'r'
      ORDER BY c.relname`,
    [schema],
  );
  return rows;
}

/**
 * The columns of one table, as Postgres itself would write them.
 *
 * format_type is used rather than information_schema because it gives the type
 * back exactly - numeric(10,2) stays numeric(10,2) - and a column that comes
 * back as the wrong width can change what a policy comparison does.
 */
async function readColumns(client, schema, table) {
  const { rows } = await client.query(
    `SELECT a.attname AS name,
            format_type(a.atttypid, a.atttypmod) AS type,
            a.attnotnull AS not_null,
            pg_get_expr(d.adbin, d.adrelid) AS default_expr,
            -- 's' for a stored generated column. Its value is computed from the
            -- others, so it can neither be given a DEFAULT nor be inserted
            -- into; treating it as an ordinary column crashed the copy outright.
            NULLIF(a.attgenerated, '') AS generated,
            a.attidentity <> '' AS identity,
            -- What can legally go in here, where the type itself says so. An
            -- enum column takes one of a fixed list and nothing else, and a
            -- generated test string is not on that list.
            -- Cast to text[] on purpose. array_agg over enumlabel produces
            -- name[], which node-postgres has no parser for, so it arrives as
            -- the raw string "{new,paid,shipped}" - and the first "label" is
            -- then the character "{". Exactly what pg_policies.roles did.
            (SELECT array_agg(e.enumlabel::text ORDER BY e.enumsortorder)
               FROM pg_enum e WHERE e.enumtypid = t.oid) AS enum_labels,
            -- A domain is a type with a rule attached. The rule cannot be
            -- guessed at, but the type underneath it can be used.
            CASE WHEN t.typtype = 'd' THEN format_type(t.typbasetype, a.atttypmod) END AS base_type,
            t.typcategory = 'A' AS is_array
       FROM pg_attribute a
       JOIN pg_type t ON t.oid = a.atttypid
       LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
      WHERE a.attrelid = format('%I.%I', $1::text, $2::text)::regclass
        AND a.attnum > 0
        AND NOT a.attisdropped
      ORDER BY a.attnum`,
    [schema, table],
  );
  return rows;
}

/** Primary keys, uniques and checks, in Postgres's own words. */
async function readConstraints(client, schema, table) {
  const { rows } = await client.query(
    `SELECT con.conname AS name,
            pg_get_constraintdef(con.oid) AS definition,
            con.contype AS kind
       FROM pg_constraint con
      WHERE con.conrelid = format('%I.%I', $1::text, $2::text)::regclass
      ORDER BY con.conname`,
    [schema, table],
  );
  return rows;
}

/**
 * Who was granted what on the sequences a table depends on.
 *
 * Without these the copy is not the app, in the one way that matters most.
 * Supabase grants anon USAGE on every sequence in public, so a stranger can
 * insert into a table whose key is a serial. The copy replayed the table
 * grants and not the sequence ones, so every insert the tampering attack
 * tried came back 'permission denied for sequence' - which reads as the
 * attack being beaten. "A stranger can add rows to your table" was never
 * reported on any table with a serial key, which is most tables, and it was
 * silent: it looked exactly like an app that had got it right.
 *
 * Only sequences a column owns. Those are the ones the copy has - measured,
 * not assumed: serial, bigserial and both kinds of identity all come out
 * with the same name in the copy. A sequence standing on its own does not,
 * and nothing inserts into one, so a grant on it changes no verdict.
 */
async function readSequenceGrants(client, schema) {
  const { rows } = await client.query(
    `SELECT DISTINCT s.relname AS sequence_name,
            CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee,
            a.privilege_type
       FROM pg_class s
       JOIN pg_namespace n ON n.oid = s.relnamespace
       JOIN pg_depend d ON d.objid = s.oid
                       AND d.classid = 'pg_class'::regclass
                       AND d.deptype IN ('a', 'i')
       CROSS JOIN LATERAL aclexplode(s.relacl) a
      WHERE n.nspname = $1 AND s.relkind = 'S'
        AND (CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
            IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
      ORDER BY 1, 2, 3`,
    [schema],
  );
  return rows;
}

/**
 * Unique indexes, which are the other half of "can this happen twice".
 *
 * Read separately from constraints because `CREATE UNIQUE INDEX` and
 * `UNIQUE (...)` are different objects in Postgres and real apps use both. An
 * app whose uniqueness lives in an index would arrive at the copy with none of
 * it, and the Collision attack would then report every such app as broken - a
 * false alarm on exactly the apps that got it right.
 *
 * Primary keys and indexes backing a constraint are left out: those come along
 * with the constraint itself, and creating them again is an error.
 */
async function readIndexes(client, schema) {
  const { rows } = await client.query(
    `SELECT c.relname AS name,
            t.relname AS table_name,
            pg_get_indexdef(i.indexrelid) AS definition
       FROM pg_index i
       JOIN pg_class c ON c.oid = i.indexrelid
       JOIN pg_class t ON t.oid = i.indrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1
        AND i.indisunique
        AND NOT i.indisprimary
        AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = i.indexrelid)
      ORDER BY t.relname, c.relname`,
    [schema],
  );
  return rows;
}

/**
 * The policies. These are the thing under test, so they are copied verbatim.
 *
 * pg_policies hands back `qual` and `with_check` already rendered as SQL, which
 * is what makes an exact copy possible at all.
 */
/**
 * Functions an anonymous visitor can call that run with their owner's rights.
 *
 * A SECURITY DEFINER function runs as whoever wrote it, not as the caller, so
 * the row level security on every table it touches is checked against the
 * owner - and bypassed for the caller. That is exactly what such a function is
 * for; it is only a problem when the person allowed to call it is somebody who
 * should not have that reach.
 *
 * Only `anon` is treated as that person here, on purpose. anon is the whole
 * internet with no account. A definer function granted only to `authenticated`
 * is the ordinary Supabase RPC pattern - it is meant to be called by signed-in
 * users and guarded inside with auth.uid() - and flagging every one of those
 * would bury the real finding under the intended design. So the low-false-
 * alarm signal is: security definer, callable by anon, and not a trigger.
 *
 * Trigger functions are excluded because calling one directly does nothing (it
 * needs a row event), so "anon can call it" is not a reach anon actually has.
 *
 * This is read only. Nothing is executed - the finding it produces is a
 * "verification required", not a proven break, because whether an anon RPC is
 * intended is a question only the person who wrote it can answer.
 *
 * Every definer function is returned, each with `callable` saying whether the
 * role can run it. The ones that cannot are what makes a fix provable: a
 * re-check needs to know the function was looked at again and the grant was
 * gone, which is different from the function no longer being there at all.
 */
/**
 * Whether a function turns the caller away before it does anything.
 *
 * Found on a blind test: create_admin_export opens with
 *   if not public.is_org_admin(p_org_id) then raise exception ...
 * and was reported as "anyone can call it, with full rights". A visitor with
 * no account is not an admin of anything, so the first line refuses them and
 * nothing else runs. That is a guard, and the function is examined, not
 * reported.
 *
 * Only a refusal counts - IF NOT <check> THEN RAISE - and only one that comes
 * before the first write and the first RETURN, because a check made after the
 * work is done guards nothing. The check has to ask about the caller: a call
 * to one of the schema's yes/no helpers that ask auth.uid(), or a condition
 * of its own that asks auth.uid() whether they are an admin, owner or member.
 * "Is anybody signed in at all" is not enough, and neither is a check on an
 * argument the caller chose.
 */
function guardedAtTheDoor(body, helpers) {
  const text = String(body || '');
  const writes = /\b(insert\s+into|update\s+(only\s+)?["\w]+|delete\s+from|truncate|merge\s+into)\b/i.exec(text);
  const returns = /\breturn\b/i.exec(text);
  const firstAct = Math.min(writes ? writes.index : Infinity, returns ? returns.index : Infinity);
  // The condition may not run past a THEN, or two IFs would be read as one;
  // and END IF is not the start of one.
  const guard = /(?<!\bend\s+)\bif\b((?:(?!\bthen\b)[\s\S])*?)\bthen\s+raise\b(?!\s+(?:notice|warning|info|log|debug)\b)/gi;
  // The name as a call, bare or schema-qualified (public.is_org_admin), and
  // never as the tail of a longer name.
  const asks = (cond, name) => new RegExp('(^|[^\\w$"])"?' +
    name.replace(/[$]/g, '\\$') + '"?\\s*\\(', 'i').test(cond);
  let found;
  while ((found = guard.exec(text)) !== null) {
    if (found.index > firstAct) break;
    const cond = found[1].trim();
    // Refusing when the check fails, not when it passes.
    const refusesOnNo = /^not\b/i.test(cond) || /\bis\s+(not\s+true|false)\s*$/i.test(cond) || /=\s*false\s*$/i.test(cond);
    if (!refusesOnNo) continue;
    if ((helpers || []).some((name) => asks(cond, name))) return true;
    if (/\bauth\s*\.\s*(uid|jwt)\s*\(/i.test(cond) && /admin|owner|member|role/i.test(cond)) return true;
  }
  return false;
}

async function readAnonDefinerFunctions(client, schema, role) {
  const caller = role || 'anon';
  // A plain Postgres with no anon role has no anonymous caller at all, so
  // nothing is callable by it - and has_function_privilege() on a role that
  // does not exist throws, which took the whole scan down with it before this
  // was checked first.
  const exists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [caller]);
  const { rows } = await client.query(
    `SELECT p.proname AS name,
            pg_get_function_identity_arguments(p.oid) AS args,
            p.proconfig::text AS config,
            pg_get_functiondef(p.oid) AS def,
            p.prorettype = 'pg_catalog.bool'::regtype AS returns_bool,
            ${exists.rows.length ? "has_function_privilege($2, p.oid, 'EXECUTE')" : 'false'} AS callable
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = $1
        AND p.prosecdef
        AND p.prorettype <> 'pg_catalog.trigger'::regtype
      ORDER BY p.proname`,
    exists.rows.length ? [schema, caller] : [schema],
  );
  // The schema's yes/no helpers about the caller - is_org_admin(org) asking
  // whether auth.uid() is an admin of it - definer or not, since a guard can
  // call either. Read once, for guardedAtTheDoor.
  const { rows: yesNo } = await client.query(
    `SELECT p.proname AS name, pg_get_functiondef(p.oid) AS def
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = $1 AND p.prokind = 'f' AND p.prorettype = 'pg_catalog.bool'::regtype`,
    [schema],
  );
  const helpers = yesNo.filter((row) => {
    const body = String(row.def || '').replace(/--[^\n]*/g, ' ');
    return /\bauth\s*\.\s*(uid|jwt)\s*\(/i.test(body) &&
      !/\b(insert\s+into|update\s+(only\s+)?["\w]+|delete\s+from|truncate|merge\s+into)\b/i.test(body);
  }).map((row) => row.name);
  return rows.map((row) => {
    // A definer function with no search_path pinned is a second, separate
    // hazard: the caller can set their own search_path and make the function
    // resolve to their objects. Said as part of the same finding.
    const config = row.config || '';
    const hasFixedSearchPath = /(^|,)search_path=/i.test(config.replace(/[{}"]/g, ''));
    // The body is only used to say, in the report, whether it writes - which
    // decides how the finding is worded, not whether it is reported. A comment
    // could fool this, and that is acceptable: it never turns a non-finding
    // into a finding, only "can read" into "can change".
    const body = String(row.def || '').replace(/--[^\n]*/g, ' ');
    // `update\s+\w` followed by \b matched only a one-letter table name, so
    // UPDATE was never seen - archive_notebook was worded as reading. The
    // whole name, quoted or not, is matched now.
    const writes = /\b(insert\s+into|update\s+(only\s+)?["\w]+|delete\s+from|truncate|merge\s+into)\b/i.test(body);
    // A yes/no about the caller alone - is_org_member(org) asking whether
    // auth.uid() belongs to it. Found on a blind test, where two such helpers
    // were reported as "anyone can call it, with full rights": they are how
    // row level security avoids checking a table against itself, and to a
    // visitor with no account they answer no. Reading nothing about anybody
    // else and writing nothing, they are not a reach. A yes/no that does not
    // ask auth.uid() - is_admin(user_id) - answers about other people, and
    // stays a finding.
    const aboutCaller = row.returns_bool === true && !writes && /\bauth\s*\.\s*(uid|jwt)\s*\(/i.test(body);
    return {
      name: row.name,
      args: row.args || '',
      writes: writes,
      aboutCaller: aboutCaller,
      guarded: guardedAtTheDoor(body, helpers),
      hasFixedSearchPath: hasFixedSearchPath,
      callable: row.callable === true,
    };
  });
}

/**
 * The app's own SQL and PL/pgSQL functions, with their full definitions.
 *
 * Read so the helpers a rule calls can be built inside the copy. Found on a
 * blind test: a rule called has_org_role(org_id, ARRAY[...]::org_role[]). The
 * copy has its own org_role, the helper stayed in the original schema taking
 * the original's, and no rule could be created - the scan stopped before it
 * began. Left in the original, a helper also answers from the original's
 * tables rather than from the copy's.
 */
async function readFunctions(client, schema) {
  const { rows } = await client.query(
    `SELECT p.proname AS name,
            l.lanname AS language,
            p.prosrc AS src,
            pg_get_functiondef(p.oid) AS def,
            pg_get_function_identity_arguments(p.oid) AS args,
            p.proacl IS NULL AS default_acl,
            (SELECT coalesce(array_agg(g ORDER BY g), '{}'::text[])
               FROM (SELECT DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END AS g
                       FROM aclexplode(p.proacl) a
                      WHERE a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner) x) AS executors
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_language l ON l.oid = p.prolang
      WHERE n.nspname = $1
        AND p.prokind = 'f'
        AND p.prorettype <> 'pg_catalog.trigger'::regtype
      ORDER BY p.proname, p.oid`,
    [schema],
  );
  return rows;
}

/**
 * Supabase Storage's buckets: whether each is public, and the rules on
 * storage.objects that say who may read it (a rule naming the bucket's id).
 *
 * The settings and the rules only - never a file, never a file's name. A
 * database without Supabase Storage, or one this connection cannot read it in,
 * has none. Mirrors read_buckets in engine.sql, query for query.
 *
 * Asked first rather than left to fail: a failed query inside a caller's
 * transaction would abort everything after it.
 */
async function readBuckets(client) {
  try {
    const here = await client.query(
      `SELECT to_regclass('storage.buckets') IS NOT NULL
          AND EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_schema = 'storage' AND table_name = 'buckets' AND column_name = 'public') AS found`,
    );
    if (!here.rows[0].found) return [];
    const { rows } = await client.query(BUCKETS_QUERY);
    return rows[0].buckets;
  } catch (err) {
    return [];
  }
}

const BUCKETS_QUERY =
  `SELECT coalesce(jsonb_agg(jsonb_build_object(
            'id', b.id::text,
            'name', b.name::text,
            'public', coalesce(b.public, false),
            'readRules', (SELECT coalesce(jsonb_agg(jsonb_build_object(
                                   'name', p.policyname::text,
                                   'roles', to_jsonb(p.roles::text[]),
                                   'qual', p.qual) ORDER BY p.policyname), '[]'::jsonb)
                            FROM pg_policies p
                           WHERE p.schemaname = 'storage' AND p.tablename = 'objects'
                             AND p.cmd IN ('SELECT', 'ALL')
                             AND position(quote_literal(b.id::text) IN coalesce(p.qual, '')) > 0)
          ) ORDER BY b.id), '[]'::jsonb) AS buckets
     FROM storage.buckets b`;

async function readPolicies(client, schema) {
  const { rows } = await client.query(
    `SELECT tablename AS table_name,
            policyname AS name,
            permissive,
            -- Cast on purpose. pg_policies.roles is name[], which
            -- node-postgres has no parser for, so it arrives as the raw
            -- string "{anon,authenticated}" - and code that treats it as a
            -- list gets the characters of that string instead of the roles.
            -- roleList() was written to undo that; casting here means there is
            -- nothing to undo. The third time this exact shape has cost a bug,
            -- and the one the two engines disagreed about on their first run.
            roles::text[] AS roles,
            cmd,
            qual,
            with_check
       FROM pg_policies
      WHERE schemaname = $1
      ORDER BY tablename, policyname`,
    [schema],
  );
  return rows;
}

/**
 * Who was granted what. A policy is irrelevant if the grant is not there.
 *
 * Restricted to ordinary tables on purpose. role_table_grants also lists views
 * and materialised views, and replaying a grant on a view the copy does not
 * contain fails outright - which took down the scan of any app with a view in
 * it, and almost every app has one.
 */
async function readGrants(client, schema) {
  const { rows } = await client.query(
    `SELECT g.table_name, g.grantee, g.privilege_type
       FROM information_schema.role_table_grants g
       JOIN pg_class c ON c.relname = g.table_name
       JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = g.table_schema
      WHERE g.table_schema = $1
        AND c.relkind = 'r'
        AND g.grantee IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
      ORDER BY g.table_name, g.grantee, g.privilege_type`,
    [schema],
  );
  return rows;
}

/**
 * Views, which are a door of their own.
 *
 * A view runs with its creator's rights unless it says otherwise, so a view
 * over a table that row level security protects hands out every row in that
 * table to anyone allowed to read the view. The policy is intact, the
 * dashboard is green, and the data is gone. `security_invoker` is what turns
 * that off, and it lives in reloptions, so it is copied with the view.
 */
async function readViews(client, schema) {
  const { rows } = await client.query(
    `SELECT c.relname AS name,
            pg_get_viewdef(c.oid, true) AS definition,
            c.relkind = 'm' AS materialised,
            array_to_string(c.reloptions, ', ') AS options
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relkind IN ('v', 'm')
      ORDER BY c.relname`,
    [schema],
  );
  return rows;
}

/** Views, with the columns they expose, so a finding can name what leaked. */
async function readViewsWithColumns(client, schema) {
  const views = await readViews(client, schema);
  for (const view of views) {
    view.columns = await readColumns(client, schema, view.name);
  }
  return views;
}

/** Who was granted what on a view. Separate, because views are created later. */
async function readViewGrants(client, schema) {
  const { rows } = await client.query(
    `SELECT g.table_name, g.grantee, g.privilege_type
       FROM information_schema.role_table_grants g
       JOIN pg_class c ON c.relname = g.table_name
       JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = g.table_schema
      WHERE g.table_schema = $1
        AND c.relkind IN ('v', 'm')
        AND g.grantee IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
      ORDER BY g.table_name, g.grantee, g.privilege_type`,
    [schema],
  );
  return rows;
}

/**
 * The types the app made for itself: enums, and domains.
 *
 * Copied, so that the copy stands on its own. It used to borrow them from the
 * schema it was copied from, which worked right up until a view mentioned one:
 * pg_get_viewdef writes a literal as 'paid'::app.order_status, the rewrite
 * turned app into the copy, and the copy had no such type. Any app with a view
 * over an enum column - which is a great many of them - crashed the scan
 * outright, with a stack trace where the report should have been.
 *
 * Borrowing was quietly wrong anyway. A copy that reaches back into the
 * original for anything is a copy that can change under the attack.
 */
async function readTypes(client, schema) {
  const { rows } = await client.query(
    `SELECT t.typname AS name,
            t.typtype AS kind,
            CASE WHEN t.typtype = 'e' THEN (
              SELECT array_agg(e.enumlabel::text ORDER BY e.enumsortorder)
                FROM pg_enum e WHERE e.enumtypid = t.oid
            ) END AS labels,
            CASE WHEN t.typtype = 'd'
                 THEN format_type(t.typbasetype, t.typtypmod) END AS base_type,
            CASE WHEN t.typtype = 'd' THEN (
              SELECT array_agg(pg_get_constraintdef(c.oid) ORDER BY c.conname)
                FROM pg_constraint c WHERE c.contypid = t.oid
            ) END AS constraints,
            t.typnotnull AS not_null,
            CASE WHEN t.typtype = 'd' THEN t.typdefault END AS default_value
       FROM pg_type t
       JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = $1
        AND t.typtype IN ('e', 'd')
      -- Enums first. A domain can be built on one, and a domain created
      -- before the enum it stands on is a type that does not exist yet.
      ORDER BY CASE WHEN t.typtype = 'e' THEN 0 ELSE 1 END, t.typname`,
    [schema],
  );
  return rows;
}

/** What a foreign key points at, pulled out of Postgres's own wording. */
function referenceIn(definition) {
  const match = /FOREIGN KEY\s*\(([^)]+)\)\s*REFERENCES\s+([^\s(]+)\s*\(([^)]+)\)/i.exec(String(definition));
  if (!match) return null;
  const strip = (text) => text.trim().replace(/^"(.*)"$/, '$1');
  const target = match[2].trim().split(/\.(?=(?:[^"]*"[^"]*")*[^"]*$)/).map(strip);
  return {
    schema: target.length > 1 ? target[0] : null,
    table: target[target.length - 1],
    columns: match[3].split(',').map(strip),
  };
}

/**
 * The name a stand-in for an outside table is given inside the copy.
 *
 * `taken` is every name the customer already uses, and the stand-in keeps
 * moving until it clashes with none of them. Identifying our own tables by
 * their prefix alone meant a customer table that happened to start with the
 * same letters was quietly dropped from every attack - a real hole reported as
 * nothing at all, which is the failure this whole program exists to avoid.
 */
function stubNameFor(refSchema, refTable, taken) {
  const used = new Set(taken || []);
  const base = 'kn_ext__' + refSchema + '__' + refTable;
  let name = base;
  let nth = 2;
  while (used.has(name)) {
    name = base + '__' + nth;
    nth += 1;
  }
  return name;
}

/**
 * Tables outside this schema that its foreign keys point at.
 *
 * Nearly every Supabase app has `references auth.users(id)`, and the copy
 * cannot carry that as written: pointed at the real auth.users, every seeded
 * row becomes a write into the customer's own authentication table. So the
 * shape of the outside table is read - columns and types, never rows - and a
 * stand-in is built inside the copy instead.
 *
 * A target whose shape cannot be read at all is returned with no columns, and
 * the caller treats that as unsupported rather than guessing at it.
 */
async function readExternalTargets(client, schema, tables) {
  const wanted = new Map();
  for (const table of tables) {
    for (const constraint of table.constraints || []) {
      if (constraint.kind !== 'f') continue;
      const points = referenceIn(constraint.definition);
      if (!points || !points.schema || points.schema === schema) continue;
      const key = points.schema + '.' + points.table;
      if (!wanted.has(key)) {
        wanted.set(key, { schema: points.schema, table: points.table, columns: new Set() });
      }
      points.columns.forEach((column) => wanted.get(key).columns.add(column));
    }
  }

  const targets = [];
  for (const entry of wanted.values()) {
    let columns = [];
    try {
      const { rows } = await client.query(
        `SELECT a.attname AS name, format_type(a.atttypid, a.atttypmod) AS type
           FROM pg_attribute a
          WHERE a.attrelid = format('%I.%I', $1::text, $2::text)::regclass
            AND a.attname = ANY($3) AND a.attnum > 0 AND NOT a.attisdropped
          ORDER BY a.attnum`,
        [entry.schema, entry.table, Array.from(entry.columns)],
      );
      columns = rows;
    } catch (err) {
      columns = [];
    }
    targets.push({
      schema: entry.schema,
      table: entry.table,
      columns: columns,
      stub: stubNameFor(entry.schema, entry.table, tables.map((t) => t.name)),
      wanted: Array.from(entry.columns),
    });
  }
  return targets;
}

/**
 * Everything needed to rebuild a schema, and everything that could not be.
 *
 * `unsupported` is the important half. A caller that ignores it is attacking a
 * database that is not the customer's.
 */
async function readSchema(client, schema) {
  const tables = await readTables(client, schema);
  const unsupported = [];
  const built = [];

  for (const table of tables) {
    const columns = await readColumns(client, schema, table.name);
    const constraints = await readConstraints(client, schema, table.name);

    built.push({
      name: table.name,
      rlsEnabled: table.rls_enabled,
      rlsForced: table.rls_forced,
      columns: columns,
      constraints: constraints,
    });
  }

  // A foreign key pointing outside this schema gets a stand-in inside the
  // copy. Quietly dropping it instead would change what seeding is allowed to
  // insert, and pointing it at the real table would make every seeded row a
  // write into the customer's own data.
  const external = await readExternalTargets(client, schema, built);
  for (const target of external) {
    if (target.columns.length !== target.wanted.length) {
      unsupported.push(
        'a foreign key points at ' + target.schema + '.' + target.table +
          ', and I could not read its shape to stand in for it',
      );
    }
  }

  return {
    schema: schema,
    tables: built,
    policies: await readPolicies(client, schema),
    grants: await readGrants(client, schema),
    sequenceGrants: await readSequenceGrants(client, schema),
    types: await readTypes(client, schema),
    indexes: await readIndexes(client, schema),
    views: await readViewsWithColumns(client, schema),
    viewGrants: await readViewGrants(client, schema),
    external: external,
    anonFunctions: await readAnonDefinerFunctions(client, schema),
    functions: await readFunctions(client, schema),
    buckets: await readBuckets(client),
    unsupported: unsupported,
  };
}

/* --------------------------------------------------------------------------
   Rebuilding.
-------------------------------------------------------------------------- */

function quote(name) {
  return '"' + String(name).split('"').join('""') + '"';
}

/**
 * The roles a policy applies to, as a list.
 *
 * pg_policies hands this back as the raw Postgres array literal - the string
 * "{anon,authenticated}", not an array - because node-postgres has no parser
 * registered for name[]. Measured, not assumed. Treating it as an array gives
 * either a crash or, worse, a policy created for the wrong roles.
 */
function roleList(roles) {
  if (Array.isArray(roles)) return roles;
  const raw = String(roles === null || roles === undefined ? '' : roles).trim();
  if (!raw || raw === '{}') return [];
  const inner = raw.startsWith('{') && raw.endsWith('}') ? raw.slice(1, -1) : raw;
  return inner
    .split(',')
    .map((part) => part.trim().replace(/^"(.*)"$/, '$1'))
    .filter(Boolean);
}

/**
 * Points anything schema-qualified at the copy instead of the original.
 *
 * Both spellings, and that is the whole point of this existing. Postgres
 * writes a name unquoted when it does not need quoting, so a foreign key came
 * back as "REFERENCES app.profiles(id)" while only the quoted form was being
 * rewritten - and the copy was created holding a live reference into the
 * customer's real schema. Every insert into the copy would then have been
 * checked against the customer's real table, which is the one thing this is
 * built never to touch.
 */
function rewriteSchemaRefs(expr, fromSchema, toSchema) {
  if (!expr) return null;
  return String(expr).split(quote(fromSchema) + '.').join(quote(toSchema) + '.').split(fromSchema + '.').join(toSchema + '.');
}

/**
 * Points a rule's references to the app's own tables and views at the copy -
 * and leaves everything else alone.
 *
 * A rule is copied as Postgres printed it. For an app outside the search_path
 * that includes the schema - "EXISTS (SELECT 1 FROM kn_app.members m ...)" -
 * and replayed verbatim into the copy, the copy's rule read the customer's
 * members table. Caught by the pg_depend guard in writeSchema the day it
 * learned to look at rules; the text comparison had passed it for months,
 * since source and copy printed the same words.
 *
 * Not rewriteSchemaRefs, which moves every "kn_app." it finds: a rule calling
 * one of the app's functions that is not copied (kn_app.whoami() in another
 * language) has to keep calling it, and pointing it at the copy makes the
 * CREATE POLICY fail. Only tables, views, and the functions the copy was
 * given (copiedFunctions) move. A name followed by more identifier characters
 * is a different name - members_log is not members - so the match stops at a
 * word boundary.
 */
function rewriteOwnTableRefs(expr, plan, target, copiedFunctions) {
  if (expr === null || expr === undefined) return expr;
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const simple = (s) => /^[a-z_][a-z0-9_$]*$/.test(s);
  const schemaForms = [quote(plan.schema)].concat(simple(plan.schema) ? [plan.schema] : []);
  const own = (plan.tables || []).map((t) => t.name).concat((plan.views || []).map((v) => v.name), copiedFunctions || []);
  let out = String(expr);
  for (const name of own) {
    const nameForms = [quote(name)].concat(simple(name) ? [name] : []);
    for (const s of schemaForms) {
      for (const n of nameForms) {
        const tail = n.charAt(0) === '"' ? '' : '(?![A-Za-z0-9_$])';
        out = out.replace(new RegExp(escape(s + '.' + n) + tail, 'g'), quote(target) + '.' + quote(name));
      }
    }
  }
  return out;
}

/**
 * Which of the app's functions the copy needs: every SQL or PL/pgSQL function
 * a rule or a view calls, and every one those call in turn. Matched by name
 * followed by "(", bare or schema-qualified; every overload of a name comes
 * along. Functions in other languages stay where they are.
 */
function functionsToCopy(plan) {
  const copyable = (plan.functions || []).filter((f) => f.language === 'sql' || f.language === 'plpgsql');
  const names = Array.from(new Set(copyable.map((f) => f.name)));
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const calls = (text, name) => new RegExp('(^|[^A-Za-z0-9_$])"?' + escape(name) + '"?\\s*\\(').test(String(text || ''));
  const seeds = []
    .concat((plan.policies || []).map((p) => String(p.qual || '') + ' ' + String(p.with_check || '')))
    .concat((plan.views || []).map((v) => v.definition));
  const wanted = new Set(names.filter((name) => seeds.some((text) => calls(text, name))));
  // And whatever those call, until nothing new turns up.
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of copyable) {
      if (!wanted.has(f.name)) continue;
      for (const name of names) {
        if (!wanted.has(name) && calls(f.src, name)) {
          wanted.add(name);
          grew = true;
        }
      }
    }
  }
  return copyable.filter((f) => wanted.has(f.name));
}

/**
 * One of the app's functions, rebuilt in the copy: the same body and settings,
 * its name in the copy, its references to the app's own tables, views and
 * copied functions pointed at the copy, and a pinned search_path that looks in
 * the copy first and the original second (for what the copy does not have,
 * such as an extension's functions).
 */
function copyFunctionStatement(fn, plan, target, copiedNames) {
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const schemaForms = [quote(plan.schema), plan.schema].map(escape).join('|');
  let def = String(fn.def).replace(
    new RegExp('^CREATE OR REPLACE FUNCTION\\s+(?:' + schemaForms + ')\\.'),
    () => 'CREATE FUNCTION ' + quote(target) + '.',
  );
  // The settings line, e.g.  SET search_path TO 'public', 'storage'
  const pinned = /^\s*SET search_path (?:TO|=) /m.test(def);
  def = def.replace(/^(\s*SET search_path (?:TO|=) )(.*)$/m, (all, head, list) =>
    head + list.split(',').map((part) => {
      const bare = part.trim().replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
      return bare === plan.schema ? "'" + target + "', " + part.trim() : part.trim();
    }).join(', '));
  // None pinned, so a bare name in the body is looked up on the caller's path
  // when it runs - and the caller's path has never heard of the copy. Found on
  // a blind test (OrbitDesk): member_of and has_role read `workspace_members`
  // bare, so the copy's helpers read the original's members, with the
  // original's workspace_role, against the copy's. Every rule calling has_role
  // failed with "operator does not exist", 13 attacks never ran, and a loop
  // through member_of never fired because the original's table was empty.
  // So the copy's helper is pinned the way the copy itself was built: the copy
  // first, then where the original's bare names would have gone. A BEGIN
  // ATOMIC body has no AS line and needs none - it was bound when it was made.
  if (!pinned) {
    const path = Array.from(new Set([target, plan.schema, 'public', 'extensions']));
    def = def.replace(/\nAS /, '\n SET search_path TO ' + path.map((s) => "'" + s + "'").join(', ') + '\nAS ');
  }
  return rewriteOwnTableRefs(def, plan, target, copiedNames);
}

/**
 * Points a reference with no schema on it at the copy.
 *
 * The one the other two rewrites could not see. `pg_get_constraintdef` writes
 * the schema only when the referenced table is *not* reachable through
 * `search_path` - so an app living in `app_something` comes back as
 * "REFERENCES app_something.profiles(id)" and is rewritten, while the same app
 * living in `public` comes back as "REFERENCES profiles(id)" and there is
 * nothing to rewrite. Replayed into the copy, that bare name resolves through
 * `search_path` all over again, and binds to the customer's real table.
 *
 * Found on the first real Supabase project this was ever pointed at, which is
 * the first app that was not in a schema of its own:
 *
 *   notes_owner_fkey     -> public.profiles      (the customer's own table)
 *   orders_user_id_fkey  -> public.profiles      (the customer's own table)
 *
 * Nothing was written to those tables - the copy only pointed at them - but
 * the copy was not the app, which is the same failure three other bugs in this
 * file were. Here it meant every insert into the copy was checked against a
 * table the seeder had put nothing in, so two tables out of four were never
 * attacked and were reported, honestly but uselessly, as not checked.
 *
 * Only names the plan itself owns are touched. A reference to something
 * outside the schema is the stand-in's business, not this one's.
 */
function qualifyOwnRefs(definition, plan, target) {
  const own = new Set((plan.tables || []).map((table) => table.name));
  // A replacer function, never a replacement string: `$&` and friends are read
  // as instructions inside one, and that has already cost this project an
  // engine that would not install.
  // A quoted identifier can hold anything, including spaces and quotes of its
  // own doubled up, so it is matched as a whole rather than as a run of safe
  // characters. The first attempt used [^".\s(]+ inside the quotes and
  // silently did not match `REFERENCES "Group Table"(...)` - which the twin
  // fixture has, because it was built out of every shape that has ever been
  // read wrong, and it caught this the first time it ran.
  //
  // The unquoted alternative excludes a dot, so a name that is already
  // schema-qualified is left alone: that is the other rewrite's work.
  return String(definition).replace(
    /(\bREFERENCES\s+)("(?:[^"]|"")*"|[^\s(".]+)(\s*\()/gi,
    (whole, before, written, after) => {
      const name = written.charAt(0) === '"'
        ? written.slice(1, -1).split('""').join('"')
        : written;
      return own.has(name) ? before + quote(target) + '.' + quote(name) + after : whole;
    },
  );
}

/**
 * Points a foreign key at the stand-in instead of at the real outside table.
 *
 * Both spellings again, for the same reason the schema rewrite handles both:
 * Postgres writes a name unquoted whenever it does not have to quote it, and
 * missing one spelling leaves the copy holding a live reference into the
 * customer's database.
 */
function rewriteExternalRefs(expr, external, toSchema) {
  let text = String(expr);
  for (const target of external || []) {
    const stub = quote(toSchema) + '.' + quote(target.stub);
    text = text
      .split(quote(target.schema) + '.' + quote(target.table))
      .join(stub)
      .split(target.schema + '.' + target.table)
      .join(stub);
  }
  return text;
}

/** Two people who do not exist, used wherever a stand-in row is needed. */
// Everyone the attacks ever act as: the seeded pair (A, B) and the two who
// own nothing (C, D, see attack.js) - the same values, kept literal here
// because attack.js requires this file. All four go into every stand-in.
// With only A and B there, a row an attack added under C was refused by the
// foreign key to auth.users before any rule was consulted, and "anyone can
// place an order" or "two accounts share one email" came back as not tested.
// Measured on a test app shaped like a Supabase shop, where nearly every
// table's user_id points at auth.users - so on real apps, most of them.
const IDENTITIES = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  '55555555-5555-4555-8555-555555555555',
  '66666666-6666-4666-8666-666666666666',
];

/** Something of the right type to put in a stand-in row. */
function stubValue(type, nth) {
  const kind = String(type).toLowerCase();
  if (kind === 'uuid') return "'" + IDENTITIES[nth] + "'";
  if (/^(integer|bigint|smallint|numeric|decimal|real|double)/.test(kind)) return String(nth + 1);
  if (/^bool/.test(kind)) return nth === 0 ? 'true' : 'false';
  if (/^(timestamp|date)/.test(kind)) return 'now()';
  return "'kryptheon-" + (nth + 1) + "'";
}

/** Which of these roles this database actually has. */
async function existingRoles(client, wanted) {
  const { rows } = await client.query('SELECT rolname FROM pg_roles WHERE rolname = ANY($1)', [wanted]);
  return rows.map((row) => row.rolname);
}

/**
 * Nothing may be written outside the copy. Ever.
 *
 * The product is sold on one sentence - we never touch your live app - and
 * this is the line that keeps it true. It is a structural guard rather than a
 * careful habit, because the two statements that broke the promise were
 * written carefully and sat there for weeks: every check built its own
 * auth.uid() first, so replacing the customer's looked exactly like doing
 * nothing.
 *
 * Every statement has to name the copy schema, quoted or not. A statement that
 * does not is not run, and the scan stops rather than guessing.
 */
function mustStayInside(statements, target) {
  const bare = new RegExp('(^|[^A-Za-z0-9_"])' + target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.');
  for (const statement of statements) {
    if (statement.includes(quote(target)) || bare.test(statement)) continue;
    throw new Error(
      'refusing to run a statement that does not stay inside the copy ' + target + ': ' + statement,
    );
  }
  return statements;
}

/**
 * Builds the schema again, in a database we own.
 *
 * Order matters: tables, then constraints, then grants, then policies. A policy
 * cannot be created before the table it guards, and a grant given after a
 * policy would widen access the original did not have.
 */
async function writeSchema(client, plan, target) {
  const statements = ['CREATE SCHEMA ' + quote(target)];

  // The app's own types first: a column, a check, a view or a cast can all
  // name one, and nothing that mentions a type can be created before it.
  for (const made of plan.types || []) {
    if (made.kind === 'e') {
      statements.push(
        'CREATE TYPE ' + quote(target) + '.' + quote(made.name) + ' AS ENUM (' +
          (made.labels || []).map((label) => "'" + String(label).split("'").join("''") + "'").join(', ') + ')',
      );
    } else {
      const here = (text) => rewriteSchemaRefs(text, plan.schema, target);
      // A domain can stand on another of the app's own types, and its rule can
      // name one too, so both go through the same rewrite a column does.
      const parts = ['CREATE DOMAIN ' + quote(target) + '.' + quote(made.name) + ' AS ' + here(made.base_type)];
      if (made.default_value) parts.push('DEFAULT ' + here(made.default_value));
      if (made.not_null) parts.push('NOT NULL');
      for (const rule of made.constraints || []) parts.push(here(rule));
      statements.push(parts.join(' '));
    }
  }

  for (const table of plan.tables) {
    const columns = table.columns.map((column) => {
      // The type is rewritten like everything else now that the copy has its
      // own. Left alone, the copy leaned on the original for them.
      const parts = [quote(column.name), rewriteSchemaRefs(column.type, plan.schema, target)];
      const fallback = rewriteSchemaRefs(column.default_expr, plan.schema, target);
      if (column.generated) {
        // A stored generated column carries its expression in default_expr, and
        // replaying that as a DEFAULT is a syntax error - "cannot use column
        // reference in DEFAULT expression" - which took the whole scan down.
        parts.push('GENERATED ALWAYS AS (' + fallback + ') STORED');
      } else if (column.identity) {
        parts.push('GENERATED ALWAYS AS IDENTITY');
      } else if (fallback) {
        parts.push('DEFAULT ' + fallback);
      }
      if (column.not_null && !column.generated && !column.identity) parts.push('NOT NULL');
      return parts.join(' ');
    });

    // Sequences first, or a serial column's default has nothing to point at.
    for (const column of table.columns) {
      const match = /nextval\('([^']+)'/.exec(column.default_expr || '');
      if (!match) continue;
      const bare = match[1].split('.').pop().split('"').join('');
      statements.push('CREATE SEQUENCE IF NOT EXISTS ' + quote(target) + '.' + quote(bare));
    }

    statements.push(
      'CREATE TABLE ' + quote(target) + '.' + quote(table.name) + ' (' + columns.join(', ') + ')',
    );

    // And the sequence belongs to its column, the way serial makes it.
    //
    // Not tidiness. A sequence a column owns is linked to it in pg_depend,
    // and that link is how the grants on it are found again - so a copy
    // whose sequences stand loose reads back as having no sequence grants
    // at all, however many were replayed onto it. It also means the
    // sequence goes when the copy's table goes, which is what the original
    // does.
    for (const column of table.columns) {
      const match = /nextval\('([^']+)'/.exec(column.default_expr || '');
      if (!match) continue;
      const bare = match[1].split('.').pop().split('"').join('');
      statements.push(
        'ALTER SEQUENCE ' + quote(target) + '.' + quote(bare) + ' OWNED BY ' +
          quote(target) + '.' + quote(table.name) + '.' + quote(column.name),
      );
    }
  }

  // Stand-ins for the tables outside this schema that its foreign keys point
  // at, with two rows already in them so seeding has something to reference.
  // Built before the constraints, because a foreign key cannot be added to a
  // table that is not there yet.
  for (const outside of plan.external || []) {
    const stub = quote(target) + '.' + quote(outside.stub);
    const columns = outside.columns.map((column) => quote(column.name) + ' ' + column.type + ' NOT NULL');
    const keyed = outside.columns.map((column) => quote(column.name)).join(', ');
    statements.push('CREATE TABLE ' + stub + ' (' + columns.join(', ') + ', PRIMARY KEY (' + keyed + '))');
    for (let nth = 0; nth < IDENTITIES.length; nth++) {
      const values = outside.columns.map((column) => stubValue(column.type, nth));
      statements.push('INSERT INTO ' + stub + ' VALUES (' + values.join(', ') + ')');
    }
  }

  // Keys and uniques across every table first, then the foreign keys.
  // Constraints used to be added table by table, so a foreign key on `orders`
  // was created before the primary key on `profiles` existed and Postgres
  // refused it: "no unique constraint matching given keys". A foreign key can
  // only be added once the thing it points at is already unique.
  for (const wantForeign of [false, true]) {
    for (const table of plan.tables) {
      for (const constraint of table.constraints) {
        const isForeign = constraint.kind === 'f';
        if (isForeign !== wantForeign) continue;
        const definition = qualifyOwnRefs(
          rewriteExternalRefs(
            rewriteSchemaRefs(constraint.definition, plan.schema, target),
            plan.external,
            target,
          ),
          plan,
          target,
        );
        statements.push(
          'ALTER TABLE ' + quote(target) + '.' + quote(table.name) +
            ' ADD CONSTRAINT ' + quote(constraint.name) + ' ' + definition,
        );
      }
    }
  }

  // Unique indexes, once every table exists. The schema name inside the
  // definition is rewritten for the same reason a foreign key's was: Postgres
  // writes it unquoted, and every single index definition carries it. Replayed
  // as-is, the copy would build its indexes on the customer's real tables.
  for (const index of plan.indexes || []) {
    statements.push(rewriteSchemaRefs(index.definition, plan.schema, target));
  }

  // The helpers the rules and views call, after the tables their bodies read
  // and before anything that calls them.
  const copied = functionsToCopy(plan);
  const copiedNames = Array.from(new Set(copied.map((f) => f.name)));
  // The app's own types move with them: a copied helper taking app.role_t[]
  // has to take the copy's role_t, or the copy's columns cannot be compared
  // with its arguments.
  const movedNames = copiedNames.concat((plan.types || []).map((t) => t.name));
  for (const fn of copied) {
    statements.push(copyFunctionStatement(fn, plan, target, movedNames));
    // Who may call it, as in the original. Found by the blocked-read check: a
    // helper the original had closed to anon and authenticated came out of
    // the copy open to everyone, and a rule that cannot be evaluated was
    // reported as evaluated.
    if (!fn.default_acl) {
      const signature = quote(target) + '.' + quote(fn.name) + '(' + rewriteOwnTableRefs(fn.args, plan, target, movedNames) + ')';
      statements.push('REVOKE ALL ON FUNCTION ' + signature + ' FROM PUBLIC');
      for (const who of fn.executors || []) {
        statements.push('GRANT EXECUTE ON FUNCTION ' + signature + ' TO ' + (who === 'PUBLIC' ? 'PUBLIC' : quote(who)));
      }
    }
  }

  // Views last, because they read from the tables above. Copied rather than
  // skipped because a view is a way into a table: it runs with its creator
  // rights unless it says security_invoker, so a view over a protected table
  // hands out every row in it. Leaving views out meant never looking at that
  // door at all.
  for (const view of plan.views || []) {
    const body = rewriteExternalRefs(rewriteSchemaRefs(view.definition, plan.schema, target), plan.external, target);
    const options = view.options ? ' WITH (' + view.options + ')' : '';
    statements.push(
      'CREATE ' + (view.materialised ? 'MATERIALIZED VIEW ' : 'VIEW ') +
        quote(target) + '.' + quote(view.name) + options + ' AS ' + body,
    );
  }

  for (const grant of plan.viewGrants || []) {
    const who = grant.grantee === 'PUBLIC' ? 'PUBLIC' : quote(grant.grantee);
    statements.push(
      'GRANT ' + grant.privilege_type + ' ON ' + quote(target) + '.' + quote(grant.table_name) + ' TO ' + who,
    );
  }

  // The copy needs the roles PostgREST switches into to be able to reach it.
  // Granted on the copy's own schema and nowhere else.
  //
  // What used to be here, and must never come back: CREATE SCHEMA auth,
  // CREATE OR REPLACE FUNCTION auth.uid(), and GRANT USAGE ON SCHEMA auth.
  // Those ran against the customer's live database. The first overwrote their
  // own authentication function; the third opened a schema they may have
  // deliberately closed. The policies reference auth.uid() and that is fine -
  // calling their function is a read, and a read is all we are ever allowed.
  // If it is missing, their app does not work either, and the copy failing to
  // build says so honestly instead of papering over it.
  for (const role of await existingRoles(client, ['anon', 'authenticated'])) {
    statements.push('GRANT USAGE ON SCHEMA ' + quote(target) + ' TO ' + quote(role));
  }

  for (const grant of plan.grants) {
    const who = grant.grantee === 'PUBLIC' ? 'PUBLIC' : quote(grant.grantee);
    statements.push(
      'GRANT ' + grant.privilege_type + ' ON ' + quote(target) + '.' + quote(grant.table_name) + ' TO ' + who,
    );
  }

  // The sequences, on the same terms as the tables. A table grant without
  // the sequence grant that goes with it is a copy nobody can insert into.
  for (const grant of plan.sequenceGrants || []) {
    const who = grant.grantee === 'PUBLIC' ? 'PUBLIC' : quote(grant.grantee);
    statements.push(
      'GRANT ' + grant.privilege_type + ' ON SEQUENCE ' + quote(target) + '.' +
        quote(grant.sequence_name) + ' TO ' + who,
    );
  }

  for (const table of plan.tables) {
    if (table.rlsEnabled) {
      statements.push('ALTER TABLE ' + quote(target) + '.' + quote(table.name) + ' ENABLE ROW LEVEL SECURITY');
    }
    if (table.rlsForced) {
      statements.push('ALTER TABLE ' + quote(target) + '.' + quote(table.name) + ' FORCE ROW LEVEL SECURITY');
    }
  }

  for (const policy of plan.policies) {
    const roles = roleList(policy.roles).join(', ') || 'PUBLIC';
    const parts = [
      'CREATE POLICY ' + quote(policy.name),
      'ON ' + quote(target) + '.' + quote(policy.table_name),
      'AS ' + (policy.permissive === 'PERMISSIVE' ? 'PERMISSIVE' : 'RESTRICTIVE'),
      'FOR ' + policy.cmd,
      'TO ' + roles,
    ];
    if (policy.qual) parts.push('USING (' + rewriteOwnTableRefs(policy.qual, plan, target, movedNames) + ')');
    if (policy.with_check) parts.push('WITH CHECK (' + rewriteOwnTableRefs(policy.with_check, plan, target, movedNames) + ')');
    statements.push(parts.join(' '));
  }

  mustStayInside(statements, target);
  // Built with the copy first on the search_path, so a bare name binds to the
  // copy and not to whatever the customer happens to have.
  //
  // This is the structural half, and it went in after chasing the same bug
  // through three different kinds of expression. Postgres writes a name
  // without its schema whenever that name is already reachable - so a real app
  // in `public` hands back "REFERENCES profiles(id)" and
  // "nextval('orders_id_seq'::regclass)", and a rewrite that goes looking for
  // a schema name finds nothing to change in either. Replayed into the copy,
  // both bound to the customer's own objects: the foreign keys pointed at
  // their tables, and the copy drew its keys from their sequences, which
  // advanced them.
  //
  // Rewriting each kind of expression in turn is a game with no end - index
  // predicates, checks that call a function, view bodies. Naming the copy
  // first on the path ends all of them at once, because it changes what a
  // bare name means rather than trying to find every place one can appear.
  //
  // `public` stays on the path, after the copy, because the copy legitimately
  // needs what lives there - gen_random_uuid() and the like. `extensions` is
  // where Supabase keeps them; a schema on the path that does not exist is
  // ignored rather than an error.
  const { rows: pathRows } = await client.query('SHOW search_path');
  const restoreTo = pathRows[0].search_path;
  await client.query('SET search_path TO ' + quote(target) + ', public, extensions');
  try {
    for (const statement of statements) {
      await client.query(statement);
    }
  } finally {
    await client.query('SET search_path TO ' + restoreTo).catch(() => {});
  }

  // And then look at what was actually built, rather than at what was meant.
  //
  // Everything above this line reasons about strings. The guard at the top of
  // this file reads the statements before they run; this one asks Postgres
  // where the copy ended up pointing, which is the only account of it that
  // cannot be fooled by a spelling nobody anticipated - and one was not. A
  // bare "REFERENCES profiles(id)" replayed into the copy bound to the
  // customer's own table, silently, on every app that lives in `public`.
  //
  // Nothing is written to a table outside the copy either way. The damage is
  // subtler than that: a copy tied to the customer's rows is not the app being
  // attacked, and every verdict taken from it is about something else.
  // Foreign keys AND column defaults, because the second one is where this
  // hid after the first was closed: a serial column's default is
  // nextval('<sequence>'), and the copy was calling the customer's. Nothing
  // was written to their tables, but nextval advances a sequence, so their
  // database changed - and "we never touch your live app" says at all.
  //
  // Asked of pg_depend rather than of the text, so it holds for any
  // expression that ends up pointing at a relation, not only the ones anybody
  // thought to look at. pg_catalog is excluded because everything depends on
  // it; anything else outside the copy is the bug.
  const { rows: strays } = await client.query(
    `SELECT con.conname AS what, rn.nspname AS points_at
       FROM pg_constraint con
       JOIN pg_class cl ON cl.oid = con.conrelid
       JOIN pg_namespace cn ON cn.oid = cl.relnamespace
       JOIN pg_class rc ON rc.oid = con.confrelid
       JOIN pg_namespace rn ON rn.oid = rc.relnamespace
      WHERE con.contype = 'f' AND cn.nspname = $1 AND rn.nspname <> $1
      UNION ALL
     SELECT cl.relname || '.' || a.attname || ' default' AS what,
            rn.nspname || '.' || rc.relname AS points_at
       FROM pg_depend d
       JOIN pg_attrdef ad ON ad.oid = d.objid AND d.classid = 'pg_attrdef'::regclass
       JOIN pg_class cl ON cl.oid = ad.adrelid
       JOIN pg_namespace cn ON cn.oid = cl.relnamespace
       JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
       JOIN pg_class rc ON rc.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass
       JOIN pg_namespace rn ON rn.oid = rc.relnamespace
      WHERE cn.nspname = $1 AND rn.nspname <> $1 AND rn.nspname <> 'pg_catalog'
      UNION ALL
     -- And the rules. A policy that reads another table - "items of my
     -- orders" - has to read the copy's orders; one reading the customer's
     -- would evaluate the attack against their real rows. The text comparison
     -- further down never caught this for an app in public: a reference to
     -- public.orders prints as plain "orders" either way. Postgres records
     -- every relation a policy expression uses, so ask it.
     SELECT pol.polname || ' rule on ' || cl.relname AS what,
            rn.nspname || '.' || rc.relname AS points_at
       FROM pg_depend d
       JOIN pg_policy pol ON pol.oid = d.objid AND d.classid = 'pg_policy'::regclass
       JOIN pg_class cl ON cl.oid = pol.polrelid
       JOIN pg_namespace cn ON cn.oid = cl.relnamespace
       JOIN pg_class rc ON rc.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass
       JOIN pg_namespace rn ON rn.oid = rc.relnamespace
      WHERE cn.nspname = $1 AND rn.nspname <> $1 AND rn.nspname <> 'pg_catalog'`,
    [target],
  );
  if (strays.length) {
    throw new Error(
      'the copy points outside itself, so it is not the app: ' +
        strays.map((row) => row.what + ' -> ' + row.points_at).join(', '),
    );
  }

  return statements;
}

/* --------------------------------------------------------------------------
   Checking the copy is the original.
-------------------------------------------------------------------------- */

/** A piece of SQL with its own schema name taken off, quoted or not. */
function withoutSchema(text, plan) {
  return String(text == null ? '' : text)
    .split(quote(plan.schema) + '.').join('')
    .split(plan.schema + '.').join('');
}

/**
 * Where a copy differs from what it was copied from.
 *
 * Anything here means the verdicts that follow are about the wrong database,
 * so this returning empty is a precondition for attacking, not a nicety.
 */
function diffSchemas(source, copy) {
  const differences = [];

  // The stand-ins exist only in the copy, by design. Comparing them against
  // an original that never had them would report every Supabase app as a
  // copy that came out wrong.
  const standIns = new Set((source.external || []).map((e) => e.stub));
  const mine = (list) => list.filter((t) => !standIns.has(t.name));
  const named = (list) => mine(list).map((t) => t.name).sort().join(', ');
  if (named(source.tables) !== named(copy.tables)) {
    differences.push('tables differ: ' + named(source.tables) + '  vs  ' + named(copy.tables));
  }

  for (const table of source.tables) {
    const mirror = copy.tables.find((t) => t.name === table.name);
    if (!mirror) continue;

    if (table.rlsEnabled !== mirror.rlsEnabled) {
      differences.push(
        table.name + ': row level security is ' + (table.rlsEnabled ? 'on' : 'off') +
          ' but the copy has it ' + (mirror.rlsEnabled ? 'on' : 'off'),
      );
    }
    if (table.rlsForced !== mirror.rlsForced) {
      differences.push(table.name + ': forced row level security does not match');
    }

    // The schema name comes off the type first. A column of the app's own enum
    // reads as app.order_status in the original and as <copy>.order_status in
    // the copy - the same type, built twice, and calling that a difference
    // would stop every scan of an app that has one.
    const shape = (plan, t) =>
      t.columns.map((c) => c.name + ' ' + withoutSchema(c.type, plan) + (c.not_null ? ' NOT NULL' : '')).join(' | ');
    if (shape(source, table) !== shape(copy, mirror)) {
      differences.push(table.name + ' columns differ:\n      ' + shape(source, table) + '\n      ' + shape(copy, mirror));
    }
  }

  // The app's own types. An enum that arrived with a label missing narrows
  // what the attacks are able to insert, and nothing else here would notice.
  const typeText = (plan) =>
    (plan.types || [])
      .map((made) =>
        made.name + ' ' + made.kind + ' ' + (made.labels || []).join(',') + ' ' +
        withoutSchema(made.base_type, plan) + ' ' +
        (made.constraints || []).map((rule) => withoutSchema(rule, plan)).join(' '))
      .sort();
  const sourceTypes = typeText(source);
  const copyTypes = typeText(copy);
  for (const made of sourceTypes) {
    if (!copyTypes.includes(made)) differences.push('a type did not come across whole: ' + made);
  }

  // The sequence grants, for the same reason they are copied at all: without
  // them nothing can insert, and every write attack reads as the app
  // defending itself.
  const sequenceText = (plan) =>
    (plan.sequenceGrants || [])
      .map((g) => g.sequence_name + ' ' + g.grantee + ' ' + g.privilege_type)
      .sort();
  const sourceSequences = sequenceText(source);
  const copySequences = sequenceText(copy);
  for (const one of sourceSequences) {
    if (!copySequences.includes(one)) {
      differences.push('a sequence grant did not come across: ' + one);
    }
  }

  // Uniqueness decides whether the Collision attack has anything to report, so
  // a unique index that failed to come across has to be caught here rather
  // than turn into a confident finding about a table that was actually fine.
  // The schema name is stripped before comparing, since it differs by design.
  const indexText = (plan) =>
    (plan.indexes || [])
      .map((index) => withoutSchema(index.definition, plan))
      .sort();
  const sourceIndexes = indexText(source);
  const copyIndexes = indexText(copy);
  if (sourceIndexes.length !== copyIndexes.length) {
    differences.push(
      'the copy has ' + copyIndexes.length + ' unique indexes, the original has ' + sourceIndexes.length,
    );
  }
  for (let i = 0; i < Math.max(sourceIndexes.length, copyIndexes.length); i++) {
    if (sourceIndexes[i] !== copyIndexes[i]) {
      differences.push('a unique index came across changed:\n      ' + sourceIndexes[i] + '\n      ' + copyIndexes[i]);
    }
  }

  // The policies matter most, so they are compared word for word - except for
  // the schema names, which differ by design. A rule that looks at another of
  // the app's own tables ("items of my orders": EXISTS (SELECT 1 FROM orders
  // ...)) comes back from the copy naming the copy's orders, kn_xxx.orders,
  // which is exactly right. Compared raw, that read as "the copy came out
  // changed" and the whole app went unscanned - found on a test app built to
  // look like a Lovable shop, where this rule is ordinary. And a rule calling
  // one of the app's functions keeps naming the original schema in both,
  // because functions are not copied - so both names are taken out of both
  // sides. Where a rule actually points - the copy's table or the customer's -
  // is not left to this text: writeSchema asks pg_depend, and refuses a copy
  // whose rules read anything outside it.
  const bothSchemas = (text) => withoutSchema(withoutSchema(text, source), copy);
  const asText = (list) =>
    list
      .map((p) =>
        [p.table_name, p.name, p.permissive, roleList(p.roles).join('+'), p.cmd,
          bothSchemas(p.qual), bothSchemas(p.with_check)]
          .map((x) => String(x === null || x === undefined ? '' : x))
          .join(' :: '),
      )
      .sort();

  const sourcePolicies = asText(source.policies);
  const copyPolicies = asText(copy.policies);
  if (sourcePolicies.length !== copyPolicies.length) {
    differences.push('the copy has ' + copyPolicies.length + ' policies, the original has ' + sourcePolicies.length);
  }
  for (let i = 0; i < Math.max(sourcePolicies.length, copyPolicies.length); i++) {
    if (sourcePolicies[i] !== copyPolicies[i]) {
      differences.push('a policy came across changed:\n      ' + sourcePolicies[i] + '\n      ' + copyPolicies[i]);
    }
  }

  return differences;
}

module.exports = {
  readSchema: readSchema,
  readAnonDefinerFunctions: readAnonDefinerFunctions,
  guardedAtTheDoor: guardedAtTheDoor,
  writeSchema: writeSchema,
  diffSchemas: diffSchemas,
  readPolicies: readPolicies,
  readBuckets: readBuckets,
  readTypes: readTypes,
  readSequenceGrants: readSequenceGrants,
  readIndexes: readIndexes,
  readViews: readViews,
  readExternalTargets: readExternalTargets,
  referenceIn: referenceIn,
  rewriteSchemaRefs: rewriteSchemaRefs,
  qualifyOwnRefs: qualifyOwnRefs,
  functionsToCopy: functionsToCopy,
  copyFunctionStatement: copyFunctionStatement,
  stubNameFor: stubNameFor,
  IDENTITIES: IDENTITIES,
  quote: quote,
  roleList: roleList,
};
