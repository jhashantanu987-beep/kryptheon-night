-- The engine, in SQL.
--
-- The attacks live here rather than in Node so that there is one
-- implementation and two ways to reach it:
--
--   npx        install these functions in a throwaway schema, call them,
--              drop them. The customer's password never leaves their machine.
--   installer  install them permanently, and let pg_cron call them nightly.
--              The customer's password never leaves their database.
--
-- Written once on purpose. A second implementation in another language means
-- every bug has to be fixed twice, and the second copy is where the one you
-- forgot lives. twin.check.js runs both paths over the same fixtures and fails
-- if their answers differ by a single character.
--
-- INSTALLING
--
-- Every occurrence of __KN__ is replaced with the schema these functions are
-- to live in, before this file is run. A token rather than a real name so that
-- the replacement cannot quietly hit a comment or a string that happened to
-- say `kryptheon`.
--
-- NOT SECURITY DEFINER, ANYWHERE
--
-- Measured: Postgres refuses `SET ROLE` inside a security-definer function,
-- and becoming `anon` is the whole attack. So these run with the rights of
-- whoever calls them and have no powers of their own - which is also the
-- honest thing to install in somebody else's database.

CREATE SCHEMA IF NOT EXISTS __KN__;

-- --------------------------------------------------------------------------
-- Reading the shape of an app.
--
-- Every function below mirrors one in schema.js, query for query, so that the
-- two engines cannot drift apart without the twin check noticing.
-- --------------------------------------------------------------------------

/* Every table in a schema, with whether row level security is switched on. */
CREATE OR REPLACE FUNCTION __KN__.read_tables(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(t ORDER BY t->>'name'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'name', c.relname,
               'rlsEnabled', c.relrowsecurity,
               'rlsForced', c.relforcerowsecurity
             ) AS t
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = source AND c.relkind = 'r'
    ) rows;
$$;

/*
 * The columns of one table, as Postgres itself would write them.
 *
 * format_type rather than information_schema, because it gives the type back
 * exactly - numeric(10,2) stays numeric(10,2) - and a column that comes back
 * the wrong width can change what a policy comparison does.
 *
 * enum labels are cast to text[] on purpose: array_agg over enumlabel produces
 * name[], which some drivers hand back as the raw string "{new,paid}", whose
 * first "label" is the character "{".
 */
CREATE OR REPLACE FUNCTION __KN__.read_columns(source text, tab text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(c ORDER BY ord), '[]'::jsonb)
    FROM (
      SELECT a.attnum AS ord,
             jsonb_build_object(
               'name', a.attname,
               'type', format_type(a.atttypid, a.atttypmod),
               'not_null', a.attnotnull,
               'default_expr', pg_get_expr(d.adbin, d.adrelid),
               'generated', nullif(a.attgenerated, ''),
               'identity', a.attidentity <> '',
               'enum_labels', (
                 SELECT to_jsonb(array_agg(e.enumlabel::text ORDER BY e.enumsortorder))
                   FROM pg_enum e WHERE e.enumtypid = t.oid
               ),
               'base_type', CASE WHEN t.typtype = 'd'
                                 THEN format_type(t.typbasetype, a.atttypmod) END,
               'is_array', t.typcategory = 'A'
             ) AS c
        FROM pg_attribute a
        JOIN pg_type t ON t.oid = a.atttypid
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
       WHERE a.attrelid = format('%I.%I', source, tab)::regclass
         AND a.attnum > 0
         AND NOT a.attisdropped
    ) rows;
$$;

/* Primary keys, uniques, checks and foreign keys, in Postgres's own words. */
CREATE OR REPLACE FUNCTION __KN__.read_constraints(source text, tab text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(c ORDER BY c->>'name'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'name', con.conname,
               'definition', pg_get_constraintdef(con.oid),
               'kind', con.contype
             ) AS c
        FROM pg_constraint con
       WHERE con.conrelid = format('%I.%I', source, tab)::regclass
    ) rows;
$$;

/*
 * Unique indexes, which are the other half of "can this happen twice".
 *
 * Primary keys and indexes backing a constraint are left out: those come along
 * with the constraint itself, and creating them again is an error.
 */
CREATE OR REPLACE FUNCTION __KN__.read_indexes(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(i ORDER BY i->>'table_name', i->>'name'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'name', c.relname,
               'table_name', t.relname,
               'definition', pg_get_indexdef(i.indexrelid)
             ) AS i
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = source
         AND i.indisunique
         AND NOT i.indisprimary
         AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = i.indexrelid)
    ) rows;
$$;

/*
 * The policies. These are the thing under test, so they are read verbatim.
 *
 * pg_policies hands back qual and with_check already rendered as SQL, which is
 * what makes an exact copy possible at all. roles comes back as name[], so it
 * is cast to text[] before going into JSON for the same reason enum labels are.
 */
CREATE OR REPLACE FUNCTION __KN__.read_policies(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(p ORDER BY p->>'table_name', p->>'name'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'table_name', tablename,
               'name', policyname,
               'permissive', permissive,
               'roles', to_jsonb(roles::text[]),
               'cmd', cmd,
               'qual', qual,
               'with_check', with_check
             ) AS p
        FROM pg_policies
       WHERE schemaname = source
    ) rows;
$$;

/*
 * Who was granted what. A policy is irrelevant if the grant is not there.
 *
 * Ordinary tables only. role_table_grants also lists views, and replaying a
 * grant on a view the copy does not contain fails outright - which took down
 * the scan of any app with a view in it.
 */
CREATE OR REPLACE FUNCTION __KN__.read_grants(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(g ORDER BY g->>'table_name', g->>'grantee', g->>'privilege_type'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'table_name', gr.table_name,
               'grantee', gr.grantee,
               'privilege_type', gr.privilege_type
             ) AS g
        FROM information_schema.role_table_grants gr
        JOIN pg_class c ON c.relname = gr.table_name
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = gr.table_schema
       WHERE gr.table_schema = source
         AND c.relkind = 'r'
         AND gr.grantee IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
    ) rows;
$$;

/*
 * Views, which are a door of their own.
 *
 * A view runs with its creator's rights unless it says otherwise, so one over
 * a table that row level security protects hands out every row in that table.
 * security_invoker is what turns that off and it lives in reloptions, so it
 * travels with the view.
 */
CREATE OR REPLACE FUNCTION __KN__.read_views(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(v ORDER BY v->>'name'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'name', c.relname,
               'definition', pg_get_viewdef(c.oid, true),
               'materialised', c.relkind = 'm',
               'options', array_to_string(c.reloptions, ', '),
               'columns', __KN__.read_columns(source, c.relname)
             ) AS v
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = source AND c.relkind IN ('v', 'm')
    ) rows;
$$;

/*
 * Who was granted what on the sequences a table depends on.
 *
 * Without these the copy is not the app, in the one way that matters most.
 * Supabase grants anon USAGE on every sequence in public, so a stranger can
 * insert into a table whose key is a serial. The copy replayed the table
 * grants and not the sequence ones, so every insert the tampering attack
 * tried came back 'permission denied for sequence' - which reads as the
 * attack being beaten. "A stranger can add rows to your table" was never
 * reported on any table with a serial key, which is most tables.
 *
 * Only sequences a column owns. Those are the ones the copy has - measured,
 * not assumed. A sequence standing on its own does not come across, and
 * nothing inserts into one, so a grant on it changes no verdict.
 */
CREATE OR REPLACE FUNCTION __KN__.read_sequence_grants(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(g ORDER BY g->>'sequence_name', g->>'grantee', g->>'privilege_type'),
                  '[]'::jsonb)
    FROM (
      SELECT DISTINCT jsonb_build_object(
               'sequence_name', s.relname,
               'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,
               'privilege_type', a.privilege_type
             ) AS g
        FROM pg_class s
        JOIN pg_namespace n ON n.oid = s.relnamespace
        JOIN pg_depend d ON d.objid = s.oid
                        AND d.classid = 'pg_class'::regclass
                        AND d.deptype IN ('a', 'i')
        CROSS JOIN LATERAL aclexplode(s.relacl) a
       WHERE n.nspname = source AND s.relkind = 'S'
         AND (CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
             IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
    ) rows;
$$;

/* The grants on views. Separate, because views are created after the tables. */
CREATE OR REPLACE FUNCTION __KN__.read_view_grants(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(g ORDER BY g->>'table_name', g->>'grantee', g->>'privilege_type'), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'table_name', gr.table_name,
               'grantee', gr.grantee,
               'privilege_type', gr.privilege_type
             ) AS g
        FROM information_schema.role_table_grants gr
        JOIN pg_class c ON c.relname = gr.table_name
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = gr.table_schema
       WHERE gr.table_schema = source
         AND c.relkind IN ('v', 'm')
         AND gr.grantee IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
    ) rows;
$$;

/*
 * The app's own enums and domains.
 *
 * Copied, so that the copy stands on its own. Borrowing them from the schema
 * it was copied from worked right up until a view mentioned one:
 * pg_get_viewdef writes a literal as 'paid'::app.order_status, the rewrite
 * turned app into the copy, and the copy had no such type. Any app with a
 * view over an enum column crashed the scan outright.
 *
 * Enums are listed first. A domain can be built on one, and a domain created
 * before the enum it stands on is a type that does not exist yet.
 */
CREATE OR REPLACE FUNCTION __KN__.read_types(source text)
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(entry ORDER BY sort_first, name), '[]'::jsonb)
    FROM (
      SELECT CASE WHEN t.typtype = 'e' THEN 0 ELSE 1 END AS sort_first,
             t.typname AS name,
             jsonb_build_object(
               'name', t.typname,
               'kind', t.typtype,
               'labels', CASE WHEN t.typtype = 'e' THEN to_jsonb((
                 SELECT array_agg(e.enumlabel::text ORDER BY e.enumsortorder)
                   FROM pg_enum e WHERE e.enumtypid = t.oid
               )) END,
               'base_type', CASE WHEN t.typtype = 'd'
                                 THEN format_type(t.typbasetype, t.typtypmod) END,
               'constraints', CASE WHEN t.typtype = 'd' THEN to_jsonb((
                 SELECT array_agg(pg_get_constraintdef(c.oid) ORDER BY c.conname)
                   FROM pg_constraint c WHERE c.contypid = t.oid
               )) END,
               'not_null', t.typnotnull,
               'default_value', CASE WHEN t.typtype = 'd' THEN t.typdefault END
             ) AS entry
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
       WHERE n.nspname = source
         AND t.typtype IN ('e', 'd')
    ) rows;
$$;

/* Everything needed to rebuild a schema, in one shape. */
CREATE OR REPLACE FUNCTION __KN__.read_schema(source text)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
  tables jsonb := '[]'::jsonb;
  one jsonb;
BEGIN
  FOR one IN SELECT * FROM jsonb_array_elements(__KN__.read_tables(source)) LOOP
    tables := tables || jsonb_build_array(
      one
      || jsonb_build_object('columns', __KN__.read_columns(source, one->>'name'))
      || jsonb_build_object('constraints', __KN__.read_constraints(source, one->>'name'))
    );
  END LOOP;

  RETURN jsonb_build_object(
    'schema', source,
    'tables', tables,
    'external', __KN__.read_external(source, tables),
    'policies', __KN__.read_policies(source),
    'grants', __KN__.read_grants(source),
    'sequenceGrants', __KN__.read_sequence_grants(source),
    'types', __KN__.read_types(source),
    'indexes', __KN__.read_indexes(source),
    'views', __KN__.read_views(source),
    'viewGrants', __KN__.read_view_grants(source),
    -- A foreign key pointing at something whose shape could not be read is
    -- not something to guess at. The caller stops rather than attacking a
    -- copy that is missing a piece.
    'unsupported', (
      SELECT coalesce(jsonb_agg(
               'a foreign key points at ' || (e->>'schema') || '.' || (e->>'table') ||
               ', and I could not read its shape to stand in for it'
             ), '[]'::jsonb)
        FROM jsonb_array_elements(__KN__.read_external(source, tables)) e
       WHERE jsonb_array_length(e->'columns') <> jsonb_array_length(e->'wanted')
    )
  );
END $$;
-- --------------------------------------------------------------------------
-- Slice 2: reading what the schema points at, and building the copy.
--
-- Appended to engine.sql. Mirrors readExternalTargets and writeSchema in
-- schema.js, statement for statement, because twin.check.js compares the two
-- copies afterwards and any drift shows up as a difference nobody can explain.
-- --------------------------------------------------------------------------

/* What a foreign key points at, pulled out of Postgres's own wording. */
CREATE OR REPLACE FUNCTION __KN__.reference_in(definition text)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  hit text[];
  target text;
  parts text[];
BEGIN
  hit := regexp_match(definition, 'FOREIGN KEY\s*\(([^)]+)\)\s*REFERENCES\s+([^\s(]+)\s*\(([^)]+)\)', 'i');
  IF hit IS NULL THEN RETURN NULL; END IF;

  target := btrim(hit[2]);
  -- Split on a dot that is not inside quotes, the same way the Node side does.
  parts := regexp_split_to_array(target, '\.(?=(?:[^"]*"[^"]*")*[^"]*$)');

  RETURN jsonb_build_object(
    'schema', CASE WHEN array_length(parts, 1) > 1 THEN btrim(parts[1], '"') END,
    'table', btrim(parts[array_length(parts, 1)], '"'),
    'columns', (SELECT to_jsonb(array_agg(btrim(btrim(x), '"')))
                  FROM unnest(string_to_array(hit[3], ',')) x)
  );
END $$;

/*
 * The name a stand-in for an outside table is given inside the copy.
 *
 * It keeps moving until it clashes with nothing the customer already has.
 * Identifying our own tables by their prefix alone meant a customer table that
 * happened to start the same way was silently dropped from every attack.
 */
CREATE OR REPLACE FUNCTION __KN__.stub_name_for(ref_schema text, ref_table text, taken jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  base text := 'kn_ext__' || ref_schema || '__' || ref_table;
  name text := base;
  nth integer := 2;
BEGIN
  WHILE taken ? name LOOP
    name := base || '__' || nth;
    nth := nth + 1;
  END LOOP;
  RETURN name;
END $$;

/*
 * Tables outside this schema that its foreign keys point at.
 *
 * Nearly every Supabase app has `references auth.users(id)`, and the copy
 * cannot carry that as written: pointed at the real auth.users, every seeded
 * row becomes a write into the customer's own authentication table. So the
 * shape of the outside table is read - columns and types, never rows - and a
 * stand-in is built inside the copy instead.
 */
CREATE OR REPLACE FUNCTION __KN__.read_external(source text, tables jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
  tab jsonb;
  con jsonb;
  points jsonb;
  key text;
  wanted jsonb := '{}'::jsonb;
  entry jsonb;
  out jsonb := '[]'::jsonb;
  names jsonb := '{}'::jsonb;
  cols jsonb;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(tables) LOOP
    names := names || jsonb_build_object(tab->>'name', true);
    FOR con IN SELECT * FROM jsonb_array_elements(tab->'constraints') LOOP
      CONTINUE WHEN con->>'kind' <> 'f';
      points := __KN__.reference_in(con->>'definition');
      CONTINUE WHEN points IS NULL
                 OR points->>'schema' IS NULL
                 OR points->>'schema' = source;
      key := (points->>'schema') || '.' || (points->>'table');
      IF NOT (wanted ? key) THEN
        wanted := wanted || jsonb_build_object(key, jsonb_build_object(
          'schema', points->'schema', 'table', points->'table', 'columns', '[]'::jsonb));
      END IF;
      wanted := jsonb_set(wanted, ARRAY[key, 'columns'],
        (SELECT to_jsonb(array_agg(DISTINCT c))
           FROM (SELECT jsonb_array_elements_text(wanted->key->'columns') AS c
                 UNION SELECT jsonb_array_elements_text(points->'columns')) u));
    END LOOP;
  END LOOP;

  FOR entry IN SELECT value FROM jsonb_each(wanted) LOOP
    SELECT coalesce(jsonb_agg(jsonb_build_object('name', a.attname,
                                                 'type', format_type(a.atttypid, a.atttypmod))
                              ORDER BY a.attnum), '[]'::jsonb)
      INTO cols
      FROM pg_attribute a
     WHERE a.attrelid = format('%I.%I', entry->>'schema', entry->>'table')::regclass
       AND a.attname = ANY (SELECT jsonb_array_elements_text(entry->'columns'))
       AND a.attnum > 0 AND NOT a.attisdropped;

    out := out || jsonb_build_array(jsonb_build_object(
      'schema', entry->'schema',
      'table', entry->'table',
      'columns', cols,
      'stub', __KN__.stub_name_for(entry->>'schema', entry->>'table', names),
      'wanted', entry->'columns'
    ));
  END LOOP;

  RETURN out;
EXCEPTION WHEN OTHERS THEN
  -- A target whose shape cannot be read at all comes back with no columns, and
  -- the caller treats that as unsupported rather than guessing at it.
  RETURN out;
END $$;

/*
 * A name in double quotes, always.
 *
 * NOT quote_ident, which only quotes when it has to: quote_ident('app') is
 * app, so a rewrite built on it went looking for app. and walked straight
 * past "app". - and the copy kept a live reference into the customer real
 * schema, which is the most dangerous bug this product has had. The Node
 * side always quotes, so this does too, and the twin check is what noticed
 * they had stopped agreeing.
 */
CREATE OR REPLACE FUNCTION __KN__.always_quote(name text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT '"' || replace(name, '"', '""') || '"';
$$;

/*
 * Points anything schema-qualified at the copy instead of the original.
 *
 * Both spellings, and that is the whole point of this existing. Postgres
 * writes a name unquoted when it does not need quoting, so a foreign key came
 * back as "REFERENCES app.profiles(id)" while only the quoted form was being
 * rewritten - and the copy was created holding a live reference into the
 * customer's real schema.
 */
CREATE OR REPLACE FUNCTION __KN__.rewrite_schema_refs(expr text, from_schema text, to_schema text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN expr IS NULL THEN NULL ELSE
    replace(
      replace(expr, __KN__.always_quote(from_schema) || '.', __KN__.always_quote(to_schema) || '.'),
      from_schema || '.', to_schema || '.')
  END;
$$;

/* Points a foreign key at the stand-in instead of at the real outside table. */
CREATE OR REPLACE FUNCTION __KN__.rewrite_external_refs(expr text, external jsonb, to_schema text)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  out text := expr;
  target jsonb;
  stub text;
BEGIN
  IF expr IS NULL THEN RETURN NULL; END IF;
  FOR target IN SELECT * FROM jsonb_array_elements(external) LOOP
    stub := __KN__.always_quote(to_schema) || '.' || __KN__.always_quote(target->>'stub');
    out := replace(out, __KN__.always_quote(target->>'schema') || '.' || __KN__.always_quote(target->>'table'), stub);
    out := replace(out, (target->>'schema') || '.' || (target->>'table'), stub);
  END LOOP;
  RETURN out;
END $$;

/* Two people who do not exist, used wherever a stand-in row is needed. */
CREATE OR REPLACE FUNCTION __KN__.identities() RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
  SELECT ARRAY['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];
$$;

/* Something of the right type to put in a stand-in row. */
CREATE OR REPLACE FUNCTION __KN__.stub_value(kind text, nth integer)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k text := lower(kind);
BEGIN
  IF k = 'uuid' THEN RETURN quote_literal((__KN__.identities())[nth + 1]); END IF;
  IF k ~ '^(integer|bigint|smallint|numeric|decimal|real|double)' THEN RETURN (nth + 1)::text; END IF;
  IF k ~ '^bool' THEN RETURN CASE WHEN nth = 0 THEN 'true' ELSE 'false' END; END IF;
  IF k ~ '^(timestamp|date)' THEN RETURN 'now()'; END IF;
  RETURN quote_literal('kryptheon-' || (nth + 1));
END $$;

/*
 * Nothing may be written outside the copy. Ever.
 *
 * The product is sold on one sentence - we never touch your live app - and
 * this is the line that keeps it true. A structural guard rather than a
 * careful habit, because the two statements that broke the promise were
 * written carefully and sat there for weeks.
 */
CREATE OR REPLACE FUNCTION __KN__.must_stay_inside(statements jsonb, target text)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE s text;
BEGIN
  FOR s IN SELECT jsonb_array_elements_text(statements) LOOP
    IF position(__KN__.always_quote(target) in s) > 0 THEN CONTINUE; END IF;
    IF s ~ ('(^|[^A-Za-z0-9_"])' || target || '\.') THEN CONTINUE; END IF;
    RAISE EXCEPTION 'refusing to run a statement that does not stay inside the copy %: %', target, s;
  END LOOP;
  RETURN statements;
END $$;

/* Which of these roles this database actually has. */
CREATE OR REPLACE FUNCTION __KN__.existing_roles(wanted text[])
RETURNS text[] LANGUAGE sql STABLE AS $$
  SELECT coalesce(array_agg(rolname ORDER BY rolname), ARRAY[]::text[])
    FROM pg_roles WHERE rolname = ANY (wanted);
$$;

-- --------------------------------------------------------------------------
-- Building the copy.
--
-- Mirrors writeSchema in schema.js statement for statement. The order is not
-- a preference: a policy cannot be created before the table it guards, a
-- foreign key cannot be added before the key it points at exists, and a grant
-- given after a policy would widen access the original never had.
-- --------------------------------------------------------------------------

/* One column, written the way CREATE TABLE wants it. */
CREATE OR REPLACE FUNCTION __KN__.column_definition(col jsonb, source text, target text, external jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  -- The type is rewritten like everything else, now that the copy has its
  -- own. Left alone, the copy leaned on the original for them.
  parts text := __KN__.always_quote(col->>'name') || ' '
                || __KN__.rewrite_schema_refs(col->>'type', source, target);
  fallback text := __KN__.rewrite_external_refs(
    __KN__.rewrite_schema_refs(col->>'default_expr', source, target), external, target);
BEGIN
  IF col->>'generated' IS NOT NULL THEN
    -- A stored generated column carries its expression in default_expr, and
    -- replaying that as a DEFAULT is a syntax error - "cannot use column
    -- reference in DEFAULT expression" - which took the whole copy down.
    parts := parts || ' GENERATED ALWAYS AS (' || fallback || ') STORED';
  ELSIF (col->>'identity')::boolean THEN
    parts := parts || ' GENERATED ALWAYS AS IDENTITY';
  ELSIF fallback IS NOT NULL THEN
    parts := parts || ' DEFAULT ' || fallback;
  END IF;

  IF (col->>'not_null')::boolean
     AND col->>'generated' IS NULL
     AND NOT (col->>'identity')::boolean THEN
    parts := parts || ' NOT NULL';
  END IF;

  RETURN parts;
END $$;

/*
 * Every statement that rebuilds one schema as another.
 *
 * Returned rather than run, so that the guard can look at all of them before
 * a single one touches the database, and so that a test can read what would
 * have happened without anything happening.
 */
CREATE OR REPLACE FUNCTION __KN__.copy_statements(plan jsonb, target text)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
  source text := plan->>'schema';
  external jsonb := coalesce(plan->'external', '[]'::jsonb);
  out text[] := ARRAY[]::text[];
  tab jsonb;
  col jsonb;
  con jsonb;
  idx jsonb;
  view_ jsonb;
  grant_ jsonb;
  pol jsonb;
  stub jsonb;
  made jsonb;
  cols text[];
  bare text;
  want_foreign boolean;
  role_ text;
  nth integer;
  values_ text[];
  here text := __KN__.always_quote(target);
BEGIN
  out := out || ('CREATE SCHEMA ' || here);

  -- The app's own types first: a column, a check, a view or a cast can all
  -- name one, and nothing that mentions a type can be created before it.
  FOR made IN SELECT * FROM jsonb_array_elements(coalesce(plan->'types', '[]'::jsonb)) LOOP
    IF made->>'kind' = 'e' THEN
      out := out || ('CREATE TYPE ' || here || '.' || __KN__.always_quote(made->>'name')
        || ' AS ENUM (' || coalesce((SELECT string_agg(
                                       '''' || replace(label, '''', '''''') || '''', ', ' ORDER BY at)
                                       FROM jsonb_array_elements_text(
                                              CASE WHEN jsonb_typeof(made->'labels') = 'array'
                                                   THEN made->'labels' ELSE '[]'::jsonb END)
                                              WITH ORDINALITY AS l(label, at)), '') || ')');
    ELSE
      out := out || (('CREATE DOMAIN ' || here || '.' || __KN__.always_quote(made->>'name')
        || ' AS ' || __KN__.rewrite_schema_refs(made->>'base_type', source, target))
        || coalesce(' DEFAULT ' || __KN__.rewrite_schema_refs(made->>'default_value', source, target), '')
        || CASE WHEN (made->>'not_null')::boolean THEN ' NOT NULL' ELSE '' END
        || coalesce((SELECT string_agg(' ' || __KN__.rewrite_schema_refs(rule, source, target), '' ORDER BY at)
                       FROM jsonb_array_elements_text(
                              CASE WHEN jsonb_typeof(made->'constraints') = 'array'
                                   THEN made->'constraints' ELSE '[]'::jsonb END)
                              WITH ORDINALITY AS r(rule, at)), ''));
    END IF;
  END LOOP;

  FOR tab IN SELECT * FROM jsonb_array_elements(plan->'tables') LOOP
    -- Sequences first, or a serial column's default has nothing to point at.
    FOR col IN SELECT * FROM jsonb_array_elements(tab->'columns') LOOP
      CONTINUE WHEN col->>'default_expr' IS NULL;
      bare := (regexp_match(col->>'default_expr', 'nextval\(''([^'']+)'''))[1];
      CONTINUE WHEN bare IS NULL;
      bare := replace(split_part(bare, '.', greatest(array_length(string_to_array(bare, '.'), 1), 1)), '"', '');
      out := out || ('CREATE SEQUENCE IF NOT EXISTS ' || here || '.' || __KN__.always_quote(bare));
    END LOOP;

    cols := ARRAY[]::text[];
    FOR col IN SELECT * FROM jsonb_array_elements(tab->'columns') LOOP
      cols := cols || __KN__.column_definition(col, source, target, external);
    END LOOP;
    out := out || ('CREATE TABLE ' || here || '.' || __KN__.always_quote(tab->>'name')
                   || ' (' || array_to_string(cols, ', ') || ')');

    -- And the sequence belongs to its column, the way serial makes it.
    --
    -- Not tidiness. A sequence a column owns is linked to it in pg_depend,
    -- and that link is how the grants on it are found again - so a copy
    -- whose sequences stand loose reads back as having no sequence grants
    -- at all, however many were replayed onto it.
    FOR col IN SELECT * FROM jsonb_array_elements(tab->'columns') LOOP
      CONTINUE WHEN col->>'default_expr' IS NULL;
      bare := (regexp_match(col->>'default_expr', 'nextval\(''([^'']+)'''))[1];
      CONTINUE WHEN bare IS NULL;
      bare := replace(split_part(bare, '.', greatest(array_length(string_to_array(bare, '.'), 1), 1)), '"', '');
      out := out || ('ALTER SEQUENCE ' || here || '.' || __KN__.always_quote(bare)
                     || ' OWNED BY ' || here || '.' || __KN__.always_quote(tab->>'name')
                     || '.' || __KN__.always_quote(col->>'name'));
    END LOOP;
  END LOOP;

  -- Stand-ins for the tables outside this schema that its foreign keys point
  -- at, with two rows already in them so seeding has something to reference.
  FOR stub IN SELECT * FROM jsonb_array_elements(external) LOOP
    cols := ARRAY[]::text[];
    FOR col IN SELECT * FROM jsonb_array_elements(stub->'columns') LOOP
      cols := cols || (__KN__.always_quote(col->>'name') || ' ' || (col->>'type') || ' NOT NULL');
    END LOOP;
    out := out || ('CREATE TABLE ' || here || '.' || __KN__.always_quote(stub->>'stub')
                   || ' (' || array_to_string(cols, ', ')
                   || ', PRIMARY KEY (' || (SELECT string_agg(__KN__.always_quote(c->>'name'), ', ')
                                              FROM jsonb_array_elements(stub->'columns') c) || '))');
    FOR nth IN 0..1 LOOP
      values_ := ARRAY[]::text[];
      FOR col IN SELECT * FROM jsonb_array_elements(stub->'columns') LOOP
        values_ := values_ || __KN__.stub_value(col->>'type', nth);
      END LOOP;
      out := out || ('INSERT INTO ' || here || '.' || __KN__.always_quote(stub->>'stub')
                     || ' VALUES (' || array_to_string(values_, ', ') || ')');
    END LOOP;
  END LOOP;

  -- Keys and uniques across every table first, then the foreign keys. A
  -- foreign key on `orders` used to be created before the primary key on
  -- `profiles` existed, and Postgres refused it.
  FOREACH want_foreign IN ARRAY ARRAY[false, true] LOOP
    FOR tab IN SELECT * FROM jsonb_array_elements(plan->'tables') LOOP
      FOR con IN SELECT * FROM jsonb_array_elements(tab->'constraints') LOOP
        CONTINUE WHEN (con->>'kind' = 'f') <> want_foreign;
        out := out || ('ALTER TABLE ' || here || '.' || __KN__.always_quote(tab->>'name')
                       || ' ADD CONSTRAINT ' || __KN__.always_quote(con->>'name') || ' '
                       || __KN__.rewrite_external_refs(
                            __KN__.rewrite_schema_refs(con->>'definition', source, target),
                            external, target));
      END LOOP;
    END LOOP;
  END LOOP;

  -- Unique indexes, once every table exists. Every index definition carries
  -- the schema name unquoted, so replayed as-is the copy would build its
  -- indexes on the customer's real tables.
  FOR idx IN SELECT * FROM jsonb_array_elements(coalesce(plan->'indexes', '[]'::jsonb)) LOOP
    out := out || __KN__.rewrite_schema_refs(idx->>'definition', source, target);
  END LOOP;

  -- Views last, because they read from the tables above.
  FOR view_ IN SELECT * FROM jsonb_array_elements(coalesce(plan->'views', '[]'::jsonb)) LOOP
    out := out || ('CREATE '
      || CASE WHEN (view_->>'materialised')::boolean THEN 'MATERIALIZED VIEW ' ELSE 'VIEW ' END
      || here || '.' || __KN__.always_quote(view_->>'name')
      || CASE WHEN coalesce(view_->>'options', '') <> '' THEN ' WITH (' || (view_->>'options') || ')' ELSE '' END
      || ' AS ' || __KN__.rewrite_external_refs(
                     __KN__.rewrite_schema_refs(view_->>'definition', source, target), external, target));
  END LOOP;

  FOR grant_ IN SELECT * FROM jsonb_array_elements(coalesce(plan->'viewGrants', '[]'::jsonb)) LOOP
    out := out || ('GRANT ' || (grant_->>'privilege_type') || ' ON ' || here || '.'
                   || __KN__.always_quote(grant_->>'table_name') || ' TO '
                   || CASE WHEN grant_->>'grantee' = 'PUBLIC' THEN 'PUBLIC'
                           ELSE __KN__.always_quote(grant_->>'grantee') END);
  END LOOP;

  -- The copy needs the roles PostgREST switches into to be able to reach it.
  -- Granted on the copy's own schema and nowhere else.
  FOREACH role_ IN ARRAY __KN__.existing_roles(ARRAY['anon', 'authenticated']) LOOP
    out := out || ('GRANT USAGE ON SCHEMA ' || here || ' TO ' || __KN__.always_quote(role_));
  END LOOP;

  FOR grant_ IN SELECT * FROM jsonb_array_elements(coalesce(plan->'grants', '[]'::jsonb)) LOOP
    out := out || ('GRANT ' || (grant_->>'privilege_type') || ' ON ' || here || '.'
                   || __KN__.always_quote(grant_->>'table_name') || ' TO '
                   || CASE WHEN grant_->>'grantee' = 'PUBLIC' THEN 'PUBLIC'
                           ELSE __KN__.always_quote(grant_->>'grantee') END);
  END LOOP;

  -- The sequences, on the same terms as the tables. A table grant without
  -- the sequence grant that goes with it is a copy nobody can insert into.
  FOR grant_ IN SELECT * FROM jsonb_array_elements(coalesce(plan->'sequenceGrants', '[]'::jsonb)) LOOP
    out := out || ('GRANT ' || (grant_->>'privilege_type') || ' ON SEQUENCE ' || here || '.'
                   || __KN__.always_quote(grant_->>'sequence_name') || ' TO '
                   || CASE WHEN grant_->>'grantee' = 'PUBLIC' THEN 'PUBLIC'
                           ELSE __KN__.always_quote(grant_->>'grantee') END);
  END LOOP;

  FOR tab IN SELECT * FROM jsonb_array_elements(plan->'tables') LOOP
    IF (tab->>'rlsEnabled')::boolean THEN
      out := out || ('ALTER TABLE ' || here || '.' || __KN__.always_quote(tab->>'name')
                     || ' ENABLE ROW LEVEL SECURITY');
    END IF;
    IF (tab->>'rlsForced')::boolean THEN
      out := out || ('ALTER TABLE ' || here || '.' || __KN__.always_quote(tab->>'name')
                     || ' FORCE ROW LEVEL SECURITY');
    END IF;
  END LOOP;

  FOR pol IN SELECT * FROM jsonb_array_elements(coalesce(plan->'policies', '[]'::jsonb)) LOOP
    out := out || (
      'CREATE POLICY ' || __KN__.always_quote(pol->>'name')
      || ' ON ' || here || '.' || __KN__.always_quote(pol->>'table_name')
      || ' AS ' || CASE WHEN pol->>'permissive' = 'PERMISSIVE' THEN 'PERMISSIVE' ELSE 'RESTRICTIVE' END
      || ' FOR ' || (pol->>'cmd')
      || ' TO ' || coalesce(nullif((SELECT string_agg(r, ', ')
                                      FROM jsonb_array_elements_text(pol->'roles') r), ''), 'PUBLIC')
      || CASE WHEN pol->>'qual' IS NOT NULL THEN ' USING (' || (pol->>'qual') || ')' ELSE '' END
      || CASE WHEN pol->>'with_check' IS NOT NULL THEN ' WITH CHECK (' || (pol->>'with_check') || ')' ELSE '' END
    );
  END LOOP;

  RETURN to_jsonb(out);
END $$;

/* Builds the schema again, in a database we own. */
CREATE OR REPLACE FUNCTION __KN__.write_schema(plan jsonb, target text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  statements jsonb := __KN__.must_stay_inside(__KN__.copy_statements(plan, target), target);
  s text;
BEGIN
  FOR s IN SELECT jsonb_array_elements_text(statements) LOOP
    EXECUTE s;
  END LOOP;
  RETURN statements;
END $$;

-- --------------------------------------------------------------------------
-- Slice 3: seeding, in SQL.
--
-- Mirrors attack.js. The three functions here are the deterministic half of
-- deciding what to put in a row: who a row belongs to, how wide a value may
-- be, and what a CHECK constraint will actually accept. They take the shape
-- read_schema hands back and nothing else, so the twin check can compare them
-- answer for answer with no database state in the way.
-- --------------------------------------------------------------------------

/*
 * The column that says who a row belongs to, or NULL if nothing does.
 *
 * The order is what these names are worth believing, not alphabetical. `id`
 * is last and only counts on a table that looks like a profile, where the row
 * id IS the person.
 */
CREATE OR REPLACE FUNCTION __KN__.owner_column(tab jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  wanted text;
  found text;
BEGIN
  FOREACH wanted IN ARRAY ARRAY['user_id', 'owner_id', 'owner', 'profile_id',
                                'account_id', 'created_by', 'author_id'] LOOP
    SELECT c->>'name' INTO found
      FROM jsonb_array_elements(tab->'columns') c
     WHERE c->>'type' = 'uuid' AND c->>'name' = wanted
     LIMIT 1;
    IF found IS NOT NULL THEN RETURN found; END IF;
  END LOOP;

  -- A profiles table keyed by the person themselves.
  IF (tab->>'name') ~* '(profile|user|account|member)' THEN
    SELECT c->>'name' INTO found
      FROM jsonb_array_elements(tab->'columns') c
     WHERE c->>'type' = 'uuid' AND c->>'name' = 'id'
     LIMIT 1;
    IF found IS NOT NULL THEN RETURN found; END IF;
  END IF;

  RETURN NULL;
END $$;

/* Keeps a generated value inside a declared width like varchar(20). */
CREATE OR REPLACE FUNCTION __KN__.fit_to(text_ text, kind text)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  width text := (regexp_match(btrim(coalesce(kind, '')), '^[a-z ]*\((\d+)\)$'))[1];
BEGIN
  IF width IS NULL THEN RETURN text_; END IF;
  IF length(text_) > width::integer THEN RETURN left(text_, width::integer); END IF;
  RETURN text_;
END $$;

/*
 * Values a CHECK constraint will actually accept for one column.
 *
 * `status text CHECK (status IN ('open','closed'))` is one of the most common
 * things anyone writes, and Postgres stores it as
 * `CHECK ((status = ANY (ARRAY['open'::text, 'closed'::text])))`. Reading the
 * literals back out turns a table that could never be seeded into one that can.
 *
 * Only this one shape is understood, deliberately. A CHECK can contain
 * anything, and pretending to satisfy an arbitrary one would mean inventing
 * rows the app itself would reject.
 */
CREATE OR REPLACE FUNCTION __KN__.allowed_by_check(tab jsonb, column_name text)
RETURNS text[] LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  found text[] := ARRAY[]::text[];
  con jsonb;
  inside text;
  literal text;
BEGIN
  FOR con IN SELECT * FROM jsonb_array_elements(coalesce(tab->'constraints', '[]'::jsonb)) LOOP
    CONTINUE WHEN con->>'kind' <> 'c';
    -- Both spellings of the same rule. On a text column Postgres writes
    --   state = ANY (ARRAY['open'::text, ...])
    -- and on a varchar column it writes
    --   (state)::text = ANY ((ARRAY['open'::character varying, ...])::text[])
    -- which the first pattern could not cross: it stopped at the bracket that
    -- closes the cast, so every varchar column with an IN list was seeded with
    -- an invented value, refused by its own constraint, and its table reported
    -- as one that could not be checked.
    --
    -- What may sit between the column and the = is spelled out rather than
    -- left to a negated class: anything looser reaches across the next AND and
    -- hands one column's allowed values to another.
    inside := (regexp_match(
      con->>'definition',
      '\m' || regexp_replace(column_name, '([.*+?^${}()|\[\]\\])', '\\\1', 'g')
        || '\M\)?(?:::[a-z ]+)?\s*=\s*ANY\s*\(+\s*ARRAY\[(.*?)\]',
      'i'))[1];
    CONTINUE WHEN inside IS NULL;
    -- Picked out one at a time rather than split on commas, which came apart
    -- in the middle of any value that had a comma in it.
    FOR literal IN
      SELECT (m)[1] FROM regexp_matches(inside, '''((?:[^'']|'''')*)''', 'g') m
    LOOP
      found := found || replace(literal, '''''', '''');
    END LOOP;
  END LOOP;
  RETURN found;
END $$;

/*
 * Something valid to put in a column, so a row can exist at all.
 *
 * Mirrors valueFor in attack.js. What comes back is the TEXT of the value,
 * which the insert casts to the column's own type - the Node side hands the
 * same thing to the driver as a parameter instead. Both are "the value that
 * belongs here", written the way each engine has to write it.
 *
 * `distinct` is what keeps two seeded rows from being identical. Without it
 * every row carried the same text, so a table with a unique email column
 * refused the second insert and the whole table was reported as "not checked"
 * - a well-built app treated as an unknown one. The tag goes at the front
 * because a narrow varchar truncates the end, and two rows truncated to the
 * same string is that bug all over again.
 */
CREATE OR REPLACE FUNCTION __KN__.value_for(col jsonb, owner text, distinct_ text, attempt integer)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  -- A domain is somebody's own type with a rule bolted on. The rule cannot be
  -- guessed at from here, but the type underneath it can be filled in.
  kind text := lower(coalesce(col->>'base_type', col->>'type'));
  tag text := coalesce(distinct_, '');
  step integer := coalesce(nullif(tag, '')::numeric::integer, 0);
  shapes text[];
  nth integer;
BEGIN
  -- An enum accepts one of a fixed list and nothing else. Every generated
  -- string was rejected, and the table went down as "not checked".
  IF jsonb_typeof(col->'enum_labels') = 'array'
     AND jsonb_array_length(col->'enum_labels') > 0 THEN
    RETURN col->'enum_labels'->>0;
  END IF;
  -- Anything at all is allowed in an empty array, whatever the element type.
  IF (col->>'is_array')::boolean OR kind ~ '\[\]$' THEN RETURN '{}'; END IF;

  IF kind = 'uuid' THEN RETURN owner; END IF;
  IF kind ~ '^(integer|bigint|smallint|numeric|decimal|real|double|money)' THEN
    RETURN (1 + step)::text;
  END IF;
  IF kind ~ '^bool' THEN RETURN 'true'; END IF;
  IF kind ~ '^(timestamp|date)' THEN
    RETURN to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  END IF;
  IF kind ~ '^time' THEN RETURN '12:00:00'; END IF;
  IF kind ~ '^interval' THEN RETURN '1 day'; END IF;
  IF kind ~ '^json' THEN RETURN '{}'; END IF;
  IF kind ~ '^(inet|cidr)' THEN RETURN '192.0.2.' || (1 + step)::text; END IF;
  IF kind ~ '^macaddr8' THEN RETURN '08:00:2b:01:02:03:04:0' || (5 + step)::text; END IF;
  IF kind ~ '^macaddr' THEN RETURN '08:00:2b:01:02:0' || (3 + step)::text; END IF;
  IF kind ~ '^(tsvector|tsquery)' THEN RETURN 'kryptheon'; END IF;
  IF kind ~ '^bytea' THEN RETURN 'kryptheon'; END IF;
  IF kind ~ '^xml' THEN RETURN '<kryptheon/>'; END IF;
  IF kind ~ '^bit' THEN RETURN '0'; END IF;
  IF kind ~ '^(point|line|lseg|box|path|polygon|circle)' THEN RETURN '(0,0)'; END IF;

  -- Text is where the rules live that cannot be read: a domain that insists on
  -- an @, a CHECK on a length, a regex for a product code. Rather than pretend
  -- to understand them, the seeder works down a short ladder of shapes and
  -- keeps whichever one the database accepts.
  shapes := ARRAY[
    CASE WHEN tag <> '' THEN tag || ' kryptheon test' ELSE 'kryptheon test' END,
    'kryptheon' || tag || '@example.com',
    'KN' || CASE WHEN tag <> '' THEN tag ELSE '1' END,
    (step + 1)::text,
    'https://example.com/kryptheon'
  ];
  nth := least(greatest(coalesce(attempt, 0), 0), array_length(shapes, 1) - 1);
  RETURN __KN__.fit_to(shapes[nth + 1], kind);
END $$;

/*
 * The foreign keys on a table, read out of Postgres's own wording.
 *
 * Every column of the key, not just the first. A key over (org_id, cart_id)
 * used to be read as though it were only org_id: the second column got an
 * invented value, the pair pointed at no row that existed, and the table was
 * reported as one that could not be checked.
 */
CREATE OR REPLACE FUNCTION __KN__.foreign_keys(tab jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  keys jsonb := '[]'::jsonb;
  con jsonb;
  parts text[];
BEGIN
  FOR con IN SELECT * FROM jsonb_array_elements(coalesce(tab->'constraints', '[]'::jsonb)) LOOP
    CONTINUE WHEN con->>'kind' <> 'f';
    parts := regexp_match(
      con->>'definition',
      'FOREIGN KEY \(([^)]+)\) REFERENCES ([^(]+)\(([^)]+)\)',
      'i');
    CONTINUE WHEN parts IS NULL;
    keys := keys || jsonb_build_array(jsonb_build_object(
      'columns', __KN__.unquoted_list(parts[1]),
      -- The schema is dropped: inside the copy every table it can point at is
      -- in the copy, and keeping the original's name would send it home.
      'refTable', __KN__.unquoted(split_part(parts[2], '.', greatest(
        array_length(string_to_array(parts[2], '.'), 1), 1))),
      'refColumns', __KN__.unquoted_list(parts[3])
    ));
  END LOOP;
  RETURN keys;
END $$;

/* A name as Postgres wrote it, with the quoting taken back off. */
CREATE OR REPLACE FUNCTION __KN__.unquoted(name text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT replace(btrim(name), '"', '');
$$;

/* And a comma-separated list of them. */
CREATE OR REPLACE FUNCTION __KN__.unquoted_list(list text)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(jsonb_agg(__KN__.unquoted(piece) ORDER BY at), '[]'::jsonb)
    FROM regexp_split_to_table(list, ',') WITH ORDINALITY AS p(piece, at);
$$;

/*
 * One step of the walk: everything this table points at, before the table.
 *
 * The three sets are carried in and out rather than held in a closure, which
 * plpgsql does not have. Post-order, exactly as the Node side walks it, so the
 * two engines hand back the same order and not merely a workable one.
 */
CREATE OR REPLACE FUNCTION __KN__.dependency_visit(name text, tables jsonb, state jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  tab jsonb;
  key jsonb;
  parent text;
BEGIN
  IF state->'done' ? name OR state->'visiting' ? name THEN RETURN state; END IF;

  SELECT t INTO tab FROM jsonb_array_elements(tables) t WHERE t->>'name' = name;
  IF tab IS NULL THEN RETURN state; END IF;

  state := jsonb_set(state, '{visiting}', (state->'visiting') || to_jsonb(name));

  FOR key IN SELECT * FROM jsonb_array_elements(__KN__.foreign_keys(tab)) LOOP
    parent := key->>'refTable';
    CONTINUE WHEN parent = name;
    CONTINUE WHEN NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(tables) t WHERE t->>'name' = parent);
    state := __KN__.dependency_visit(parent, tables, state);
  END LOOP;

  state := jsonb_set(state, '{visiting}',
    coalesce((SELECT jsonb_agg(v) FROM jsonb_array_elements(state->'visiting') v
               WHERE v <> to_jsonb(name)), '[]'::jsonb));
  state := jsonb_set(state, '{done}', (state->'done') || to_jsonb(name));
  state := jsonb_set(state, '{ordered}', (state->'ordered') || to_jsonb(name));
  RETURN state;
END $$;

/*
 * Parents before children.
 *
 * Tables come back in alphabetical order, which put `orders` before `profiles`
 * and made every insert fail on the foreign key - on the first real app it was
 * pointed at, because every app has one of these. A cycle is left in whatever
 * order it arrived: it cannot be satisfied anyway, and the table that fails is
 * reported rather than dropped.
 */
CREATE OR REPLACE FUNCTION __KN__.dependency_order(tables jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  state jsonb := jsonb_build_object('done', '[]'::jsonb, 'visiting', '[]'::jsonb, 'ordered', '[]'::jsonb);
  tab jsonb;
  out jsonb := '[]'::jsonb;
  name text;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(tables) LOOP
    state := __KN__.dependency_visit(tab->>'name', tables, state);
  END LOOP;

  FOR name IN SELECT jsonb_array_elements_text(state->'ordered') LOOP
    out := out || jsonb_build_array(
      (SELECT t FROM jsonb_array_elements(tables) t WHERE t->>'name' = name));
  END LOOP;
  RETURN out;
END $$;

-- --------------------------------------------------------------------------
-- Seeding, the half that writes.
--
-- Everything above this decides things from the shape and nothing else. From
-- here on rows really go in, which is why the twin check stops comparing
-- answers and starts comparing the two copies that come out.
-- --------------------------------------------------------------------------

/* The two people the copy is seeded with. */
CREATE OR REPLACE FUNCTION __KN__.user_a() RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT '11111111-1111-4111-8111-111111111111';
$$;
CREATE OR REPLACE FUNCTION __KN__.user_b() RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT '22222222-2222-4222-8222-222222222222';
$$;

-- Two more who own nothing at all. The seeded pair already hold a row each,
-- so an attack that inserts under their name collides with the row the
-- seeder put there - on a table keyed by the person that is a primary key
-- clash, and it was being read as the app refusing the attack.
CREATE OR REPLACE FUNCTION __KN__.user_c() RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT '55555555-5555-4555-8555-555555555555';
$$;
CREATE OR REPLACE FUNCTION __KN__.user_d() RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT '66666666-6666-4666-8666-666666666666';
$$;

/*
 * One row that is really in the parent table, so a foreign key is satisfied.
 *
 * The whole row, not one column of it. A composite key has to point at a pair
 * that exists together: borrowing each column from a separate row would build
 * a combination the parent never had.
 */
CREATE OR REPLACE FUNCTION __KN__.existing_row(source text, key jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  picked text[];
  names text;
BEGIN
  SELECT string_agg(__KN__.always_quote(name), ', ' ORDER BY at) INTO names
    FROM jsonb_array_elements_text(key->'refColumns') WITH ORDINALITY AS c(name, at);
  IF names IS NULL THEN RETURN NULL; END IF;

  EXECUTE 'SELECT ARRAY[' || replace(names, ', ', '::text, ') || '::text] FROM '
    || __KN__.always_quote(source) || '.' || __KN__.always_quote(key->>'refTable')
    || ' LIMIT 1'
    INTO picked;
  IF picked IS NULL THEN RETURN NULL; END IF;
  RETURN to_jsonb(picked);
EXCEPTION WHEN OTHERS THEN
  -- A parent that cannot be read is a key that cannot be satisfied, and the
  -- table that holds it is reported rather than guessed at.
  RETURN NULL;
END $$;

/*
 * A row that will actually go in.
 *
 * Owner column set to the person, foreign keys pointing at rows that really
 * exist, every NOT NULL column filled, and anything with a default left to
 * supply its own value.
 *
 * `overrides` is what the Collision attack needs: it forces one column to a
 * chosen value while everything else stays distinct, so when two inserts race
 * they collide on that column and on nothing else. Without it a second unique
 * column elsewhere in the table would refuse the insert, and the refusal would
 * be read as the app defending itself.
 */
CREATE OR REPLACE FUNCTION __KN__.row_for(
  source text, tab jsonb, person text, distinct_ text, overrides jsonb, attempt integer)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  forced jsonb := coalesce(overrides, '{}'::jsonb);
  owner text := __KN__.owner_column(tab);
  columns jsonb := '[]'::jsonb;
  values_ jsonb := '[]'::jsonb;
  borrowed jsonb := '{}'::jsonb;
  part_of_key jsonb := '[]'::jsonb;
  key jsonb;
  row_ jsonb;
  col jsonb;
  name text;
  allowed text[];
  nth integer;
  at integer;
BEGIN
  -- Every column that takes part in a foreign key, and the value it has to
  -- hold. Resolved one key at a time so that all of a composite key's columns
  -- come from the same parent row.
  FOR key IN SELECT * FROM jsonb_array_elements(__KN__.foreign_keys(tab)) LOOP
    row_ := __KN__.existing_row(source, key);
    CONTINUE WHEN row_ IS NULL;
    at := 0;
    FOR name IN SELECT jsonb_array_elements_text(key->'columns') LOOP
      IF NOT (borrowed ? name) THEN
        borrowed := jsonb_set(borrowed, ARRAY[name], coalesce(row_->at, 'null'::jsonb));
      END IF;
      at := at + 1;
    END LOOP;
  END LOOP;
  FOR key IN SELECT * FROM jsonb_array_elements(__KN__.foreign_keys(tab)) LOOP
    part_of_key := part_of_key || (key->'columns');
  END LOOP;

  FOR col IN SELECT * FROM jsonb_array_elements(tab->'columns') LOOP
    name := col->>'name';

    IF forced ? name THEN
      columns := columns || to_jsonb(name);
      values_ := values_ || jsonb_build_array(forced->name);
      CONTINUE;
    END IF;

    IF name = owner THEN
      columns := columns || to_jsonb(name);
      values_ := values_ || jsonb_build_array(to_jsonb(person));
      CONTINUE;
    END IF;

    -- A column pointing at another table has to hold something that is
    -- actually there, whatever its type would otherwise suggest.
    IF part_of_key ? name THEN
      IF borrowed ? name THEN
        columns := columns || to_jsonb(name);
        values_ := values_ || jsonb_build_array(borrowed->name);
        CONTINUE;
      END IF;
      IF (col->>'not_null')::boolean THEN
        RAISE EXCEPTION 'nothing to point % at', name;
      END IF;
      CONTINUE;
    END IF;

    -- A generated column computes itself and refuses to be written to at all.
    --
    -- Two halves, and only one of them can be observed. An identity column
    -- carries no default_expr, so without the identity half the seeder writes
    -- to it and Postgres refuses the row - both engines are caught doing it.
    -- A stored generated column keeps its expression IN default_expr, so the
    -- line below skips it whether or not this one does: removing the generated
    -- half changes nothing any fixture could see. It stays because that is a
    -- fact about how readColumns fills the shape, not about Postgres, and the
    -- day it changes this is the only thing standing in the way.
    CONTINUE WHEN col->>'generated' IS NOT NULL OR (col->>'identity')::boolean;
    -- Anything with a default can supply its own value.
    CONTINUE WHEN col->>'default_expr' IS NOT NULL;
    CONTINUE WHEN NOT (col->>'not_null')::boolean;

    columns := columns || to_jsonb(name);
    -- A CHECK that lists what it will accept beats anything invented here.
    allowed := __KN__.allowed_by_check(tab, name);
    IF array_length(allowed, 1) > 0 THEN
      nth := least(greatest(coalesce(attempt, 0), 0), array_length(allowed, 1) - 1);
      values_ := values_ || jsonb_build_array(to_jsonb(allowed[nth + 1]));
    ELSE
      values_ := values_ || jsonb_build_array(
        to_jsonb(__KN__.value_for(col, person, distinct_, attempt)));
    END IF;
  END LOOP;

  RETURN jsonb_build_object('columns', columns, 'values', values_);
END $$;

/*
 * The statement that puts a built row in.
 *
 * Written out rather than run, because the tampering attack needs the same
 * insert the seeder would use and needs it as text: it has to be built
 * before the attack stops being itself, and run afterwards as somebody else.
 */
CREATE OR REPLACE FUNCTION __KN__.insert_statement(source text, table_name text, row_ jsonb)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  where_ text := 'INSERT INTO ' || __KN__.always_quote(source) || '.' || __KN__.always_quote(table_name);
  names text;
  places text;
BEGIN
  -- A table of nothing but an id and its defaults leaves no columns to name,
  -- and "INSERT INTO t () VALUES ()" is a syntax error. Postgres has a
  -- spelling for exactly this, and without it every settings and flags table
  -- in the world came back as one that could not be checked.
  IF jsonb_array_length(row_->'columns') = 0 THEN
    RETURN where_ || ' DEFAULT VALUES';
  END IF;

  SELECT string_agg(__KN__.always_quote(name), ', ' ORDER BY at) INTO names
    FROM jsonb_array_elements_text(row_->'columns') WITH ORDINALITY AS c(name, at);
  -- Written as literals rather than passed as parameters: EXECUTE ... USING
  -- needs a fixed argument list, and the number of columns is not known until
  -- the row is built. quote_nullable casts nothing and lets the column's own
  -- type decide, which is what the driver does for the other engine.
  SELECT string_agg(quote_nullable(v), ', ' ORDER BY at) INTO places
    FROM jsonb_array_elements_text(row_->'values') WITH ORDINALITY AS c(v, at);

  RETURN where_ || ' (' || names || ') VALUES (' || places || ')';
END $$;

/* And running it. Separate so the same row can be raced against itself. */
CREATE OR REPLACE FUNCTION __KN__.insert_row(source text, table_name text, row_ jsonb)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE __KN__.insert_statement(source, table_name, row_);
END $$;

/*
 * Two people, in every table, in an order that can actually be satisfied.
 *
 * A table whose rules reject every shape offered is reported, never quietly
 * passed over: an empty table and an open one look identical from outside.
 */
CREATE OR REPLACE FUNCTION __KN__.seed(source text, tables jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  seeded jsonb := '[]'::jsonb;
  skipped jsonb := '[]'::jsonb;
  tab jsonb;
  owner text;
  people text[];
  person text;
  refused text;
  landed boolean;
  worked integer;
  attempt integer;
  nth integer;
  shapes_to_try constant integer := 5;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(__KN__.dependency_order(tables)) LOOP
    owner := __KN__.owner_column(tab);

    -- A table with nobody's name on it still gets a row. Without one, an open
    -- door cannot be told from an empty room: a logged-out stranger reads zero
    -- rows either way, and the tool reports the app as safe. Settings tables,
    -- waitlists and contact forms are exactly this shape, and exactly the ones
    -- that get left open.
    IF owner IS NULL THEN
      people := ARRAY[__KN__.user_a()];
    ELSE
      people := ARRAY[__KN__.user_a(), __KN__.user_b()];
    END IF;

    refused := NULL;
    landed := false;
    worked := 0;

    attempt := 0;
    WHILE attempt < shapes_to_try AND NOT landed LOOP
      BEGIN
        nth := 0;
        FOREACH person IN ARRAY people LOOP
          nth := nth + 1;
          PERFORM __KN__.insert_row(source, tab->>'name',
            __KN__.row_for(source, tab, person, nth::text, NULL, attempt));
        END LOOP;
        landed := true;
        worked := attempt;
      EXCEPTION WHEN OTHERS THEN
        refused := SQLERRM;
        -- The block is a subtransaction, so anything that did go in on this
        -- attempt is already gone. The other engine has to delete it by hand;
        -- what matters is that the next attempt does not collide with a row
        -- this one left behind.
      END;
      attempt := attempt + 1;
    END LOOP;

    IF landed THEN
      -- The shape that worked is kept: any later attack that has to insert
      -- into this table can use the same one instead of rediscovering it, and
      -- be sure a refusal is the app defending itself rather than a CHECK it
      -- never satisfied.
      seeded := seeded || jsonb_build_array(jsonb_build_object(
        'table', tab->>'name', 'owner', owner, 'attempt', worked));
    ELSE
      -- Recorded, never swallowed. The report has to say this table was not
      -- checked rather than let an empty table pass for a safe one.
      skipped := skipped || jsonb_build_array(jsonb_build_object(
        'table', tab->>'name', 'why', refused));
    END IF;
  END LOOP;

  RETURN jsonb_build_object('seeded', seeded, 'skipped', skipped);
END $$;

-- --------------------------------------------------------------------------
-- The impersonation attack, inside the database.
--
-- Nothing here is SECURITY DEFINER, and it cannot be: Postgres refuses to let
-- a security-definer function change role, and changing role is the whole
-- attack. Measured, not assumed - probe-plpgsql.js asks exactly this.
-- --------------------------------------------------------------------------

/*
 * A refusal is only an answer when it is the right refusal.
 *
 * "permission denied for table orders" means this caller cannot reach the
 * table at all. That is the attack being defeated, and it is good news worth
 * recording as a pass.
 *
 * Everything else - a schema the policy needs and the role cannot use, a
 * function the policy calls that is not there, a timeout - means the rule was
 * never evaluated. No verdict exists. Both come back as an error and return
 * zero rows, and zero rows is exactly what a perfectly secured table returns,
 * so telling them apart is the difference between "you are safe" and "I could
 * not tell", which is the difference the whole product rests on.
 */
CREATE OR REPLACE FUNCTION __KN__.refusal_means(message text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  -- The multi-word kinds come first. Postgres says "permission denied for
  -- materialized view hits", and an alternation that tried `view` first would
  -- never reach it - so a matview nobody had granted was filed as untested
  -- rather than as the attack being beaten, and a correct app collected a
  -- warning it had not earned.
  SELECT CASE WHEN coalesce(message, '') ~*
    'permission denied for (materialized view|foreign table|partitioned table|table|relation|view|sequence)'
    THEN 'unreachable' ELSE 'untested' END;
$$;

/*
 * Reads a table the way a request would, as whoever is asking.
 *
 * Counted rather than fetched. The Node side pulls the rows back and counts
 * them there; here the count is the only thing wanted, and row level security
 * applies to a count exactly as it applies to a select.
 *
 * `owner` being given also asks the second question: of the rows this caller
 * can see, how many belong to somebody else.
 */
CREATE OR REPLACE FUNCTION __KN__.read_as(
  source text, table_name text, role_ text, user_id text, owner text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  claims text;
  total bigint;
  theirs bigint := NULL;
  target text := __KN__.always_quote(source) || '.' || __KN__.always_quote(table_name);
  -- Both statements are written out before the role changes, and this is
  -- not tidiness. Once this function becomes anon it cannot call anything
  -- in the engine schema any more - anon has no USAGE on it - so a call to
  -- always_quote or user_b made after the switch fails with "permission
  -- denied for schema kn_engine_...". That is not the app defending
  -- itself, but it arrives looking exactly like it: every crossed attack
  -- came back as a table that could not be tested.
  --
  -- The rule for everything on this side of the engine: whatever the
  -- attack needs, it must already hold before it stops being itself.
  counting text := 'SELECT count(*) FROM ' || target;
  counting_theirs text := CASE WHEN owner IS NULL THEN NULL ELSE
    'SELECT count(*) FROM ' || target || ' WHERE '
      || __KN__.always_quote(owner) || '::text = ' || quote_literal(__KN__.user_b()) END;
BEGIN
  -- A logged-out visitor is not "no claims". Supabase hands PostgREST the
  -- anon key, which is itself a JWT, so request.jwt.claims arrives as a real
  -- JSON object that simply has no `sub` in it.
  --
  -- Sending an empty string instead made auth.uid() throw on the cast, and a
  -- read that throws returns no rows - which is exactly what a properly
  -- secured table returns. Every table whose policy calls auth.uid(), which
  -- is nearly every table anyone writes, came back looking safe without the
  -- rule ever being evaluated.
  claims := CASE WHEN user_id IS NULL
    THEN json_build_object('role', role_)::text
    ELSE json_build_object('sub', user_id, 'role', role_)::text END;

  BEGIN
    EXECUTE 'SET LOCAL ROLE ' || quote_ident(role_);
    PERFORM set_config('request.jwt.claims', claims, true);

    EXECUTE counting INTO total;
    IF counting_theirs IS NOT NULL THEN
      EXECUTE counting_theirs INTO theirs;
    END IF;

    RESET ROLE;
    PERFORM set_config('request.jwt.claims', '', true);
    RETURN jsonb_build_object('ok', true, 'count', total, 'theirs', theirs);
  EXCEPTION WHEN OTHERS THEN
    -- A refusal is an answer: the table is not reachable by this caller at
    -- all. Which kind of refusal it was is decided by the caller.
    RESET ROLE;
    PERFORM set_config('request.jwt.claims', '', true);
    RETURN jsonb_build_object('ok', false, 'why', SQLERRM);
  END;
END $$;

/*
 * What each table gives away, and to whom.
 *
 * Two separate findings, because they are two different conversations with the
 * person who has to fix it:
 *
 *   exposed  - a logged-out stranger can read the table. This is the one that
 *              ends up on a news site.
 *   crossed  - a signed-in customer can read another customer's rows. Quieter,
 *              and the one that breaks trust with the people already paying.
 */
CREATE OR REPLACE FUNCTION __KN__.impersonate(source text, tables jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  findings jsonb := '[]'::jsonb;
  completed jsonb := '[]'::jsonb;
  blocked jsonb := '[]'::jsonb;
  tab jsonb;
  owner text;
  anon jsonb;
  as_a jsonb;
  key text;
  named jsonb;
  reached boolean;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(tables) LOOP
    owner := __KN__.owner_column(tab);
    named := coalesce((SELECT jsonb_agg(c->>'name') FROM jsonb_array_elements(tab->'columns') c),
                      '[]'::jsonb);

    anon := __KN__.read_as(source, tab->>'name', 'anon', NULL, NULL);
    as_a := __KN__.read_as(source, tab->>'name', 'authenticated', __KN__.user_a(), owner);

    -- Did this read produce a verdict, and if not, why not?
    key := 'exposed:' || (tab->>'name');
    IF (anon->>'ok')::boolean THEN
      completed := completed || to_jsonb(key);
      reached := true;
    ELSIF __KN__.refusal_means(anon->>'why') = 'unreachable' THEN
      -- Refused outright. The attack ran and lost, which is the result we
      -- want for a table that is properly closed.
      completed := completed || to_jsonb(key);
      reached := false;
    ELSE
      blocked := blocked || jsonb_build_array(jsonb_build_object(
        'table', tab->>'name', 'key', key,
        'why', 'as a logged-out visitor: ' || (anon->>'why')));
      reached := false;
    END IF;

    IF reached AND (anon->>'count')::bigint > 0 THEN
      findings := findings || jsonb_build_array(jsonb_build_object(
        'kind', 'exposed',
        'table', tab->>'name',
        'readable', (anon->>'count')::bigint,
        'columns', named,
        'rlsEnabled', coalesce((tab->>'rlsEnabled')::boolean, false),
        'isView', coalesce((tab->>'isView')::boolean, false)));
    END IF;

    -- Crossed is only ever looked for where a row says who it belongs to, so
    -- on a table with no owner there is no attack to record either way.
    IF owner IS NOT NULL THEN
      key := 'crossed:' || (tab->>'name');
      IF (as_a->>'ok')::boolean THEN
        completed := completed || to_jsonb(key);
        IF coalesce((as_a->>'theirs')::bigint, 0) > 0 THEN
          findings := findings || jsonb_build_array(jsonb_build_object(
            'kind', 'crossed',
            'table', tab->>'name',
            'owner', owner,
            'readable', (as_a->>'theirs')::bigint,
            'columns', named,
            'rlsEnabled', coalesce((tab->>'rlsEnabled')::boolean, false)));
        END IF;
      ELSIF __KN__.refusal_means(as_a->>'why') = 'unreachable' THEN
        completed := completed || to_jsonb(key);
      ELSE
        blocked := blocked || jsonb_build_array(jsonb_build_object(
          'table', tab->>'name', 'key', key,
          'why', 'as a signed-in customer: ' || (as_a->>'why')));
      END IF;
    END IF;
  END LOOP;

  RETURN jsonb_build_object('findings', findings, 'completed', completed, 'blocked', blocked);
END $$;

-- --------------------------------------------------------------------------
-- Can a stranger change your data?
--
-- Everything above asks whether the wrong person can READ. This asks whether
-- they can WRITE, and the answer matters more: a leak is bad, but a stranger
-- who can delete your customers table has taken something you cannot get back.
--
-- EVERYTHING HERE IS ROLLED BACK. Each write runs inside an exception block,
-- which in plpgsql is a subtransaction, and the block is always left by
-- raising on purpose - so the write happens, the count is kept, and the row
-- is gone. Measured before it was written: probe-plpgsql.js asks exactly this.
-- --------------------------------------------------------------------------

/*
 * A column an UPDATE can harmlessly set to itself.
 *
 * Setting a column to its own value changes nothing about the row while still
 * proving the write was allowed - so the finding is real and the data is not
 * even momentarily wrong inside the transaction that gets rolled back.
 */
CREATE OR REPLACE FUNCTION __KN__.first_writable(tab jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  found text;
BEGIN
  SELECT c->>'name' INTO found
    FROM jsonb_array_elements(tab->'columns') WITH ORDINALITY AS e(c, at)
   WHERE c->>'generated' IS NULL AND NOT (c->>'identity')::boolean
     AND (c->>'name') !~* '^id$'
   ORDER BY at LIMIT 1;
  IF found IS NOT NULL THEN RETURN found; END IF;

  SELECT c->>'name' INTO found
    FROM jsonb_array_elements(tab->'columns') WITH ORDINALITY AS e(c, at)
   WHERE c->>'generated' IS NULL AND NOT (c->>'identity')::boolean
   ORDER BY at LIMIT 1;
  RETURN coalesce(found, 'id');
END $$;

/*
 * What a write actually achieved.
 *
 * Three outcomes, and the middle one is the one that matters: a statement can
 * succeed and change nothing, which is row level security doing its job. Row
 * level security filters rows away rather than complaining, so every verdict
 * is taken from the number of rows that actually moved.
 */
CREATE OR REPLACE FUNCTION __KN__.what_happened(result jsonb)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN (result->>'ok')::boolean THEN
      CASE WHEN (result->>'count')::bigint > 0 THEN 'got through' ELSE 'refused' END
    -- A WITH CHECK turning a write away IS the app defending itself, and it is
    -- the single most common way a correct app says no. Reading it as "I could
    -- not tell" put a warning on every table that had got it right, and a
    -- warning nobody earned is how a report stops being read.
    WHEN coalesce(result->>'why', '') ~* 'violates row-level security policy' THEN 'refused'
    WHEN __KN__.refusal_means(result->>'why') = 'unreachable' THEN 'refused'
    ELSE 'untested'
  END;
$$;

/*
 * Runs one write the way a request runs it, and never keeps the result.
 *
 * The rollback is not a tidy-up, it is the safety property. Nothing this
 * attack does survives the statement that did it.
 *
 * The statement arrives already written, for the same reason read_as builds
 * its queries up front: once this function becomes anon it can no longer call
 * anything in the engine schema, and a refusal from its own housekeeping is
 * indistinguishable from the app defending itself.
 */
CREATE OR REPLACE FUNCTION __KN__.try_write(role_ text, identity text, statement text)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  claims text := CASE WHEN identity IS NULL
    THEN json_build_object('role', role_)::text
    ELSE json_build_object('sub', identity, 'role', role_)::text END;
  moved bigint := 0;
  worked boolean := false;
  why text := NULL;
BEGIN
  BEGIN
    EXECUTE 'SET LOCAL statement_timeout = ' || quote_literal('15s');
    EXECUTE 'SET LOCAL ROLE ' || quote_ident(role_);
    PERFORM set_config('request.jwt.claims', claims, true);

    EXECUTE statement;
    GET DIAGNOSTICS moved = ROW_COUNT;
    worked := true;

    -- Raised on purpose. The block is a subtransaction, so leaving it this way
    -- undoes the write while the count, which is a plpgsql variable and not a
    -- database change, survives.
    RAISE EXCEPTION 'kryptheon: undoing the write' USING ERRCODE = 'KN001';
  EXCEPTION
    WHEN SQLSTATE 'KN001' THEN
      NULL;
    WHEN OTHERS THEN
      worked := false;
      moved := 0;
      why := SQLERRM;
  END;

  RESET ROLE;
  PERFORM set_config('request.jwt.claims', '', true);
  PERFORM set_config('statement_timeout', '0', true);
  RETURN jsonb_build_object('ok', worked, 'count', moved, 'why', why);
END $$;

/*
 * Every way in, per table, per kind of caller.
 *
 * `seeded` carries the shape of row that worked when the table was seeded, so
 * the insert here is not rejected by some CHECK the seeder already solved.
 */
CREATE OR REPLACE FUNCTION __KN__.tamper(source text, tables jsonb, seeded jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  findings jsonb := '[]'::jsonb;
  completed jsonb := '[]'::jsonb;
  blocked jsonb := '[]'::jsonb;
  tab jsonb;
  owner text;
  shape integer;
  actor record;
  key text;
  can jsonb;
  changed jsonb;
  stuck text;
  their_rows text;
  at text;
  row_ jsonb;
  column_ text;
  moves jsonb;
  move jsonb;
  result jsonb;
  outcome text;
  named jsonb;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(tables) LOOP
    -- Never seeded, so there is nothing in it to protect.
    SELECT (s->>'attempt')::integer INTO shape
      FROM jsonb_array_elements(coalesce(seeded, '[]'::jsonb)) s
     WHERE s->>'table' = tab->>'name';
    CONTINUE WHEN NOT FOUND;
    shape := coalesce(shape, 0);

    owner := __KN__.owner_column(tab);
    at := __KN__.always_quote(source) || '.' || __KN__.always_quote(tab->>'name');
    column_ := __KN__.always_quote(__KN__.first_writable(tab));
    named := coalesce((SELECT jsonb_agg(c->>'name') FROM jsonb_array_elements(tab->'columns') c),
                      '[]'::jsonb);

    -- Rows belonging to the other fake person. Scoped on purpose: a signed-in
    -- customer deleting their OWN rows is not a finding, it is the feature,
    -- and an unscoped DELETE would report every correctly built app.
    their_rows := CASE WHEN owner IS NULL THEN ''
      ELSE ' WHERE ' || __KN__.always_quote(owner) || ' = ' || quote_literal(__KN__.user_a()) END;

    -- Written under a name nobody has used, which is both what makes the row
    -- land at all and what makes it the right test: adding a row of your own
    -- is the feature, adding one under somebody else's name is not.
    row_ := __KN__.row_for(source, tab, __KN__.user_c(), '7', NULL, shape);

    -- Every statement written out before anybody changes role.
    moves := jsonb_build_array(
      jsonb_build_object('what', 'add',
        'statement', __KN__.insert_statement(source, tab->>'name', row_)),
      jsonb_build_object('what', 'change',
        'statement', 'UPDATE ' || at || ' SET ' || column_ || ' = ' || column_ || their_rows),
      jsonb_build_object('what', 'delete',
        'statement', 'DELETE FROM ' || at || their_rows));

    FOR actor IN
      SELECT * FROM (VALUES
        ('anyone', 'anon', NULL::text),
        ('any customer', 'authenticated', __KN__.user_b())
      ) AS a(who, role_, identity)
    LOOP
      key := 'writable:' || (tab->>'name') || ':' || actor.who;
      can := '[]'::jsonb;
      changed := '{}'::jsonb;
      stuck := NULL;

      FOR move IN SELECT * FROM jsonb_array_elements(moves) LOOP
        result := __KN__.try_write(actor.role_, actor.identity, move->>'statement');
        outcome := __KN__.what_happened(result);
        IF outcome = 'got through' THEN
          can := can || to_jsonb(move->>'what');
          changed := jsonb_set(changed, ARRAY[move->>'what'], to_jsonb((result->>'count')::bigint));
        ELSIF outcome = 'untested' THEN
          stuck := result->>'why';
        END IF;
      END LOOP;

      IF stuck IS NOT NULL THEN
        -- Something went wrong that was not the app defending itself, so no
        -- verdict exists for this table and saying nothing would read as safe.
        blocked := blocked || jsonb_build_array(jsonb_build_object(
          'table', tab->>'name', 'key', key,
          'why', 'as ' || actor.who || ': ' || stuck));
        CONTINUE;
      END IF;

      completed := completed || to_jsonb(key);
      IF jsonb_array_length(can) > 0 THEN
        findings := findings || jsonb_build_array(jsonb_build_object(
          'kind', 'writable',
          'table', tab->>'name',
          'who', actor.who,
          'can', can,
          'changed', changed,
          'owner', owner,
          'columns', named,
          'rlsEnabled', coalesce((tab->>'rlsEnabled')::boolean, false)));
      END IF;
    END LOOP;
  END LOOP;

  RETURN jsonb_build_object('findings', findings, 'completed', completed, 'blocked', blocked);
END $$;

-- --------------------------------------------------------------------------
-- The interruption attack: can a half-finished write survive?
--
-- A request cut off partway is mostly a question about the app's code - were
-- the two inserts wrapped in a transaction? - and this tool never sees the
-- app's code. But there is a half of it the database answers on its own. A
-- foreign key is what makes a half-finished state impossible to keep, no
-- matter how badly the app behaves or where the connection drops.
--
-- So the attack is: put in a row pointing at something that is not there, and
-- see whether the database takes it. Rolled back, always.
-- --------------------------------------------------------------------------

/*
 * Tables whose job is to remember things after they are gone.
 *
 * A dangling id in an audit row is the feature, and a foreign key there would
 * be the bug.
 */
CREATE OR REPLACE FUNCTION __KN__.keeps_history(name text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT name ~* '(^|_)(log|logs|audit|audits|event|events|history|archive|archives|snapshot|snapshots|activity|activities)(_|$)';
$$;

/* The single-column primary key of a table, or NULL if it has none. */
CREATE OR REPLACE FUNCTION __KN__.primary_key_of(tab jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  con jsonb;
  inside text;
  names jsonb;
BEGIN
  FOR con IN SELECT * FROM jsonb_array_elements(coalesce(tab->'constraints', '[]'::jsonb)) LOOP
    CONTINUE WHEN con->>'kind' <> 'p';
    inside := (regexp_match(con->>'definition', 'PRIMARY KEY \(([^)]+)\)', 'i'))[1];
    CONTINUE WHEN inside IS NULL;
    names := __KN__.unquoted_list(inside);
    -- A composite key is not something a single `<thing>_id` column points at.
    IF jsonb_array_length(names) = 1 THEN RETURN names->>0; END IF;
    RETURN NULL;
  END LOOP;
  RETURN NULL;
END $$;

/*
 * The table a column named `<thing>_id` is pointing at, if there is one.
 *
 * The name has to match a table that is really here, and the types have to
 * agree. Both, because `stripe_id` matches nothing and `org_id integer` does
 * not point at an `orgs.id` that is a uuid. Telling somebody to add a foreign
 * key to a column that names something outside this database would be telling
 * them to break their app.
 */
CREATE OR REPLACE FUNCTION __KN__.parent_for(col jsonb, tables jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  stem text := (regexp_match(col->>'name', '^(.+)_id$', 'i'))[1];
  wanted text;
  parent jsonb;
  key text;
  key_column jsonb;
BEGIN
  IF stem IS NULL THEN RETURN NULL; END IF;
  wanted := lower(stem);

  SELECT t INTO parent FROM jsonb_array_elements(tables) t
   WHERE lower(t->>'name') IN (wanted, wanted || 's', wanted || 'es')
   LIMIT 1;
  IF parent IS NULL THEN RETURN NULL; END IF;

  key := __KN__.primary_key_of(parent);
  IF key IS NULL THEN RETURN NULL; END IF;

  SELECT c INTO key_column FROM jsonb_array_elements(parent->'columns') c
   WHERE c->>'name' = key LIMIT 1;
  IF key_column IS NULL OR (key_column->>'type') IS DISTINCT FROM (col->>'type') THEN
    RETURN NULL;
  END IF;

  RETURN jsonb_build_object('table', parent->>'name', 'keyColumn', key, 'type', key_column->>'type');
END $$;

/* Is this column already held down by a foreign key? */
CREATE OR REPLACE FUNCTION __KN__.already_tied(tab jsonb, column_name text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM jsonb_array_elements(__KN__.foreign_keys(tab)) k
     WHERE k->'columns' ? column_name);
$$;

/*
 * Every column that looks like it points somewhere, with whether it is already
 * tied down.
 *
 * Tied columns are attacked too. Skipping them would mean that the moment
 * somebody adds the foreign key this asked for, the attack stops running - and
 * the re-check could no longer watch it be refused, so it would report the fix
 * it requested as "could not confirm".
 *
 * `tied` decides what is reported, never what is attempted.
 */
CREATE OR REPLACE FUNCTION __KN__.candidates(tables jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  found jsonb := '[]'::jsonb;
  tab jsonb;
  col jsonb;
  parent jsonb;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(tables) LOOP
    CONTINUE WHEN __KN__.keeps_history(tab->>'name');
    FOR col IN SELECT * FROM jsonb_array_elements(coalesce(tab->'columns', '[]'::jsonb)) LOOP
      parent := __KN__.parent_for(col, tables);
      CONTINUE WHEN parent IS NULL;
      found := found || jsonb_build_array(jsonb_build_object(
        'table', tab->>'name',
        'column', col->>'name',
        'parent', parent->>'table',
        'parentKey', parent->>'keyColumn',
        'type', parent->>'type',
        'tied', __KN__.already_tied(tab, col->>'name')));
    END LOOP;
  END LOOP;
  RETURN found;
END $$;

/* A value of the right type that is certainly not in the parent table. */
CREATE OR REPLACE FUNCTION __KN__.nobody(kind text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN lower(kind) = 'uuid' THEN '99999999-9999-4999-8999-999999999999'
    WHEN lower(kind) ~ '^(integer|bigint|smallint)' THEN '2147480000'
    WHEN lower(kind) ~ '^(numeric|decimal|real|double)' THEN '2147480000'
    ELSE 'kryptheon-nobody'
  END;
$$;

/*
 * Point a row at something that is not there, and see if it is taken.
 *
 * Run as the owner of the schema on purpose. The question is not who is
 * allowed to create an orphan - it is whether the database permits one to
 * exist at all, which is what decides whether a dropped connection can leave
 * one behind.
 */
CREATE OR REPLACE FUNCTION __KN__.orphan(source text, tables jsonb, seeded jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  findings jsonb := '[]'::jsonb;
  completed jsonb := '[]'::jsonb;
  not_tried jsonb := '[]'::jsonb;
  target jsonb;
  tab jsonb;
  key text;
  missing text;
  already integer;
  shape integer;
  row_ jsonb;
  statement text;
  landed boolean;
  refused text;
  named jsonb;
BEGIN
  FOR target IN SELECT * FROM jsonb_array_elements(__KN__.candidates(tables)) LOOP
    key := 'orphaned:' || (target->>'table') || ':' || (target->>'column');
    SELECT t INTO tab FROM jsonb_array_elements(tables) t WHERE t->>'name' = target->>'table';
    missing := __KN__.nobody(target->>'type');

    -- It only proves anything if the value really is absent from the parent.
    BEGIN
      EXECUTE 'SELECT 1 FROM ' || __KN__.always_quote(source) || '.'
        || __KN__.always_quote(target->>'parent') || ' WHERE '
        || __KN__.always_quote(target->>'parentKey') || '::text = '
        || quote_literal(missing) || ' LIMIT 1'
        INTO already;
    EXCEPTION WHEN OTHERS THEN
      not_tried := not_tried || jsonb_build_array(jsonb_build_object(
        'table', target->>'table', 'column', target->>'column',
        'why', 'could not look in ' || (target->>'parent') || ': ' || SQLERRM));
      CONTINUE;
    END;
    IF already IS NOT NULL THEN
      not_tried := not_tried || jsonb_build_array(jsonb_build_object(
        'table', target->>'table', 'column', target->>'column',
        'why', 'the test value was already in ' || (target->>'parent')));
      CONTINUE;
    END IF;

    SELECT (s->>'attempt')::integer INTO shape
      FROM jsonb_array_elements(coalesce(seeded, '[]'::jsonb)) s
     WHERE s->>'table' = target->>'table';
    shape := coalesce(shape, 0);

    BEGIN
      row_ := __KN__.row_for(source, tab, __KN__.user_c(), '9',
        jsonb_build_object(target->>'column', to_jsonb(missing)), shape);
      statement := __KN__.insert_statement(source, target->>'table', row_);
    EXCEPTION WHEN OTHERS THEN
      not_tried := not_tried || jsonb_build_array(jsonb_build_object(
        'table', target->>'table', 'column', target->>'column', 'why', SQLERRM));
      CONTINUE;
    END;

    landed := false;
    refused := NULL;
    BEGIN
      EXECUTE 'SET LOCAL statement_timeout = ' || quote_literal('15s');
      EXECUTE statement;
      landed := true;
      -- Raised on purpose, to undo the row that just landed. The block is a
      -- subtransaction; the fact that it landed is a variable and survives.
      RAISE EXCEPTION 'kryptheon: undoing the orphan' USING ERRCODE = 'KN001';
    EXCEPTION
      WHEN SQLSTATE 'KN001' THEN
        NULL;
      WHEN OTHERS THEN
        landed := false;
        refused := SQLERRM;
    END;
    PERFORM set_config('statement_timeout', '0', true);

    IF NOT landed AND coalesce(refused, '') !~* 'violates foreign key constraint' THEN
      -- Turned away by something other than referential integrity, so nothing
      -- was learned about whether an orphan can exist.
      not_tried := not_tried || jsonb_build_array(jsonb_build_object(
        'table', target->>'table', 'column', target->>'column', 'why', refused));
      CONTINUE;
    END IF;

    completed := completed || to_jsonb(key);
    -- Whether a key is supposedly there does not come into it. What is
    -- reported is what landed.
    IF landed THEN
      named := coalesce((SELECT jsonb_agg(c->>'name') FROM jsonb_array_elements(tab->'columns') c),
                        '[]'::jsonb);
      findings := findings || jsonb_build_array(jsonb_build_object(
        'kind', 'orphaned',
        'table', target->>'table',
        'column', target->>'column',
        'parent', target->>'parent',
        'parentKey', target->>'parentKey',
        'columns', named));
    END IF;
  END LOOP;

  RETURN jsonb_build_object('findings', findings, 'completed', completed, 'notTried', not_tried);
END $$;

-- --------------------------------------------------------------------------
-- The collision attack, and why this engine cannot run it.
--
-- "Can the same thing exist twice" is answered by two requests arriving at the
-- same instant: the second insert has to be in flight while the first
-- transaction is still open. A plpgsql function is one session, so it needs a
-- second one from inside the database.
--
-- MEASURED, ON A REAL HOST (scratchpad/dblinkrace.js)
--
--   dblink is available and this role may even create it. It cannot connect
--   back to its own database without a password - dbname alone, an empty
--   conninfo and a local socket all answer "password or GSSAPI delegated
--   credentials required". So the only way to open that second session is to
--   hold a credential, and the whole reason this engine exists is that no
--   credential ever moves.
--
-- So it is not run here. What matters is what that is called. An attack that
-- did not run is not a table that held, and reporting nothing would read as
-- safety - so every column that WOULD have been raced comes back as notTried,
-- by name, with the reason. The npx door still races them for real, because
-- Node has two connections and can.
--
-- The candidates are worked out here in full, identically to the other engine,
-- precisely so that the two can be compared: what was considered has to match
-- even when what was concluded cannot.
-- --------------------------------------------------------------------------

/*
 * Columns where two rows holding one value is a security problem rather than
 * an untidy spreadsheet.
 *
 * Anchored on the whole name on purpose. `token` is a credential; `token_id`,
 * `token_expires_at` and `has_token` are not, and matching loosely would put
 * three false alarms on screen for every real one.
 */
CREATE OR REPLACE FUNCTION __KN__.must_be_unique(column_name text, table_name text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    -- One secret matching two rows opens two different doors.
    WHEN column_name ~* '^(token|auth_token|access_token|refresh_token|reset_token|session_token|session_id|api_key|apikey|access_key|secret_key)$'
      THEN 'credential'
    -- A one-time code that can exist twice can be redeemed twice.
    WHEN column_name ~* '^(invite_code|invitation_code|coupon_code|promo_code|promotion_code|referral_code|voucher_code|redemption_code|activation_code|license_key|serial_key)$'
      THEN 'code'
    -- Two accounts answering to one login make "who is this" ambiguous, and
    -- password reset has to pick one of them. Only on a table that really is
    -- the account table: `customers` is left alone on purpose, because in half
    -- the apps it is a contact list where a shared office email is correct.
    WHEN column_name ~* '^(email|e_mail|username|user_name|handle|login)$'
     AND table_name ~* '^(users?|profiles?|accounts?|members?|auth_users|app_users|logins?)$'
      THEN 'identity'
    ELSE NULL
  END;
$$;

/*
 * Is this column already protected?
 *
 * Deliberately generous. A composite UNIQUE (org_id, email) counts, because
 * the same email in two different organisations is how multi-tenant apps are
 * supposed to work. A partial index counts, and so does an expression index on
 * lower(email). The cost is that a column merely mentioned in some other
 * index's WHERE clause also counts and gets skipped - an attack not run rather
 * than a false alarm raised, which is the right way round.
 */
CREATE OR REPLACE FUNCTION __KN__.covered_by_unique(tab jsonb, column_name text, indexes jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  word text := '(^|[^A-Za-z0-9_])'
    || regexp_replace(column_name, '([.*+?^${}()|\[\]\\])', '\\\1', 'g')
    || '([^A-Za-z0-9_]|$)';
  text_ text;
BEGIN
  FOR text_ IN
    SELECT c->>'definition' FROM jsonb_array_elements(coalesce(tab->'constraints', '[]'::jsonb)) c
     WHERE c->>'kind' IN ('u', 'p')
    UNION ALL
    SELECT i->>'definition' FROM jsonb_array_elements(coalesce(indexes, '[]'::jsonb)) i
     WHERE i->>'table_name' = tab->>'name'
  LOOP
    IF text_ ~ word THEN RETURN true; END IF;
  END LOOP;
  RETURN false;
END $$;

/* Every column where the same value twice would be somebody's problem. */
CREATE OR REPLACE FUNCTION __KN__.collision_candidates(tables jsonb, indexes jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  found jsonb := '[]'::jsonb;
  tab jsonb;
  col jsonb;
  expectation text;
BEGIN
  FOR tab IN SELECT * FROM jsonb_array_elements(tables) LOOP
    FOR col IN SELECT * FROM jsonb_array_elements(coalesce(tab->'columns', '[]'::jsonb)) LOOP
      expectation := __KN__.must_be_unique(col->>'name', tab->>'name');
      CONTINUE WHEN expectation IS NULL;
      found := found || jsonb_build_array(jsonb_build_object(
        'table', tab->>'name',
        'column', col->>'name',
        'expectation', expectation,
        'type', col->>'type',
        'covered', __KN__.covered_by_unique(tab, col->>'name', indexes)));
    END LOOP;
  END LOOP;
  RETURN found;
END $$;

/*
 * What this engine can say about "can the same thing exist twice".
 *
 * Nothing, and it says so by name. Reporting an empty result would be the one
 * mistake this product cannot afford: a column nobody tested reading as a
 * column that held.
 */
CREATE OR REPLACE FUNCTION __KN__.collide(source text, tables jsonb, indexes jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  not_tried jsonb := '[]'::jsonb;
  one jsonb;
  why constant text :=
    'this attack needs two requests at the same instant, and a second connection '
    'cannot be opened from inside the database without a credential - which this '
    'engine is never given. Run the command line scan to have it raced for real.';
BEGIN
  FOR one IN SELECT * FROM jsonb_array_elements(
    __KN__.collision_candidates(tables, indexes)) LOOP
    not_tried := not_tried || jsonb_build_array(jsonb_build_object(
      'table', one->>'table',
      'column', one->>'column',
      'why', why));
  END LOOP;

  RETURN jsonb_build_object(
    'findings', '[]'::jsonb,
    'completed', '[]'::jsonb,
    'notTried', not_tried);
END $$;
