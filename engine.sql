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
