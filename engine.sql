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
    'policies', __KN__.read_policies(source),
    'grants', __KN__.read_grants(source),
    'indexes', __KN__.read_indexes(source),
    'views', __KN__.read_views(source),
    'viewGrants', __KN__.read_view_grants(source)
  );
END $$;
