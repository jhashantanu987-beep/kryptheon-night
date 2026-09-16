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
// What is deliberately not copied: data (none of it, ever - that is the whole
// promise), triggers, views and functions. Unique indexes ARE copied, because
// they decide whether the same thing can exist twice - an app that enforces
// uniqueness with CREATE UNIQUE INDEX rather than a UNIQUE constraint would
// otherwise arrive at the copy with none of it, and be reported as broken for
// having got it right. Data being absent is the point; the rest is noted and
// will matter when the Scale and Interruption attacks arrive.

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
            pg_get_expr(d.adbin, d.adrelid) AS default_expr
       FROM pg_attribute a
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
async function readPolicies(client, schema) {
  const { rows } = await client.query(
    `SELECT tablename AS table_name,
            policyname AS name,
            permissive,
            roles,
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

/** Who was granted what. A policy is irrelevant if the grant is not there. */
async function readGrants(client, schema) {
  const { rows } = await client.query(
    `SELECT table_name, grantee, privilege_type
       FROM information_schema.role_table_grants
      WHERE table_schema = $1
        AND grantee IN ('anon', 'authenticated', 'service_role', 'PUBLIC')
      ORDER BY table_name, grantee, privilege_type`,
    [schema],
  );
  return rows;
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

    for (const constraint of constraints) {
      // A foreign key pointing outside this schema cannot be rebuilt as
      // written, and quietly dropping it would change what seeding is allowed
      // to insert.
      if (constraint.kind === 'f' && !constraint.definition.includes(schema + '.')) {
        unsupported.push(
          table.name + '.' + constraint.name + ' points outside the schema: ' + constraint.definition,
        );
      }
    }

    built.push({
      name: table.name,
      rlsEnabled: table.rls_enabled,
      rlsForced: table.rls_forced,
      columns: columns,
      constraints: constraints,
    });
  }

  return {
    schema: schema,
    tables: built,
    policies: await readPolicies(client, schema),
    grants: await readGrants(client, schema),
    indexes: await readIndexes(client, schema),
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
 * Builds the schema again, in a database we own.
 *
 * Order matters: tables, then constraints, then grants, then policies. A policy
 * cannot be created before the table it guards, and a grant given after a
 * policy would widen access the original did not have.
 */
async function writeSchema(client, plan, target, options) {
  const opts = options || {};
  const authSchema = opts.authSchema || 'auth';
  const statements = [];

  await client.query('CREATE SCHEMA ' + quote(target));

  for (const table of plan.tables) {
    const columns = table.columns.map((column) => {
      const parts = [quote(column.name), column.type];
      const fallback = rewriteSchemaRefs(column.default_expr, plan.schema, target);
      if (fallback) parts.push('DEFAULT ' + fallback);
      if (column.not_null) parts.push('NOT NULL');
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
        const definition = rewriteSchemaRefs(constraint.definition, plan.schema, target);
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

  // The roles PostgREST switches into, and the auth.uid() the policies read.
  // Without these the policies would fail to create, or would create and then
  // never match anything - which would look like a very secure application.
  statements.push('CREATE SCHEMA IF NOT EXISTS ' + quote(authSchema));
  statements.push(
    'CREATE OR REPLACE FUNCTION ' + quote(authSchema) + '.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ ' +
      "SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid $$",
  );
  statements.push('GRANT USAGE ON SCHEMA ' + quote(authSchema) + ' TO anon, authenticated');
  statements.push('GRANT USAGE ON SCHEMA ' + quote(target) + ' TO anon, authenticated');

  for (const grant of plan.grants) {
    const who = grant.grantee === 'PUBLIC' ? 'PUBLIC' : quote(grant.grantee);
    statements.push(
      'GRANT ' + grant.privilege_type + ' ON ' + quote(target) + '.' + quote(grant.table_name) + ' TO ' + who,
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
    if (policy.qual) parts.push('USING (' + policy.qual + ')');
    if (policy.with_check) parts.push('WITH CHECK (' + policy.with_check + ')');
    statements.push(parts.join(' '));
  }

  for (const statement of statements) {
    await client.query(statement);
  }
  return statements;
}

/* --------------------------------------------------------------------------
   Checking the copy is the original.
-------------------------------------------------------------------------- */

/**
 * Where a copy differs from what it was copied from.
 *
 * Anything here means the verdicts that follow are about the wrong database,
 * so this returning empty is a precondition for attacking, not a nicety.
 */
function diffSchemas(source, copy) {
  const differences = [];

  const named = (list) => list.map((t) => t.name).sort().join(', ');
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

    const shape = (t) => t.columns.map((c) => c.name + ' ' + c.type + (c.not_null ? ' NOT NULL' : '')).join(' | ');
    if (shape(table) !== shape(mirror)) {
      differences.push(table.name + ' columns differ:\n      ' + shape(table) + '\n      ' + shape(mirror));
    }
  }

  // Uniqueness decides whether the Collision attack has anything to report, so
  // a unique index that failed to come across has to be caught here rather
  // than turn into a confident finding about a table that was actually fine.
  // The schema name is stripped before comparing, since it differs by design.
  const indexText = (plan) =>
    (plan.indexes || [])
      .map((index) => String(index.definition).split(quote(plan.schema) + '.').join('').split(plan.schema + '.').join(''))
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

  // The policies matter most, so they are compared word for word.
  const asText = (list, schema) =>
    list
      .map((p) =>
        [p.table_name, p.name, p.permissive, roleList(p.roles).join('+'), p.cmd, p.qual, p.with_check]
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
  writeSchema: writeSchema,
  diffSchemas: diffSchemas,
  readPolicies: readPolicies,
  readIndexes: readIndexes,
  quote: quote,
  roleList: roleList,
};
