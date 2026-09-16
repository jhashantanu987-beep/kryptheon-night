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

/** The name a stand-in for an outside table is given inside the copy. */
function stubNameFor(refSchema, refTable) {
  return 'kn_ext__' + refSchema + '__' + refTable;
}

/** Is this one of our stand-ins rather than something the customer wrote? */
function isStub(name) {
  return /^kn_ext__/.test(String(name));
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
      stub: stubNameFor(entry.schema, entry.table),
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
    indexes: await readIndexes(client, schema),
    external: external,
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
const IDENTITIES = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];

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
  const statements = [];

  await client.query('CREATE SCHEMA ' + quote(target));

  for (const table of plan.tables) {
    const columns = table.columns.map((column) => {
      const parts = [quote(column.name), column.type];
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
        const definition = rewriteExternalRefs(
          rewriteSchemaRefs(constraint.definition, plan.schema, target),
          plan.external,
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

  mustStayInside(statements, target);
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

  // The stand-ins exist only in the copy, by design. Comparing them against
  // an original that never had them would report every Supabase app as a
  // copy that came out wrong.
  const mine = (list) => list.filter((t) => !isStub(t.name));
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
  readExternalTargets: readExternalTargets,
  referenceIn: referenceIn,
  stubNameFor: stubNameFor,
  isStub: isStub,
  IDENTITIES: IDENTITIES,
  quote: quote,
  roleList: roleList,
};
