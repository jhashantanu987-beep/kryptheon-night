// Turning what the attack saw into something a person can act on.
//
// The detection is the easy tenth. A builder who cannot read code does not buy
// "crossed:customers:1" - they buy knowing their customer list is open, seeing
// it happen, and having one thing to paste that closes it.
//
// The rule everything here follows: never say more than was actually seen. If
// the attack read a table with an email column in it, say email. If it did not,
// do not reach for "personal details" because it sounds more urgent. A report
// that overstates once is a report nobody trusts again, and trust is the entire
// product - the re-check at the end is worth exactly as much as the first
// report was honest.

/* --------------------------------------------------------------------------
   What was in the table.
-------------------------------------------------------------------------- */

// Things that identify a person. Matched on whole words so that `company_name`
// counts and `renamed_at` does not.
const IDENTITY = [
  [/\b(email|e_mail|mail)\b/i, 'email addresses'],
  [/\b(phone|mobile|contact_number|telephone)\b/i, 'phone numbers'],
  [/\b(full_name|first_name|last_name|given_name|surname|name)\b/i, 'names'],
  [/\b(address|street|city|postcode|zip|pincode)\b/i, 'addresses'],
  [/\b(dob|date_of_birth|birth_date|birthday)\b/i, 'dates of birth'],
];

// Things that are worse than identifying - they let somebody act as the person,
// or take money.
const SECRETS = [
  [/\b(password|passwd|pass_hash|password_hash)\b/i, 'passwords'],
  [/\b(token|api_key|apikey|secret|private_key|access_key)\b/i, 'access tokens'],
  [/\b(card|card_number|cvv|iban|account_number|upi)\b/i, 'payment details'],
];

const MONEY = [/\b(amount|total|price|balance|salary|revenue|invoice)\b/i, 'amounts of money'];

function matched(columns, table) {
  const names = columns || [];
  const found = [];
  for (const [pattern, label] of table) {
    if (names.some((column) => pattern.test(String(column)))) found.push(label);
  }
  return found;
}

/** What a table holds, in the words a person would use. */
function readContents(columns) {
  const identity = matched(columns, IDENTITY);
  const secrets = matched(columns, SECRETS);
  const money = matched(columns, [MONEY]);
  return { identity: identity, secrets: secrets, money: money };
}

/** A list, written the way a person writes one. */
function listOf(items) {
  const list = items.filter(Boolean);
  if (!list.length) return '';
  if (list.length === 1) return list[0];
  return list.slice(0, -1).join(', ') + ' and ' + list[list.length - 1];
}

/* --------------------------------------------------------------------------
   How bad it is.
-------------------------------------------------------------------------- */

/**
 * Severity, decided by what could be read rather than by how it was read.
 *
 * Only two levels on purpose. A scale of five invites the reader to skim past
 * the bottom three, and everything the night shift reports is something that
 * should be fixed - there is no such thing as a low finding here.
 */
function severityOf(finding, contents) {
  if (finding.kind === 'writable') {
    // Deleting and rewriting are unrecoverable in a way that reading is not:
    // a leak is bad, but a customer table somebody emptied is gone. Being able
    // only to add rows is serious and not the same thing.
    const canDestroy = (finding.can || []).some((what) => what === 'delete' || what === 'change');
    return canDestroy ? 'CRITICAL' : 'HIGH';
  }
  if (finding.kind === 'duplicated') {
    // Judged by what the duplicate lets somebody do, not by what else sits in
    // the table. A second row holding the same session token is critical even
    // if the table has nothing personal in it at all.
    if (finding.expectation === 'credential') return 'CRITICAL';
    if (finding.expectation === 'identity') return 'CRITICAL';
    return 'HIGH';
  }
  if (contents.secrets.length) return 'CRITICAL';
  if (contents.identity.length) return 'CRITICAL';
  return 'HIGH';
}

/* --------------------------------------------------------------------------
   Saying it.
-------------------------------------------------------------------------- */

/**
 * Why the door was open - and these two are genuinely different problems.
 *
 * Row level security switched off is an oversight. Switched on with a policy
 * that lets everybody through is worse, because the dashboard shows the table
 * as protected and the person has already been told they are safe. Saying which
 * one it is saves them looking in the wrong place.
 */
function causeOf(finding) {
  if (finding.kind === 'writable') {
    if (finding.rlsEnabled) {
      return {
        short: 'the rule on it allows writes as well as reads',
        long:
          'The table has row level security switched on, but the rule attached ' +
          'to it covers every command rather than only reading - so the same ' +
          'rule that lets people see the rows also lets them change them.',
      };
    }
    return {
      short: 'row level security was never switched on',
      long:
        'Row level security has never been switched on for this table. Supabase ' +
        'grants insert, update and delete on the public schema by default, and ' +
        'row level security is what takes them back - so until it is on, those ' +
        'permissions are simply in force.',
    };
  }
  if (finding.isView) {
    // The one people are caught by, because everything looks right. The table
    // is protected, the policy is correct, the dashboard is green - and the
    // view hands the rows out anyway.
    return {
      short: 'a view reads with its creator\'s rights, not the visitor\'s',
      long:
        'This is a view, and a view runs as whoever created it unless it is ' +
        'told otherwise. So any row level security on the tables underneath is ' +
        'checked against the creator, not against the person asking - and the ' +
        'rules you wrote on those tables do not apply here at all.',
    };
  }
  if (finding.kind === 'duplicated') {
    return {
      short: 'nothing in the database makes it unique',
      long:
        'There is no unique constraint and no unique index on this column, so ' +
        'the database has no way to refuse the second one. Checking in your app ' +
        'code before inserting does not close this: between the check and the ' +
        'insert, the other request has already been accepted.',
    };
  }
  if (finding.rlsEnabled) {
    return {
      short: 'the rule that guards it lets everybody through',
      long:
        'The table has row level security switched on, so it looks protected, ' +
        'but the rule attached to it allows every request. That is why nothing ' +
        'in your dashboard flags it.',
    };
  }
  return {
    short: 'it has no protection switched on at all',
    long:
      'Row level security has never been switched on for this table, so every ' +
      'rule you might have written elsewhere does not apply to it.',
  };
}

/** What a caller could do, written the way a person would say it. */
const WRITE_WORDS = { add: 'add rows to', change: 'change rows in', delete: 'delete rows from' };

function headlineFor(finding) {
  if (finding.kind === 'writable') {
    // Worst first, because the headline is often all that gets read.
    const order = ['delete', 'change', 'add'];
    const does = order.filter((what) => (finding.can || []).includes(what)).map((what) => WRITE_WORDS[what]);
    return (finding.who === 'anyone' ? 'Anyone' : 'Any signed-in customer') + ' can ' +
      listOf(does) + ' your ' + finding.table + ' table.';
  }
  if (finding.kind === 'duplicated') {
    return 'Your ' + finding.table + ' table lets the same ' + finding.column + ' exist twice.';
  }
  if (finding.kind === 'exposed') {
    return 'Your ' + finding.table + ' ' + (finding.isView ? 'view' : 'table') + ' can be read by anyone.';
  }
  // The table name goes in front of the sentence rather than inside it. Put
  // inside, a table called `customers` produced "One customer can read another
  // customer's customers", which is the kind of line that loses a reader.
  return 'Your ' + finding.table + ' table lets one customer read another one\'s rows.';
}

/** What a duplicate of this particular column actually costs the person. */
const COST_OF_A_DUPLICATE = {
  credential: 'A credential that matches more than one row means one secret opens more than one account.',
  identity: 'Two accounts can answer to the same login, and a password reset has to guess which one to send.',
  code: 'A one-time code that can exist twice can be redeemed twice.',
};

function bodyFor(finding, contents) {
  const holds = listOf(contents.secrets.concat(contents.identity, contents.money));
  const rowWord = finding.readable === 1 ? 'row' : 'rows';

  if (finding.kind === 'writable') {
    const holds = listOf(contents.secrets.concat(contents.identity, contents.money));
    const who = finding.who === 'anyone'
      ? 'Without logging in and without an account, I '
      : 'Signed in as one of your customers, I ';
    const did = [];
    if ((finding.can || []).includes('add')) did.push('added a row');
    if ((finding.can || []).includes('change')) {
      did.push('changed ' + (finding.changed.change || 1) + " of another customer's rows");
    }
    if ((finding.can || []).includes('delete')) {
      did.push('deleted ' + (finding.changed.delete || 1) + " of another customer's rows");
    }
    // Said immediately, because "I deleted your rows" is a sentence that stops
    // somebody reading, and they need the next line more than the first.
    return who + listOf(did) + ' on a copy of your app' +
      (holds ? ', in a table holding ' + holds : '') +
      '. Every one of those was undone straight away - nothing on the copy was ' +
      'kept, and your live app was never touched.';
  }

  if (finding.kind === 'duplicated') {
    // Said as what was done, not as what it implies. Two connections, one
    // moment, both accepted, and here is the count afterwards.
    return (
      'I opened two connections to a copy of your app and inserted the same ' +
      finding.column + ' from both at the same moment. Both were accepted, so there are ' +
      'now ' + finding.copies + ' rows holding the identical value. ' +
      (COST_OF_A_DUPLICATE[finding.expectation] || '')
    ).trim();
  }

  if (finding.kind === 'exposed') {
    return (
      'Anyone on the internet, without logging in and without an account, can read ' +
      'this table. I did it myself just now and got back ' + finding.readable + ' ' + rowWord +
      (holds ? ', including ' + holds : '') + '.'
    );
  }
  return (
    'Signed in as one customer, I asked for another customer\'s rows and got ' +
    finding.readable + ' of them back' + (holds ? ', including ' + holds : '') +
    '. Every customer you have can do this to every other customer.'
  );
}

/**
 * The thing they paste.
 *
 * Written to the tool they already use, which means it has to carry its own
 * context - the assistant on the other end has not seen any of this. It names
 * the table, says what is wrong in terms of the code rather than the symptom,
 * and asks for the same mistake to be swept up elsewhere, because it is almost
 * never in only one place.
 */
/** Wraps one paragraph to a width that reads in a chat box and a terminal. */
function wrapTo(text, width) {
  const words = String(text).split(/\s+/);
  const out = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > width) {
      out.push(current.trim());
      current = word;
    } else {
      current = (current + ' ' + word).trim();
    }
  }
  if (current) out.push(current.trim());
  return out;
}

function fixPromptFor(finding) {
  const cause = causeOf(finding);
  const owner = finding.owner ? '"' + finding.owner + '"' : 'the column that says who each row belongs to';

  const lines = finding.kind === 'writable'
    ? [
      'My app has a security problem.',
      '',
      'The "' + finding.table + '" table can be written to by ' +
        (finding.who === 'anyone' ? 'anyone who is not logged in' : 'any signed-in user, including other users rows') +
        ', because ' + cause.short + '. I proved it: I ' +
        (finding.can || []).map((what) => ({ add: 'added a row', change: 'changed rows', delete: 'deleted rows' })[what])
          .join(', ') + '.',
      '',
      'Switch row level security on for this table, then write separate rules for ' +
        'reading, inserting, updating and deleting. A rule written FOR SELECT does ' +
        'not cover writes, and a rule written FOR ALL covers far more than reading.',
      '',
      'For insert and update, use WITH CHECK comparing ' + owner +
        ' to the id of the signed-in user, so nobody can write a row under somebody ' +
        "else's name.",
      '',
      'Then check every other table for the same thing - a table with no row level ' +
        'security on it is writable by default.',
    ]
    : finding.kind === 'duplicated'
    ? [
      'My app has a security problem.',
      '',
      'Two rows in the "' + finding.table + '" table can hold the same "' + finding.column +
        '". I proved it by inserting the same value from two connections at the same ' +
        'moment, and both were accepted.',
      '',
      'Add a unique constraint on "' + finding.table + '"."' + finding.column +
        '" in the database itself. Checking in application code before inserting is not ' +
        'enough - between the check and the insert, the other request has already gone in.',
      '',
      // Said because the obvious fix is wrong for multi-tenant apps, and being
      // told to drop a legitimate design would cost them more than the bug.
      'If the same value is allowed to repeat for different owners, make the constraint ' +
        'cover both columns together rather than leaving it off.',
      '',
      'Then look for the same missing constraint on every other table and fix those too.',
    ]
    : finding.isView
      ? [
        'My app has a security problem.',
        '',
        'The "' + finding.table + '" view can be read by anyone who is not logged in. ' +
          'A view runs with the rights of whoever created it, so the row level security ' +
          'on the tables underneath is never checked against the person asking.',
        '',
        'Fix it by recreating the view with security_invoker set on, so it runs as the ' +
          'visitor and the rules on the underlying tables apply - and make sure those ' +
          'tables actually have those rules.',
        '',
        'Then check every other view in the app for the same thing.',
      ]
      : [
        'My app has a security problem.',
        '',
        'The "' + finding.table + '" table ' +
          (finding.kind === 'exposed'
            ? 'can be read by anyone who is not logged in, because ' + cause.short + '.'
            : 'lets one signed-in user read rows belonging to a different user, because ' + cause.short + '.'),
        '',
        'Fix it so a person can only read their own rows: compare ' + owner +
          ' against the id of the signed-in user, and make sure logged-out visitors get nothing.',
        '',
        'Then look for the same mistake on every other table and fix those too.',
      ];
  // Wrapped here rather than by whoever prints it: this text is pasted into a
  // chat box as often as it is read in a terminal, and an unwrapped paragraph
  // is a wall in both.
  return lines
    .map((paragraph) => (paragraph ? wrapTo(paragraph, 72) : ['']))
    .reduce((all, part) => all.concat(part), [])
    .join('\n');
}

/** Everything the report needs about one thing the attack found. */
function describe(finding) {
  const contents = readContents(finding.columns);
  const cause = causeOf(finding);
  return {
    severity: severityOf(finding, contents),
    table: finding.table,
    kind: finding.kind,
    // Carried through because a table can have two different columns that each
    // accept a duplicate, and the re-check tells one finding from another by
    // what it is about. Without the column they would share an identity and
    // fixing one would look like fixing both.
    column: finding.column,
    expectation: finding.expectation,
    headline: headlineFor(finding, contents),
    body: bodyFor(finding, contents),
    cause: cause.long,
    who: finding.who,
    can: finding.can,
    proof: finding.kind === 'duplicated'
      ? 'I created ' + finding.copies + ' rows in "' + finding.table + '" holding the same ' +
        finding.column + '.'
      : 'I read ' + finding.readable + ' ' + (finding.readable === 1 ? 'row' : 'rows') +
        ' from "' + finding.table + '" that should not have been readable.',
    fixPrompt: fixPromptFor(finding),
    contents: contents,
  };
}

/** The whole report, in the order a person should read it. */
function describeAll(findings) {
  // A table anyone can read is also, necessarily, a table one customer can read
  // of another. Reporting both puts the same table on screen twice and turns
  // two problems into a list of three that reads like a mistake. The public one
  // is kept, and it carries the rest.
  const raw = findings || [];
  const publiclyOpen = new Set(raw.filter((f) => f.kind === 'exposed').map((f) => f.table));
  const described = raw
    .filter((f) => !(f.kind === 'crossed' && publiclyOpen.has(f.table)))
    .map((f) =>
      Object.assign(describe(f), {
        alsoCrossed:
          f.kind === 'exposed' && raw.some((o) => o.kind === 'crossed' && o.table === f.table),
      }),
    );
  for (const item of described) {
    if (item.alsoCrossed) {
      item.body += ' Your signed-in customers can read each other\'s rows for the same reason.';
    }
  }
  // Worst first, and within that the ones open to the whole internet before the
  // ones that need an account, and those before the ones that need two requests
  // to arrive together.
  // Writes above reads: a table somebody emptied is worse than one they read.
  const byKind = { writable: 0, exposed: 1, crossed: 2, duplicated: 3 };
  const rank = (d) => (d.severity === 'CRITICAL' ? 0 : 1) * 10 + (byKind[d.kind] === undefined ? 9 : byKind[d.kind]);
  return described.sort((a, b) => rank(a) - rank(b));
}

/** What is printed when a run finds nothing. Silence would read as a failure. */
function allClearLines(attacksRun) {
  // Nothing attacked is not the same as nothing got through. The callers all
  // stop before this now, but the sentence is the one thing in the product
  // that must never be printed by accident, so it guards itself too.
  if (!attacksRun) {
    return ['', '  I did not manage to attack anything, so there is nothing to report.', ''];
  }
  return [
    '',
    '  Nothing got through.',
    '',
    '  I ran ' + attacksRun + ' ' + (attacksRun === 1 ? 'attack' : 'attacks') + ' against a copy of your app',
    '  and every one of them was refused. Your data held.',
    '',
  ];
}

module.exports = {
  readContents: readContents,
  severityOf: severityOf,
  causeOf: causeOf,
  describe: describe,
  describeAll: describeAll,
  fixPromptFor: fixPromptFor,
  allClearLines: allClearLines,
  listOf: listOf,
};
