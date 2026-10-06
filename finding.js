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
  // `\b` treats "_" as part of a word, so display_name never matched `name` -
  // found on a blind test, where a public profiles table was reported as
  // holding nothing in particular. The compound names are listed instead.
  [/\b(full_name|first_name|last_name|given_name|surname|name|display_name|username|user_name|nickname|screen_name)\b/i, 'names'],
  [/\b(address|street|city|postcode|zip|pincode)\b/i, 'addresses'],
  [/\b(dob|date_of_birth|birth_date|birthday)\b/i, 'dates of birth'],
];

// Things that are worse than identifying - they let somebody act as the person,
// or take money.
const SECRETS = [
  // `\b` counts "_" as a letter, so these missed every compound name - found
  // on a blind test: integration_token, access_token and signing_secret, all
  // readable by anyone, and the report named none of them. A name that ENDS
  // in the secret word is the secret; token_expires_at is only about one.
  // Singular only: `tokens` and `input_tokens` count what an AI call used -
  // found on the next blind test, where api_usage.tokens (an integer) was
  // named as a secret.
  [/\b(password|passwd|pass_hash|password_hash)\b|(^|_)(password|passwd|pwd|password_hash)$/i, 'passwords'],
  [/\b(token|api_key|apikey|secret|private_key|access_key)\b|(^|_)(token|secret|(api|private|access|secret|signing|service|encryption)_?key)$/i, 'access tokens and secrets'],
  [/\b(card|card_number|cvv|iban|account_number|upi)\b/i, 'payment details'],
  // A code that grants something: whoever reads a moderator_code can become a
  // moderator. Found on a blind test, added straight in production and readable
  // by anyone - reported only as "2 rows".
  [/^(?:\w+_)?(moderator|invite|invitation|access|reset|verification|recovery|admin|join|auth|login|magic|security|otp)_code$|^(otp|pin)$/i, 'secret codes'],
];

// Who holds power in the app. Not a secret in itself, but a list of exactly
// which accounts are worth attacking.
const PRIVILEGE = [/^(is_admin|is_superuser|is_super_admin|is_staff|is_moderator|is_owner|role|roles|permissions)$/i, 'who is an admin'];

const MONEY = [/\b(amount|total|price|balance|salary|revenue|invoice)\b/i, 'amounts of money'];

// Each kind named with the columns that showed it: "secret codes
// (moderator_code)" can be found in the table; "secret codes" has to be
// looked for.
function matched(columns, table) {
  const names = (columns || []).map(String);
  const found = [];
  for (const [pattern, label] of table) {
    const hits = names.filter((column) => pattern.test(column));
    if (hits.length) found.push(label + ' (' + hits.join(', ') + ')');
  }
  return found;
}

/** What a table holds, in the words a person would use. */
function readContents(columns) {
  const identity = matched(columns, IDENTITY);
  const secrets = matched(columns, SECRETS);
  const money = matched(columns, [MONEY]);
  const privilege = matched(columns, [PRIVILEGE]);
  return { identity: identity, secrets: secrets, money: money, privilege: privilege };
}

/** Everything worth naming, worst first. */
function heldIn(contents) {
  return contents.secrets.concat(contents.identity, contents.privilege || [], contents.money);
}

/** A list, written the way a person writes one. */
function listOf(items) {
  const list = items.filter(Boolean);
  if (!list.length) return '';
  if (list.length === 1) return list[0];
  return list.slice(0, -1).join(', ') + ' and ' + list[list.length - 1];
}

/** One of a table's things: workspaces -> workspace, companies -> company. */
/** A role, quoted, with its article: a "viewer", an "analyst". */
function aRole(role) {
  return (/^[aeiou]/i.test(String(role)) ? 'an "' : 'a "') + role + '"';
}

/** The first letter made a capital, for the start of a sentence. */
function capital(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** The same, with its article: a workspace, an organization. */
function aOne(table) {
  const one = oneOf(table);
  return (/^[aeiou]/i.test(one) ? 'an ' : 'a ') + one;
}

function oneOf(table) {
  return String(table || 'team').replace(/ies$/, 'y').replace(/s$/, '');
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
  if (finding.kind === 'recursive') {
    // Nothing leaks and nothing is written: the request fails. Serious,
    // because the app is broken for whoever it fails for, but not a break-in.
    return 'HIGH';
  }
  if (finding.kind === 'role' || finding.kind === 'teamread' || finding.kind === 'bucket') {
    // Something to check, never a confirmed break: whether a viewer may edit,
    // or a bucket may be public, is the owner's decision. So never CRITICAL.
    return 'HIGH';
  }
  if (finding.kind === 'privileged') {
    // Not proven, so never CRITICAL: this is a reach that exists, not a break
    // that was demonstrated. A function anon can call that also writes is worth
    // more attention than one that only reads, but both stay HIGH and both
    // carry "verification required" - the person has to say whether the anon
    // call was intended.
    return 'HIGH';
  }
  if (finding.kind === 'orphaned') {
    // Nothing is exposed and nothing is destroyed, so this is not the same
    // order of thing as a table anyone can empty. It stays serious because
    // the data it strands is data somebody asked to have deleted.
    return 'HIGH';
  }
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
    // Critical only while this column could be the login itself. When the
    // database has Supabase's auth.users, sign-in goes through that table,
    // which keeps every email unique - so a duplicate here is a copy that
    // disagrees with itself, not two accounts sharing one login. Found on a
    // real app: the report said "two accounts can answer to the same login"
    // about a profiles table the login never read.
    if (finding.expectation === 'identity') return finding.loginElsewhere ? 'HIGH' : 'CRITICAL';
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
  if (finding.kind === 'recursive') {
    return {
      short: 'a rule on it looks the same table up again',
      long:
        'A row level security rule on this table checks something by reading ' +
        'this same table - usually "is this person a member?" asked of the ' +
        'members table itself. Reading the table means applying the rule, and ' +
        'applying the rule means reading the table, so Postgres stops the ' +
        'request with an error instead of going round forever. Any other ' +
        'table whose rule asks this one fails the same way.',
    };
  }
  if (finding.kind === 'orphaned') {
    return {
      short: 'nothing in the database ties the two tables together',
      long:
        'There is no foreign key between these two tables, so the database has '+
        'no idea they are related. It will not refuse a row that points at '+
        'nothing, it will not stop somebody being deleted while their rows are '+
        'still here, and it will never find these rows again afterwards.',
    };
  }
  if (finding.kind === 'writable') {
    if (finding.rlsEnabled) {
      // Which rule let it through, from what is actually on the table rather
      // than from an assumption.
      //
      // This branch used to say, of every writable table with row level
      // security on, that its rule "covers every command rather than only
      // reading". Measured against a table whose only policy was written FOR
      // INSERT, that sentence was false twice over: the rule covered one
      // command, and there was no rule letting anybody read at all. The
      // finding was proved; the reason was invented. A report that overstates
      // once is believed never again, so the reason is now read, not guessed.
      const rules = (finding.rules || []).map((rule) => String(rule).toUpperCase());
      const WRITTEN_FOR = { add: 'INSERT', change: 'UPDATE', 'delete': 'DELETE' };
      const IN_WORDS = { INSERT: 'adding rows', UPDATE: 'changing rows', DELETE: 'deleting rows' };
      const named = [];
      for (const move of finding.can || []) {
        const command = WRITTEN_FOR[move];
        if (command && rules.includes(command) && !named.includes(command)) named.push(command);
      }

      if (rules.includes('ALL')) {
        return {
          short: 'the rule on it covers every command, not only reading',
          long:
            'The table has row level security switched on, but the rule attached ' +
            'to it is written FOR ALL - so the same rule that decides who may ' +
            'see a row also decides who may add, change and delete one, and it ' +
            'is letting this through.',
        };
      }

      if (named.length) {
        return {
          short: 'the rule you wrote for ' + listOf(named.map((c) => IN_WORDS[c])) +
            ' lets everybody through',
          long:
            'The table has row level security switched on, and there is a rule on ' +
            'it written for ' + listOf(named.map((c) => IN_WORDS[c])) + '. That ' +
            'rule is the one letting this through: it does not check who is ' +
            'asking, so it accepts the request from a stranger exactly as it ' +
            'would from the person the row belongs to.',
        };
      }

      // Row level security on, and no permissive rule that names this write.
      // It should not have been possible, and saying which rule did it would
      // be inventing one. What is certain is what was done, and that is all
      // this says.
      return {
        short: 'row level security is on, and something let this through anyway',
        long:
          'The table has row level security switched on, and none of the rules on ' +
          'it are written for this kind of write - so this should have been ' +
          'refused and was not. Check whether the role your app connects as owns ' +
          'the table or has BYPASSRLS, because either of those goes round every ' +
          'rule you have written.',
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

/**
 * The error a looping rule produces, as Postgres words it. A rule that reads
 * its own table directly is caught as recursion and named; one that reaches
 * it through a helper function runs out of stack, and Postgres names nothing.
 */
function loopError(finding) {
  return finding.deep
    ? '"stack depth limit exceeded"'
    : '"infinite recursion detected in policy for relation ' + finding.table + '"';
}

/** Who a looping rule fails for, said the way the headline and body need it. */
function loopVictims(finding) {
  const callers = finding.callers || [];
  if (callers.includes('anyone') && callers.includes('signed-in')) return 'everyone, signed in or not,';
  if (callers.includes('anyone')) return 'visitors who are not logged in';
  return 'signed-in users';
}

function headlineFor(finding) {
  if (finding.kind === 'recursive') {
    return 'A rule on your ' + finding.table + ' table refers to itself, so ' + loopVictims(finding) +
      ' get an error instead of data.';
  }
  if (finding.kind === 'orphaned') {
    return 'Your ' + finding.table + ' table can point at a ' +
      finding.parent.replace(/s$/, '') + ' that does not exist.';
  }
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
  if (finding.kind === 'privileged') {
    return 'Anyone on the internet can call your ' + finding.fn + ' function, and it runs with full rights.';
  }
  if (finding.kind === 'role' && finding.takeover) {
    return capital(aRole(finding.who)) + ' in ' + aOne(finding.parent) + ' can take another member\'s place in your ' +
      finding.table + ' table - and with it their role.';
  }
  if (finding.kind === 'role') {
    const order = ['delete', 'change', 'add'];
    const does = order.filter((what) => (finding.can || []).includes(what)).map((what) => WRITE_WORDS[what]);
    return capital(aRole(finding.who)) + ' in ' + aOne(finding.parent) + ' can ' + listOf(does) + ' your ' +
      finding.table + ' table.';
  }
  if (finding.kind === 'teamread') {
    return capital(aRole(finding.who)) + ' in ' + aOne(finding.parent) + ' can read your ' + finding.table +
      ' table, which holds ' + listOf(finding.secrets || []) + '.';
  }
  if (finding.kind === 'bucket' && finding.noRule) {
    return 'Your ' + finding.table + ' storage bucket is public, and its name says its files are not for everyone.';
  }
  if (finding.kind === 'bucket') {
    return 'Your ' + finding.table + ' storage bucket is public, but a rule says only some people may read it.';
  }
  if (finding.kind === 'exposed') {
    return 'Your ' + finding.table + ' ' + (finding.isView ? 'view' : 'table') + ' can be read by anyone.';
  }
  // The table name goes in front of the sentence rather than inside it. Put
  // inside, a table called `customers` produced "One customer can read another
  // customer's customers", which is the kind of line that loses a reader.
  if (finding.tenant) return 'Your ' + finding.table + ' table lets a signed-in user read another organization\'s rows.';
  return 'Your ' + finding.table + ' table lets one customer read another one\'s rows.';
}

/** What a duplicate of this particular column actually costs the person. */
const COST_OF_A_DUPLICATE = {
  credential: 'A credential that matches more than one row means one secret opens more than one account.',
  identity: 'Two accounts can answer to the same login, and a password reset has to guess which one to send.',
  code: 'A one-time code that can exist twice can be redeemed twice.',
};

// Said instead of the login sentence when sign-in happens in auth.users.
const COST_OF_A_COPIED_IDENTITY =
  'Signing in is not affected: your app signs people in through auth.users, ' +
  'which keeps each email unique. But anything that looks a person up by this ' +
  'column can get two rows back and pick the wrong one.';

function costOf(finding) {
  if (finding.expectation === 'identity' && finding.loginElsewhere) return COST_OF_A_COPIED_IDENTITY;
  return COST_OF_A_DUPLICATE[finding.expectation] || '';
}

function bodyFor(finding, contents) {
  const holds = listOf(heldIn(contents));
  const rowWord = finding.readable === 1 ? 'row' : 'rows';

  if (finding.kind === 'recursive') {
    // Said as what happened to the requests, and then what it cost this
    // report: the tables behind the error could not be tested for leaks.
    const reads = finding.reads || [];
    const callers = finding.callers || [];
    const as = [];
    if (callers.includes('anyone')) as.push('a visitor who is not logged in');
    if (callers.includes('signed-in')) as.push('a signed-in user');
    const one = reads.length === 1;
    return (
      'Using ' + listOf(reads) + ' on a copy of your app as ' + as.join(' and as ') +
      ', every request was refused with ' + loopError(finding) +
      (finding.deep ? ' - a rule on ' + finding.table + ' calls a helper that reads ' + finding.table + ' again, which runs the rule again' : '') +
      '. Every page in your app that uses ' + (one ? 'that table' : 'those tables') +
      ' fails the same way for ' + loopVictims(finding).replace(/,$/, '') + '. It also means I could ' +
      'not test ' + (one ? 'it' : 'them') + ' for leaks - those attacks are listed at the end.'
    );
  }

  if (finding.kind === 'orphaned') {
    // Said as the thing a person will actually meet: a customer asks to be
    // deleted, and their rows are still here afterwards.
    return (
      'I added a row to ' + finding.table + ' naming a ' +
      finding.parent.replace(/s$/, '') + " that is not in your " + finding.parent +
      ' table, and it was accepted. So when one of them is deleted, the rows here ' +
      'stay behind pointing at nobody - and a signup or checkout that stops halfway ' +
      'leaves the same thing. The row I added was undone straight away.'
    );
  }

  if (finding.kind === 'writable') {
    const holds = listOf(heldIn(contents));
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

  if (finding.kind === 'role' && finding.takeover) {
    // Not a matter of taste like a viewer who may edit: taking somebody
    // else's membership is never what a role is for.
    const place = oneOf(finding.parent);
    return (
      'I put one of my fake people into the other one\'s ' + place + ' as ' + aRole(finding.who) +
      ' in ' + finding.via + '.' + finding.roleColumn + ' and, signed in as them, changed ' +
      finding.via + '.' + finding.personColumn + ' on the other person\'s own membership row to their own id - so ' +
      'they held that member\'s place and role, on a copy of your app. Before joining, they could not. It was ' +
      'undone straight away. A member taking over another member\'s row is never something a role should be able ' +
      'to do, even where members may edit some of a membership.'
    );
  }

  if (finding.kind === 'role') {
    // Said as what was done, and then whose decision it is: a viewer who may
    // edit is a hole in one app and the design of another.
    const did = [];
    const rows = (n) => n + (n === 1 ? ' row' : ' rows');
    if ((finding.can || []).includes('add')) did.push('added ' + rows((finding.changed || {}).add || 1));
    if ((finding.can || []).includes('change')) did.push('changed ' + rows((finding.changed || {}).change || 1));
    if ((finding.can || []).includes('delete')) did.push('deleted ' + rows((finding.changed || {}).delete || 1));
    const place = oneOf(finding.parent);
    // The roles below it that were tried first and could not, when there are
    // any: a role in the middle is named because the ones under it held.
    const below = (finding.below || []).map((r) => '"' + r + '"');
    return (
      'I put one of my fake people into the other one\'s ' + place + ' as ' + aRole(finding.who) +
      ' - ' + (below.length ? 'a role' : 'the lowest role') + ' in ' + finding.via + '.' + finding.roleColumn +
      ' - and, signed in as them, I ' + listOf(did) + ' in ' + finding.table + ' for that ' + place +
      ', on a copy of your app. Before joining, they could not.' +
      (below.length ? ' As ' + listOf(below).replace(/ and /, ' or ') + ' they could not either, and no rule on this ' +
        'table lists ' + aRole(finding.who).replace(/^an? /, '') + ' among the roles allowed to make that change.' : '') +
      ' Every one of those was undone straight away. Whether ' + aRole(finding.who) + ' may do this is your ' +
      'decision: if it is meant to, nothing needs fixing; if not, the rules on this table let them do more.'
    );
  }

  if (finding.kind === 'teamread') {
    // Said as what was read and by whom, and which roles below it could not:
    // a dispatcher seeing a key may be the design, a viewer rarely is.
    const place = oneOf(finding.parent);
    const n = finding.readable || 1;
    const below = (finding.below || []).map((r) => '"' + r + '"');
    return (
      'I put one of my fake people into the other one\'s ' + place + ' as ' + aRole(finding.who) + ' and, signed ' +
      'in as them, read ' + n + (n === 1 ? ' row' : ' rows') + ' of ' + finding.table + ' for that ' + place +
      ', on a copy of your app - including ' + listOf(finding.secrets || []) + '. Before joining, they could not.' +
      (below.length ? ' As ' + listOf(below).replace(/ and /, ' or ') + ' they could not read it either.' : '') +
      ' Nothing was changed. Whether ' + aRole(finding.who) + ' should see these is your decision: if not, a read ' +
      'rule on this table lets them.'
    );
  }

  if (finding.kind === 'bucket' && finding.noRule) {
    return (
      'In Supabase Storage the bucket "' + finding.bucket + '" is set to public, so anyone with a ' +
      'file\'s link can download it without logging in - the rules on storage.objects are not asked. ' +
      'No rule says who may read it, but its name says what it holds, and that does not sound like ' +
      'something for everyone. I only read the bucket\'s setting and its rules; I did not open or list ' +
      'any file. Whether it should be public is yours to say.'
    );
  }
  if (finding.kind === 'bucket') {
    // Said as what was read, never as a file taken: no file was opened.
    return (
      'In Supabase Storage the bucket "' + finding.bucket + '" is set to public, so anyone with a ' +
      'file\'s link can download it without logging in - the rules on storage.objects are not asked. ' +
      'You also wrote ' + ((finding.rules || []).length === 1 ? 'a rule' : 'rules') + ' saying who may read it (' +
      listOf(finding.rules || []) + '), so it was probably meant to be private. I only read the ' +
      'bucket\'s setting and its rules; I did not open or list any file. Whether it should be public ' +
      'is yours to say.'
    );
  }

  if (finding.kind === 'privileged') {
    // Said as what is true, not as what was done - nothing was executed. The
    // reach is real; whether it is a mistake is the person's to say, so the
    // wording asks rather than accuses.
    return (
      'This function is SECURITY DEFINER, so it runs as whoever created it, not ' +
      'as the visitor calling it - which means the row level security on the tables ' +
      'it touches is checked against the owner and skipped for the caller. It is ' +
      'granted to anon, the role a visitor with no account uses, so anyone on the ' +
      'internet can call it' +
      (finding.writes ? ' - and it writes to your data, so a caller can change rows the rules would otherwise protect.'
                       : ', reaching whatever it reads past the rules on those tables.') +
      ' I did not call it: whether an open function like this is intended is ' +
      'something only you can confirm.' +
      (finding.nullSlips
        ? ' Its first lines do check the caller\'s role - but with NOT IN or <>, and somebody with no role ' +
          'there gets NULL back, and NULL NOT IN (...) is not true: the IF never raises, so a signed-in ' +
          'stranger gets through as if they had passed.'
        : '') +
      (finding.hasFixedSearchPath ? ''
        : ' It also does not pin its search_path, so a caller can point the names ' +
          'inside it at their own objects.')
    );
  }
  if (finding.kind === 'duplicated') {
    // Said as what was done, not as what it implies. Two connections, one
    // moment, both accepted, and here is the count afterwards.
    return (
      'I opened two connections to a copy of your app and inserted the same ' +
      finding.column + ' from both at the same moment. Both were accepted, so there are ' +
      'now ' + finding.copies + ' rows holding the identical value. ' + costOf(finding)
    ).trim();
  }

  if (finding.kind === 'exposed') {
    // Two different proofs, said as two different things. The copy-based scan
    // signed in with the anon key and pulled the rows out; the outside check
    // (outside.js) asked the live app for the count alone and never pulled a
    // row, so it may not claim it did.
    if (finding.countOnly) {
      const many = finding.readable === 1 ? 'is 1 row' : 'are ' + finding.readable + ' rows';
      return (
        'Anyone on the internet, without logging in and without an account, can read ' +
        'this table. I asked your live app as a stranger and it let me - there ' + many +
        ' in it. I asked only for the count, so I never pulled a row out; a real ' +
        'attacker would have taken them.'
      );
    }
    return (
      'Anyone on the internet, without logging in and without an account, can read ' +
      // Read back the next morning, "just now" would be untrue: it was the
      // nightly run, hours earlier.
      'this table. ' + (finding.fromNight ? 'The nightly run did it on a copy and got back ' : 'I did it myself just now and got back ') +
      finding.readable + ' ' + rowWord +
      (holds ? ', including ' + holds : '') + '.'
    );
  }
  if (finding.tenant) {
    return (
      'Signed in as someone in a different organization, I asked for another organization\'s rows and got ' +
      finding.readable + ' of them back' + (holds ? ', including ' + holds : '') +
      '. Anyone with an account can read every organization\'s rows.'
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

/**
 * Whether the app signs people in through Supabase: any foreign key to
 * auth.users, or any rule that asks auth.uid() or auth.jwt(). Decided for the
 * whole app, not table by table. Found on a blind test: appointments points
 * at profiles, which points at auth.users - no key of its own and no rule
 * asking auth.uid(), so it was told the app "signs people in its own way"
 * when it plainly used Supabase's. Read from the original schema, not the
 * copy - the copy points those keys at a stand-in. A table missing from the
 * map is unknown, which the prompts treat as tied.
 */
function authTiesOf(plan) {
  const tables = (plan && plan.tables) || [];
  const keyed = tables.some((table) => (table.constraints || []).some((c) =>
    c.kind === 'f' && /references\s+"?auth"?\s*\.\s*"?users"?\s*\(/i.test(String(c.definition || ''))));
  const asked = ((plan && plan.policies) || []).some((policy) =>
    /\bauth\s*\.\s*(uid|jwt)\s*\(/i.test(String(policy.qual || '') + ' ' + String(policy.with_check || '')));
  return new Map(tables.map((table) => [table.name, keyed || asked]));
}

/**
 * The fix for a table no rule can tie to the signed-in user, or null when one
 * can. Two ways that happens. The app has its own login: found on a real app,
 * "compare the owner to the id of the signed-in user" cannot be done there -
 * auth.uid() is empty for everybody - and an assistant that writes it anyway
 * locks the app out of its own table. Or the table has no column saying whose
 * row it is - a waitlist, a contact form - so there is nothing to compare.
 */
// A column that says which organization a row belongs to. Such a table is
// not "nobody's" - its rows are a team's.
const TENANT_COLUMN = /^(org_id|organization_id|workspace_id|team_id|tenant_id|company_id)$/i;

function serverOnlyLines(finding) {
  const table = finding.table;
  let why;
  // Found on a fix test: api_usage has org_id, and the prompt said it had no
  // column saying whose row it is. The assistant applying it had to correct
  // the prompt; a less careful one would have locked the table away from the
  // members who use it.
  // A row an organization owns names its organization even when the column is
  // not called organization_id: the attack found which key it is.
  const team = finding.authTied !== false &&
    (finding.tenant ? finding.owner : (finding.columns || []).find((c) => TENANT_COLUMN.test(String(c))));
  const maker = finding.owner || finding.ownedBy;
  // A team's row that also says who made it - created_by beside workspace_id.
  // Found on a benchmark: the prompt said to compare created_by to auth.uid()
  // for reading, which hides every teammate's rows and breaks the shared
  // view the table exists for. Who made a row decides who may write it
  // under their name, not who may see it.
  if (team && !finding.tenant && finding.owned !== false && maker) {
    return [
      'Rows in "' + table + '" belong to a team ("' + team + '"), and "' + maker + '" only records who ' +
        'made each one. So reading should be decided by team membership: let a signed-in user read a ' +
        'row when they are a member of that row\'s "' + team + '" - checked through your membership ' +
        'table, or a helper function that asks it - and give logged-out visitors nothing. Do not ' +
        'compare "' + maker + '" to auth.uid() for reading: that hides teammates\' rows from each other ' +
        'and breaks the feature.',
      '',
      'Write separate rules for reading, inserting, updating and deleting. Inserting: WITH CHECK that ' +
        'the user is a member of the row\'s "' + team + '" AND "' + maker + '" = auth.uid(), so nobody ' +
        'writes a row under somebody else\'s name or into a team they are not in. Updating and ' +
        'deleting: the membership check in USING (and WITH CHECK for updating), and decide whether any ' +
        'member may do it or only the row\'s "' + maker + '" or an admin. If only your server writes ' +
        'this table, add no write rules at all.',
      '',
    ];
  }
  const tenant = (finding.tenant || finding.owned === false) && team;
  if (tenant) {
    return [
      'Rows in "' + table + '" belong to an organization ("' + tenant + '"), not to one person. So the ' +
        'rule should let a signed-in user in only when they are a member of that row\'s organization - ' +
        'checked through your membership table, or a helper function that asks it - and give logged-out ' +
        'visitors nothing.',
      '',
      'Write separate rules for reading, inserting, updating and deleting, each with that membership ' +
        'check (USING for reading, updating and deleting, WITH CHECK for inserting and updating), and ' +
        'decide whether every member should be able to write or only admins. If only your server ' +
        'writes this table, add no write rules at all.',
      '',
    ];
  }
  if (finding.authTied === false) {
    why = 'Nothing in "' + table + '" points at auth.users and no rule on it uses auth.uid(), so your ' +
      'app signs people in its own way. A rule comparing a column to the signed-in user cannot ' +
      'work here - auth.uid() is empty for everyone - and adding one would lock your own app out.';
  } else if (finding.owned === false) {
    why = '"' + table + '" has no column that says whose row it is, so a rule tying rows to the ' +
      'signed-in user has nothing to compare against.';
  } else {
    return null;
  }
  return [
    why,
    '',
    'If only your server reads and writes this table: keep row level security on, drop the rules ' +
      'that let everyone in, and add none for anon or authenticated. Have your server use the ' +
      'service_role key, which skips these rules - and keep that key on the server only, never ' +
      'in the browser or in the app\'s public code.',
    '',
    'If the browser needs to read or write part of it directly, tell me which part first, so we ' +
      'write the narrowest rule for exactly that.',
    '',
  ];
}

/**
 * The opening of a rules fix. "Switch row level security on" is said only
 * when it is off: told it about a table where it was already on, the person
 * looks for a switch that is already flipped and misses the rule that is the
 * real problem.
 */
function switchOn(finding) {
  return finding.rlsEnabled
    ? 'Row level security is already on for this table, so the rules on it are the problem: '
    : 'Switch row level security on for this table, then ';
}

/**
 * One prompt for everything wrong with one table's rules - read and write,
 * strangers and customers - because it is one rule to replace, not four.
 */
function groupPromptFor(members) {
  const lead = members.find((m) => m.kind === 'writable') || members[0];
  const cause = causeOf(lead);
  const table = lead.table;
  const owner = (members.find((m) => m.owner) || {}).owner;
  const ownerWords = owner ? '"' + owner + '"' : 'the column that says who each row belongs to';
  const read = members.find((m) => m.kind === 'exposed');
  const writers = members.filter((m) => m.kind === 'writable');
  const anyoneWrites = writers.find((w) => w.who === 'anyone');
  const customersWrite = writers.find((w) => w.who !== 'anyone');
  const what = [];
  if (read) what.push('read');
  if (writers.length) what.push('written');
  const who = read || anyoneWrites ? 'anyone who is not logged in' : 'any signed-in user, including other users\' rows';
  const did = [];
  if (read) did.push('read ' + read.readable + ' ' + (read.readable === 1 ? 'row' : 'rows'));
  const moves = [];
  for (const w of writers) for (const m of w.can || []) if (!moves.includes(m)) moves.push(m);
  for (const m of ['add', 'change', 'delete']) {
    if (moves.includes(m)) did.push({ add: 'added a row', change: 'changed rows', delete: 'deleted rows' }[m]);
  }
  const lines = [
    'My app has a security problem.',
    '',
    'The "' + table + '" table can be ' + what.join(' and ') + ' by ' + who +
      ', because ' + cause.short + '. I proved it on a copy: I ' + listOf(did) + '.' +
      (anyoneWrites && customersWrite ? ' Signed-in users can do the same.' : ''),
    '',
  ].concat(
    serverOnlyLines(lead) || [
        switchOn(lead) + 'remove the rule that lets everyone in, and write separate rules for reading, ' +
          'inserting, updating and deleting. A rule written FOR ALL covers far more than reading.',
        '',
        'Each of them should compare ' + ownerWords + ' to the id of the signed-in user (auth.uid()): ' +
          'USING for reading, updating and deleting, WITH CHECK for inserting and updating, so nobody ' +
          'reads, changes or writes a row under somebody else\'s name. Give logged-out visitors no rule ' +
          'at all unless they truly need one.',
        '',
      ],
    ['Then check every other table for the same thing.'],
  );
  return lines
    .map((paragraph) => (paragraph ? wrapTo(paragraph, 72) : ['']))
    .reduce((all, part) => all.concat(part), [])
    .join('\n');
}

function fixPromptFor(finding) {
  const cause = causeOf(finding);
  const owner = finding.owner ? '"' + finding.owner + '"' : 'the column that says who each row belongs to';

  const lines = finding.kind === 'recursive'
    ? [
      'My app has a broken database rule.',
      '',
      'A row level security policy on the "' + finding.table + '" table reads "' + finding.table +
        '" itself' + (finding.deep ? ', through a helper function it calls,' : '') +
        ' so Postgres stops every request that touches it with ' + loopError(finding) + '. I saw it when using ' +
        listOf((finding.reads || []).map((t) => '"' + t + '"')) + '.',
      '',
      'Show me the policies on "' + finding.table + '" and on every table whose policy reads "' +
        finding.table + '", and find the lookup that goes back into "' + finding.table + '".',
      '',
      'Move that lookup into a SECURITY DEFINER function that answers only about the signed-in ' +
        'user - for example is_member_of(org uuid) returning whether auth.uid() is in that ' +
        'organization - with SET search_path fixed, owned by the table\'s owner so it reads the ' +
        'table without the rule applying again. Grant EXECUTE on it to authenticated only. Then ' +
        'make the policies call that function instead of reading "' + finding.table + '" directly.',
      '',
      'Keep each policy exactly as strict as it was meant to be: members see only their own ' +
        'organization\'s rows, and logged-out visitors get nothing. Do not replace it with USING ' +
        '(true) to make the error go away.',
      '',
      'Then sign in as an ordinary user and open the pages that use these tables, and run this ' +
        'check again - the tables it could not test will be tested this time.',
    ]
    : finding.kind === 'role' && finding.takeover
    ? [
      'My app has a permissions problem - a member can take over another member\'s place.',
      '',
      'In my database, a member of ' + aOne(finding.parent) + ' whose role in "' + finding.via + '"."' +
        finding.roleColumn + '" is "' + finding.who + '" can update another member\'s row in "' + finding.via +
        '" and set "' + finding.personColumn + '" to their own id - taking that member\'s place and role, an ' +
        'admin\'s or the owner\'s included. This was proved on a copy of the database.',
      '',
      'Fix the rules on "' + finding.via + '" that cover UPDATE or ALL: nobody may change "' + finding.personColumn +
        '" or the team a membership belongs to on an existing row - adding or removing members is how membership ' +
        'changes. Let only the roles that manage the team (usually owner and admin) update membership rows at ' +
        'all, check that in WITH CHECK as well as USING, and never use WITH CHECK (true). If members only need to ' +
        'change something of their own, allow exactly that column on their own row and nothing else.',
      '',
      'Then check every function that updates "' + finding.via + '" for the same thing.',
    ]
    : finding.kind === 'role'
    ? [
      'My app may have a permissions problem - please check it rather than assume it.',
      '',
      'In my database, a member of ' + aOne(finding.parent) + ' whose role in "' + finding.via + '"."' +
        finding.roleColumn + '" is "' + finding.who + '" can ' +
        listOf((finding.can || []).map((what) => ({ add: 'add', change: 'change', delete: 'delete' })[what])) +
        ' rows of that ' + oneOf(finding.parent) + ' in the "' + finding.table + '" table. This was proved ' +
        'on a copy of the database: ' + aRole(finding.who) + ' was added, and the writes went through.',
      '',
      'First tell me: should ' + aRole(finding.who) + ' be able to do that? If yes, change nothing.',
      '',
      'If not, make the rules on "' + finding.table + '" that cover UPDATE, DELETE, INSERT or ALL check ' +
        'the member\'s role as well as membership - for example with a helper that reads "' + finding.via +
        '" for auth.uid() and the roles allowed to edit. Postgres lets a write through if ANY permissive ' +
        'policy allows it, so a strict rule beside a loose one does nothing: list every such policy on "' +
        finding.table + '" and narrow or drop the loose one. Keep the read rule as it is if ' +
        aRole(finding.who) + ' should still see these rows.',
      '',
      'Then check every other table where members can write for the same thing.',
    ]
    : finding.kind === 'teamread'
    ? [
      'My app may have a permissions problem - please check it rather than assume it.',
      '',
      'In my database, a member of ' + aOne(finding.parent) + ' whose role in "' + finding.via + '"."' +
        finding.roleColumn + '" is "' + finding.who + '" can read the "' + finding.table + '" table of that ' +
        oneOf(finding.parent) + ', including ' + listOf((finding.secrets || []).map((c) => '"' + c + '"')) +
        '. This was proved on a copy of the database: ' + aRole(finding.who) + ' was added, and the rows came back.',
      '',
      'First tell me: should ' + aRole(finding.who) + ' see these? If yes, change nothing.',
      '',
      'If not, make the rules on "' + finding.table + '" that cover SELECT or ALL check the member\'s role as ' +
        'well as membership. Postgres lets a read through if ANY permissive policy allows it, so a strict rule ' +
        'beside a loose one does nothing: list every such policy on "' + finding.table + '" and narrow or drop ' +
        'the loose one. If members need the other columns, a view or function that leaves the secret ones out ' +
        'is often the better fix.',
      '',
      'Then check every other table that holds tokens, keys, secrets or payloads for the same thing.',
    ]
    : finding.kind === 'bucket'
    ? [
      'My app may have a storage problem - please check it rather than assume it.',
      '',
      'The Supabase Storage bucket "' + finding.bucket + '" is public. Anyone with a file\'s URL can ' +
        'download it without logging in' + (finding.noRule
        ? ', and no rule on storage.objects says who may read it - its name suggests its files are not ' +
          'meant for everyone.'
        : ', and the storage.objects ' +
          ((finding.rules || []).length === 1 ? 'policy that names' : 'policies that name') + ' this bucket (' +
          listOf((finding.rules || []).map((r) => '"' + r + '"')) + ') ' +
          ((finding.rules || []).length === 1 ? 'is' : 'are') + ' not checked for public URLs - so ' +
          ((finding.rules || []).length === 1 ? 'it protects' : 'they protect') + ' nothing while it is public.'),
      '',
      'First tell me: is every file in this bucket meant to be downloadable by anyone? If yes, change nothing.',
      '',
      'If not, make the bucket private (in the Supabase dashboard: Storage, edit the bucket, turn Public ' +
        'off - or UPDATE storage.buckets SET public = false WHERE id = \'' + finding.bucket + '\'). Then ' +
        'change the app to fetch these files with signed URLs (createSignedUrl) instead of getPublicUrl, ' +
        'or the links it shows will stop working.',
      '',
      finding.noRule
        ? 'Once it is private, add a read rule on storage.objects for this bucket that lets in only the ' +
          'people a file belongs to - without one, nobody but your server can read them.'
        : 'Keep the read rule: once the bucket is private it is what decides who gets a file. Check that it ' +
          'only lets in the right people.',
      '',
      'Then look at every other bucket for the same thing.',
    ]
    : finding.kind === 'privileged'
    ? [
      'My app may have a security problem - please check it rather than assume it.',
      '',
      'The database function "' + finding.fn + '(' + (finding.args || '') + ')" is SECURITY ' +
        'DEFINER, so it runs with its owner\'s rights and ignores row level security. It is ' +
        'granted EXECUTE to "anon", so anyone who is not logged in can call it' +
        (finding.writes ? ', and it writes to tables.' : '.'),
      '',
      'First tell me: is it meant to be callable by logged-out visitors? If it is not, ' +
        'REVOKE EXECUTE ON FUNCTION "' + finding.fn + '"(' + (finding.args || '') + ') FROM anon, PUBLIC, ' +
        'and GRANT EXECUTE only to the role that should run it - usually service_role, the ' +
        'backend key, the way an admin-only function like this should be reached.',
      '',
    ].concat(
      finding.nullSlips
        ? [
          'Its role check lets through anyone with no role at all: the helper returns NULL for them, and ' +
            'NULL NOT IN (...) - or NULL <> ... - is not true, so the IF never raises. Write the check so ' +
            'NULL cannot pass, for example IF coalesce(<the helper>(...), \'none\') NOT IN (...) THEN RAISE, ' +
            'or IF <the helper>(...) IS NULL OR <the helper>(...) NOT IN (...) THEN RAISE - and check every ' +
            'other function that uses the same helper the same way.',
          '',
        ]
        : [],
      finding.hasFixedSearchPath
        ? []
        : [
          'It also does not set a fixed search_path. Add SET search_path = pg_catalog, public (or ' +
            'the schemas it truly needs) so a caller cannot make it resolve names to their own objects.',
          '',
        ],
      [
        'If it is meant to be public, keep it, but make sure everything inside it checks what the ' +
          'caller is allowed to see or change itself - the table rules will not do it here.',
        '',
        'Then look at every other SECURITY DEFINER function for the same grant.',
      ],
    )
    : finding.kind === 'orphaned'
    ? [
      'My app has a data problem.',
      '',
      'The "' + finding.table + '" table has a "' + finding.column +
        '" column that is meant to point at "' + finding.parent + '".' +
        ' There is no foreign key between them, so the database does not know they ' +
        'are related. I proved it by adding a row naming one that does not exist, ' +
        'and it was accepted.',
      '',
      'Add a foreign key from "' + finding.table + '"."' + finding.column +
        '" to "' + finding.parent + '"."' + finding.parentKey + '".',
      '',
      'Decide on purpose what should happen when the parent row is deleted: ON ' +
        'DELETE CASCADE if the children should go too, ON DELETE SET NULL if they ' +
        'should stay without an owner, or nothing at all if the delete should be ' +
        'refused while children exist.',
      '',
      'There may already be rows pointing at nothing, and the constraint will not ' +
        'be created until those are dealt with. Find them first.',
    ]
    : finding.kind === 'writable'
    ? [
      'My app has a security problem.',
      '',
      'The "' + finding.table + '" table can be written to by ' +
        (finding.who === 'anyone' ? 'anyone who is not logged in' : 'any signed-in user, including other users rows') +
        ', because ' + cause.short + '. I proved it: I ' +
        (finding.can || []).map((what) => ({ add: 'added a row', change: 'changed rows', delete: 'deleted rows' })[what])
          .join(', ') + '.',
      '',
    ].concat(
      serverOnlyLines(finding) || [
          switchOn(finding) + 'write separate rules for reading, inserting, updating and deleting. ' +
            'A rule written FOR SELECT does not cover writes, and a rule written FOR ALL covers ' +
            'far more than reading.',
          '',
          'For insert and update, use WITH CHECK comparing ' + owner +
            ' to the id of the signed-in user, so nobody can write a row under somebody ' +
            "else's name. For update and delete, add USING with the same comparison: " +
            'with USING (true) left on the update, anyone can take a row that is not ' +
            'theirs and rewrite it as their own.',
          '',
        ],
      [
        'Then check every other table for the same thing - a table with no row level ' +
          'security on it is writable by default.',
      ],
    )
    : finding.kind === 'duplicated'
    ? [
      'My app has a security problem.',
      '',
      'Two rows in the "' + finding.table + '" table can hold the same "' + finding.column +
        '". I proved it by inserting the same value from two connections at the same ' +
        'moment, and both were accepted.',
      '',
      // First, because it has to happen before anything is changed. Learned
      // by applying the short version of this prompt literally to a real app:
      // the constraint cannot be created while duplicates exist, and an
      // assistant told only "add a constraint" may delete rows to get there.
      'First, find the rows that already share a value and show them to me. Do not ' +
        'delete or merge any of them without asking me: the rule below cannot be ' +
        'created while they exist, and deleting rows to make it pass loses real data.',
      '',
      (finding.expectation === 'identity'
        ? 'Then add a unique index on lower("' + finding.column + '"), so that "' + finding.table +
          '"."' + finding.column + '" is unique whatever the case - Ann@example.com and ' +
          'ann@example.com are the same person.'
        : 'Then add a unique constraint on "' + finding.table + '"."' + finding.column + '".') +
        ' It has to be in the database itself. Checking in application code before inserting ' +
        'is not enough - between the check and the insert, the other request has already gone in.',
      '',
      // Said because the obvious fix is wrong for multi-tenant apps, and being
      // told to drop a legitimate design would cost them more than the bug.
      'If the same value is allowed to repeat for different owners, make it cover both ' +
        'columns together rather than leaving it off.',
      '',
    ].concat(
      [
        'Find everything that writes this column - app code, and any database trigger or ' +
          'function, such as one that copies each new sign-up into this table - and make ' +
          'sure each one handles "this value already exists" instead of failing. If people ' +
          'can edit this column themselves, decide whether they should: once it is unique, ' +
          'someone who puts another person\'s value in first will block that person.',
        '',
      ],
      finding.expectation === 'identity' && finding.loginElsewhere
        ? [
          'Sign-in uses auth.users, so this column is only a copy of the email there. ' +
            'Consider not letting people edit it at all and keeping it in step with auth.users.',
          '',
        ]
        : [],
      [
        'Afterwards, sign up a brand-new account and edit an existing profile to make sure ' +
          'both still work, and run this check again.',
        '',
        'Then look for the same missing constraint on every other table and fix those too.',
      ],
    )
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
            : finding.tenant
              ? 'lets a signed-in user read rows belonging to a different organization, because ' + cause.short + '.'
              : 'lets one signed-in user read rows belonging to a different user, because ' + cause.short + '.'),
        '',
      ].concat(
        serverOnlyLines(finding) || [
            'Fix it so a person can only read their own rows: compare ' + owner +
              ' against the id of the signed-in user, and make sure logged-out visitors get nothing.',
            '',
          ],
        ['Then look for the same mistake on every other table and fix those too.'],
      );
  // Wrapped here rather than by whoever prints it: this text is pasted into a
  // chat box as often as it is read in a terminal, and an unwrapped paragraph
  // is a wall in both.
  return lines
    .map((paragraph) => (paragraph ? wrapTo(paragraph, 72) : ['']))
    .reduce((all, part) => all.concat(part), [])
    .join('\n');
}

// Found and said, but never claimed as a break: the owner decides. Counted
// apart in the report, never towards the exit code or a clean re-check.
const TO_CHECK = ['privileged', 'role', 'teamread', 'bucket'];

/** Everything the report needs about one thing the attack found. */
function describe(finding) {
  const contents = readContents(finding.columns);
  const cause = causeOf(finding);
  return {
    severity: severityOf(finding, contents),
    // Every other finding here was proven by an attack that ran; this is the
    // one the tool reasons about without executing, so it says so. The report
    // and the re-check both read this: a "verification required" finding is
    // never counted towards a clean re-check on its own.
    status: TO_CHECK.includes(finding.kind) ? 'verification required' : 'confirmed',
    table: finding.kind === 'privileged' ? finding.fn : finding.table,
    fn: finding.fn,
    args: finding.args,
    writes: finding.writes,
    kind: finding.kind,
    // Carried through because a table can have two different columns that each
    // accept a duplicate, and the re-check tells one finding from another by
    // what it is about. Without the column they would share an identity and
    // fixing one would look like fixing both.
    column: finding.column,
    parent: finding.parent,
    parentKey: finding.parentKey,
    expectation: finding.expectation,
    headline: headlineFor(finding, contents),
    body: bodyFor(finding, contents),
    // For a privileged function there is no "why the door is open" the way a
    // table has one; the body already carries the whole explanation, so the
    // cause line would only repeat it. Left empty and skipped by the report.
    cause: TO_CHECK.includes(finding.kind) ? '' : cause.long,
    who: finding.who,
    can: finding.can,
    via: finding.via,
    roleColumn: finding.roleColumn,
    readable: finding.readable,
    secrets: finding.secrets,
    bucket: finding.bucket,
    // An organization's rows read from outside it, and a member taking over
    // another member's row: kept so the re-check and the read-back word them
    // the same way the report did.
    tenant: finding.tenant,
    takeover: finding.takeover,
    personColumn: finding.personColumn,
    nullSlips: finding.nullSlips,
    noRule: finding.noRule,
    proof: finding.kind === 'recursive'
      ? 'Using ' + listOf((finding.reads || []).map((t) => '"' + t + '"')) + ' stopped with ' +
        loopError(finding) + '.'
      : finding.kind === 'privileged'
      ? 'I did not call "' + finding.fn + '". This is a reach that exists in the grants, not a break I ran.'
      : finding.kind === 'role' && finding.takeover
      ? 'As ' + aRole(finding.who) + ' who had just joined, I put my own id on the other person\'s row of "' +
        finding.via + '", which I could not touch before joining. It was undone.'
      : finding.kind === 'role'
      ? 'As ' + aRole(finding.who) + ' who had just joined, I ' +
        listOf((finding.can || []).map((what) => {
          const n = (finding.changed || {})[what] || 1;
          return ({ add: 'added ', change: 'changed ', delete: 'deleted ' })[what] + n + (n === 1 ? ' row' : ' rows');
        })) + ' in "' + finding.table + '" that I could not touch before joining. All of it was undone.'
      : finding.kind === 'teamread'
      ? 'As ' + aRole(finding.who) + ' who had just joined, I read ' + (finding.readable || 1) +
        ((finding.readable || 1) === 1 ? ' row' : ' rows') + ' of "' + finding.table + '" that I could not read before joining.'
      : finding.kind === 'bucket' && finding.noRule
      ? 'I read that "' + finding.bucket + '" is public and that no rule says who may read it. I did not open any file.'
      : finding.kind === 'bucket'
      ? 'I read that "' + finding.bucket + '" is public and that ' + listOf((finding.rules || []).map((r) => '"' + r + '"')) +
        ' says who may read it. I did not open any file.'
      : finding.kind === 'duplicated'
      ? 'I created ' + finding.copies + ' rows in "' + finding.table + '" holding the same ' +
        finding.column + '.'
      : finding.countOnly
      ? 'I counted ' + finding.readable + ' ' + (finding.readable === 1 ? 'row' : 'rows') +
        ' in "' + finding.table + '" that a stranger can read, without pulling any of them out.'
      : 'I read ' + finding.readable + ' ' + (finding.readable === 1 ? 'row' : 'rows') +
        ' from "' + finding.table + '" that should not have been readable.',
    fixPrompt: fixPromptFor(finding),
    contents: contents,
  };
}

/** Everything wrong with one table's rules, said once. */
function mergeTable(group, one) {
  const members = group.map(one);
  const read = group.find((m) => m.kind === 'exposed');
  const anyoneWrites = group.find((m) => m.kind === 'writable' && m.who === 'anyone');
  const customersWrite = group.find((m) => m.kind === 'writable' && m.who !== 'anyone');
  const lead = anyoneWrites || customersWrite || read;
  const leadItem = members[group.indexOf(lead)];
  const table = lead.table;
  const order = ['delete', 'change', 'add'];
  const does = (w) => order.filter((m) => (w.can || []).includes(m)).map((m) => WRITE_WORDS[m]);
  let headline;
  if (read && anyoneWrites) {
    const verbs = ['read'].concat(order.filter((m) => (anyoneWrites.can || []).includes(m)));
    headline = 'Anyone can ' + listOf(verbs) + ' rows in your ' + table + ' table.';
  } else if (read && customersWrite) {
    headline = 'Anyone can read your ' + table + ' table, and any signed-in customer can ' + listOf(does(customersWrite)) + ' it.';
  } else {
    headline = leadItem.headline;
  }
  // The customers' part is said in one line when strangers can already do it.
  const bodies = [];
  for (let i = 0; i < group.length; i++) {
    if (group[i] === customersWrite && anyoneWrites) continue;
    bodies.push(members[i].body);
  }
  if (customersWrite && anyoneWrites) bodies.push('Signed-in customers can do the same.');
  const severity = members.some((m) => m.severity === 'CRITICAL') ? 'CRITICAL' : leadItem.severity;
  const can = [];
  for (const m of group) for (const c of m.can || []) if (!can.includes(c)) can.push(c);
  return Object.assign({}, leadItem, {
    severity: severity,
    status: 'confirmed',
    kind: lead.kind,
    who: read || anyoneWrites ? 'anyone' : leadItem.who,
    can: can,
    headline: headline,
    body: bodies.join(' '),
    proof: members.map((m) => m.proof).join(' '),
    fixPrompt: groupPromptFor(group),
    members: members,
  });
}

/** The whole report, in the order a person should read it. */
function describeAll(findings) {
  // A table anyone can read is also, necessarily, a table one customer can read
  // of another. Reporting both puts the same table on screen twice and turns
  // two problems into a list of three that reads like a mistake. The public one
  // is kept, and it carries the rest.
  const raw = findings || [];
  const publiclyOpen = new Set(raw.filter((f) => f.kind === 'exposed').map((f) => f.table));
  const kept = raw.filter((f) => !(f.kind === 'crossed' && publiclyOpen.has(f.table)));
  const one = (f) => {
    const item = Object.assign(describe(f), {
      alsoCrossed: f.kind === 'exposed' && raw.some((o) => o.kind === 'crossed' && o.table === f.table),
    });
    if (item.alsoCrossed) item.body += ' Your signed-in customers can read each other\'s rows for the same reason.';
    return item;
  };

  // One table, one finding. A single rule written FOR ALL USING (true) opens a
  // table to reading and writing, for strangers and customers alike - four
  // proofs of one mistake. Listed as four, a real app's report showed six
  // CRITICAL findings for two rules, and the person reads six problems where
  // there are two to fix. The proofs are kept as members, so a re-check can
  // still tell "strangers can no longer write" from "strangers can still read".
  const grouped = new Map();
  for (const f of kept) {
    if ((f.kind !== 'exposed' && f.kind !== 'writable') || f.isView || f.countOnly) continue;
    if (!grouped.has(f.table)) grouped.set(f.table, []);
    grouped.get(f.table).push(f);
  }
  const described = [];
  const done = new Set();
  for (const f of kept) {
    const group = grouped.get(f.table);
    if (!group || group.length < 2 || group.indexOf(f) === -1) {
      described.push(one(f));
      continue;
    }
    if (done.has(f.table)) continue;
    done.add(f.table);
    described.push(mergeTable(group, one));
  }
  // Worst first, and within that the ones open to the whole internet before the
  // ones that need an account, and those before the ones that need two requests
  // to arrive together.
  // Writes above reads: a table somebody emptied is worse than one they read.
  // A looping rule sits with the reads: it breaks the app for everyone it
  // fails for, which matters more than a duplicate or a stray row.
  const byKind = { writable: 0, exposed: 1, crossed: 2, recursive: 2.5, duplicated: 3, orphaned: 4, role: 4.5, teamread: 4.6, bucket: 4.7, privileged: 5 };
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
  // "Your data held" used to be the last line here, and it was the wrong
  // sentence: it says something about the app, and all this program knows is
  // something about the attacks it happened to run. A person who reads "your
  // data held" stops looking. A person who reads "these attacks lost" knows
  // what they have been handed and what they have not.
  return [
    '',
    '  Nothing got through.',
    '',
    '  I ran ' + attacksRun + ' ' + (attacksRun === 1 ? 'attack' : 'attacks') + ' against a copy of your app,',
    '  and every one of them lost.',
    '',
    '  That is not the same as "your app is safe". It means these attacks,',
    '  against this shape of database, this time, did not get in. Anything I',
    '  did not try is listed at the end.',
    '',
  ];
}

module.exports = {
  authTiesOf: authTiesOf,
  readContents: readContents,
  severityOf: severityOf,
  causeOf: causeOf,
  describe: describe,
  describeAll: describeAll,
  fixPromptFor: fixPromptFor,
  allClearLines: allClearLines,
  listOf: listOf,
};
