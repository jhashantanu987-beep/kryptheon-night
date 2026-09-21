// Does the thing npm would hand a stranger actually work?
//
// Everything else in this repo runs the code where it sits, with every file
// present and `node_modules` already there. None of that is what a customer
// gets. They get a tarball containing whatever `files` in package.json
// happened to list, unpacked into a folder that has never seen this repo.
//
// The sibling project shipped a broken `kryptheon@0.1.8` exactly this way:
// green locally, broken for everybody who installed it, and nothing in the
// suite could have known. So this check does not read package.json and reason
// about it. It builds the real tarball with `npm pack`, installs it into an
// empty folder the way a person would, and runs the command from there.
//
// It needs no database. That is the point - it is the one check that can be
// run before publishing without a connection string, and `prepublishOnly`
// runs it.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const HERE = __dirname;
const results = [];
function check(name, problems) {
  results.push({ name: name, problems: problems });
}

/**
 * npm, on either kind of machine.
 *
 * On Windows `npm` is a batch file, and current Node refuses to start one
 * directly - `spawnSync npm.cmd EINVAL`, with nothing on stderr to say why.
 * `shell: true` works but hands the arguments to cmd unescaped and prints a
 * deprecation warning into the middle of this check's output. Naming cmd
 * itself does neither.
 *
 * Found by this check failing the moment it was run through `npm run`, which
 * is the only way it is ever actually run.
 */
function npm(args, cwd) {
  const command = process.platform === 'win32' ? 'cmd.exe' : 'npm';
  const argv = process.platform === 'win32' ? ['/c', 'npm'].concat(args) : args;
  const r = spawnSync(command, argv, {
    cwd: cwd,
    encoding: 'utf8',
    timeout: 300000,
  });
  return { out: String(r.stdout || ''), err: String(r.stderr || ''), code: r.status };
}

/**
 * Every local file the command needs, found by following the requires.
 *
 * Reading the list in package.json and trusting it is what let the broken
 * publish out. The only list worth checking against is the one the code
 * itself demands.
 */
function requiredFrom(entry) {
  const seen = new Set();
  const queue = [path.resolve(entry)];
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    let source;
    try {
      source = fs.readFileSync(file, 'utf8');
    } catch (err) {
      continue;
    }
    const pattern = /require\(\s*['"](\.[^'"]+)['"]\s*\)/g;
    let found;
    while ((found = pattern.exec(source))) {
      queue.push(path.resolve(path.dirname(file), found[1]));
    }
  }
  return [...seen];
}

/** A stack trace is the tool saying "this is not for you". */
function looksLikeACrash(text) {
  return /at [A-Za-z_$][\w$]*\s*\(|node:internal|MODULE_NOT_FOUND|Cannot find module/.test(text);
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8'));
  const entry = path.join(HERE, manifest.bin['kryptheon-night']);

  /* ---- 1. the manifest, before anything is built ---- */
  // Fast, and it names the missing file. The same fault found through an
  // install comes back as "Cannot find module './orphan.js'", which is true
  // and tells nobody which list to add it to.
  check('1. every file the command requires is in the "files" list', (() => {
    const problems = [];
    const shipped = new Set(
      (manifest.files || []).map((f) => f.replace(/\/$/, '')),
    );
    for (const needed of requiredFrom(entry)) {
      const relative = path.relative(HERE, needed).split(path.sep).join('/');
      const covered = shipped.has(relative) || [...shipped].some((f) => relative.startsWith(f + '/'));
      if (!covered) problems.push(relative + ' is required but would not be published');
    }
    return problems;
  })());

  check('2. the command is executable and points at a file that is there', (() => {
    const problems = [];
    if (!manifest.bin || !manifest.bin['kryptheon-night']) return ['there is no bin entry'];
    if (!fs.existsSync(entry)) return [manifest.bin['kryptheon-night'] + ' does not exist'];
    const first = fs.readFileSync(entry, 'utf8').split('\n')[0];
    // Without this line npm's shim runs it as a shell script and the person
    // gets a page of syntax errors from their own shell.
    if (!/^#!\/usr\/bin\/env node/.test(first)) problems.push('no #!/usr/bin/env node on the first line');
    if (manifest.private) problems.push('"private": true - npm will refuse to publish this');
    return problems;
  })());

  check('3. nothing that reads a database is listed for publishing', (() => {
    // A check file in the tarball is a file that imports test fixtures a
    // customer does not have, and a probe is a script that connects to
    // whatever is in the environment. Neither belongs in an install.
    const problems = [];
    for (const f of manifest.files || []) {
      if (/\.check\.js$/.test(f) || /^probe-/.test(f) || /^fixture/.test(f)) {
        problems.push(f + ' is a development file and would be shipped');
      }
    }
    return problems;
  })());

  /* ---- 4. the real thing: pack, install, run ---- */
  const packed = npm(['pack', '--silent'], HERE);
  const tarball = packed.out.trim().split('\n').filter(Boolean).pop();

  if (packed.code !== 0 || !tarball) {
    check('4. npm pack builds a tarball', ['npm pack failed: ' + (packed.err || packed.out).trim()]);
    return report();
  }

  const tarballPath = path.join(HERE, tarball);
  const fresh = fs.mkdtempSync(path.join(os.tmpdir(), 'kn-fresh-'));

  try {
    fs.writeFileSync(
      path.join(fresh, 'package.json'),
      JSON.stringify({ name: 'not-kryptheon', version: '1.0.0', private: true }, null, 2),
    );

    const installed = npm(['install', tarballPath, '--silent', '--no-audit', '--no-fund'], fresh);
    check('4. it installs into a folder that has never seen this repo', (() => {
      if (installed.code !== 0) return ['npm install failed: ' + (installed.err || installed.out).trim().split('\n').slice(0, 4).join(' | ')];
      return [];
    })());

    // Run it the way the shim does, rather than through `npx`, so a failure
    // here is the package's and not the network's.
    const command = path.join(fresh, 'node_modules', 'kryptheon-night', manifest.bin['kryptheon-night']);

    check('5. every file it needs came with it', (() => {
      const problems = [];
      if (!fs.existsSync(command)) return ['the command was not installed at all'];
      const root = path.dirname(path.dirname(command));
      for (const needed of requiredFrom(entry)) {
        const relative = path.relative(HERE, needed).split(path.sep).join('/');
        if (!fs.existsSync(path.join(root, relative))) problems.push(relative + ' is missing from the install');
      }
      return problems;
    })());

    const run = (args, env) => {
      const r = spawnSync(process.execPath, [command].concat(args), {
        cwd: fresh,
        encoding: 'utf8',
        timeout: 120000,
        env: Object.assign({}, process.env, { KN_DATABASE_URL: '' }, env || {}),
      });
      return { out: String(r.stdout || '') + String(r.stderr || ''), code: r.status };
    };

    const help = run(['--help']);
    check('6. --help works from the installed copy', (() => {
      const problems = [];
      if (looksLikeACrash(help.out)) problems.push('it crashed: ' + help.out.trim().split('\n').slice(0, 3).join(' | '));
      if (!/npx kryptheon-night/.test(help.out)) problems.push('the help does not say how to run it: ' + help.out.trim());
      if (help.code !== 0) problems.push('--help exited ' + help.code);
      return problems;
    })());

    // The most common first mistake there is: the line copied out of Supabase
    // with the password blank still in it.
    const placeholder = run(['--yes'], { KN_DATABASE_URL: 'postgresql://postgres:[YOUR-PASSWORD]@db.abc.supabase.co:5432/postgres' });
    check('7. the Supabase password placeholder is named, not passed to Postgres', (() => {
      const problems = [];
      if (looksLikeACrash(placeholder.out)) problems.push('it crashed: ' + placeholder.out.trim().split('\n').slice(0, 3).join(' | '));
      if (!/\[YOUR-PASSWORD\]/.test(placeholder.out)) problems.push('it does not name the placeholder: ' + placeholder.out.trim());
      if (placeholder.code !== 2) problems.push('exit code was ' + placeholder.code + ', expected 2');
      return problems;
    })());

    const rubbish = run(['--yes'], { KN_DATABASE_URL: 'this is not a connection string' });
    check('8. something that is not a connection string is refused in words', (() => {
      const problems = [];
      if (looksLikeACrash(rubbish.out)) problems.push('it crashed: ' + rubbish.out.trim().split('\n').slice(0, 3).join(' | '));
      if (!/could not read that|connection string/i.test(rubbish.out)) problems.push('it does not say what is wrong: ' + rubbish.out.trim());
      if (rubbish.code !== 2) problems.push('exit code was ' + rubbish.code + ', expected 2');
      return problems;
    })());

    // Nothing can be connected to here, but the credential is well formed, so
    // this reaches the network and comes back. It is the check that the
    // failure a person is most likely to hit is still one readable line.
    const nowhere = run(['--yes'], { KN_DATABASE_URL: 'postgresql://postgres:pw@127.0.0.1:1/postgres' });
    check('9. a database that cannot be reached is one line, not a stack trace', (() => {
      const problems = [];
      if (looksLikeACrash(nowhere.out)) problems.push('it crashed: ' + nowhere.out.trim().split('\n').slice(0, 3).join(' | '));
      if (/Nothing got through|Kryptheon Verified/.test(nowhere.out)) problems.push('it claimed safety having never connected');
      if (nowhere.code !== 2) problems.push('exit code was ' + nowhere.code + ', expected 2');
      return problems;
    })());

    check('10. it never prints the password back', (() => {
      // Everything above was run with a password in the string. A tool whose
      // subject is other people's credentials must not echo one into a
      // terminal a person is about to screenshot.
      const problems = [];
      for (const [name, r] of [['placeholder', placeholder], ['unreachable', nowhere]]) {
        if (/:pw@|YOUR-PASSWORD\]@/.test(r.out.replace(/\[YOUR-PASSWORD\]/g, ''))) {
          problems.push('the ' + name + ' run echoed the credential');
        }
      }
      return problems;
    })());
  } finally {
    fs.rmSync(fresh, { recursive: true, force: true });
    fs.rmSync(tarballPath, { force: true });
  }

  report();
}

function report() {
  console.log('');
  let failures = 0;
  for (const result of results) {
    if (result.problems.length) {
      failures++;
      console.log('FAIL  ' + result.name);
      result.problems.forEach((p) => console.log('      - ' + p));
    } else {
      console.log('PASS  ' + result.name);
    }
  }
  console.log('');
  if (failures) {
    console.log(failures + ' check(s) failed.');
    process.exitCode = 1;
  } else {
    console.log('All ' + results.length + ' packaging checks passed.');
  }
}

try {
  main();
} catch (err) {
  console.error('');
  console.error('  The packaging check could not run: ' + err.message);
  console.error('');
  process.exit(1);
}
