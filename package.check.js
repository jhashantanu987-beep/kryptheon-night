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

// A run this check causes is saved to a scratch store, never the real
// ~/.kryptheon (see store.js).
process.env.KRYPTHEON_HOME = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'kryptheon-home-'));

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

  // npm passes its own settings to child processes as npm_config_* variables,
  // and this check runs as `prepublishOnly` - so under `npm publish
  // --dry-run` the pack below inherits npm_config_dry_run and packs nothing.
  // It still prints the file name it would have written, which is how a check
  // ends up installing a tarball that does not exist and reporting the
  // product as broken. Cleared here so the pack is always a real one.
  const env = Object.assign({}, process.env);
  delete env.npm_config_dry_run;

  const r = spawnSync(command, argv, {
    cwd: cwd,
    encoding: 'utf8',
    timeout: 300000,
    env: env,
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

  const tarballPath = tarball ? path.join(HERE, tarball) : '';

  // npm printing a name is not npm writing a file, and the two came apart the
  // first time this check ran inside a publish. Checked on disk, and said in
  // one line - without this the run carries on and every later check fails
  // with `Cannot find module`, which reads like a broken product rather than
  // like a tarball that was never built.
  if (packed.code !== 0 || !tarball || !fs.existsSync(tarballPath)) {
    check('4. npm pack builds a tarball', [
      packed.code !== 0
        ? 'npm pack failed: ' + (packed.err || packed.out).trim()
        : 'npm pack said it wrote ' + (tarball || '(nothing)') + ', and there is no such file',
    ]);
    return report();
  }
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

    // What the require graph cannot see.
    //
    // Checks 1 and 5 follow `require()`, and `sqlengine.js` does not require
    // `engine.sql` - it reads it with readFileSync at the moment somebody
    // installs the nightly run. So the graph is satisfied, the install is
    // complete as far as every static check goes, and the first customer to
    // type `kryptheon-night install` gets ENOENT.
    //
    // There is no way to find that by reading the requires, so it is not
    // looked for: the installed copy is asked to produce the engine, which is
    // the thing that would fail.
    check('5b. files the code reads rather than requires came too', (() => {
      const problems = [];
      const root = path.dirname(path.dirname(command));

      // And it is the same engine the suites ran against, byte for byte.
      //
      // "It is there and it is long enough" was the first version of this and
      // it is not much of a claim. What the checks in this repo prove is that
      // *this* engine.sql builds a copy that is the app, agrees with the node
      // engine, and can be installed and removed - and none of that is worth
      // anything if the tarball carries a different one. There is no database
      // here to install it into, so identity is the strongest thing that can
      // honestly be checked, and it is enough: same bytes, same behaviour.
      const mine = fs.readFileSync(path.join(HERE, 'engine.sql'));
      let shipped = null;
      try {
        shipped = fs.readFileSync(path.join(root, 'engine.sql'));
      } catch (err) {
        problems.push('engine.sql did not come with the package at all');
      }
      if (shipped && !shipped.equals(mine)) {
        problems.push('the engine.sql that shipped is not the one the checks ran against (' +
          shipped.length + ' bytes against ' + mine.length + ')');
      }
      const probe = spawnSync(process.execPath, [
        '-e',
        'const s = require(' + JSON.stringify(path.join(root, 'sqlengine.js')) + ');' +
        'const text = s.engineFor("kn_probe");' +
        'process.stdout.write(String(text.length));',
      ], { encoding: 'utf8', timeout: 60000 });
      if (probe.status !== 0) {
        // The line that says what went wrong, not the last line - node ends
        // its stack traces with its own version number, and reporting that
        // as the reason is how a real fault reads like noise.
        const said = String(probe.stderr || '').split('\n')
          .map((l) => l.trim())
          .filter((l) => /Error|ENOENT|Cannot find/.test(l));
        problems.push('the installed copy cannot build the engine: ' +
          (said[0] || 'it exited ' + probe.status + ' and said nothing'));
      } else if (Number(probe.stdout) < 1000) {
        problems.push('the engine it built is ' + probe.stdout + ' characters, which is not an engine');
      }

      // Nothing of the placeholder left. `engineFor` replaces __KN__ with the
      // schema the engine is being addressed to, and one that got through
      // would be a syntax error at install time, in somebody else's database.
      const addressed = spawnSync(process.execPath, [
        '-e',
        'const s = require(' + JSON.stringify(path.join(root, 'sqlengine.js')) + ');' +
        'const t = s.engineFor("kn_probe");' +
        'process.stdout.write(String(t.includes("__KN__")) + " " + String(t.includes(String.fromCharCode(34) + "kn_probe" + String.fromCharCode(34))));',
      ], { encoding: 'utf8', timeout: 60000 });
      if (addressed.status === 0) {
        const [leftOver, addressedTo] = String(addressed.stdout).split(' ');
        if (leftOver !== 'false') problems.push('the engine still has __KN__ in it after being addressed');
        if (addressedTo !== 'true') problems.push('the engine was not addressed to the schema it was given');
      }
      return problems;
    })());

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
