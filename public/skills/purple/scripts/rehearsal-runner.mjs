// This self-contained function is serialized into the existing Node sandbox.
// Keep imports and helpers inside it: repository commands receive no API keys.
export async function runUpgradeRehearsal(input) {
  const loadModule = name => import(name);
  const fs = await loadModule('node:fs/promises');
  const path = await loadModule('node:path');
  const { spawn } = await loadModule('node:child_process');
  const { createReadStream } = await loadModule('node:fs');
  const { createHash } = await loadModule('node:crypto');
  const root = input.root;
  const isolation = process.env.PURPLE_FIX_ISOLATE_COMMANDS === '1' ? await loadModule(input.repositoryIsolationPath || 'file:///opt/purple/agent/repository-isolation.mjs') : null;
  const isolatedDirectories = isolation ? await isolation.prepareIsolationDirectories({ workDirectory: root, outputDirectory: path.dirname(root) }) : null;
  const startedAt = Date.now();
  const deadline = startedAt + 11 * 60_000;
  const commands = [];
  const cloudflareCa = await fs.access('/etc/cloudflare/certs/cloudflare-containers-ca.crt').then(() => true, () => false);
  const egressProxy = (process.env.PURPLE_FIX_EGRESS_PROXY || process.env.HTTPS_PROXY) === 'http://purple-egress:8080' ? 'http://purple-egress:8080' : null;
  async function command(argv, cwd, phase, timeout = 90000) {
    if (Date.now() >= deadline) throw new Error('Rehearsal time budget exhausted.');
    const environment = { PATH: process.env.PATH, HOME: isolatedDirectories?.home || '/tmp/purple-rehearsal-home', CI: 'true',
      TMPDIR: isolatedDirectories?.temp || process.env.TMPDIR,
      GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', npm_config_registry: 'https://registry.npmjs.org/',
      npm_config_userconfig: '/dev/null', npm_config_ignore_scripts: 'true',
      npm_config_audit: 'false', npm_config_fund: 'false', npm_config_update_notifier: 'false', npm_config_engine_strict: 'true', npm_config_strict_peer_deps: 'true',
      npm_config_cache: isolatedDirectories?.cache || '/tmp/purple-rehearsal-cache',
      ...(egressProxy ? { HTTP_PROXY: egressProxy, HTTPS_PROXY: egressProxy, NO_PROXY: '127.0.0.1,localhost', npm_config_proxy: egressProxy, npm_config_https_proxy: egressProxy, NODE_USE_ENV_PROXY: '1' } : {}),
      ...(cloudflareCa ? { NODE_EXTRA_CA_CERTS: '/etc/cloudflare/certs/cloudflare-containers-ca.crt' } : {}) };
    if (isolation) {
      const trusted = argv[0] === 'git';
      const component = path.relative(root, cwd).split(path.sep)[0];
      const repositoryDirectory = path.join(root, component);
      if (!trusted) {
        if (!/^(?:source|candidate-\d+)$/.test(component)) throw new Error('Repository command escaped its isolated checkout.');
        await isolation.prepareRepositoryTree(repositoryDirectory);
      } else argv = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', `safe.directory=${path.join(root, 'source')}`, '-c', `safe.directory=${path.join(root, 'source', '.git')}`, ...argv.slice(1)];
      const result = await isolation.runRepositoryCommand(argv, { cwd, env: environment, repository: !trusted, repositoryDirectory, timeoutMs: Math.min(timeout, deadline - Date.now()) });
      const record = { ...result, command: argv, phase, directory: path.relative(root, cwd), exitCode: result.code,
        passed: result.code === 0 && !result.timedOut && !result.truncated && !result.signal,
        output: (result.stdout + '\n' + result.stderr).replace(/(?:gh[opsu]_[\w]+|github_pat_[\w]+|sk-or-[\w-]+|Bearer\s+\S+)/gi, '[REDACTED]').slice(-6000) };
      commands.push(record); return record;
    }
    const result = await new Promise((resolve, reject) => {
      const child = spawn(argv[0], argv.slice(1), { cwd, detached: true,
        env: environment,
        stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '', outputBytes = 0, timedOut = false, truncated = false;
      const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
      const timer = setTimeout(() => { timedOut = true; kill(); }, Math.min(timeout, deadline - Date.now()));
      for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
        outputBytes += chunk.length;
        if (outputBytes > 500000) { truncated = true; kill(); return; }
        output = (output + chunk.toString()).slice(-6000);
      });
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', (code, signal) => { clearTimeout(timer); kill(); resolve({ command: argv, phase,
        directory: path.relative(root, cwd), exitCode: code, passed: code === 0 && !timedOut && !truncated && !signal, timedOut, truncated, signal, outputBytes,
        output: output.replace(/(?:gh[opsu]_[\w]+|github_pat_[\w]+|sk-or-[\w-]+|Bearer\s+\S+)/gi, '[REDACTED]') }); });
    });
    commands.push(result);
    return result;
  }
  async function required(argv, cwd) {
    const result = await command(argv, cwd, 'checkout');
    if (!result.passed) throw new Error('Could not create the isolated rehearsal checkout.');
    return result;
  }
  const source = path.join(root, 'source');
  if (isolation) await isolation.prepareRepositoryTree(source);
  const files = await new Promise((resolve, reject) => {
    const child = spawn('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', `safe.directory=${source}`, 'ls-files', '-z'], { cwd: source, env: { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let text = '';
    child.stdout.on('data', part => { text += part; if (text.length > 1000000) child.kill('SIGKILL'); });
    child.on('error', reject); child.on('close', code => code === 0 ? resolve(text.split('\0').filter(Boolean)) : reject(new Error('Repository file list exceeds limits.')));
  });
  const packageFiles = files.filter(name => /(^|\/)package\.json$/.test(name) && !name.includes('node_modules/'));
  const locks = files.filter(name => /(^|\/)(?:(?:package-lock|npm-shrinkwrap)\.json|pnpm-lock\.yaml)$/.test(name));
  if (!locks.length || locks.length > 6 || packageFiles.length > 30) throw new Error('Rehearsals support 1–6 npm/pnpm lockfiles and at most 30 package manifests.');
  const projects = [...new Set(locks.map(name => path.dirname(name)))];
  if (projects.some(project => locks.filter(file => path.dirname(file) === project).length > 1)) throw new Error('Multiple lockfiles in one project need manual package-manager selection.');
  const managerFor = project => locks.find(file => path.dirname(file) === project).endsWith('pnpm-lock.yaml') ? 'pnpm' : 'npm';
  let pnpmParser;
  if (locks.some(file => file.endsWith('pnpm-lock.yaml'))) {
    pnpmParser = await loadModule(input.pnpmParserPath || 'file:///opt/purple/pnpm.mjs');
  }
  async function regular(directory, relative) {
    let current = directory;
    for (const part of relative.split('/')) {
      if (!part || part === '..' || part === '.git') throw new Error('Unsafe package file path.');
      current = path.join(current, part);
      if ((await fs.lstat(current)).isSymbolicLink()) throw new Error('Symlinked package files are unsupported.');
    }
    return current;
  }
  for (const file of [...packageFiles, ...locks]) await regular(source, file);
  const manifests = await Promise.all(packageFiles.map(async file => ({ file, value: JSON.parse(await fs.readFile(path.join(source, file), 'utf8')) })));
  const workspaceFiles = files.filter(file => /(^|\/)pnpm-workspace\.yaml$/.test(file));
  for (const file of workspaceFiles) await regular(source, file);
  const lockDocuments = new Map(await Promise.all(locks.map(async file => {
    const content = await fs.readFile(path.join(source, file), 'utf8');
    return [file, file.endsWith('pnpm-lock.yaml') ? pnpmParser.pnpmGraph({ path: file, content }) : JSON.parse(content)];
  })));
  function installedVersion(file, name) {
    const directory = path.dirname(file);
    const owner = locks.filter(lock => path.dirname(lock) === '.' || directory === path.dirname(lock) || directory.startsWith(`${path.dirname(lock)}/`))
      .sort((a, b) => path.dirname(b).length - path.dirname(a).length)[0];
    if (!owner) return null;
    if (owner.endsWith('pnpm-lock.yaml')) {
      const graph = lockDocuments.get(owner), importer = path.relative(path.dirname(owner), directory) || '.';
      const node = graph.nodes.find(item => !item.path && item.workspace === importer);
      const edge = node?.requires.find(item => item.name === name);
      return graph.nodes.find(item => item.id === edge?.to)?.version || null;
    }
    let base = path.relative(path.dirname(owner), directory);
    const locations = lockDocuments.get(owner).packages || {};
    for (;;) {
      const entry = locations[`${base ? `${base}/` : ''}node_modules/${name}`];
      if (entry && !entry.link) return entry.version;
      if (!base) return null;
      const parent = path.dirname(base); base = parent === '.' ? '' : parent;
    }
  }
  for (const { file, value } of manifests) {
    if (!value.packageManager) continue;
    const directory = path.dirname(file);
    const owner = projects.filter(project => project === '.' || directory === project || directory.startsWith(`${project}/`)).sort((a,b) => b.length-a.length)[0];
    if (owner === undefined || !value.packageManager.startsWith(`${managerFor(owner)}@`)) throw new Error('Package-manager declaration does not match the covering lockfile.');
    const expected = value.packageManager.split('@')[1]?.split('+')[0];
    const actual = await command(managerFor(owner) === 'pnpm' ? ['pnpm', '--config.manage-package-manager-versions=false', '--version'] : ['npm', '--version'], path.join(source, directory), 'environment');
    if (!actual.passed || actual.output.trim() !== expected) throw new Error(`Rehearsal requires ${value.packageManager}; provision that version in the agent's sandbox.`);
  }
  const checks = input.checks || manifests.flatMap(({ file, value }) => ['test', 'typecheck', 'build'].filter(name => value.scripts?.[name] && !/no test specified/.test(value.scripts[name]))
    .map(name => ({ directory: path.dirname(file), script: name })));
  if (checks.length > 18) throw new Error('Repository exceeds the 18-check rehearsal limit.');
  async function inventory(directory) {
    const packages = [], locations = {};
    for (const file of locks) {
      if (file.endsWith('pnpm-lock.yaml')) {
        const graph = pnpmParser.pnpmGraph({ path: file, content: await fs.readFile(path.join(directory, file), 'utf8') });
        if (graph.warnings.length) throw new Error(`pnpm dependency coverage is incomplete: ${graph.warnings[0]}`);
        packages.push(...graph.packages);
        for (const node of graph.nodes.filter(item => item.path)) locations[node.id] = { name: node.name, version: node.version };
        continue;
      }
      const lock = JSON.parse(await fs.readFile(path.join(directory, file), 'utf8'));
      if (!lock.packages || ![2, 3].includes(lock.lockfileVersion)) throw new Error('Rehearsals require npm lockfile version 2 or 3.');
      for (const [location, entry] of Object.entries(lock.packages)) {
        if (!location.includes('node_modules/') || !entry.version || entry.link) continue;
        const name = entry.name || location.slice(location.lastIndexOf('node_modules/') + 13);
        packages.push({ name, version: entry.version, resolved: true, kind: 'transitive', files: [file] });
        locations[`${file}:${location}`] = { name, version: entry.version };
      }
    }
    if (packages.length > 5000) throw new Error('Repository exceeds the 5,000 installed-package rehearsal limit.');
    const unique = new Map();
    for (const item of packages) {
      const key = `${item.name}@${item.version}`;
      if (unique.has(key)) unique.get(key).files.push(...item.files);
      else unique.set(key, item);
    }
    return { packages: [...unique.values()], locations };
  }
  async function trackedFiles(directory) {
    return new Promise((resolve, reject) => {
      const child = spawn('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', `safe.directory=${directory}`, 'ls-files', '-z'],
        { cwd: directory, env: { PATH: process.env.PATH, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }, stdio: ['ignore', 'pipe', 'ignore'] });
      let text = '', exceeded = false;
      child.stdout.on('data', part => { text += part; if (text.length > 1000000) { exceeded = true; child.kill('SIGKILL'); } });
      child.on('error', reject); child.on('close', code => code === 0 && !exceeded ? resolve([...new Set(text.split('\0').filter(Boolean))].sort()) : reject(new Error('Could not verify tracked repository files.')));
    });
  }
  async function fingerprint(directory) {
    const entries = new Map();
    // Inspect the original tracked paths even after deletion or index changes.
    // Track newly indexed files too, without trusting repository Git metadata
    // to decide which original source/test files still need verification.
    const names = [...new Set([...files, ...await trackedFiles(directory)])].sort();
    for (const file of names) {
      if (Date.now() >= deadline) throw new Error('Rehearsal time budget exhausted while verifying repository integrity.');
      let current = directory, identity;
      for (const [index, part] of file.split('/').entries()) {
        if (!part || part === '..' || part === '.' || part === '.git') throw new Error('Unsafe tracked repository path.');
        current = path.join(current, part);
        let record;
        try { record = await fs.lstat(current); } catch (error) {
          if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
          identity = 'missing'; break;
        }
        if (record.isSymbolicLink()) {
          // Record the link itself; never follow it outside the checkout.
          identity = `symlink:${index}:${await fs.readlink(current)}`; break;
        }
        if (index < file.split('/').length - 1) {
          if (!record.isDirectory()) { identity = 'non-directory-parent'; break; }
        } else if (record.isFile()) {
          const hash = createHash('sha256');
          for await (const chunk of createReadStream(current)) hash.update(chunk);
          identity = `file:${record.mode & 0o111}:${hash.digest('hex')}`;
        } else identity = 'unsupported-file-type';
      }
      entries.set(file, identity);
    }
    return entries;
  }
  async function installAndCheck(directory, phase) {
    const originalFiles = await fingerprint(directory), changed = new Set();
    async function verifyIntegrity() {
      const current = await fingerprint(directory);
      for (const file of new Set([...originalFiles.keys(), ...current.keys()])) {
        if (originalFiles.get(file) !== current.get(file)) changed.add(file);
      }
    }
    const setup = [];
    for (const project of projects) {
      setup.push(await command(managerFor(project) === 'pnpm' ?
        ['pnpm', 'install', '--frozen-lockfile', '--ignore-scripts', '--strict-peer-dependencies', '--config.manage-package-manager-versions=false'] :
        ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], path.join(directory, project), `${phase}:install`));
      await verifyIntegrity();
    }
    const integrityEvidence = () => ({ integrityVersion: 2, integrity: changed.size === 0, changedTrackedFiles: [...changed].sort().slice(0, 100),
      changedTrackedFilesCount: changed.size, trackedFilesChecked: originalFiles.size });
    if (setup.some(item => !item.passed) || changed.size) return { setup, checks: [], ...integrityEvidence() };
    const results = [];
    for (const check of checks) {
      const owner = projects.filter(project => project === '.' || check.directory === project || check.directory.startsWith(`${project}/`)).sort((a,b)=>b.length-a.length)[0];
      results.push(await command(check.command || (managerFor(owner) === 'pnpm' ? ['pnpm', '--config.enable-pre-post-scripts=false', 'run', check.script] : ['npm', 'run', '--ignore-scripts', check.script]), path.join(directory, check.directory), `${phase}:${check.script || 'explicit'}`, 180000));
      await verifyIntegrity();
      // A changed command definition or test/source file cannot certify the
      // next check. Preserve the failing boundary and stop this phase.
      if (changed.size) break;
    }
    return { setup, checks: results, ...integrityEvidence() };
  }
  const original = await inventory(source);
  const baseline = await installAndCheck(source, 'baseline');
  const scenarios = [];
  for (let index = 0; index < input.scenarios.length; index++) {
    const proposal = input.scenarios[index];
    const directory = path.join(root, `candidate-${index}`);
    await required(['git', 'clone', '--quiet', '--no-hardlinks', '--no-local', source, directory], root);
    const applied = [];
    for (const { file } of manifests) {
      const target = await regular(directory, file);
      const manifest = JSON.parse(await fs.readFile(target, 'utf8'));
      for (const change of proposal.changes) for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        if (Object.hasOwn(manifest[field] || {}, change.name) && installedVersion(file, change.name) === change.currentVersion) {
          if (/^(catalog|workspace):/.test(manifest[field][change.name])) throw new Error(`The catalog/workspace declaration for ${change.name} needs an explicit central configuration migration.`);
          manifest[field][change.name] = change.targetVersion;
          applied.push({ file, field, ...change });
        }
      }
      if (applied.some(change => change.file === file)) await fs.writeFile(target, `${JSON.stringify(manifest, null, 2)}\n`);
    }
    for (const project of projects) {
      // pnpm transitive upgrades are resolved through checked parent upgrades.
      // Preserve pnpm override/catalog policy for the agent to migrate explicitly.
      if (managerFor(project) === 'pnpm') continue;
      const file = path.join(project, 'package.json');
      const target = await regular(directory, file);
      const manifest = JSON.parse(await fs.readFile(target, 'utf8'));
      for (const change of proposal.changes) {
        const direct = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].some(field => Object.hasOwn(manifest[field] || {}, change.name));
        const lock = locks.find(name => path.dirname(name) === project);
        if (!direct && original.packages.some(item => item.name === change.name && item.version === change.currentVersion && item.files.includes(lock))) {
          manifest.overrides ||= {};
          const selector = `${change.name}@${change.currentVersion}`;
          if (Object.hasOwn(manifest.overrides, change.name) || Object.hasOwn(manifest.overrides, selector)) throw new Error(`Existing override for ${change.name} needs manual review.`);
          manifest.overrides[selector] = change.targetVersion;
          applied.push({ file, field: 'overrides', ...change });
        }
      }
      if (applied.some(change => change.file === file)) await fs.writeFile(target, `${JSON.stringify(manifest, null, 2)}\n`);
    }
    const resolution = [];
    for (const project of projects) resolution.push(await command(managerFor(project) === 'pnpm' ?
      ['pnpm', 'install', '--lockfile-only', '--no-frozen-lockfile', '--ignore-scripts', '--strict-peer-dependencies', '--config.manage-package-manager-versions=false'] :
      ['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], path.join(directory, project), `candidate-${index}:resolve`));
    if (resolution.some(item => !item.passed)) {
      scenarios.push({ ...proposal, status: 'resolution_failed', applied, resolution, checks: [], integrity: false, integrityVersion: null, resolvedPackages: [] });
      continue;
    }
    const resolved = await inventory(directory);
    const coverage = proposal.changes.map(change => ({ ...change,
      targetPresent: resolved.packages.some(item => item.name === change.name && item.version === change.targetVersion),
      oldVersionRemaining: resolved.packages.some(item => item.name === change.name && item.version === change.currentVersion) }));
    const validation = await installAndCheck(directory, `candidate-${index}`);
    const changes = [...new Set([...Object.keys(original.locations), ...Object.keys(resolved.locations)])]
      .filter(location => original.locations[location]?.version !== resolved.locations[location]?.version)
      .map(location => ({ location, before: original.locations[location] || null, after: resolved.locations[location] || null }));
    const successful = baseline.setup.every(item => item.passed) && baseline.checks.length > 0 && baseline.checks.every(item => item.passed) && baseline.integrity &&
      validation.setup.every(item => item.passed) && validation.checks.length === baseline.checks.length && validation.checks.every(item => item.passed) && validation.integrity &&
      coverage.every(item => item.targetPresent && !item.oldVersionRemaining);
    const status = successful ? 'tests_passed' : !validation.setup.every(item => item.passed) ? 'install_failed' :
      !baseline.setup.every(item => item.passed) || !baseline.checks.every(item => item.passed) || !baseline.integrity ? 'baseline_failed' :
        !validation.integrity || !validation.checks.every(item => item.passed) ? 'checks_failed' : 'resolved';
    scenarios.push({ ...proposal, status, applied, resolution, coverage,
      ...validation, dependencyChanges: changes.slice(0, 200), totalDependencyChanges: changes.length, resolvedPackages: resolved.packages });
  }
  return { status: 'completed', revision: input.revision, startedAt, finishedAt: Date.now(),
    runtime: { node: process.version, packageManagers: [...new Set(projects.map(managerFor))] }, baseline, scenarios,
    limitations: ['Only existing test, typecheck and build scripts were run; no exploit reproduction or new regression test was generated.',
      'Package lifecycle scripts were disabled. Projects needing generated install artifacts may need a separate reviewed verification.',
      'Tracked source, tests, command definitions and dependency files must remain unchanged during each install/check phase; generated untracked files are not covered by this integrity check.',
      'Passing existing checks does not establish complete runtime compatibility or confirm vulnerability exploitability.'] };
}

export function rehearsalProgram() {
  return `const {writeFile}=await import('node:fs/promises');let text='';for await(const chunk of process.stdin){text+=chunk;if(text.length>180000)throw new Error('Input too large');}let result;try{result=await (${runUpgradeRehearsal.toString()})(JSON.parse(text));}catch(error){result={status:'failed',error:String(error.message).slice(0,500)};}await writeFile('/tmp/purple-rehearsal-result.json',JSON.stringify(result),{mode:0o600});`;
}
