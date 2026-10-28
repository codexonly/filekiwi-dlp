#!/usr/bin/env node
// Release build: patch version -> SEA blob -> inject -> package.
//
//   node build.mjs --version 2026.10.27 --channel stable [--target win-x64]
//
// The SEA blob is architecture independent (no snapshot, no code cache), so a
// single x64 host can produce arm64 artifacts by downloading the matching
// official Node binary and injecting the same blob into it.
//
// Host requirements per target:
//   win-*    Windows host (zip packaging)
//   linux-*  Linux host   (tar.gz packaging, exec bits)
//   macos-*  macOS host   (tar.gz + ad-hoc codesign, required to run at all)

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const POSTJECT_VERSION = '1.0.0-alpha.6';   // must match package.json
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';

const TARGETS = {
  'win-x64': { os: 'win', nodePlat: 'win', arch: 'x64' },
  'win-arm64': { os: 'win', nodePlat: 'win', arch: 'arm64' },
  'linux-x64': { os: 'linux', nodePlat: 'linux', arch: 'x64' },
  'linux-arm64': { os: 'linux', nodePlat: 'linux', arch: 'arm64' },
  'macos-x64': { os: 'macos', nodePlat: 'darwin', arch: 'x64' },
  'macos-arm64': { os: 'macos', nodePlat: 'darwin', arch: 'arm64' },
};

const HOST_OS = { win32: 'win', linux: 'linux', darwin: 'macos' }[process.platform];
const HOST_TARGET = `${HOST_OS}-${process.arch}`;

const SENTINEL_RE = /const VERSION = '([^']*)';/;
const CHANNEL_RE = /const CHANNEL = '([^']*)';/;
const STABLE_RE = /^\d{4}\.\d{2}\.\d{2}(\.\d{1,2})?$/;
const NIGHTLY_RE = /^\d{4}\.\d{2}\.\d{2}\.\d{6}$/;

const argv = process.argv.slice(2);
const arg = (name, fallback = null) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
};

const version = arg('version');
const channel = arg('channel', 'stable');
const gitHead = arg('git-head', '');
const target = arg('target', HOST_TARGET);
const outRoot = path.resolve(ROOT, arg('out', 'dist'));

// ---- validate ------------------------------------------------------------

if (!version) fail('--version is required (e.g. 2026.10.27)');
if (channel === 'stable' && !STABLE_RE.test(version)) {
  fail(`stable version must be YYYY.MM.DD, got ${version}`);
}
if (channel === 'nightly' && !NIGHTLY_RE.test(version)) {
  fail(`nightly version must be YYYY.MM.DD.HHMMSS, got ${version}`);
}
if (!['stable', 'nightly', 'dev'].includes(channel)) fail(`unknown channel ${channel}`);
if (!TARGETS[target]) fail(`unknown --target ${target} (one of: ${Object.keys(TARGETS).join(', ')})`);

const t = TARGETS[target];
if (t.os !== HOST_OS) {
  fail(`${target} must be built on a ${t.os} host (current: ${HOST_OS}); SEA builds can't cross OSes`);
}

const nodeVersion = process.versions.node;
const buildDir = path.join(ROOT, 'build');
const exeName = t.os === 'win' ? 'filekiwi.exe' : 'filekiwi';

// ---- 1. patch cli.js -----------------------------------------------------

const cliPath = path.join(ROOT, 'cli.js');
let source = fs.readFileSync(cliPath, 'utf8');
if (!SENTINEL_RE.test(source)) fail('could not find `const VERSION = ...` in cli.js');
if (!CHANNEL_RE.test(source)) fail('could not find `const CHANNEL = ...` in cli.js');
source = source
  .replace(SENTINEL_RE, `const VERSION = '${version}';`)
  .replace(CHANNEL_RE, `const CHANNEL = '${channel}';`);

const work = path.join(buildDir, target);
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(work, { recursive: true });
fs.writeFileSync(path.join(work, 'cli.js'), source);
fs.writeFileSync(path.join(work, 'sea-config.json'), JSON.stringify({
  main: path.relative(ROOT, path.join(work, 'cli.js')).replaceAll('\\', '/'),
  output: path.relative(ROOT, path.join(work, 'sea-prep.blob')).replaceAll('\\', '/'),
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false,
}, null, 2) + '\n');

// ---- 2. SEA blob + base binary ------------------------------------------

step('generating SEA blob');
execFileSync(process.execPath, ['--experimental-sea-config', path.relative(ROOT, path.join(work, 'sea-config.json'))], {
  cwd: ROOT, stdio: 'inherit',
});

const exePath = path.join(work, exeName);
const base = target === HOST_TARGET ? process.execPath : await fetchNodeBinary(t);
step(`base binary: ${target === HOST_TARGET ? `host node (${nodeVersion})` : `${target} node ${nodeVersion}`}`);
fs.copyFileSync(base, exePath);

// ---- 3. inject -----------------------------------------------------------

const postjectCli = path.join(ROOT, 'node_modules', 'postject', 'dist', 'cli.js');
if (!fs.existsSync(postjectCli)) fail('postject is not installed — run `npm ci` first');
const installed = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'node_modules', 'postject', 'package.json'), 'utf8'),
).version;
if (installed !== POSTJECT_VERSION) {
  fail(`postject ${installed} installed but ${POSTJECT_VERSION} is pinned — run \`npm ci\``);
}

if (t.os === 'macos') {
  try { execFileSync('codesign', ['--remove-signature', exePath], { stdio: 'ignore' }); } catch { /* unsigned */ }
}

step('injecting blob (postject)');
const injectArgs = [postjectCli, exePath, 'NODE_SEA_BLOB', path.join(work, 'sea-prep.blob'),
  '--sentinel-fuse', FUSE];
if (t.os === 'macos') injectArgs.push('--macho-segment-name', 'NODE_SEA');
execFileSync(process.execPath, injectArgs, { cwd: ROOT, stdio: 'inherit', timeout: 10 * 60 * 1000 });

if (t.os === 'macos') {
  step('ad-hoc codesign');
  execFileSync('codesign', ['--sign', '-', exePath], { stdio: 'inherit' });
}
if (t.os !== 'win') fs.chmodSync(exePath, 0o755);

// ---- 4. package ----------------------------------------------------------

const name = `filekiwi-${version}-${target}`;
const pkgDir = path.join(outRoot, name);
fs.rmSync(pkgDir, { recursive: true, force: true });
fs.mkdirSync(pkgDir, { recursive: true });

const readme = fs
  .readFileSync(path.join(ROOT, 'README.txt'), 'utf8')
  .replaceAll('{{VERSION}}', version)
  .replaceAll('{{DATE}}', new Date().toISOString().slice(0, 10));
fs.writeFileSync(path.join(pkgDir, 'README.txt'), '\ufeff' + readme);   // BOM: Windows 记事本友好
fs.writeFileSync(path.join(pkgDir, 'cli.js'), source);
fs.copyFileSync(exePath, path.join(pkgDir, exeName));
fs.writeFileSync(path.join(pkgDir, 'build-info.txt'), [
  `filekiwi ${version}`,
  `channel : ${channel}`,
  `target  : ${target}`,
  `git head: ${gitHead || '(unknown)'}`,
  `node    : ${nodeVersion}`,
  `built   : ${new Date().toISOString()}`,
  `host    : ${process.platform}-${process.arch}`,
  '',
].join('\n'));

const files = ['README.txt', 'cli.js', exeName, 'build-info.txt'];
const archive = t.os === 'win'
  ? path.join(outRoot, `${name}.zip`)
  : path.join(outRoot, `${name}.tar.gz`);
fs.rmSync(archive, { force: true });

step(`packaging ${path.basename(archive)}`);
if (t.os === 'win') {
  execFileSync('powershell', ['-NoProfile', '-Command',
    `Compress-Archive -Path "${path.join(pkgDir, '*')}" -DestinationPath "${archive}" -Force`],
  { stdio: 'inherit', timeout: 10 * 60 * 1000 });
} else {
  execFileSync('tar', ['-czf', archive, '-C', pkgDir, ...files], { stdio: 'inherit' });
}

// ---- 5. checksums (yt-dlp style: "<hash>  <name>") ----------------------

const assets = [archive, path.join(pkgDir, exeName), path.join(pkgDir, 'cli.js')];
const sums = [];
for (const f of assets) sums.push(`${await sha256File(f)}  ${path.basename(f)}`);
const sumsPath = path.join(outRoot, `SHA2-256SUMS.${target}`);
fs.writeFileSync(sumsPath, sums.join('\n') + '\n');

// ---- done ---------------------------------------------------------------

console.log(`\nfilekiwi ${version} (${channel}) — ${target}`);
console.log(`  ${path.relative(ROOT, archive)}   ${(fs.statSync(archive).size / 1048576).toFixed(1)} MiB`);
for (const line of sums) console.log(`  ${line}`);

function step(msg) { console.log(`\n[build] ${msg}`); }
function fail(msg) { console.error(`error: ${msg}`); process.exit(1); }

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (d) => h.update(d)).on('error', reject)
      .on('end', () => resolve(h.digest('hex')));
  });
}

/** Download the official Node binary for another arch and verify its sha256. */
async function fetchNodeBinary(t) {
  const ext = t.nodePlat === 'win' ? 'zip' : 'tar.gz';
  const file = `node-v${nodeVersion}-${t.nodePlat}-${t.arch}.${ext}`;
  const cacheDir = path.join(ROOT, '.cache', 'node');
  fs.mkdirSync(cacheDir, { recursive: true });
  const archive = path.join(cacheDir, file);

  if (!fs.existsSync(archive)) {
    const url = `https://nodejs.org/dist/v${nodeVersion}/${file}`;
    step(`downloading ${url}`);
    const res = await fetch(url);
    if (!res.ok) fail(`download failed: HTTP ${res.status} ${url}`);
    fs.writeFileSync(archive, Buffer.from(await res.arrayBuffer()));
  }

  const sumsRes = await fetch(`https://nodejs.org/dist/v${nodeVersion}/SHASUMS256.txt`);
  if (!sumsRes.ok) fail('could not fetch nodejs SHASUMS256.txt');
  const line = (await sumsRes.text()).split('\n').find((l) => l.trim().endsWith(`  ${file}`));
  if (!line) fail(`${file} not listed in SHASUMS256.txt`);
  const expected = line.trim().split(/\s+/)[0];
  const actual = await sha256File(archive);
  if (actual !== expected) {
    fs.rmSync(archive, { force: true });
    fail(`checksum mismatch for ${file}: ${actual} != ${expected}`);
  }

  const unpacked = path.join(cacheDir, `node-v${nodeVersion}-${t.nodePlat}-${t.arch}`);
  if (!fs.existsSync(unpacked)) {
    step(`extracting ${file}`);
    execFileSync('tar', ['-xf', archive, '-C', cacheDir], { stdio: 'inherit' });
  }
  const bin = path.join(unpacked, t.nodePlat === 'win' ? 'node.exe' : 'bin/node');
  if (!fs.existsSync(bin)) fail(`unexpected layout, missing ${bin}`);
  return bin;
}
