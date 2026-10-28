#!/usr/bin/env node
'use strict';
// file.kiwi downloader demo — single-file, zero-dependency.
//
//   filekiwi probe  <share-url>
//   filekiwi get    <share-url> [-o dir] [--engine internal|aria2|auto]
//   filekiwi serve  <share-url> [--port 8770] [--token t]
//
// Decryption: RFC 8188 aes128gcm, matching wormhole-crypto/lib/ece.js.
// Key lives only in the URL fragment; the server never sees plaintext.
//
// The aria2 engine is fully managed: the same process spawns aria2c with its
// own private RPC port (no config file, no service, no manual start), feeds it
// a localhost URL from the built-in decrypting proxy, then shuts it down.

const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn, spawnSync } = require('node:child_process');

const API = 'https://file.kiwi';
const RS = 65536;            // wire record size
const CAP = RS - 17;         // 65519 plaintext bytes per record
const HDR = 21;              // salt(16) + rs(4) + idlen(1)
const WINDOW_RECORDS = 64;   // 4 MiB per upstream Range request
const SIG_TTL_MS = 55 * 60 * 1000;
const SEG_SIZE = Number(process.env.FK_SEG_SIZE) || 8 * 1024 * 1024;   // internal engine segment (resume unit)
const VERSION = '0.2.0';    // overridden by build.mjs at release time
const CHANNEL = 'dev';      // stable | nightly | dev (overridden by build.mjs)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- crypto --

const b64d = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const hkdf = (ikm, salt, info, len) =>
  Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), len));

const keysFor = (key, salt) => ({
  cek: hkdf(key, salt, 'Content-Encoding: aes128gcm\0', 16),
  nonceBase: hkdf(key, salt, 'Content-Encoding: nonce\0', 12),
});

function decryptRecord(key, rec, cek, nonceBase, seq) {
  const nonce = Buffer.from(nonceBase);
  nonce.writeUInt32BE((nonce.readUInt32BE(8) ^ seq) >>> 0, 8);
  const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
  d.setAuthTag(rec.subarray(rec.length - 16));
  return Buffer.concat([d.update(rec.subarray(0, rec.length - 16)), d.final()]);
}

/** Decrypt one complete ECE stream (used for encrypted filenames). */
function decryptStream(key, blob) {
  const salt = blob.subarray(0, 16);
  const rs = blob.readUInt32BE(16);
  const idlen = blob[20];
  let pos = 21 + idlen;
  const { cek, nonceBase } = keysFor(key, salt);
  const out = [];
  for (let seq = 0; ; seq++) {
    const rec = blob.subarray(pos, pos + rs);
    if (!rec.length) throw new Error('truncated ECE stream');
    const raw = decryptRecord(key, rec, cek, nonceBase, seq);
    let i = raw.length - 1;
    while (i >= 0 && raw[i] === 0) i -= 1;
    if (i < 0 || (raw[i] !== 1 && raw[i] !== 2)) throw new Error('bad ECE delimiter');
    out.push(raw.subarray(0, i));
    if (raw[i] === 2) break;
    pos += rs;
  }
  return Buffer.concat(out);
}

const chunkPlainLen = (e, i) => Math.min(e.chunksize, e.size - i * e.chunksize);
const chunkCtLen = (e, i) => {
  const p = chunkPlainLen(e, i);
  return HDR + p + 17 * Math.ceil(p / CAP);
};

// ------------------------------------------------------------------- api --

async function listFiles(roomid) {
  const r = await fetch(`${API}/api/files/list?roomid=${encodeURIComponent(roomid)}`);
  if (!r.ok) throw new Error(`files/list: HTTP ${r.status}`);
  const j = await r.json();
  if (!j.files || !Object.keys(j.files).length) throw new Error('no files — link expired, deleted, or wrong');
  return j.files;
}

async function signChunk(e, idx, force) {
  const hit = e.sigs.get(idx);
  if (!force && hit && Date.now() - hit.at < SIG_TTL_MS) return hit.url;
  const r = await fetch(`${API}/api/getdlurl`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      id: e.roomid, idf: e.fid, sname: e.sname, dd: e.dd,
      chunks: e.chunks, chunk: idx, usepoint: false,
    }),
    signal: AbortSignal.timeout(20000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(`getdlurl chunk ${idx}: ${j.alert || j.error || r.status}`);
  const url = `${j.head}/${String(idx + 1).padStart(5, '0')}?X-Amz-Signature=${j.dlist[0]}&${j.dntail}`;
  e.sigs.set(idx, { url, at: Date.now() });
  if (e.sigs.size > 256) e.sigs.delete(e.sigs.keys().next().value);
  return url;
}

async function openRange(e, idx, start, end, signal) {
  for (let attempt = 0; ; attempt++) {
    const url = await signChunk(e, idx, attempt > 0);
    const timeout = AbortSignal.timeout(30000);
    const sig = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const r = await fetch(url, { headers: { range: `bytes=${start}-${end}` }, signal: sig });
    if (r.status === 403 && attempt < 2) continue;   // signature expired -> re-sign
    if (!r.ok && r.status !== 206) throw new Error(`chunk ${idx} range ${start}-${end}: HTTP ${r.status}`);
    return r;
  }
}

async function ensureSalt(e, idx, signal) {
  if (e.salts[idx]) return e.salts[idx];
  const r = await openRange(e, idx, 0, 15, signal);
  const salt = Buffer.from(await r.arrayBuffer());
  if (salt.length !== 16) throw new Error(`chunk ${idx}: short salt`);
  e.salts[idx] = salt;
  return salt;
}

async function* recordStream(e, ci, rStart, rStop, cek, nbase, signal) {
  const ctLen = chunkCtLen(e, ci);
  const ctStart = HDR + rStart * RS;
  const ctEnd = Math.min(HDR + (rStop + 1) * RS, ctLen) - 1;
  const res = await openRange(e, ci, ctStart, ctEnd, signal);

  let buf = Buffer.alloc(0);
  let rr = rStart;
  for await (const piece of res.body) {
    buf = buf.length ? Buffer.concat([buf, piece]) : Buffer.from(piece);
    while (rr <= rStop) {
      const recLen = Math.min(RS, ctLen - (HDR + rr * RS));
      if (buf.length < recLen) break;
      const raw = decryptRecord(e.key, buf.subarray(0, recLen), cek, nbase, rr);
      buf = buf.subarray(recLen);
      let i = raw.length - 1;
      while (i >= 0 && raw[i] === 0) i -= 1;
      if (i < 0 || (raw[i] !== 1 && raw[i] !== 2)) throw new Error(`bad delimiter at record ${rr}`);
      const plain = raw.subarray(0, i);
      const want = Math.min(CAP, chunkPlainLen(e, ci) - rr * CAP);
      if (plain.length !== want) throw new Error(`record ${rr}: ${plain.length}B, want ${want}B`);
      yield { rr, plain };
      rr += 1;
    }
  }
  if (rr <= rStop) throw new Error(`chunk ${ci}: upstream ended early`);
}

/** Yield plaintext bytes for [start, end) — arbitrary, unaligned, streaming. */
async function* plainRange(e, start, end, signal) {
  let pos = start;
  while (pos < end) {
    if (signal && signal.aborted) return;
    const ci = Math.min(Math.floor(pos / e.chunksize), e.chunks - 1);
    const base = ci * e.chunksize;
    const pLen = chunkPlainLen(e, ci);
    const q = pos - base;
    const qEnd = Math.min(end - base, pLen);
    if (qEnd <= q) break;

    const salt = await ensureSalt(e, ci, signal);
    const { cek, nonceBase } = keysFor(e.key, salt);
    const r0 = Math.floor(q / CAP);
    const r1 = Math.floor((qEnd - 1) / CAP);

    for (let r = r0; r <= r1; r += WINDOW_RECORDS) {
      const rStop = Math.min(r1, r + WINDOW_RECORDS - 1);
      for await (const { rr, plain } of recordStream(e, ci, r, rStop, cek, nonceBase, signal)) {
        const recStart = base + rr * CAP;
        const a = Math.max(start, recStart);
        const b = Math.min(end, recStart + plain.length);
        if (a < b) yield plain.subarray(a - recStart, b - recStart);
      }
      if (signal && signal.aborted) return;
    }
    pos = base + qEnd;
  }
}

// --------------------------------------------------------------- helpers --

function parseShare(url) {
  const u = new URL(url);
  const roomid = u.pathname.replace(/^\/+/, '').split('/')[0];
  if (!roomid) throw new Error('no room id in URL');
  const frag = decodeURIComponent(u.hash.replace(/^#/, ''));
  if (!frag) throw new Error('URL has no #secretKey — the decryption key lives in the fragment');
  const [k, password] = frag.split(',');
  if (password) throw new Error('password-protected links are not supported yet');
  const key = b64d(k);
  if (key.length !== 16) throw new Error(`secret key is ${key.length} bytes, expected 16`);
  return { roomid, key };
}

async function loadEntries(share) {
  const { roomid, key } = parseShare(share);
  const files = await listFiles(roomid);
  const out = [];
  for (const [fid, meta] of Object.entries(files)) {
    const name = decryptStream(key, b64d(meta.filename)).toString('utf8');
    out.push({
      roomid, fid, key, name,
      size: meta.filesize, chunks: meta.chunks, chunksize: meta.chunksize,
      sname: meta.sname, dd: meta.dd, salts: {}, sigs: new Map(),
      expireView: meta.expireview, expire: meta.expire,
    });
  }
  return out;
}

const human = (n) => {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 2)} ${u[i]}`;
};
const safeName = (s) => s.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').replace(/[. ]+$/, '') || 'download';

function progressLine(done, total, speed, extra) {
  const pct = total ? (done / total) * 100 : 0;
  const eta = speed > 0 ? Math.round((total - done) / speed) : 0;
  const bar = `${human(done)} / ${human(total)}  ${pct.toFixed(1).padStart(5)}%  `
    + `${human(speed)}/s  ETA ${eta}s`;
  process.stdout.write(`\r  ${bar}${extra || ''}   `);
}

async function sha256File(file) {
  const h = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) h.update(chunk);
  return h.digest('hex');
}

function sniff(b) {
  if (b.length > 32774 && b.subarray(32769, 32774).toString('latin1') === 'CD001') return 'ISO9660 image';
  if (b[0] === 0x4d && b[1] === 0x5a) return 'PE/Windows executable';
  if (b.subarray(0, 4).toString('latin1') === 'PK\x03\x04') return 'ZIP';
  if (b[0] === 0x7f && b.subarray(1, 4).toString('latin1') === 'ELF') return 'ELF';
  if (b.subarray(0, 5).toString('latin1') === '%PDF-') return 'PDF';
  return 'unknown';
}

// ------------------------------------------------------- decrypting proxy --

function parseRangeHeader(header, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec((header || '').trim());
  if (!m) return null;
  const [, a, b] = m;
  if (a === '' && b === '') return null;
  let start = 0;
  let endIncl = size - 1;
  if (a === '') start = Math.max(0, size - Number(b));
  else {
    start = Number(a);
    if (b !== '') endIncl = Math.min(Number(b), size - 1);
  }
  if (start > endIncl || start >= size) return { invalid: true };
  return { start, endIncl };
}

async function startProxy(entries, opts = {}) {
  const byId = new Map(entries.map((e) => [e.fid, e]));
  const token = opts.token || crypto.randomBytes(8).toString('hex');
  const verbose = opts.verbose !== false;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const m = /^\/f\/([\w]+)/.exec(url.pathname);
    if (!m || url.searchParams.get('t') !== token) { res.writeHead(404).end('not found'); return; }
    const e = byId.get(m[1]);
    if (!e) { res.writeHead(404).end('unknown file'); return; }

    const range = parseRangeHeader(req.headers.range, e.size);
    if (range && range.invalid) {
      res.writeHead(416, { 'content-range': `bytes */${e.size}` }).end();
      return;
    }
    const start = range ? range.start : 0;
    const endIncl = range ? range.endIncl : e.size - 1;
    const end = endIncl + 1;

    const headers = {
      'content-type': 'application/octet-stream',
      'accept-ranges': 'bytes',
      'content-length': end - start,
      'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent(e.name)}`,
      'cache-control': 'no-store',
      'etag': `"${crypto.createHash('md5').update(`${e.roomid}:${e.fid}:${e.size}`).digest('hex')}"`,
    };
    if (range) headers['content-range'] = `bytes ${start}-${endIncl}/${e.size}`;
    res.writeHead(range ? 206 : 200, headers);
    if (req.method === 'HEAD') { res.end(); return; }

    const ac = new AbortController();
    let sent = 0;
    res.on('close', () => { if (sent < end - start) ac.abort(); });
    try {
      for await (const buf of plainRange(e, start, end, ac.signal)) {
        sent += buf.length;
        if (!res.write(buf)) {
          await new Promise((resolve) => {
            const done = () => { res.off('drain', done); res.off('close', done); resolve(); };
            res.on('drain', done);
            res.on('close', done);
          });
        }
      }
      res.end();
      if (verbose) {
        console.log(`[${e.fid}] ${req.method} ${range ? `bytes=${start}-${endIncl}` : 'full'} -> ${sent} B`);
      }
    } catch (err) {
      if (err.name === 'AbortError' || ac.signal.aborted) {
        if (verbose) console.log(`[${e.fid}] aborted after ${sent} B`);
        return;
      }
      console.error(`[${e.fid}] ${start}-${endIncl}: ${err.message}`);
      res.destroy();
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port || 0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  return {
    port,
    token,
    urlFor: (e) => `http://127.0.0.1:${port}/f/${e.fid}/${encodeURIComponent(e.name)}?t=${token}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// ------------------------------------------------------- internal engine --

/**
 * Fixed 8 MiB segments + a sidecar bitmap.
 * The bitmap is what makes resume safe: a segment counts as done only after it
 * was fully written (and therefore every record in it passed GCM auth).
 * File size alone is NOT a valid progress marker for concurrent downloads.
 */
async function downloadInternal(e, outPath, opts) {
  const segCount = Math.ceil(e.size / SEG_SIZE);
  const part = `${outPath}.part`;
  const sidecar = `${outPath}.part.json`;

  let doneMap = new Array(segCount).fill(false);
  if (fs.existsSync(part) && fs.existsSync(sidecar)) {
    try {
      const s = JSON.parse(fs.readFileSync(sidecar, 'utf8'));
      if (s.size === e.size && s.seg === SEG_SIZE && Array.isArray(s.done) && s.done.length === segCount) {
        doneMap = s.done.map(Boolean);
      } else if (process.env.FK_DEBUG) {
        console.log(`  sidecar mismatch: size=${s.size}/${e.size} seg=${s.seg}/${SEG_SIZE} done=${s.done?.length}/${segCount}`);
      }
    } catch (err) {
      if (process.env.FK_DEBUG) console.log(`  sidecar ignored: ${err.message}`);
    }
  } else if (process.env.FK_DEBUG) {
    console.log(`  no resume state (part=${fs.existsSync(part)} sidecar=${fs.existsSync(sidecar)})`);
  }
  const resumedSegments = doneMap.filter(Boolean).length;
  const resumedBytes = doneMap.reduce(
    (n, ok, i) => n + (ok ? Math.min(SEG_SIZE, e.size - i * SEG_SIZE) : 0), 0);

  const fh = await fsp.open(part, fs.existsSync(part) ? 'r+' : 'w+');

  let completed = resumedBytes;
  const t0 = Date.now();
  let lastPrint = 0;
  const tick = (force) => {
    const now = Date.now();
    if (!force && now - lastPrint < 150) return;
    lastPrint = now;
    const el = Math.max((now - t0) / 1000, 0.001);
    progressLine(completed, e.size, (completed - resumedBytes) / el);
  };

  const queue = [];
  for (let i = 0; i < segCount; i++) if (!doneMap[i]) queue.push(i);
  let next = 0;
  const conn = Math.max(1, Math.min(opts.conn, 32));
  const signal = opts.signal;

  const saveSidecar = () => {
    const tmp = `${sidecar}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ size: e.size, seg: SEG_SIZE, done: doneMap }));
    fs.renameSync(tmp, sidecar);
  };
  if (resumedSegments) console.log(`  resuming: ${resumedSegments}/${segCount} segments already complete`);

  const worker = async () => {
    for (;;) {
      if (signal && signal.aborted) return;
      const qi = next++;
      if (qi >= queue.length) return;
      const seg = queue[qi];
      const a = seg * SEG_SIZE;
      const b = Math.min(e.size, a + SEG_SIZE);
      let pos = a;
      for await (const buf of plainRange(e, a, b, signal)) {
        await fh.write(buf, 0, buf.length, pos);
        pos += buf.length;
        completed += buf.length;
        tick();
      }
      if (pos !== b) throw new Error(`segment ${seg} incomplete (${pos}/${b})`);
      doneMap[seg] = true;
      saveSidecar();
    }
  };

  try {
    await Promise.all(Array.from({ length: conn }, worker));
    tick(true);
    process.stdout.write('\n');
    await fh.truncate(e.size);        // in case a trailing write overshot
    await fh.close();
    fs.renameSync(part, outPath);
    fs.rmSync(sidecar, { force: true });
  } catch (err) {
    await fh.close();
    throw err;
  }
}

// ----------------------------------------------------------- aria2 engine --

function findAria2(explicit) {
  const ok = (bin) => {
    try {
      const r = spawnSync(bin, ['--version'], { encoding: 'utf8', windowsHide: true, timeout: 5000 });
      return r.status === 0 && /aria2 version/i.test(r.stdout || '');
    } catch { return false; }
  };
  if (explicit) {
    if (!ok(explicit)) throw new Error(`not a working aria2c: ${explicit}`);
    const v = spawnSync(explicit, ['--version'], { encoding: 'utf8', windowsHide: true }).stdout || '';
    return { bin: explicit, version: (v.match(/aria2 version ([\w.]+)/i) || [, '?'])[1] };
  }
  const candidates = [
    process.env.ARIA2C,
    'aria2c',
    'D:\\aria2\\aria2c.exe',
    'C:\\ProgramData\\chocolatey\\bin\\aria2c.exe',
    path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Links', 'aria2c.exe'),
    path.join(os.homedir(), 'scoop', 'shims', 'aria2c.exe'),
    '/usr/bin/aria2c', '/usr/local/bin/aria2c',
  ];
  for (const c of candidates) {
    if (c && (c.includes(path.sep) || c.includes('/') ? fs.existsSync(c) : true) && ok(c)) {
      const v = spawnSync(c, ['--version'], { encoding: 'utf8', windowsHide: true }).stdout || '';
      return { bin: c, version: (v.match(/aria2 version ([\w.]+)/i) || [, '?'])[1] };
    }
  }
  return null;
}

const ARIA2_ERRORS = {
  1: 'unknown error', 2: 'timeout', 3: 'resource not found', 4: 'max file not found',
  6: 'network problem', 13: 'file already exists', 19: 'name resolution failed',
  22: 'bad HTTP response header', 24: 'authorization failed', 32: 'checksum validation failed',
};

class Aria2 {
  constructor(bin) {
    this.bin = bin;
    this.secret = crypto.randomBytes(12).toString('hex');
    this.child = null;
    this.stderr = '';
    this.port = 0;
  }

  async start() {
    this.port = await new Promise((resolve, reject) => {
      const s = net.createServer();
      s.once('error', reject);
      s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    });

    const args = [
      '--no-conf',                       // ignore the user's aria2.conf
      '--enable-rpc',
      `--rpc-listen-port=${this.port}`,
      '--rpc-listen-all=false',
      `--rpc-secret=${this.secret}`,
      `--stop-with-process=${process.pid}`,  // aria2 dies with us
      '--console-log-level=error',
      '--summary-interval=0',
      '--quiet=true',
      '--file-allocation=none',
      '--auto-file-renaming=false',
      '--allow-overwrite=false',
      '--check-integrity=true',
      '--max-tries=5',
      '--retry-wait=3',
      '--connect-timeout=15',
    ];
    this.child = spawn(this.bin, args, { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
    this.child.stderr.on('data', (d) => { this.stderr += d; });

    for (let i = 0; i < 120; i++) {
      try { await this.rpc('aria2.getVersion'); return; } catch { await sleep(100); }
    }
    throw new Error(`aria2 RPC did not start${this.stderr ? `: ${this.stderr.trim().split('\n').pop()}` : ''}`);
  }

  async rpc(method, params = []) {
    const r = await fetch(`http://127.0.0.1:${this.port}/jsonrpc`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'fk', method, params: [`token:${this.secret}`, ...params] }),
      signal: AbortSignal.timeout(15000),
    });
    const j = await r.json();
    if (j.error) throw new Error(`aria2 ${method}: ${j.error.message}`);
    return j.result;
  }

  /** Add a download and stream progress until it finishes. */
  async download(url, outDir, name, size, opts) {
    const gid = await this.rpc('aria2.addUri', [[url], {
      dir: path.resolve(outDir),
      out: name,
      split: String(opts.conn),
      'max-connection-per-server': String(opts.conn),
      'min-split-size': '1M',
      'file-allocation': 'none',
      'auto-file-renaming': 'false',
      continue: 'true',
      'remote-time': 'false',
      ...(opts.expect ? { checksum: `sha-256=${opts.expect}` } : {}),
    }]);

    const t0 = Date.now();
    let lastPrint = 0;
    for (;;) {
      const st = await this.rpc('aria2.tellStatus', [gid, [
        'status', 'totalLength', 'completedLength', 'downloadSpeed', 'errorCode', 'errorMessage', 'files', 'connections',
      ]]);
      const now = Date.now();
      if (now - lastPrint >= 150) {
        lastPrint = now;
        progressLine(Number(st.completedLength || 0), Number(st.totalLength || size),
          Number(st.downloadSpeed || 0), `  [aria2 ${st.connections ?? ''}]`);
      }
      if (st.status === 'complete') { process.stdout.write('\n'); return st.files?.[0]?.path; }
      if (st.status === 'error' || st.status === 'removed') {
        process.stdout.write('\n');
        const code = Number(st.errorCode);
        throw new Error(`aria2: ${st.errorMessage || ARIA2_ERRORS[code] || `error ${code}`}`);
      }
      if (Date.now() - t0 > 24 * 3600 * 1000) throw new Error('aria2: giving up after 24h');
      await sleep(300);
    }
  }

  async stop() {
    if (!this.child || this.child.exitCode !== null) return;
    try { await this.rpc('aria2.shutdown'); } catch { /* already gone */ }
    for (let i = 0; i < 40; i++) {
      if (this.child.exitCode !== null) return;
      await sleep(100);
    }
    try { this.child.kill(); } catch { /* ignore */ }
  }
}

// -------------------------------------------------------------- commands --

async function cmdProbe(share) {
  const entries = await loadEntries(share);
  console.log(`files: ${entries.length}\n`);
  for (const e of entries) {
    const left = e.expireView ? ((e.expireView * 1000 - Date.now()) / 3600000).toFixed(1) : '?';
    console.log(`[${e.fid}] ${e.name}`);
    console.log(`  ${human(e.size)}  chunks=${e.chunks}  chunksize=${human(e.chunksize)}`);
    console.log(`  free download window left: ${left} h`);
    const t0 = Date.now();
    const first = [];
    for await (const buf of plainRange(e, 0, Math.min(65536, e.size), null)) first.push(buf);
    const head = Buffer.concat(first);
    const hex = head.subarray(0, 16).toString('hex').match(/../g).join(' ');
    console.log(`  first 64KiB: ${human(head.length)} in ${Date.now() - t0} ms, head=${hex}`);
    console.log(`  sniff: ${sniff(head)}\n`);
  }
}

async function cmdGet(share, opts) {
  let entries = await loadEntries(share);
  if (opts.only) entries = entries.filter((e) => e.name.toLowerCase().includes(opts.only.toLowerCase()));
  if (!entries.length) throw new Error('no matching files');
  fs.mkdirSync(opts.dir, { recursive: true });

  const ac = new AbortController();
  const onSigint = () => {
    console.log('\ninterrupted — progress is saved, rerun the same command to resume');
    ac.abort();
  };
  process.once('SIGINT', onSigint);

  try {
    if (opts.engine === 'aria2' || opts.engine === 'auto') {
      const found = findAria2(opts.aria2c);
      if (found) {
        console.log(`engine: aria2 ${found.version} (${found.bin})`);
        try {
          await getWithAria2(entries, found.bin, opts, ac.signal);
        } catch (err) {
          if (ac.signal.aborted || err.name === 'AbortError') return;
          throw err;
        }
        return;
      }
      if (opts.engine === 'aria2') {
        throw new Error('aria2c not found — install it, or pass --aria2c <path>, or use --engine internal');
      }
      console.log('engine: internal (aria2c not found)');
    } else {
      console.log('engine: internal');
    }
    try {
      await getInternal(entries, opts, ac.signal);
    } catch (err) {
      if (ac.signal.aborted || err.name === 'AbortError') return;
      throw err;
    }
  } finally {
    process.removeListener('SIGINT', onSigint);
  }
}

async function getInternal(entries, opts, signal) {
  for (const e of entries) {
    const out = path.join(opts.dir, safeName(e.name));
    if (fs.existsSync(out) && fs.statSync(out).size === e.size) {
      console.log(`skip (already complete): ${e.name}`);
      continue;
    }
    console.log(`\n${e.name}  ${human(e.size)}  (${e.chunks} chunk${e.chunks > 1 ? 's' : ''})`);
    const t0 = Date.now();
    await downloadInternal(e, out, { ...opts, signal });
    const hash = await sha256File(out);
    const ok = opts.expect ? hash === opts.expect.toLowerCase() : null;
    console.log(`  saved : ${out}`);
    console.log(`  sha256: ${hash}${ok === null ? '' : ok ? '  [OK]' : '  [MISMATCH]'}`);
    console.log(`  time  : ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    if (ok === false) throw new Error('sha256 mismatch');
  }
}

async function getWithAria2(entries, bin, opts, signal) {
  const proxy = await startProxy(entries, { verbose: false });
  const aria = new Aria2(bin);
  await aria.start();
  try {
    for (const e of entries) {
      if (signal.aborted) break;
      const out = path.join(opts.dir, safeName(e.name));
      if (fs.existsSync(out) && fs.statSync(out).size === e.size) {
        console.log(`skip (already complete): ${e.name}`);
        continue;
      }
      console.log(`\n${e.name}  ${human(e.size)}`);
      const t0 = Date.now();
      await aria.download(proxy.urlFor(e), opts.dir, safeName(e.name), e.size, opts);
      const hash = await sha256File(out);
      const ok = opts.expect ? hash === opts.expect.toLowerCase() : null;
      console.log(`  saved : ${out}`);
      console.log(`  sha256: ${hash}${ok === null ? '' : ok ? '  [OK]' : '  [MISMATCH]'}`);
      console.log(`  time  : ${((Date.now() - t0) / 1000).toFixed(1)}s`);
      if (ok === false) throw new Error('sha256 mismatch');
    }
  } finally {
    await aria.stop();
    await proxy.close();
  }
}

async function cmdServe(share, opts) {
  const entries = await loadEntries(share);
  const proxy = await startProxy(entries, {
    port: opts.port, token: opts.token, verbose: !opts.quiet,
  });
  console.log(`file.kiwi proxy v${VERSION} on http://127.0.0.1:${proxy.port}  (token ${proxy.token})\n`);
  for (const e of entries) {
    const exp = e.expireView ? new Date(e.expireView * 1000).toISOString() : '?';
    console.log(`  ${e.name}`);
    console.log(`    ${human(e.size)}   free download until ${exp}`);
    console.log(`    ${proxy.urlFor(e)}\n`);
  }
  const first = entries[0];
  console.log('manual aria2 (if you ever want it):');
  console.log(`  aria2c -x16 -s16 -k1M --file-allocation=none --continue=true "${proxy.urlFor(first)}"\n`);
  await new Promise(() => { /* run until killed */ });
}

// ------------------------------------------------------------------ main --

function usage() {
  console.log(`filekiwi ${VERSION}${CHANNEL === 'stable' ? '' : ` (${CHANNEL})`} — file.kiwi share downloader (unofficial)

usage:
  filekiwi probe <share-url>
  filekiwi get   <share-url> [options]
  filekiwi serve <share-url> [options]

get options:
  -o, --dir <path>        output directory (default: .)
      --only <text>       only files whose name contains <text>
      --conn <n>          parallel connections (default 8, max 32)
      --engine <mode>     internal | aria2 | auto   (default: auto)
      --aria2c <path>     aria2c executable (default: auto-detect)
      --expect-sha256 <hex>  verify the result, exit non-zero on mismatch

serve options:
      --port <n>          listen port (default 8770)
      --token <s>         path token (default random)
      --quiet             don't log every request

notes:
  --engine aria2  spawns its own aria2c with a private RPC port and no config
  file; nothing to start by hand, and it is shut down when the download ends.

examples:
  filekiwi get "https://file.kiwi/19c80d4a#HeIu5YkXdwnzR8ZBOLIE5g" -o downloads
  filekiwi get "https://file.kiwi/19c80d4a#HeIu5YkXdwnzR8ZBOLIE5g" --engine internal --conn 4
`);
}

async function main() {
  const argv = process.argv.slice(2);
  if (!argv.length || argv.includes('-h') || argv.includes('--help')) { usage(); return; }
  if (argv[0] === '--version' || argv[0] === '-V') { console.log(VERSION); return; }
  const cmd = argv[0];
  const share = argv[1];
  const opts = {
    dir: '.', only: null, conn: 8, engine: 'auto', aria2c: null, expect: null,
    port: 8770, token: null, quiet: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '-o' || a === '--dir') opts.dir = next();
    else if (a === '--only') opts.only = next();
    else if (a === '--conn') opts.conn = Number(next());
    else if (a === '--engine') opts.engine = next();
    else if (a === '--aria2c') opts.aria2c = next();
    else if (a === '--expect-sha256') opts.expect = next();
    else if (a === '--port') opts.port = Number(next());
    else if (a === '--token') opts.token = next();
    else if (a === '--quiet') opts.quiet = true;
    else if (a === '--version') { console.log(VERSION); return; }
    else throw new Error(`unknown option: ${a}`);
  }
  if (!['internal', 'aria2', 'auto'].includes(opts.engine)) throw new Error(`--engine must be internal|aria2|auto`);
  if (!share) throw new Error(`${cmd}: missing share URL`);

  if (cmd === 'probe') return cmdProbe(share);
  if (cmd === 'get') return cmdGet(share, opts);
  if (cmd === 'serve') return cmdServe(share, opts);
  throw new Error(`unknown command: ${cmd}`);
}

main().catch((err) => {
  console.error(`\nerror: ${err.message}`);
  process.exit(1);
});
