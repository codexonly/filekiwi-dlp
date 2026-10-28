// file.kiwi decrypting range proxy.
//
//   node serve.mjs "https://file.kiwi/<room>#<key>" [--port=8770] [--token=xxx]
//
// Presents every file in a share as a plain HTTP resource with Range support,
// decrypting RFC 8188 (aes128gcm) chunks on the fly, so aria2c / curl / any
// range-capable client can drive it (resume, -x16, --checksum all work).
//
// Design notes
//   * plaintext offset -> (chunk, record) is fully computable from the
//     metadata (filesize / chunks / chunksize), so no probing is needed.
//   * upstream reads are record-aligned Range requests, streamed and decrypted
//     record by record: time-to-first-byte is ~1 RTT, not one whole window.
//   * the client closing early aborts the upstream fetch (aria2 probes a lot).

import http from 'node:http';
import crypto from 'node:crypto';
import { RS, CAP, HDR, keysFor, decryptRecord, decryptStream } from './ece.mjs';

const API = 'https://file.kiwi';
const WINDOW_RECORDS = 64;   // 4 MiB per upstream Range request
const SIG_TTL_MS = 55 * 60 * 1000;

const b64d = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const chunkPlainLen = (e, i) => Math.min(e.chunksize, e.size - i * e.chunksize);
const chunkCtLen = (e, i) => {
  const p = chunkPlainLen(e, i);
  return HDR + p + 17 * Math.ceil(p / CAP);
};

// ---- file.kiwi upstream -------------------------------------------------

async function listFiles(roomid) {
  const r = await fetch(`${API}/api/files/list?roomid=${encodeURIComponent(roomid)}`);
  const j = await r.json();
  if (!j.files || !Object.keys(j.files).length) throw new Error('no files (expired or wrong key?)');
  return j.files;
}

async function signChunk(e, idx, force = false) {
  if (!force && e.sig?.idx === idx && Date.now() - e.sig.at < SIG_TTL_MS) return e.sig.url;
  const r = await fetch(`${API}/api/getdlurl`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      id: e.roomid, idf: e.fid, sname: e.sname, dd: e.dd,
      chunks: e.chunks, chunk: idx, usepoint: false,
    }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(`getdlurl chunk ${idx}: ${j.alert || j.error || r.status}`);
  const url = `${j.head}/${String(idx + 1).padStart(5, '0')}?X-Amz-Signature=${j.dlist[0]}&${j.dntail}`;
  e.sig = { idx, url, at: Date.now() };
  return url;
}

async function openRange(e, idx, start, end, signal) {
  for (let attempt = 0; ; attempt++) {
    const url = await signChunk(e, idx, attempt > 0);
    const r = await fetch(url, { headers: { range: `bytes=${start}-${end}` }, signal });
    if (r.status === 403 && attempt < 2) continue;      // signature expired -> re-sign
    if (!r.ok && r.status !== 206) throw new Error(`chunk ${idx} range ${start}-${end}: HTTP ${r.status}`);
    return r;
  }
}

async function ensureSalt(e, idx, signal) {
  if (e.salts[idx]) return e.salts[idx];
  const r = await openRange(e, idx, 0, 15, signal);
  const salt = Buffer.from(await r.arrayBuffer());
  if (salt.length !== 16) throw new Error(`chunk ${idx}: bad salt`);
  e.salts[idx] = salt;
  return salt;
}

/** Decrypt records [rStart..rStop] of chunk `ci`, yielding as bytes arrive. */
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
      const raw = decryptRecord(e.key, buf.subarray(0, recLen), null, cek, nbase, rr);
      buf = buf.subarray(recLen);
      // strip ECE padding: 0x01 delimiter for non-final records, 0x02 for the final one
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
  if (rr <= rStop) throw new Error(`chunk ${ci}: upstream ended early at record ${rr}`);
}

async function* plainRange(e, start, end, signal) {
  let pos = start;
  while (pos < end) {
    if (signal?.aborted) return;
    const ci = Math.min(Math.floor(pos / e.chunksize), e.chunks - 1);
    const base = ci * e.chunksize;
    const pLen = chunkPlainLen(e, ci);
    const q = pos - base;
    const qEnd = Math.min(end - base, pLen);
    if (qEnd <= q) break;

    const salt = await ensureSalt(e, ci, signal);
    const { cek, nonceBase: nbase } = keysFor(e.key, salt);
    const r0 = Math.floor(q / CAP);
    const r1 = Math.floor((qEnd - 1) / CAP);

    for (let r = r0; r <= r1; r += WINDOW_RECORDS) {
      const rStop = Math.min(r1, r + WINDOW_RECORDS - 1);
      for await (const { rr, plain } of recordStream(e, ci, r, rStop, cek, nbase, signal)) {
        const recStart = base + rr * CAP;
        const a = Math.max(start, recStart);
        const b = Math.min(end, recStart + plain.length);
        if (a < b) yield plain.subarray(a - recStart, b - recStart);
      }
      if (signal?.aborted) return;
    }
    pos = base + qEnd;
  }
}

// ---- http ---------------------------------------------------------------

function parseRange(header, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec((header || '').trim());
  if (!m) return null;
  const [, a, b] = m;
  if (a === '' && b === '') return null;
  if (a === '') {                           // suffix: last N bytes
    const n = Number(b);
    return [Math.max(0, size - n), size - 1];
  }
  const start = Number(a);
  const end = b === '' ? size - 1 : Math.min(Number(b), size - 1);
  if (start > end || start >= size) return null;
  return [start, end];
}

const main = async () => {
  const argv = process.argv.slice(2);
  const share = argv.find((a) => !a.startsWith('--'));
  const port = Number((argv.find((a) => a.startsWith('--port=')) || '--port=8770').split('=')[1]);
  const token = (argv.find((a) => a.startsWith('--token=')) || '').split('=')[1]
    || crypto.randomBytes(8).toString('hex');
  if (!share) throw new Error('usage: node serve.mjs "<share url>" [--port=8770] [--token=xxx]');

  const u = new URL(share);
  const roomid = u.pathname.replace(/^\/+/, '').split('/')[0];
  const frag = decodeURIComponent(u.hash.replace(/^#/, ''));
  if (!frag) throw new Error('no #secretKey fragment');
  const [secretKey] = frag.split(',');
  const key = b64d(secretKey);
  if (key.length !== 16) throw new Error(`key is ${key.length} bytes, want 16`);

  const files = await listFiles(roomid);
  const entries = new Map();
  for (const [fid, meta] of Object.entries(files)) {
    entries.set(fid, {
      roomid, fid,
      name: decryptStream(key, b64d(meta.filename)).toString('utf8'),
      size: meta.filesize, chunks: meta.chunks, chunksize: meta.chunksize,
      sname: meta.sname, dd: meta.dd, key, salts: {}, sig: null,
      expireView: meta.expireview,
    });
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const m = /^\/f\/([\w]+)\/?/.exec(url.pathname);
    if (!m || url.searchParams.get('t') !== token) { res.writeHead(404).end('not found'); return; }
    const e = entries.get(m[1]);
    if (!e) { res.writeHead(404).end('no such file'); return; }

    const range = parseRange(req.headers.range, e.size);
    const [start, endIncl] = range || [0, e.size - 1];
    const end = endIncl + 1;                 // half-open for the generator
    const headers = {
      'content-type': 'application/octet-stream',
      'accept-ranges': 'bytes',
      'etag': `"${crypto.createHash('md5').update(`${e.roomid}:${e.fid}:${e.size}`).digest('hex')}"`,
      'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent(e.name)}`,
      'cache-control': 'no-store',
    };
    if (range) headers['content-range'] = `bytes ${start}-${endIncl}/${e.size}`;
    headers['content-length'] = end - start;
    res.writeHead(range ? 206 : 200, headers);
    if (req.method === 'HEAD') { res.end(); return; }

    const ac = new AbortController();
    let sent = 0;
    res.on('close', () => { if (sent < end - start) ac.abort(); });

    try {
      for await (const buf of plainRange(e, start, end, ac.signal)) {
        sent += buf.length;
        if (!res.write(buf)) {                // backpressure: wait for the socket
          await new Promise((resolve) => {
            const done = () => { res.off('drain', done); res.off('close', done); resolve(); };
            res.on('drain', done);
            res.on('close', done);
          });
        }
      }
      res.end();
      console.log(`[${e.fid}] ${req.method} ${range ? `bytes=${start}-${endIncl}` : 'full'} -> ${sent} B`);
    } catch (err) {
      if (err.name === 'AbortError' || ac.signal.aborted) {
        console.log(`[${e.fid}] ${range ? `bytes=${start}-${endIncl}` : 'full'} -> aborted after ${sent} B`);
        return;
      }
      console.error(`[${e.fid}] ${start}-${endIncl}: ${err.message}`);
      res.destroy();                          // aria2 will retry the segment
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`file.kiwi proxy on http://127.0.0.1:${port}  (token ${token})\n`);
    for (const e of entries.values()) {
      const exp = e.expireView ? new Date(e.expireView * 1000).toISOString() : '?';
      console.log(`  ${e.name}`);
      console.log(`    ${(e.size / 1048576).toFixed(2)} MiB  ${e.chunks} chunk(s)  free download until ${exp}`);
      console.log(`    http://127.0.0.1:${port}/f/${e.fid}/${encodeURIComponent(e.name)}?t=${token}\n`);
    }
  });
};

main().catch((e) => { console.error(e); process.exit(1); });
