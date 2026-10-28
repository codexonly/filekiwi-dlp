// file.kiwi P0 probe: list -> getdlurl -> fetch -> ECE decrypt -> verify.
// Zero npm deps (node:crypto only). Run: node probe.mjs "<share url>"

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const API = 'https://file.kiwi';
const TAG = 16;

const hkdf = (ikm, salt, info, len) =>
  Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), len));

function decryptStream(key, blob) {
  const salt = blob.subarray(0, 16);
  const rs = blob.readUInt32BE(16);
  const idlen = blob[20];
  let pos = 21 + idlen;
  const cek = hkdf(key, salt, 'Content-Encoding: aes128gcm\0', 16);
  const nonceBase = hkdf(key, salt, 'Content-Encoding: nonce\0', 12);
  const out = [];
  let seq = 0;
  for (;;) {
    const rec = blob.subarray(pos, pos + rs);
    if (!rec.length) throw new Error('stream ended without final record');
    const nonce = Buffer.from(nonceBase);
    nonce.writeUInt32BE((nonce.readUInt32BE(8) ^ seq) >>> 0, 8);
    const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
    d.setAuthTag(rec.subarray(rec.length - TAG));
    const plain = Buffer.concat([d.update(rec.subarray(0, rec.length - TAG)), d.final()]);
    let i = plain.length - 1;
    while (i >= 0 && plain[i] === 0) i -= 1;
    if (i < 0 || (plain[i] !== 1 && plain[i] !== 2)) throw new Error(`bad delimiter at seq ${seq}`);
    out.push(plain.subarray(0, i));
    if (plain[i] === 2) break;
    seq += 1;
    pos += rs;
  }
  return Buffer.concat(out);
}

const b64d = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const encryptedSize = (p, rs = 65536) =>
  21 + p + 17 * Math.ceil(p / (rs - 17));

function sniff(b) {
  if (b.length > 32774 && b.subarray(32769, 32774).toString('latin1') === 'CD001') return 'ISO9660 image (El Torito)';
  if (b.subarray(0, 4).toString('latin1') === 'PK\x03\x04') return 'ZIP';
  if (b.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) return 'ELF';
  if (b[0] === 0x4d && b[1] === 0x5a) return 'PE/MZ';
  return 'unknown';
}

const url = process.argv[2];
if (!url) throw new Error('usage: node probe.mjs "<share url>"');
const u = new URL(url);
const roomid = u.pathname.replace(/^\/+/, '').split('/')[0];
const frag = decodeURIComponent(u.hash.replace(/^#/, ''));
if (!frag) throw new Error('no #secretKey fragment');
const [secretKey, password] = frag.split(',');

const key = b64d(secretKey);
console.log(`roomid  : ${roomid}`);
console.log(`key     : ${secretKey} (${key.length} bytes)${password ? '  +password' : ''}`);

const t0 = Date.now();
const list = await (await fetch(`${API}/api/files/list?roomid=${roomid}`)).json();
const entries = Object.entries(list.files ?? {});
console.log(`files   : ${entries.length}  (list ${Date.now() - t0}ms)`);

for (const [fid, meta] of entries) {
  const name = decryptStream(key, b64d(meta.filename)).toString('utf8');
  console.log(`\n[${fid}] ${name}`);
  console.log(`  filesize=${meta.filesize} chunks=${meta.chunks} chunksize=${meta.chunksize} ctype=${meta.ctype} sname=${meta.sname} dd=${meta.dd}`);
  console.log(`  expire=${new Date(meta.expire * 1000).toISOString()} (${((meta.expire - 0) - Date.now() / 1000) / 3600 | 0}h-ish left)`);
  console.log(`  mimetype=${JSON.stringify(meta.mimetype)} path=${JSON.stringify(meta.path)} fkv=${meta.fkv}`);

  const dl = await (await fetch(`${API}/api/getdlurl`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: roomid, idf: fid, sname: meta.sname, dd: meta.dd, chunks: meta.chunks, chunk: 0, usepoint: false }),
  })).json();
  if (dl.error) throw new Error(`getdlurl: ${dl.alert || dl.error}`);

  const sig = dl.dlist[0];
  const chunkUrl = `${dl.head}/00001?X-Amz-Signature=${sig}&${dl.dntail}`;
  console.log(`  getdlurl: keys=${Object.keys(dl).join(',')} dlist=${dl.dlist.length} head=${dl.head.slice(0, 60)}...`);

  const res = await fetch(chunkUrl);
  const ct = Buffer.from(await res.arrayBuffer());
  const expect = encryptedSize(Math.min(meta.chunksize, meta.filesize));
  console.log(`  chunk0: HTTP ${res.status} ct=${ct.length}B expect=${expect}B ${ct.length === expect ? 'OK' : 'MISMATCH'}`);

  const pt = decryptStream(key, ct);
  const dir = path.join(process.cwd(), 'downloads');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, path.basename(name)), pt);
  console.log(`  plaintext=${pt.length}B ${pt.length === Math.min(meta.chunksize, meta.filesize) ? 'OK' : 'MISMATCH'}`);
  console.log(`  sha256=${crypto.createHash('sha256').update(pt).digest('hex')}`);
  console.log(`  first16=${pt.subarray(0, 16).toString('hex').match(/../g).join(' ')}`);
  console.log(`  sniff=${sniff(pt)}`);
}
