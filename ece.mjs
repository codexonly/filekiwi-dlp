// RFC 8188 (aes128gcm) helpers, matching wormhole-crypto/lib/ece.js exactly.
import crypto from 'node:crypto';

export const RS = 65536;
export const CAP = RS - 17;   // plaintext bytes per record
export const HDR = 21;        // salt(16) + rs(4) + idlen(1)

export const hkdf = (ikm, salt, info, len) =>
  Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), len));

export function decryptRecord(key, rec, salt, cek, nonceBase, seq) {
  const nonce = Buffer.from(nonceBase);
  nonce.writeUInt32BE((nonce.readUInt32BE(8) ^ seq) >>> 0, 8);
  const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
  d.setAuthTag(rec.subarray(rec.length - 16));
  return Buffer.concat([d.update(rec.subarray(0, rec.length - 16)), d.final()]);
}

export function keysFor(key, salt) {
  return {
    cek: hkdf(key, salt, 'Content-Encoding: aes128gcm\0', 16),
    nonceBase: hkdf(key, salt, 'Content-Encoding: nonce\0', 12),
  };
}

/** Decrypt one complete, self-contained ECE stream (one file.kiwi chunk). */
export function decryptStream(key, blob) {
  const salt = blob.subarray(0, 16);
  const rs = blob.readUInt32BE(16);
  const idlen = blob[20];
  let pos = 21 + idlen;
  const { cek, nonceBase } = keysFor(key, salt);
  const out = [];
  for (let seq = 0; ; seq++) {
    const rec = blob.subarray(pos, pos + rs);
    if (!rec.length) throw new Error('stream ended without a final record');
    const plain = decryptRecord(key, rec, salt, cek, nonceBase, seq);
    let i = plain.length - 1;
    while (i >= 0 && plain[i] === 0) i -= 1;
    if (i < 0 || (plain[i] !== 1 && plain[i] !== 2)) throw new Error(`bad delimiter at seq ${seq}`);
    out.push(plain.subarray(0, i));
    if (plain[i] === 2) break;
    pos += rs;
  }
  return Buffer.concat(out);
}

export const encryptedSize = (p, rs = RS) => HDR + p + 17 * Math.ceil(p / (rs - 17));
