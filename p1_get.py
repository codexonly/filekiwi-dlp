#!/usr/bin/env python
"""file.kiwi P1: serial downloader (ground-truth reference implementation).

Usage:
    python p1_get.py "https://file.kiwi/<roomid>#<secretKey>" [outdir]

Deliberately dumb: one chunk at a time, no resume, no concurrency. Its job is
to produce trusted bytes so the aria2-backed proxy has something to compare
against (sha256 + first bytes).
"""

import base64
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request

from ece import decrypt_stream, encrypted_size, parse_header

API = "https://file.kiwi"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) filekiwi-p1"


def b64d(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def http_json(url: str, payload=None, timeout=60):
    data = None
    headers = {"user-agent": UA}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def http_bytes(url: str, timeout=300) -> bytes:
    req = urllib.request.Request(url, headers={"user-agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_share_url(url: str):
    u = urllib.parse.urlsplit(url)
    roomid = u.path.strip("/").split("/")[0]
    frag = urllib.parse.unquote(u.fragment)
    if not frag:
        raise SystemExit("URL has no #secretKey fragment")
    key, _, password = frag.partition(",")
    return roomid, key, (password or None)


def chunk_url(meta: dict, chunk_index: int) -> str:
    body = {
        "id": meta["_roomid"],
        "idf": meta["_fid"],
        "sname": meta["sname"],
        "dd": meta["dd"],
        "chunks": meta["chunks"],
        "chunk": chunk_index,
        "usepoint": False,
    }
    d = http_json(f"{API}/api/getdlurl", body)
    if d.get("error"):
        raise RuntimeError(f"getdlurl: {d.get('alert') or d['error']}")
    num = f"{chunk_index + 1:05d}"
    return f"{d['head']}/{num}?X-Amz-Signature={d['dlist'][0]}&{d['dntail']}"


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.2f} {unit}"
        n /= 1024


def sniff(b: bytes) -> str:
    if len(b) >= 32769 and b[32769:32774] == b"CD001":
        return "ISO9660 filesystem image"
    if b[:4] == b"\x7fELF":
        return "ELF"
    if b[:2] == b"MZ":
        return "PE/Windows executable"
    if b[:4] == b"PK\x03\x04":
        return "ZIP/Office"
    if b[:5] == b"%PDF-":
        return "PDF"
    if b[:4] in (b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18"):
        return "compressed stream"
    return "unknown"


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    url = sys.argv[1]
    outdir = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "downloads")
    os.makedirs(outdir, exist_ok=True)

    roomid, secret, password = parse_share_url(url)
    key = b64d(secret)
    print(f"roomid     : {roomid}")
    print(f"secret key : {secret}  ({len(key)} bytes)")
    if password:
        print("password   : present (not supported yet)")
    if len(key) != 16:
        raise SystemExit(f"unexpected key length {len(key)}")

    listing = http_json(f"{API}/api/files/list?roomid={urllib.parse.quote(roomid)}")
    files = listing.get("files") or {}
    if not files:
        raise SystemExit("no files (expired / deleted / wrong key?)")
    print(f"files      : {len(files)}\n")

    for fid, meta in files.items():
        meta["_roomid"], meta["_fid"] = roomid, fid
        name = decrypt_stream(key, b64d(meta["filename"])).decode("utf-8", "replace")
        size, chunks, csize = meta["filesize"], meta["chunks"], meta["chunksize"]
        print(f"[{fid}] {name}")
        print(f"  size={size} ({human(size)})  chunks={chunks}  chunksize={human(csize)}")
        print(f"  mimetype={meta.get('mimetype')!r}  sname={meta['sname']}  dd={meta['dd']}  ctype={meta.get('ctype')}")
        left_h = (meta["expire"] - time.time()) / 3600
        print(f"  expire={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta['expire']))}  left={left_h:.1f}h")

        out = os.path.join(outdir, os.path.basename(name))
        h = hashlib.sha256()
        t0 = time.time()
        head = b""
        written = 0
        with open(out + ".part", "wb") as fh:
            for i in range(chunks):
                ct = http_bytes(chunk_url(meta, i))
                expect = encrypted_size(min(csize, size - i * csize))
                if len(ct) != expect:
                    print(f"  ! chunk {i}: ciphertext {len(ct)}B, expected {expect}B")
                pt = decrypt_stream(key, ct)
                if i == 0:
                    head = pt[:64]
                h.update(pt)
                fh.write(pt)
                written += len(pt)
                el = max(time.time() - t0, 1e-6)
                sys.stdout.write(
                    f"\r  chunk {i + 1}/{chunks}  {human(written)}/{human(size)}"
                    f"  {human(written / el)}/s   "
                )
                sys.stdout.flush()
        os.replace(out + ".part", out)
        el = time.time() - t0
        with open(out, "rb") as fh:
            probe = fh.read(40 * 1024)
        print(f"\n  saved: {out}")
        print(f"  sha256: {h.hexdigest()}")
        print(f"  first bytes: {probe[:16].hex(' ')}")
        print(f"  sniff: {sniff(probe)}")
        print(f"  elapsed {el:.1f}s ({human(written / max(el, 1e-6))}/s)\n")


if __name__ == "__main__":
    main()
