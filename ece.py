"""Minimal RFC 8188 (aes128gcm) decryptor for file.kiwi chunks.

Format facts verified against wormhole-crypto/lib/ece.js:
  - header = salt(16) | rs(4, big endian) | idlen(1) | keyid(idlen)
  - every record is `rs` bytes on the wire, except the final one
  - plaintext record = data || delimiter || zero-padding, delimiter 0x01 (more)
    or 0x02 (final)
  - CEK     = HKDF-SHA256(ikm=key, salt=header_salt, info="Content-Encoding: aes128gcm\0")
  - nonce   = HKDF-SHA256(... "Content-Encoding: nonce\0", 12 bytes) with the
              last 4 bytes XORed with the record sequence number
  - AES-GCM with a 16 byte tag, no AAD
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RS_DEFAULT = 65536
TAG_LEN = 16
DELIM_LEN = 1
HEADER_LEN = 16 + 4 + 1
RECORD_PLAINTEXT_MAX = RS_DEFAULT - TAG_LEN - DELIM_LEN  # 65519


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def parse_header(blob: bytes):
    salt = blob[:16]
    rs = int.from_bytes(blob[16:20], "big")
    idlen = blob[20]
    return salt, rs, idlen, HEADER_LEN + idlen


def decrypt_stream(key: bytes, blob: bytes) -> bytes:
    """Decrypt one complete ECE stream (one file.kiwi chunk)."""
    salt, rs, _idlen, pos = parse_header(blob)
    cek = _hkdf(key, salt, b"Content-Encoding: aes128gcm\x00", 16)
    nonce_base = _hkdf(key, salt, b"Content-Encoding: nonce\x00", 12)
    gcm = AESGCM(cek)
    out = bytearray()
    seq = 0
    while pos < len(blob):
        record = blob[pos:pos + rs]
        nonce = nonce_base[:8] + (
            int.from_bytes(nonce_base[8:], "big") ^ seq
        ).to_bytes(4, "big")
        plain = gcm.decrypt(nonce, record, None)
        i = len(plain) - 1
        while i >= 0 and plain[i] == 0:
            i -= 1
        if i < 0 or plain[i] not in (1, 2):
            raise ValueError(f"bad delimiter at record {seq}")
        delim = plain[i]
        out += plain[:i]
        if delim == 2:
            break
        seq += 1
        pos += rs
    return bytes(out)


def encrypted_size(plain_size: int, rs: int = RS_DEFAULT) -> int:
    cap = rs - TAG_LEN - DELIM_LEN
    return HEADER_LEN + plain_size + (TAG_LEN + DELIM_LEN) * ((plain_size + cap - 1) // cap)
