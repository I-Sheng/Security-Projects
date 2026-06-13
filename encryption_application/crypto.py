import os
import struct
import hmac as hmac_module

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES as _TripleDES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidTag

MAGIC = b"ENCR"
VERSION_BASE = 0x01
FLAG_META_HMAC = 0x80   # bit 7: metadata included in HMAC input
FLAG_HKDF      = 0x40   # bit 6: HKDF used for second-stage key derivation

SALT_LEN = 16

# Suite parameters: each entry fully describes one algorithm combination.
SUITE_PARAMS: dict[int, dict] = {
    0x01: {
        "label": "AES-128-CBC / HMAC-SHA256",
        "cipher": "AES-128", "mode": "CBC", "hash": "SHA-256",
        "km_len": 32, "ke_len": 16, "kh_len": 32, "iv_len": 16, "legacy": False,
    },
    0x02: {
        "label": "AES-128-CBC / HMAC-SHA512",
        "cipher": "AES-128", "mode": "CBC", "hash": "SHA-512",
        "km_len": 64, "ke_len": 16, "kh_len": 64, "iv_len": 16, "legacy": False,
    },
    0x04: {
        "label": "AES-256-CBC / HMAC-SHA512 [default]",
        "cipher": "AES-256", "mode": "CBC", "hash": "SHA-512",
        "km_len": 64, "ke_len": 32, "kh_len": 64, "iv_len": 16, "legacy": False,
    },
    0x05: {
        "label": "3DES-CBC / HMAC-SHA256 [legacy]",
        "cipher": "3DES", "mode": "CBC", "hash": "SHA-256",
        "km_len": 32, "ke_len": 24, "kh_len": 32, "iv_len": 8, "legacy": True,
    },
    0x06: {
        "label": "3DES-CBC / HMAC-SHA512 [legacy]",
        "cipher": "3DES", "mode": "CBC", "hash": "SHA-512",
        "km_len": 64, "ke_len": 24, "kh_len": 64, "iv_len": 8, "legacy": True,
    },
    0x10: {
        "label": "AES-128-GCM",
        "cipher": "AES-128", "mode": "GCM", "hash": "SHA-256",
        "km_len": 32, "ke_len": 16, "kh_len": 0, "iv_len": 12, "legacy": False,
    },
    0x11: {
        "label": "AES-256-GCM / SHA-512 [recommended]",
        "cipher": "AES-256", "mode": "GCM", "hash": "SHA-512",
        "km_len": 32, "ke_len": 32, "kh_len": 0, "iv_len": 12, "legacy": False,
    },
}

DEFAULT_SUITE = 0x04
DEFAULT_ITER = {"SHA-256": 600_000, "SHA-512": 210_000}


class HMACVerificationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_algo(name: str):
    return hashes.SHA512() if name == "SHA-512" else hashes.SHA256()


def _pbkdf2(password: bytes, salt: bytes, iterations: int, hash_name: str, dklen: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=_hash_algo(hash_name), length=dklen, salt=salt, iterations=iterations)
    return kdf.derive(password)


def _hkdf_expand(km: bytes, info: bytes, length: int, hash_name: str) -> bytes:
    return HKDFExpand(algorithm=_hash_algo(hash_name), length=length, info=info).derive(km)


def _cbc_encrypt(plaintext: bytes, ke: bytes, iv: bytes, cipher_name: str) -> bytes:
    if cipher_name == "3DES":
        padder = PKCS7(64).padder()
        padded = padder.update(plaintext) + padder.finalize()
        c = Cipher(_TripleDES(ke), modes.CBC(iv))
    else:
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        c = Cipher(algorithms.AES(ke), modes.CBC(iv))
    enc = c.encryptor()
    return enc.update(padded) + enc.finalize()


def _cbc_decrypt(ciphertext: bytes, ke: bytes, iv: bytes, cipher_name: str) -> bytes:
    if cipher_name == "3DES":
        c = Cipher(_TripleDES(ke), modes.CBC(iv))
        unpadder = PKCS7(64).unpadder()
    else:
        c = Cipher(algorithms.AES(ke), modes.CBC(iv))
        unpadder = PKCS7(128).unpadder()
    dec = c.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return unpadder.update(padded) + unpadder.finalize()


def _hmac_compute(kh: bytes, data: bytes, hash_name: str) -> bytes:
    h = crypto_hmac.HMAC(kh, _hash_algo(hash_name))
    h.update(data)
    return h.finalize()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def derive_keys(
    password: bytes,
    salt: bytes,
    iterations: int,
    suite_id: int,
    use_hkdf: bool = False,
) -> tuple[bytes, bytes | None]:
    """Return (Ke, Kh). Kh is None for GCM suites."""
    p = SUITE_PARAMS[suite_id]
    km = _pbkdf2(password, salt, iterations, p["hash"], p["km_len"])

    if p["mode"] == "GCM":
        return km[: p["ke_len"]], None

    if use_hkdf:
        ke = _hkdf_expand(km, b"encryption key", p["ke_len"], p["hash"])
        kh = _hkdf_expand(km, b"hmac key", p["kh_len"], p["hash"])
    else:
        ke = _pbkdf2(km, b"encryption key", 1, p["hash"], p["ke_len"])
        kh = _pbkdf2(km, b"hmac key", 1, p["hash"], p["kh_len"])

    return ke, kh


def encrypt(
    plaintext: bytes,
    password: bytes,
    suite_id: int = DEFAULT_SUITE,
    iterations: int | None = None,
    include_metadata_in_hmac: bool = True,
    use_hkdf: bool = False,
) -> bytes:
    """Encrypt *plaintext* and return the complete binary output blob."""
    p = SUITE_PARAMS[suite_id]
    if iterations is None:
        iterations = DEFAULT_ITER[p["hash"]]

    salt = os.urandom(SALT_LEN)
    iv = os.urandom(p["iv_len"])

    version = VERSION_BASE
    if include_metadata_in_hmac:
        version |= FLAG_META_HMAC
    if use_hkdf:
        version |= FLAG_HKDF

    ke, kh = derive_keys(password, salt, iterations, suite_id, use_hkdf)

    # Fixed-layout metadata block: bytes 0..10+SALT_LEN
    meta = MAGIC + bytes([version, suite_id, SALT_LEN]) + salt + struct.pack(">I", iterations)
    iv_block = bytes([p["iv_len"]]) + iv

    if p["mode"] == "GCM":
        ct_and_tag = AESGCM(ke).encrypt(iv, plaintext, None)
        return meta + iv_block + struct.pack(">Q", len(ct_and_tag)) + ct_and_tag

    ciphertext = _cbc_encrypt(plaintext, ke, iv, p["cipher"])
    hmac_prefix = meta if include_metadata_in_hmac else b""
    mac = _hmac_compute(kh, hmac_prefix + iv + ciphertext, p["hash"])
    return meta + mac + iv_block + struct.pack(">Q", len(ciphertext)) + ciphertext


def decrypt(data: bytes, password: bytes) -> bytes:
    """Decrypt *data* and return plaintext. Raises HMACVerificationError on auth failure."""
    if len(data) < 7 or data[:4] != MAGIC:
        raise ValueError("Not a valid encrypted file (bad magic)")

    version  = data[4]
    suite_id = data[5]
    salt_len = data[6]

    if suite_id not in SUITE_PARAMS:
        raise ValueError(f"Unknown suite ID 0x{suite_id:02X}")

    p            = SUITE_PARAMS[suite_id]
    use_hkdf     = bool(version & FLAG_HKDF)
    include_meta = bool(version & FLAG_META_HMAC)

    off = 7
    salt       = data[off: off + salt_len]; off += salt_len
    iterations = struct.unpack(">I", data[off: off + 4])[0]; off += 4

    if p["mode"] != "GCM":
        mac_stored = data[off: off + p["kh_len"]]; off += p["kh_len"]

    iv_len = data[off]; off += 1
    iv     = data[off: off + iv_len]; off += iv_len
    ct_len = struct.unpack(">Q", data[off: off + 8])[0]; off += 8

    ke, kh = derive_keys(password, salt, iterations, suite_id, use_hkdf)

    if p["mode"] == "GCM":
        ct_and_tag = data[off: off + ct_len]
        try:
            return AESGCM(ke).decrypt(iv, ct_and_tag, None)
        except InvalidTag:
            raise HMACVerificationError("GCM authentication tag verification failed")

    ciphertext = data[off: off + ct_len]

    # Reconstruct exact metadata bytes from the raw file header
    meta = data[: 7 + salt_len + 4]   # magic+ver+suite+salt_len+salt+iterations
    hmac_prefix = meta if include_meta else b""
    mac_expected = _hmac_compute(kh, hmac_prefix + iv + ciphertext, p["hash"])

    if not hmac_module.compare_digest(mac_stored, mac_expected):
        raise HMACVerificationError("HMAC verification failed")

    return _cbc_decrypt(ciphertext, ke, iv, p["cipher"])
