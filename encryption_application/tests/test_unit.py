"""Unit tests U-01 through U-15."""

import hashlib
import os
import struct

import pytest

from crypto import (
    SUITE_PARAMS, MAGIC, VERSION_BASE, FLAG_META_HMAC,
    derive_keys, encrypt, decrypt, HMACVerificationError,
)

# Low-iteration password for fast tests
_FAST_ITERS = 1
_PW = b"test-password"
_SALT = bytes(16)  # 16 zero bytes


# ---------------------------------------------------------------------------
# U-01 — PBKDF2 key derivation matches reference vectors
# ---------------------------------------------------------------------------

def test_u01_key_derivation_sha256():
    """Derived keys match hashlib reference computation (SHA-256)."""
    # Suite 0x01: AES-128-CBC / HMAC-SHA256
    km = hashlib.pbkdf2_hmac("sha256", _PW, _SALT, _FAST_ITERS, dklen=32)
    ke_ref = hashlib.pbkdf2_hmac("sha256", km, b"encryption key", 1, dklen=16)
    kh_ref = hashlib.pbkdf2_hmac("sha256", km, b"hmac key", 1, dklen=32)

    ke, kh = derive_keys(_PW, _SALT, _FAST_ITERS, suite_id=0x01)
    assert ke == ke_ref
    assert kh == kh_ref


def test_u01_key_derivation_sha512():
    """Derived keys match hashlib reference computation (SHA-512)."""
    # Suite 0x04: AES-256-CBC / HMAC-SHA512
    km = hashlib.pbkdf2_hmac("sha512", _PW, _SALT, _FAST_ITERS, dklen=64)
    ke_ref = hashlib.pbkdf2_hmac("sha512", km, b"encryption key", 1, dklen=32)
    kh_ref = hashlib.pbkdf2_hmac("sha512", km, b"hmac key", 1, dklen=64)

    ke, kh = derive_keys(_PW, _SALT, _FAST_ITERS, suite_id=0x04)
    assert ke == ke_ref
    assert kh == kh_ref


# ---------------------------------------------------------------------------
# U-02..U-06 — Round-trip encrypt/decrypt for each suite
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("suite_id, label", [
    (0x01, "AES-128-CBC/HMAC-SHA256"),
    (0x03, "AES-256-CBC/HMAC-SHA256"),
    (0x04, "AES-256-CBC/HMAC-SHA512"),
    (0x05, "3DES-CBC/HMAC-SHA256"),
    (0x10, "AES-128-GCM"),
    (0x11, "AES-256-GCM"),
])
def test_round_trip(suite_id, label):
    plaintext = b"Hello, round-trip test! " * 4
    blob = encrypt(plaintext, _PW, suite_id=suite_id, iterations=_FAST_ITERS)
    recovered = decrypt(blob, _PW)
    assert recovered == plaintext, f"{label} round-trip failed"


# U-02
def test_u02_aes128_cbc():
    pt = b"AES-128-CBC plaintext"
    assert decrypt(encrypt(pt, _PW, suite_id=0x01, iterations=_FAST_ITERS), _PW) == pt


# U-03
def test_u03_aes256_cbc():
    pt = b"AES-256-CBC plaintext"
    assert decrypt(encrypt(pt, _PW, suite_id=0x03, iterations=_FAST_ITERS), _PW) == pt


# U-04
def test_u04_3des_cbc():
    pt = b"3DES-CBC plaintext data"
    assert decrypt(encrypt(pt, _PW, suite_id=0x05, iterations=_FAST_ITERS), _PW) == pt


# U-05
def test_u05_aes128_gcm():
    pt = b"AES-128-GCM plaintext"
    assert decrypt(encrypt(pt, _PW, suite_id=0x10, iterations=_FAST_ITERS), _PW) == pt


# U-06
def test_u06_aes256_gcm():
    pt = b"AES-256-GCM plaintext"
    assert decrypt(encrypt(pt, _PW, suite_id=0x11, iterations=_FAST_ITERS), _PW) == pt


# ---------------------------------------------------------------------------
# U-07 — Tampered ciphertext is rejected (CBC)
# ---------------------------------------------------------------------------

def test_u07_tampered_ciphertext_rejected():
    blob = encrypt(b"secret message", _PW, suite_id=0x04, iterations=_FAST_ITERS)
    # Flip a byte in the ciphertext region (well past the header)
    tampered = bytearray(blob)
    tampered[-50] ^= 0xFF
    with pytest.raises(HMACVerificationError):
        decrypt(bytes(tampered), _PW)


# ---------------------------------------------------------------------------
# U-08 — Tampered IV is rejected
# ---------------------------------------------------------------------------

def test_u08_tampered_iv_rejected():
    blob = bytearray(encrypt(b"secret message", _PW, suite_id=0x04, iterations=_FAST_ITERS))
    # Locate the IV: offset = 7 + SALT_LEN(16) + 4(iter) + 1(iv_len) = 28
    # IV starts at byte 28, length 16
    blob[28] ^= 0x01
    with pytest.raises(HMACVerificationError):
        decrypt(bytes(blob), _PW)


# ---------------------------------------------------------------------------
# U-09 — Tampered metadata is rejected (CBC with metadata-in-HMAC)
# ---------------------------------------------------------------------------

def test_u09_tampered_metadata_rejected():
    blob = bytearray(encrypt(
        b"protected message", _PW, suite_id=0x04, iterations=_FAST_ITERS,
        include_metadata_in_hmac=True,
    ))
    # Flip a bit in the salt (bytes 7..22)
    blob[10] ^= 0x80
    with pytest.raises(HMACVerificationError):
        decrypt(bytes(blob), _PW)


# ---------------------------------------------------------------------------
# U-10 — GCM auth tag failure on tampered ciphertext
# ---------------------------------------------------------------------------

def test_u10_gcm_tampered_ciphertext():
    blob = bytearray(encrypt(b"gcm secret", _PW, suite_id=0x11, iterations=_FAST_ITERS))
    blob[-20] ^= 0xFF
    with pytest.raises(HMACVerificationError):
        decrypt(bytes(blob), _PW)


# ---------------------------------------------------------------------------
# U-11 — Binary header round-trips correctly
# ---------------------------------------------------------------------------

def test_u11_header_round_trip():
    blob = encrypt(b"header test", _PW, suite_id=0x04, iterations=12345)
    assert blob[:4] == MAGIC
    version  = blob[4]
    suite_id = blob[5]
    salt_len = blob[6]
    assert version & 0x3F == VERSION_BASE
    assert suite_id == 0x04
    assert salt_len == 16
    iterations = struct.unpack(">I", blob[7 + salt_len: 7 + salt_len + 4])[0]
    assert iterations == 12345


# ---------------------------------------------------------------------------
# U-12 — Empty plaintext round-trip
# ---------------------------------------------------------------------------

def test_u12_empty_plaintext():
    blob = encrypt(b"", _PW, suite_id=0x04, iterations=_FAST_ITERS)
    assert decrypt(blob, _PW) == b""


# ---------------------------------------------------------------------------
# U-13 — Large input (64 MB) round-trip
# ---------------------------------------------------------------------------

def test_u13_large_input():
    plaintext = os.urandom(64 * 1024 * 1024)
    blob = encrypt(plaintext, _PW, suite_id=0x11, iterations=_FAST_ITERS)
    assert decrypt(blob, _PW) == plaintext


# ---------------------------------------------------------------------------
# U-14 — Wrong password causes verification failure
# ---------------------------------------------------------------------------

def test_u14_wrong_password():
    blob = encrypt(b"private data", _PW, suite_id=0x04, iterations=_FAST_ITERS)
    with pytest.raises(HMACVerificationError):
        decrypt(blob, b"wrong-password")


def test_u14_wrong_password_gcm():
    blob = encrypt(b"private data", _PW, suite_id=0x11, iterations=_FAST_ITERS)
    with pytest.raises(HMACVerificationError):
        decrypt(blob, b"wrong-password")


# ---------------------------------------------------------------------------
# U-15 — All six CBC-HMAC suite IDs produce distinct outputs
# ---------------------------------------------------------------------------

def test_u15_all_suites_distinct():
    CBC_SUITES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    plaintext = b"same plaintext for all suites"
    outputs = [
        encrypt(plaintext, _PW, suite_id=sid, iterations=_FAST_ITERS)
        for sid in CBC_SUITES
    ]
    # All outputs must be pairwise distinct
    for i in range(len(outputs)):
        for j in range(i + 1, len(outputs)):
            assert outputs[i] != outputs[j], f"Suites 0x{CBC_SUITES[i]:02X} and 0x{CBC_SUITES[j]:02X} produced identical output"
