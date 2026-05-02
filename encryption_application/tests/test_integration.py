"""Integration tests I-01..I-05 and benchmarks B-01..B-03."""

import os
import time
import tempfile

import pytest

from crypto import SUITE_PARAMS, encrypt, decrypt, HMACVerificationError

_PW = b"integration-test-password"
_FAST_ITERS = 1


# ---------------------------------------------------------------------------
# I-01 — Text round-trip across all suites
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("suite_id", list(SUITE_PARAMS.keys()))
def test_i01_text_round_trip(suite_id):
    text = "Hello, encrypted world! 🔐"
    plaintext = text.encode("utf-8")
    blob = encrypt(plaintext, _PW, suite_id=suite_id, iterations=_FAST_ITERS)
    recovered = decrypt(blob, _PW)
    assert recovered.decode("utf-8") == text


# ---------------------------------------------------------------------------
# I-02 — Binary file round-trip
# ---------------------------------------------------------------------------

def test_i02_binary_file_round_trip(tmp_path):
    original = os.urandom(4 * 1024)   # 4 KB random binary
    in_file  = tmp_path / "input.bin"
    enc_file = tmp_path / "input.enc"
    out_file = tmp_path / "output.bin"

    in_file.write_bytes(original)
    blob = encrypt(in_file.read_bytes(), _PW, suite_id=0x04, iterations=_FAST_ITERS)
    enc_file.write_bytes(blob)
    out_file.write_bytes(decrypt(enc_file.read_bytes(), _PW))

    assert out_file.read_bytes() == original


# ---------------------------------------------------------------------------
# I-03 — Input file is not modified after encryption
# ---------------------------------------------------------------------------

def test_i03_input_file_unchanged(tmp_path):
    original = b"do not touch this file"
    in_file  = tmp_path / "input.txt"
    enc_file = tmp_path / "output.enc"

    in_file.write_bytes(original)
    blob = encrypt(in_file.read_bytes(), _PW, suite_id=0x11, iterations=_FAST_ITERS)
    enc_file.write_bytes(blob)

    assert in_file.read_bytes() == original


# ---------------------------------------------------------------------------
# I-04 — Changing iteration count produces a different ciphertext
# ---------------------------------------------------------------------------

def test_i04_different_iterations_differ():
    plaintext = b"same plaintext, different iterations"
    blob_a = encrypt(plaintext, _PW, suite_id=0x11, iterations=1)
    blob_b = encrypt(plaintext, _PW, suite_id=0x11, iterations=2)
    assert blob_a != blob_b


# ---------------------------------------------------------------------------
# I-05 — Wrong suite ID or corrupted header fails cleanly
# ---------------------------------------------------------------------------

def test_i05_wrong_magic_fails():
    blob = bytearray(encrypt(b"data", _PW, suite_id=0x04, iterations=_FAST_ITERS))
    blob[0] = 0xFF  # corrupt magic
    with pytest.raises((ValueError, HMACVerificationError)):
        decrypt(bytes(blob), _PW)


def test_i05_unknown_suite_fails():
    blob = bytearray(encrypt(b"data", _PW, suite_id=0x04, iterations=_FAST_ITERS))
    blob[5] = 0x99  # unknown suite
    with pytest.raises((ValueError, HMACVerificationError)):
        decrypt(bytes(blob), _PW)


# ---------------------------------------------------------------------------
# B-01..B-03 — Benchmarks (reported only, no hard timing assertions)
# ---------------------------------------------------------------------------

def _bench(label, fn):
    t0 = time.perf_counter()
    fn()
    elapsed = (time.perf_counter() - t0) * 1000
    print(f"\n[INFO] {label}: {elapsed:.0f} ms")
    return elapsed


def test_b01_pbkdf2_sha256_600k(capsys):
    _bench(
        "B-01  PBKDF2-SHA256 600k iterations",
        lambda: encrypt(b"bench", b"password", suite_id=0x01, iterations=600_000),
    )


def test_b02_pbkdf2_sha512_210k(capsys):
    _bench(
        "B-02  PBKDF2-SHA512 210k iterations",
        lambda: encrypt(b"bench", b"password", suite_id=0x04, iterations=210_000),
    )


def test_b03_aes256_gcm_throughput(capsys):
    data = os.urandom(64 * 1024 * 1024)
    blob = encrypt(data, b"password", suite_id=0x11, iterations=1)   # derive once
    t0   = time.perf_counter()
    decrypt(blob, b"password")
    elapsed = time.perf_counter() - t0
    throughput = (64 / elapsed)
    print(f"\n[INFO] B-03  AES-256-GCM 64 MB throughput: {throughput:.0f} MB/s")
