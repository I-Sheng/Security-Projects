# Encryption Utility

A command-line tool for symmetric file and text encryption. Supports AES-128, AES-256, and 3DES in CBC-HMAC and GCM modes, with password-based key derivation via PBKDF2 and optional HKDF. All encrypted output is self-describing: the binary header stores the algorithm suite, salt, and iteration count so decryption requires only the password.

---

## Cryptographic Design

### Key Derivation

Three keys are derived from the user's password using PBKDF2:

```
Km = PBKDF2(password,  salt,             iterations, H)
Ke = PBKDF2(Km,        "encryption key", 1,          H)   ← CBC only
Kh = PBKDF2(Km,        "hmac key",       1,          H)   ← CBC only
```

For GCM suites, `Km` is truncated directly to the cipher key length — the authentication tag replaces HMAC entirely.

An optional HKDF second stage is available for faster derivation when maximum compatibility is not required.

### Supported Suites

| Suite ID | Algorithm                    | Mode | Auth        | Notes                        |
|----------|------------------------------|------|-------------|------------------------------|
| `0x01`   | AES-128                      | CBC  | HMAC-SHA256 |                              |
| `0x02`   | AES-128                      | CBC  | HMAC-SHA512 |                              |
| `0x03`   | AES-256                      | CBC  | HMAC-SHA256 |                              |
| `0x04`   | AES-256                      | CBC  | HMAC-SHA512 | **Default**                  |
| `0x05`   | 3DES (168-bit)               | CBC  | HMAC-SHA256 | Legacy — deprecation warning |
| `0x06`   | 3DES (168-bit)               | CBC  | HMAC-SHA512 | Legacy — deprecation warning |
| `0x10`   | AES-128                      | GCM  | 128-bit tag |                              |
| `0x11`   | AES-256                      | GCM  | 128-bit tag | Recommended for new files    |

Default iteration counts (OWASP 2023 / NIST SP 800-132):

| Hash    | Iterations | ~Time on i7-12700 |
|---------|------------|-------------------|
| SHA-256 | 600,000    | ~570 ms           |
| SHA-512 | 210,000    | ~295 ms           |

### Binary Output Format

Every encrypted file begins with the magic bytes `ENCR` followed by a self-describing header:

```
Offset     Field
------     -----
0          Magic: "ENCR" (4 bytes)
4          Version byte  (flags: bit 7 = metadata in HMAC, bit 6 = HKDF)
5          Suite ID
6          Salt length N
7          Salt (N bytes, random)
7+N        Iteration count (big-endian uint32)
11+N       IV length M
12+N       IV (M bytes, random)
12+N+M     Ciphertext length (big-endian uint64)
20+N+M     Ciphertext  [CBC: followed by HMAC | GCM: tag appended in-band]
```

The HMAC (CBC mode) covers `[metadata header ||] IV || Ciphertext` and is verified with a constant-time comparison before any decryption takes place — preventing padding-oracle attacks.

---

## Installation

Requires Python 3.11+ and [Poetry](https://python-poetry.org/).

```bash
cd encryption_application
poetry install
```

---

## Usage

```
poetry run python app.py <command> [options]
```

### List cipher suites

```bash
poetry run python app.py suites
```

### Encrypt

```bash
# Encrypt a file (default suite: AES-256-CBC/HMAC-SHA512)
poetry run python app.py encrypt -i plaintext.txt -o plaintext.enc

# Encrypt a text string directly
poetry run python app.py encrypt -t "secret message" -o message.enc

# Choose a specific suite by ID or label substring
poetry run python app.py encrypt -i file.txt -o file.enc -s 0x11        # AES-256-GCM
poetry run python app.py encrypt -i file.txt -o file.enc -s gcm         # same, by label

# Override iteration count
poetry run python app.py encrypt -i file.txt -o file.enc -n 1000000

# Use HKDF for second-stage key derivation
poetry run python app.py encrypt -i file.txt -o file.enc --hkdf
```

The password is always prompted interactively (with confirmation) — it is never passed on the command line.

### Decrypt

```bash
# Decrypt to a file
poetry run python app.py decrypt -i plaintext.enc -o plaintext.txt

# Decrypt and print to stdout (text files)
poetry run python app.py decrypt -i message.enc
```

If the password is wrong or the file has been tampered with, decryption is refused with an authentication error — no partial plaintext is exposed.

### Options reference

**`encrypt`**

| Flag | Description |
|------|-------------|
| `-i FILE` / `--input FILE` | Input file to encrypt (mutually exclusive with `--text`) |
| `-t TEXT` / `--text TEXT` | Input text to encrypt (mutually exclusive with `--input`) |
| `-o FILE` / `--output FILE` | Output encrypted file (required) |
| `-s SUITE` / `--suite SUITE` | Suite ID (hex) or label substring (default: `0x04`) |
| `-n N` / `--iterations N` | PBKDF2 iteration count (default: suite-dependent) |
| `--hkdf` | Use HKDF for second-stage key derivation |
| `--no-meta-hmac` | Exclude metadata from HMAC input |

**`decrypt`**

| Flag | Description |
|------|-------------|
| `-i FILE` / `--input FILE` | Input encrypted file (required) |
| `-o FILE` / `--output FILE` | Output file (default: print plaintext to stdout) |

---

## Running the Tests

```bash
# Fast tests only (< 1 second total)
poetry run pytest tests/ -v -k "not b01 and not b02 and not b03 and not u13"

# Full suite including 64 MB round-trip and PBKDF2 benchmarks
poetry run pytest tests/ -v -s
```

### Test Coverage

| ID    | Description                                               |
|-------|-----------------------------------------------------------|
| U-01  | PBKDF2 key derivation against hashlib reference vectors   |
| U-02  | AES-128-CBC round-trip                                    |
| U-03  | AES-256-CBC round-trip                                    |
| U-04  | 3DES-CBC round-trip                                       |
| U-05  | AES-128-GCM round-trip                                    |
| U-06  | AES-256-GCM round-trip                                    |
| U-07  | Tampered ciphertext rejected (HMAC)                       |
| U-08  | Tampered IV rejected (HMAC)                               |
| U-09  | Tampered metadata rejected (HMAC)                         |
| U-10  | Tampered ciphertext rejected (GCM auth tag)               |
| U-11  | Binary header round-trips correctly                       |
| U-12  | Empty plaintext encrypts and decrypts                     |
| U-13  | 64 MB input round-trip                                    |
| U-14  | Wrong password causes HMAC/GCM failure                    |
| U-15  | All six CBC-HMAC suite IDs produce distinct outputs       |
| I-01  | Text round-trip across all suites                         |
| I-02  | Binary file round-trip (byte-for-byte identical)          |
| I-03  | Input file unchanged after encryption                     |
| I-04  | Different iteration count produces different ciphertext   |
| I-05  | Corrupted magic / unknown suite fails cleanly             |
| B-01  | PBKDF2-SHA256 600k iterations — wall time reported        |
| B-02  | PBKDF2-SHA512 210k iterations — wall time reported        |
| B-03  | AES-256-GCM 64 MB throughput — MB/s reported              |

---

## Project Structure

```
encryption_application/
├── crypto.py                  # All cryptographic operations
├── app.py                     # CLI entry point (encrypt / decrypt / suites)
├── tests/
│   ├── conftest.py
│   ├── test_unit.py           # U-01..U-15
│   └── test_integration.py    # I-01..I-05, B-01..B-03
├── encryption_utility_design.md
└── pyproject.toml
```

`crypto.py` can also be imported directly for scripted use:

```python
from crypto import encrypt, decrypt, HMACVerificationError

blob = encrypt(b"secret data", b"my-password", suite_id=0x11)
plaintext = decrypt(blob, b"my-password")
```

---

## Security Notes

- **Encrypt-then-MAC** — HMAC is verified before any decryption in all CBC modes.
- **Constant-time comparison** — `hmac.compare_digest` prevents timing side-channels.
- **Random salt and IV** — generated with `os.urandom` (CSPRNG) per encryption; never reused.
- **No file overwrite** — encrypted output is always written to a new path.
- **Password never on command line** — always collected via `getpass` (no shell history exposure).
- **3DES** — included for legacy interoperability only. Its 64-bit block size makes it vulnerable to SWEET32 at ~68 GB of traffic, and its effective security is ~112 bits. Prefer AES for all new data.

---

## Dependencies

| Package        | Purpose                                          |
|----------------|--------------------------------------------------|
| `cryptography` | AES-CBC, AES-GCM, 3DES, PBKDF2, HKDF, HMAC      |
| `pytest`       | Test runner (dev dependency)                     |
