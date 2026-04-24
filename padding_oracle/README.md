# Padding Oracle Attack — Complete Guide

## Table of Contents

1. [What is AES-CBC?](#1-what-is-aes-cbc)
2. [What is PKCS7 Padding?](#2-what-is-pkcs7-padding)
3. [What is a Padding Oracle?](#3-what-is-a-padding-oracle)
4. [How a Server Becomes a Padding Oracle](#4-how-a-server-becomes-a-padding-oracle)
5. [How the Attack Works](#5-how-the-attack-works)
6. [Can the Attack Recover the Key?](#6-can-the-attack-recover-the-key)

---

## 1. What is AES-CBC?

**AES (Advanced Encryption Standard)** is a symmetric block cipher. It encrypts data in fixed 16-byte (128-bit) blocks. The same key is used to encrypt and decrypt.

**CBC (Cipher Block Chaining)** is the mode that defines how multiple blocks are handled.

### Encryption

Each plaintext block is XOR'd with the previous ciphertext block before encrypting. For the first block, a random **IV (Initialization Vector)** plays the role of the previous block.

```
CipherText[n] = Encrypt( PlainText[n] XOR CipherText[n-1] )
```

### Decryption

```
PlainText[n] = Decrypt( CipherText[n] ) XOR CipherText[n-1]
```

### Output Format

```
[IV (16 bytes, plaintext)][C1 (16 bytes, encrypted)][C2 (16 bytes, encrypted)]...
```

- The **IV is sent unencrypted** — it doesn't need to be secret, just random
- **C1, C2, ...** are the actual encrypted ciphertext blocks
- IV and every ciphertext block are the **same size: 16 bytes**

The chaining relationship `PlainText[n] = Decrypt(C[n]) XOR C[n-1]` is exactly what the padding oracle attack exploits.

---

## 2. What is PKCS7 Padding?

AES requires input to be an **exact multiple of 16 bytes**. PKCS7 padding fills the gap.

### The Rule

Fill the missing bytes with a value equal to the number of missing bytes.

```
"Hello World" (11 bytes) → needs 5 bytes of padding:

H  e  l  l  o     W  o  r  l  d  05 05 05 05 05
[0][1][2][3][4][5][6][7][8][9][10][11][12][13][14][15]
```

### Examples

| Message length | Padding needed | Padding bytes        |
| -------------- | -------------- | -------------------- |
| 11 bytes       | 5 bytes        | `05 05 05 05 05`     |
| 14 bytes       | 2 bytes        | `02 02`              |
| 15 bytes       | 1 byte         | `01`                 |
| 16 bytes       | full block!    | `10 10 ... 10` (×16) |

> If the message is already a perfect multiple of 16, a **full extra block of padding** is added so the receiver can always unambiguously remove it.

### Validation on Decryption

After decrypting, the receiver reads the **last byte** and checks that all padding bytes match that value. If they don't match, an exception is thrown:

```
Last byte = 0x05?
→ Check that bytes [11][12][13][14][15] are ALL 0x05
→ If any differ → throw exception
```

This exception is the foundation of the padding oracle.

---

## 3. What is a Padding Oracle?

An **oracle** in cryptography is anything that answers yes/no questions about secret data. A padding oracle is specifically something that tells you — directly or indirectly — whether a decrypted message has **valid or invalid padding**.

The crucial point: **the attacker doesn't need to know the key**. They only need to be able to submit encrypted data and observe the difference in the server's response.

### In This Code

`TryDecrypt` is the oracle:

```csharp
public bool TryDecrypt(byte[] enc_data)
{
    try
    {
        using (CryptoStream cryptoStream = ...)
        {
            string msg = reader.ReadToEnd();
            return true;    // ← padding was VALID
        }
    }
    catch (Exception ex)
    {
        return false;       // ← padding was INVALID
    }
}
```

- ✅ `true` = padding is valid
- ❌ `false` = padding is invalid

That single bit of information is enough to decrypt the entire message without knowing the key.

---

## 4. How a Server Becomes a Padding Oracle

In a real application, the client only submits an encrypted message — it never sees the server's key or the decryption logic. But the **server's response itself** becomes the oracle.

### The Client-Server Flow

```
Client                                  Server
  │                                        │
  │── sends modified encrypted message ───▶│
  │                                        │  1. Decrypt with AES-CBC
  │                                        │  2. Check PKCS7 padding
  │                                        │     ├── valid   → process request
  │                                        │     └── invalid → throw exception
  │◀── response ───────────────────────────│
  │    (200 OK  or  500 Error)             │
```

The client never sees the key. But the server's response — `200 OK` vs `500 Error`, a different error message, or even a timing difference — reveals whether the padding was valid. That's the oracle.

The attacker's strategy is simple:

1. Take a legitimate encrypted message
2. Modify one byte at a time
3. Submit it to the server and observe the response
4. Repeat until the plaintext is recovered

### What Makes the Server Vulnerable

The vulnerability is not in AES or CBC themselves — it is in **leaking the reason for failure**. A safe server always returns the same response regardless of what went wrong:

```
✅ Safe:   "Request failed"         ← same message always, attacker learns nothing
❌ Unsafe: "Padding error"          ← tells attacker the ciphertext was decrypted but padding was wrong
❌ Unsafe: "Authentication failed"  ← tells attacker the padding was fine, but content was wrong
❌ Unsafe: fast vs slow response    ← timing difference reveals padding validity
```

### What Happens in C#

In .NET, when AES-CBC encounters invalid padding during decryption, it throws a specific exception:

```
System.Security.Cryptography.CryptographicException:
  "Padding is invalid and cannot be removed."
```

If the server catches this exception but returns a different HTTP response than it would for a normal error (like an auth failure), the distinction leaks out. A vulnerable ASP.NET server might return:

```
HTTP 500 — CryptographicException  ← bad padding
HTTP 403 — Forbidden               ← valid padding, but wrong credentials
```

An attacker watching these responses has their oracle. This is exactly how the **ASP.NET padding oracle (CVE-2010-3332)** worked — it was exploited against millions of ASP.NET websites using a tool called POET.

### What Happens in Java

Java behaves the same way but with different exception types:

```
javax.crypto.BadPaddingException     ← invalid padding
javax.crypto.IllegalBlockSizeException ← ciphertext length not a multiple of 16
```

A vulnerable Java server leaks these the same way:

```java
try {
    cipher.doFinal(encryptedBytes);   // throws BadPaddingException if padding is wrong
    // process request...
} catch (BadPaddingException e) {
    response.sendError(500, "Decryption failed");   // ← different from auth errors
} catch (AuthException e) {
    response.sendError(403, "Access denied");        // ← attacker sees the difference
}
```

Even if the error messages look the same to a human, an attacker can measure **response timing**. Java's AES implementation may take slightly different amounts of time to throw `BadPaddingException` vs complete successfully — that timing difference alone is enough (this is the **Lucky Thirteen** attack, 2013).

### Summary: What Makes Any Server a Padding Oracle

| Behaviour                                                | Oracle? |
| -------------------------------------------------------- | ------- |
| Returns `500` for bad padding, `403` for auth failure    | ✅ Yes  |
| Returns different error messages for each failure type   | ✅ Yes  |
| Responds faster for bad padding than for auth failure    | ✅ Yes  |
| Always returns the same response and takes the same time | ❌ No   |

---

## 5. How the Attack Works

### The Core Insight

Because CBC XORs the previous ciphertext block into the plaintext, **controlling that previous block lets you manipulate the plaintext one byte at a time** — and the oracle tells you when you've guessed correctly.

### The Setup

Message: `"HELLOWORLD1234"` — 14 bytes, so PKCS7 adds `02 02` padding.

Plaintext block:

```
H    E    L    L    O    W    O    R    L    D    1    2    3    4    02   02
0x48 0x45 0x4C 0x4C 0x4F 0x57 0x4F 0x52 0x4C 0x44 0x31 0x32 0x33 0x34 0x02 0x02
[0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]  [8]  [9]  [10] [11] [12] [13] [14] [15]
```

After encryption you get `[IV][C1]`. The attacker can see:

```
IV[15] = 0xB4    ← known (sent in plaintext)
IV[14] = 0xA1    ← known
IV[13] = 0x77    ← known
C1     = ???     ← known but encrypted, can't read directly
```

What is **unknown** to the attacker — the hidden intermediate values inside the cipher:

```
Decrypt(C1)[15] = 0xB6    ← fixed by the key, never changes
Decrypt(C1)[14] = 0xA3    ← fixed by the key, never changes
Decrypt(C1)[13] = 0x43    ← fixed by the key, never changes
```

The real plaintext (what the attacker wants):

```
P1[15] = Decrypt(C1)[15] XOR IV[15] = 0xB6 XOR 0xB4 = 0x02
P1[14] = Decrypt(C1)[14] XOR IV[14] = 0xA3 XOR 0xA1 = 0x02
P1[13] = Decrypt(C1)[13] XOR IV[13] = 0x43 XOR 0x77 = 0x34 = '4'
```

The attacker knows none of this — they only know IV and C1. The attack figures it out one byte at a time.

---

### Round 1 — Recover byte [15]

**Goal:** find `test_IV[15]` that makes the last decrypted byte = `0x01` (valid 1-byte padding).

The attacker makes a copy of the ciphertext, tries all 256 values for `test_IV[15]`, and sends each one to the oracle:

```
test_IV[15] = 0x00 → Decrypt(C1)[15] XOR 0x00 = 0xB6 XOR 0x00 = 0xB6 → ❌
test_IV[15] = 0x01 → 0xB6 XOR 0x01 = 0xB7 → ❌
test_IV[15] = 0x02 → 0xB6 XOR 0x02 = 0xB4 → ❌
...
test_IV[15] = 0xB7 → 0xB6 XOR 0xB7 = 0x01 → ✅  STOP!
```

Oracle says ✅ at `0xB7`. Now the attacker knows:

```
Decrypt(C1)[15] XOR 0xB7 = 0x01
→ Decrypt(C1)[15] = 0xB7 XOR 0x01 = 0xB6   ← intermediate value revealed!
```

**Recover the real plaintext byte:**

```
plaintext[15] = Decrypt(C1)[15] XOR original_IV[15]
              = 0xB6 XOR 0xB4
              = 0x02  ✅
```

Byte `[15]` = `0x02` — the padding byte. Correct!

---

### Round 2 — Recover byte [14]

**Goal:** find `test_IV[14]` that makes the last two bytes = `0x02 0x02`.

First, **lock byte [15]** so it always produces `0x02`. Using the intermediate value found in Round 1:

```
test_IV[15] = Decrypt(C1)[15] XOR 0x02
            = 0xB6 XOR 0x02
            = 0xB4   ← locked for this entire round
```

Now brute-force `test_IV[14]` with `test_IV[15] = 0xB4` fixed:

```
test_IV[14] = 0x00 → P1[14] = 0xA3 XOR 0x00 = 0xA3,  P1[15] = 0x02 → ❌  (0xA3 ≠ 0x02)
test_IV[14] = 0x01 → P1[14] = 0xA3 XOR 0x01 = 0xA2 → ❌
...
test_IV[14] = 0xA1 → P1[14] = 0xA3 XOR 0xA1 = 0x02,  P1[15] = 0x02 → ✅  STOP!
```

Oracle says ✅ at `0xA1`. Now the attacker knows:

```
Decrypt(C1)[14] XOR 0xA1 = 0x02
→ Decrypt(C1)[14] = 0xA1 XOR 0x02 = 0xA3   ← intermediate value revealed!
```

**Recover the real plaintext byte:**

```
plaintext[14] = Decrypt(C1)[14] XOR original_IV[14]
              = 0xA3 XOR 0xA1
              = 0x02  ✅
```

Byte `[14]` = `0x02` — second padding byte. Correct!

---

### Round 3 — Recover byte [13]

**Goal:** find `test_IV[13]` that makes the last three bytes = `0x03 0x03 0x03`.

Lock bytes `[15]` and `[14]` to produce `0x03`, using their intermediate values:

```
test_IV[15] = Decrypt(C1)[15] XOR 0x03 = 0xB6 XOR 0x03 = 0xB5
test_IV[14] = Decrypt(C1)[14] XOR 0x03 = 0xA3 XOR 0x03 = 0xA0
```

Now brute-force `test_IV[13]`:

```
test_IV[13] = 0x00 → P1[13] = 0x43 XOR 0x00 = 0x43 → ❌
test_IV[13] = 0x01 → P1[13] = 0x43 XOR 0x01 = 0x42 → ❌
...
test_IV[13] = 0x40 → P1[13] = 0x43 XOR 0x40 = 0x03,  P1[14] = 0x03,  P1[15] = 0x03 → ✅  STOP!
```

Oracle says ✅ at `0x40`. Now the attacker knows:

```
Decrypt(C1)[13] XOR 0x40 = 0x03
→ Decrypt(C1)[13] = 0x40 XOR 0x03 = 0x43   ← intermediate value revealed!
```

**Recover the real plaintext byte — broken into two steps:**

Step 1 — the intermediate value (from oracle result):

```
Decrypt(C1)[13] = found_value XOR padding_target
                = 0x40        XOR 0x03
                = 0x43
```

Step 2 — the real plaintext (CBC decryption):

```
plaintext[13] = Decrypt(C1)[13] XOR original_IV[13]
              = 0x43            XOR 0x77
              = 0x34 = '4'  ✅
```

Combined as one line:

```
plaintext[13] = (0x40 XOR 0x03) XOR 0x77 = 0x43 XOR 0x77 = 0x34 = '4'
```

Breaking down the XOR bit by bit:

```
  0x40 = 0100 0000   ← the value the attacker found
  0x03 = 0000 0011   ← the padding target
  XOR  = 0100 0011 = 0x43   ← Decrypt(C1)[13], the hidden intermediate

  0x43 = 0100 0011
  0x77 = 0111 0111   ← original_IV[13], always known
  XOR  = 0011 0100 = 0x34 = '4'   ← plaintext recovered!
```

Byte `[13]` = `'4'` — the last real character of the message. Correct!

---

### The Pattern — Every Byte Follows These 3 Steps

```
① Fix all previously-recovered bytes to produce the next padding value
② Try all 256 values for the current byte position
③ When oracle says ✅ → compute the real plaintext byte
```

Visualised across all 16 positions of a block:

```
Round 1:  target = 01                → recover byte [15]  = 0x02 (padding)
Round 2:  target = 02 02             → recover byte [14]  = 0x02 (padding)
Round 3:  target = 03 03 03          → recover byte [13]  = '4'
Round 4:  target = 04 04 04 04       → recover byte [12]  = '3'
...
Round 16: target = 10 10 ... 10      → recover byte [0]   = 'H'
```

Each round builds on the previous — every intermediate value found is reused to lock that position at the new padding target for all future rounds.

### The Core Formula

```
plaintext[pos] = (found_value XOR padding_target) XOR original_IV[pos]
               =  Decrypt(C1)[pos]               XOR original_IV[pos]
```

This is just CBC decryption — but `Decrypt(C1)[pos]` was revealed using the oracle instead of the key.

### Cost

- At most **256 oracle calls per byte**
- 16 bytes × 256 = **4096 oracle calls** to decrypt one full block
- No key required

---

## 6. Can the Attack Recover the Key?

**No.** The padding oracle attack only recovers the **plaintext**. The AES key remains completely unknown throughout the entire attack.

The attack works by exploiting the CBC XOR relationship to deduce plaintext byte by byte — it never needs to touch or guess the key. Even after recovering the full plaintext, the key is still secret.

To compromise the key itself, a completely different class of attack would be needed — for example, a flaw in how the key is stored or transmitted, or a side-channel attack on the AES hardware implementation.

---

## Sources

The following references were used as the basis for the concepts explained in this document.

**AES and CBC Mode**
- NIST FIPS 197 — *Advanced Encryption Standard (AES)* — https://csrc.nist.gov/publications/detail/fips/197/final
- NIST SP 800-38A — *Recommendation for Block Cipher Modes of Operation* — https://csrc.nist.gov/publications/detail/sp/800-38a/final

**PKCS7 Padding**
- RFC 5652 — *Cryptographic Message Syntax (CMS)*, Section 6.3 — https://www.rfc-editor.org/rfc/rfc5652#section-6.3

**Padding Oracle Attack — Original Research**
- Serge Vaudenay (2002) — *Security Flaws Induced by CBC Padding Applications to SSL, IPSEC, WTLS...* — https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf

**Real-World Attacks**
- CVE-2010-3332 — ASP.NET Padding Oracle Vulnerability — https://www.cve.org/CVERecord?id=CVE-2010-3332
- Thai Duong & Juliano Rizzo (2011) — *BEAST: Browser Exploit Against SSL/TLS* — https://bug665814.bmoattachments.org/attachment.cgi?id=540839
- Bodo Möller, Thai Duong & Krzysztof Kotowicz (2014) — *This POODLE Bites: Exploiting the SSL 3.0 Fallback* — https://www.openssl.org/~bodo/ssl-poodle.pdf
- Nadhem AlFardan & Kenneth Paterson (2013) — *Lucky Thirteen: Breaking the TLS and DTLS Record Protocols* — https://www.isg.rhul.ac.uk/tls/TLStiming.pdf

---

## Acknowledgement

This document was written with the assistance of **Claude** (Anthropic), an AI assistant, as part of a step-by-step learning session on cryptographic attack techniques. The explanations, examples, and hex calculations were developed interactively to build understanding from first principles.

The code analysed throughout this document (`Program.cs`) is a C# demonstration of the padding oracle attack for educational purposes.

