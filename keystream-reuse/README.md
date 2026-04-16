# Stream Cipher Keystream Reuse Attack

This document shows how to recover the plaintext of two ciphertexts that were encrypted with the same stream-cipher keystream.

## Problem

We are given two ciphertexts in hex:

```text
C1 = 889e18c32d084fb44c49558a97d3c5f7a694325f36ac45752de9a423ea428161
C2 = 98974d9a2f1408b857071c91c390cdffb794215f79ab09732cfbe066b9428161
```

The ciphertexts are the same length, and we are told both plaintexts are standard printable ASCII with no control characters.

## Why keystream reuse is fatal

For a stream cipher:

```text
C1 = P1 XOR K
C2 = P2 XOR K
```

If the same keystream `K` is reused, then XORing the ciphertexts cancels the keystream:

```text
C1 XOR C2 = P1 XOR P2
```

That means we do not immediately get either plaintext, but we do get a byte-by-byte relationship between the two plaintexts. For English text, that is often enough to recover both messages.

## Step 1: XOR the ciphertexts

```python
c1 = bytes.fromhex("889e18c32d084fb44c49558a97d3c5f7a694325f36ac45752de9a423ea428161")
c2 = bytes.fromhex("98974d9a2f1408b857071c91c390cdffb794215f79ab09732cfbe066b9428161")

x = bytes(a ^ b for a, b in zip(c1, c2))

print("Length:", len(x))
print("C1 XOR C2:", x.hex())
```

Output:

```text
Length: 32
C1 XOR C2: 10095559021c470c1b4e491b54430808110013004f074c060112444553000000
```

So:

```text
P1 XOR P2 = 10 09 55 59 02 1c 47 0c 1b 4e 49 1b 54 43 08 08 11 00 13 00 4f 07 4c 06 01 12 44 45 53 00 00 00
```

## Step 2: Use ASCII structure

Because the plaintexts are printable ASCII, spaces are especially useful.

The space character is:

```text
0x20
```

If one plaintext contains a space and the other contains a letter at the same position, then:

```text
space XOR letter
```

often gives another alphabetic-looking byte. That makes likely space positions easier to spot.

Code:

```python
for i, b in enumerate(x):
    candidate = chr(b ^ 0x20)
    if candidate.isalpha():
        print(i, hex(b), "possible space/letter position ->", candidate)
```

This does not directly solve the problem, but it shows that the XOR pattern is consistent with ordinary English text.

## Step 3: Crib-dragging

Crib-dragging means guessing a likely word or phrase in one plaintext, XORing it against `P1 XOR P2`, and seeing whether the resulting text in the other plaintext is also readable English.

Use this helper:

```python
def crib_drag(x, crib):
    crib = crib.encode("ascii")
    for i in range(len(x) - len(crib) + 1):
        other = bytes(x[i + j] ^ crib[j] for j in range(len(crib)))
        if all(32 <= b <= 126 for b in other):
            print(f"offset {i:2d}: {crib.decode()}  <->  {other.decode()}")
```

Try a few common words or openings:

```python
crib_drag(x, "You ")
crib_drag(x, "If ")
crib_drag(x, "class")
crib_drag(x, "grades")
```

One strong starting hit appears at offset `0`:

```text
"You " <-> "If y"
```

That suggests the messages may start like:

```text
P2: You ...
P1: If y...
```

Now extend that idea with a longer natural English guess:

```python
guess2 = b"You might not get "
guess1 = bytes(x[i] ^ guess2[i] for i in range(len(guess2)))
print(guess1.decode())
```

Output:

```text
If you don't come
```

That is a very strong sign we are on the right track, because both sides are fluent English and match the XOR exactly.

So the first 18 characters are:

```text
P1: If you don't come 
P2: You might not get 
```

## Step 4: Finish the messages

Look at the remaining suffix. A natural continuation for the first plaintext is:

```text
to class   ...
```

Use the XOR to recover the matching suffix in the second plaintext:

```python
prefix1 = b"If you don't come "
prefix2 = b"You might not get "

rest = x[len(prefix1):]
suffix1 = b"to class   ..."
suffix2 = bytes(rest[i] ^ suffix1[i] for i in range(len(suffix1)))

print("Recovered suffix 2:", suffix2.decode())
```

Output:

```text
Recovered suffix 2: good grades...
```

So the full plaintexts are:

```text
P1 = "If you don't come to class   ..."
P2 = "You might not get good grades..."
```

## Step 5: Verify by recovering the reused keystream segment

Once the plaintexts are known, we can recover the keystream bytes used for these 32 positions:

```python
p1 = b"If you don't come to class   ..."
p2 = b"You might not get good grades..."

k1 = bytes(c1[i] ^ p1[i] for i in range(len(c1)))
k2 = bytes(c2[i] ^ p2[i] for i in range(len(c2)))

print("Same keystream?", k1 == k2)
print("Keystream:", k1.hex())
```

Output:

```text
Same keystream? True
Keystream: c1f838ba427d6fd0232772feb7b0aa9ac3b4463016cf29145e9a8403ca6caf4f
```

Recovered keystream segment:

```text
c1 f8 38 ba 42 7d 6f d0 23 27 72 fe b7 b0 aa 9a
c3 b4 46 30 16 cf 29 14 5e 9a 84 03 ca 6c af 4f
```

Now verify by re-encrypting:

```python
reenc1 = bytes(p1[i] ^ k1[i] for i in range(len(p1)))
reenc2 = bytes(p2[i] ^ k1[i] for i in range(len(p2)))

print("C1 matches?", reenc1 == c1)
print("C2 matches?", reenc2 == c2)
```

Expected output:

```text
C1 matches? True
C2 matches? True
```

## Can we recover the original secret key?

We can recover the reused keystream segment for these exact 32 byte positions:

```text
c1f838ba427d6fd0232772feb7b0aa9ac3b4463016cf29145e9a8403ca6caf4f
```

But in general, we cannot recover the underlying long-term secret key from only this information unless we also know more about the cipher construction, such as:

- the exact stream cipher being used
- whether there is a nonce or IV
- how the keystream is derived from the secret key
- enough extra information to invert that derivation

For example, if this were a one-time pad, the recovered keystream segment is all we can ever get. If it were a modern stream cipher like ChaCha20 or RC4, this recovered keystream segment still would not normally be enough to recover the secret key itself.

So the correct statement is:

- We successfully recovered both plaintexts.
- We successfully recovered the 32-byte reused keystream segment.
- We did not recover the underlying secret encryption key.

## Complete script

```python
c1 = bytes.fromhex("889e18c32d084fb44c49558a97d3c5f7a694325f36ac45752de9a423ea428161")
c2 = bytes.fromhex("98974d9a2f1408b857071c91c390cdffb794215f79ab09732cfbe066b9428161")

x = bytes(a ^ b for a, b in zip(c1, c2))
print("C1 XOR C2 =", x.hex())

print("\nLikely space/letter positions:")
for i, b in enumerate(x):
    candidate = chr(b ^ 0x20)
    if candidate.isalpha():
        print(i, hex(b), "->", candidate)

def crib_drag(x, crib):
    crib = crib.encode("ascii")
    print(f"\nTrying crib: {crib.decode()!r}")
    for i in range(len(x) - len(crib) + 1):
        other = bytes(x[i + j] ^ crib[j] for j in range(len(crib)))
        if all(32 <= b <= 126 for b in other):
            print(f"offset {i:2d}: {crib.decode()}  <->  {other.decode()}")

crib_drag(x, "You ")
crib_drag(x, "If ")
crib_drag(x, "class")
crib_drag(x, "grades")

p1 = b"If you don't come to class   ..."
p2 = b"You might not get good grades..."

k1 = bytes(c1[i] ^ p1[i] for i in range(len(c1)))
k2 = bytes(c2[i] ^ p2[i] for i in range(len(c2)))

print("\nRecovered plaintexts:")
print("P1 =", p1.decode())
print("P2 =", p2.decode())

print("\nRecovered keystream segment:")
print(k1.hex())

print("\nVerification:")
print("Same keystream?", k1 == k2)
print("C1 matches?", bytes(p1[i] ^ k1[i] for i in range(len(p1))) == c1)
print("C2 matches?", bytes(p2[i] ^ k1[i] for i in range(len(p2))) == c2)
```

## Final answer

```text
Plaintext 1: If you don't come to class   ...
Plaintext 2: You might not get good grades...
Recovered keystream segment: c1f838ba427d6fd0232772feb7b0aa9ac3b4463016cf29145e9a8403ca6caf4f
```
