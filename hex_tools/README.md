# Hex Tools

A small Python utility for XOR cipher operations on raw byte sequences. Useful for decoding obfuscated shellcode, reversing simple XOR-encrypted payloads, or experimenting with symmetric key cryptography basics.

## Files

- `xor.py` — Implements a repeating-key XOR cipher over arbitrary byte data.

## Background

XOR encryption is one of the simplest symmetric ciphers. Each byte of plaintext is combined with the corresponding byte of the key using the XOR (`^`) operator. Because XOR is its own inverse (`a ^ k ^ k == a`), the same function encrypts and decrypts:

```
ciphertext = plaintext XOR key
plaintext  = ciphertext XOR key
```

The **repeating-key** variant cycles the key when it is shorter than the data — a generalisation of the one-time pad that is insecure when the key repeats, but is commonly found in CTF challenges and obfuscated malware payloads.

## How It Works

### `xor_cipher_repeating(data, key_hex)`

```python
def xor_cipher_repeating(data: bytes, key_hex: str) -> bytes:
    key_bytes = bytes.fromhex(key_hex.replace("0x", ""))
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
```

Each byte `b` at index `i` is XOR'd with `key_bytes[i % len(key_bytes)]`, cycling the key for data longer than the key.

### Single-byte XOR (commented out)

A simpler variant that XOR's every byte against a single integer value is included as a comment above the main function — useful when brute-forcing single-byte keys (only 256 possibilities).

## Usage

```bash
python3 xor.py
```

The script operates on a hardcoded hex string and key. Edit the variables at the bottom of the file to supply your own input and key:

```python
hex_input = "C7 E7 E7 ..."      # space-separated hex bytes
my_key    = "0xE7"              # single-byte key

raw_bytes = bytes.fromhex(hex_input.replace(" ", ""))
processed = xor_cipher_repeating(raw_bytes, my_key)

print(f"Hex Output:   {processed.hex()}")
print(f"ASCII Output: {processed.decode('ascii')}")
```

The key `0xE7` in the example decodes an embedded encoded string into readable ASCII.

## Extending the Script

**Multi-byte key:**

```python
my_key = "0xDEADBEEF"   # 4-byte repeating key
```

**Process a file instead of a hardcoded string:**

```python
with open("payload.bin", "rb") as f:
    raw_bytes = f.read()

processed = xor_cipher_repeating(raw_bytes, my_key)

with open("decoded.bin", "wb") as f:
    f.write(processed)
```

**Brute-force a single-byte key (find which key produces readable ASCII):**

```python
for key in range(256):
    result = bytes(b ^ key for b in raw_bytes)
    try:
        text = result.decode('ascii')
        if text.isprintable():
            print(f"Key 0x{key:02x}: {text}")
    except UnicodeDecodeError:
        pass
```
