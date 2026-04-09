# Hex Tools

A small Python utility for XOR cipher operations on raw byte sequences. Useful for decoding obfuscated shellcode, reversing simple XOR-encrypted payloads, or experimenting with symmetric key cryptography basics.

## Files

- `xor.py` — Implements a repeating-key XOR cipher over arbitrary byte data.

## Usage

```bash
python3 xor.py
```

The script operates on a hardcoded hex string and key. Edit the variables at the bottom of the file to supply your own input and key.

## How It Works

### `xor_cipher_repeating(data, key_hex)`

Applies repeating-key XOR: each byte of `data` is XOR'd with the corresponding byte of `key_bytes`, cycling the key when it is shorter than the data.

```python
def xor_cipher_repeating(data: bytes, key_hex: str) -> bytes:
    key_bytes = bytes.fromhex(key_hex.replace("0x", ""))
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
```

### Single-byte XOR (commented out)

A simpler variant that XOR's every byte against a single integer value is included as a comment above the main function — useful when brute-forcing single-byte keys.

## Example

```python
# Space-separated hex input
hex_input = "C7 E7 E7 ..."

# Convert to raw bytes
raw_bytes = bytes.fromhex(hex_input.replace(" ", ""))

# Apply single-byte repeating XOR with key 0xE7
processed = xor_cipher_repeating(raw_bytes, "0xE7")

print(f"Hex Output:   {processed.hex()}")
print(f"ASCII Output: {processed.decode('ascii')}")
```

The key `0xE7` used in the example decodes an embedded shellcode or encoded string into readable ASCII (or binary output).

## Extending the Script

To use a multi-byte key, change `my_key` to a longer hex string:

```python
my_key = "0xDEADBEEF"   # 4-byte repeating key
```

To process a file instead of a hardcoded string:

```python
with open("payload.bin", "rb") as f:
    raw_bytes = f.read()
processed = xor_cipher_repeating(raw_bytes, my_key)
with open("decoded.bin", "wb") as f:
    f.write(processed)
```
