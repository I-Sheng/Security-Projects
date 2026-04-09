# def xor_cipher(data: bytes, hex_key: str) -> bytes:
    # key_int = int(hex_key, 16)
    # return bytes([byte ^ key_int for byte in data])

def xor_cipher_repeating(data: bytes, key_hex: str) -> bytes:
    key_bytes = bytes.fromhex(key_hex.replace("0x", ""))  # e.g., b'\xe7' for "0xE7"
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


# 1. Your input string (Hex values represented as text)
hex_input = "C7 E7 E7 E7 0E 86 E6 E7 E7 B1 B0 6C 93 C3 EB D6 18 1B D6 27 4B DF 07 93 ED 26 28 EA E6 20 0E 08 18 18 18 6E 1F B8 B9 25 E3 E7 87 6C 8B C3 C3 6C A2 DB 6C B3 E2 9F E6 0D 6C AD FF 6C BD C7 E6 0C 04 CD AE 6C D3 6C E6 09 B1 0F 5C 18 18 18 DC A3 C3 CF 92 0B 6C BD C3 E6 0C 81 6C EB AC 6C BD FB E6 0C 6C E3 6C E6 0F 0E E5 E7 E7 E7 D6 27 6E A3 C3 FB 86 25 EF E7 B1 D6 27 83 6C A7 D7 62 27 9F E8 6C A7 EB 6C 97 FB 4A 6C A7 EF 0E E2 E7 E7 E7 0E 1C 18 18 18 B9 24 B9 6E 14 6E 10 0F 32 18 18 18 6E 25 5E E3 E7 E7 E7 4A B7 B5 0F 9D 18 18 18 4C 05 12 8F D4 D5 E7 E7 8F 90 94 D5 B8 B3 18 F4 6E 25 5E E4 E7 E7 E7 4A B7 B5 0F BC 18 18 18 4C 05 12 66 0B D7 E5 E7 E7 5F 17 18 18 18 C6 23 B3 8F E6 E6 E7 E7 18 B4 F7 62 27 92 95 B7 B7 B7 B7 A7 B7 A7 B7 18 B4 F3 DA 18 18 18 18 93 87 6E 21 8F 27 4F 2F E5 8F E5 E7 D3 F5 6E 06 8F F7 E7 E7 E7 B6 B7 18 B4 FF 62 27 92 A3 8F 84 8A 83 E7 6E 84 FB 66 0B B3 E7 E7 E7 D6 27 5E F2 E7 E7 E7 6A DB C3 14 4C 21 A3 C3 F7 A3 19 A3 C3 DB 19 A3 C3 DA 6E 17 6A 9B C3 AF 4C 4C 4C 6A A3 C3 F7 B3 B7 B6 B6 B6 8D E6 B6 B6 18 94 FB B6 18 B4 E3 18 B4 EB 8F E7 E7 E7 E7 B7 18 B4 EF 0F CF 18 18 18 69 A9 E9 0B 95 19 54 F1 64 5E 52 9F 01 F0 68 9C 2C 0A 1B DC 3E EE 12 4A 0B 1E 4D 87 00"


# 2. Convert that space-separated string into actual raw bytes
raw_bytes = bytes.fromhex(hex_input.replace(" ", ""))

my_key = "0xE7"

# 3. Perform the XOR
processed_bytes = xor_cipher_repeating(raw_bytes, my_key)

# 4. Print Results
print(f"Hex Output:   {processed_bytes.hex()}")

try:
    # This converts the resulting bytes into readable ASCII text
    ascii_text = processed_bytes.decode('ascii')
    print(f"ASCII Output: {ascii_text}")
except UnicodeDecodeError:
    print("ASCII Output: [Contains non-printable characters]")
