"""Command-line encryption utility — AES-CBC, AES-GCM, 3DES-CBC with PBKDF2."""

import argparse
import getpass
import sys

from crypto import (
    SUITE_PARAMS, DEFAULT_SUITE, DEFAULT_ITER,
    encrypt, decrypt, HMACVerificationError,
)


def _resolve_suite(value: str) -> int:
    try:
        sid = int(value, 0)
        if sid in SUITE_PARAMS:
            return sid
    except ValueError:
        pass
    value_lower = value.lower()
    for sid, p in SUITE_PARAMS.items():
        if value_lower in p["label"].lower():
            return sid
    raise argparse.ArgumentTypeError(
        f"Unknown suite {value!r}. Run 'suites' to list available options."
    )


def _print_suites() -> None:
    print(f"{'ID':>4}  {'Label'}")
    print("-" * 55)
    for sid, p in SUITE_PARAMS.items():
        # Strip embedded markers from the raw label; we add our own
        label = p["label"].replace(" [default]", "").replace(" [legacy]", "").replace(" [recommended]", "")
        suffix = ""
        if sid == DEFAULT_SUITE:
            suffix += "  [default]"
        if p["legacy"]:
            suffix += "  [legacy — SWEET32]"
        print(f"0x{sid:02X}  {label}{suffix}")


def cmd_encrypt(args: argparse.Namespace) -> int:
    if args.input:
        if args.input == args.output:
            print("error: input and output paths must differ", file=sys.stderr)
            return 1
        try:
            with open(args.input, "rb") as f:
                plaintext = f.read()
        except OSError as e:
            print(f"error: cannot read input file: {e}", file=sys.stderr)
            return 1
    else:
        plaintext = args.text.encode("utf-8")

    pw = getpass.getpass("Password: ")
    if not pw:
        print("error: password cannot be empty", file=sys.stderr)
        return 1
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("error: passwords do not match", file=sys.stderr)
        return 1

    suite_id = args.suite
    p = SUITE_PARAMS[suite_id]
    if p["legacy"]:
        print(
            "warning: 3DES is deprecated (SWEET32). Use AES for new data.",
            file=sys.stderr,
        )

    iterations = args.iterations if args.iterations is not None else DEFAULT_ITER[p["hash"]]

    try:
        blob = encrypt(
            plaintext,
            pw.encode("utf-8"),
            suite_id=suite_id,
            iterations=iterations,
            include_metadata_in_hmac=not args.no_meta_hmac,
            use_hkdf=args.hkdf,
        )
    except Exception as e:
        print(f"error: encryption failed: {e}", file=sys.stderr)
        return 1

    try:
        with open(args.output, "wb") as f:
            f.write(blob)
    except OSError as e:
        print(f"error: cannot write output file: {e}", file=sys.stderr)
        return 1

    print(f"Encrypted → {args.output}  ({len(blob)} bytes, suite 0x{suite_id:02X}, {iterations} iterations)")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    try:
        with open(args.input, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"error: cannot read input file: {e}", file=sys.stderr)
        return 1

    pw = getpass.getpass("Password: ")
    if not pw:
        print("error: password cannot be empty", file=sys.stderr)
        return 1

    try:
        plaintext = decrypt(data, pw.encode("utf-8"))
    except HMACVerificationError as e:
        print(f"error: authentication failed — {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: decryption failed — {e}", file=sys.stderr)
        return 1

    if args.output:
        try:
            with open(args.output, "wb") as f:
                f.write(plaintext)
        except OSError as e:
            print(f"error: cannot write output file: {e}", file=sys.stderr)
            return 1
        print(f"Decrypted → {args.output}  ({len(plaintext)} bytes)")
    else:
        try:
            sys.stdout.write(plaintext.decode("utf-8"))
            if not plaintext.endswith(b"\n"):
                sys.stdout.write("\n")
        except UnicodeDecodeError:
            sys.stdout.buffer.write(plaintext)

    return 0


def cmd_suites(_args: argparse.Namespace) -> int:
    _print_suites()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="encrypt",
        description="File encryption utility — AES/GCM/3DES with PBKDF2 key derivation.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file or text string")
    src = enc.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--input", metavar="FILE", help="Input file to encrypt")
    src.add_argument("-t", "--text", metavar="TEXT", help="Input text to encrypt")
    enc.add_argument("-o", "--output", metavar="FILE", required=True, help="Output encrypted file")
    enc.add_argument(
        "-s", "--suite", metavar="SUITE",
        type=_resolve_suite, default=DEFAULT_SUITE,
        help="Suite ID (hex) or label substring (default: 0x04 — AES-256-CBC/HMAC-SHA512)",
    )
    enc.add_argument(
        "-n", "--iterations", metavar="N", type=int, default=None,
        help="PBKDF2 iterations (default: 600000 for SHA-256, 210000 for SHA-512)",
    )
    enc.add_argument("--hkdf", action="store_true", help="Use HKDF for second-stage key derivation")
    enc.add_argument("--no-meta-hmac", action="store_true", help="Exclude metadata from HMAC input")
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt an encrypted file")
    dec.add_argument("-i", "--input", metavar="FILE", required=True, help="Input encrypted file")
    dec.add_argument(
        "-o", "--output", metavar="FILE", default=None,
        help="Output file (default: print plaintext to stdout)",
    )
    dec.set_defaults(func=cmd_decrypt)

    # suites
    sl = sub.add_parser("suites", help="List available cipher suites")
    sl.set_defaults(func=cmd_suites)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
