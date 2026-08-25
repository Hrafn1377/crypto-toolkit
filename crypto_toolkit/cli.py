"""
Command-line interface for the crypto fundamentals toolkit.

Run `python -m crypto_toolkit --help` (or `crypto-toolkit --help` if
installed) for full usage.
"""

import argparse
import sys
from getpass import getpass

from cryptography.exceptions import InvalidTag

from . import classic, hashing, symmetric


def cmd_caesar(args: argparse.Namespace) -> None:
    if args.action == "encrypt":
        print(classic.caesar_encrypt(args.text, args.shift))
    elif args.action == "decrypt":
        print(classic.caesar_decrypt(args.text, args.shift))
    elif args.action == "crack":
        results = classic.caesar_crack(args.text)
        print(f"{'Shift':<7}{'Score':<10}Decoded text")
        print("-" * 60)
        for shift, candidate, score in results[:5]:
            print(f"{shift:<7}{score:<10.2f}{candidate}")
        print("\n(Lower score = closer match to expected English letter frequency.")
        print(" Top result is the most likely correct shift.)")


def cmd_vigenere(args: argparse.Namespace) -> None:
    if args.action == "encrypt":
        print(classic.vigenere_encrypt(args.text, args.key))
    else:
        print(classic.vigenere_decrypt(args.text, args.key))


def cmd_hash(args: argparse.Namespace) -> None:
    print(hashing.hash_hex(args.text, args.algorithm))


def cmd_avalanche(args: argparse.Namespace) -> None:
    result = hashing.avalanche_demo(args.text, args.algorithm)
    print(f"Algorithm:       {result['algorithm']}")
    print(f"Original text:   {result['original_text']!r}")
    print(f"Original hash:   {result['original_hash']}")
    print(f"Modified text:   {result['modified_text']!r}  (last char, 1 bit flipped)")
    print(f"Modified hash:   {result['modified_hash']}")
    print(f"Bit difference:  {result['bit_difference_pct']}%  (ideal is ~50%)")


def cmd_compare(args: argparse.Namespace) -> None:
    results = hashing.compare_algorithms(args.text)
    print(f"{'Algorithm':<12}{'Time/100k':<12}{'Status':<14}Note")
    print("-" * 90)
    for r in results:
        status = "DEPRECATED" if r["deprecated"] else "OK"
        print(f"{r['algorithm']:<12}{r['seconds_per_100k_hashes']:<12}{status:<14}{r['note']}")


def cmd_aes_encrypt(args: argparse.Namespace) -> None:
    password = args.password or getpass("Password: ")
    try:
        symmetric.encrypt_file(args.input, args.output, password)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    print(f"Encrypted: {args.input} -> {args.output}")


def cmd_aes_decrypt(args: argparse.Namespace) -> None:
    password = args.password or getpass("Password: ")
    try:
        symmetric.decrypt_file(args.input, args.output, password)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except InvalidTag:
        print("Error: decryption failed — wrong password or corrupted/tampered file.",
              file=sys.stderr)
        sys.exit(1)
    print(f"Decrypted: {args.input} -> {args.output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto-toolkit",
        description="Crypto fundamentals toolkit: classic ciphers, hashing demos, AES-GCM.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- caesar ---
    p_caesar = sub.add_parser("caesar", help="Caesar cipher: encrypt, decrypt, or crack")
    p_caesar.add_argument("action", choices=["encrypt", "decrypt", "crack"])
    p_caesar.add_argument("text", help="Text to process")
    p_caesar.add_argument("--shift", type=int, default=3,
                           help="Shift amount (ignored for 'crack')")
    p_caesar.set_defaults(func=cmd_caesar)

    # --- vigenere ---
    p_vig = sub.add_parser("vigenere", help="Vigenère cipher: encrypt or decrypt")
    p_vig.add_argument("action", choices=["encrypt", "decrypt"])
    p_vig.add_argument("text", help="Text to process")
    p_vig.add_argument("--key", required=True, help="Alphabetic key")
    p_vig.set_defaults(func=cmd_vigenere)

    # --- hash ---
    p_hash = sub.add_parser("hash", help="Hash text with a chosen algorithm")
    p_hash.add_argument("text", help="Text to hash")
    p_hash.add_argument("--algorithm", default="sha256",
                         help="hashlib algorithm name (default: sha256)")
    p_hash.set_defaults(func=cmd_hash)

    # --- avalanche ---
    p_ava = sub.add_parser("avalanche", help="Demonstrate the avalanche effect")
    p_ava.add_argument("text", help="Input text")
    p_ava.add_argument("--algorithm", default="sha256")
    p_ava.set_defaults(func=cmd_avalanche)

    # --- compare ---
    p_cmp = sub.add_parser("compare", help="Compare multiple hash algorithms")
    p_cmp.add_argument("text", help="Input text")
    p_cmp.set_defaults(func=cmd_compare)

    # --- aes encrypt/decrypt ---
    p_enc = sub.add_parser("aes-encrypt", help="Encrypt a file with AES-256-GCM")
    p_enc.add_argument("input", help="Path to plaintext input file")
    p_enc.add_argument("output", help="Path to write encrypted output")
    p_enc.add_argument("--password", help="Password (omit to be prompted securely)")
    p_enc.set_defaults(func=cmd_aes_encrypt)

    p_dec = sub.add_parser("aes-decrypt", help="Decrypt a file with AES-256-GCM")
    p_dec.add_argument("input", help="Path to encrypted input file")
    p_dec.add_argument("output", help="Path to write decrypted output")
    p_dec.add_argument("--password", help="Password (omit to be prompted securely)")
    p_dec.set_defaults(func=cmd_aes_decrypt)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()