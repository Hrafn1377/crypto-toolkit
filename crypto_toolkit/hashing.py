"""
Hashing demos: avalanche effect and algorithm comparison.

Point of this module: show *why* certain hash algorithms are
deprecated for security use (MD5, SHA-1) versus why SHA-256+ and
purpose-built password hashes (bcrypt/argon2) are recommended —
not just how to call hashlib.
"""
from __future__ import annotations
import hashlib
import time

# Algorithms considered broken/deprecated for security purposes,
# kept here only for comparison in the demo.
DEPRECATED_ALGOS = {"md5", "sha1"}

ALGO_NOTES = {
    "md5": "Broken: practical collision attacks since 2004. Never use for security.",
    "sha1": "Broken: practical collision attacks (SHAttered, 2017). Deprecated.",
    "sha256": "Currently considered secure for integrity/fingerprinting.",
    "sha512": "Currently considered secure; larger digest, often faster on 64-bit.",
    "sha3_256": "Newer construction (Keccak), different internal design than SHA-2 family.",
}


def hash_hex(text: str, algorithm: str = "sha256") -> str:
    """Return the hex digest of `text` using the given hashlib algorithm."""
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def bit_diff_percentage(hex_a: str, hex_b: str) -> float:
    """
    Percentage of differing bits between two equal-length hex digests.
    A good hash should sit close to 50% here even for a 1-bit input change
    (the "avalanche effect").
    """
    int_a = int(hex_a, 16)
    int_b = int(hex_b, 16)
    xor = int_a ^ int_b
    diff_bits = bin(xor).count("1")
    total_bits = max(len(hex_a), len(hex_b)) * 4
    return (diff_bits / total_bits) * 100


def avalanche_demo(text: str, algorithm: str = "sha256") -> dict:
    """
    Flip the last character's case (or first bit if non-alpha) and show
    how much the digest changes. Demonstrates why hashes can't be
    "nudged" toward a target output — small input changes look nothing
    alike in the output.
    """
    if not text:
        raise ValueError("Input text must not be empty")

    original_hash = hash_hex(text, algorithm)

    # Flip a single bit in the input by toggling the last character's
    # lowest bit via XOR on its byte value.
    chars = list(text)
    last = chars[-1]
    flipped_char = chr(ord(last) ^ 1)
    chars[-1] = flipped_char
    modified_text = "".join(chars)

    modified_hash = hash_hex(modified_text, algorithm)
    diff_pct = bit_diff_percentage(original_hash, modified_hash)

    return {
        "algorithm": algorithm,
        "original_text": text,
        "original_hash": original_hash,
        "modified_text": modified_text,
        "modified_hash": modified_hash,
        "bit_difference_pct": round(diff_pct, 1),
    }


def compare_algorithms(text: str, algorithms: list[str] | None = None) -> list[dict]:
    """
    Hash the same text with several algorithms and report digest +
    rough timing, so speed differences (relevant to brute-force
    resistance) are visible directly.
    """
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256", "sha512", "sha3_256"]

    results = []
    for algo in algorithms:
        start = time.perf_counter()
        # Hash many times to get a measurable duration for fast algorithms.
        iterations = 100_000
        for _ in range(iterations):
            digest = hash_hex(text, algo)
        elapsed = time.perf_counter() - start

        results.append({
            "algorithm": algo,
            "digest": digest,
            "seconds_per_100k_hashes": round(elapsed, 4),
            "deprecated": algo in DEPRECATED_ALGOS,
            "note": ALGO_NOTES.get(algo, ""),
        })

    return results