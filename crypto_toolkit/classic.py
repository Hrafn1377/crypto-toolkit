"""
Classic ciphers: Caesar and Vigenère.

These are NOT secure by modern standards — they're here to demonstrate
*why* substitution/polyalphabetic ciphers are broken, via frequency
analysis. Use the symmetric module for anything that actually needs
to stay secret.
"""

from __future__ import annotations

from collections import Counter
from string import ascii_uppercase

# Approximate relative frequency of letters in English text (%).
# Used by the frequency analysis demo to guess a likely Caesar shift.
ENGLISH_FREQ = {
    "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97, "N": 6.75,
    "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25, "L": 4.03, "C": 2.78,
    "U": 2.76, "M": 2.41, "W": 2.36, "F": 2.23, "G": 2.02, "Y": 1.97,
    "P": 1.93, "B": 1.29, "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15,
    "Q": 0.10, "Z": 0.07,
}


def caesar_shift(text: str, shift: int) -> str:
    """Shift each letter by `shift` positions. Negative shift decrypts."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_encrypt(plaintext: str, shift: int) -> str:
    return caesar_shift(plaintext, shift)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_shift(ciphertext, -shift)


def caesar_crack(ciphertext: str) -> list[tuple[int, str, float]]:
    """
    Try all 26 shifts and score each by how closely its letter
    distribution matches expected English frequency (lower score = better
    fit, using sum of squared differences — a simple chi-squared-style
    metric). Returns results sorted best-first.

    This is the point of the demo: a human (or a script) can crack a
    Caesar cipher in milliseconds without knowing the key, because the
    keyspace is only 26 and the letter statistics leak the answer.
    """
    letters_only = [c for c in ciphertext.upper() if c in ascii_uppercase]
    total = len(letters_only) or 1

    scored = []
    for shift in range(26):
        candidate = caesar_decrypt(ciphertext, shift)
        counts = Counter(c for c in candidate.upper() if c in ascii_uppercase)
        score = 0.0
        for letter in ascii_uppercase:
            observed_pct = (counts.get(letter, 0) / total) * 100
            expected_pct = ENGLISH_FREQ.get(letter, 0)
            score += (observed_pct - expected_pct) ** 2
        scored.append((shift, candidate, score))

    scored.sort(key=lambda item: item[2])
    return scored


def vigenere_shift(text: str, key: str, decrypt: bool = False) -> str:
    """Apply a Vigenère cipher (repeating-key polyalphabetic shift)."""
    if not key or not key.isalpha():
        raise ValueError("Vigenère key must be a non-empty alphabetic string")

    key = key.upper()
    result = []
    key_index = 0

    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            key_shift = ord(key[key_index % len(key)]) - ord("A")
            if decrypt:
                key_shift = -key_shift
            result.append(chr((ord(ch) - base + key_shift) % 26 + base))
            key_index += 1
        else:
            result.append(ch)

    return "".join(result)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    return vigenere_shift(plaintext, key, decrypt=False)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    return vigenere_shift(ciphertext, key, decrypt=True)