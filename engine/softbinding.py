"""Robust text fingerprint soft binding: com.writerslogic.text-fingerprint.1

A FINGERPRINT-type C2PA soft binding for text content. Unlike an embedded
zero-width-character watermark, this computes a fingerprint *from* the text, so
it survives normalization, re-encoding, and ZWC stripping. The fingerprint is
recorded in the (agent-signed) C2PA manifest rather than carried in the
document, which is what makes it forge/transfer-resistant.

Algorithm (com.writerslogic.text-fingerprint.1):
  1. Normalize -> a single normalized character stream (NFC; strip
     zero-width/formatting chars and variation selectors; lowercase; collapse
     whitespace to single spaces; strip punctuation; trim).
  2. Overlapping character 4-grams (sliding window of 4 chars, step 1).
  3. SimHash-256 over the 4-gram multiset -> 32 bytes, hex-encoded.
  4. Match = Hamming distance <= MATCH_THRESHOLD bits.

For excerpt robustness, a document is also split into overlapping windows of
WINDOW normalized characters with 50% overlap; each window gets its own
fingerprint, recorded as an additional block in the soft binding assertion.

Stdlib + hashlib only. No third-party dependencies.
"""

import hashlib
import re
import sys
import unicodedata

ALG = "com.writerslogic.text-fingerprint.1"

# Character n-gram size: overlapping 4-grams over the normalized char stream.
NGRAM_N = 4

# 256-bit SimHash -> 32 bytes.
SIMHASH_BITS = 256

# A Hamming distance at or below this many bits (12.5% of 256) indicates the
# same content under light edits (a word changed, punctuation/case/whitespace
# adjusted). Above it, the texts are treated as unrelated.
MATCH_THRESHOLD = 32

# Windowed fingerprints: overlapping windows of WINDOW normalized chars with
# 50% overlap (step = WINDOW // 2). Gives one fingerprint per window so an
# extracted excerpt can still match a window block of the source document.
WINDOW = 512
WINDOW_STEP = WINDOW // 2

# Zero-width / formatting characters explicitly removed during normalization.
# Variation selectors U+FE00-U+FE0F are handled by the range check below.
_ZERO_WIDTH = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "﻿",  # zero width no-break space / BOM
    "⁠",  # word joiner
}

_WHITESPACE_RUN = re.compile(r"\s+")


def _strip_zero_width(text):
    """Remove zero-width / formatting chars and variation selectors."""
    out = []
    for ch in text:
        if ch in _ZERO_WIDTH:
            continue
        if "︀" <= ch <= "️":  # variation selectors VS1-VS16
            continue
        out.append(ch)
    return "".join(out)


def normalize(text):
    """Normalize text to a single normalized character string.

    Steps: Unicode NFC -> strip zero-width/formatting chars -> lowercase ->
    collapse whitespace runs to a single space -> strip punctuation -> trim.
    Returns the normalized string (which may be empty).
    """
    text = unicodedata.normalize("NFC", text)
    text = _strip_zero_width(text)
    text = text.lower()
    # Collapse all whitespace runs to a single space.
    text = _WHITESPACE_RUN.sub(" ", text)
    # Strip punctuation: drop any char in Unicode category starting with "P"
    # (and symbols "S"). Keep letters, numbers, and spaces.
    cleaned = []
    for ch in text:
        if ch == " ":
            cleaned.append(ch)
            continue
        cat = unicodedata.category(ch)
        if cat[0] in ("P", "S"):
            continue
        cleaned.append(ch)
    text = "".join(cleaned)
    # Stripping punctuation may have left double spaces; collapse again, trim.
    text = _WHITESPACE_RUN.sub(" ", text).strip()
    return text


def char_ngrams(norm, n=NGRAM_N):
    """Overlapping character n-grams (sliding window of n chars, step 1).

    Operates on a normalized character string. If the string is shorter than
    n, return a single n-gram of the whole string. Empty input -> no grams.
    """
    if not norm:
        return []
    if len(norm) < n:
        return [norm]
    return [norm[i:i + n] for i in range(len(norm) - n + 1)]


def simhash256(grams):
    """SimHash over an iterable of grams -> 32 bytes (256-bit fingerprint).

    For each gram, SHA-256 gives a 256-bit vector. Each bit position
    accumulates +1 when the gram's bit is 1, else -1. The final fingerprint
    bit is 1 when the column sum is > 0, else 0.
    """
    sums = [0] * SIMHASH_BITS
    for gram in grams:
        digest = hashlib.sha256(gram.encode("utf-8")).digest()
        value = int.from_bytes(digest, "big")
        for bit in range(SIMHASH_BITS):
            if (value >> bit) & 1:
                sums[bit] += 1
            else:
                sums[bit] -= 1
    result = 0
    for bit in range(SIMHASH_BITS):
        if sums[bit] > 0:
            result |= (1 << bit)
    return result.to_bytes(SIMHASH_BITS // 8, "big")


def _fingerprint_norm(norm):
    """Hex fingerprint of an already-normalized character string."""
    return simhash256(char_ngrams(norm)).hex()


def fingerprint(text):
    """Compute the hex-encoded 256-bit fingerprint for text."""
    return _fingerprint_norm(normalize(text))


def windows(norm, size=WINDOW, step=WINDOW_STEP):
    """Overlapping windows over a normalized char string.

    Yields (start, length, substring) tuples for windows of `size` chars with
    `step` advance (50% overlap by default). If the string is no longer than a
    single window, yields nothing (the whole-doc fingerprint already covers it).
    """
    out = []
    if len(norm) <= size:
        return out
    start = 0
    while start < len(norm):
        chunk = norm[start:start + size]
        out.append((start, len(chunk), chunk))
        if start + size >= len(norm):
            break
        start += step
    return out


def hamming(hex_a, hex_b):
    """Hamming distance between two hex fingerprints (popcount of XOR)."""
    a = int(hex_a, 16)
    b = int(hex_b, 16)
    return (a ^ b).bit_count()


def matches(hex_a, hex_b, max_hamming=MATCH_THRESHOLD):
    """True if the two fingerprints are within max_hamming bits."""
    return hamming(hex_a, hex_b) <= max_hamming


def soft_binding_assertion(text):
    """Return a c2pa.soft_binding-shaped assertion dict for text.

    Block 0 is the whole-document fingerprint (scope: {}). When the normalized
    text spans more than one window, one additional block per window follows,
    each with scope {"start": <char offset>, "length": <chars>} so that an
    extracted excerpt can match a window block.
    """
    norm = normalize(text)
    blocks = [
        {
            "scope": {},
            "value": _fingerprint_norm(norm),
        }
    ]
    for start, length, chunk in windows(norm):
        blocks.append(
            {
                "scope": {"start": start, "length": length},
                "value": _fingerprint_norm(chunk),
            }
        )
    return {
        "alg": ALG,
        "blocks": blocks,
    }


def matches_assertion(text, assertion, max_hamming=MATCH_THRESHOLD):
    """True if `text` matches the soft binding `assertion`.

    Match when either:
      - the recomputed whole-document fingerprint is within threshold of the
        assertion's whole-document block (scope == {}); or
      - any recomputed window fingerprint of `text` is within threshold of ANY
        window block in the assertion.

    The second path handles excerpts and truncation: a single extracted
    paragraph recomputes its own whole-doc (and possibly window) fingerprints,
    one of which lines up with a window block of the larger source document.
    """
    if assertion.get("alg") != ALG:
        return False
    blocks = assertion.get("blocks", [])

    whole_block = None
    window_block_values = []
    for block in blocks:
        scope = block.get("scope", {})
        if scope == {}:
            whole_block = block
        else:
            window_block_values.append(block.get("value"))

    norm = normalize(text)

    # Path 1: whole-doc vs whole-doc.
    if whole_block is not None:
        if matches(_fingerprint_norm(norm), whole_block["value"], max_hamming):
            return True

    if not window_block_values:
        return False

    # Path 2: any recomputed window of `text` (plus the text's own whole-doc
    # fingerprint, to cover a short excerpt that fits in one window) vs any
    # window block of the assertion.
    candidate_fps = [_fingerprint_norm(norm)]
    for _start, _length, chunk in windows(norm):
        candidate_fps.append(_fingerprint_norm(chunk))

    for cand in candidate_fps:
        for value in window_block_values:
            if value is not None and matches(cand, value, max_hamming):
                return True
    return False


def _main(argv):
    if len(argv) == 3 and argv[1] == "fingerprint":
        with open(argv[2], "r", encoding="utf-8") as fh:
            sys.stdout.write(fingerprint(fh.read()) + "\n")
        return 0
    sys.stderr.write("usage: python softbinding.py fingerprint <file>\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
