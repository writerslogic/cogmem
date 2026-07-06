"""Tests for the text-fingerprint soft binding (com.writerslogic.text-fingerprint.1)."""

import unittest

from cogmem import softbinding


# A document-length paragraph used for the whole-doc / edit / unrelated tests.
BASE = (
    "Provenance for written text has historically been fragile because the "
    "moment a paragraph is copied, reformatted, or pasted into another editor, "
    "any embedded metadata is silently discarded. A durable approach must bind "
    "to the words themselves rather than to invisible markers that a single "
    "normalization pass can strip away. The fingerprint described here reduces a "
    "document to a compact bit vector that shifts only slightly when an author "
    "fixes a typo or adjusts spacing, yet diverges sharply for unrelated "
    "writing. Because the value is recorded inside a signed manifest, an "
    "adversary cannot transfer it onto a different document without invalidating "
    "the signature, which is what gives the binding its forgery resistance in "
    "practice across many editing tools and pipelines today."
)

# A ~30-token single sentence. With the old k=5 word shingles a single changed
# word perturbed too large a fraction of the few shingles to stay under
# threshold; character 4-grams keep the perturbation local.
SHORT = (
    "Provenance for written text has historically been fragile because the "
    "moment a paragraph is copied or reformatted into another editor, any "
    "embedded metadata is silently discarded forever."
)

# Window-scale paragraphs (~400 normalized chars each) so an extracted
# paragraph aligns with a window block of the assembled document.
PARA_1 = (
    "Provenance for written text has historically been fragile because the "
    "moment a paragraph is copied, reformatted, or pasted into another editor, "
    "any embedded metadata is silently discarded, and the chain of custody that "
    "a reader might rely on to judge authorship simply evaporates without "
    "warning or trace, leaving the words to stand entirely on their own with no "
    "verifiable origin attached to them at all."
)
PARA_2 = (
    "A durable approach must bind to the words themselves rather than to "
    "invisible markers that a single normalization pass can strip away, because "
    "any scheme that hides its signal in formatting will not survive the "
    "ordinary handling that text receives as it moves between systems, editors, "
    "and clipboards, each of which feels free to rewrite spacing, punctuation, "
    "and encoding however it pleases at any time."
)
PARA_3 = (
    "The fingerprint reduces a document to a compact bit vector that shifts only "
    "slightly when an author fixes a typo or adjusts spacing, yet diverges "
    "sharply for unrelated writing, which is precisely the property that lets a "
    "verifier recover the right manifest for a passage even after it has been "
    "copied out of its original context and pasted somewhere new with all of "
    "its surrounding material removed."
)
DOCUMENT = "\n\n".join([PARA_1, PARA_2, PARA_3])


class TestFingerprint(unittest.TestCase):
    def test_identical_text_hamming_zero(self):
        fp = softbinding.fingerprint(BASE)
        self.assertEqual(softbinding.hamming(fp, fp), 0)
        self.assertTrue(softbinding.matches(fp, fp))

    def test_single_word_edit_short_text_within_threshold(self):
        # ~30-token sentence, change exactly one word. Character 4-grams keep
        # the distance under threshold where word shingles did not.
        edited = SHORT.replace("fragile", "brittle")
        self.assertNotEqual(edited, SHORT)
        self.assertEqual(len(softbinding.normalize(SHORT).split()), 27)
        a = softbinding.fingerprint(SHORT)
        b = softbinding.fingerprint(edited)
        dist = softbinding.hamming(a, b)
        self.assertLessEqual(dist, softbinding.MATCH_THRESHOLD)
        self.assertTrue(softbinding.matches(a, b))

    def test_light_edit_within_threshold(self):
        edited = (
            BASE.replace("fixes a typo", "fixes a  MISTAKE,")
            .replace("The fingerprint", "THE fingerprint")
            .replace("today.", "today!")
        )
        self.assertNotEqual(edited, BASE)
        a = softbinding.fingerprint(BASE)
        b = softbinding.fingerprint(edited)
        dist = softbinding.hamming(a, b)
        self.assertLessEqual(dist, softbinding.MATCH_THRESHOLD)
        self.assertTrue(softbinding.matches(a, b))

    def test_zero_width_injection_unchanged(self):
        # Inject zero-width chars throughout; normalization must strip them so
        # the fingerprint is identical to the clean text.
        zw = "​"  # zero width space
        injected = zw.join(BASE) + "﻿"
        self.assertNotEqual(injected, BASE)
        self.assertEqual(
            softbinding.fingerprint(injected),
            softbinding.fingerprint(BASE),
        )

    def test_unrelated_text_above_threshold(self):
        other = (
            "Quarterly financial results exceeded analyst expectations across "
            "every business segment, prompting the board to approve an expanded "
            "share repurchase program for the upcoming fiscal year while "
            "management reaffirmed its full-year guidance and outlined fresh "
            "investments in automation, logistics, and overseas distribution "
            "capacity to sustain double-digit growth into the next decade."
        )
        a = softbinding.fingerprint(BASE)
        b = softbinding.fingerprint(other)
        dist = softbinding.hamming(a, b)
        self.assertGreater(dist, softbinding.MATCH_THRESHOLD)
        self.assertFalse(softbinding.matches(a, b))
        # And the assertion-level matcher agrees on unrelated text.
        assertion = softbinding.soft_binding_assertion(DOCUMENT)
        self.assertFalse(softbinding.matches_assertion(other, assertion))

    def test_normalize_strips_punctuation_and_case(self):
        self.assertEqual(
            softbinding.normalize("Hello, World!  FOO\tbar"),
            "hello world foo bar",
        )

    def test_char_ngrams_short_input(self):
        self.assertEqual(softbinding.char_ngrams("ab"), ["ab"])
        self.assertEqual(softbinding.char_ngrams(""), [])

    def test_char_ngrams_overlap(self):
        self.assertEqual(
            softbinding.char_ngrams("abcdef"),
            ["abcd", "bcde", "cdef"],
        )

    def test_fingerprint_is_32_byte_hex(self):
        fp = softbinding.fingerprint(BASE)
        self.assertEqual(len(fp), 64)
        bytes.fromhex(fp)

    def test_soft_binding_assertion_shape(self):
        assertion = softbinding.soft_binding_assertion(BASE)
        self.assertEqual(assertion["alg"], "com.writerslogic.text-fingerprint.1")
        # Whole-doc block present at index 0 with empty scope.
        whole = assertion["blocks"][0]
        self.assertEqual(whole["scope"], {})
        self.assertEqual(whole["value"], softbinding.fingerprint(BASE))

    def test_multi_window_assertion_block_shape(self):
        assertion = softbinding.soft_binding_assertion(DOCUMENT)
        # Whole-doc block plus at least one window block.
        self.assertEqual(assertion["blocks"][0]["scope"], {})
        window_blocks = assertion["blocks"][1:]
        self.assertGreaterEqual(len(window_blocks), 1)
        for block in window_blocks:
            self.assertIsInstance(block["scope"]["start"], int)
            self.assertIsInstance(block["scope"]["length"], int)
            self.assertEqual(len(block["value"]), 64)
            bytes.fromhex(block["value"])

    def test_single_window_doc_has_only_whole_block(self):
        assertion = softbinding.soft_binding_assertion(SHORT)
        self.assertEqual(len(assertion["blocks"]), 1)
        self.assertEqual(assertion["blocks"][0]["scope"], {})

    def test_excerpt_matches_via_window_block(self):
        # Build the assertion for the full document, then verify a single
        # extracted paragraph satisfies matches_assertion through a window
        # block (the whole-doc fingerprint alone would not match an excerpt).
        assertion = softbinding.soft_binding_assertion(DOCUMENT)
        self.assertTrue(softbinding.matches_assertion(PARA_1, assertion))
        # The excerpt is genuinely below the whole-doc threshold, so the match
        # must be coming from a window block rather than the whole-doc block.
        whole_fp = assertion["blocks"][0]["value"]
        excerpt_fp = softbinding.fingerprint(PARA_1)
        self.assertGreater(
            softbinding.hamming(excerpt_fp, whole_fp),
            softbinding.MATCH_THRESHOLD,
        )


if __name__ == "__main__":
    unittest.main()
