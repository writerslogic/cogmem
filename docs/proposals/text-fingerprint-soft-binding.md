# Text Fingerprint Soft Binding (`com.writerslogic.text-fingerprint.1`)

A C2PA **fingerprint**-type soft binding for text content. It computes a
durable 256-bit fingerprint *from* the words of a document, rather than
embedding hidden markers *into* it. The fingerprint is recorded in the
agent-signed C2PA manifest and used to recover that manifest for a piece of text
even after the text has been copied, reformatted, or re-encoded.

Reference implementation: `engine/softbinding.py` (Python stdlib + `hashlib`
only). Tests: `engine/test_softbinding.py`.

## Algorithm

1. **Normalize** the text to a single normalized character stream:
   - Unicode **NFC** normalization.
   - Remove all zero-width / formatting characters: U+200B (zero-width space),
     U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM / zero-width no-break space),
     U+2060 (word joiner), and variation selectors U+FE00–U+FE0F.
   - **Lowercase**.
   - **Collapse** every run of whitespace to a single space.
   - **Strip punctuation** (and symbols), keeping letters, numbers, and spaces.
   - **Trim** to produce the normalized character string.

2. **Character 4-grams** — overlapping character 4-grams over the normalized
   string (sliding window of 4 characters, step 1). If the normalized string is
   shorter than 4 characters, produce a single n-gram of the whole string.
   Character grams are used instead of word shingles because a single-word edit
   then perturbs only the handful of grams that touch the changed characters,
   keeping the fingerprint stable on short text where a word edit would
   otherwise move a large fraction of the few shingles.

3. **SimHash-256** — for each 4-gram, compute SHA-256 to obtain a 256-bit
   vector. For each of the 256 bit positions, add +1 when the gram's bit is
   1 and −1 when it is 0, accumulated across all grams. The final fingerprint
   bit is 1 when the column sum is `> 0`, else 0. Output is **32 bytes** (256
   bits), **hex-encoded** (64 hex chars).

4. **Distance** — the **Hamming distance** between two fingerprints is the
   popcount of their XOR. A distance of **≤ 32 bits (12.5% of 256)** indicates
   the same content under light edits. The threshold is the named constant
   `MATCH_THRESHOLD` in the reference implementation.

5. **Windowed fingerprints** (excerpt robustness) — in addition to the
   whole-document fingerprint, the normalized character stream is split into
   overlapping windows of **512 normalized characters with 50% overlap**
   (step 256). Each window is fingerprinted with the same character-4-gram
   SimHash, producing one fingerprint per window. This lets an extracted
   excerpt of a larger document match a window fingerprint even when its own
   whole-document fingerprint is far from the source's whole-document value.

## Soft binding assertion shape

`soft_binding_assertion(text)` returns a `c2pa.soft_binding`-shaped dict. Block
0 is always the whole-document fingerprint (empty scope). When the normalized
text spans more than one 512-character window, one block per window follows,
each carrying its character offset (`start`) and length (`length`):

```json
{
  "alg": "com.writerslogic.text-fingerprint.1",
  "blocks": [
    { "scope": {}, "value": "<whole-doc fingerprint hex>" },
    { "scope": { "start": 0, "length": 512 }, "value": "<window fingerprint hex>" },
    { "scope": { "start": 256, "length": 512 }, "value": "<window fingerprint hex>" }
  ]
}
```

`matches_assertion(text, assertion)` returns true when the recomputed
whole-document fingerprint is within threshold of block 0, **or** any recomputed
window fingerprint of `text` is within threshold of **any** window block in the
assertion. The window path is what recovers the manifest from an extracted
excerpt or a truncated copy.

## Rationale: why a computed fingerprint beats an embedded ZWC watermark

A zero-width-character (ZWC) watermark carries the binding *inside* the
document as invisible characters. That is fragile in exactly the ways text is
routinely handled:

- **Durable / non-destructive.** The fingerprint is derived from the visible
  words and stored in the manifest. Nothing is added to the document, so the
  author's text is never altered, and there is nothing to accidentally damage.
- **Normalization-proof.** NFC normalization, lowercasing, whitespace
  collapsing, and punctuation stripping all happen *before* the fingerprint is
  computed, so reformatting, re-wrapping, and case/spacing changes do not break
  the binding. A ZWC watermark, by contrast, is destroyed the moment an editor
  or platform normalizes or strips invisible characters.
- **ZWC-immune.** Normalization explicitly removes U+200B/C/D, U+FEFF, U+2060,
  and variation selectors, so an adversary injecting zero-width characters
  throughout the text cannot perturb the fingerprint — and cannot smuggle a
  competing watermark into the same channel.
- **Forge / transfer-resistant.** The fingerprint value is recorded in an
  agent-signed C2PA manifest. An adversary cannot lift the binding from one
  document and re-attach it to a different one without re-signing the manifest,
  which they cannot do. The signature, not the document, anchors the binding.

## Honest limit

The fingerprint is robust to **edits and formatting** (typo fixes, spacing,
case, punctuation, ZWC injection, re-encoding), not to **paraphrase**. SimHash
over character 4-grams tracks lexical and sub-word overlap; a thorough rewrite
that preserves meaning while replacing most words will drift past the match
threshold and read as unrelated content. Character grams hold up on short text
where word shingles did not — a single-word edit on a one-sentence snippet stays
within the threshold — but a paraphrase that changes most characters still falls
outside it.

## Roadmap: layered durability (research-informed)

The 2026 literature establishes that no text fingerprint or watermark survives determined paraphrase, and that "robust + publicly-detectable" is provably hard (SoK on watermarking, arXiv:2411.18479; "On the Difficulty of Constructing a Robust and Publicly-Detectable Watermark", arXiv:2502.04901). This algorithm is therefore one layer of a defense-in-depth design, not a paraphrase-proof guarantee:

1. **Registry fingerprint (this algorithm)** — deterministic, dependency-free char-4-gram SimHash with windowed blocks; re-locates the manifest under light edits, formatting changes, and excerpting. Standardizable.
2. **Resilient-embedding matching (roadmap)** — a RETSim-style neural near-duplicate embedding (arXiv:2311.17264) as the lookup layer, improving recall on heavier edits and short text. It adds a pinned-model dependency, so it augments matching rather than replacing the registered algorithm.
3. **Generation-time semantic watermark (roadmap, complementary)** — because a cogmem agent controls its own generation, a SAMark/Waterfall-style semantic watermark (arXiv:2605.25796, arXiv:2407.04411) can give best-effort paraphrase survival that a post-hoc fingerprint cannot, within the literature's documented limits.
4. **Cryptographic root of trust** — durability only re-finds the manifest; the agent-signed C2PA manifest (did:web ICA) is what actually attests provenance. The fingerprint is a locator, not the trust anchor.
