"""
Cognitive Memory — test suite (stdlib unittest, no API/model needed)

Covers the pure, breakage-prone glue: frontmatter roundtrip, note validation,
slugify, recall floor+gap filtering, and the recall client's fail-open contract.

Run:  python test_cogmem.py
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common
import recall
from acquire import slugify


class TestNoteIO(unittest.TestCase):
    def test_roundtrip(self):
        meta = {"id": "x-1", "layer": "B", "scope": "rust", "status": "active"}
        body = "Zeroize keys after init.\n\n**Why:** secrets must not linger."
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            common.write_note(p, meta, body)
            rmeta, rbody = common.read_note(p)
        self.assertEqual(rmeta["id"], "x-1")
        self.assertEqual(rmeta["layer"], "B")
        self.assertEqual(rmeta["scope"], "rust")
        self.assertEqual(rbody, body)

    def test_quoting_values_with_colons(self):
        meta = {"id": "y", "evidence": "uses a:b mapping and #tags"}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "y.md"
            common.write_note(p, meta, "body")
            rmeta, _ = common.read_note(p)
        self.assertEqual(rmeta["evidence"], "uses a:b mapping and #tags")

    def test_read_note_without_frontmatter(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "z.md"
            p.write_text("just text, no frontmatter")
            meta, body = common.read_note(p)
        self.assertEqual(meta, {})
        self.assertEqual(body, "just text, no frontmatter")


class TestValidate(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(common.validate_note({"id": "a", "layer": "A"}, "text"), [])

    def test_missing_id(self):
        self.assertIn("missing id", common.validate_note({"layer": "B"}, "text"))

    def test_bad_layer(self):
        self.assertTrue(
            any("invalid layer" in e for e in common.validate_note({"id": "a", "layer": "Z"}, "t"))
        )

    def test_empty_body(self):
        self.assertIn("empty body", common.validate_note({"id": "a"}, "  "))

    def test_episode_without_layer_ok(self):
        self.assertEqual(common.validate_note({"id": "e", "kind": "episode"}, "text"), [])


class TestSlugify(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(
            slugify("Use subprocess.run, not os.system!"), "use-subprocess-run-not-os-system"
        )

    def test_empty_fallback(self):
        self.assertEqual(slugify("!!!"), "rule")


class TestRecallFilter(unittest.TestCase):
    def test_cosine_floor_drops_below(self):
        rows = [
            {"id": "a", "score": 0.85, "rerank": 5.0},
            {"id": "b", "score": 0.50, "rerank": 4.0},
        ]
        kept = recall.filter_results(rows, min_score=0.62, gap=6.0)
        self.assertEqual([r["id"] for r in kept], ["a"])

    def test_gap_drops_far_below_best(self):
        rows = [
            {"id": "a", "score": 0.80, "rerank": 7.0},
            {"id": "b", "score": 0.70, "rerank": -9.0},
        ]
        kept = recall.filter_results(rows, min_score=0.62, gap=6.0)
        self.assertEqual([r["id"] for r in kept], ["a"])

    def test_keeps_close_pair(self):
        rows = [
            {"id": "a", "score": 0.80, "rerank": 2.0},
            {"id": "b", "score": 0.70, "rerank": -1.0},
        ]
        kept = recall.filter_results(rows, min_score=0.62, gap=6.0)
        self.assertEqual(len(kept), 2)

    def test_empty_when_all_below_floor(self):
        rows = [{"id": "a", "score": 0.40, "rerank": 9.0}]
        self.assertEqual(recall.filter_results(rows, 0.62, 6.0), [])


class TestSelfModel(unittest.TestCase):
    def test_activate_filters_scope_and_sorts_by_count(self):
        import selfmodel

        original = selfmodel.FAILURES
        with tempfile.TemporaryDirectory() as d:
            selfmodel.FAILURES = Path(d)
            try:
                common.write_note(
                    Path(d) / "a.md", {"id": "a", "scope": "universal", "count": 3}, "mistake A"
                )
                common.write_note(
                    Path(d) / "b.md", {"id": "b", "scope": "rust", "count": 1}, "mistake B"
                )
                common.write_note(
                    Path(d) / "c.md", {"id": "c", "scope": "universal", "count": 1}, "mistake C"
                )
                block = selfmodel.activate(["universal"])
                self.assertIn("mistake A", block)
                self.assertIn("mistake C", block)
                self.assertNotIn("mistake B", block)  # rust scope excluded
                self.assertLess(block.index("mistake A"), block.index("mistake C"))  # count desc
                self.assertEqual(selfmodel.activate(["python"]), "")  # no match
            finally:
                selfmodel.FAILURES = original


class TestConfig(unittest.TestCase):
    def test_defaults_when_absent(self):
        import config

        original = config.CONFIG
        try:
            config.CONFIG = Path("/tmp/cogmem-nonexistent-config-xyz.json")
            cfg = config.load()
            self.assertEqual(cfg["recall_floor"], config.DEFAULTS["recall_floor"])
        finally:
            config.CONFIG = original

    def test_save_load_roundtrip(self):
        import config

        original = config.CONFIG
        with tempfile.TemporaryDirectory() as d:
            config.CONFIG = Path(d) / "config.json"
            try:
                config.save({"recall_floor": 0.5, "recall_gap": 7.0})
                cfg = config.load()
                self.assertEqual(cfg["recall_floor"], 0.5)
                self.assertEqual(cfg["recall_gap"], 7.0)
            finally:
                config.CONFIG = original


class TestProjectState(unittest.TestCase):
    def test_activate_strips_comment_header(self):
        import projectstate

        original = projectstate.PROJECTS
        with tempfile.TemporaryDirectory() as d:
            projectstate.PROJECTS = Path(d)
            try:
                (Path(d) / "demo.md").write_text("<!-- header -->\n## Goal\nship it\n")
                out = projectstate.activate("demo")
                self.assertNotIn("<!--", out)
                self.assertIn("ship it", out)
                self.assertEqual(projectstate.activate("missing"), "")
            finally:
                projectstate.PROJECTS = original


class TestGuard(unittest.TestCase):
    def test_tripwire_match(self):
        import guard

        original = guard.FAILURES
        with tempfile.TemporaryDirectory() as d:
            guard.FAILURES = Path(d)
            try:
                common.write_note(
                    Path(d) / "fm.md",
                    {"id": "fm", "tripwire": "read -a", "guard": "warn"},
                    "shell array breaks in zsh",
                )
                hits = guard.check("while read -a x; do :; done")
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["guard"], "warn")
                self.assertEqual(guard.check("ls -la"), [])
            finally:
                guard.FAILURES = original


class TestNarrative(unittest.TestCase):
    def test_stall_signal_detects_persisting_blocker(self):
        import narrative

        original = narrative.PROJECTS
        with tempfile.TemporaryDirectory() as d:
            narrative.PROJECTS = Path(d)
            try:
                h = Path(d) / "p.history.jsonl"
                h.write_text(
                    '{"ts": "2026-06-01T00:00:00+00:00", "blockers": "- encryption unimplemented"}\n'
                    '{"ts": "2026-06-20T00:00:00+00:00", "blockers": "- encryption unimplemented"}\n'
                )
                sig = narrative.stall_signal("p")
                self.assertGreater(sig["blocked_days"], 10)
                self.assertIn("encryption", narrative.stall_alert("p"))
            finally:
                narrative.PROJECTS = original

    def test_no_alert_without_blocker(self):
        import narrative

        original = narrative.PROJECTS
        with tempfile.TemporaryDirectory() as d:
            narrative.PROJECTS = Path(d)
            try:
                (Path(d) / "q.history.jsonl").write_text(
                    '{"ts": "2026-06-20T00:00:00+00:00", "blockers": "none"}\n'
                )
                self.assertEqual(narrative.stall_alert("q"), "")
            finally:
                narrative.PROJECTS = original


class TestConsolidationBudget(unittest.TestCase):
    def test_knowledge_corpus_bounded(self):
        import consolidate

        saved = (consolidate.CLAUDE_DIR, consolidate.RULES, consolidate.PENDING)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            rules = root / "rules"
            rules.mkdir()
            consolidate.CLAUDE_DIR = root / "claude"
            consolidate.RULES = rules
            consolidate.PENDING = root / "pending"
            try:
                big = "x" * 5000
                for i in range(40):  # ~200k chars >> 48k budget
                    common.write_note(
                        rules / f"r{i:03}.md", {"id": f"r{i}", "layer": "B", "scope": "web"}, big
                    )
                # one old, in-scope rule the candidate might duplicate
                target = rules / "rust-target.md"
                common.write_note(
                    target,
                    {"id": "rust-target", "layer": "B", "scope": "rust"},
                    "RUSTNEEDLE " + big,
                )
                import os

                os.utime(target, (1, 1))  # make it the OLDEST file
                corpus = consolidate.load_existing_knowledge({"rust"})
                self.assertLess(len(corpus), consolidate.KNOWLEDGE_BUDGET + 6000)
                # despite being oldest, the in-scope rule must survive eviction
                self.assertIn("rust-target", corpus)
            finally:
                (consolidate.CLAUDE_DIR, consolidate.RULES, consolidate.PENDING) = saved


class TestGuardHardening(unittest.TestCase):
    def test_catastrophic_regex_does_not_hang(self):
        import guard

        with tempfile.TemporaryDirectory() as d:
            failures = Path(d) / "failures"
            failures.mkdir()
            common.write_note(
                failures / "evil.md",
                {"id": "evil", "tripwire": "(a+)+$", "guard": "warn"},
                "pathological pattern",
            )
            saved = guard.FAILURES
            guard.FAILURES = failures
            try:
                import time

                start = time.monotonic()
                result = guard.check("a" * 60 + "!")  # would backtrack for ages unguarded
                self.assertLess(time.monotonic() - start, 2.0)
                self.assertIsInstance(result, list)
            finally:
                guard.FAILURES = saved

    def test_normal_tripwire_still_matches(self):
        import guard

        with tempfile.TemporaryDirectory() as d:
            failures = Path(d) / "failures"
            failures.mkdir()
            common.write_note(
                failures / "rm.md",
                {"id": "rm", "tripwire": "rm -rf /", "guard": "block"},
                "do not wipe root",
            )
            saved = guard.FAILURES
            guard.FAILURES = failures
            try:
                self.assertEqual(len(guard.check("rm -rf / --no-preserve-root")), 1)
                self.assertEqual(guard.check("ls -la"), [])
            finally:
                guard.FAILURES = saved


class TestFailOpen(unittest.TestCase):
    def test_recall_raises_without_socket(self):
        original = recall.SOCK_PATH
        try:
            recall.SOCK_PATH = Path("/tmp/cogmem-nonexistent-socket-xyz.sock")
            with self.assertRaises(Exception):
                recall.recall("anything", 3, None)
        finally:
            recall.SOCK_PATH = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
