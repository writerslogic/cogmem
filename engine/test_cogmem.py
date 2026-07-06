"""
Cognitive Memory — test suite (stdlib unittest, no API/model needed)

Covers the pure, breakage-prone glue: frontmatter roundtrip, note validation,
slugify, recall floor+gap filtering, and the recall client's fail-open contract.

Run:  python test_cogmem.py
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

from cogmem import common
from cogmem import recall
from cogmem.acquire import slugify


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
        from cogmem import selfmodel

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
        from cogmem import config

        original = config.CONFIG
        try:
            config.CONFIG = Path("/tmp/cogmem-nonexistent-config-xyz.json")
            cfg = config.load()
            self.assertEqual(cfg["recall_floor"], config.DEFAULTS["recall_floor"])
        finally:
            config.CONFIG = original

    def test_save_load_roundtrip(self):
        from cogmem import config

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
        from cogmem import projectstate

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
        from cogmem import guard

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
        from cogmem import narrative

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
        from cogmem import narrative

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
        from cogmem import consolidate

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
        from cogmem import guard

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
        from cogmem import guard

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


class TestOutcomeEval(unittest.TestCase):
    def test_realized_efficacy_math(self):
        from cogmem import eval as cogmem_eval

        saved = cogmem_eval.RULES
        with tempfile.TemporaryDirectory() as d:
            rules = Path(d)
            cogmem_eval.RULES = rules
            try:
                common.write_note(
                    rules / "a.md", {"id": "a", "recalled": 4, "helpful": 3, "contradicted": 1}, "x"
                )
                common.write_note(
                    rules / "b.md", {"id": "b", "recalled": 0, "helpful": 0, "contradicted": 0}, "y"
                )
                o = cogmem_eval.outcomes()
                self.assertEqual(o["rules"], 2)
                self.assertEqual(o["rules_ever_recalled"], 1)  # only 'a' fired
                self.assertEqual(o["coverage"], 0.5)
                self.assertEqual(o["recall_events"], 4)
                self.assertEqual(o["helpful_rate"], 0.75)  # 3/4
                self.assertEqual(o["contradicted_rate"], 0.25)  # 1/4
                self.assertEqual(o["net_per_recall"], 0.5)  # (3-1)/4
            finally:
                cogmem_eval.RULES = saved

    def test_no_recalls_yields_none_rates(self):
        from cogmem import eval as cogmem_eval

        saved = cogmem_eval.RULES
        with tempfile.TemporaryDirectory() as d:
            cogmem_eval.RULES = Path(d)
            try:
                common.write_note(Path(d) / "a.md", {"id": "a"}, "x")
                o = cogmem_eval.outcomes()
                self.assertIsNone(o["helpful_rate"])
                self.assertEqual(o["coverage"], 0.0)
            finally:
                cogmem_eval.RULES = saved


class TestNote(unittest.TestCase):
    def test_note_honors_cogmem_home(self):
        import os
        import subprocess

        note_py = Path(__file__).resolve().parent / "note.py"
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "COGMEM_HOME": d}
            subprocess.run([sys.executable, str(note_py), "use", "ripgrep"], env=env, check=True)
            notes = Path(d) / "vault" / ".notes.jsonl"
            self.assertTrue(
                notes.exists(), "note must write under COGMEM_HOME, not the default vault"
            )
            self.assertIn("use ripgrep", notes.read_text())


class TestUserModel(unittest.TestCase):
    def test_gather_evidence_tags_each_source(self):
        from cogmem import usermodel

        original = usermodel.VAULT
        with tempfile.TemporaryDirectory() as d:
            usermodel.VAULT = Path(d)
            try:
                common.write_note(
                    Path(d) / "episodes" / "e1.md",
                    {"id": "e1", "kind": "episode"},
                    "discovered the build flakes without --locked",
                )
                common.write_note(
                    Path(d) / "learned" / "r1.md",
                    {"id": "r1", "scope": "rust"},
                    "pin dependencies with --locked",
                )
                common.write_note(
                    Path(d) / "failures" / "f1.md",
                    {"id": "f1", "scope": "universal"},
                    "you declared done before running the tests",
                )
                ev = usermodel.gather_evidence()
                self.assertIn("EPISODE:", ev)
                self.assertIn("RULE:", ev)
                self.assertIn("CORRECTS:", ev)
            finally:
                usermodel.VAULT = original

    def test_synthesize_uses_configured_name(self):
        from cogmem import config
        from cogmem import usermodel

        captured = {}

        def fake_api(model, prompt, max_tokens):
            captured["prompt"] = prompt
            return "## Standards\na high bar for rigor"

        saved = (usermodel.VAULT, usermodel.MODEL_FILE, usermodel.api_call, config.CONFIG)
        with tempfile.TemporaryDirectory() as d:
            usermodel.VAULT = Path(d)
            usermodel.MODEL_FILE = Path(d) / "user-model.md"
            usermodel.api_call = fake_api
            config.CONFIG = Path(d) / "config.json"
            config.save({"user_name": "Ada"})
            try:
                for i in range(3):
                    common.write_note(
                        Path(d) / "episodes" / f"e{i}.md",
                        {"id": f"e{i}", "kind": "episode"},
                        "a sufficiently long episode body so evidence clears the length floor " * 2,
                    )
                self.assertTrue(usermodel.synthesize())
                self.assertIn("Ada", captured["prompt"])
                self.assertIn("# User model: Ada", usermodel.MODEL_FILE.read_text())
            finally:
                (usermodel.VAULT, usermodel.MODEL_FILE, usermodel.api_call, config.CONFIG) = saved


class TestArtifacts(unittest.TestCase):
    def _make_repo(self, path: Path) -> None:
        import subprocess

        env = {
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
        }
        import os

        env = {**os.environ, **env}
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        (path / "f.txt").write_text("x")
        subprocess.run(["git", "-C", str(path), "add", "."], check=True, env=env)
        subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "commit",
                "-q",
                "-m",
                "fix: revert the eager cache flush that corrupted state on a cold start, "
                "a recurring gotcha when the daemon races the indexer",
                "-m",
                "The flush ran before the index finished loading, so a cold start lost the "
                "freshly embedded rules. Defer it until the daemon reports ready; this has "
                "bitten us twice now and both times the symptom was an empty recall.",
            ],
            check=True,
            env=env,
        )

    def test_git_history_reads_commits(self):
        from cogmem import artifacts

        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            self._make_repo(repo)
            hist = artifacts.git_history(repo)
            self.assertIsNotNone(hist)
            self.assertIn("eager cache flush", hist)

    def test_ingest_writes_scoped_candidate(self):
        from cogmem import artifacts

        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "MyRepo"
            repo.mkdir()
            self._make_repo(repo)
            cand = Path(d) / "candidates"
            saved = (artifacts.CANDIDATES, artifacts.api_call)
            artifacts.CANDIDATES = cand
            artifacts.api_call = lambda *a, **k: (
                '{"rules": [{"rule": "flush the cache lazily, not on cold start", '
                '"evidence": "the revert commit"}]}'
            )
            try:
                n = artifacts.ingest(repo)
                self.assertEqual(n, 1)
                written = list(cand.glob("*.md"))
                self.assertEqual(len(written), 1)
                meta, body = common.read_note(written[0])
                self.assertEqual(meta["scope"], "myrepo")  # repo name, lowercased
                self.assertIn("flush the cache lazily", body)
            finally:
                (artifacts.CANDIDATES, artifacts.api_call) = saved


class TestFeedbackRouting(unittest.TestCase):
    """The promote/demote/refine routing in feedback.apply_verdict is the core of the
    learning loop and runs with no API — exercise every branch directly."""

    def _dirs(self, d):
        from cogmem import feedback

        root = Path(d)
        feedback.RULES = root / "rules"
        feedback.PENDING = root / "pending"
        feedback.REJECTED = root / "rejected"
        feedback.CANDIDATES = root / "candidates"
        for p in (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES):
            p.mkdir(parents=True, exist_ok=True)
        return feedback

    def test_helpful_increments_in_place(self):
        from cogmem import feedback

        saved = (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES)
        with tempfile.TemporaryDirectory() as d:
            fb = self._dirs(d)
            try:
                meta = {"id": "r", "layer": "B", "scope": "rust"}
                p = fb.RULES / "r.md"
                common.write_note(p, meta, "use --locked")
                out = fb.apply_verdict(
                    p,
                    dict(meta),
                    "use --locked",
                    {"verdict": "helpful", "correction": None},
                    "s",
                    "now",
                )
                self.assertEqual(out, "helpful")
                rmeta, _ = common.read_note(p)
                self.assertEqual(int(rmeta["helpful"]), 1)
                self.assertEqual(int(rmeta["recalled"]), 1)
            finally:
                (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES) = saved

    def test_repeated_helpful_suggests_promotion(self):
        from cogmem import feedback

        saved = (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES)
        with tempfile.TemporaryDirectory() as d:
            fb = self._dirs(d)
            try:
                meta = {"id": "r", "layer": "B", "scope": "rust", "helpful": fb.PROMOTE_HELPFUL - 1}
                p = fb.RULES / "r.md"
                common.write_note(p, meta, "use --locked")
                out = fb.apply_verdict(
                    p,
                    dict(meta),
                    "use --locked",
                    {"verdict": "helpful", "correction": None},
                    "s",
                    "now",
                )
                self.assertEqual(out, "helpful+promote-suggested")
                promoted = fb.PENDING / "promoted-r.md"
                self.assertTrue(promoted.exists())
                pmeta, _ = common.read_note(promoted)
                self.assertEqual(pmeta["layer"], "A")  # promotion targets the always-load layer
            finally:
                (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES) = saved

    def test_contradiction_with_correction_refines_via_pipeline(self):
        from cogmem import feedback

        saved = (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES)
        with tempfile.TemporaryDirectory() as d:
            fb = self._dirs(d)
            try:
                meta = {"id": "r", "layer": "B", "scope": "rust"}
                p = fb.RULES / "r.md"
                common.write_note(p, meta, "old wrong rule")
                out = fb.apply_verdict(
                    p,
                    dict(meta),
                    "old wrong rule",
                    {"verdict": "contradicted", "correction": "pin deps with --locked always"},
                    "s",
                    "now",
                )
                self.assertEqual(out, "refined")
                self.assertFalse(p.exists())  # original retired
                self.assertTrue((fb.REJECTED / "r.md").exists())
                # correction re-enters the SAFE pipeline as a candidate, never an in-place edit
                cands = list(fb.CANDIDATES.glob("*.md"))
                self.assertEqual(len(cands), 1)
                _, cbody = common.read_note(cands[0])
                self.assertIn("--locked", cbody)
            finally:
                (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES) = saved

    def test_repeated_contradiction_demotes(self):
        from cogmem import feedback

        saved = (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES)
        with tempfile.TemporaryDirectory() as d:
            fb = self._dirs(d)
            try:
                meta = {
                    "id": "r",
                    "layer": "B",
                    "scope": "rust",
                    "contradicted": fb.DEMOTE_CONTRA - 1,
                    "helpful": 0,
                }
                p = fb.RULES / "r.md"
                common.write_note(p, meta, "misleading rule")
                out = fb.apply_verdict(
                    p,
                    dict(meta),
                    "misleading rule",
                    {"verdict": "contradicted", "correction": None},
                    "s",
                    "now",
                )
                self.assertEqual(out, "demoted")
                self.assertFalse(p.exists())
                dmeta, _ = common.read_note(fb.REJECTED / "r.md")
                self.assertEqual(dmeta["status"], "demoted-contradicted")
            finally:
                (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES) = saved

    def test_ignored_is_neutral(self):
        from cogmem import feedback

        saved = (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES)
        with tempfile.TemporaryDirectory() as d:
            fb = self._dirs(d)
            try:
                meta = {"id": "r", "layer": "B", "scope": "rust"}
                p = fb.RULES / "r.md"
                common.write_note(p, meta, "situational rule")
                out = fb.apply_verdict(
                    p,
                    dict(meta),
                    "situational rule",
                    {"verdict": "ignored", "correction": None},
                    "s",
                    "now",
                )
                self.assertEqual(out, "ignored")
                self.assertTrue(p.exists())  # stays active
                rmeta, _ = common.read_note(p)
                self.assertEqual(int(rmeta["recalled"]), 1)
                self.assertEqual(int(rmeta.get("helpful", 0)), 0)
            finally:
                (feedback.RULES, feedback.PENDING, feedback.REJECTED, feedback.CANDIDATES) = saved


class TestWriteCandidate(unittest.TestCase):
    """acquire.write_candidate turns a model-emitted rule dict into a candidate note;
    deterministic, so cover the slug/layer/collision logic without the API."""

    def test_empty_rule_writes_nothing(self):
        from cogmem import acquire

        saved = acquire.CANDIDATES_DIR
        with tempfile.TemporaryDirectory() as d:
            acquire.CANDIDATES_DIR = Path(d)
            try:
                self.assertIsNone(acquire.write_candidate({"rule": "   "}, "sess", "now"))
            finally:
                acquire.CANDIDATES_DIR = saved

    def test_basic_candidate_has_frontmatter_and_body(self):
        from cogmem import acquire

        saved = acquire.CANDIDATES_DIR
        with tempfile.TemporaryDirectory() as d:
            acquire.CANDIDATES_DIR = Path(d)
            try:
                p = acquire.write_candidate(
                    {"rule": "Run cargo fmt before commit", "layer": "B", "scope": "rust"},
                    "sess",
                    "now",
                )
                self.assertIsNotNone(p)
                meta, body = common.read_note(p)
                self.assertEqual(meta["layer"], "B")
                self.assertEqual(meta["scope"], "rust")
                self.assertEqual(meta["status"], "candidate")
                self.assertIn("Run cargo fmt before commit", body)
            finally:
                acquire.CANDIDATES_DIR = saved

    def test_invalid_layer_defaults_to_b(self):
        from cogmem import acquire

        saved = acquire.CANDIDATES_DIR
        with tempfile.TemporaryDirectory() as d:
            acquire.CANDIDATES_DIR = Path(d)
            try:
                p = acquire.write_candidate(
                    {"rule": "x rule", "layer": "Z", "scope": "universal"}, "sess", "now"
                )
                meta, _ = common.read_note(p)
                self.assertEqual(meta["layer"], "B")
            finally:
                acquire.CANDIDATES_DIR = saved

    def test_slug_collision_does_not_clobber(self):
        from cogmem import acquire

        saved = acquire.CANDIDATES_DIR
        with tempfile.TemporaryDirectory() as d:
            acquire.CANDIDATES_DIR = Path(d)
            try:
                rule = {"rule": "same text", "scope": "rust"}
                p1 = acquire.write_candidate(rule, "s1", "now")
                p2 = acquire.write_candidate(rule, "s2", "now")
                self.assertNotEqual(p1, p2)
                self.assertEqual(len(list(Path(d).glob("*.md"))), 2)
            finally:
                acquire.CANDIDATES_DIR = saved


class TestConsolidateRoute(unittest.TestCase):
    """consolidate.route is the dedup verdict -> destination router; deterministic."""

    def _setup(self, d):
        from cogmem import consolidate

        root = Path(d)
        consolidate.RULES = root / "rules"
        consolidate.PENDING = root / "pending"
        consolidate.REJECTED = root / "rejected"
        cand = root / "candidates"
        cand.mkdir(parents=True, exist_ok=True)
        return consolidate, cand

    def test_known_goes_to_rejected(self):
        from cogmem import consolidate

        saved = (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED)
        with tempfile.TemporaryDirectory() as d:
            con, cand = self._setup(d)
            try:
                p = cand / "r.md"
                common.write_note(p, {"id": "r", "layer": "B"}, "dup rule")
                con.route(
                    p,
                    {"id": "r", "layer": "B"},
                    "dup rule",
                    {"verdict": "known", "reason": "already covered"},
                    "now",
                    False,
                )
                self.assertFalse(p.exists())
                dmeta, _ = common.read_note(con.REJECTED / "r.md")
                self.assertEqual(dmeta["status"], "rejected-known")
            finally:
                (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED) = saved

    def test_new_layer_b_becomes_active_rule(self):
        from cogmem import consolidate

        saved = (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED)
        with tempfile.TemporaryDirectory() as d:
            con, cand = self._setup(d)
            try:
                p = cand / "r.md"
                common.write_note(p, {"id": "r", "layer": "B"}, "new situational rule")
                con.route(
                    p,
                    {"id": "r", "layer": "B"},
                    "new situational rule",
                    {"verdict": "new", "reason": ""},
                    "now",
                    False,
                )
                rmeta, _ = common.read_note(con.RULES / "r.md")
                self.assertEqual(rmeta["status"], "active")
            finally:
                (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED) = saved

    def test_new_layer_a_waits_for_approval(self):
        from cogmem import consolidate

        saved = (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED)
        with tempfile.TemporaryDirectory() as d:
            con, cand = self._setup(d)
            try:
                p = cand / "r.md"
                common.write_note(p, {"id": "r", "layer": "A"}, "always-load guardrail")
                con.route(
                    p,
                    {"id": "r", "layer": "A"},
                    "always-load guardrail",
                    {"verdict": "new", "reason": ""},
                    "now",
                    False,
                )
                pmeta, _ = common.read_note(con.PENDING / "r.md")
                self.assertEqual(pmeta["status"], "pending-approval")
            finally:
                (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED) = saved

    def test_dry_run_moves_nothing(self):
        from cogmem import consolidate

        saved = (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED)
        with tempfile.TemporaryDirectory() as d:
            con, cand = self._setup(d)
            try:
                p = cand / "r.md"
                common.write_note(p, {"id": "r", "layer": "B"}, "rule")
                con.route(
                    p,
                    {"id": "r", "layer": "B"},
                    "rule",
                    {"verdict": "new", "reason": ""},
                    "now",
                    True,
                )
                self.assertTrue(p.exists())  # untouched
                self.assertFalse((con.RULES / "r.md").exists())
            finally:
                (consolidate.RULES, consolidate.PENDING, consolidate.REJECTED) = saved


class TestIndexProvenanceGate(unittest.TestCase):
    def test_current_rules_weight_is_helpful_minus_contradicted(self):
        from cogmem import indexstore

        saved = indexstore.RULES
        with tempfile.TemporaryDirectory() as d:
            indexstore.RULES = Path(d)
            try:
                common.write_note(
                    Path(d) / "r.md",
                    {"id": "r", "scope": "rust", "helpful": 5, "contradicted": 2},
                    "a rule",
                )
                rows = indexstore.current_rules()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], "r")  # id
                self.assertEqual(rows[0][4], 3.0)  # weight = 5 - 2
            finally:
                indexstore.RULES = saved

    def test_provenance_gate_rejects_missing_or_tampered(self):
        from cogmem import indexstore

        class StubPV:
            def __init__(self, creds):
                self.CREDENTIALS = creds

            @staticmethod
            def verify_credential(vc):
                return True

        with tempfile.TemporaryDirectory() as d:
            creds = Path(d)
            pv = StubPV(creds)
            f = Path(d) / "r.md"
            # missing credential -> excluded
            self.assertFalse(indexstore._provenance_ok(pv, {"id": "r"}, "body", f))
            # credential whose statement matches the rule body -> kept
            (creds / "r.jsonld").write_text('{"credentialSubject": {"statement": "body"}}')
            self.assertTrue(indexstore._provenance_ok(pv, {"id": "r"}, "body", f))
            # statement no longer matches the body (a post-signing edit) -> excluded
            self.assertFalse(indexstore._provenance_ok(pv, {"id": "r"}, "EDITED", f))


class TestWireHooks(unittest.TestCase):
    """install.sh's settings.json merge is the riskiest install step (it can
    double-wire hooks or clobber a user's config). It is pure JSON, so test it."""

    def test_first_wire_adds_all_then_idempotent(self):
        from cogmem import wire_hooks

        with tempfile.TemporaryDirectory() as d:
            settings = Path(d) / "settings.json"
            hooks_dir = Path(d) / "hooks"
            added = wire_hooks.wire(settings, hooks_dir)
            self.assertEqual(added, len(wire_hooks.WIRING))
            # second run must add nothing (idempotent) and not duplicate entries
            self.assertEqual(wire_hooks.wire(settings, hooks_dir), 0)
            data = json.loads(settings.read_text())
            cmds = [h["command"] for arr in data["hooks"].values() for e in arr for h in e["hooks"]]
            self.assertEqual(len(cmds), len(wire_hooks.WIRING))  # no dupes
            self.assertTrue(all(str(hooks_dir) in c for c in cmds))

    def test_preserves_existing_settings_and_hooks(self):
        from cogmem import wire_hooks

        with tempfile.TemporaryDirectory() as d:
            settings = Path(d) / "settings.json"
            settings.write_text(
                json.dumps(
                    {
                        "model": "opus",
                        "hooks": {
                            "Stop": [
                                {
                                    "matcher": "*",
                                    "hooks": [
                                        {"type": "command", "command": "/usr/bin/my-own-hook"}
                                    ],
                                }
                            ]
                        },
                    }
                )
            )
            wire_hooks.wire(settings, Path(d) / "hooks")
            data = json.loads(settings.read_text())
            self.assertEqual(data["model"], "opus")  # unrelated setting untouched
            stop_cmds = [h["command"] for e in data["hooks"]["Stop"] for h in e["hooks"]]
            self.assertIn("/usr/bin/my-own-hook", stop_cmds)  # user's own hook kept
            self.assertTrue(
                any("cogmem-capture.sh" in c for c in stop_cmds)
            )  # ours added alongside


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
