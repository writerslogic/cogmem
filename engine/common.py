"""Shared helpers for the cogmem engine: API access and frontmatter I/O.

The markdown files are the source of truth. Frontmatter is a small, fixed set of
scalar fields, so a minimal parser is used rather than pulling in a YAML dependency.
"""

import json
import logging
import os
import urllib.request
import urllib.error
from pathlib import Path

log = logging.getLogger("cogmem")

COGMEM = Path(os.environ.get("COGMEM_HOME", Path.home() / ".claude" / "cogmem"))
VAULT = COGMEM / "vault"
CLAUDE_DIR = Path.home() / ".claude"

API_URL = "https://api.anthropic.com/v1/messages"


def api_call(model: str, prompt: str, max_tokens: int) -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        log.error("ANTHROPIC_API_KEY not set")
        return None
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read())["content"][0]["text"]
    except urllib.error.HTTPError as e:
        log.error("API HTTP %s: %s", e.code, e.read()[:200])
    except Exception as e:  # noqa: BLE001 — callers run inside hooks; never crash a session
        log.error("API call failed: %s", e)
    return None


def parse_json_block(text: str) -> object | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        log.warning("Could not parse model output: %s", text[:200])
        return None


def read_note(path: Path) -> tuple[dict, str]:
    """Return (frontmatter_dict, body) for a markdown note. Tolerant of files
    without frontmatter (returns empty dict + full text as body)."""
    text = path.read_text(errors="replace")
    if not text.startswith("---\n"):
        return {}, text.strip()
    _, fm, body = text.split("---\n", 2)
    meta: dict = {}
    for line in fm.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        meta[k.strip()] = v
    return meta, body.strip()


def validate_note(meta: dict, body: str) -> list[str]:
    """Return a list of problems with a note (empty list = valid). Used to keep
    malformed model output out of the vault."""
    errors = []
    if not meta.get("id"):
        errors.append("missing id")
    layer = meta.get("layer")
    if layer and str(layer).upper() not in ("A", "B"):
        errors.append(f"invalid layer: {layer}")
    if not body or not body.strip():
        errors.append("empty body")
    return errors


def write_note(path: Path, meta: dict, body: str) -> None:
    lines = ["---"]
    for k, v in meta.items():
        v = str(v)
        if any(c in v for c in ':"#') or v == "":
            v = '"' + v.replace('"', "'") + '"'
        lines.append(f"{k}: {v}")
    lines.append("---\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n" + body.strip() + "\n")
