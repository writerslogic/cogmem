"""
cogmem — Python CLI entry point (console_scripts: ``cogmem``).

Mirrors the bash ``cogmem`` dispatcher so a ``pip install cogmem`` gets the same
commands. Most subcommands delegate to a module's ``__main__`` via runpy, reusing
the exact tested code paths; ``recall``, ``status``, and ``init`` are handled
directly. ``init`` performs the post-install wiring the clone installer's
install.sh does: Claude Code hooks, the warm daemon, and the recall index.
"""

import os
import runpy
import sys
from pathlib import Path

COGMEM_HOME = Path(os.environ.get("COGMEM_HOME", Path.home() / ".claude" / "cogmem"))

USAGE = (
    "Usage: cogmem [status|doctor|trust|recall|note|guard|review|capture|mcp|"
    "consolidate|index|verify|init]"
)

# subcommand -> (module, prefix args prepended to the user's args)
_DELEGATE = {
    "doctor": ("cogmem.metrics", ["doctor"]),
    "trust": ("cogmem.provenance", ["trust"]),
    "witness": ("cogmem.provenance", ["witness"]),
    "verify": ("cogmem.provenance", ["verify"]),
    "receipt": ("cogmem.provenance", ["receipt"]),
    "statement": ("cogmem.provenance", ["statement"]),
    "sign-vault": ("cogmem.provenance", ["sign-vault"]),
    "provenance": ("cogmem.provenance", []),
    "review": ("cogmem.review", []),
    "model": ("cogmem.usermodel", []),
    "progress": ("cogmem.narrative", []),
    "note": ("cogmem.note", []),
    "capture": ("cogmem.acquire", []),
    "guard": ("cogmem.guard", []),
    "ingest": ("cogmem.artifacts", []),
    "tune": ("cogmem.tune", []),
    "eval": ("cogmem.eval", []),
    "consolidate": ("cogmem.consolidate", []),
    "index": ("cogmem.index", []),
    "mcp": ("cogmem.mcp_server", []),
}


def _delegate(module: str, argv: list[str]) -> int:
    sys.argv = [module.rsplit(".", 1)[-1], *argv]
    try:
        runpy.run_module(module, run_name="__main__")
    except SystemExit as e:  # modules call sys.exit; treat as their return code
        return int(e.code or 0)
    return 0


def _recall(args: list[str]) -> int:
    from cogmem import config, recall

    if not args:
        sys.stdout.write("(no relevant memories)\n")
        return 0
    query = args[0]
    cfg = config.load()
    try:
        results = recall.recall(query, k=3, scope=None)
        results = recall.filter_results(results, cfg["recall_floor"], cfg["recall_gap"])
    except Exception:  # noqa: BLE001 — daemon down / cold: match the fail-open CLI contract
        results = []
    if not results:
        sys.stdout.write("(no relevant memories)\n")
        return 0
    for r in results:
        sys.stdout.write("- " + r["text"] + "\n")
    return 0


def _status() -> int:
    from cogmem.common import SOCK_PATH

    _delegate("cogmem.metrics", [])
    warm = "warm" if _daemon_alive(SOCK_PATH) else "cold (lazy-spawns)"
    sys.stdout.write(f"Daemon:                   {warm}\n")
    pending = COGMEM_HOME / "vault" / "pending"
    n = len(list(pending.glob("*.md"))) if pending.exists() else 0
    if n:
        sys.stdout.write(f"-> {n} rule(s) await approval: cogmem review list\n")
    return 0


def _daemon_alive(sock: Path) -> bool:
    if not sock.exists():
        return False
    import socket

    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(1.0)
        c.connect(str(sock))
        c.sendall(b'{"cmd":"ping"}\n')
        ok = b"ok" in c.recv(64)
        c.close()
        return ok
    except OSError:
        return False


def _init() -> int:
    """Post-install wiring, idempotent: record the cogmem interpreter, materialize
    the hook scripts under COGMEM_HOME, wire them into settings.json, build the
    recall index. Makes a pip install a full Claude Code integration, not just a CLI."""
    from importlib import resources

    from cogmem import wire_hooks

    COGMEM_HOME.mkdir(parents=True, exist_ok=True)
    # The hooks are bash; record the interpreter that can `import cogmem` so they can
    # invoke `python -m cogmem.<module>` regardless of how cogmem was installed.
    (COGMEM_HOME / ".cogmem-python").write_text(sys.executable + "\n")

    hooks_dir = COGMEM_HOME / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    try:
        packaged = resources.files("cogmem") / "hooks"
        count = 0
        for entry in packaged.iterdir():
            if entry.name.endswith(".sh"):
                dest = hooks_dir / entry.name
                dest.write_text(entry.read_text())
                dest.chmod(0o755)
                count += 1
        sys.stdout.write(f"   hooks: materialized {count} script(s) to {hooks_dir}\n")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        sys.stdout.write("   hooks: skipped (no packaged hook scripts found)\n")

    claude_dir = Path(os.environ.get("CLAUDE_DIR", Path.home() / ".claude"))
    added = wire_hooks.wire(claude_dir / "settings.json", hooks_dir)
    sys.stdout.write(
        f"   settings: {added} hook(s) added, {len(wire_hooks.WIRING) - added} already present\n"
    )

    # Build the recall index if the recall extra is installed; harmless no-op otherwise.
    try:
        _delegate("cogmem.index", [])
    except ModuleNotFoundError:
        sys.stdout.write("   index: skipped (install the [recall] extra for semantic recall)\n")
    sys.stdout.write("cogmem initialized. Try:  cogmem status\n")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    cmd = argv[0] if argv else "status"
    rest = argv[1:]
    if cmd == "status":
        return _status()
    if cmd == "recall":
        return _recall(rest)
    if cmd == "init":
        return _init()
    if cmd in _DELEGATE:
        module, prefix = _DELEGATE[cmd]
        return _delegate(module, prefix + rest)
    sys.stderr.write(USAGE + "\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
