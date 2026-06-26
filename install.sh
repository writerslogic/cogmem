#!/usr/bin/env bash
# cogmem installer — idempotent and re-runnable.
#
# Sets up the full local system: code at ~/.claude/cogmem, a Python venv with
# dependencies, the `cogmem` CLI on your PATH, Claude Code hooks, and (on macOS)
# a warm recall daemon. Running it again upgrades in place without duplicating
# anything. No data leaves your machine.
#
#   git clone https://github.com/writerslogic/cogmem.git && cd cogmem && ./install.sh
#   curl -fsSL https://raw.githubusercontent.com/writerslogic/cogmem/main/install.sh | bash
#
# Flags / env:
#   --no-daemon          skip the macOS launchd daemon (recall lazy-spawns anyway)
#   --no-hooks           skip wiring Claude Code hooks into settings.json
#   COGMEM_HOME=<dir>     install location          (default: ~/.claude/cogmem)
#   COGMEM_BIN=<dir>      where to symlink the CLI   (default: ~/.local/bin)
set -euo pipefail

REPO_URL="https://github.com/writerslogic/cogmem.git"
COGMEM_HOME="${COGMEM_HOME:-$HOME/.claude/cogmem}"
CLAUDE_DIR="$HOME/.claude"
BIN_DIR="${COGMEM_BIN:-$HOME/.local/bin}"
WANT_DAEMON=1
WANT_HOOKS=1
for arg in "$@"; do
  case "$arg" in
    --no-daemon) WANT_DAEMON=0 ;;
    --no-hooks)  WANT_HOOKS=0 ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;36m=>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. Resolve source (run from a checkout, or self-clone for curl|bash) ──────
SCRIPT_SRC="${BASH_SOURCE[0]:-}"
if [ -n "$SCRIPT_SRC" ] && [ -f "$SCRIPT_SRC" ]; then
  REPO_DIR="$(cd "$(dirname "$SCRIPT_SRC")" && pwd)"
else
  REPO_DIR=""
fi
if [ -n "$REPO_DIR" ] && [ -f "$REPO_DIR/engine/mcp_server.py" ]; then
  SRC="$REPO_DIR"
else
  command -v git >/dev/null 2>&1 || die "git is required to fetch cogmem"
  SRC="$(mktemp -d)/cogmem"
  say "fetching cogmem into a temp dir"
  git clone --depth 1 "$REPO_URL" "$SRC" >/dev/null 2>&1 || die "git clone failed"
fi

# ── 2. Python check ──────────────────────────────────────────────────────────
PY_BIN="$(command -v python3 || true)"
[ -n "$PY_BIN" ] || die "python3 not found (need 3.12+)"
"$PY_BIN" - <<'PY' || die "Python 3.12+ required"
import sys
sys.exit(0 if sys.version_info[:2] >= (3, 12) else 1)
PY

# ── 3. Place code at COGMEM_HOME (sync, preserving runtime data) ──────────────
mkdir -p "$COGMEM_HOME"
if [ "$SRC" != "$COGMEM_HOME" ]; then
  say "installing code into $COGMEM_HOME"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude '.git/' --exclude 'engine/.venv/' --exclude '__pycache__/' \
      --exclude 'vault/' --exclude 'episodes/' --exclude 'hypotheses/' \
      --exclude 'activations/' --exclude 'stream/' --exclude '*.log' \
      --exclude 'engine/recall.sock' --exclude 'engine/index.db' \
      "$SRC"/ "$COGMEM_HOME"/
  else
    # Fallback: copy tracked files only, never clobber data dirs.
    ( cd "$SRC" && find . -path ./.git -prune -o -type f -print ) | while read -r f; do
      case "$f" in
        ./vault/*|./episodes/*|./hypotheses/*|./activations/*|./stream/*|*.log|*/.venv/*) continue ;;
      esac
      mkdir -p "$COGMEM_HOME/$(dirname "$f")"; cp "$SRC/$f" "$COGMEM_HOME/$f"
    done
  fi
fi
chmod +x "$COGMEM_HOME/cogmem" "$COGMEM_HOME"/hooks/*.sh 2>/dev/null || true

# ── 4. Virtualenv + dependencies ─────────────────────────────────────────────
VENV="$COGMEM_HOME/engine/.venv"
if [ ! -x "$VENV/bin/python3" ]; then
  say "creating virtualenv (engine/.venv)"
  "$PY_BIN" -m venv "$VENV"
fi
say "installing dependencies (fastembed pulls onnxruntime — first run is slow)"
"$VENV/bin/python3" -m pip install --quiet --upgrade pip
"$VENV/bin/python3" -m pip install --quiet -r "$COGMEM_HOME/requirements.txt"

# ── 5. CLI on PATH ───────────────────────────────────────────────────────────
mkdir -p "$BIN_DIR"
ln -sf "$COGMEM_HOME/cogmem" "$BIN_DIR/cogmem"
say "linked CLI -> $BIN_DIR/cogmem"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

# ── 6. Claude Code hooks (idempotent settings.json merge) ────────────────────
if [ "$WANT_HOOKS" -eq 1 ]; then
  say "wiring Claude Code hooks into settings.json (idempotent)"
  COGMEM_HOME="$COGMEM_HOME" CLAUDE_DIR="$CLAUDE_DIR" "$VENV/bin/python3" - <<'PY'
import json, os
from pathlib import Path

home = Path(os.environ["COGMEM_HOME"])
hooks_dir = home / "hooks"
settings = Path(os.environ["CLAUDE_DIR"]) / "settings.json"

# (event, matcher, hook script) — the working v2 integration.
WIRING = [
    ("SessionStart",     "*",          "cogmem-activate.sh"),
    ("UserPromptSubmit", "*",          "cogmem-recall.sh"),
    ("PreToolUse",       "Bash",       "cogmem-guard.sh"),
    ("PostToolUse",      "Edit|Write", "cogmem-context.sh"),
    ("Stop",             "*",          "cogmem-capture.sh"),
]

data = json.loads(settings.read_text()) if settings.exists() else {}
hooks = data.setdefault("hooks", {})
added = 0
for event, matcher, script in WIRING:
    cmd = str(hooks_dir / script)
    arr = hooks.setdefault(event, [])
    # Idempotent: skip if any entry already runs this cogmem hook.
    if any(h.get("command") == cmd
           for entry in arr for h in entry.get("hooks", [])):
        continue
    arr.append({"matcher": matcher,
                "hooks": [{"type": "command", "command": cmd}]})
    added += 1

if added or not settings.exists():
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(data, indent=2) + "\n")
print(f"   {added} hook(s) added, {len(WIRING) - added} already present")
PY
fi

# ── 7. macOS warm recall daemon (optional; recall lazy-spawns without it) ─────
if [ "$WANT_DAEMON" -eq 1 ] && [ "$(uname -s)" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/com.cogmem.recall.plist"
  say "installing launchd recall daemon"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.cogmem.recall</string>
    <key>ProgramArguments</key>
    <array>
        <string>$VENV/bin/python3</string>
        <string>$COGMEM_HOME/engine/daemon.py</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$COGMEM_HOME/daemon.log</string>
    <key>StandardErrorPath</key><string>$COGMEM_HOME/daemon.log</string>
</dict>
</plist>
PLISTEOF
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  launchctl load  "$PLIST" >/dev/null 2>&1 || warn "could not load launchd agent (daemon will lazy-spawn instead)"
fi

# ── 8. First-run init: build the index, materialize identity ─────────────────
say "building recall index"
"$VENV/bin/python3" "$COGMEM_HOME/engine/index.py" >/dev/null 2>&1 || warn "index build skipped (no rules yet — normal on a fresh install)"

echo
say "cogmem installed. Try:  cogmem status"
echo "   docs:      $COGMEM_HOME/README.md"
echo "   uninstall: launchctl unload ~/Library/LaunchAgents/com.cogmem.recall.plist; rm ~/.local/bin/cogmem; rm -rf $COGMEM_HOME"
