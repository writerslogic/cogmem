#!/usr/bin/env bash
# cogmem installer — idempotent and re-runnable.
#
# Sets up the full local system: code at ~/.claude/cogmem, a Python venv with
# dependencies, the `cogmem` CLI on your PATH, Claude Code hooks, and a warm
# recall daemon (launchd on macOS, systemd --user on Linux). Running it again
# upgrades in place without duplicating anything. No data leaves your machine.
#
#   git clone https://github.com/writerslogic/cogmem.git && cd cogmem && ./install.sh
#   curl -fsSL https://raw.githubusercontent.com/writerslogic/cogmem/main/install.sh | bash
#
# Flags / env:
#   --no-daemon          skip the warm recall daemon (recall lazy-spawns anyway)
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
chmod +x "$COGMEM_HOME/cogmem" "$COGMEM_HOME"/engine/hooks/*.sh 2>/dev/null || true

# ── 4. Virtualenv + dependencies ─────────────────────────────────────────────
VENV="$COGMEM_HOME/engine/.venv"
if [ ! -x "$VENV/bin/python3" ]; then
  say "creating virtualenv (engine/.venv)"
  "$PY_BIN" -m venv "$VENV"
fi
say "installing cogmem + dependencies (fastembed pulls onnxruntime — first run is slow)"
"$VENV/bin/python3" -m pip install --quiet --upgrade pip
# Editable install of the package with the recall extra (fastembed/numpy), so the
# CLI, hooks (which run engine/*.py by path), and daemon all resolve `import cogmem`.
"$VENV/bin/python3" -m pip install --quiet -e "${COGMEM_HOME}[recall]"

# ── 5. CLI on PATH ───────────────────────────────────────────────────────────
mkdir -p "$BIN_DIR"
ln -sf "$COGMEM_HOME/cogmem" "$BIN_DIR/cogmem"
say "linked CLI -> $BIN_DIR/cogmem"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

# ── 6. Claude Code hooks + index (via `cogmem init`, idempotent) ─────────────
# `cogmem init` records the interpreter, materializes the hook scripts into
# $COGMEM_HOME/hooks, merges them into settings.json, and builds the recall index —
# the same wiring a `pip install cogmem` user runs.
if [ "$WANT_HOOKS" -eq 1 ]; then
  say "wiring Claude Code hooks + building index (cogmem init, idempotent)"
  COGMEM_HOME="$COGMEM_HOME" CLAUDE_DIR="$CLAUDE_DIR" "$VENV/bin/cogmem" init
fi

# ── 7. Warm recall daemon (optional; recall lazy-spawns without it) ───────────
# launchd on macOS, a systemd --user service on Linux. Either way the daemon is
# the same engine/daemon.py, kept alive across sessions so the first prompt's
# recall is fast instead of paying a model load.
if [ "$WANT_DAEMON" -eq 1 ]; then
  OS="$(uname -s)"
  if [ "$OS" = "Darwin" ]; then
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
  elif [ "$OS" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
    UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    say "installing systemd --user recall daemon"
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/cogmem-recall.service" <<UNITEOF
[Unit]
Description=cogmem warm recall daemon
After=default.target

[Service]
Type=simple
ExecStart=$VENV/bin/python3 $COGMEM_HOME/engine/daemon.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
UNITEOF
    if systemctl --user daemon-reload >/dev/null 2>&1 \
       && systemctl --user enable --now cogmem-recall.service >/dev/null 2>&1; then
      say "systemd user service enabled (cogmem-recall.service)"
    else
      warn "could not enable systemd user service (daemon will lazy-spawn instead). On a headless host, persist it with: loginctl enable-linger \"\$USER\""
    fi
  fi
fi

# ── 8. First-run index (only when `cogmem init` above didn't already build it) ─
if [ "$WANT_HOOKS" -eq 0 ]; then
  say "building recall index"
  "$VENV/bin/python3" -m cogmem.index >/dev/null 2>&1 || warn "index build skipped (no rules yet — normal on a fresh install)"
fi

echo
say "cogmem installed. Try:  cogmem status"
echo "   docs:      $COGMEM_HOME/README.md"
if [ "$(uname -s)" = "Linux" ]; then
  echo "   uninstall: systemctl --user disable --now cogmem-recall.service; rm ~/.local/bin/cogmem; rm -rf $COGMEM_HOME"
else
  echo "   uninstall: launchctl unload ~/Library/LaunchAgents/com.cogmem.recall.plist; rm ~/.local/bin/cogmem; rm -rf $COGMEM_HOME"
fi
