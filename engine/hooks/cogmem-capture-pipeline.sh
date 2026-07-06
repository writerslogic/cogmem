#!/bin/bash
# Background capture pipeline — invoked detached by the Stop hook so it never
# delays session end. Runs acquire -> consolidate -> reindex. Single-flight
# (one capture at a time), dedups already-captured transcript states, and
# reindexes through the warm daemon (cold fallback). All steps fail-soft.
set -uo pipefail

TRANSCRIPT="${1:-}"
PROJECT="${2:-}"
[[ -z "$TRANSCRIPT" || ! -f "$TRANSCRIPT" ]] && exit 0

# Self-locate (invoked from $COGMEM_HOME/hooks/), honoring an explicit COGMEM_HOME,
# so a non-default install runs its pipeline against its own vault.
COGMEM="${COGMEM_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# Interpreter that can import cogmem: init-recorded, else clone venv, else system.
PY="$(cat "$COGMEM/.cogmem-python" 2>/dev/null)"
[[ -x "$PY" ]] || PY="$COGMEM/engine/.venv/bin/python3"
[[ -x "$PY" ]] || PY="python3"
LOG="$COGMEM/capture.log"
CAPTURED="$COGMEM/vault/.captured"
LOCK="$COGMEM/.capture.lock"
SOCK="$COGMEM/recall.sock"

# Portable mtime in epoch seconds: BSD stat (macOS) then GNU stat (Linux).
mtime() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0; }

SID=$(basename "$TRANSCRIPT" .jsonl)
MT=$(mtime "$TRANSCRIPT")

# Dedup: skip if this transcript was already captured at this size/mtime or later.
if [[ -f "$CAPTURED" ]] && awk -v s="$SID" -v m="$MT" '$1==s && $2>=m{found=1} END{exit !found}' "$CAPTURED"; then
    exit 0
fi

# Single-flight lock (mkdir is atomic). Recover locks older than 10 min (crash).
if ! mkdir "$LOCK" 2>/dev/null; then
    AGE=$(( $(date +%s) - $(mtime "$LOCK") ))
    if [[ $AGE -gt 600 ]]; then
        rmdir "$LOCK" 2>/dev/null && mkdir "$LOCK" 2>/dev/null || exit 0
    else
        exit 0
    fi
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

{
    echo "--- $(date -u +%FT%TZ) capture: $SID ---"
    "$PY" -m cogmem.acquire "$TRANSCRIPT" 2>&1
    CHANGED=false
    if ls "$COGMEM/vault/candidates"/*.md >/dev/null 2>&1; then
        "$PY" -m cogmem.consolidate 2>&1
        CHANGED=true
    fi
    # Score the rules that were recalled this session (may demote/promote).
    "$PY" -m cogmem.feedback "$TRANSCRIPT" 2>&1 && CHANGED=true
    # Capture the assistant's own failure modes from this session.
    "$PY" -m cogmem.selfmodel "$TRANSCRIPT" 2>&1
    # Update the living project-state model for this project.
    [[ -n "$PROJECT" ]] && "$PY" -m cogmem.projectstate "$TRANSCRIPT" "$PROJECT" 2>&1
    # Refresh the synthesized user model at most once per day.
    if [[ -z "$(find "$COGMEM/vault/user-model.md" -mtime -1 2>/dev/null)" ]]; then
        "$PY" -m cogmem.usermodel 2>&1
    fi
    # Reindex via the warm daemon (cheap no-op when unchanged); cold fallback only
    # when something actually changed, to avoid a model load on routine sessions.
    "$PY" -c "import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(180)
s.connect('$SOCK'); s.sendall(b'{\"cmd\":\"reindex\"}\n'); sys.stdout.write(s.recv(4096).decode())" 2>/dev/null \
        || { $CHANGED && "$PY" -m cogmem.index 2>&1; }
    # Issue verifiable credentials for new/edited memories and extend the
    # tamper-evident transparency log (fail-soft; never blocks capture).
    "$PY" -m cogmem.provenance sign-vault 2>&1 || true
    echo "$SID $MT" >> "$CAPTURED"
} >> "$LOG" 2>&1

exit 0
