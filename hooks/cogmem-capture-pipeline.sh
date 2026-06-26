#!/bin/bash
# Background capture pipeline — invoked detached by the Stop hook so it never
# delays session end. Runs acquire -> consolidate -> reindex. Single-flight
# (one capture at a time), dedups already-captured transcript states, and
# reindexes through the warm daemon (cold fallback). All steps fail-soft.
set -uo pipefail

TRANSCRIPT="${1:-}"
PROJECT="${2:-}"
[[ -z "$TRANSCRIPT" || ! -f "$TRANSCRIPT" ]] && exit 0

COGMEM="$HOME/.claude/cogmem"
ENGINE="$COGMEM/engine"
PY="$ENGINE/.venv/bin/python3"
LOG="$COGMEM/capture.log"
CAPTURED="$COGMEM/vault/.captured"
LOCK="$COGMEM/.capture.lock"
SOCK="$ENGINE/recall.sock"
[[ -x "$PY" ]] || PY="python3"

SID=$(basename "$TRANSCRIPT" .jsonl)
MT=$(stat -f %m "$TRANSCRIPT" 2>/dev/null || echo 0)

# Dedup: skip if this transcript was already captured at this size/mtime or later.
if [[ -f "$CAPTURED" ]] && awk -v s="$SID" -v m="$MT" '$1==s && $2>=m{found=1} END{exit !found}' "$CAPTURED"; then
    exit 0
fi

# Single-flight lock (mkdir is atomic). Recover locks older than 10 min (crash).
if ! mkdir "$LOCK" 2>/dev/null; then
    AGE=$(( $(date +%s) - $(stat -f %m "$LOCK" 2>/dev/null || echo 0) ))
    if [[ $AGE -gt 600 ]]; then
        rmdir "$LOCK" 2>/dev/null && mkdir "$LOCK" 2>/dev/null || exit 0
    else
        exit 0
    fi
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

{
    echo "--- $(date -u +%FT%TZ) capture: $SID ---"
    "$PY" "$ENGINE/acquire.py" "$TRANSCRIPT" 2>&1
    CHANGED=false
    if ls "$COGMEM/vault/candidates"/*.md >/dev/null 2>&1; then
        "$PY" "$ENGINE/consolidate.py" 2>&1
        CHANGED=true
    fi
    # Score the rules that were recalled this session (may demote/promote).
    "$PY" "$ENGINE/feedback.py" "$TRANSCRIPT" 2>&1 && CHANGED=true
    # Capture the assistant's own failure modes from this session.
    "$PY" "$ENGINE/selfmodel.py" "$TRANSCRIPT" 2>&1
    # Update the living project-state model for this project.
    [[ -n "$PROJECT" ]] && "$PY" "$ENGINE/projectstate.py" "$TRANSCRIPT" "$PROJECT" 2>&1
    # Refresh the synthesized user model at most once per day.
    if [[ -z "$(find "$COGMEM/vault/user-model.md" -mtime -1 2>/dev/null)" ]]; then
        "$PY" "$ENGINE/usermodel.py" 2>&1
    fi
    # Reindex via the warm daemon (cheap no-op when unchanged); cold fallback only
    # when something actually changed, to avoid a model load on routine sessions.
    "$PY" -c "import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(180)
s.connect('$SOCK'); s.sendall(b'{\"cmd\":\"reindex\"}\n'); sys.stdout.write(s.recv(4096).decode())" 2>/dev/null \
        || { $CHANGED && "$PY" "$ENGINE/index.py" 2>&1; }
    # Issue verifiable credentials for new/edited memories and extend the
    # tamper-evident transparency log (fail-soft; never blocks capture).
    "$PY" "$ENGINE/provenance.py" sign-vault 2>&1 || true
    echo "$SID $MT" >> "$CAPTURED"
} >> "$LOG" 2>&1

exit 0
