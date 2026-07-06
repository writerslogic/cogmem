#!/bin/bash
# PostToolUse(Edit|Write) hook — records which files the session is actively
# changing, so recall can fire on the work, not just the prompt text. Tiny and
# fail-open: appends one basename, caps history, never blocks a tool call.
set -uo pipefail

# Resolve cogmem's home from COGMEM_HOME, else from this hook's own location
# ($COGMEM_HOME/hooks/), so a non-default install operates on its own vault.
COGMEM_HOME="${COGMEM_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

INPUT=$(cat)
FP=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
SID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null)
[[ -z "$FP" || -z "$SID" ]] && exit 0

CTXDIR="$COGMEM_HOME/vault/.ctx"
mkdir -p "$CTXDIR" 2>/dev/null || exit 0
CTX="$CTXDIR/$SID"

basename "$FP" >> "$CTX" 2>/dev/null
# keep only the most recent touches
tail -40 "$CTX" > "$CTX.tmp" 2>/dev/null && mv -f "$CTX.tmp" "$CTX" 2>/dev/null
exit 0
