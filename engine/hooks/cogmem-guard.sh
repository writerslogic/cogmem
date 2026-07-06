#!/bin/bash
# PreToolUse(Bash) hook — intercepts mistakes the assistant has made before.
# Matches the proposed command against failure-mode tripwires: a "block" hit denies
# the command (the model sees the lesson and corrects); a "warn" hit injects the
# lesson as context but lets the command run. Strictly fail-open: any error allows.
set -uo pipefail

# Resolve cogmem's home from COGMEM_HOME, else from this hook's own location
# ($COGMEM_HOME/hooks/), so a non-default install operates on its own vault.
COGMEM_HOME="${COGMEM_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

# Resolve a Python that can import cogmem (see cogmem-recall.sh for the rationale).
PY="$(cat "$COGMEM_HOME/.cogmem-python" 2>/dev/null)"
[[ -x "$PY" ]] || PY="$COGMEM_HOME/engine/.venv/bin/python3"
[[ -x "$PY" ]] || PY="python3"

HITS=$("$PY" -m cogmem.guard "$CMD" 2>/dev/null)
[[ -z "$HITS" || "$HITS" == "[]" ]] && exit 0

BLOCK=$(echo "$HITS" | jq -r 'map(select(.guard=="block")) | length' 2>/dev/null)
LESSONS=$(echo "$HITS" | jq -r '[.[].lesson] | join(" | ")' 2>/dev/null)
[[ -z "$LESSONS" ]] && exit 0

if [[ "${BLOCK:-0}" -gt 0 ]]; then
    jq -n --arg r "COGMEM guard blocked this (you have made this mistake before): $LESSONS" '{
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: $r
      }
    }'
else
    jq -n --arg c "COGMEM guard (you have hit this before): $LESSONS" '{
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        additionalContext: $c
      }
    }'
fi
exit 0
