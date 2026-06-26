#!/bin/bash
# PreToolUse(Bash) hook — intercepts mistakes the assistant has made before.
# Matches the proposed command against failure-mode tripwires: a "block" hit denies
# the command (the model sees the lesson and corrects); a "warn" hit injects the
# lesson as context but lets the command run. Strictly fail-open: any error allows.
set -uo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

ENGINE="$HOME/.claude/cogmem/engine"
VENV_PY="$ENGINE/.venv/bin/python3"
[[ -x "$VENV_PY" ]] || exit 0

HITS=$("$VENV_PY" "$ENGINE/guard.py" "$CMD" 2>/dev/null)
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
