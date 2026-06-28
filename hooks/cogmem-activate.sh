#!/bin/bash
# SessionStart hook — injects promoted Layer-A rules (always-load knowledge the
# user approved) scoped to the current project/language, and warms the recall
# daemon so the first prompt's Layer-B lookup is fast. Strictly fail-open.
set -uo pipefail

INPUT=$(cat)
SOURCE=$(echo "$INPUT" | jq -r '.source // empty')
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

# Startup only, to avoid repeating on every resume.
[[ "$SOURCE" != "startup" ]] && exit 0

ENGINE="$HOME/.claude/cogmem/engine"
LEARNED="$HOME/.claude/cogmem/vault/learned"

# Warm the recall daemon in the background if it is not already up.
VENV_PY="$ENGINE/.venv/bin/python3"
if [[ -x "$VENV_PY" && ! -S "$ENGINE/recall.sock" ]]; then
    nohup "$VENV_PY" "$ENGINE/daemon.py" >/dev/null 2>&1 &
fi

# Detect scope (language) from the project.
SCOPE=""
for d in "$CWD" "$CWD"/*/; do
    [[ -f "${d}Cargo.toml" ]] && SCOPE="rust"
    [[ -f "${d}Package.swift" ]] && SCOPE="swift"
    [[ -f "${d}package.json" ]] && SCOPE="web"
done

# The user model (a synthesis of episodes + rules) is the always-loaded "who is
# David" framing; universal.md carries specific cross-cutting guardrails. Both load:
# the model gives principles, the rules give precise do/don'ts.
USERMODEL=""
USERMODEL_FILE="$HOME/.claude/cogmem/vault/user-model.md"
[[ -f "$USERMODEL_FILE" ]] && USERMODEL=$(grep -v '^<!--' "$USERMODEL_FILE")

FILES=("$LEARNED/universal.md")
[[ -n "$SCOPE" ]] && FILES+=("$LEARNED/$SCOPE.md")
PROJECT=$(basename "$CWD" 2>/dev/null | tr '[:upper:]' '[:lower:]')
[[ -n "$PROJECT" && "$PROJECT" != "/" && "$PROJECT" != "$SCOPE" ]] && FILES+=("$LEARNED/$PROJECT.md")

RULES=""
for f in "${FILES[@]}"; do
    [[ -f "$f" ]] || continue
    # Pull bullet lines, strip the trailing <!-- id --> provenance comment.
    while IFS= read -r line; do
        clean=$(echo "$line" | sed -E 's/^- //; s/[[:space:]]*<!--[^>]*-->[[:space:]]*$//')
        [[ -n "$clean" ]] && RULES="${RULES}\n- ${clean}"
    done < <(grep -E '^- ' "$f" 2>/dev/null)
done

# Pending Layer-A approvals: push them to the user at session start instead of
# making him remember to run a command. Rate-limited to once / 24h so it is not
# naggy: if he ignores them they resurface tomorrow until acted on.
PENDING_DIR="$HOME/.claude/cogmem/vault/pending"
STAMP="$HOME/.claude/cogmem/vault/.approval-surfaced"
PENDING_MSG=""
if compgen -G "$PENDING_DIR/*.md" >/dev/null 2>&1; then
    SURFACE=true
    if [[ -f "$STAMP" ]]; then
        AGE=$(( $(date +%s) - $(stat -f %m "$STAMP" 2>/dev/null || stat -c %Y "$STAMP" 2>/dev/null || echo 0) ))
        [[ $AGE -lt 86400 ]] && SURFACE=false
    fi
    if $SURFACE; then
        N=$(ls "$PENDING_DIR"/*.md | wc -l | tr -d ' ')
        PENDING_MSG="\n\nCOGMEM: ${N} learned rule(s) await David's approval to become always-loaded. Early in this session, briefly tell him and offer to promote or reject each. Apply his choice with: ~/.claude/cogmem/cogmem review promote|reject <id>. Pending:"
        for f in "$PENDING_DIR"/*.md; do
            id=$(grep -m1 '^id:' "$f" | sed 's/^id:[[:space:]]*//')
            rule=$(awk '/^---$/{c++; next} c>=2 && NF' "$f" | tr '\n' ' ' | cut -c1-180)
            PENDING_MSG="${PENDING_MSG}\n- ${id}: ${rule}"
        done
        touch "$STAMP"
    fi
fi

# Pre-flight self-check: the assistant's own known failure modes for this scope.
SELFCHECK=""
PROJSTATE=""
STALL=""
if [[ -x "$VENV_PY" ]]; then
    SELFCHECK=$("$VENV_PY" "$ENGINE/selfmodel.py" --activate universal "$SCOPE" "$PROJECT" 2>/dev/null)
    [[ -n "$PROJECT" ]] && PROJSTATE=$("$VENV_PY" "$ENGINE/projectstate.py" --activate "$PROJECT" 2>/dev/null)
    [[ -n "$PROJECT" ]] && STALL=$("$VENV_PY" "$ENGINE/narrative.py" --alert "$PROJECT" 2>/dev/null)
fi

CONTEXT=""
[[ -n "$USERMODEL" ]] && CONTEXT="$USERMODEL"
[[ -n "$PROJSTATE" ]] && CONTEXT="${CONTEXT:+$CONTEXT$'\n\n'}COGMEM project state (where this work stands):"$'\n'"$PROJSTATE"
[[ -n "$STALL" ]] && CONTEXT="${CONTEXT:+$CONTEXT$'\n\n'}$STALL"
[[ -n "$RULES" ]] && CONTEXT="${CONTEXT:+$CONTEXT$'\n\n'}COGMEM learned rules (apply these):${RULES}"
[[ -n "$SELFCHECK" ]] && CONTEXT="${CONTEXT:+$CONTEXT$'\n\n'}$SELFCHECK"

# Memory protocol: make memory a tool used DURING the task, not just context at t=0.
PROTOCOL="COGMEM protocol: before non-trivial work run \`cogmem recall \"<what you are about to do>\"\` to surface past lessons; the moment you make a decision or hit a finding worth keeping, run \`cogmem note \"<it>\"\` so it folds into project state."
CONTEXT="${CONTEXT:+$CONTEXT$'\n\n'}$PROTOCOL"
[[ -n "$PENDING_MSG" ]] && CONTEXT="${CONTEXT}${PENDING_MSG}"
[[ -z "$CONTEXT" ]] && exit 0

jq -n --arg ctx "$(printf '%b' "$CONTEXT")" '{
  hookSpecificOutput: {
    hookEventName: "SessionStart",
    additionalContext: $ctx
  }
}'
exit 0
