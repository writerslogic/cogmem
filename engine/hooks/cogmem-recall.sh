#!/bin/bash
# UserPromptSubmit hook — Layer-B semantic recall.
# Queries the warm recall daemon for rules relevant to the current prompt and
# injects the top matches as additionalContext. Strictly fail-open: any error,
# timeout, or cold daemon results in NO injection (and a background daemon spawn),
# never a blocked or broken prompt.
set -uo pipefail

# Resolve cogmem's home from COGMEM_HOME, else from this hook's own location
# ($COGMEM_HOME/hooks/), so a non-default install operates on its own vault.
COGMEM_HOME="${COGMEM_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty' 2>/dev/null)
CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null)
SESSION=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null)
[[ -z "$PROMPT" ]] && exit 0

# Resolve a Python that can import cogmem: the interpreter `cogmem init` recorded
# (pip installs), else the clone venv, else system python3. Invocations go through
# `-m cogmem.<module>`, so this works whether cogmem was cloned or pip-installed.
PY="$(cat "$COGMEM_HOME/.cogmem-python" 2>/dev/null)"
[[ -x "$PY" ]] || PY="$COGMEM_HOME/engine/.venv/bin/python3"
[[ -x "$PY" ]] || PY="python3"

# Detect scope (language) from the project so language-scoped rules can match.
SCOPE="universal"
for d in "$CWD" "$CWD"/*/; do
    [[ -f "${d}Cargo.toml" ]] && SCOPE="rust"
    [[ -f "${d}Package.swift" ]] && SCOPE="swift"
    [[ -f "${d}package.json" ]] && SCOPE="web"
done

# Fuse in what the session is actively editing, so recall fires on the work and
# not only the prompt wording (e.g. touching a crypto file surfaces a crypto rule).
QUERY="$PROMPT"
CTXFILE="$COGMEM_HOME/vault/.ctx/$SESSION"
if [[ -n "$SESSION" && -f "$CTXFILE" ]]; then
    FILES=$(tail -12 "$CTXFILE" 2>/dev/null | sort -u | tr '\n' ' ')
    [[ -n "$FILES" ]] && QUERY="$PROMPT [working on: $FILES]"
fi

# Query the daemon (fast path). cogmem.recall exits 1 if the daemon is unreachable.
RESULT=$("$PY" -m cogmem.recall "$QUERY" --scope "$SCOPE" --k 3 2>/dev/null)
STATUS=$?

if [[ $STATUS -eq 1 ]]; then
    # Daemon cold/down: spawn it detached so the NEXT prompt is fast. Inject nothing now.
    if [[ ! -S "$COGMEM_HOME/recall.sock" ]]; then
        nohup "$PY" -m cogmem.daemon >/dev/null 2>&1 &
    fi
    exit 0
fi

[[ -z "$RESULT" ]] && exit 0

# Log which rules were injected for this session so the Stop-time feedback loop
# can judge whether they actually helped.
if [[ -n "$SESSION" ]]; then
    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "$RESULT" | jq -c --arg s "$SESSION" --arg ts "$TS" \
        '{session:$s, ts:$ts, ids:[.[].id]}' >> "$COGMEM_HOME/vault/.recall-log.jsonl" 2>/dev/null
fi

# Format the matches into a compact context block.
CONTEXT=$(echo "$RESULT" | jq -r '
    "COGMEM recall (relevant past lessons):\n" +
    ([.[] | "- \(.text)"] | join("\n"))
' 2>/dev/null)
[[ -z "$CONTEXT" ]] && exit 0

jq -n --arg ctx "$CONTEXT" '{
  hookSpecificOutput: {
    hookEventName: "UserPromptSubmit",
    additionalContext: $ctx
  }
}'
exit 0
