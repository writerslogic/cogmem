#!/bin/bash
# Stop hook — fires the capture pipeline (acquire -> consolidate -> index) detached
# and logs session metadata to the cogmem stream. Strictly fail-open: any missing
# input or script is a no-op and never delays session end.
set -uo pipefail

INPUT=$(cat)
STOP_REASON=$(echo "$INPUT" | jq -r '.stop_reason // "end_turn"')
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')
TRANSCRIPT=$(echo "$INPUT" | jq -r '.transcript_path // empty')

[[ "$STOP_REASON" == "error" ]] && exit 0

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COGMEM_DIR="${COGMEM_HOME:-$HOME/.claude/cogmem}"
STREAM_FILE="$COGMEM_DIR/stream/events.jsonl"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PROJECT=$(basename "$CWD" 2>/dev/null || echo "unknown")
[[ -z "$PROJECT" ]] && PROJECT="unknown"

# Fire the capture pipeline detached so it never delays session end. The pipeline
# lives next to this hook, wherever cogmem was installed.
if [[ -n "$TRANSCRIPT" && -f "$HOOKS_DIR/cogmem-capture-pipeline.sh" ]]; then
    nohup "$HOOKS_DIR/cogmem-capture-pipeline.sh" "$TRANSCRIPT" "$PROJECT" >/dev/null 2>&1 &
fi

# Detect project languages (may be multiple) for the stream record.
LANGS=""
for d in "$CWD" "$CWD"/*/; do
    [[ -f "${d}Cargo.toml" ]] && LANGS="${LANGS}rust,"
    [[ -f "${d}pyproject.toml" || -f "${d}setup.py" || -f "${d}requirements.txt" ]] && LANGS="${LANGS}python,"
    [[ -f "${d}package.json" ]] && LANGS="${LANGS}typescript,"
    [[ -f "${d}Package.swift" ]] && LANGS="${LANGS}swift,"
done
LANGS=$(echo "$LANGS" | tr ',' '\n' | sort -u | paste -sd',' - | sed 's/^,//;s/,$//')
[[ -z "$LANGS" ]] && LANGS="unknown"

# Dedup: skip if the last stream event was for this project within 30 seconds.
SKIP_STREAM=false
if [[ -f "$STREAM_FILE" ]]; then
    LAST_LINE=$(tail -1 "$STREAM_FILE")
    LAST_TS=$(echo "$LAST_LINE" | jq -r '.timestamp // empty' 2>/dev/null)
    LAST_PROJ=$(echo "$LAST_LINE" | jq -r '.project // empty' 2>/dev/null)
    if [[ "$LAST_PROJ" == "$PROJECT" && -n "$LAST_TS" ]]; then
        LAST_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$LAST_TS" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DIFF=$((NOW_EPOCH - LAST_EPOCH))
        [[ $DIFF -lt 30 ]] && SKIP_STREAM=true
    fi
fi

if ! $SKIP_STREAM; then
    mkdir -p "$(dirname "$STREAM_FILE")"
    echo "{\"timestamp\":\"$TIMESTAMP\",\"type\":\"session_end\",\"project\":\"$PROJECT\",\"languages\":\"$LANGS\",\"content\":\"$STOP_REASON\"}" >> "$STREAM_FILE"
fi

exit 0
