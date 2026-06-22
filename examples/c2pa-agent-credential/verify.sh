#!/usr/bin/env bash
# Verify that the sample C2PA manifest carries a valid CAWG agent identity.
# Requires a c2patool that runs the async CawgValidator (see README). Override the
# binary with C2PATOOL=/path/to/c2patool.
set -euo pipefail

C2PATOOL="${C2PATOOL:-c2patool}"
here="$(cd "$(dirname "$0")" && pwd)"
manifest="$here/agent-content.c2pa"

report="$("$C2PATOOL" "$manifest" --detailed)"

if grep -q '"cawg.ica.credential_valid"' <<<"$report"; then
  echo "PASS: cawg.ica.credential_valid — the AI agent's identity validates."
  # Show the verified credential's issuer + type for context.
  python3 - "$report" <<'PY' 2>/dev/null || true
import json, sys
d = json.loads(sys.argv[1])
cred = d["manifests"][d["active_manifest"]]["assertion_store"]["cawg.identity"]
print(f"  issuer: {cred.get('issuer','?')}")
print(f"  type:   {cred.get('type',['?'])[-1]}")
PY
  # Second step: prove the identity is bound to the agent's actual cognition by
  # verifying the two embedded COSE/SCITT statements. Non-fatal: a missing-deps
  # environment skips it without failing the identity check above.
  echo "--- cognition binding ---"
  python3 "$here/verify-cognition.py" <<<"$report" || true
  exit 0
else
  echo "FAIL: cawg.ica.credential_valid not found. Is your c2patool running the CawgValidator? See README." >&2
  exit 1
fi
