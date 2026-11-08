#!/usr/bin/env bash
# prune.sh — example: audit, review, then delete stale function-call keys.
#
#   ./prune.sh <account.near> <path/to/full-access-credentials.json>
#
# Copy this, set KEEP to the contracts you still use, run it, read the dry run,
# then type "yes". Anything whose receiver_id is not in KEEP and which has not
# signed in --stale-days days is deleted. Full-access keys are never touched.
set -euo pipefail

ACCOUNT="${1:?usage: prune.sh <account.near> <credentials.json>}"
KEY_FILE="${2:?usage: prune.sh <account.near> <credentials.json>}"
KEEP="${KEEP:-}"                     # e.g. export KEEP="myapp.near,otherapp.near"
STALE_DAYS="${STALE_DAYS:-365}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$HERE/../near-keys.py"

ARGS=(clean "$ACCOUNT" --stale-days "$STALE_DAYS" --batch 50)
[[ -n "$KEEP" ]] && ARGS+=(--keep "$KEEP")

echo "=== DRY RUN — nothing is signed ==============================="
python3 "$TOOL" "${ARGS[@]}"
echo "=============================================================="
echo "signer: $KEY_FILE"
read -r -p "Delete those keys for real? type 'yes': " ans
[[ "$ans" == "yes" ]] || { echo "aborted, nothing sent."; exit 1; }

python3 "$TOOL" "${ARGS[@]}" --key-file "$KEY_FILE" --execute
