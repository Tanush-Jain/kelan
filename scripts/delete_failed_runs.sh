#!/usr/bin/env bash
# Kelan Security — Delete Failed Actions Runs

set -euo pipefail

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
  echo "❌ Error: GitHub CLI ('gh') is not installed."
  echo "Please install it by running: sudo apt update && sudo apt install -y gh"
  exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
  echo "🔑 Please authenticate first by running: gh auth login"
  exit 1
fi

echo "🔍 Fetching failed workflow runs for Kelan-Security/kelan-core..."

# Fetch failed run IDs
RUN_IDS=$(gh run list \
  --status failure \
  --limit 1000 \
  --json databaseId \
  -q '.[].databaseId')

if [ -z "$RUN_IDS" ]; then
  echo "✅ No failed workflow runs found."
  exit 0
fi

COUNT=$(echo "$RUN_IDS" | wc -l)
echo "Found $COUNT failed run(s). Deleting..."

echo "$RUN_IDS" | while read -r run_id; do
  if [ -n "$run_id" ]; then
    echo "🗑 Deleting failed run $run_id..."
    gh api \
      -X DELETE \
      "repos/Kelan-Security/kelan-core/actions/runs/$run_id" --silent || echo "   ⚠️ Could not delete run $run_id"
  fi
done

echo "🎉 Completed deleting failed workflow runs!"
