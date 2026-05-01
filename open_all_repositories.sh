#!/usr/bin/env bash
set -u

REPO_FILE="${1:-repositories.json}"

if [ ! -f "$REPO_FILE" ]; then
  echo "Error: file not found -> $REPO_FILE"
  exit 1
fi

if ! command -v open >/dev/null 2>&1; then
  echo "Error: 'open' command not found (this script is for macOS)."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required to read $REPO_FILE."
  exit 1
fi

python3 - "$REPO_FILE" <<'PY' | while IFS= read -r url; do
import json
import sys

repo_file = sys.argv[1]
with open(repo_file, "r", encoding="utf-8") as f:
    data = json.load(f)

if not isinstance(data, list):
    raise SystemExit("Error: repositories.json must be a JSON array of URLs.")

for item in data:
    if isinstance(item, str):
        url = item.strip()
        if url:
            print(url)
PY
  echo "Opening: $url"
  open "$url"
done

echo "Done opening URLs from $REPO_FILE"
