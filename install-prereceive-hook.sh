#!/usr/bin/env bash
set -euo pipefail

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
HOOK_PATH="$HOOK_DIR/pre-receive"

if [ -e "$HOOK_PATH" ]; then
  echo "Error: $HOOK_PATH already exists. Move or remove the existing hook to continue." >&2
  exit 1
fi

cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
# Pre-receive hook to scan pushed commits with Kingfisher
set -euo pipefail

if ! command -v kingfisher >/dev/null 2>&1; then
  echo "kingfisher not found in PATH" >&2
  exit 1
fi

while read -r oldrev newrev refname; do
  if [ "$oldrev" = "0000000000000000000000000000000000000000" ]; then
    git diff-tree --name-only -r "$newrev" -z |
      xargs -0 --no-run-if-empty kingfisher scan --no-update-check
  else
    git diff-tree --no-commit-id --name-only -r "$oldrev" "$newrev" -z |
      xargs -0 --no-run-if-empty kingfisher scan --no-update-check
  fi
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "Kingfisher detected secrets in push. Push rejected." >&2
    exit "$status"
  fi
done
HOOK

chmod +x "$HOOK_PATH"
echo "Pre-receive hook installed to $HOOK_PATH"
