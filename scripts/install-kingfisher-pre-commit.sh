#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install-kingfisher-pre-commit.sh [--global] [--hooks-path PATH] [--uninstall]

Installs a Git pre-commit hook that runs Kingfisher.

Modes:
  (default)    Install in the current repo.
  --global     Install in the global Git hooks directory.
  --hooks-path Override hooks directory (repo only).
  --uninstall  Remove the installed hook.

USAGE
}

GLOBAL=false
UNINSTALL=false
HOOKS_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --global)
      GLOBAL=true
      shift
      ;;
    --hooks-path)
      HOOKS_PATH="$2"
      shift 2
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# ------------------------------
# Determine hooks directory
# ------------------------------
if $GLOBAL; then
  GLOBAL_PATH="$(git config --global core.hooksPath || true)"
  if [[ -z "$GLOBAL_PATH" ]]; then
    GLOBAL_PATH="$HOME/.git-hooks"
    git config --global core.hooksPath "$GLOBAL_PATH"
    echo "Configured global Git hooks at $GLOBAL_PATH"
  fi
  HOOKS_PATH="$GLOBAL_PATH"
else
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: must be run inside a Git repository unless using --global." >&2
    exit 1
  fi
  if [[ -z "$HOOKS_PATH" ]]; then
    HOOKS_PATH="$(git rev-parse --git-path hooks)"
  fi
fi

mkdir -p "$HOOKS_PATH"

PRE_COMMIT="$HOOKS_PATH/pre-commit"
LEGACY="$HOOKS_PATH/pre-commit.legacy.kingfisher"
KF_HOOK="$HOOKS_PATH/kingfisher-pre-commit"
MARKER="# Kingfisher pre-commit wrapper"

# ------------------------------
# Uninstall
# ------------------------------
uninstall() {
  if [[ -f "$PRE_COMMIT" ]] && grep -q "$MARKER" "$PRE_COMMIT"; then
    if [[ -f "$LEGACY" ]]; then
      mv "$LEGACY" "$PRE_COMMIT"
      chmod +x "$PRE_COMMIT"
      echo "Restored previous pre-commit hook from $LEGACY"
    else
      rm -f "$PRE_COMMIT"
      echo "Removed Kingfisher pre-commit wrapper."
    fi
  fi

  rm -f "$KF_HOOK" "$LEGACY"
  echo "Kingfisher pre-commit hook uninstalled."
}

if $UNINSTALL; then
  uninstall
  exit 0
fi

# ------------------------------
# Create Kingfisher hook
# ------------------------------
cat > "$KF_HOOK" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if ! command -v kingfisher >/dev/null 2>&1; then
  echo "Kingfisher is not on PATH; skipping scan." >&2
  exit 0
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

kingfisher scan . --staged --quiet --redact --only-valid --no-update-check
EOF
chmod +x "$KF_HOOK"

# ------------------------------
# Preserve existing hook only if it exists
# ------------------------------
if [[ -f "$PRE_COMMIT" ]]; then
  if ! grep -q "$MARKER" "$PRE_COMMIT"; then
    mv "$PRE_COMMIT" "$LEGACY"
    chmod +x "$LEGACY"
    echo "Existing pre-commit hook preserved at $LEGACY"
  fi
fi

# ------------------------------
# Install wrapper
# ------------------------------
cat > "$PRE_COMMIT" <<EOF
#!/usr/bin/env bash
$MARKER
set -euo pipefail

legacy_hook="$LEGACY"
kf_hook="$KF_HOOK"

if [[ -f "\$legacy_hook" && -x "\$legacy_hook" ]]; then
  "\$legacy_hook" "\$@"
fi

"\$kf_hook" "\$@"
EOF
chmod +x "$PRE_COMMIT"

echo "Kingfisher pre-commit hook installed at $PRE_COMMIT"
if [[ -f "$LEGACY" ]]; then
  echo "Existing hook will run first from $LEGACY"
fi
