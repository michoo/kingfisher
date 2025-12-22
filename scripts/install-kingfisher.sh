#!/usr/bin/env bash
set -euo pipefail

REPO="mongodb/kingfisher"
DEFAULT_INSTALL_DIR="$HOME/.local/bin"
TAG=""

usage() {
  cat <<'USAGE'
Usage: install-kingfisher.sh [OPTIONS] [INSTALL_DIR]

Downloads a Kingfisher release for Linux or macOS and installs the binary into
INSTALL_DIR (default: ~/.local/bin).

Requirements: curl, tar

Options:
  -t, --tag TAG  Install a specific release tag (e.g., v1.71.0).
USAGE
}

if [[ "${1-}" == "-h" || "${1-}" == "--help" ]]; then
  usage
  exit 0
fi

INSTALL_DIR="$DEFAULT_INSTALL_DIR"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tag)
      if [[ -z "${2-}" ]]; then
        echo "Error: --tag requires a value." >&2
        usage
        exit 1
      fi
      TAG="$2"
      shift 2
      ;;
    -*)
      echo "Error: Unknown option '$1'." >&2
      usage
      exit 1
      ;;
    *)
      if [[ "$INSTALL_DIR" != "$DEFAULT_INSTALL_DIR" ]]; then
        echo "Error: INSTALL_DIR specified multiple times." >&2
        usage
        exit 1
      fi
      INSTALL_DIR="$1"
      shift
      ;;
  esac
done

# deps
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required." >&2; exit 1; }
command -v tar  >/dev/null 2>&1 || { echo "Error: tar is required."  >&2; exit 1; }

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  platform="linux"  ;;
  Darwin) platform="darwin" ;;
  *) echo "Error: Unsupported OS '$OS' (Linux/macOS only)." >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)  arch_suffix="x64"   ;;
  arm64|aarch64) arch_suffix="arm64" ;;
  *) echo "Error: Unsupported arch '$ARCH' (x86_64/amd64, arm64/aarch64 only)." >&2; exit 1 ;;
esac

asset_name="kingfisher-${platform}-${arch_suffix}.tgz"
: "${asset_name:?internal error: asset_name not set}"  # guard for set -u

if [[ -n "$TAG" ]]; then
  dl_base="https://github.com/${REPO}/releases/download/${TAG}"
  release_label="release tag ${TAG}"
else
  dl_base="https://github.com/${REPO}/releases/latest/download"
  release_label="latest release"
fi

download_url="${dl_base}/${asset_name}"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

archive_path="$tmpdir/$asset_name"

echo "Downloading ${release_label}: ${asset_name} …"
# -f: fail on HTTP errors (e.g., 404 if asset missing)
if ! curl -fLsS "${download_url}" -o "$archive_path"; then
  echo "Error: Failed to download ${download_url}" >&2
  echo "Tip: Ensure the release includes '${asset_name}'." >&2
  exit 1
fi

echo "Extracting archive…"
tar -C "$tmpdir" -xzf "$archive_path"

if [[ ! -f "$tmpdir/kingfisher" ]]; then
  echo "Error: Extracted archive did not contain the 'kingfisher' binary." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmpdir/kingfisher" "$INSTALL_DIR/kingfisher"

printf 'Kingfisher installed to: %s/kingfisher\n\n' "$INSTALL_DIR"
if ! command -v kingfisher >/dev/null 2>&1; then
  printf 'Add this to your shell config if %s is not on PATH:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR"
fi
