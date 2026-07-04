#!/bin/sh
# install.sh — Install the peep binary from GitHub Releases.
# Usage: curl -sSfL https://raw.githubusercontent.com/thexsa/peep/main/install.sh | sh
#   or:  sh install.sh

set -e

REPO="thexsa/peep"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Use printf for POSIX portability (echo behavior varies across shells).
info()  { printf "  %s\n" "$@"; }
warn()  { printf "⚠ %s\n" "$@" >&2; }
error() { printf "✗ %s\n" "$@" >&2; exit 1; }

# Clean up temp directory on exit.
cleanup() {
  if [ -n "${TMPDIR_INSTALL:-}" ] && [ -d "${TMPDIR_INSTALL}" ]; then
    rm -rf "${TMPDIR_INSTALL}"
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------

detect_os() {
  case "$(uname -s)" in
    Darwin) OS="darwin" ;;
    Linux)  OS="linux"  ;;
    CYGWIN*|MINGW*|MSYS*)
      error "Windows is not supported by this installer. Use 'go install' or download from GitHub Releases:
  https://github.com/${REPO}/releases" ;;
    *)
      error "Unsupported operating system: $(uname -s). Use 'go install' or download from GitHub Releases:
  https://github.com/${REPO}/releases" ;;
  esac
}

# ---------------------------------------------------------------------------
# Detect Architecture
# ---------------------------------------------------------------------------

detect_arch() {
  case "$(uname -m)" in
    x86_64)          ARCH="amd64"   ;;
    aarch64|arm64)   ARCH="arm64"   ;;
    ppc64le)         ARCH="ppc64le" ;;
    *)
      error "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ---------------------------------------------------------------------------
# Determine latest release version
# ---------------------------------------------------------------------------

get_latest_version() {
  VERSION=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"([^"]+)".*/\1/')

  if [ -z "${VERSION}" ]; then
    error "Could not determine the latest version. Check your internet connection or visit:
  https://github.com/${REPO}/releases"
  fi
}

# ---------------------------------------------------------------------------
# Ask user for install location (interactive)
# ---------------------------------------------------------------------------

choose_install_dir() {
  printf "\nWhere would you like to install peep?\n"
  printf "  1) /usr/local/bin  (may require sudo)\n"
  printf "  2) ~/.local/bin\n"
  printf "  3) Custom path\n"
  printf "Choose [1/2/3] (default: 1): "
  read -r choice

  case "${choice}" in
    2)
      INSTALL_DIR="${HOME}/.local/bin"
      NEED_SUDO="false"
      # Create directory if it doesn't exist.
      if [ ! -d "${INSTALL_DIR}" ]; then
        mkdir -p "${INSTALL_DIR}"
        info "Created ${INSTALL_DIR}"
      fi
      ;;
    3)
      printf "Enter install path: "
      read -r custom_path
      if [ -z "${custom_path}" ]; then
        error "No path provided."
      fi
      INSTALL_DIR="${custom_path}"
      NEED_SUDO="false"
      # Create directory if it doesn't exist.
      if [ ! -d "${INSTALL_DIR}" ]; then
        mkdir -p "${INSTALL_DIR}" 2>/dev/null || {
          error "Could not create directory: ${INSTALL_DIR}"
        }
        info "Created ${INSTALL_DIR}"
      fi
      ;;
    # Default to option 1 (empty input or explicit "1").
    *)
      INSTALL_DIR="/usr/local/bin"
      # Use sudo if not already root.
      if [ "$(id -u)" -ne 0 ]; then
        NEED_SUDO="true"
      else
        NEED_SUDO="false"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Verify checksum
# ---------------------------------------------------------------------------

verify_checksum() {
  binary_path="$1"
  checksums_path="$2"

  if [ ! -f "${checksums_path}" ]; then
    warn "Checksum file unavailable — skipping verification."
    return 0
  fi

  # Extract expected checksum for our binary.
  binary_name="$(basename "${binary_path}")"
  expected=$(grep "${binary_name}" "${checksums_path}" | awk '{print $1}')

  if [ -z "${expected}" ]; then
    warn "No checksum entry found for ${binary_name} — skipping verification."
    return 0
  fi

  # Compute actual checksum (sha256sum on Linux, shasum on macOS).
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${binary_path}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${binary_path}" | awk '{print $1}')
  else
    warn "Neither sha256sum nor shasum found — skipping checksum verification."
    return 0
  fi

  if [ "${actual}" != "${expected}" ]; then
    error "Checksum verification failed!
  Expected: ${expected}
  Got:      ${actual}
  The downloaded binary may be corrupted or tampered with."
  fi

  info "Checksum verified ✓"
}

# ---------------------------------------------------------------------------
# Check if a directory is in PATH
# ---------------------------------------------------------------------------

in_path() {
  case ":${PATH}:" in
    *":$1:"*) return 0 ;;
    *)        return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  printf "Installing peep...\n\n"

  detect_os
  detect_arch
  get_latest_version

  info "OS:      ${OS}"
  info "Arch:    ${ARCH}"
  info "Version: ${VERSION}"

  # Construct download URLs.
  BINARY_NAME="peep-${OS}-${ARCH}"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums-sha256.txt"

  # Ask user where to install.
  choose_install_dir

  # Create a temp directory for downloads.
  TMPDIR_INSTALL=$(mktemp -d)

  # Download the binary.
  printf "\nDownloading %s...\n" "${BINARY_NAME}"
  curl -sSfL -o "${TMPDIR_INSTALL}/${BINARY_NAME}" "${DOWNLOAD_URL}" || \
    error "Failed to download binary from:
  ${DOWNLOAD_URL}"

  # Download checksums (non-fatal if unavailable).
  curl -sSfL -o "${TMPDIR_INSTALL}/checksums-sha256.txt" "${CHECKSUMS_URL}" 2>/dev/null || true

  # Verify checksum.
  verify_checksum "${TMPDIR_INSTALL}/${BINARY_NAME}" "${TMPDIR_INSTALL}/checksums-sha256.txt"

  # Make binary executable.
  chmod +x "${TMPDIR_INSTALL}/${BINARY_NAME}"

  # Move binary to install location.
  if [ "${NEED_SUDO}" = "true" ]; then
    sudo mv "${TMPDIR_INSTALL}/${BINARY_NAME}" "${INSTALL_DIR}/peep"
  else
    mv "${TMPDIR_INSTALL}/${BINARY_NAME}" "${INSTALL_DIR}/peep"
  fi

  # Success message.
  printf "\n✓ peep %s installed to %s/peep\n" "${VERSION}" "${INSTALL_DIR}"
  printf "\nGet started:\n"
  printf "  peep google.com\n"
  printf "  peep --examples\n"
  printf "  peep --help\n"

  # Warn if install directory is not in PATH.
  if ! in_path "${INSTALL_DIR}"; then
    printf "\n⚠ %s is not in your PATH. Add it with:\n" "${INSTALL_DIR}"
    printf "  export PATH=\"%s:\$PATH\"\n" "${INSTALL_DIR}"
  fi
}

main
