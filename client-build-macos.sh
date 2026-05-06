#!/usr/bin/env bash
# =============================================================================
# havoc_macos_setup.sh
# Havoc C2 Framework - macOS Apple Silicon (arm64) build setup
# Fixes:
#   1. Qt5 cmake symlink path resolution bug (mkspecs/plugins relative to prefix)
#   2. toml/exception.hpp strerror_r POSIX vs GNU return type mismatch
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log_info() { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok() { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
log_err() { echo -e "${RED}[-]${RESET} $*"; }
log_section() { echo -e "\n${BOLD}${CYAN}==> $*${RESET}"; }

# =============================================================================
# Preflight checks
# =============================================================================

log_section "Preflight checks"

# Must be macOS
if [[ "$(uname)" != "Darwin" ]]; then
  log_err "This script is for macOS only. Detected: $(uname)"
  exit 1
fi

# Must be arm64
ARCH="$(uname -m)"
if [[ "$ARCH" != "arm64" ]]; then
  log_warn "Expected arm64 (Apple Silicon), detected: $ARCH"
  log_warn "Script may still work on Intel but is untested."
fi

log_ok "macOS arm64 detected"

# Must be run from the Havoc repo root
if [[ ! -f "makefile" ]] || [[ ! -d "client" ]]; then
  log_err "Run this script from the root of the Havoc repository."
  log_err "Expected: ./makefile and ./client/ to exist."
  exit 1
fi

log_ok "Havoc repository root confirmed"

# Homebrew
if ! command -v brew &>/dev/null; then
  log_err "Homebrew is not installed. Install it from https://brew.sh and re-run."
  exit 1
fi

HOMEBREW_PREFIX="$(brew --prefix)"
log_ok "Homebrew prefix: ${HOMEBREW_PREFIX}"

# =============================================================================
# Install dependencies
# =============================================================================

log_section "Installing Homebrew dependencies"

PACKAGES=(
  "cmake"
  "qt@5"
  "spdlog"
  "golang"
  "python@3.10"
)

for pkg in "${PACKAGES[@]}"; do
  if brew list "$pkg" &>/dev/null; then
    log_ok "${pkg} already installed"
  else
    log_info "Installing ${pkg}..."
    brew install "$pkg"
    log_ok "${pkg} installed"
  fi
done

# =============================================================================
# Qt5 setup — fix cmake prefix path resolution
# =============================================================================

log_section "Configuring Qt5"

QT5_CELLAR="$(brew --prefix qt@5)"

if [[ ! -d "$QT5_CELLAR" ]]; then
  log_err "qt@5 cellar not found at: ${QT5_CELLAR}"
  log_err "Try: brew reinstall qt@5"
  exit 1
fi

log_info "Qt5 cellar: ${QT5_CELLAR}"

# Unlink any existing qt symlinks to avoid conflicts, then relink qt@5
log_info "Relinking qt@5..."
brew unlink qt@5 &>/dev/null || true
brew link --overwrite qt@5
log_ok "qt@5 linked"

# The core issue: Homebrew symlinks Qt5 cmake files into $HOMEBREW_PREFIX/lib/cmake/
# but Qt's cmake files resolve sibling paths (mkspecs, plugins) relative to the
# cmake file's detected install prefix, which becomes $HOMEBREW_PREFIX instead of
# the actual Qt5 cellar. Setting CMAKE_PREFIX_PATH to the cellar makes all internal
# Qt cmake path resolution self-consistent.
export CMAKE_PREFIX_PATH="${QT5_CELLAR}"
export Qt5_DIR="${QT5_CELLAR}/lib/cmake/Qt5"

log_ok "CMAKE_PREFIX_PATH set to: ${CMAKE_PREFIX_PATH}"
log_ok "Qt5_DIR set to: ${Qt5_DIR}"

# Remove stale mkspecs symlink if created by previous workaround attempts
STALE_MKSPECS="${HOMEBREW_PREFIX}/mkspecs"
if [[ -L "$STALE_MKSPECS" ]]; then
  log_warn "Removing stale mkspecs symlink: ${STALE_MKSPECS}"
  rm "$STALE_MKSPECS"
  log_ok "Removed"
fi

# Verify the actual mkspecs dir exists inside the cellar
if [[ ! -d "${QT5_CELLAR}/mkspecs" ]]; then
  log_err "mkspecs directory not found inside Qt5 cellar: ${QT5_CELLAR}/mkspecs"
  log_err "Try: brew reinstall qt@5"
  exit 1
fi

log_ok "Qt5 mkspecs found at: ${QT5_CELLAR}/mkspecs"

# =============================================================================
# Patch toml/exception.hpp — strerror_r POSIX vs GNU return type
# =============================================================================
# On macOS, strerror_r follows the POSIX XSI standard: returns int (0 on success).
# On Linux (glibc), strerror_r uses the GNU extension: returns char*.
# The bundled toml library assumes the GNU signature unconditionally, which causes
# a type error on Apple Clang: cannot initialize 'const char*' with 'int'.
# We patch with __APPLE__ guards to preserve Linux behaviour unchanged.
# =============================================================================

log_section "Patching client/external/toml/toml/exception.hpp"

EXCEPTION_HPP="client/external/toml/toml/exception.hpp"

if [[ ! -f "$EXCEPTION_HPP" ]]; then
  log_err "File not found: ${EXCEPTION_HPP}"
  log_err "Ensure you are in the Havoc repo root and submodules are initialised."
  exit 1
fi

# Check if the patch is already applied
if grep -q "__APPLE__" "$EXCEPTION_HPP"; then
  log_ok "exception.hpp already patched — skipping"
else
  log_info "Applying __APPLE__ guard to strerror_r call..."

  # The original line (GNU extension assumes char* return):
  #   const char* result = strerror_r(errnum, buf.data(), bufsize);
  #
  # Patched version:
  #   #ifdef __APPLE__
  #       // POSIX XSI strerror_r returns int; result is written into buf
  #       strerror_r(errnum, buf.data(), bufsize);
  #       const char* result = buf.data();
  #   #else
  #       // GNU strerror_r returns char* (may or may not use buf)
  #       const char* result = strerror_r(errnum, buf.data(), bufsize);
  #   #endif

  # Use perl for reliable cross-platform in-place substitution
  perl -i -0pe \
    's|(\s*)(const char\* result = strerror_r\(errnum, buf\.data\(\), bufsize\);)|\
#ifdef __APPLE__\n\
        \/\/ POSIX XSI: strerror_r returns int, result is written into buf\n\
        strerror_r(errnum, buf.data(), bufsize);\n\
        const char* result = buf.data();\n\
#else\n\
        \/\/ GNU extension: strerror_r returns char* directly\n\
        ${2}\n\
#endif|' \
    "$EXCEPTION_HPP"

  # Verify the patch landed
  if grep -q "__APPLE__" "$EXCEPTION_HPP"; then
    log_ok "Patch applied successfully"
  else
    log_err "Patch failed — strerror_r line may have changed in this version"
    log_err "Manually edit ${EXCEPTION_HPP} around line 44:"
    log_err '  Replace: const char* result = strerror_r(errnum, buf.data(), bufsize);'
    log_err '  With the #ifdef __APPLE__ block described in the README'
    exit 1
  fi
fi

# Show the patched region for confirmation
log_info "Patched region in ${EXCEPTION_HPP}:"
grep -n -A4 -B1 "__APPLE__" "$EXCEPTION_HPP" | sed 's/^/    /'

# =============================================================================
# Clean stale build artifacts
# =============================================================================

log_section "Cleaning stale build directory"

if [[ -d "client/Build" ]]; then
  log_info "Removing client/Build..."
  rm -rf client/Build
  log_ok "Cleaned"
else
  log_ok "client/Build does not exist — nothing to clean"
fi

# =============================================================================
# Build
# =============================================================================

log_section "Building Havoc client"

log_info "CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}"
log_info "Qt5_DIR           = ${Qt5_DIR}"
log_info "Running: make client-build"
echo ""

CMAKE_PREFIX_PATH="${QT5_CELLAR}" Qt5_DIR="${QT5_CELLAR}/lib/cmake/Qt5" make client-build

BUILD_EXIT=$?

echo ""
if [[ $BUILD_EXIT -eq 0 ]]; then
  log_ok "Build succeeded."
  log_ok "Run the client with: ./havoc client"
else
  log_err "Build failed with exit code ${BUILD_EXIT}."
  log_err "Check the output above for the next error to resolve."
  exit $BUILD_EXIT
fi
