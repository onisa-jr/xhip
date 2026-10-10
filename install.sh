#!/usr/bin/env bash
set -euo pipefail

# Expected GPG signing key fingerprint
EXPECTED_FINGERPRINT="4ECCF977D6621D4494D7D7FA59517E954D3A313F"
KEY_URL="https://onisa-jr.github.io/xhip/xhip-archive-keyring.asc"
REPO_URL="https://onisa-jr.github.io/xhip"
KEYRING_PATH="/etc/apt/keyrings/xhip.gpg"
SOURCES_PATH="/etc/apt/sources.list.d/xhip.list"

echo "==> Xhip Installer"

# 1. Require root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This installer must be run as root (use sudo bash install.sh)." >&2
    exit 1
fi

# 2. Check architecture (amd64)
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
fi

if [ "$ARCH" != "amd64" ]; then
    echo "Error: Unsupported architecture '${ARCH}'. Xhip currently supports 'amd64' only." >&2
    exit 1
fi

# 3. Check Debian / Ubuntu
if [ ! -f /etc/os-release ]; then
    echo "Error: Cannot detect operating system (/etc/os-release not found)." >&2
    exit 1
fi

# shellcheck source=/dev/null
. /etc/os-release

IS_DEBIAN_OR_UBUNTU=0
case "${ID:-}" in
    debian|ubuntu)
        IS_DEBIAN_OR_UBUNTU=1
        ;;
    *)
        for id_like in ${ID_LIKE:-}; do
            if [ "$id_like" = "debian" ] || [ "$id_like" = "ubuntu" ]; then
                IS_DEBIAN_OR_UBUNTU=1
                break
            fi
        done
        ;;
esac

if [ "$IS_DEBIAN_OR_UBUNTU" -ne 1 ]; then
    echo "Error: Unsupported operating system '${NAME:-unknown}'. Xhip installer requires Debian or Ubuntu." >&2
    exit 1
fi

# 4. Install prerequisites if missing
MISSING_PKGS=()
for cmd_pkg in "curl:curl" "gpg:gnupg"; do
    cmd="${cmd_pkg%%:*}"
    pkg="${cmd_pkg##*:}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "==> Installing required tools: ${MISSING_PKGS[*]}..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends "${MISSING_PKGS[@]}"
fi

# 5. Fetch and verify GPG key
echo "==> Fetching and verifying APT signing key..."
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

TEMP_ASC="${TEMP_DIR}/xhip-key.asc"
curl -fsSL --proto '=https' --tlsv1.2 "${KEY_URL}" -o "${TEMP_ASC}"

# Verify fingerprint
ACTUAL_FINGERPRINT="$(gpg --show-keys --with-colons "${TEMP_ASC}" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"

if [ -z "$ACTUAL_FINGERPRINT" ]; then
    echo "Error: Failed to extract GPG fingerprint from downloaded key." >&2
    exit 1
fi

# Case-insensitive comparison
if [ "${ACTUAL_FINGERPRINT^^}" != "${EXPECTED_FINGERPRINT^^}" ]; then
    echo "SECURITY ERROR: GPG key fingerprint mismatch!" >&2
    echo "  Expected: ${EXPECTED_FINGERPRINT}" >&2
    echo "  Got:      ${ACTUAL_FINGERPRINT}" >&2
    exit 1
fi

echo "==> GPG key verified successfully (${ACTUAL_FINGERPRINT})."

# 6. Install keyring securely
mkdir -p /etc/apt/keyrings
chmod 755 /etc/apt/keyrings

# Dearmor to binary GPG format at /etc/apt/keyrings/xhip.gpg
gpg --dearmor < "${TEMP_ASC}" > "${TEMP_DIR}/xhip.gpg"
install -m 644 "${TEMP_DIR}/xhip.gpg" "${KEYRING_PATH}"

# 7. Configure APT repository list
echo "==> Configuring APT repository at ${SOURCES_PATH}..."
cat <<EOF > "${SOURCES_PATH}"
deb [arch=amd64 signed-by=${KEYRING_PATH}] ${REPO_URL} stable main
EOF
chmod 644 "${SOURCES_PATH}"

# 8. Update and install Xhip
echo "==> Updating package lists and installing xhip..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -o Dir::Etc::sourcelist="sources.list.d/xhip.list" \
               -o Dir::Etc::sourceparts="-" \
               -o APT::Get::List-Cleanup="0" -qq || apt-get update -qq

apt-get install -y -qq xhip

echo ""
echo "==> Success! Xhip has been installed to $(command -v xhip)."
xhip --version
