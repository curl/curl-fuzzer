#!/usr/bin/env bash
#
# This script is called from google/oss-fuzz:projects/curl/Dockerfile to install necessary
# dependencies for building curl fuzz targets.
#
# Use it to compile and install all the dependencies

set -exo pipefail

SCRIPTDIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
REPO_ROOT=$(readlink -f "${SCRIPTDIR}/..")
PYTHON_VENV=${CURL_FUZZER_PYTHON_VENV:-/opt/curl-fuzzer-python}

# Work out if we need to install with sudo or not.
if [[ $(id -u) -eq 0 ]]
then
  # We are root, so we can install without sudo.
  echo "Running as root, no sudo required."
  export SUDO=""
else
  # We are not root, so we need to use sudo.
  echo "Running as non-root, using sudo."
  export SUDO="sudo"
fi

# Download dependencies for oss-fuzz
$SUDO apt-get -o Dpkg::Use-Pty=0 update
$SUDO apt-get -o Dpkg::Use-Pty=0 install -y --no-install-recommends \
  make \
  autoconf \
  automake \
  libtool \
  libgmp-dev \
  libssl-dev \
  zlib1g-dev \
  pkg-config \
  ca-certificates \
  wget \
  cmake \
  ninja-build \
  python3

# The OSS-Fuzz project image cannot use GitHub Actions to provision uv. Keep
# this version sourced from the same Renovate-managed pin as setup-uv.
UV_VERSION=$(sed -nE \
  's/^required-version = "==([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' \
  "${REPO_ROOT}/pyproject.toml")
if [[ ! ${UV_VERSION} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Could not determine one exact uv version from pyproject.toml." >&2
  exit 1
fi
wget --https-only --secure-protocol=TLSv1_2 --quiet --output-document=- \
  "https://astral.sh/uv/${UV_VERSION}/install.sh" | \
  $SUDO env UV_UNMANAGED_INSTALL=/usr/local/bin sh
uv --version

# Schema projection and target-aware corpus encoding use protobuf's descriptor
# APIs at build time. Keep the locked tooling environment isolated from the
# base image and populate it before OSS-Fuzz disables networking.
$SUDO env UV_PROJECT_ENVIRONMENT="${PYTHON_VENV}" \
  uv sync --locked --no-dev --no-editable --project "${REPO_ROOT}"
$SUDO "${PYTHON_VENV}/bin/check_python_protobuf"
