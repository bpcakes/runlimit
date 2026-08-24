#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISHABLE_CRATES=(
  "runlimit-core"
  "runlimit-memory"
  "runlimit-postgres"
  "runlimit-http"
  "runlimit-axum"
)
MSRV_TOOLCHAIN="${MSRV_TOOLCHAIN:-1.88.0}"
STABLE_TOOLCHAIN="${STABLE_TOOLCHAIN:-stable}"
CRATES_IO_USER_AGENT="runlimit-release-script/0.2 (https://github.com/bpcakes/runlimit)"

usage() {
  echo "usage: $0 <version>" >&2
  echo "example: $0 0.2.1" >&2
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

require_clean_worktree() {
  if [[ -n "$(git status --porcelain)" ]]; then
    die "working tree must be clean before preparing a release"
  fi
}

validate_version() {
  local version="$1"
  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    die "version must look like a Cargo semver version, got '$version'"
  fi
}

crate_manifest_version() {
  cargo pkgid -p "$1" | sed 's/.*#//'
}

require_manifest_versions() {
  local version="$1"
  local crate
  local manifest_version

  for crate in "${PUBLISHABLE_CRATES[@]}"; do
    manifest_version="$(crate_manifest_version "$crate")"
    if [[ "$manifest_version" != "$version" ]]; then
      die "${crate} manifest is ${manifest_version}, expected ${version}"
    fi
  done

  for crate in "${PUBLISHABLE_CRATES[@]}"; do
    grep -Eq "^${crate}[[:space:]]*=[[:space:]]*\\{[[:space:]]*version[[:space:]]*=[[:space:]]*\"${version}\"" \
      "$ROOT_DIR/Cargo.toml" \
      || die "workspace dependency for ${crate} is not pinned to ${version}"
  done
}

version_exists_on_crates_io() {
  local crate="$1"
  local version="$2"
  local http_code

  http_code="$(curl \
    --silent \
    --show-error \
    --location \
    --user-agent "$CRATES_IO_USER_AGENT" \
    --output /dev/null \
    --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/${crate}/${version}")" \
    || die "failed to query crates.io for ${crate} ${version}"

  case "$http_code" in
    200) return 0 ;;
    404) return 1 ;;
    *) die "unexpected crates.io response for ${crate} ${version}: HTTP ${http_code}" ;;
  esac
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

VERSION="$1"

cd "$ROOT_DIR"

require_command cargo
require_command curl
require_command git
require_command grep
require_command sed
require_clean_worktree
validate_version "$VERSION"

cargo "+${STABLE_TOOLCHAIN}" --version >/dev/null 2>&1 \
  || die "Rust ${STABLE_TOOLCHAIN} is required"
cargo "+${STABLE_TOOLCHAIN}" fmt --version >/dev/null 2>&1 \
  || die "rustfmt for ${STABLE_TOOLCHAIN} is required"
cargo "+${STABLE_TOOLCHAIN}" clippy --version >/dev/null 2>&1 \
  || die "Clippy for ${STABLE_TOOLCHAIN} is required"
cargo "+${MSRV_TOOLCHAIN}" --version >/dev/null 2>&1 \
  || die "Rust ${MSRV_TOOLCHAIN} is required (install it with 'rustup toolchain install ${MSRV_TOOLCHAIN} --profile minimal')"

cargo metadata --locked --no-deps --format-version 1 >/dev/null
require_manifest_versions "$VERSION"
[[ -n "${RUNLIMIT_POSTGRES_TEST_DATABASE_URL:-}" ]] \
  || die "RUNLIMIT_POSTGRES_TEST_DATABASE_URL must point to disposable PostgreSQL for the required database suite"

for crate in "${PUBLISHABLE_CRATES[@]}"; do
  if version_exists_on_crates_io "$crate" "$VERSION"; then
    die "${crate} ${VERSION} already exists on crates.io"
  fi
done

cargo "+${STABLE_TOOLCHAIN}" fmt --all -- --check
cargo "+${STABLE_TOOLCHAIN}" clippy \
  --workspace \
  --all-targets \
  --locked \
  -- \
  -D warnings
cargo "+${STABLE_TOOLCHAIN}" clippy \
  --workspace \
  --all-targets \
  --all-features \
  --locked \
  -- \
  -D warnings
cargo "+${STABLE_TOOLCHAIN}" test --workspace --locked
cargo "+${STABLE_TOOLCHAIN}" test --workspace --all-features --locked
cargo "+${STABLE_TOOLCHAIN}" test \
  -p runlimit-memory \
  --release \
  --locked \
  corrupt_quota_state_fails_closed_in_release_builds
RUSTDOCFLAGS="-D warnings" \
  cargo "+${STABLE_TOOLCHAIN}" doc --workspace --all-features --no-deps --locked
cargo "+${MSRV_TOOLCHAIN}" check --workspace --all-targets --locked
cargo "+${MSRV_TOOLCHAIN}" check --workspace --all-targets --all-features --locked

EXTERNAL_TARGET_DIR="$ROOT_DIR/target/release-external-consumer"
cargo "+${MSRV_TOOLCHAIN}" test \
  --manifest-path "$ROOT_DIR/smoke/external-consumer/Cargo.toml" \
  --locked \
  --all-targets \
  --target-dir "$EXTERNAL_TARGET_DIR"
RUNLIMIT_KEY_SECRET="runlimit-release-smoke-secret-at-least-32-bytes" \
  cargo "+${MSRV_TOOLCHAIN}" run \
    --manifest-path "$ROOT_DIR/smoke/external-consumer/Cargo.toml" \
    --locked \
    --target-dir "$EXTERNAL_TARGET_DIR" \
    --quiet

MSRV_TOOLCHAIN="$MSRV_TOOLCHAIN" \
  "$ROOT_DIR/scripts/run-external-consumer-smoke.sh"

cargo "+${STABLE_TOOLCHAIN}" test \
  -p runlimit-postgres \
  --test postgres \
  --locked \
  -- \
  --ignored \
  --test-threads=1
cargo "+${STABLE_TOOLCHAIN}" test \
  -p runlimit-postgres \
  --test postgres \
  --all-features \
  --locked \
  -- \
  --ignored \
  --test-threads=1

echo "Release ${VERSION} passed every required preparation check."
echo "Commit and push this exact tree to origin/master before publishing."
