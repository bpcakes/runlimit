#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_SOURCE_DIR="$ROOT_DIR/smoke/external-consumer"
MSRV_TOOLCHAIN="${MSRV_TOOLCHAIN:-1.88.0}"
CRATES=(
  "runlimit-core"
  "runlimit-memory"
  "runlimit-postgres"
)
PACKAGE_PATCH_ARGS=(
  --config "patch.crates-io.runlimit-core.path=\"$ROOT_DIR/crates/runlimit-core\""
  --config "patch.crates-io.runlimit-memory.path=\"$ROOT_DIR/crates/runlimit-memory\""
  --config "patch.crates-io.runlimit-postgres.path=\"$ROOT_DIR/crates/runlimit-postgres\""
)

die() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

crate_version() {
  cargo pkgid -p "$1" | sed 's/.*#//'
}

require_command cargo
require_command cp
require_command find
require_command grep
require_command mktemp
require_command perl
require_command sed
require_command tar

[[ -d "$SMOKE_SOURCE_DIR" ]] \
  || die "external consumer fixture not found at $SMOKE_SOURCE_DIR"

cargo "+${MSRV_TOOLCHAIN}" --version >/dev/null 2>&1 \
  || die "Rust ${MSRV_TOOLCHAIN} is required (install it with 'rustup toolchain install ${MSRV_TOOLCHAIN} --profile minimal')"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/runlimit-packaged-smoke.XXXXXX")"
PACKAGE_TARGET_DIR="$WORK_DIR/package-target"
VENDOR_DIR="$WORK_DIR/vendor"
CONSUMER_DIR="$WORK_DIR/external-consumer"
BUILD_TARGET_DIR="$WORK_DIR/build-target"
PATCH_CONFIG="$WORK_DIR/patch-config.toml"

cleanup() {
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$VENDOR_DIR"
cp -R "$SMOKE_SOURCE_DIR" "$CONSUMER_DIR"

CORE_VERSION="$(crate_version runlimit-core)"
MEMORY_VERSION="$(crate_version runlimit-memory)"
POSTGRES_VERSION="$(crate_version runlimit-postgres)"

for crate in "${CRATES[@]}"; do
  CARGO_TARGET_DIR="$PACKAGE_TARGET_DIR" \
    cargo "+${MSRV_TOOLCHAIN}" package \
      --locked \
      --allow-dirty \
      --no-verify \
      -p "$crate" \
      "${PACKAGE_PATCH_ARGS[@]}" \
      --quiet

  case "$crate" in
    runlimit-core) version="$CORE_VERSION" ;;
    runlimit-memory) version="$MEMORY_VERSION" ;;
    runlimit-postgres) version="$POSTGRES_VERSION" ;;
    *) die "unsupported crate $crate" ;;
  esac

  archive="$PACKAGE_TARGET_DIR/package/${crate}-${version}.crate"
  [[ -f "$archive" ]] || die "package archive not found: $archive"
  tar -xzf "$archive" -C "$VENDOR_DIR"
done

RELEASE_CORE_VERSION="$CORE_VERSION" \
RELEASE_MEMORY_VERSION="$MEMORY_VERSION" \
RELEASE_POSTGRES_VERSION="$POSTGRES_VERSION" \
perl -0pi -e '
  s/^runlimit-core\s*=.*$/runlimit-core = { version = "=$ENV{RELEASE_CORE_VERSION}" }/m
    or die "failed to pin runlimit-core in $ARGV\n";
  s/^runlimit-memory\s*=.*$/runlimit-memory = { version = "=$ENV{RELEASE_MEMORY_VERSION}" }/m
    or die "failed to pin runlimit-memory in $ARGV\n";
  if (/^runlimit-postgres\s*=/m) {
    s/^runlimit-postgres\s*=.*$/runlimit-postgres = { version = "=$ENV{RELEASE_POSTGRES_VERSION}" }/m
      or die "failed to pin runlimit-postgres in $ARGV\n";
  } else {
    s/^(runlimit-memory\s*=.*\n)/$1runlimit-postgres = { version = "=$ENV{RELEASE_POSTGRES_VERSION}" }\n/m
      or die "failed to add runlimit-postgres to $ARGV\n";
  }
' "$CONSUMER_DIR/Cargo.toml"

if grep -Eq '^runlimit-(core|memory|postgres)[[:space:]]*=.*path[[:space:]]*=' \
  "$CONSUMER_DIR/Cargo.toml"; then
  die "copied consumer manifest still contains a Runlimit path dependency"
fi
grep -Eq "^runlimit-core[[:space:]]*=.*version[[:space:]]*=[[:space:]]*\"=${CORE_VERSION}\"" \
  "$CONSUMER_DIR/Cargo.toml" \
  || die "copied consumer does not require exactly runlimit-core ${CORE_VERSION}"
grep -Eq "^runlimit-memory[[:space:]]*=.*version[[:space:]]*=[[:space:]]*\"=${MEMORY_VERSION}\"" \
  "$CONSUMER_DIR/Cargo.toml" \
  || die "copied consumer does not require exactly runlimit-memory ${MEMORY_VERSION}"
grep -Eq "^runlimit-postgres[[:space:]]*=.*version[[:space:]]*=[[:space:]]*\"=${POSTGRES_VERSION}\"" \
  "$CONSUMER_DIR/Cargo.toml" \
  || die "copied consumer does not require exactly runlimit-postgres ${POSTGRES_VERSION}"

{
  printf '[patch.crates-io]\n'
  printf 'runlimit-core = { path = "%s/runlimit-core-%s" }\n' \
    "$VENDOR_DIR" "$CORE_VERSION"
  printf 'runlimit-memory = { path = "%s/runlimit-memory-%s" }\n' \
    "$VENDOR_DIR" "$MEMORY_VERSION"
  printf 'runlimit-postgres = { path = "%s/runlimit-postgres-%s" }\n' \
    "$VENDOR_DIR" "$POSTGRES_VERSION"
} >"$PATCH_CONFIG"

sql_file_count=0
while IFS= read -r sql_file; do
  sql_file_count=$((sql_file_count + 1))
  sql_relative_path="${sql_file#"$ROOT_DIR/crates/runlimit-postgres/"}"
  [[ -f "$VENDOR_DIR/runlimit-postgres-${POSTGRES_VERSION}/${sql_relative_path}" ]] \
    || die "runlimit-postgres package omitted SQL file ${sql_relative_path}"
done < <(find "$ROOT_DIR/crates/runlimit-postgres" -type f -name '*.sql' -print)
(( sql_file_count > 0 )) || die "no PostgreSQL SQL files were found to audit"

for crate in "${CRATES[@]}"; do
  case "$crate" in
    runlimit-core) version="$CORE_VERSION" ;;
    runlimit-memory) version="$MEMORY_VERSION" ;;
    runlimit-postgres) version="$POSTGRES_VERSION" ;;
    *) die "unsupported crate $crate" ;;
  esac

  manifest="$VENDOR_DIR/${crate}-${version}/Cargo.toml"
  [[ -f "$manifest" ]] || die "extracted manifest not found: $manifest"
  if ! perl -0ne '
    while (/\[(?:dev-)?dependencies\.(runlimit-[^]]+)\](.*?)(?=\n\[|\z)/sg) {
      die "$1 retained a path dependency in $ARGV\n" if $2 =~ /^\s*path\s*=/m;
    }
  ' "$manifest"; then
    die "${crate} package retained a Runlimit path dependency"
  fi

  CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
    cargo "+${MSRV_TOOLCHAIN}" generate-lockfile \
      --manifest-path "$manifest" \
      --config "$PATCH_CONFIG" \
      --quiet
  CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
    cargo "+${MSRV_TOOLCHAIN}" test \
      --manifest-path "$manifest" \
      --config "$PATCH_CONFIG" \
      --locked \
      --all-targets
done

rm -f "$CONSUMER_DIR/Cargo.lock"
CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
  cargo "+${MSRV_TOOLCHAIN}" generate-lockfile \
    --manifest-path "$CONSUMER_DIR/Cargo.toml" \
    --config "$PATCH_CONFIG" \
    --quiet
CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
  cargo "+${MSRV_TOOLCHAIN}" test \
    --manifest-path "$CONSUMER_DIR/Cargo.toml" \
    --config "$PATCH_CONFIG" \
    --locked \
    --all-targets
RUNLIMIT_KEY_SECRET="runlimit-packaged-smoke-secret-at-least-32-bytes" \
  CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
  cargo "+${MSRV_TOOLCHAIN}" run \
    --manifest-path "$CONSUMER_DIR/Cargo.toml" \
    --config "$PATCH_CONFIG" \
    --locked \
    --quiet

echo "Packaged-source external-consumer smoke test passed with Rust ${MSRV_TOOLCHAIN}."
