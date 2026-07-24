#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISHABLE_CRATES=(
  "runlimit-core"
  "runlimit-memory"
  "runlimit-postgres"
)
CRATES_IO_USER_AGENT="runlimit-release-script/0.1 (https://github.com/bpcakes/runlimit)"
CRATES_IO_TIMEOUT_SECONDS="${CRATES_IO_TIMEOUT_SECONDS:-600}"
CRATES_IO_POLL_SECONDS="${CRATES_IO_POLL_SECONDS:-10}"
RESUME_RELEASE="${RESUME_RELEASE:-0}"

usage() {
  echo "usage: $0 <version>" >&2
  echo "example: $0 0.1.0" >&2
  echo "set RESUME_RELEASE=1 only to resume a partially published release" >&2
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
    die "working tree must be clean before publishing"
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

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | sed 's/[[:space:]].*//'
  else
    shasum -a 256 "$1" | sed 's/[[:space:]].*//'
  fi
}

query_crates_io_version() {
  local crate="$1"
  local version="$2"
  local output_file="$3"
  local http_code

  http_code="$(curl \
    --silent \
    --show-error \
    --location \
    --user-agent "$CRATES_IO_USER_AGENT" \
    --output "$output_file" \
    --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/${crate}/${version}")" \
    || die "failed to query crates.io for ${crate} ${version}"

  case "$http_code" in
    200|404)
      printf '%s\n' "$http_code"
      ;;
    *)
      die "unexpected crates.io response for ${crate} ${version}: HTTP ${http_code}"
      ;;
  esac
}

verify_registry_checksum() {
  local crate="$1"
  local version="$2"
  local response_file="$3"
  local archive="$PACKAGE_TARGET_DIR/package/${crate}-${version}.crate"
  local registry_checksum
  local local_checksum
  local yanked

  [[ -f "$archive" ]] || die "local package archive not found: $archive"
  yanked="$(jq -er '.version.yanked | tostring' "$response_file")" \
    || die "crates.io did not return yanked state for ${crate} ${version}"
  [[ "$yanked" == "false" ]] \
    || die "${crate} ${version} exists on crates.io but is yanked"
  registry_checksum="$(jq -er '.version.checksum' "$response_file")" \
    || die "crates.io did not return a checksum for ${crate} ${version}"
  local_checksum="$(sha256_file "$archive")"

  if [[ "$registry_checksum" != "$local_checksum" ]]; then
    die "${crate} ${version} exists, but its crates.io checksum does not match the package built from HEAD"
  fi
}

verify_local_package_provenance() {
  local crate="$1"
  local version="$2"
  local archive="$PACKAGE_TARGET_DIR/package/${crate}-${version}.crate"
  local expected_path="crates/${crate}"
  local vcs_json
  local vcs_sha
  local vcs_path

  [[ -f "$archive" ]] || die "local package archive not found: $archive"
  vcs_json="$(tar -xOf "$archive" \
    "${crate}-${version}/.cargo_vcs_info.json")" \
    || die "${crate} package does not contain .cargo_vcs_info.json"
  vcs_sha="$(printf '%s' "$vcs_json" | jq -er '.git.sha1')" \
    || die "${crate} package does not identify its source commit"
  vcs_path="$(printf '%s' "$vcs_json" | jq -er '.path_in_vcs')" \
    || die "${crate} package does not identify its repository path"

  [[ "$vcs_sha" == "$RELEASE_COMMIT" ]] \
    || die "${crate} package source commit ${vcs_sha} is not ${RELEASE_COMMIT}"
  [[ "$(printf '%s' "$vcs_json" | jq -r '.git.dirty // false')" == "false" ]] \
    || die "${crate} package was built from a dirty working tree"
  [[ "$vcs_path" == "$expected_path" ]] \
    || die "${crate} package path ${vcs_path} is not ${expected_path}"
}

preflight_initial_crate_names() {
  local crate
  local spelling
  local response_file
  local http_code
  local registry_name

  [[ "$VERSION" == "0.1.0" ]] || return 0

  for crate in "${PUBLISHABLE_CRATES[@]}"; do
    for spelling in "$crate" "${crate//-/_}"; do
      response_file="$WORK_DIR/${spelling}-name.json"
      http_code="$(curl \
        --silent \
        --show-error \
        --location \
        --user-agent "$CRATES_IO_USER_AGENT" \
        --output "$response_file" \
        --write-out '%{http_code}' \
        "https://crates.io/api/v1/crates/${spelling}")" \
        || die "failed to query crates.io for ${spelling}"
      case "$http_code" in
        404) ;;
        200)
          [[ "$RESUME_RELEASE" == "1" ]] \
            || die "initial-release crate name ${spelling} is not available"
          registry_name="$(jq -er '.crate.id' "$response_file")" \
            || die "crates.io did not identify the crate returned for ${spelling}"
          [[ "$registry_name" == "$crate" ]] \
            || die "${spelling} resolves to unexpected crate ${registry_name}"
          ;;
        *) die "unexpected crates.io response for ${spelling}: HTTP ${http_code}" ;;
      esac
    done
  done
}

require_release_commit() {
  local current_head

  current_head="$(git rev-parse HEAD)"
  [[ "$current_head" == "$RELEASE_COMMIT" ]] \
    || die "HEAD moved from frozen release commit ${RELEASE_COMMIT} to ${current_head}"
  require_clean_worktree
}

wait_for_crates_io() {
  local crate="$1"
  local version="$2"
  local response_file="$WORK_DIR/${crate}-wait.json"
  local started_at
  local now
  local http_code

  started_at="$(date +%s)"
  echo "Waiting for crates.io to index ${crate} ${version}..."

  while true; do
    http_code="$(query_crates_io_version "$crate" "$version" "$response_file")"
    if [[ "$http_code" == "200" ]]; then
      verify_registry_checksum "$crate" "$version" "$response_file"
      if cargo info --registry crates-io "${crate}@${version}" >/dev/null 2>&1; then
        echo "Indexed with matching checksum: ${crate} ${version}"
        return 0
      fi
    fi

    now="$(date +%s)"
    if (( now - started_at >= CRATES_IO_TIMEOUT_SECONDS )); then
      die "timed out waiting for crates.io to index ${crate} ${version}"
    fi
    sleep "$CRATES_IO_POLL_SECONDS"
  done
}

inspect_tag_state() {
  local tag="$1"
  local local_commit
  local remote_commit
  local remote_result
  local remote_status

  LOCAL_TAG_PRESENT=0
  REMOTE_TAG_PRESENT=0

  if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    LOCAL_TAG_PRESENT=1
    local_commit="$(git rev-list -n 1 "refs/tags/${tag}")"
    if [[ "$RESUME_RELEASE" != "1" ]]; then
      die "local tag ${tag} already exists"
    fi
    [[ "$local_commit" == "$RELEASE_COMMIT" ]] \
      || die "local tag ${tag} does not point to HEAD"
  fi

  set +e
  remote_result="$(git ls-remote --exit-code --tags origin \
    "refs/tags/${tag}" "refs/tags/${tag}^{}" 2>&1)"
  remote_status=$?
  set -e

  case "$remote_status" in
    0)
      REMOTE_TAG_PRESENT=1
      if [[ "$RESUME_RELEASE" != "1" ]]; then
        die "remote tag ${tag} already exists on origin"
      fi
      remote_commit="$(printf '%s\n' "$remote_result" \
        | awk '$2 ~ /\^\{\}$/ { print $1; found=1 } END { if (!found) exit 1 }')" \
        || remote_commit="$(printf '%s\n' "$remote_result" \
          | awk '$2 !~ /\^\{\}$/ { print $1; exit }')"
      [[ "$remote_commit" == "$RELEASE_COMMIT" ]] \
        || die "remote tag ${tag} does not point to HEAD"
      ;;
    2) ;;
    *) die "failed to check remote tag ${tag}: ${remote_result}" ;;
  esac
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

VERSION="$1"
TAG="v${VERSION}"

cd "$ROOT_DIR"

require_command cargo
require_command curl
require_command date
require_command git
require_command grep
require_command jq
require_command mktemp
require_command awk
require_command sed
require_command sleep
require_command tar
if ! command -v sha256sum >/dev/null 2>&1; then
  require_command shasum
fi

validate_version "$VERSION"
[[ "$RESUME_RELEASE" == "0" || "$RESUME_RELEASE" == "1" ]] \
  || die "RESUME_RELEASE must be 0 or 1"
[[ "$CRATES_IO_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] \
  || die "CRATES_IO_TIMEOUT_SECONDS must be a positive integer"
[[ "$CRATES_IO_POLL_SECONDS" =~ ^[1-9][0-9]*$ ]] \
  || die "CRATES_IO_POLL_SECONDS must be a positive integer"

require_clean_worktree
cargo metadata --locked --no-deps --format-version 1 >/dev/null
require_manifest_versions "$VERSION"
RELEASE_COMMIT="$(git rev-parse HEAD)"

current_branch="$(git symbolic-ref --quiet --short HEAD)" \
  || die "cannot publish from detached HEAD"
[[ "$current_branch" == "master" ]] \
  || die "publishing is allowed only from master, currently on ${current_branch}"
git remote get-url origin >/dev/null 2>&1 \
  || die "git remote 'origin' does not exist"
origin_url="$(git remote get-url origin)"
case "$origin_url" in
  git@github.com:bpcakes/runlimit.git|https://github.com/bpcakes/runlimit.git) ;;
  *) die "origin must be the canonical Runlimit repository, got ${origin_url}" ;;
esac

git fetch --quiet --no-tags origin \
  "refs/heads/master:refs/remotes/origin/master"
remote_head="$(git rev-parse refs/remotes/origin/master)"
[[ "$RELEASE_COMMIT" == "$remote_head" ]] \
  || die "HEAD (${RELEASE_COMMIT}) must exactly match origin/master (${remote_head})"
remote_advertised_head="$(git ls-remote --exit-code origin refs/heads/master \
  | awk 'NR == 1 { print $1 }')" \
  || die "failed to resolve refs/heads/master directly from origin"
[[ "$RELEASE_COMMIT" == "$remote_advertised_head" ]] \
  || die "origin advertises master at ${remote_advertised_head}, expected ${RELEASE_COMMIT}"
inspect_tag_state "$TAG"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/runlimit-publish.XXXXXX")"
PACKAGE_TARGET_DIR="$WORK_DIR/package-target"
PREFLIGHT_PACKAGE_TARGET_DIR="$WORK_DIR/preflight-package-target"

cleanup() {
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

preflight_initial_crate_names

# Preflight every crate before the first irreversible upload. Existing versions
# are accepted only for an explicitly resumed release. A valid partial release
# is necessarily a contiguous prefix of the dependency-ordered crate list.
PREFLIGHT_HTTP_CODES=()
seen_missing=0
for crate in "${PUBLISHABLE_CRATES[@]}"; do
  response_file="$WORK_DIR/${crate}-preflight.json"
  http_code="$(query_crates_io_version "$crate" "$VERSION" "$response_file")"
  PREFLIGHT_HTTP_CODES+=("$http_code")
  if [[ "$http_code" == "200" ]]; then
    if [[ "$RESUME_RELEASE" != "1" ]]; then
      die "${crate} ${VERSION} already exists; set RESUME_RELEASE=1 only if this is a partial-release recovery"
    fi
    if [[ "$seen_missing" == "1" ]]; then
      die "${crate} ${VERSION} exists while an earlier dependency is absent; refusing a noncontiguous release"
    fi
  else
    seen_missing=1
  fi
done

# Prove that Cargo can normalize every workspace package before the first
# upload. These workspace archives are only a feasibility check; authoritative
# checksum archives are built one at a time below against the registry state
# that exists immediately before each sequential publish.
CARGO_TARGET_DIR="$PREFLIGHT_PACKAGE_TARGET_DIR" \
  cargo package \
    --workspace \
    --locked \
    --no-verify \
    --quiet

echo "Cargo authentication is assumed; each cargo publish call will use the configured crates.io credential."

for index in "${!PUBLISHABLE_CRATES[@]}"; do
  crate="${PUBLISHABLE_CRATES[$index]}"
  response_file="$WORK_DIR/${crate}-publish.json"
  http_code="$(query_crates_io_version "$crate" "$VERSION" "$response_file")"

  if [[ "$http_code" == "200" && "${PREFLIGHT_HTTP_CODES[$index]}" == "404" && "$RESUME_RELEASE" != "1" ]]; then
    die "${crate} ${VERSION} appeared on crates.io after preflight; refusing to adopt an unexpected publish"
  fi

  require_release_commit
  CARGO_TARGET_DIR="$PACKAGE_TARGET_DIR" \
    cargo package \
      --locked \
      --no-verify \
      -p "$crate" \
      --quiet
  verify_local_package_provenance "$crate" "$VERSION"

  if [[ "$http_code" == "200" ]]; then
    verify_registry_checksum "$crate" "$VERSION" "$response_file"
    echo "Verified existing package while resuming: ${crate} ${VERSION}"
  else
    require_release_commit
    CARGO_TARGET_DIR="$PACKAGE_TARGET_DIR" \
      cargo publish --registry crates-io --locked --dry-run -p "$crate"
    require_release_commit
    CARGO_TARGET_DIR="$PACKAGE_TARGET_DIR" \
      cargo publish --registry crates-io --locked -p "$crate"
  fi

  wait_for_crates_io "$crate" "$VERSION"
done

require_release_commit
if [[ "$LOCAL_TAG_PRESENT" == "0" ]]; then
  if [[ "$REMOTE_TAG_PRESENT" == "1" ]]; then
    git fetch --quiet origin "refs/tags/${TAG}:refs/tags/${TAG}"
    [[ "$(git rev-list -n 1 "refs/tags/${TAG}")" == "$RELEASE_COMMIT" ]] \
      || die "fetched tag ${TAG} does not point to the published commit"
  else
    git tag -a "$TAG" -m "Runlimit ${VERSION}"
  fi
fi
if [[ "$REMOTE_TAG_PRESENT" == "0" ]]; then
  git push origin "refs/tags/${TAG}"
fi

echo "Published Runlimit ${VERSION} and pushed ${TAG}."
