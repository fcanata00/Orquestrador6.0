#!/usr/bin/env bash
# utils.sh - Utilities for Rolling LFS sandbox (with upstream_check)
# Features:
#  - load global config
#  - create and validate directory structure
#  - create/load metafiles (INI)
#  - support sources (tarballs, zip, git, directory), patches, hooks
#  - verify checksums (md5/sha1/sha256/sha512)
#  - fetch sources with curl/wget, resume, retries, progress
#  - apply patches, run hooks
#  - --check and --repair modes, --dry-run, --verbose, --require-checksum, --log-file
#  - upstream_check: check upstream versions via URL+regex, --update, --all
#  - concurrency-safe with flock, atomic writes, robust error handling
#
# NOTE: Requires Bash >= 4 for associative arrays.
set -euo pipefail
IFS=$'\n\t'

# ---------- Defaults and globals ----------
SANDBOX_ROOT="${SANDBOX_ROOT:-$HOME/lfs-sandbox}"
CONFIG_FILE="${CONFIG_FILE:-$SANDBOX_ROOT/etc/lfs-rolling.conf}"
LOG_FILE_DEFAULT="${LOG_FILE:-$SANDBOX_ROOT/logs/utils.log}"
LOG_FILE="${LOG_FILE:-$LOG_FILE_DEFAULT}"
REQUIRE_CHECKSUM=true
DRY_RUN=false
VERBOSE=false
FORCE=false
RETRY_COUNT=3
RETRY_DELAY=5
MAX_LOG_FILES=7
LOCK_DIR="${SANDBOX_ROOT}/locks"
CACHE_DIR="${SANDBOX_ROOT}/cache"
META_DIR="${SANDBOX_ROOT}/meta"
BUILD_DIR="${SANDBOX_ROOT}/build"
PACKAGES_DIR="${SANDBOX_ROOT}/packages"
TMPDIR="${SANDBOX_ROOT}/tmp"
UMASK_DEFAULT=022
UPSTREAM_TIMEOUT=15   # seconds for HTTP requests

# Ensure directories exist (may be adjusted later by config)
mkdir -p "$LOCK_DIR" "$CACHE_DIR" "$META_DIR" "$BUILD_DIR" "$PACKAGES_DIR" "$TMPDIR" "$(dirname "$LOG_FILE")"

# Exit codes
E_OK=0
E_GENERIC=1
E_ARGS=2
E_PERM=3
E_MISSING=4
E_DOWNLOAD=5
E_CHECKSUM=6
E_PATCH=7
E_HOOK=8
E_PARSE=9
E_UPSTREAM=13

# Check bash version
if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "utils.sh requires Bash >= 4" >&2
  exit 1
fi

# ---------- Logging helpers ----------
log_to_file() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf "[%s] %s %s\n" "$level" "$ts" "$msg" >> "$LOG_FILE"
}
log() {
  local level="$1"; shift
  local msg="$*"
  if [ "$VERBOSE" = true ]; then
    printf "[%s] %s %s\n" "$level" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$msg"
  fi
  log_to_file "$level" "$msg"
  # also try to forward to log.sh if present
  if command -v log.sh >/dev/null 2>&1; then
    log.sh debug utils "$LOG_FILE" "[$level] $msg" >/dev/null 2>&1 || true
  fi
}

die() {
  local code=${1:-1}
  shift || true
  log ERROR "$*"
  exit "$code"
}

# ---------- Utility helpers ----------
abspath() {
  if [ -z "${1:-}" ]; then
    echo ""
    return
  fi
  case "$1" in
    /*) printf "%s" "$1";;
    *) printf "%s" "$(pwd)/$1";;
  esac
}

atomic_write_file() {
  local file="$1"; local content="$2"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/.tmp.XXXXXX")"
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: would write to $file"
    rm -f "$tmp"
    return 0
  fi
  printf "%s" "$content" > "$tmp"
  mv -f "$tmp" "$file"
}

ensure_dir() {
  local dir="$1"; local perms="${2:-0755}"; local owner="${3:-}"
  dir=$(abspath "$dir")
  if [ ! -d "$dir" ]; then
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: create dir $dir"
    else
      mkdir -p "$dir" || die $E_PERM "Failed to create directory $dir"
      log INFO "Created directory $dir"
    fi
  fi
  if [ "$DRY_RUN" = false ]; then
    chmod "$perms" "$dir" || log WARN "Could not set perms $perms on $dir"
    if [ -n "$owner" ] && [ "$(id -u)" -eq 0 ]; then
      chown "$owner" "$dir" || log WARN "Could not chown $owner on $dir"
    fi
  fi
}

ensure_file() {
  local file="$1"; local perms="${2:-0644}"; local owner="${3:-}"
  file=$(abspath "$file")
  if [ ! -f "$file" ]; then
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: create file $file"
    else
      mkdir -p "$(dirname "$file")"
      : > "$file" || die $E_PERM "Failed to create file $file"
      log INFO "Created file $file"
    fi
  fi
  if [ "$DRY_RUN" = false ]; then
    chmod "$perms" "$file" || log WARN "Could not set perms $perms on $file"
    if [ -n "$owner" ] && [ "$(id -u)" -eq 0 ]; then
      chown "$owner" "$file" || log WARN "Could not chown $owner on $file"
    fi
  fi
}

# Simple lock wrapper using flock
with_lock() {
  local lockname="$1"; shift
  local lockfile="$LOCK_DIR/${lockname}.lock"
  mkdir -p "$(dirname "$lockfile")"
  exec 9>"$lockfile"
  flock -n 9 || die $E_PERM "Could not acquire lock $lockname"
  "$@"
  flock -u 9 || true
  exec 9>&-
}

# ---------- Config loading ----------
default_config() {
  mkdir -p "$(dirname "$CONFIG_FILE")"
  cat > "$CONFIG_FILE" <<'EOF'
# lfs-rolling.conf - default config
SANDBOX_ROOT="${SANDBOX_ROOT:-$HOME/lfs-sandbox}"
META_DIR="${META_DIR:-$SANDBOX_ROOT/meta}"
CACHE_DIR="${CACHE_DIR:-$SANDBOX_ROOT/cache}"
BUILD_DIR="${BUILD_DIR:-$SANDBOX_ROOT/build}"
PACKAGES_DIR="${PACKAGES_DIR:-$SANDBOX_ROOT/packages}"
LOG_FILE="${LOG_FILE:-$SANDBOX_ROOT/logs/utils.log}"
RETRY_COUNT=3
RETRY_DELAY=5
REQUIRE_CHECKSUM=true
UPSTREAM_TIMEOUT=15
EOF
  chmod 0644 "$CONFIG_FILE"
  log INFO "Wrote default config to $CONFIG_FILE"
}

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE" || die $E_GENERIC "Config file invalid: $CONFIG_FILE"
    log INFO "Loaded config: $CONFIG_FILE"
  else
    log WARN "Config file not found at $CONFIG_FILE, creating default."
    default_config
    source "$CONFIG_FILE"
  fi
  # apply variables (ensure directory creation)
  mkdir -p "$SANDBOX_ROOT"
  META_DIR="${META_DIR:-$SANDBOX_ROOT/meta}"
  CACHE_DIR="${CACHE_DIR:-$SANDBOX_ROOT/cache}"
  BUILD_DIR="${BUILD_DIR:-$SANDBOX_ROOT/build}"
  PACKAGES_DIR="${PACKAGES_DIR:-$SANDBOX_ROOT/packages}"
  LOCK_DIR="${LOCK_DIR:-$SANDBOX_ROOT/locks}"
  TMPDIR="${TMPDIR:-$SANDBOX_ROOT/tmp}"
  LOG_FILE="${LOG_FILE:-$SANDBOX_ROOT/logs/utils.log}"
  UPSTREAM_TIMEOUT="${UPSTREAM_TIMEOUT:-$UPSTREAM_TIMEOUT}"
  mkdir -p "$META_DIR" "$CACHE_DIR" "$BUILD_DIR" "$PACKAGES_DIR" "$LOCK_DIR" "$TMPDIR" "$(dirname "$LOG_FILE")"
  umask "$UMASK_DEFAULT"
}

# ---------- INI Parser ----------
declare -A INI
parse_ini() {
  local file="$1"
  if [ ! -f "$file" ]; then
    log ERROR "INI file not found: $file"
    return $E_MISSING
  fi
  if grep -q $'\x00' "$file"; then
    log ERROR "INI file contains NUL bytes: $file"
    return $E_PARSE
  fi

  local awkprog
  awkprog='
    BEGIN{section=""; OFS="";}
    /^[ \t]*([;#].*)?$/ {next}
    /^[ \t]*\[/ {
      s=$0
      sub(/^[ \t]*\[/,"",s)
      sub(/\].*$/,"",s)
      gsub(/ /,"_",s)
      section=s; next
    }
    /^[ \t]*[^=]+=[ \t]*.*$/ {
      line=$0
      sub(/^[ \t]*/,"",line)
      n=split(line,kv,"=")
      key=kv[1]; sub(/[ \t]*$/,"",key)
      pos=index(line,"=")
      value=substr(line,pos+1)
      gsub(/^[ \t]+|[ \t]+$/,"",value)
      gsub(/^[ \t]+|[ \t]+$/,"",key)
      sub(/[ \t]*[;#].*$/,"",value)
      print section "\034" key "\034" value
    }
  '
  INI=()
  while IFS=$'\034' read -r section key value; do
    if [ -z "$section" ]; then
      section="__global__"
    fi
    key=$(echo "$key" | tr '[:upper:]' '[:lower:]' | sed 's/ /_/g')
    INI["$section.$key"]="$value"
  done < <(awk "$awkprog" "$file")
  return 0
}

ini_get() {
  local section="$1" key="$2" default="${3:-}"
  local k="${section}.${key}"
  if [ -n "${INI[$k]:-}" ]; then
    printf "%s" "${INI[$k]}"
    return 0
  else
    printf "%s" "$default"
    return 1
  fi
}

collect_ordered_entries() {
  local section="$1" prefix="$2"
  local -a keys=()
  for k in "${!INI[@]}"; do
    if [[ "$k" == "$section."* ]]; then
      keys+=("${k#${section}.}")
    fi
  done
  local -a indices=()
  for k in "${keys[@]}"; do
    if [[ "$k" =~ ^${prefix}([0-9]+)\. ]]; then
      indices+=("${BASH_REMATCH[1]}")
    fi
  done
  IFS=$'\n' sorted=($(printf "%s\n" "${indices[@]}" | sort -n -u))
  unset IFS
  for i in "${sorted[@]}"; do
    printf "%s\n" "$i"
  done
}

# ---------- Metafile create/load ----------
validate_name() {
  local name="$1"
  if [[ ! "$name" =~ ^[a-z0-9._+\-]+$ ]]; then
    return 1
  fi
  return 0
}

create_metafile() {
  local category="$1" pkg="$2" force="${3:-false}"
  if ! validate_name "$category" || ! validate_name "$pkg"; then
    die $E_ARGS "Invalid category or package name. Allowed: a-z0-9._+-"
  fi
  local pkg_dir="$META_DIR/$category/$pkg"
  if [ -d "$pkg_dir" ] && [ "$force" != "true" ]; then
    die $E_GENERIC "Package dir exists: $pkg_dir. Use --force to overwrite"
  fi
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: would create package dir $pkg_dir and template INI"
    return 0
  fi
  mkdir -p "$pkg_dir/patches" "$pkg_dir/hooks" "$pkg_dir/files"
  local ini="$pkg_dir/${pkg}.ini"
  if [ -f "$ini" ] && [ "$force" != "true" ]; then
    die $E_GENERIC "Metafile exists: $ini"
  fi
  cat > "$ini" <<EOF
[meta]
name = $pkg
version = 0.0.0
category = $category
bootstrap = false
install_root = /usr

[source]
# src1.type = tarball|zip|git|directory
# src1.url  = https://...
# src1.sha256 = ...

[patches]
# patch1.type = url|local
# patch1.url/path = ...

[build]
configure =
make =
check =
install =

[environment]
# CFLAGS = -O2
# path.prepend = /mnt/lfs/tools/bin

[hooks]
# pre_download = hooks/pre_download.sh

[upstream]
# check_type = release_page|git_tags|api
# check_url = https://ftp.gnu.org/gnu/
# check_regex = gcc-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.xz
# current_version = 0.0.0
EOF
  chmod 0644 "$ini"
  chmod 0755 "$pkg_dir/hooks"
  log INFO "Created metafile template: $ini"
}

load_metafile() {
  local meta_path="$1"
  if [ ! -f "$meta_path" ]; then
    die $E_MISSING "Metafile not found: $meta_path"
  fi
  INI=()
  parse_ini "$meta_path" || die $E_PARSE "Failed to parse INI: $meta_path"
  local name version category
  name=$(ini_get meta name "" ) || true
  version=$(ini_get meta version "" ) || true
  category=$(ini_get meta category "misc") || true
  if [ -z "$name" ]; then
    die $E_PARSE "Metafile missing meta.name"
  fi
  META_NAME="$name"
  META_VERSION="$version"
  META_CATEGORY="$category"
  META_INSTALL_ROOT=$(ini_get meta install_root "/usr" )
  META_BOOTSTRAP=$(ini_get meta bootstrap "false" )
  META_PKG_DIR="$(cd "$(dirname "$meta_path")" && pwd)"
  mapfile -t SRC_INDICES < <(collect_ordered_entries source src)
  META_SOURCES=()
  for idx in "${SRC_INDICES[@]:-}"; do
    local typ="$(ini_get source src${idx}.type "")"
    local url="$(ini_get source src${idx}.url "")"
    local sha="$(ini_get source src${idx}.sha256 "")"
    local rev="$(ini_get source src${idx}.revision "")"
    META_SOURCES+=("${typ}|||${url}|||${sha}|||${rev}")
  done
  mapfile -t PATCH_INDICES < <(collect_ordered_entries patches patch)
  META_PATCHES=()
  for idx in "${PATCH_INDICES[@]:-}"; do
    local typ="$(ini_get patches patch${idx}.type "")"
    local url="$(ini_get patches patch${idx}.url "")"
    local pathp="$(ini_get patches patch${idx}.path "")"
    local sha="$(ini_get patches patch${idx}.sha256 "")"
    local pstrip="$(ini_get patches patch${idx}.pstrip "1")"
    META_PATCHES+=("${typ}|||${url}|||${pathp}|||${sha}|||${pstrip}")
  done
  META_BUILD_CONFIGURE=$(ini_get build configure "")
  META_BUILD_MAKE=$(ini_get build make "")
  META_BUILD_CHECK=$(ini_get build check "")
  META_BUILD_INSTALL=$(ini_get build install "")
  META_ENV_KEYS=()
  META_PATH_PREPEND=$(ini_get environment path.prepend "")
  META_PATH_APPEND=$(ini_get environment path.append "")
  for k in "${!INI[@]}"; do
    if [[ "$k" =~ ^environment\.(.+)$ ]]; then
      META_ENV_KEYS+=("${BASH_REMATCH[1]}")
    fi
  done
  META_ENV_VARS=()
  for key in "${META_ENV_KEYS[@]:-}"; do
    val=$(ini_get environment "$key" "")
    META_ENV_VARS+=("${key}|||${val}")
  done
  META_HOOKS_PRE_DOWNLOAD=$(ini_get hooks pre_download "")
  META_HOOKS_POST_DOWNLOAD=$(ini_get hooks post_download "")
  META_HOOKS_PRE_BUILD=$(ini_get hooks pre_build "")
  META_HOOKS_POST_BUILD=$(ini_get hooks post_build "")
  META_HOOKS_IGNORE_ERRORS=$(ini_get hooks hooks.ignore_errors "false")
  META_UPSTREAM_CHECK_TYPE=$(ini_get upstream check_type "")
  META_UPSTREAM_CHECK_URL=$(ini_get upstream check_url "")
  META_UPSTREAM_CHECK_REGEX=$(ini_get upstream check_regex "")
  META_UPSTREAM_CURRENT_VERSION=$(ini_get upstream current_version "$META_VERSION")
  log INFO "Loaded metafile $meta_path (name=$META_NAME version=$META_VERSION)"
}

# ---------- Checksum verification ----------
verify_checksum() {
  local file="$1" expected="$2"
  if [ -z "$expected" ]; then
    if [ "$REQUIRE_CHECKSUM" = true ]; then
      log ERROR "Checksum required but not provided for $file"
      return $E_CHECKSUM
    else
      log WARN "No checksum provided for $file (REQUIRE_CHECKSUM=false)"
      return 0
    fi
  fi
  local len=${#expected}
  local algo=""
  case "$len" in
    32) algo="md5sum" ;;
    40) algo="sha1sum" ;;
    64) algo="sha256sum" ;;
    128) algo="sha512sum" ;;
    *) algo="sha256sum"; log WARN "Unknown checksum length $len, assuming sha256";;
  esac
  if ! command -v "$algo" >/dev/null 2>&1; then
    log ERROR "Required checksum tool $algo not found"
    return $E_CHECKSUM
  fi
  if [ ! -f "$file" ]; then
    log ERROR "File not found for checksum: $file"
    return $E_MISSING
  fi
  local calc
  calc=$("$algo" "$file" | awk '{print $1}')
  if [ "$calc" = "$expected" ]; then
    log INFO "Checksum OK for $file ($algo)"
    return 0
  else
    log ERROR "Checksum mismatch for $file: expected $expected got $calc"
    return $E_CHECKSUM
  fi
}

# ---------- Download helpers ----------
_download_with_curl() {
  local url="$1" dest="$2"
  local rc=0
  curl_opts=( -L --fail --retry "$RETRY_COUNT" --retry-delay "$RETRY_DELAY" --connect-timeout 10 --max-time 0 -o "$dest" )
  if [ "$VERBOSE" = false ]; then
    curl_opts+=( --silent --show-error --progress-bar )
  fi
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: curl ${curl_opts[*]} $url"
    return 0
  fi
  curl "${curl_opts[@]}" "$url"
  rc=$?
  return $rc
}
_download_with_wget() {
  local url="$1" dest="$2"
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: wget -O $dest $url"
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget --tries="$RETRY_COUNT" -O "$dest" "$url"
    return $?
  else
    return 127
  fi
}

fetch_source_entry() {
  local entry="$1" pkg="$2"
  IFS='|||' read -r typ url sha rev <<< "$entry"
  local cache_pkg_dir="$CACHE_DIR/$pkg"
  mkdir -p "$cache_pkg_dir"
  case "$typ" in
    tarball|zip)
      local filename
      filename="$(basename "$url")"
      local dest="$cache_pkg_dir/$filename"
      if [ -f "$dest" ]; then
        if [ -n "$sha" ]; then
          if verify_checksum "$dest" "$sha"; then
            log INFO "Using cached $dest"
            printf "%s" "$dest"
            return 0
          else
            log WARN "Cached file checksum mismatch, will re-download $url"
            rm -f "$dest"
          fi
        else
          log INFO "Using cached $dest (no checksum provided)"
          printf "%s" "$dest"
          return 0
        fi
      fi
      local tmpf="$dest.part"
      if command -v curl >/dev/null 2>&1; then
        _download_with_curl "$url" "$tmpf" || return $E_DOWNLOAD
      else
        _download_with_wget "$url" "$tmpf" || return $E_DOWNLOAD
      fi
      mv -f "$tmpf" "$dest"
      log INFO "Downloaded $url -> $dest"
      if [ -n "$sha" ]; then
        verify_checksum "$dest" "$sha" || return $E_CHECKSUM
      elif [ "$REQUIRE_CHECKSUM" = true ]; then
        log ERROR "Checksum required but not provided for $url"
        return $E_CHECKSUM
      fi
      printf "%s" "$dest"
      return 0
      ;;
    git)
      local gitdir="$cache_pkg_dir/git"
      mkdir -p "$gitdir"
      if [ ! -d "$gitdir/.git" ]; then
        if [ "$DRY_RUN" = true ]; then
          log INFO "DRY-RUN: git clone --mirror $url $gitdir"
        else
          git clone --mirror "$url" "$gitdir" || return $E_DOWNLOAD
        fi
      else
        if [ "$DRY_RUN" = false ]; then
          (cd "$gitdir" && git remote update) || log WARN "git remote update failed for $url"
        fi
      fi
      local revspec="${rev:-HEAD}"
      local out="$cache_pkg_dir/git-$(echo "$revspec" | sed 's/[^a-zA-Z0-9._-]/_/g').tar.gz"
      if [ -f "$out" ]; then
        log INFO "Using cached git archive $out"
        printf "%s" "$out"
        return 0
      fi
      if [ "$DRY_RUN" = true ]; then
        log INFO "DRY-RUN: create git archive $out for $revspec"
        printf "%s" "$out"
        return 0
      fi
      tmpgit="$(mktemp -d "${TMPDIR}/git.XXXX")"
      git clone --depth 1 --branch "${revspec}" "$url" "$tmpgit" >/dev/null 2>&1 || {
        rm -rf "$tmpgit"
        tmpgit="$(mktemp -d "${TMPDIR}/gitfull.XXXX")"
        git clone "$url" "$tmpgit" || return $E_DOWNLOAD
        (cd "$tmpgit" && git archive --format=tar.gz -o "$out" "$revspec") || { rm -rf "$tmpgit"; return $E_DOWNLOAD; }
        rm -rf "$tmpgit"
        printf "%s" "$out"
        return 0
      }
      (cd "$tmpgit" && tar -czf "$out" .)
      rm -rf "$tmpgit"
      log INFO "Created git archive $out"
      printf "%s" "$out"
      return 0
      ;;
    directory)
      local srcpath="$url"
      if [ -d "$srcpath" ]; then
        printf "%s" "$srcpath"
        return 0
      fi
      if [ -d "$META_PKG_DIR/$srcpath" ]; then
        printf "%s" "$META_PKG_DIR/$srcpath"
        return 0
      fi
      log ERROR "Directory source not found: $srcpath"
      return $E_MISSING
      ;;
    *)
      log ERROR "Unknown source type: $typ"
      return $E_ARGS
      ;;
  esac
}

fetch_all_sources() {
  local pkg="$1" outdir="$2"
  mkdir -p "$outdir"
  for entry in "${META_SOURCES[@]:-}"; do
    local srcpath
    srcpath=$(fetch_source_entry "$entry" "$pkg") || return $?
    log INFO "Fetched source: $srcpath"
    if [ -f "$srcpath" ]; then
      case "$srcpath" in
        *.tar.gz|*.tgz) tar -xzf "$srcpath" -C "$outdir" || die $E_GENERIC "tar xzf failed";;
        *.tar.xz) tar -xJf "$srcpath" -C "$outdir" || die $E_GENERIC "tar xJf failed";;
        *.tar.bz2) tar -xjf "$srcpath" -C "$outdir" || die $E_GENERIC "tar xjf failed";;
        *.zip) unzip -q "$srcpath" -d "$outdir" || die $E_GENERIC "unzip failed";;
        *) if file "$srcpath" | grep -q 'gzip compressed'; then
             tar -xzf "$srcpath" -C "$outdir" || die $E_GENERIC "tar xzf failed"; fi;;
      esac
    else
      if [ -d "$srcpath" ]; then
        cp -a "$srcpath/." "$outdir/" || die $E_GENERIC "Failed to copy directory source"
      fi
    fi
  done
  return 0
}

# ---------- Patches ----------
apply_patches() {
  local pkg="$1" workdir="$2"
  for p in "${META_PATCHES[@]:-}"; do
    IFS='|||' read -r typ url pathp sha pstrip <<< "$p"
    local patchfile=""
    if [ "$typ" = "url" ]; then
      local filename
      filename="$(basename "$url")"
      patchfile="$CACHE_DIR/$pkg/$filename"
      if [ ! -f "$patchfile" ]; then
        mkdir -p "$(dirname "$patchfile")"
        if command -v curl >/dev/null 2>&1; then
          _download_with_curl "$url" "$patchfile" || return $E_DOWNLOAD
        else
          _download_with_wget "$url" "$patchfile" || return $E_DOWNLOAD
        fi
      fi
      if [ -n "$sha" ]; then
        verify_checksum "$patchfile" "$sha" || return $E_CHECKSUM
      fi
    elif [ "$typ" = "local" ]; then
      patchfile="$META_PKG_DIR/${pathp}"
      if [ ! -f "$patchfile" ]; then
        log ERROR "Local patch not found: $patchfile"
        return $E_MISSING
      fi
    else
      log ERROR "Unknown patch type: $typ"
      return $E_ARGS
    fi
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: would apply patch $patchfile (pstrip=$pstrip) in $workdir"
      continue
    fi
    log INFO "Applying patch $patchfile in $workdir"
    (cd "$workdir" && patch -p"${pstrip:-1}" < "$patchfile") || {
      log ERROR "Patch apply failed: $patchfile"
      return $E_PATCH
    }
  done
  return 0
}

# ---------- Hooks ----------
run_hook() {
  local hookpath="$1" stage="$2"
  if [ -z "$hookpath" ]; then
    return 0
  fi
  if [[ "$hookpath" != /* ]]; then
    hookpath="$META_PKG_DIR/$hookpath"
  fi
  if [ ! -f "$hookpath" ]; then
    log WARN "Hook not found: $hookpath"
    return 0
  fi
  if [ ! -x "$hookpath" ]; then
    if [ "$DRY_RUN" = false ]; then
      chmod +x "$hookpath" || log WARN "Could not chmod +x $hookpath"
    fi
  fi
  log INFO "Running hook $hookpath (stage=$stage)"
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: would execute $hookpath"
    return 0
  fi
  (
    set -euo pipefail
    export META_NAME META_VERSION META_CATEGORY META_INSTALL_ROOT META_BOOTSTRAP
    for kv in "${META_ENV_VARS[@]:-}"; do
      IFS='|||' read -r key val <<< "$kv"
      export "$key"="$val"
    done
    local OLD_PATH="$PATH"
    if [ -n "$META_PATH_PREPEND" ]; then
      export PATH="${META_PATH_PREPEND}:$PATH"
    fi
    if [ -n "$META_PATH_APPEND" ]; then
      export PATH="$PATH:${META_PATH_APPEND}"
    fi
    bash "$hookpath"
  )
  local rc=$?
  if [ $rc -ne 0 ]; then
    log ERROR "Hook failed: $hookpath (rc=$rc)"
    if [ "${META_HOOKS_IGNORE_ERRORS}" = "true" ]; then
      log WARN "Ignoring hook error as configured"
      return 0
    fi
    return $E_HOOK
  fi
  return 0
}

# ---------- Permissions ----------
set_permissions() {
  local path="$1" type="${2:-meta}"
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: would set permissions for $path type=$type"
    return 0
  fi
  case "$type" in
    meta)
      find "$path" -type d -exec chmod 0755 {} \; || true
      find "$path" -type f -name "*.ini" -exec chmod 0644 {} \; || true
      find "$path" -type f -path "*/hooks/*" -exec chmod 0755 {} \; || true
      ;;
    cache)
      find "$path" -type d -exec chmod 0755 {} \; || true
      find "$path" -type f -exec chmod 0644 {} \; || true
      ;;
    logs)
      find "$path" -type d -exec chmod 0755 {} \; || true
      find "$path" -type f -exec chmod 0644 {} \; || true
      ;;
    *)
      chmod -R 0755 "$path" || true
      ;;
  esac
}

# ---------- Check and Repair ----------
check_metafile() {
  local meta_path="$1"
  local errors=0
  INI=()
  if ! parse_ini "$meta_path"; then
    log ERROR "Failed to parse INI: $meta_path"
    return $E_PARSE
  fi
  local name version
  name=$(ini_get meta name "" ) || true
  version=$(ini_get meta version "" ) || true
  if [ -z "$name" ]; then
    log ERROR "$meta_path: missing meta.name"
    errors=$((errors+1))
  fi
  mapfile -t sidx < <(collect_ordered_entries source src)
  if [ "${#sidx[@]}" -eq 0 ] && [ -z "$(ini_get upstream check_url "")" ]; then
    log WARN "$meta_path: no source entries and no upstream specified"
  fi
  mapfile -t pidx < <(collect_ordered_entries patches patch)
  for idx in "${pidx[@]:-}"; do
    typ=$(ini_get patches patch${idx}.type "")
    if [ "$typ" = "local" ]; then
      ppath=$(ini_get patches patch${idx}.path "")
      if [ -z "$ppath" ]; then
        log ERROR "$meta_path: patch${idx}.path empty"
        errors=$((errors+1))
      else
        local fullp="$(dirname "$meta_path")/$ppath"
        if [ ! -f "$fullp" ]; then
          log ERROR "$meta_path: local patch missing: $fullp"
          errors=$((errors+1))
        fi
      fi
    fi
  done
  for hk in pre_download post_download pre_build post_build pre_install post_install; do
    hpath=$(ini_get hooks $hk "")
    if [ -n "$hpath" ]; then
      local fullh
      if [[ "$hpath" != /* ]]; then
        fullh="$(dirname "$meta_path")/$hpath"
      else
        fullh="$hpath"
      fi
      if [ ! -f "$fullh" ]; then
        log ERROR "$meta_path: hook missing: $fullh"
        errors=$((errors+1))
      elif [ ! -x "$fullh" ]; then
        log WARN "$meta_path: hook not executable: $fullh (can repair)"
      fi
    fi
  done
  for k in "${!INI[@]}"; do
    if [[ "$k" =~ ^environment\.(.+)$ ]]; then
      key="${BASH_REMATCH[1]}"
      if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_\.]*$ ]]; then
        log ERROR "$meta_path: invalid environment key: $key"
        errors=$((errors+1))
      fi
    fi
  done

  if [ $errors -ne 0 ]; then
    log ERROR "$meta_path: check finished with $errors errors"
    return $E_GENERIC
  fi
  log INFO "$meta_path: check OK"
  return 0
}

repair_metafile() {
  local meta_path="$1"
  local bak="${meta_path}.bak.$(date +%s)"
  if [ "$DRY_RUN" = false ]; then
    cp -a "$meta_path" "$bak" || log WARN "Could not backup $meta_path"
    log INFO "Backup saved to $bak"
  else
    log INFO "DRY-RUN: would backup $meta_path to $bak"
  fi
  local pkgdir
  pkgdir="$(dirname "$meta_path")"
  ensure_dir "$pkgdir/patches" 0755
  ensure_dir "$pkgdir/hooks" 0755
  ensure_dir "$pkgdir/files" 0755
  for hk in pre_download post_download pre_build post_build pre_install post_install; do
    hpath=$(ini_get hooks $hk "")
    if [ -n "$hpath" ]; then
      if [[ "$hpath" != /* ]]; then
        fullh="$pkgdir/$hpath"
      else
        fullh="$hpath"
      fi
      if [ -f "$fullh" ] && [ ! -x "$fullh" ]; then
        if [ "$DRY_RUN" = true ]; then
          log INFO "DRY-RUN: would chmod +x $fullh"
        else
          chmod +x "$fullh" || log WARN "Could not chmod +x $fullh"
          log INFO "Set +x on $fullh"
        fi
      fi
    fi
  done
  log INFO "Repair actions completed for $meta_path (limited set)"
  return 0
}

# ---------- Upstream check ----------
# upstream_check <meta_path> [--update]
# If --all is requested, caller will supply meta_path="__all__"
upstream_check_single() {
  local meta_path="$1"
  local do_update="${2:-false}"
  if [ ! -f "$meta_path" ]; then
    log ERROR "upstream_check: metafile not found: $meta_path"
    return $E_MISSING
  fi
  load_metafile "$meta_path"
  # read upstream fields
  local url regex type current
  url="$META_UPSTREAM_CHECK_URL"
  regex="$META_UPSTREAM_CHECK_REGEX"
  type="$META_UPSTREAM_CHECK_TYPE"
  current="$META_UPSTREAM_CURRENT_VERSION"
  if [ -z "$url" ] || [ -z "$regex" ]; then
    log WARN "upstream_check: missing check_url or check_regex in $meta_path"
    return $E_GENERIC
  fi
  # basic sanitization of regex: disallow backticks and command-substitution chars
  if echo "$regex" | grep -qE '[`$()]'; then
    log ERROR "upstream_check: unsafe regex detected in $meta_path; aborting"
    return $E_UPSTREAM
  fi
  log INFO "Checking upstream for $META_NAME using $url and regex"
  local html tmpout
  tmpout="$(mktemp "${TMPDIR}/upstream.XXXX")"
  # fetch page
  if command -v curl >/dev/null 2>&1; then
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: would curl -s --max-time $UPSTREAM_TIMEOUT $url"
      rm -f "$tmpout"
      return 0
    fi
    if ! curl -s --max-time "$UPSTREAM_TIMEOUT" -L "$url" -o "$tmpout"; then
      log ERROR "upstream_check: failed to fetch $url"
      rm -f "$tmpout" || true
      return $E_UPSTREAM
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: would wget -q -T $UPSTREAM_TIMEOUT -O - $url"
      rm -f "$tmpout"
      return 0
    fi
    if ! wget -q -T "$UPSTREAM_TIMEOUT" -O "$tmpout" "$url"; then
      log ERROR "upstream_check: failed to fetch $url"
      rm -f "$tmpout" || true
      return $E_UPSTREAM
    fi
  else
    log ERROR "upstream_check: neither curl nor wget available"
    return $E_UPSTREAM
  fi

  # extract candidate versions using regex
  # Use grep -Eo to get matches; ensure regex is used as extended regex
  local matches raw_versions newest
  # protect against extremely large pages
  head -c 200000 "$tmpout" > "${tmpout}.head" || true
  matches="$(grep -Eo "$regex" "${tmpout}.head" | sort -u || true)"
  rm -f "${tmpout}.head"
  rm -f "$tmpout" || true
  if [ -z "$matches" ]; then
    log WARN "upstream_check: no matches found at $url using regex"
    return $E_UPSTREAM
  fi
  # extract version substring from match using capture group if regex contains ()
  # If regex includes capture group, use perl to extract group 1; else use the full match
  raw_versions=()
  if echo "$regex" | grep -q '(' 2>/dev/null; then
    # Attempt to extract capture group 1 using perl-compatible regex
    while IFS= read -r m; do
      # use perl to extract capture if available
      if command -v perl >/dev/null 2>&1; then
        v=$(perl -ne 'if(/'"$regex"'/){ print $1,"\n"; exit }' <<< "$m" 2>/dev/null || true)
      else
        # fallback: attempt with sed to strip prefix/suffix (best-effort)
        v=$(echo "$m" | sed -E "s/$regex/\\1/" 2>/dev/null || true)
      fi
      if [ -n "$v" ]; then raw_versions+=("$v"); fi
    done <<< "$matches"
  else
    while IFS= read -r m; do raw_versions+=("$m"); done <<< "$matches"
  fi
  if [ "${#raw_versions[@]}" -eq 0 ]; then
    log WARN "upstream_check: could not extract versions with regex"
    return $E_UPSTREAM
  fi

  # choose newest using sort -V if available
  if command -v sort >/dev/null 2>&1 && sort -V </dev/null >/dev/null 2>&1 2>/dev/null; then
    newest=$(printf "%s\n" "${raw_versions[@]}" | sort -V | tail -n1)
  else
    newest=$(printf "%s\n" "${raw_versions[@]}" | sort | tail -n1)
  fi

  if [ -z "$newest" ]; then
    log WARN "upstream_check: no newest version determined"
    return $E_UPSTREAM
  fi

  log INFO "Upstream latest version for $META_NAME: $newest (current: $current)"
  if [ "$newest" != "$current" ]; then
    log INFO "Newer version available: $newest (current: $current)"
    if [ "$do_update" = true ]; then
      if [ "$DRY_RUN" = true ]; then
        log INFO "DRY-RUN: would update $meta_path: set upstream.current_version = $newest"
        return 0
      fi
      # update INI: replace or add upstream.current_version
      local content
      content="$(awk -v ver="$newest" -v section="upstream" '
        BEGIN{ins=1; insec=0}
        {
          if ($0 ~ /^[[:space:]]*\[.*\]/) {
            if (tolower($0) ~ "\\["section"\\]") { insec=1 } else { insec=0 }
          }
          if (insec==1 && $0 ~ /^[[:space:]]*current_version[[:space:]]*=.*/ ) {
            print "current_version = " ver
            ins=0
            next
          }
          print $0
        }
        END{
          if (ins==1) {
            print ""
            print "["section"]"
            print "current_version = " ver
          }
        }
      ' "$meta_path")"
      # write atomically with backup
      cp -a "$meta_path" "${meta_path}.bak.$(date +%s)" || true
      atomic_write_file "$meta_path" "$content"
      log INFO "Updated $meta_path with new upstream.current_version = $newest"
    fi
    return 0
  else
    log INFO "No update needed for $META_NAME"
    return 0
  fi
}

upstream_check_all() {
  local do_update="${1:-false}"
  local count=0
  shopt -s globstar nullglob
  for ini in "$META_DIR"/**/*.ini; do
    if [ -f "$ini" ]; then
      upstream_check_single "$ini" "$do_update" || log WARN "upstream_check failed for $ini"
      count=$((count+1))
    fi
  done
  shopt -u globstar nullglob
  if [ "$count" -eq 0 ]; then
    log WARN "No metafiles found under $META_DIR"
    return $E_MISSING
  fi
  return 0
}

# ---------- CLI and dispatch ----------
show_usage() {
  cat <<EOF
utils.sh - manage LFS sandbox metafiles and sources
Usage:
  utils.sh --create <category> <pkg> [--force]
  utils.sh --load <meta_path>
  utils.sh --fetch <meta_path> --out <workdir>
  utils.sh --apply-patches <meta_path> --workdir <workdir>
  utils.sh --check <meta_path> [--repair] [--dry-run]
  utils.sh --upstream-check <meta_path>|--all [--update] [--dry-run]
  utils.sh --set-perms <path> <type>
  common options:
    --require-checksum (default)
    --no-require-checksum
    --dry-run
    --verbose
    --log-file <path>
    --force
EOF
}

# Parse args
ARGS=("$@")
if [ "$#" -eq 0 ]; then show_usage; exit 0; fi
# defaults for upstream
UPSTREAM_CMD=""
UPSTREAM_UPDATE=false
UPSTREAM_ALL=false

while [ "${#ARGS[@]}" -gt 0 ]; do
  arg="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$arg" in
    --create) CMD="create"; CATEGORY="${ARGS[0]:-}"; PKG="${ARGS[1]:-}"; ARGS=("${ARGS[@]:2}");;
    --load) CMD="load"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --fetch) CMD="fetch"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --apply-patches) CMD="apply-patches"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --check) CMD="check"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --repair) DO_REPAIR=true;;
    --out) OUT_DIR="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --workdir) WORKDIR="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --require-checksum) REQUIRE_CHECKSUM=true;;
    --no-require-checksum) REQUIRE_CHECKSUM=false;;
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    --log-file) LOG_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --force) FORCE=true;;
    --upstream-check) UPSTREAM_CMD="single"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --all) UPSTREAM_ALL=true;;
    --update) UPSTREAM_UPDATE=true;;
    --help|-h) show_usage; exit 0;;
    *) echo "Unknown arg: $arg"; show_usage; exit $E_ARGS;;
  esac
done

# Load config
load_config

# Ensure log file exists
ensure_file "$LOG_FILE" 0644

# Dispatch commands
case "${CMD:-}" in
  create)
    if [ -z "${CATEGORY:-}" ] || [ -z "${PKG:-}" ]; then
      die $E_ARGS "create requires <category> <pkg>"
    fi
    create_metafile "$CATEGORY" "$PKG" "${FORCE}"
    ;;
  load)
    if [ -z "${META_PATH:-}" ]; then die $E_ARGS "load needs meta path"; fi
    load_metafile "$META_PATH"
    ;;
  fetch)
    if [ -z "${META_PATH:-}" ] || [ -z "${OUT_DIR:-}" ]; then die $E_ARGS "fetch needs meta path and --out"; fi
    META_PKG_DIR="$(cd "$(dirname "$META_PATH")" && pwd)"
    load_metafile "$META_PATH"
    mkdir -p "$OUT_DIR"
    fetch_all_sources "$META_NAME" "$OUT_DIR"
    ;;
  "apply-patches")
    if [ -z "${META_PATH:-}" ] || [ -z "${WORKDIR:-}" ]; then die $E_ARGS "apply-patches needs meta path and --workdir"; fi
    META_PKG_DIR="$(cd "$(dirname "$META_PATH")" && pwd)"
    load_metafile "$META_PATH"
    apply_patches "$META_NAME" "$WORKDIR"
    ;;
  check)
    if [ -z "${META_PATH:-}" ]; then die $E_ARGS "check needs meta path"; fi
    if [ "${DRY_RUN}" = true ]; then log INFO "Running in DRY-RUN mode"; fi
    if check_metafile "$META_PATH"; then
      if [ "${DO_REPAIR:-false}" = true ]; then
        repair_metafile "$META_PATH"
      fi
    else
      log ERROR "Check failed for $META_PATH"
      if [ "${DO_REPAIR:-false}" = true ]; then
        repair_metafile "$META_PATH"
      else
        log INFO "You can run --repair to attempt fixes"
      fi
    fi
    ;;
  "")
    ;;
  *)
    # if CMD empty, maybe upstream command requested
    if [ -n "$UPSTREAM_CMD" ] || [ "$UPSTREAM_ALL" = true ]; then
      if [ "$UPSTREAM_ALL" = true ]; then
        upstream_check_all "$UPSTREAM_UPDATE"
      else
        if [ -z "${META_PATH:-}" ]; then die $E_ARGS "--upstream-check requires a metafile path or use --all"; fi
        upstream_check_single "$META_PATH" "$UPSTREAM_UPDATE"
      fi
    else
      show_usage
    fi
    ;;
esac
