#!/usr/bin/env bash
# install.sh - Installer for Rolling LFS packages
# Features:
#  - Install from artifact (.tar.zst/.tar.xz/.tar.gz) or from build directory
#  - Pre/post hooks, check-only mode, --diff, strip ELF binaries, manifest, DB updates
#  - Robust error handling, trap, notify-send integration, rollback/backup
#  - Detailed logs and JSON/text reports
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Defaults & paths ----------
SANDBOX_SH="${SANDBOX_SH:-/mnt/data/sandbox.sh}"
LOG_DIR="${LOG_DIR:-/var/log/lfs-installer}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$HOME/lfs-sandbox/artifacts}"
BUILD_ROOT="${BUILD_ROOT:-$HOME/lfs-sandbox/build}"
DB_DIR="${DB_DIR:-/var/lib/lfsdb}"
BACKUP_DIR="${BACKUP_DIR:-/var/cache/lfs-backups}"
TMPDIR="${TMPDIR:-/tmp}"
DRY_RUN=false
VERBOSE=false
FORCE=false
CHECK_ONLY=false
DO_DIFF=false
NOTIFY=true
REPORT_JSON=false

mkdir -p "$LOG_DIR" "$ARTIFACTS_DIR" "$BUILD_ROOT" "$DB_DIR" "$BACKUP_DIR" "$TMPDIR"

# ---------- Logging helpers ----------
timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
logfile="$LOG_DIR/installer-$(date -u +%Y%m%dT%H%M%SZ).log"
_errlog="$LOG_DIR/installer-errors.log"

_log(){ local lvl="$1"; shift; printf "[%s] %s %s\n" "$lvl" "$(timestamp)" "$*" | tee -a "$logfile"; }
log_info(){ _log "INFO" "$*"; }
log_warn(){ _log "WARN" "$*"; }
log_error(){ _log "ERROR" "$*"; echo "[ERROR] $(timestamp) $*" >> "$_errlog"; }

notify() {
  local title="$1"; local body="$2"
  if [ "$NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1 && [ -n "${DISPLAY-}" ]; then
    notify-send --urgency=normal "$title" "$body" || true
  fi
  _log "NOTIFY" "$title - $body"
}

# ---------- Error handling ----------
handle_error(){
  local rc=${1:-1}; local cmd="${2:-unknown}"; local lineno=${3:-0}
  log_error "Error rc=$rc at line $lineno; cmd=${cmd}"
  notify "Install failed" "See $logfile"
  exit "$rc"
}
trap 'handle_error $? "$BASH_COMMAND" $LINENO' ERR INT TERM

# ---------- Utilities ----------
abspath(){ case "$1" in /*) printf "%s" "$1";; *) printf "%s" "$(pwd)/$1";; esac; }

atomic_write(){
  local file="$1"; shift; local tmp; tmp="$(mktemp "${TMPDIR}/.tmp.XXXX")"
  printf "%s" "$*" > "$tmp"
  mv -f "$tmp" "$file"
}

require_root(){
  if [ "$(id -u)" -ne 0 ]; then
    log_warn "Not running as root. Some install actions may fail."
  fi
}

ensure_space(){
  local target="${1:-/}"
  local need="${2:-0}"
  local avail; avail=$(df --output=avail -B1 "$target" 2>/dev/null | tail -n1 || echo 0)
  if [ "$avail" -lt "$need" ]; then
    log_error "Insufficient space on $target: need ${need} bytes, available $avail"
    return 1
  fi
  return 0
}

sha256_of_file(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else echo ""; fi }

# ---------- INI/simple metafile helpers ----------
declare -A META
parse_meta(){
  local meta="$1"
  META=()
  [ -f "$meta" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%[#;]*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
      key="$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]' | tr ' ' '_' )"
      val="${BASH_REMATCH[2]}"
      META["$key"]="$val"
    fi
  done < "$meta"
}

meta_get(){ local k="$1" d="${2:-}"; printf "%s" "${META[$k]:-$d}"; }

# ---------- Backup / rollback ----------
create_backup(){
  local target="$1"
  local tag="$2"
  local dest="$BACKUP_DIR/$(basename "$target")-${tag}-$(date -u +%Y%m%dT%H%M%SZ)"
  log_info "Creating backup of $target -> $dest"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN backup skipped"; echo "$dest"; return 0; fi
  mkdir -p "$dest"
  rsync -a --delete "$target"/ "$dest"/ || { log_error "Backup rsync failed"; return 1; }
  echo "$dest"
}

restore_backup(){
  local backup="$1" target="$2"
  log_warn "Restoring backup $backup -> $target"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN restore skipped"; return 0; fi
  rsync -a --delete "$backup"/ "$target"/ || { log_error "Restore rsync failed"; return 1; }
}

# ---------- Manifest & DB ----------
write_manifest(){
  local target="$1" manifestfile="$2"
  log_info "Writing manifest to $manifestfile"
  (cd "$target" && find . -type f -print0 | xargs -0 sha256sum > "$manifestfile") || return 1
}

update_db(){
  local name="$1" version="$2" origin="$3" manifest="$4"
  mkdir -p "$DB_DIR"
  local info="$DB_DIR/${name}-${version}.info"
  local tmp; tmp="$(mktemp "${TMPDIR}/.tmp.XXXX")"
  {
    echo "name=$name"
    echo "version=$version"
    echo "origin=$origin"
    echo "installed_at=$(timestamp)"
    echo "manifest=$manifest"
  } > "$tmp"
  mv -f "$tmp" "$info"
  log_info "DB updated: $info"
}

# ---------- Install helpers ----------
install_from_artifact(){
  local art="$1" target="$2" name="$3" version="$4"
  log_info "Installing from artifact $art to $target"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: would extract $art -> $target"; return 0; fi
  case "$art" in
    *.tar.zst) if command -v zstdcat >/dev/null 2>&1; then zstdcat "$art" | tar -x -C "$target"; else tar -I zstd -xf "$art" -C "$target"; fi ;;
    *.tar.xz) tar -xJf "$art" -C "$target" ;;
    *.tar.gz|*.tgz) tar -xzf "$art" -C "$target" ;;
    *) log_error "Unsupported artifact format: $art"; return 1 ;;
  esac
  return 0
}

install_from_builddir(){
  local builddir="$1" target="$2"
  log_info "Installing from build dir $builddir -> $target"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: would rsync $builddir -> $target"; return 0; fi
  rsync -a --delete "$builddir"/ "$target"/ || return 1
  return 0
}

# ---------- Strip ELF binaries ----------
do_strip(){
  local target="$1"
  log_info "Stripping ELF binaries under $target"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN strip skipped"; return 0; fi
  command -v strip >/dev/null 2>&1 || { log_warn "strip not found"; return 0; }
  while IFS= read -r -d '' f; do
    if file "$f" | grep -q 'ELF'; then
      strip --strip-unneeded "$f" || log_warn "strip failed for $f"
      echo "$f" >> "$LOG_DIR/strip-$(basename "$target").log"
    fi
  done < <(find "$target" -type f -print0)
}

# ---------- Diff helper ----------
do_diff(){
  local old="$1" new="$2" out="$3"
  log_info "Generating diff $out between $old and $new"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN diff skipped"; return 0; fi
  diff -ruN "$old" "$new" > "$out" 2>&1 || true
  log_info "Diff written: $out"
}

# ---------- Check-only mode ----------
check_only(){
  local source="$1" checksum_expected="$2"
  log_info "CHECK-ONLY: verifying source $source"
  if [ -f "$source" ]; then
    local calc; calc="$(sha256_of_file "$source")"
    if [ -n "$checksum_expected" ] && [ "$calc" != "$checksum_expected" ]; then
      log_error "Checksum mismatch in check-only: expected $checksum_expected got $calc"; return 2
    fi
    case "$source" in
      *.tar.*|*.tgz|*.zip)
        if ! tar -tf "$source" >/dev/null 2>&1; then log_error "Archive integrity test failed for $source"; return 3; fi
        ;;
    esac
    log_info "CHECK-ONLY: OK"
    return 0
  else
    log_error "CHECK-ONLY: source not found: $source"; return 1
  fi
}

# ---------- Main flow ----------
show_usage(){
  cat <<EOF
install.sh - install LFS packages
Usage:
  install.sh --meta <metafile.ini> [--target /] [--from-artifact <file>] [--from-build <dir>] [--dry-run] [--force] [--check-only] [--diff] [--no-notify] [--report-json]
Options:
  --meta <file>         metafile describing package (required)
  --target <dir>        where to install (default /)
  --from-artifact <f>   install from artifact file
  --from-build <d>      install from build directory
  --force               force overwrite/conflicts
  --check-only          validate artifact/build without installing
  --diff                generate diff against previous install (requires previous backup)
  --no-notify           disable notify-send
  --report-json         produce JSON report
EOF
}

# parse args
ARGS=("$@")
if [ "$#" -eq 0 ]; then show_usage; exit 0; fi
META_FILE=""
TARGET="/"
FROM_ART=""
FROM_BUILD=""
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --meta) META_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --target) TARGET="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --from-artifact) FROM_ART="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --from-build) FROM_BUILD="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    --force) FORCE=true;;
    --check-only) CHECK_ONLY=true;;
    --diff) DO_DIFF=true;;
    --no-notify) NOTIFY=false;;
    --report-json) REPORT_JSON=true;;
    --help) show_usage; exit 0;;
    *) echo "Unknown arg: $a"; show_usage; exit 2;;
  esac
done

# validate
if [ -z "$META_FILE" ] || [ ! -f "$META_FILE" ]; then log_error "Missing metafile"; show_usage; exit 2; fi
parse_meta "$META_FILE" || { log_error "Failed to parse metafile"; exit 2; }

NAME="$(meta_get name)"
VERSION="$(meta_get version)"
STRIP="$(meta_get strip true)"
PRE_HOOK="$(meta_get pre_install)"
POST_HOOK="$(meta_get post_install)"
ARTIFACT_SHA="$(meta_get artifact_sha256 "")"

if [ -z "$NAME" ] || [ -z "$VERSION" ]; then log_error "meta must contain name and version"; exit 2; fi

require_root

# check-only mode
if [ "$CHECK_ONLY" = true ]; then
  if [ -n "$FROM_ART" ]; then check_only "$FROM_ART" "$ARTIFACT_SHA"; exit $?; fi
  if [ -n "$FROM_BUILD" ]; then
    if [ ! -d "$FROM_BUILD" ]; then log_error "Build dir not found"; exit 3; fi
    log_info "CHECK-ONLY: build dir looks present"
    exit 0
  fi
  log_error "CHECK-ONLY: no source specified"; exit 2
fi

# backup current target for rollback/diff
BACKUP_PATH=""
if [ -d "$TARGET" ]; then
  BACKUP_PATH="$(create_backup "$TARGET" "${NAME}-${VERSION}")" || { log_error "Backup creation failed"; exit 1; }
fi

# pre-install hook
if [ -n "$PRE_HOOK" ] && [ -f "$(dirname "$META_FILE")/$PRE_HOOK" ]; then
  log_info "Running pre_install hook $PRE_HOOK"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN hook skipped"; else
    if ! bash "$(dirname "$META_FILE")/$PRE_HOOK" >> "$logfile" 2>&1; then
      log_error "pre_install hook failed"
      if [ "$FORCE" != true ]; then restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 1; fi
    fi
  fi
fi

# choose and perform installation
if [ -n "$FROM_ART" ]; then
  if [ ! -f "$FROM_ART" ]; then log_error "Artifact not found: $FROM_ART"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 2; fi
  if [ -n "$ARTIFACT_SHA" ]; then
    calc="$(sha256_of_file "$FROM_ART")"
    if [ -n "$calc" ] && [ "$calc" != "$ARTIFACT_SHA" ]; then log_error "Artifact checksum mismatch"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 3; fi
  fi
  if ! install_from_artifact "$FROM_ART" "$TARGET" "$NAME" "$VERSION"; then log_error "Artifact install failed"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 4; fi
elif [ -n "$FROM_BUILD" ]; then
  if [ ! -d "$FROM_BUILD" ]; then log_error "Build dir not found: $FROM_BUILD"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 5; fi
  if ! install_from_builddir "$FROM_BUILD" "$TARGET"; then log_error "Install from builddir failed"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 6; fi
else
  candidate="$ARTIFACTS_DIR/${NAME}-${VERSION}.tar.zst"
  if [ -f "$candidate" ]; then
    log_info "Found artifact $candidate"
    if ! install_from_artifact "$candidate" "$TARGET" "$NAME" "$VERSION"; then log_error "Artifact install failed"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 7; fi
  else
    log_error "No source specified and no artifact found ($candidate)"; restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 8
  fi
fi

# strip binaries
if [ "${STRIP:-true}" = "true" ]; then
  do_strip "$TARGET" || log_warn "Strip encountered issues"
fi

# manifest & DB update
MANIFEST="$DB_DIR/${NAME}-${VERSION}.manifest"
write_manifest "$TARGET" "$MANIFEST" || log_warn "Manifest write failed"
update_db "$NAME" "$VERSION" "${FROM_ART:-$FROM_BUILD}" "$MANIFEST" || log_warn "DB update failed"

# diff if requested
if [ "$DO_DIFF" = true ] && [ -n "$BACKUP_PATH" ]; then
  DIFF_OUT="$LOG_DIR/${NAME}-${VERSION}.diff"
  do_diff "$BACKUP_PATH" "$TARGET" "$DIFF_OUT"
fi

# post-install hook
if [ -n "$POST_HOOK" ] && [ -f "$(dirname "$META_FILE")/$POST_HOOK" ]; then
  log_info "Running post_install hook $POST_HOOK"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN post hook skipped"; else
    if ! bash "$(dirname "$META_FILE")/$POST_HOOK" >> "$logfile" 2>&1; then
      log_error "post_install hook failed"
      if [ "$FORCE" != true ]; then restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 1; fi
    fi
  fi
fi

# final report
REPORT_TXT="$LOG_DIR/report-${NAME}-${VERSION}.txt"
{
  echo "report_generated: $(timestamp)"
  echo "package: $NAME"
  echo "version: $VERSION"
  echo "target: $TARGET"
  echo "backup: $BACKUP_PATH"
  echo "manifest: $MANIFEST"
  echo "status: success"
} > "$REPORT_TXT"
log_info "Installation complete: $NAME $VERSION"
notify "Install complete" "$NAME $VERSION"

if [ "$REPORT_JSON" = true ]; then
  JSON_OUT="$LOG_DIR/report-${NAME}-${VERSION}.json"
  cat > "$JSON_OUT" <<EOF
{
  "generated":"$(timestamp)",
  "package":"$NAME",
  "version":"$VERSION",
  "target":"$TARGET",
  "backup":"$BACKUP_PATH",
  "manifest":"$MANIFEST",
  "status":"success"
}
EOF
  log_info "JSON report: $JSON_OUT"
fi

exit 0
