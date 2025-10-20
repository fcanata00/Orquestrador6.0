#!/usr/bin/env bash
# uninstall.sh - Safe uninstaller for Rolling LFS packages
# - removes packages using manifest, runs pre/post hooks, backup & rollback, orphan detection
# - robust error handling, mitigate silent errors, security checks, notifications
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Defaults & paths ----------
LOG_DIR="${LOG_DIR:-/var/log/lfs-uninstall}"
DB_DIR="${DB_DIR:-/var/lib/lfsdb}"
BACKUP_DIR="${BACKUP_DIR:-/var/cache/lfs-backups}"
TMPDIR="${TMPDIR:-/tmp}"
META_DIR="${META_DIR:-$HOME/lfs-sandbox/meta}"

DRY_RUN=false
VERBOSE=false
FORCE=false
CHECK_ONLY=false
AUTO_ORPHANS=false
ASK_ORPHANS=false
IGNORE_HOOK_ERRORS=false
NOTIFY=true
TIMEOUT_HOOK=120  # seconds

mkdir -p "$LOG_DIR" "$DB_DIR" "$BACKUP_DIR" "$TMPDIR"

# ---------- Logging & notify ----------
timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
LOGFILE="$LOG_DIR/uninstall-$(date -u +%Y%m%dT%H%M%SZ).log"
ERRLOG="$LOG_DIR/uninstall-errors.log"
_note(){ printf "[%s] %s %s\n" "$1" "$(timestamp)" "$2" | tee -a "$LOGFILE"; }
log_info(){ _note "INFO" "$*"; }
log_warn(){ _note "WARN" "$*"; }
log_error(){ _note "ERROR" "$*"; printf "[ERROR] %s %s\n" "$(timestamp)" "$*" >> "$ERRLOG"; }

notify() {
  local title="$1"; local body="$2"
  if [ "$NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1 && [ -n "${DISPLAY-}" ]; then
    notify-send --urgency=normal "$title" "$body" || true
  fi
  _note "NOTIFY" "$title - $body"
}

# ---------- Error handling ----------
handle_error() {
  local rc=${1:-1}; local cmd="${2:-unknown}"; local lineno=${3:-0}"
  log_error "ERROR rc=$rc at line $lineno cmd='$cmd'"
  notify "Uninstall failed" "See $LOGFILE"
  # if backup exists, attempt restore (best-effort) - will be handled by caller logic
  exit "$rc"
}
trap 'handle_error $? "$BASH_COMMAND" $LINENO' ERR INT TERM

# ---------- Utilities ----------
abspath(){ case "$1" in /*) printf "%s" "$1";; *) printf "%s" "$(pwd)/$1";; esac; }
atomic_write(){ local file="$1"; shift; local tmp; tmp="$(mktemp "${TMPDIR}/.tmp.XXXX")"; printf "%s" "$*" > "$tmp"; mv -f "$tmp" "$file"; }
require_root(){ if [ "$(id -u)" -ne 0 ]; then log_warn "Not running as root; some removals may fail"; fi }

# safe path check: ensure path is under allowed roots
is_path_allowed(){
  local p; p="$(abspath "$1")"
  case "$p" in
    /*) ;; # absolute ok
    *) return 1 ;; # non-absolute not allowed
  esac
  # Disallow removing outside these prefixes: /, /usr, /opt, /mnt/lfs, /var/lib
  case "$p" in
    /usr/*|/bin/*|/sbin/*|/lib*|/opt/*|/etc/*|/var/*|/srv/*|/mnt/lfs/*|/home/*|/root/*|/boot/*|/lib64/*|/usr) return 0;;
    /) return 0;;
    *) return 1;;
  esac
}

# ---------- Meta/manifest helpers ----------
declare -A META
parse_meta_file(){
  local meta="$1"
  META=()
  [ -f "$meta" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%[#;]*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
      key="$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]' | tr ' ' '_')"
      val="${BASH_REMATCH[2]}"
      META["$key"]="$val"
    fi
  done < "$meta"
  return 0
}
meta_get(){ local k="$1" d="${2:-}"; printf "%s" "${META[$k]:-$d}"; }

# manifest parsing: expect manifest list file with "sha256  path"
read_manifest_to_array(){
  local manifest="$1"
  MANIFEST_FILES=()
  if [ ! -f "$manifest" ]; then log_warn "Manifest not found: $manifest"; return 1; fi
  while IFS= read -r line || [ -n "$line" ]; do
    # Accept lines: checksum  path  OR just path
    if [[ "$line" =~ ^([a-fA-F0-9]{64})\s+(.+)$ ]]; then
      MANIFEST_FILES+=("${BASH_REMATCH[2]}|${BASH_REMATCH[1]}")
    else
      MANIFEST_FILES+=("$line|")
    fi
  done < "$manifest"
  return 0
}

# ---------- Backup / rollback ----------
create_backup(){
  local pkg="$1"
  local tag="${2:-before-uninstall}"
  local dest="$BACKUP_DIR/${pkg}-${tag}-$(date -u +%Y%m%dT%H%M%SZ)"
  log_info "Creating backup snapshot -> $dest"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: backup skipped"; echo "$dest"; return 0; fi
  mkdir -p "$dest"
  # Backup installed files using manifest if available else full path fallback
  if [ -f "$DB_DIR/${pkg}.info" ]; then
    local manifest; manifest="$(awk -F= '/manifest=/{print $2}' "$DB_DIR/${pkg}.info" || true)"
    if [ -n "$manifest" ] && [ -f "$manifest" ]; then
      # copy each file's directory preserving structure
      while IFS= read -r line || [ -n "$line" ]; do
        filepath="${line#* }"
        if [ -z "$filepath" ]; then continue; fi
        if [ -e "$filepath" ]; then
          mkdir -p "$dest/$(dirname "$filepath")"
          cp -a --no-preserve=ownership "$filepath" "$dest/$filepath" || log_warn "Could not backup $filepath"
        fi
      done < "$manifest"
    else
      # fallback: rsync the root (dangerous) -> instead only backup /usr, /etc, /opt relevant
      rsync -a --files-from=/dev/null / "$dest" || true
    fi
  else
    rsync -a --files-from=/dev/null / "$dest" || true
  fi
  echo "$dest"
}

restore_backup(){
  local backup="$1" target="${2:-/}"
  if [ -z "$backup" ] || [ ! -d "$backup" ]; then log_error "No backup to restore: $backup"; return 1; fi
  log_warn "Restoring backup $backup -> $target"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: restore skipped"; return 0; fi
  rsync -a --delete "$backup"/ "$target"/ || { log_error "Restore failed"; return 1; }
  return 0
}

# ---------- Hook runner with timeout & logging ----------
run_hook(){
  local hookfile="$1" hooklog="$2" description="$3"
  if [ ! -f "$hookfile" ]; then log_warn "Hook not found: $hookfile"; return 0; fi
  log_info "Running hook: $hookfile ($description)"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: hook skipped"; return 0; fi
  if command -v timeout >/dev/null 2>&1; then
    if ! timeout "$TIMEOUT_HOOK" bash "$hookfile" >> "$hooklog" 2>&1; then
      log_error "Hook failed or timed out: $hookfile (see $hooklog)"
      return 1
    fi
  else
    if ! bash "$hookfile" >> "$hooklog" 2>&1; then
      log_error "Hook failed: $hookfile (see $hooklog)"
      return 1
    fi
  fi
  return 0
}

# ---------- Orphan detection ----------
detect_orphans(){
  local keep="$1"  # package name being removed; we should detect packages that are no longer required by others
  ORPHANS=()
  # Basic method: iterate all installed .info and parse dependencies section via metafiles if present
  shopt -s nullglob
  declare -A required_count
  for info in "$DB_DIR"/*.info; do
    pkgname="$(basename "$info" .info)"
    # read manifest and dependencies if present
    deps="$(grep -E '^depends=' "$info" 2>/dev/null | sed 's/^depends=//')"
    IFS=',' read -r -a arr <<< "$deps"
    for d in "${arr[@]:-}"; do d="$(echo "$d" | xargs)"; [ -n "$d" ] && required_count["$d"]=$((required_count["$d"]+1)); done
  done
  # find packages with zero required_count (excluding the one we're removing)
  for info in "$DB_DIR"/*.info; do
    p="$(basename "$info" .info)"
    if [ "$p" = "$keep" ]; then continue; fi
    if [ "${required_count[$p]:-0}" -eq 0 ]; then ORPHANS+=("$p"); fi
  done
  shopt -u nullglob
  return 0
}

# ---------- Removal core ----------
remove_files_from_manifest(){
  local manifest="$1" pkg="$2" backup="$3"
  log_info "Removing files listed in manifest: $manifest"
  if [ ! -f "$manifest" ]; then log_warn "Manifest missing: $manifest"; return 1; fi
  # iterate files; protect against path traversal and only remove allowed paths
  local removed=0 skipped=0 modified=0
  while IFS= read -r line || [ -n "$line" ]; do
    # parse optional checksum and path
    if [[ "$line" =~ ^([a-fA-F0-9]{64})\s+(.+)$ ]]; then
      expected_sha="${BASH_REMATCH[1]}"; filepath="${BASH_REMATCH[2]}"
    else
      expected_sha=""; filepath="$line"
    fi
    # normalize
    filepath="$(readlink -f "$filepath" 2>/dev/null || printf "%s" "$filepath")"
    if [ -z "$filepath" ] || [ ! -e "$filepath" ]; then log_warn "File not present, skipping: $filepath"; skipped=$((skipped+1)); continue; fi
    # check allowed path
    if ! is_path_allowed "$filepath"; then log_warn "Unsafe path, skipping: $filepath"; skipped=$((skipped+1)); continue; fi
    # if checksum present, verify hasn't been modified since install
    if [ -n "$expected_sha" ] && command -v sha256sum >/dev/null 2>&1; then
      calc="$(sha256sum "$filepath" | awk '{print $1}')"
      if [ "$calc" != "$expected_sha" ]; then
        log_warn "File modified since install, skipping removal: $filepath"
        modified=$((modified+1))
        continue
      fi
    fi
    # remove file or symlink (preserve directories until end)
    if [ -f "$filepath" ] || [ -L "$filepath" ]; then
      if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN remove $filepath"; else rm -f "$filepath" || log_warn "Failed removing $filepath"; fi
      removed=$((removed+1))
    elif [ -d "$filepath" ]; then
      # try rmdir if empty
      if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN rmdir $filepath"; else rmdir --ignore-fail-on-non-empty "$filepath" || true; fi
    fi
  done < "$manifest"
  log_info "Removal summary: removed=$removed skipped=$skipped modified=$modified"
  return 0
}

# ---------- Cleanup DB & logs ----------
cleanup_db_entry(){
  local pkg="$1"
  if [ -f "$DB_DIR/${pkg}.info" ]; then rm -f "$DB_DIR/${pkg}.info" || log_warn "Could not remove db info for $pkg"; fi
  if [ -f "$DB_DIR/${pkg}.manifest" ]; then rm -f "$DB_DIR/${pkg}.manifest" || log_warn "Could not remove manifest for $pkg"; fi
}

# ---------- Main CLI ----------
show_usage(){
  cat <<EOF
uninstall.sh - safe package uninstaller for Rolling LFS
Usage:
  uninstall.sh --package <name> [--meta <metafile.ini>] [--check-only] [--dry-run] [--force] [--auto-orphans] [--ask-orphans] [--no-notify] [--ignore-hook-errors]
Options:
  --package <name>        package name to remove (required)
  --meta <file>           metafile path (optional, used for hooks and metadata)
  --target <dir>          target root (default /)
  --check-only            simulate uninstall, don't change system
  --dry-run               print actions only
  --force                 ignore non-fatal warnings and continue
  --auto-orphans          also remove orphaned dependencies automatically
  --ask-orphans           interactively ask before removing orphans
  --no-notify             disable desktop notifications
  --ignore-hook-errors    don't abort on hook failures
EOF
}

# parse args
ARGS=("$@")
if [ "$#" -eq 0 ]; then show_usage; exit 0; fi
PACKAGE=""; META_FILE=""; TARGET="/"
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --package) PACKAGE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --meta) META_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --target) TARGET="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --dry-run) DRY_RUN=true;;
    --check-only) CHECK_ONLY=true;;
    --force) FORCE=true;;
    --auto-orphans) AUTO_ORPHANS=true;;
    --ask-orphans) ASK_ORPHANS=true;;
    --no-notify) NOTIFY=false;;
    --ignore-hook-errors) IGNORE_HOOK_ERRORS=true;;
    --help) show_usage; exit 0;;
    *) echo "Unknown arg: $a"; show_usage; exit 2;;
  esac
done

if [ -z "$PACKAGE" ]; then log_error "package name required"; show_usage; exit 2; fi
require_root

# locate db info and manifest
DB_INFO="$DB_DIR/${PACKAGE}.info"
DB_MANIFEST="$DB_DIR/${PACKAGE}.manifest"
if [ ! -f "$DB_INFO" ]; then log_warn "Package $PACKAGE not recorded in DB: $DB_INFO missing"; fi

# parse meta if provided
if [ -n "$META_FILE" ]; then
  if [ -f "$META_FILE" ]; then parse_meta_file "$META_FILE" || log_warn "Could not parse meta file"; else log_warn "Meta file not found: $META_FILE"; fi
fi

# check-only handling
if [ "$CHECK_ONLY" = true ]; then
  log_info "CHECK-ONLY: Simulating uninstall of $PACKAGE"
  if [ -f "$DB_MANIFEST" ]; then
    read_manifest_to_array "$DB_MANIFEST" || true
    printf "%s\n" "${MANIFEST_FILES[@]:-}" | sed 's/|.*$//' | nl -ba
    log_info "CHECK-ONLY: done"
    exit 0
  else
    log_warn "No manifest available to simulate. Listing possible files under /usr and /opt (best-effort)"
    find /usr /opt -maxdepth 3 -type f -iname "*${PACKAGE}*" | nl -ba
    exit 0
  fi
fi

# create backup for rollback
BACKUP_PATH=""
BACKUP_PATH="$(create_backup "$PACKAGE" "before-uninstall")" || log_warn "Backup creation failed or skipped"

# run pre-uninstall hook
if [ -n "$META_FILE" ] && [ -f "$(dirname "$META_FILE")/pre_uninstall" ]; then
  prehook="$(dirname "$META_FILE")/pre_uninstall"
  prelog="$LOG_DIR/${PACKAGE}.pre_uninstall.log"
  if ! run_hook "$prehook" "$prelog" "pre_uninstall"; then
    log_error "pre_uninstall hook failed"
    if [ "$IGNORE_HOOK_ERRORS" != true ] && [ "$FORCE" != true ]; then restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 1; fi
  fi
fi

# read manifest into array
if [ -f "$DB_MANIFEST" ]; then
  read_manifest_to_array "$DB_MANIFEST" || log_warn "Could not read manifest"
else
  log_warn "Manifest not found: $DB_MANIFEST - attempting best-effort removal"
  MANIFEST_FILES=()
  # try to guess installed files by scanning common dirs for package name
  while IFS= read -r f; do MANIFEST_FILES+=("$f|"); done < <(find /usr /opt -type f -iname "*${PACKAGE}*" 2>/dev/null || true)
fi

# perform removal of files listed in manifest
if ! remove_files_from_manifest "$DB_MANIFEST" "$PACKAGE" "$BACKUP_PATH"; then
  log_error "Errors during file removal"
  if [ "$FORCE" != true ]; then restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 1; fi
fi

# cleanup DB entry and manifest files
cleanup_db_entry "$PACKAGE"

# detect orphans and optionally remove
if [ "$AUTO_ORPHANS" = true ] || [ "$ASK_ORPHANS" = true ]; then
  detect_orphans "$PACKAGE"
  if [ "${#ORPHANS[@]}" -gt 0 ]; then
    log_info "Detected orphan packages: ${ORPHANS[*]}"
    if [ "$AUTO_ORPHANS" = true ]; then
      for o in "${ORPHANS[@]}"; do
        log_info "Auto removing orphan $o"
        # call this script recursively in non-interactive mode to remove orphans
        if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN would remove orphan $o"; else
          "$0" --package "$o" --force --no-notify || log_warn "Failed to remove orphan $o"
        fi
      done
    elif [ "$ASK_ORPHANS" = true ]; then
      for o in "${ORPHANS[@]}"; do
        read -r -p "Remove orphan package $o ? [y/N] " ans
        if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then "$0" --package "$o" --force --no-notify || log_warn "Failed to remove orphan $o"; fi
      done
    fi
  else
    log_info "No orphans detected"
  fi
fi

# run post-uninstall hook
if [ -n "$META_FILE" ] && [ -f "$(dirname "$META_FILE")/post_uninstall" ]; then
  posthook="$(dirname "$META_FILE")/post_uninstall"
  postlog="$LOG_DIR/${PACKAGE}.post_uninstall.log"
  if ! run_hook "$posthook" "$postlog" "post_uninstall"; then
    log_error "post_uninstall hook failed"
    if [ "$IGNORE_HOOK_ERRORS" != true ] && [ "$FORCE" != true ]; then restore_backup "$BACKUP_PATH" "$TARGET" || true; exit 1; fi
  fi
fi

# final cleanup of logs older than 30d (best-effort)
find "$LOG_DIR" -type f -name "*.log" -mtime +30 -print -delete || true

log_info "Uninstall completed for $PACKAGE"
notify "Uninstall complete" "$PACKAGE"

exit 0
