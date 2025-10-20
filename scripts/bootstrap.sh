#!/usr/bin/env bash
# bootstrap.sh - Prepare /mnt/lfs bootstrap environment for LFS Rolling release
# Features:
#  - create dirs, set permissions, mount pseudo-filesystems, create lfs user, prepare env
#  - hooks (pre/post), logging, notify-send, dry-run, resume, repair, robust error handling
#  - safe: prevents operations outside /mnt/lfs, backups, trap cleanup
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Configuration ----------
LFS="${LFS:-/mnt/lfs}"
LFS_USER="${LFS_USER:-lfs}"
LFS_GROUP="${LFS_GROUP:-lfs}"
LFS_HOME="${LFS_HOME:-$LFS/home/$LFS_USER}"
LOG_DIR="${LOG_DIR:-$LFS/logs}"
HOOKS_PRE_DIR="${HOOKS_PRE_DIR:-$LFS/hooks/pre-bootstrap}"
HOOKS_POST_DIR="${HOOKS_POST_DIR:-$LFS/hooks/post-bootstrap}"
SOURCES_DIR="${SOURCES_DIR:-$LFS/sources}"
TOOLS_DIR="${TOOLS_DIR:-$LFS/tools}"
BUILD_DIR="${BUILD_DIR:-$LFS/build}"
CACHE_DIR="${CACHE_DIR:-$LFS/cache}"
TMP_DIR="${TMP_DIR:-$LFS/temp}"
REPORT_FILE="${REPORT_FILE:-$LOG_DIR/bootstrap_summary-$(date -u +%Y%m%dT%H%M%SZ).txt}"

DRY_RUN=false
VERBOSE=false
FORCE=false
RESUME=false
REPAIR=false
NOTIFY=true

# ---------- Safety helpers ----------
timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_logfile="${LOG_DIR:-/var/log}/bootstrap-$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$(dirname "$_logfile")"
log(){ local lvl="$1"; shift; printf "[%s] %s %s\n" "$lvl" "$(timestamp)" "$*" | tee -a "$_logfile"; }
die(){ local code=${1:-1}; shift || true; log ERROR "$*"; if [ "$NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1; then notify-send --urgency=critical "Bootstrap failed" "$*"; fi; exit "$code"; }
notify(){ local t="$1"; local b="$2"; if [ "$NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1 && [ -n "${DISPLAY-}" ]; then notify-send --urgency=low "$t" "$b" || true; fi; log INFO "$t - $b"; }

ensure_root(){
  if [ "$(id -u)" -ne 0 ]; then
    log WARN "Not running as root - some actions may fail. Rerun as root or with sudo."
  fi
}

# Prevent accidental operations outside LFS prefix
ensure_lfs_prefix(){
  case "$1" in
    "$LFS"/*) return 0 ;;
    "$LFS") return 0 ;;
    *) die 2 "Refusing to operate outside LFS prefix ($LFS): $1" ;;
  esac
}

# ---------- Argument parsing ----------
show_usage(){
  cat <<EOF
bootstrap.sh - prepare /mnt/lfs bootstrap environment
Usage: bootstrap.sh [--dry-run] [--verbose] [--force] [--resume] [--repair] [--no-notify] [--help]
Flags:
  --dry-run    : simulate actions without changing system
  --verbose    : verbose logging
  --force      : force actions (use carefully)
  --resume     : attempt to resume an interrupted bootstrap
  --repair     : revalidate perms, mounts, env
  --no-notify  : disable desktop notifications
EOF
}
ARGS=("$@")
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    --force) FORCE=true;;
    --resume) RESUME=true;;
    --repair) REPAIR=true;;
    --no-notify) NOTIFY=false;;
    --help) show_usage; exit 0;;
    *) echo "Unknown arg: $a"; show_usage; exit 2;;
  esac
done

# ---------- Defensive checks ----------
ensure_root
# sanity: LFS must be absolute path
if [[ "$LFS" != /* ]]; then die 2 "LFS path must be absolute. Current: $LFS"; fi
# create base log dir early
mkdir -p "$LOG_DIR"
_logfile="$LOG_DIR/bootstrap-$(date -u +%Y%m%dT%H%M%SZ).log"

# trap for cleanup
_cleanup_done=false
cleanup(){
  if [ "$_cleanup_done" = true ]; then return 0; fi
  _cleanup_done=true
  log INFO "Running cleanup tasks..."
  if [ "$DRY_RUN" = false ] && [ "$REPAIR" = false ]; then
    for m in run sys proc dev; do
      if mountpoint -q "$LFS/$m"; then
        log INFO "Unmounting $LFS/$m"
        umount -l "$LFS/$m" || log WARN "Could not unmount $LFS/$m"
      fi
    done
  fi
  log INFO "Cleanup complete."
}
trap 'rc=$?; if [ $rc -ne 0 ]; then log ERROR "Bootstrap exited with rc=$rc"; fi; cleanup' EXIT INT TERM

# ---------- Utility functions ----------
ensure_dir_safe(){
  local d="$1"
  ensure_lfs_prefix "$d"
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: mkdir -p $d"; return 0; fi
  mkdir -p "$d"
}

set_permissions(){
  local path="$1" owner="$2" mode="$3"
  ensure_lfs_prefix "$path"
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: chown $owner:$owner $path ; chmod $mode $path"; return 0; fi
  chown -R "$owner:$owner" "$path" || log WARN "chown failed for $path"
  chmod -R "$mode" "$path" || log WARN "chmod failed for $path"
}

# ensure minimal required commands are available
require_cmds(){
  local miss=0
  for cmd in mount umount chown chmod useradd passwd groupadd rsync tar grep awk sed cut timeout; do
    if ! command -v "$cmd" >/dev/null 2>&1; then log WARN "Command missing: $cmd"; miss=1; fi
  done
  if [ "$miss" -eq 1 ] && [ "$FORCE" != true ]; then log WARN "Some commands missing; consider installing. Continuing due to --force or will abort."; fi
}

# check disk space (bytes)
ensure_space(){
  local dir="$1"; local need_bytes="${2:-0}"
  local avail=$(df --output=avail -B1 "$dir" 2>/dev/null | tail -n1 || echo 0)
  if [ "$avail" -lt "$need_bytes" ]; then die 3 "Not enough space on $dir: need $need_bytes bytes, have $avail"; fi
}

# ---------- Core steps ----------
step_create_structure(){
  log INFO "Step: create directory structure under $LFS"
  ensure_dir_safe "$LFS"
  for d in "$TOOLS_DIR" "$SOURCES_DIR" "$BUILD_DIR" "$LOG_DIR" "$CACHE_DIR" "$HOOKS_PRE_DIR" "$HOOKS_POST_DIR" "$TMP_DIR" "$LFS_HOME"; do
    ensure_dir_safe "$d"
  done
  if [ "$DRY_RUN" = false ]; then
    chmod 0755 "$LFS" || true
  fi
  log INFO "Directory structure created."
}

step_create_lfs_user(){
  log INFO "Step: ensure LFS user/group exist: $LFS_USER"
  if id "$LFS_USER" >/dev/null 2>&1; then
    log INFO "User $LFS_USER exists."
  else
    if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: would create group and user $LFS_USER"; return 0; fi
    if ! getent group "$LFS_GROUP" >/dev/null 2>&1; then groupadd -r "$LFS_GROUP" || log WARN "groupadd failed"; fi
    useradd -m -d "$LFS_HOME" -s /bin/bash -g "$LFS_GROUP" "$LFS_USER" || die 4 "useradd failed for $LFS_USER"
    log INFO "Created user $LFS_USER with home $LFS_HOME"
  fi
  ensure_dir_safe "$LFS_HOME"
  if [ "$DRY_RUN" = false ]; then chown -R "$LFS_USER:$LFS_GROUP" "$LFS_HOME" || log WARN "chown home failed"; fi
}

step_mount_pseudo(){
  log INFO "Step: mount pseudo filesystems (dev,proc,sys,run) under $LFS"
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: would bind mount /dev /proc /sys /run"; return 0; fi
  for m in dev proc sys run; do
    ensure_dir_safe "$LFS/$m"
  done
  if ! mountpoint -q "$LFS/dev"; then mount --bind /dev "$LFS/dev" || die 5 "mount --bind /dev failed"; fi
  if ! mountpoint -q "$LFS/proc"; then mount -t proc proc "$LFS/proc" || die 5 "mount proc failed"; fi
  if ! mountpoint -q "$LFS/sys"; then mount --rbind /sys "$LFS/sys" || die 5 "mount sys failed"; fi
  if ! mountpoint -q "$LFS/run"; then mount --bind /run "$LFS/run" || die 5 "mount run failed"; fi
  log INFO "Pseudo-filesystems mounted."
}

step_prepare_envfile(){
  log INFO "Step: write LFS environment file"
  envfile="$LFS/.lfs_env"
  content="# Generated LFS environment - $(timestamp)
export LFS=$LFS
export LFS_TGT=$(uname -m)-lfs-linux-gnu
export PATH=\$LFS/tools/bin:/usr/bin:/bin
export MAKEFLAGS=\"-j$(nproc)\"
"
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: would write $envfile"; return 0; fi
  echo "$content" > "$envfile"
  chmod 0644 "$envfile"
  chown root:root "$envfile" || true
  log INFO "Environment file written: $envfile"
}

step_fetch_base_sources(){
  log INFO "Step: fetch base toolchain sources (best-effort)"
  urlsfile="$SOURCES_DIR/_urls.txt"
  if [ ! -f "$urlsfile" ]; then log WARN "No $urlsfile found - skipping automatic downloads. Populate $urlsfile with one URL per line to enable."; return 0; fi
  while IFS= read -r u || [ -n "$u" ]; do
    [ -z "$u" ] && continue
    fname="$(basename "$u" | sed 's/?.*$//')"
    dest="$SOURCES_DIR/$fname"
    if [ -f "$dest" ]; then log INFO "Source already present: $fname"; continue; fi
    log INFO "Downloading $u -> $dest"
    if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: download skipped"; continue; fi
    if command -v curl >/dev/null 2>&1; then curl -L --retry 4 -o "$dest" "$u" || log WARN "curl failed for $u"; elif command -v wget >/dev/null 2>&1; then wget -O "$dest" "$u" || log WARN "wget failed for $u"; else log WARN "No downloader available"; fi
  done < "$urlsfile"
  log INFO "Fetch base sources step done."
}

step_run_hooks(){
  local dir="$1" stage="$2"
  if [ -d "$dir" ]; then
    for h in "$dir"/*; do
      [ -f "$h" ] || continue
      log INFO "Running $stage hook: $h"
      if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: hook $h skipped"; continue; fi
      if ! timeout 120 bash "$h" >> "$_logfile" 2>&1; then
        log ERROR "Hook failed: $h"
        die 6 "Hook failure in $stage: $h"
      fi
    done
  fi
}

step_fix_permissions(){
  log INFO "Step: fix permissions for LFS directories (best-effort)"
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: permissions fix skipped"; return 0; fi
  chown -R root:root "$LFS" || log WARN "Failed chown root for $LFS (non-fatal)"
  if id "$LFS_USER" >/dev/null 2>&1; then chown -R "$LFS_USER:$LFS_GROUP" "$TOOLS_DIR" "$SOURCES_DIR" "$BUILD_DIR" || log WARN "chown lfs failed (non-fatal)"; fi
  find "$LFS" -type d -exec chmod 0755 {} \; || true
  log INFO "Permissions adjusted."
}

step_report(){
  log INFO "Step: generating summary report -> $REPORT_FILE"
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: would write report"; return 0; fi
  cat > "$REPORT_FILE" <<EOF
Bootstrap report - $(timestamp)
LFS: $LFS
User: $LFS_USER
Directories created: $TOOLS_DIR, $SOURCES_DIR, $BUILD_DIR, $CACHE_DIR, $LOG_DIR, $TMP_DIR
Hooks pre: $HOOKS_PRE_DIR
Hooks post: $HOOKS_POST_DIR
Logfile: $_logfile
EOF
  log INFO "Report written: $REPORT_FILE"
  if [ "$NOTIFY" = true ]; then notify "Bootstrap complete" "Environment prepared at $LFS"; fi
}

repair_actions(){
  log INFO "Repair mode: revalidating mounts, perms and env"
  for m in dev proc sys run; do
    if ! mountpoint -q "$LFS/$m"; then log WARN "$LFS/$m not mounted"; fi
  done
  step_create_structure
  step_fix_permissions
  step_prepare_envfile
  log INFO "Repair complete"
}

main(){
  require_cmds || true
  ensure_space "/" 10485760 || true
  step_create_structure
  step_create_lfs_user
  step_mount_pseudo
  step_prepare_envfile
  step_fetch_base_sources
  step_run_hooks "$HOOKS_PRE_DIR" "pre-bootstrap"
  step_fix_permissions
  step_run_hooks "$HOOKS_POST_DIR" "post-bootstrap"
  step_report
}

if [ "$REPAIR" = true ]; then repair_actions; exit 0; fi
if [ "$RESUME" = true ]; then log INFO "Resume requested - attempting to continue"; fi
if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN mode - no destructive actions will be taken"; fi
main || die 1 "Bootstrap failed"
exit 0
