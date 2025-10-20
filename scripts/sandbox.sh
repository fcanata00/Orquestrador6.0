#!/usr/bin/env bash
# sandbox.sh - Secure sandbox manager for Rolling LFS builds
# Implements: create, enter, exec, destroy, snapshot, restore, healthcheck, cleanup
# Integrates with utils.sh, log.sh, dependency.sh and supports notify-send notifications.
#
# Safety: set -eEuo pipefail and traps. No eval of untrusted content.
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Globals & defaults ----------
SANDBOX_ROOT="${SANDBOX_ROOT:-$HOME/lfs-sandboxes}"
SANDBOX_NAME="${SANDBOX_NAME:-default}"
SANDBOX_DIR="$SANDBOX_ROOT/$SANDBOX_NAME"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-$SANDBOX_ROOT/snapshots}"
CONFIG_FILE="${CONFIG_FILE:-$SANDBOX_DIR/sandbox.conf}"
LOG_DIR="${LOG_DIR:-$SANDBOX_DIR/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/sandbox.log}"
ERR_LOG="${ERR_LOG:-$LOG_DIR/sandbox_errors.log}"
LOCK_DIR="${LOCK_DIR:-$SANDBOX_ROOT/locks}"
TMPDIR="${TMPDIR:-$SANDBOX_DIR/tmp}"
BUILDER_USER="${BUILDER_USER:-builder}"
BACKEND="${BACKEND:-auto}"   # auto|bwrap|chroot|nspawn
MIN_FREE_BYTES=$((5 * 1024 * 1024 * 1024))  # 5 GiB
DRY_RUN=false
VERBOSE=false
FORCE=false
ENABLE_NOTIFY=true
CGROUP_LIMITS_ENABLED=false

# create dirs
mkdir -p "$SANDBOX_ROOT" "$SNAPSHOT_DIR" "$LOCK_DIR" "$LOG_DIR" "$TMPDIR"

# load utils/log if present
if [ -f "/mnt/data/utils.sh" ]; then
  # shellcheck disable=SC1091
  source /mnt/data/utils.sh || true
fi

# helper: notification via notify-send if available and DISPLAY present
notify() {
  local title="$1"; local body="$2"
  if [ "$ENABLE_NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1 && [ -n "${DISPLAY-}" ]; then
    notify-send --urgency=low "$title" "$body" || true
  fi
  # also log
  echo "[NOTIFY] $title - $body" >> "$LOG_FILE"
}

# logging helpers (fallback)
_log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "${VERBOSE}" = true ]; then
    printf "[%s] %s %s\n" "$level" "$ts" "$msg" >&2
  fi
  mkdir -p "$(dirname "$LOG_FILE")"
  printf "[%s] %s %s\n" "$level" "$ts" "$msg" >> "$LOG_FILE"
}
log_info() { _log "INFO" "$*"; }
log_warn() { _log "WARN" "$*"; }
log_error() { _log "ERROR" "$*"; echo "[ERROR] $*" >> "$ERR_LOG"; }

# trap and fail handler
_on_fail() {
  local rc=$?
  local line=${1:-0}
  log_error "sandbox.sh failed (rc=$rc) at line $line"
  notify "sandbox.sh failed" "See $ERR_LOG (rc=$rc)"
  # attempt cleanup of mounts if partially created
  if [ -n "${SANDBOX_DIR-}" ] && mountpoint -q "$SANDBOX_DIR/proc" 2>/dev/null; then
    log_warn "Attempting lazy unmounts during failure cleanup"
    umount -l "$SANDBOX_DIR/proc" || true
    umount -l "$SANDBOX_DIR/sys" || true
    umount -l "$SANDBOX_DIR/dev" || true
  fi
  exit "$rc"
}
trap '_on_fail $LINENO' ERR INT TERM

# ---------- Utility helpers ----------
abspath() {
  case "$1" in
    /*) printf "%s" "$1" ;;
    *) printf "%s" "$(pwd)/$1" ;;
  esac
}

atomic_write_file() {
  local file="$1"; local content="$2"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/.tmp.XXXX")"
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would write to $file"
    rm -f "$tmp"
    return 0
  fi
  printf "%s" "$content" > "$tmp"
  mv -f "$tmp" "$file"
}

ensure_user_builder() {
  if id -u "$BUILDER_USER" >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would create user $BUILDER_USER"
    return 0
  fi
  if [ "$(id -u)" -ne 0 ]; then
    log_warn "Not root: cannot create user $BUILDER_USER. Sandbox may still work but builder user won't exist."
    return 0
  fi
  useradd --system --home "$SANDBOX_DIR/home/$BUILDER_USER" --create-home --shell /bin/bash "$BUILDER_USER" || true
  log_info "Created builder user $BUILDER_USER"
}

check_disk_space() {
  local target="${1:-$SANDBOX_ROOT}"
  local avail
  avail=$(df --output=avail -B1 "$target" 2>/dev/null | tail -n1 || echo 0)
  if [ -z "$avail" ]; then avail=0; fi
  if [ "$avail" -lt "$MIN_FREE_BYTES" ]; then
    log_warn "Low disk space on $(df -h "$target" 2>/dev/null | tail -n1): available ${avail} bytes"
    return 1
  fi
  return 0
}

acquire_lock() {
  local name="$1"
  mkdir -p "$LOCK_DIR"
  exec 9>"$LOCK_DIR/$name.lock"
  flock -n 9 || die 1 "Could not acquire lock $name"
}

release_lock() {
  exec 9>&-
}

# ---------- Backend detection ----------
detect_backend() {
  if [ "$BACKEND" != "auto" ]; then
    echo "$BACKEND"
    return 0
  fi
  if command -v bwrap >/dev/null 2>&1; then
    echo "bwrap"
  elif command -v systemd-nspawn >/dev/null 2>&1; then
    echo "nspawn"
  else
    echo "chroot"
  fi
}

# ---------- Config file helpers ----------
default_config() {
  cat > "$CONFIG_FILE" <<'EOF'
# sandbox.conf - defaults
backend=auto
enable_network=false
mount_tmpfs=true
snapshot_dir=${SNAPSHOT_DIR}
builder_user=${BUILDER_USER}
min_free_gb=5
EOF
  chmod 0644 "$CONFIG_FILE"
  log_info "Wrote default config to $CONFIG_FILE"
}

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    # parse simple KEY=VALUE lines
    while IFS='=' read -r k v; do
      k="$(echo "$k" | tr -d ' ')"
      v="${v:-}"
      case "$k" in
        backend) BACKEND="${v}" ;;
        enable_network) ENABLE_NETWORK="${v}" ;;
        mount_tmpfs) MOUNT_TMPFS="${v}" ;;
        snapshot_dir) SNAPSHOT_DIR="${v}" ;;
        builder_user) BUILDER_USER="${v}" ;;
        *) ;;
      esac
    done < <(grep -E '^[a-zA-Z0-9_]+=.*' "$CONFIG_FILE" || true)
  else
    default_config
  fi
}

# ---------- Sandbox lifecycle ----------
sandbox_init_dirs() {
  mkdir -p "$SANDBOX_DIR" "$SANDBOX_DIR/rootfs" "$SANDBOX_DIR/build" "$SANDBOX_DIR/sources" "$LOG_DIR" "$SNAPSHOT_DIR"
  chmod 0700 "$SANDBOX_DIR"
  chmod 0755 "$SANDBOX_DIR/rootfs"
  touch "$LOG_FILE" || true
  touch "$ERR_LOG" || true
}

# create minimal rootfs by copying minimal files (fallback to empty)
create_rootfs_minimal() {
  log_info "Creating minimal rootfs for sandbox at $SANDBOX_DIR/rootfs"
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would populate rootfs minimal"
    return 0
  fi
  mkdir -p "$SANDBOX_DIR/rootfs"/{bin,lib,lib64,usr,etc,proc,sys,dev,run,tmp}
  # copy essential files from host
  for f in /bin/sh /bin/bash /bin/ls /bin/mkdir /bin/rm; do
    if [ -x "$f" ]; then
      cp -a "$f" "$SANDBOX_DIR/rootfs/bin/" || true
    fi
  done
  # basic /etc files
  cp -a /etc/nsswitch.conf "$SANDBOX_DIR/rootfs/etc/" 2>/dev/null || true
  cp -a /etc/hosts "$SANDBOX_DIR/rootfs/etc/" 2>/dev/null || true
  cp -a /etc/resolv.conf "$SANDBOX_DIR/rootfs/etc/" 2>/dev/null || true
  log_info "Minimal rootfs prepared"
}

# mount helpers (bwrap or chroot style)
sandbox_mounts_setup() {
  local backend="$1"
  if [ "$backend" = "bwrap" ]; then
    log_info "Using bubblewrap backend; no persistent mounts necessary"
    return 0
  fi
  # for chroot/nspawn configure bind mounts
  if mountpoint -q "$SANDBOX_DIR/proc" 2>/dev/null; then
    log_info "Mounts already present"
    return 0
  fi
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would mount proc/sys/dev into rootfs"
    return 0
  fi
  mount --bind /dev "$SANDBOX_DIR/dev" || true
  mount --bind /proc "$SANDBOX_DIR/proc" || true
  mount --bind /sys "$SANDBOX_DIR/sys" || true
  # bind resolv.conf and hosts
  cp -a /etc/resolv.conf "$SANDBOX_DIR/etc/resolv.conf" 2>/dev/null || true
  cp -a /etc/hosts "$SANDBOX_DIR/etc/hosts" 2>/dev/null || true
  log_info "Bind mounts created"
}

sandbox_mounts_teardown() {
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would unmount sandbox mounts"
    return 0
  fi
  for m in proc sys dev; do
    if mountpoint -q "$SANDBOX_DIR/$m" 2>/dev/null; then
      umount -l "$SANDBOX_DIR/$m" || log_warn "umount $SANDBOX_DIR/$m failed"
    fi
  done
}

# create sandbox
sandbox_create() {
  load_config
  sandbox_init_dirs
  if [ -d "$SANDBOX_DIR" ] && [ "$(ls -A "$SANDBOX_DIR" 2>/dev/null || true)" != "" ] && [ "$FORCE" != true ]; then
    log_warn "Sandbox $SANDBOX_DIR already exists. Use --force to recreate."
    return 1
  fi
  check_disk_space "$SANDBOX_ROOT" || return 1
  backend="$(detect_backend)"
  log_info "Creating sandbox $SANDBOX_NAME using backend $backend"
  ensure_user_builder
  create_rootfs_minimal
  sandbox_mounts_setup "$backend"
  # set safe perms
  chmod 700 "$SANDBOX_DIR"
  # create marker
  echo "name=$SANDBOX_NAME" > "$SANDBOX_DIR/.sandboxmeta"
  echo "backend=$backend" >> "$SANDBOX_DIR/.sandboxmeta"
  date -u +"created=%Y-%m-%dT%H:%M:%SZ" >> "$SANDBOX_DIR/.sandboxmeta"
  log_info "Sandbox $SANDBOX_NAME created at $SANDBOX_DIR"
  notify "Sandbox created" "$SANDBOX_NAME"
  return 0
}

# enter sandbox: supports bwrap, chroot, nspawn
sandbox_enter_shell() {
  load_config
  backend="$(detect_backend)"
  log_info "Entering sandbox $SANDBOX_NAME with backend $backend"
  if [ "$backend" = "bwrap" ]; then
    # bubblewrap isolates without needing root; map necessary dirs
    cmd=(bwrap --dev-bind "$SANDBOX_DIR/rootfs" / --clearenv --setenv HOME "/home/$BUILDER_USER" --setenv USER "$BUILDER_USER" --ro-bind "$SANDBOX_DIR/sources" /sources --bind "$SANDBOX_DIR/build" /build --tmpfs /tmp --proc /proc --dev /dev --unshare-net)
    # optionally allow network
    if [ "${ENABLE_NETWORK:-false}" = true ]; then
      cmd=( "${cmd[@]/--unshare-net/}" )  # remove unshare-net to allow network
    fi
    log_info "Running: ${cmd[*]} /bin/bash --login"
    if [ "$DRY_RUN" = true ]; then
      log_info "DRY-RUN: would run bwrap shell"
      return 0
    fi
    "${cmd[@]}" /bin/bash --login
    return $?
  elif [ "$backend" = "nspawn" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_info "DRY-RUN: would run systemd-nspawn -D $SANDBOX_DIR/rootfs"
      return 0
    fi
    systemd-nspawn -D "$SANDBOX_DIR/rootfs" /bin/bash --login
    return $?
  else
    # chroot fallback
    sandbox_mounts_setup "chroot"
    if [ "$DRY_RUN" = true ]; then
      log_info "DRY-RUN: would chroot into $SANDBOX_DIR/rootfs"
      return 0
    fi
    chroot "$SANDBOX_DIR/rootfs" /bin/bash --login
    return $?
  fi
}

sandbox_exec_cmd() {
  local cmd="$*"
  backend="$(detect_backend)"
  log_info "Executing inside sandbox: $cmd (backend=$backend)"
  if [ "$backend" = "bwrap" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_info "DRY-RUN: would run bwrap -- \"${cmd}\""
      return 0
    fi
    bwrap --dev-bind "$SANDBOX_DIR/rootfs" / --clearenv --setenv HOME "/home/$BUILDER_USER" --setenv USER "$BUILDER_USER" --ro-bind "$SANDBOX_DIR/sources" /sources --bind "$SANDBOX_DIR/build" /build --tmpfs /tmp --proc /proc --dev /dev --unshare-net /bin/bash -lc "$cmd"
    return $?
  elif [ "$backend" = "nspawn" ]; then
    if [ "$DRY_RUN" = true ]; then
      log_info "DRY-RUN: would run systemd-nspawn -D $SANDBOX_DIR/rootfs -- $cmd"
      return 0
    fi
    systemd-nspawn -D "$SANDBOX_DIR/rootfs" /bin/bash -lc "$cmd"
    return $?
  else
    sandbox_mounts_setup "chroot"
    if [ "$DRY_RUN" = true ]; then
      log_info "DRY-RUN: would run chroot $SANDBOX_DIR/rootfs /bin/bash -lc \"$cmd\""
      return 0
    fi
    chroot "$SANDBOX_DIR/rootfs" /bin/bash -lc "$cmd"
    return $?
  fi
}

# destroy sandbox
sandbox_destroy() {
  load_config
  if [ "$FORCE" != true ]; then
    read -r -p "Destroy sandbox $SANDBOX_DIR? This will remove all data. Type 'yes' to confirm: " ans
    if [ "$ans" != "yes" ]; then
      log_info "Abort sandbox destroy"
      return 1
    fi
  fi
  log_info "Destroying sandbox $SANDBOX_NAME at $SANDBOX_DIR"
  # ensure no processes running
  if pgrep -f "$SANDBOX_DIR" >/dev/null 2>&1; then
    log_warn "Processes running under sandbox detected; attempting to kill"
    pkill -f "$SANDBOX_DIR" || true
    sleep 1
  fi
  sandbox_mounts_teardown
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would remove $SANDBOX_DIR"
    return 0
  fi
  # backup logs
  if [ -d "$LOG_DIR" ]; then
    mkdir -p "$SNAPSHOT_DIR/backup_logs"
    tar -C "$LOG_DIR" -czf "$SNAPSHOT_DIR/backup_logs/${SANDBOX_NAME}_logs_$(date -u +%Y%m%dT%H%M%SZ).tar.gz" . || true
  fi
  rm -rf "$SANDBOX_DIR"
  log_info "Sandbox destroyed"
  notify "Sandbox destroyed" "$SANDBOX_NAME"
  return 0
}

# snapshot create
sandbox_snapshot() {
  local tag="${1:-auto-$(date -u +%Y%m%dT%H%M%SZ)}"
  mkdir -p "$SNAPSHOT_DIR"
  local out="$SNAPSHOT_DIR/${SANDBOX_NAME}_${tag}.tar.xz"
  log_info "Creating snapshot $out"
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would tar $SANDBOX_DIR -> $out"
    return 0
  fi
  tar -C "$SANDBOX_ROOT" -cJf "$out" "$(basename "$SANDBOX_DIR")"
  sha256sum "$out" > "${out}.sha256"
  log_info "Snapshot created: $out"
  notify "Sandbox snapshot" "${SANDBOX_NAME} -> ${out##*/}"
  return 0
}

# snapshot restore
sandbox_restore() {
  local snapfile="$1"
  if [ -z "$snapfile" ] || [ ! -f "$snapfile" ]; then
    log_error "Snapshot file missing: $snapfile"
    return 1
  fi
  if [ "$DRY_RUN" = true ]; then
    log_info "DRY-RUN: would restore snapshot $snapfile"
    return 0
  fi
  log_info "Restoring snapshot $snapfile to $SANDBOX_ROOT"
  tar -C "$SANDBOX_ROOT" -xJf "$snapfile"
  log_info "Restore complete"
  notify "Sandbox restored" "${snapfile##*/}"
  return 0
}

# healthcheck
sandbox_healthcheck() {
  load_config
  local ok=0
  log_info "Starting sandbox healthcheck for $SANDBOX_NAME"
  # check dirs
  if [ ! -d "$SANDBOX_DIR" ]; then
    log_warn "Sandbox dir missing: $SANDBOX_DIR"; ok=1
  fi
  # mounts
  if [ -d "$SANDBOX_DIR/rootfs/proc" ] && mountpoint -q "$SANDBOX_DIR/rootfs/proc" 2>/dev/null; then
    log_info "/proc mounted"
  else
    log_warn "/proc not mounted inside rootfs"
  fi
  # user builder
  if id -u "$BUILDER_USER" >/dev/null 2>&1; then
    log_info "Builder user exists"
  else
    log_warn "Builder user $BUILDER_USER missing"
  fi
  # DNS
  if [ -f "$SANDBOX_DIR/etc/resolv.conf" ] && grep -E '\S' "$SANDBOX_DIR/etc/resolv.conf" >/dev/null 2>&1; then
    log_info "resolv.conf present"
  else
    log_warn "resolv.conf missing or empty inside sandbox"
  fi
  # small compile test
  if command -v gcc >/dev/null 2>&1; then
    tmpc="$TMPDIR/test.c"
    echo 'int main(void){return 0;}' > "$tmpc"
    if gcc "$tmpc" -o "$TMPDIR/testbin" >/dev/null 2>&1; then
      log_info "Host gcc works (not a sandbox compile test)"
      rm -f "$TMPDIR/test.c" "$TMPDIR/testbin"
    fi
  fi
  if [ "$ok" -ne 0 ]; then
    log_warn "Healthcheck finished with warnings"
    return 1
  fi
  log_info "Healthcheck OK"
  return 0
}

# cleanup leftover mounts, tmp and logs
sandbox_cleanup() {
  load_config
  log_info "Running sandbox cleanup"
  # lazy unmount known mounts
  sandbox_mounts_teardown
  # clear old tmp
  find "$SANDBOX_ROOT" -type f -name "*.part" -mtime +3 -print -delete || true
  # rotate logs older than 30d
  find "$SANDBOX_ROOT" -type f -name "*.log" -mtime +30 -print -delete || true
  log_info "Cleanup completed"
  return 0
}

# configure cgroups (optional)
sandbox_configure_cgroups() {
  if [ "$CGROUP_LIMITS_ENABLED" != true ]; then
    log_info "Cgroup limits disabled"
    return 0
  fi
  # attempt to create a slice for sandbox builds if systemd present
  if command -v systemd-run >/dev/null 2>&1; then
    log_info "systemd-run available; sandbox builds may be limited via systemd-run"
  else
    log_warn "systemd-run not available; cannot auto-apply cgroup limits"
  fi
}

# ---------- CLI parsing ----------
show_usage() {
  cat <<EOF
sandbox.sh - manage secure sandboxes for Rolling LFS
Usage:
  sandbox.sh --name <name> --create [--force] [--dry-run]
  sandbox.sh --name <name> --enter
  sandbox.sh --name <name> --exec "<command>"
  sandbox.sh --name <name> --destroy [--force]
  sandbox.sh --name <name> --snapshot [tag]
  sandbox.sh --name <name> --restore <snapshot-file>
  sandbox.sh --name <name> --healthcheck
  sandbox.sh --name <name> --cleanup
Options:
  --dry-run   simulate actions
  --verbose   verbose logging
  --force     force actions without prompt
  --no-notify disable desktop notifications
EOF
}

# parse args
ARGS=("$@")
if [ "$#" -eq 0 ]; then show_usage; exit 0; fi
# simple parsing
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --name) SANDBOX_NAME="${ARGS[0]:-}"; SANDBOX_DIR="$SANDBOX_ROOT/$SANDBOX_NAME"; ARGS=("${ARGS[@]:1}");;
    --create) CMD="create";;
    --enter) CMD="enter";;
    --exec) CMD="exec"; EXEC_CMD="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --destroy) CMD="destroy";;
    --snapshot) CMD="snapshot"; SNAP_TAG="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --restore) CMD="restore"; SNAP_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --healthcheck) CMD="healthcheck";;
    --cleanup) CMD="cleanup";;
    --force) FORCE=true;;
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    --no-notify) ENABLE_NOTIFY=false;;
    --help|-h) show_usage; exit 0;;
    *) echo "Unknown arg $a"; show_usage; exit 2;;
  esac
done

# ensure derived vars
SANDBOX_DIR="$SANDBOX_ROOT/$SANDBOX_NAME"
LOG_DIR="${LOG_DIR:-$SANDBOX_DIR/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/sandbox.log}"
ERR_LOG="${ERR_LOG:-$LOG_DIR/sandbox_errors.log}"
TMPDIR="${TMPDIR:-$SANDBOX_DIR/tmp}"

mkdir -p "$SANDBOX_DIR" "$LOG_DIR" "$TMPDIR" "$SNAPSHOT_DIR"

# dispatch
case "${CMD:-}" in
  create)
    sandbox_create
    ;;
  enter)
    sandbox_enter_shell
    ;;
  exec)
    if [ -z "${EXEC_CMD:-}" ]; then die 2 "No command provided for --exec"; fi
    sandbox_exec_cmd "$EXEC_CMD"
    ;;
  destroy)
    sandbox_destroy
    ;;
  snapshot)
    sandbox_snapshot "${SNAP_TAG:-}"
    ;;
  restore)
    if [ -z "${SNAP_FILE:-}" ]; then die 2 "No snapshot file provided"; fi
    sandbox_restore "$SNAP_FILE"
    ;;
  healthcheck)
    sandbox_healthcheck
    ;;
  cleanup)
    sandbox_cleanup
    ;;
  *)
    show_usage
    ;;
esac
