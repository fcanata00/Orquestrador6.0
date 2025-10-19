#!/usr/bin/env bash
# log.sh - robust logging utility for Rolling LFS in a sandbox
# Generated: 2025-10-19
# Features: colorized logs, stage lifecycle, system snapshot, download progress (curl/wget/pv fallbacks), rotation, concurrency-safe writes with flock fallback

set -euo pipefail
IFS=$'\n\t'

### Configuration (edit as needed or override via environment variables) ###
: "${SANDBOX_BASE:=$HOME/lfs-sandbox}"
: "${LOG_BASE:=$SANDBOX_BASE/logs}"
: "${LOG_LEVEL:=INFO}"                # DEBUG|INFO|WARN|ERROR
: "${MAX_LOG_SIZE_BYTES:=104857600}"  # 100MB default per log file
: "${MAX_LOG_FILES:=7}"               # keep 7 rotated logs
: "${USE_SYSLOG:=false}"              # send certain logs to syslog
: "${LOCK_DIR:=$SANDBOX_BASE/locks}"
: "${TMPDIR:=$SANDBOX_BASE/tmp}"
: "${DOWNLOAD_CACHE:=$SANDBOX_BASE/cache}"

mkdir -p "$LOG_BASE" "$LOCK_DIR" "$TMPDIR" "$DOWNLOAD_CACHE"

### Internal helpers ###
log_level_to_num() {
  case "${1^^}" in
    DEBUG) echo 10;;
    INFO)  echo 20;;
    WARN)  echo 30;;
    ERROR) echo 40;;
    *)     echo 20;;
  esac
}

CURRENT_LOG_LEVEL_NUM=$(log_level_to_num "$LOG_LEVEL")

# color detection
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  COLOR_RESET=$(tput sgr0)
  COLOR_RED=$(tput setaf 1)
  COLOR_GREEN=$(tput setaf 2)
  COLOR_YELLOW=$(tput setaf 3)
  COLOR_BLUE=$(tput setaf 4)
  COLOR_MAGENTA=$(tput setaf 5)
  COLOR_CYAN=$(tput setaf 6)
else
  COLOR_RESET=""
  COLOR_RED=""
  COLOR_GREEN=""
  COLOR_YELLOW=""
  COLOR_BLUE=""
  COLOR_MAGENTA=""
  COLOR_CYAN=""
fi

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# flock wrapper (fallback to mkdir lock)
_acquire_lock() {
  local lockfile="$1"
  if command -v flock >/dev/null 2>&1; then
    exec 200>"$lockfile" || return 1
    flock -n 200 || return 1
    return 0
  else
    # fallback: try mkdir-based lock
    if mkdir "${lockfile}.lck" 2>/dev/null; then
      return 0
    else
      return 1
    fi
  fi
}
_release_lock() {
  local lockfile="$1"
  if command -v flock >/dev/null 2>&1; then
    flock -u 200 || true
    exec 200>&- || true
  else
    rmdir "${lockfile}.lck" 2>/dev/null || true
  fi
}

# Ensure path absolute
abspath() {
  case "$1" in
    /*) printf "%s" "$1";;
    *) printf "%s" "$(pwd)/$1";;
  esac
}

# safe append to log with concurrency control
_safe_append() {
  local file="$1" content="$2"
  local lockfile="$LOCK_DIR/$(echo "$file" | sha1sum | awk '{print $1}')"
  mkdir -p "$(dirname "$file")"
  if _acquire_lock "$lockfile"; then
    printf "%s\n" "$content" >>"$file"
    _release_lock "$lockfile"
    return 0
  else
    # last resort: append without lock
    printf "%s\n" "$content" >>"$file"
    return 0
  fi
}

# rotation by size & count
rotate_log_if_needed() {
  local file="$1"
  if [ ! -f "$file" ]; then return; fi
  local size
  size=$(stat -c%s -- "$file" 2>/dev/null || echo 0)
  if [ "$size" -ge "$MAX_LOG_SIZE_BYTES" ]; then
    local base="${file%.*}"
    local ext="${file##*.}"
    local ts
    ts=$(date +"%Y%m%dT%H%M%S")
    local dest="${base}.${ts}.log"
    mv -- "$file" "$dest"
    # compress old rotated files (non-blocking)
    (gzip -f "$dest" 2>/dev/null || true) &
    # prune old
    local dir
    dir=$(dirname -- "$file")
    local pattern
    pattern="$(basename -- "$base").*.log.gz"
    # keep only newest MAX_LOG_FILES
    find "$dir" -maxdepth 1 -type f -name "$(basename -- "$base")*.log.gz" -printf '%T@ %p\n' | sort -nr | awk 'NR>'"$MAX_LOG_FILES"' {print $2}' | xargs -r rm -f --
  fi
}

# system snapshot functions (fallbacks to /proc)
get_cpu_model() {
  if command -v lscpu >/dev/null 2>&1; then
    lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}'
  else
    awk -F: '/model name/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "Unknown CPU"
  fi
}
get_cpu_cores() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  else
    grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1
  fi
}
get_mem_info() {
  if command -v free >/dev/null 2>&1; then
    free -h | awk 'NR==2{print "total="$2" used="$3" free="$4}'
  else
    awk '/MemTotal/ {total=$2}/MemAvailable/ {avail=$2} END{if(total){printf "total=%sKB used=%sKB free=%sKB", total, total-avail, avail} else print "unknown"}' /proc/meminfo
  fi
}
get_loadavg() { awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo "0.00 0.00 0.00"; }

# logging core
_log_write() {
  local level="$1" stage="$2" logpath="$3" pid="$4" message="$5"
  local ts
  ts=$(timestamp)
  local entry="[${level}] ${ts} stage=${stage} pid=${pid} msg=${message}"
  # write to file (rotate if needed)
  rotate_log_if_needed "$logpath"
  _safe_append "$logpath" "$entry"
  # also print to appropriate stream
  local levelnum
  levelnum=$(log_level_to_num "$level")
  if [ "$levelnum" -ge "$CURRENT_LOG_LEVEL_NUM" ]; then
    case "$level" in
      ERROR)
        printf "%s%s%s\n" "$COLOR_RED" "$entry" "$COLOR_RESET" >&2;;
      WARN)
        printf "%s%s%s\n" "$COLOR_YELLOW" "$entry" "$COLOR_RESET" >&2;;
      DEBUG)
        printf "%s%s%s\n" "$COLOR_CYAN" "$entry" "$COLOR_RESET";&2;;
      *)
        printf "%s%s%s\n" "$COLOR_GREEN" "$entry" "$COLOR_RESET";;
    esac
  fi
  if [ "$USE_SYSLOG" = "true" ] && command -v logger >/dev/null 2>&1; then
    logger -t log.sh "${entry}"
  fi
}

# Public API:
# start-stage <stage-name> <relative-or-absolute-log-path>
start-stage() {
  local stage="$1"
  local logpath_raw="${2:-$LOG_BASE/$(date +%F)/$stage.log}"
  local logpath
  logpath=$(abspath "$logpath_raw")
  mkdir -p "$(dirname "$logpath")"
  local pid="$$"
  local cpu_model cpu_cores mem load
  cpu_model=$(get_cpu_model)
  cpu_cores=$(get_cpu_cores)
  mem=$(get_mem_info)
  load=$(get_loadavg)
  # create or touch log
  : >"$logpath" 2>/dev/null || touch "$logpath" 2>/dev/null
  _log_write "INFO" "$stage" "$logpath" "$pid" "START"
  _log_write "INFO" "$stage" "$logpath" "$pid" "CPU: $cpu_model | cores=$cpu_cores"
  _log_write "INFO" "$stage" "$logpath" "$pid" "MEM: $mem"
  _log_write "INFO" "$stage" "$logpath" "$pid" "LOAD: $load"
  # print a human friendly block
  printf "[START] %s stage=%s log=%s pid=%s\n  CPU: %s | cores=%s\n  Mem: %s\n  Load avg: %s\n" "$(timestamp)" "$stage" "$logpath" "$pid" "$cpu_model" "$cpu_cores" "$mem" "$load"
  # record metadata
  printf '{"stage":"%s","pid":%s,"start":"%s","log":"%s"}\n' "$stage" "$pid" "$(timestamp)" "$logpath" >"$LOCK_DIR/${stage}.status" 2>/dev/null || true
  # store start time for elapsed calculation
  echo "$(date +%s)" >"$LOCK_DIR/${stage}.start" 2>/dev/null || true
}

# step <stage> <logpath> <message>
step() {
  local stage="$1" logpath_raw="$2" message="$3"
  local logpath
  logpath=$(abspath "$logpath_raw")
  _log_write "INFO" "$stage" "$logpath" "$$" "$message"
}

# debug, warn, error helper wrappers
debug() { local stage="$1" logpath="$2" msg="$3"; _log_write "DEBUG" "$stage" "$logpath" "$$" "$msg"; }
warn()  { local stage="$1" logpath="$2" msg="$3"; _log_write "WARN" "$stage" "$logpath" "$$" "$msg"; }
error() { local stage="$1" logpath="$2" msg="$3"; _log_write "ERROR" "$stage" "$logpath" "$$" "$msg"; }

# download helpers
verify_checksum() {
    local file="$1"
    local expected="$2"

    if [ -z "$expected" ]; then
        log WARN "Nenhum checksum fornecido, pulando verificação."
        return 0
    fi

    local algo calc=""
    case "${#expected}" in
        32)  algo="md5sum" ;;
        40)  algo="sha1sum" ;;
        64)  algo="sha256sum" ;;
        128) algo="sha512sum" ;;
        *)   log WARN "Checksum desconhecido (tamanho ${#expected}), assumindo SHA256."
             algo="sha256sum" ;;
    esac

    if ! command -v "$algo" >/dev/null 2>&1; then
        log ERROR "Comando $algo não encontrado, não é possível verificar checksum."
        return 1
    fi

    calc=$($algo "$file" | awk '{print $1}')
    if [ "$calc" = "$expected" ]; then
        log SUCCESS "Checksum verificado com sucesso usando $algo."
        return 0
    else
        log ERROR "Checksum inválido! Esperado: $expected | Obtido: $calc"
        return 1
    fi
}
# download-with-progress <stage> <logpath> <url> <dest>
download-with-progress() {
  local stage="$1" logpath_raw="$2" url="$3" dest="$4"
  local logpath
  logpath=$(abspath "$logpath_raw")
  mkdir -p "$(dirname -- "$dest")"
  mkdir -p "$(dirname -- "$logpath")"
  _log_write "INFO" "$stage" "$logpath" "$$" "DOWNLOAD START url=$url dest=$dest"

  # check space
  if [ -n "$(command -v df 2>/dev/null)" ]; then
    local avail
    avail=$(df -k --output=avail "$(dirname -- "$dest")" 2>/dev/null | tail -1 | tr -d ' ')
    if [ -n "$avail" ]; then
      debug "$stage" "$logpath" "Available KB on destination: $avail"
    fi
  fi

  # prefer curl, then wget, then fallback to netcat-like (not implemented)
  if command -v curl >/dev/null 2>&1; then
    # use curl with progress-bar; also support resume
    curl -L --fail --retry 3 --retry-delay 5 --progress-bar -o "$dest" "$url" 2> >(while IFS= read -r line; do _safe_append "$logpath" "[CURL] $(timestamp) $line"; done)
    rc=$?
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$url" 2> >(while IFS= read -r line; do _safe_append "$logpath" "[WGET] $(timestamp) $line"; done)
    rc=$?
  else
    _log_write "WARN" "$stage" "$logpath" "$$" "No curl or wget available - cannot download"
    return 2
  fi

  if [ "$rc" -ne 0 ]; then
    _log_write "ERROR" "$stage" "$logpath" "$$" "DOWNLOAD FAILED url=$url rc=$rc"
    return $rc
  fi
  _log_write "INFO" "$stage" "$logpath" "$$" "DOWNLOAD COMPLETE url=$url dest=$dest"
  return 0
}

# end-stage <stage> <logpath> <exitcode>
end-stage() {
  local stage="$1" logpath_raw="$2" exitcode=${3:-0}
  local logpath
  logpath=$(abspath "$logpath_raw")
  local pid="$$"
  local end_ts
  end_ts=$(date +%s)
  local start_ts_file="$LOCK_DIR/${stage}.start"
  local elapsed="unknown"
  if [ -f "$start_ts_file" ]; then
    local start_ts
    start_ts=$(cat "$start_ts_file" 2>/dev/null || echo "0")
    elapsed=$((end_ts - start_ts))
    rm -f "$start_ts_file" || true
  fi
  local load
  load=$(get_loadavg)
  _log_write "INFO" "$stage" "$logpath" "$pid" "END rc=${exitcode} elapsed=${elapsed}s"
  _log_write "INFO" "$stage" "$logpath" "$pid" "AVG_LOAD: $load"
  printf "[END] %s stage=%s rc=%s elapsed=%ss log=%s\n  avg_load: %s\n" "$(timestamp)" "$stage" "$exitcode" "$elapsed" "$logpath" "$load"
}

# manual rotate command
rotate() {
  local logpath_raw="$1"
  local logpath
  logpath=$(abspath "$logpath_raw")
  rotate_log_if_needed "$logpath"
}

# small usage helper
usage() {
  cat <<EOF
Usage: log.sh <command> [args]
Commands:
  start-stage <stage> <logpath>
  step <stage> <logpath> <message>
  debug|warn|error <stage> <logpath> <message>
  download-with-progress <stage> <logpath> <url> <dest>
  end-stage <stage> <logpath> <exitcode>
  rotate <logpath>

Notes:
  - Set SANDBOX_BASE or LOG_BASE to change storage paths.
  - Designed to run inside a sandbox; minimizes external deps and uses /proc fallbacks.
EOF
}

# dispatch
if [ "$#" -lt 1 ]; then usage; exit 1; fi
cmd="$1"; shift
case "$cmd" in
  start-stage) start-stage "$@";;
  step) step "$@";;
  debug) debug "$@";;
  warn) warn "$@";;
  error) error "$@";;
  download-with-progress) download-with-progress "$@";;
  end-stage) end-stage "$@";;
  rotate) rotate "$@";;
  *) usage; exit 2;;
esac

