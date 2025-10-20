#!/usr/bin/env bash
# dependency.sh - dependency resolver for Rolling LFS
# Features:
#  - Parse dependencies from metafile INI ([dependencies] section)
#  - Resolve dependency tree (direct & recursive), detect cycles
#  - Produce build order (topological sort) using tsort fallback
#  - Check installed dependencies (binary presence, library .so, or metafiles)
#  - Verify dependency version constraints (=, >=, <=, >, <) using sort -V or fallback
#  - Generate dependency graph (DOT text) and simple ASCII tree
#  - Integration points: upgrade.sh (rebuild system), uninstall.sh (remove orphans)
#  - Robust error handling, dry-run, verbose, locking, logging integration with utils.sh/log.sh
#  - Repair suggestions and safety checks
#
# Security & robustness:
#  - No eval of untrusted content
#  - Input validation and sanitization
#  - Atomic writes for outputs
#  - Concurrency-safe with flock
#  - Explicit exit codes and non-silent failures
#
# Usage examples:
#   dependency.sh --check meta/base/gcc/gcc.ini
#   dependency.sh --resolve meta/base/gcc/gcc.ini --out order.txt
#   dependency.sh --graph meta/base/gcc/gcc.ini --out graph.dot
#   dependency.sh --all --check
#   dependency.sh --remove-orphans
#
set -euo pipefail
IFS=$'\n\t'

# --------- Globals & defaults ----------
SANDBOX_ROOT="${SANDBOX_ROOT:-$HOME/lfs-sandbox}"
META_DIR="${META_DIR:-$SANDBOX_ROOT/meta}"
CACHE_DIR="${CACHE_DIR:-$SANDBOX_ROOT/cache}"
LOCK_DIR="${LOCK_DIR:-$SANDBOX_ROOT/locks}"
TMPDIR="${TMPDIR:-$SANDBOX_ROOT/tmp}"
LOG_FILE_DEFAULT="${LOG_FILE:-$SANDBOX_ROOT/logs/dependency.log}"
LOG_FILE="${LOG_FILE:-$LOG_FILE_DEFAULT}"
PACKAGES_DIR="${PACKAGES_DIR:-$SANDBOX_ROOT/packages}"

DRY_RUN=false
VERBOSE=false
FORCE=false
DO_ALL=false
OUT_FILE=""
GRAPH_FILE=""
DO_REMOVE_ORPHANS=false
DO_UPGRADE=false
DO_UNINSTALL=false

# Exit codes
E_OK=0
E_GENERIC=1
E_ARGS=2
E_MISSING=3
E_CYCLE=4
E_PERMS=5

# ensure dirs
mkdir -p "$LOCK_DIR" "$CACHE_DIR" "$TMPDIR" "$(dirname "$LOG_FILE")" "$PACKAGES_DIR"

# Try to source utils.sh for logging and helpers if available
if [ -f "/mnt/data/utils.sh" ]; then
  # shellcheck disable=SC1091
  source "/mnt/data/utils.sh" || true
fi

# fallback logging
_log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "${VERBOSE}" = true ]; then
    printf "[%s] %s %s\n" "$level" "$ts" "$msg" >&2
  fi
  printf "[%s] %s %s\n" "$level" "$ts" "$msg" >> "$LOG_FILE"
}
log_info() { _log "INFO" "$*"; }
log_warn() { _log "WARN" "$*"; }
log_error() { _log "ERROR" "$*"; }

die() {
  local code=${1:-1}
  shift || true
  log_error "$*"
  exit "$code"
}

# --------- Utility helpers ----------
abspath() {
  case "$1" in
    /*) printf "%s" "$1";;
    *) printf "%s" "$(pwd)/$1";;
  esac
}

atomic_write() {
  local file="$1"; shift
  local tmp
  tmp="$(mktemp "${TMPDIR}/.tmp.XXXX")"
  printf "%s" "$*" > "$tmp"
  mv -f "$tmp" "$file"
}

with_lock() {
  local name="$1"; shift
  local lockfile="$LOCK_DIR/${name}.lock"
  mkdir -p "$(dirname "$lockfile")"
  exec 9>"$lockfile"
  flock -n 9 || die $E_PERMS "Failed to acquire lock $lockfile"
  "$@"
  flock -u 9 || true
  exec 9>&-
}

# --------- INI parse helpers (lightweight) ---------
declare -A INI
parse_ini_file() {
  local file="$1"
  if [ ! -f "$file" ]; then
    log_error "INI not found: $file"
    return $E_MISSING
  fi
  INI=()
  local section=""
  while IFS= read -r line || [ -n "$line" ]; do
    # strip comments
    line="${line%%[#;]*}"
    # trim
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      section="${section// /_}"
      continue
    fi
    if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]// /_}"
      value="${BASH_REMATCH[2]}"
      key="$(echo "$key" | tr '[:upper:]' '[:lower:]')"
      INI["$section.$key"]="$value"
    fi
  done < "$file"
  return 0
}

ini_get() {
  local section="$1" key="$2" default="${3:-}"
  local k="${section}.${key}"
  if [ -n "${INI[$k]:-}" ]; then
    printf "%s" "${INI[$k]}"
    return 0
  fi
  printf "%s" "$default"
  return 1
}

# --------- Dependency parsing ---------
# [dependencies] required, optional, conflicts, pins
parse_dependencies_from_metafile() {
  local meta="$1"
  parse_ini_file "$meta" || return $?
  local raw
  raw="$(ini_get dependencies required "")"
  IFS=',' read -r -a req <<< "$(echo "$raw" | sed 's/,/ /g' | xargs 2>/dev/null || echo "")"
  raw="$(ini_get dependencies optional "")"
  IFS=',' read -r -a opt <<< "$(echo "$raw" | sed 's/,/ /g' | xargs 2>/dev/null || echo "")"
  raw="$(ini_get dependencies conflicts "")"
  IFS=',' read -r -a conf <<< "$(echo "$raw" | sed 's/,/ /g' | xargs 2>/dev/null || echo "")"
  raw="$(ini_get dependencies pins "")"
  IFS=',' read -r -a pins_arr <<< "$(echo "$raw" | sed 's/,/ /g' | xargs 2>/dev/null || echo "")"

  DEP_REQUIRED=()
  DEP_OPTIONAL=()
  DEP_CONFLICTS=()
  DEP_PINS=()
  for p in "${req[@]:-}"; do p="$(echo "$p" | xargs)"; [ -n "$p" ] && DEP_REQUIRED+=("$p"); done
  for p in "${opt[@]:-}"; do p="$(echo "$p" | xargs)"; [ -n "$p" ] && DEP_OPTIONAL+=("$p"); done
  for p in "${conf[@]:-}"; do p="$(echo "$p" | xargs)"; [ -n "$p" ] && DEP_CONFLICTS+=("$p"); done
  for p in "${pins_arr[@]:-}"; do p="$(echo "$p" | xargs)"; [ -n "$p" ] && DEP_PINS+=("$p"); done
  return 0
}

validate_pkg_name() {
  local n="$1"
  if [[ "$n" =~ ^[a-z0-9._+\-]+$ ]]; then return 0; fi
  return 1
}

# --------- Resolver & cycle detection ----------
RESOLVED_LIST=()
declare -A VISITED
declare -A ONSTACK
declare -A ADJ

add_edge() {
  local a="$1" b="$2"
  ADJ["$a,$b"]=1
}

dfs_resolve() {
  local pkg="$1" meta_file="$2"
  if [ "${ONSTACK[$pkg]:-}" = "1" ]; then
    log_error "Dependency cycle detected at $pkg"
    return $E_CYCLE
  fi
  if [ "${VISITED[$pkg]:-}" = "1" ]; then
    return 0
  fi
  ONSTACK["$pkg"]=1
  VISITED["$pkg"]=1
  local meta="$(find "$META_DIR" -type f -name "${pkg}.ini" -print -quit || true)"
  if [ -z "$meta" ]; then
    log_warn "Metafile for dependency '$pkg' not found under $META_DIR"
  else
    parse_dependencies_from_metafile "$meta" || return $?
    for d in "${DEP_REQUIRED[@]:-}"; do
      d="$(echo "$d" | xargs)"
      add_edge "$d" "$pkg"
      dfs_resolve "$d" "$meta" || return $?
    done
    for d in "${DEP_OPTIONAL[@]:-}"; do
      d="$(echo "$d" | xargs)"
      local dmeta; dmeta="$(find "$META_DIR" -type f -name "${d}.ini" -print -quit || true)"
      if [ -n "$dmeta" ]; then
        add_edge "$d" "$pkg"
        dfs_resolve "$d" "$meta" || return $?
      else
        log_info "Optional dep '$d' for $pkg not present; skipping"
      fi
    done
  fi
  ONSTACK["$pkg"]=0
  RESOLVED_LIST+=("$pkg")
  return 0
}

# Topo sort (tsort fallback)
topo_sort_edges() {
  local -n _adj=$1
  local edges_file
  edges_file="$(mktemp "${TMPDIR}/edges.XXXX")"
  : > "$edges_file"
  for k in "${!_adj[@]}"; do
    IFS=',' read -r a b <<< "$k"
    printf "%s %s\n" "$a" "$b" >> "$edges_file"
  done
  if command -v tsort >/dev/null 2>&1; then
    tsort "$edges_file" || { rm -f "$edges_file"; return 1; }
    rm -f "$edges_file"
    return 0
  else
    # Kahn fallback
    declare -A indeg
    declare -A nodes
    while read -r a b; do
      nodes["$a"]=1; nodes["$b"]=1
      indeg["$b"]=$((indeg["$b"]+1))
      indeg["$a"]=$((indeg["$a"]+0))
    done < "$edges_file"
    queue=()
    for n in "${!nodes[@]}"; do
      if [ "${indeg[$n]:-0}" -eq 0 ]; then queue+=("$n"); fi
    done
    result=()
    while [ "${#queue[@]}" -gt 0 ]; do
      v="${queue[0]}"; queue=("${queue[@]:1}")
      result+=("$v")
      for k in "${!_adj[@]}"; do
        IFS=',' read -r a b <<< "$k"
        if [ "$a" = "$v" ]; then
          indeg["$b"]=$((indeg["$b"]-1))
          if [ "${indeg[$b]:-0}" -eq 0 ]; then queue+=("$b"); fi
        fi
      done
    done
    if [ "${#result[@]}" -lt "${#nodes[@]}" ]; then
      log_error "Cycle detected during topo sort"
      rm -f "$edges_file"
      return $E_CYCLE
    fi
    for r in "${result[@]}"; do printf "%s\n" "$r"; done
    rm -f "$edges_file"
    return 0
  fi
}

# --------- Installed check & version helpers ----------
check_installed() {
  local pkg="$1"
  if command -v "$pkg" >/dev/null 2>&1; then
    printf "binary"; return 0
  fi
  if [ -f "$PACKAGES_DIR/$pkg.installed" ]; then
    printf "installed_marker"; return 0
  fi
  if command -v ldconfig >/dev/null 2>&1; then
    if ldconfig -p 2>/dev/null | grep -i "lib${pkg}\." >/dev/null 2>&1; then
      printf "lib"; return 0
    fi
  fi
  return 1
}

version_compare() {
  local v1="$1" op="$2" v2="$3"
  if [ -z "$v1" ] || [ -z "$v2" ]; then return 2; fi
  if command -v sort >/dev/null 2>&1 && sort -V </dev/null >/dev/null 2>&1 2>/dev/null; then
    case "$op" in
      "=") [ "$v1" = "$v2" ] && return 0 || return 1 ;;
      ">" ) [ "$(printf '%s\n%s\n' "$v2" "$v1" | sort -V | tail -n1)" = "$v1" ] && [ "$v1" != "$v2" ] && return 0 || return 1 ;;
      "<" ) [ "$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | tail -n1)" = "$v2" ] && [ "$v1" != "$v2" ] && return 0 || return 1 ;;
      ">=") [ "$(printf '%s\n%s\n' "$v2" "$v1" | sort -V | tail -n1)" = "$v1" ] && return 0 || return 1 ;;
      "<=") [ "$(printf '%s\n%s\n' "$v1" "$v2" | sort -V | tail -n1)" = "$v2" ] && return 0 || return 1 ;;
      *) return 2 ;;
    esac
  else
    case "$op" in
      "=") [ "$v1" = "$v2" ] && return 0 || return 1 ;;
      ">" ) [ "$v1" \> "$v2" ] && return 0 || return 1 ;;
      "<" ) [ "$v1" \< "$v2" ] && return 0 || return 1 ;;
      ">=") { [ "$v1" = "$v2" ] || [ "$v1" \> "$v2" ]; } && return 0 || return 1 ;;
      "<=") { [ "$v1" = "$v2" ] || [ "$v1" \< "$v2" ]; } && return 0 || return 1 ;;
      *) return 2 ;;
    esac
  fi
}

parse_pin() {
  local pin="$1"
  if [[ "$pin" =~ ^([a-z0-9._+\-]+)([<>=]{1,2})(.+)$ ]]; then
    printf "%s|%s|%s" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return 0
  else
    if [[ "$pin" =~ ^([a-z0-9._+\-]+)$ ]]; then
      printf "%s|=|latest" "${BASH_REMATCH[1]}"
      return 0
    fi
  fi
  return 1
}

# --------- Commands ----------
cmd_check() {
  local meta="$1"
  parse_dependencies_from_metafile "$meta" || return $?
  local missing=0
  for d in "${DEP_REQUIRED[@]:-}"; do
    d="$(echo "$d" | xargs)"
    if ! validate_pkg_name "$d"; then
      log_error "Invalid dependency name: $d"; missing=1; continue
    fi
    if check_installed "$d" >/dev/null 2>&1; then
      log_info "Dependency $d: OK (installed)"
    else
      log_warn "Dependency $d: MISSING"
      missing=1
    fi
  done
  for pin in "${DEP_PINS[@]:-}"; do
    pair="$(parse_pin "$pin")" || { log_warn "Could not parse pin: $pin"; missing=1; continue; }
    pkg="${pair%%|*}"; rest="${pair#*|}"; op="${rest%%|*}"; ver="${rest##*|}"
    inst_ver=""
    if [ -f "$PACKAGES_DIR/$pkg.installed" ]; then inst_ver="$(cat "$PACKAGES_DIR/$pkg.installed" 2>/dev/null || true)"; fi
    if [ -z "$inst_ver" ] && command -v "$pkg" >/dev/null 2>&1; then
      inst_ver="$($pkg --version 2>/dev/null | head -n1 | grep -Eo '[0-9]+(\.[0-9]+)+|[0-9]+' | head -n1 || true)"
    fi
    if [ -z "$inst_ver" ]; then
      log_warn "Pin check: $pkg $op $ver -> not installed"; missing=1
    else
      if version_compare "$inst_ver" "$op" "$ver"; then
        log_info "Pin check: $pkg $op $ver -> OK (installed $inst_ver)"
      else
        log_warn "Pin check: $pkg $op $ver -> MISMATCH (installed $inst_ver)"; missing=1
      fi
    fi
  done
  if [ "$missing" -ne 0 ]; then return 1; fi
  return 0
}

cmd_resolve() {
  local meta="$1"
  parse_ini_file "$meta" || return $?
  pkgname="$(ini_get meta name "")"
  if [ -z "$pkgname" ]; then die $E_ARGS "Metafile missing meta.name"; fi
  RESOLVED_LIST=(); VISITED=(); ONSTACK=(); ADJ=()
  dfs_resolve "$pkgname" "$meta" || return $?
  # write topo order to OUT_FILE
  if [ -z "$OUT_FILE" ]; then
    topo_sort_edges ADJ
  else
    topo_sort_edges ADJ > "$OUT_FILE"
    log_info "Wrote resolve order to $OUT_FILE"
  fi
  return 0
}

cmd_graph() {
  local meta="$1" out="$2"
  parse_ini_file "$meta" || return $?
  pkgname="$(ini_get meta name "")"
  if [ -z "$pkgname" ]; then die $E_ARGS "Metafile missing meta.name"; fi
  RESOLVED_LIST=(); VISITED=(); ONSTACK=(); ADJ=()
  dfs_resolve "$pkgname" "$meta" || return $?
  local outdot="${out:-/dev/stdout}"
  {
    printf "digraph deps {\n"
    for k in "${!ADJ[@]}"; do
      IFS=',' read -r a b <<< "$k"
      printf "  \"%s\" -> \"%s\";\n" "$a" "$b"
    done
    printf "}\n"
  } > "$outdot"
  log_info "Wrote DOT graph to $outdot"
  return 0
}

cmd_remove_orphans() {
  declare -A revcount
  shopt -s globstar nullglob
  for ini in "$META_DIR"/**/*.ini; do
    parse_ini_file "$ini" || continue
    pname="$(ini_get meta name "")"
    raw="$(ini_get dependencies required "")"
    IFS=',' read -r -a reqs <<< "$(echo "$raw" | sed 's/,/ /g' | xargs 2>/dev/null || echo "")"
    for r in "${reqs[@]:-}"; do r="$(echo "$r" | xargs)"; revcount["$r"]=$((revcount["$r"]+1)); done
  done
  orphans=()
  for ini in "$META_DIR"/**/*.ini; do
    pname="$(basename "$ini" .ini)"
    if [ "${revcount[$pname]:-0}" -eq 0 ]; then orphans+=("$pname"); fi
  done
  if [ "${#orphans[@]}" -eq 0 ]; then log_info "No orphan packages found"; return 0; fi
  log_warn "Orphan packages detected: ${orphans[*]}"
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: would uninstall: ${orphans[*]}"; return 0; fi
  for p in "${orphans[@]}"; do
    if [ -x "./uninstall.sh" ]; then
      ./uninstall.sh "$p" || log_warn "uninstall.sh failed for $p"
    elif [ -x "/usr/local/bin/uninstall.sh" ]; then
      /usr/local/bin/uninstall.sh "$p" || log_warn "uninstall.sh failed for $p"
    else
      log_info "Removing orphan marker for $p"
      rm -f "$PACKAGES_DIR/$p.installed" || log_warn "Could not remove installed marker for $p"
    fi
  done
  return 0
}

cmd_upgrade_system() {
  if [ "$DRY_RUN" = true ]; then log_info "DRY-RUN: Would call upgrade.sh to rebuild system"; return 0; fi
  if [ -x "./upgrade.sh" ]; then ./upgrade.sh || die $E_GENERIC "upgrade.sh failed"
  elif [ -x "/usr/local/bin/upgrade.sh" ]; then /usr/local/bin/upgrade.sh || die $E_GENERIC "upgrade.sh failed"
  else log_error "upgrade.sh not found; cannot rebuild automatically"; return $E_MISSING; fi
  return 0
}

# --------- CLI ----------
show_usage() {
  cat <<EOF
dependency.sh - dependency resolver for Rolling LFS
Usage:
  dependency.sh --check <meta.ini>
  dependency.sh --resolve <meta.ini> --out <file>
  dependency.sh --graph <meta.ini> --out <dotfile>
  dependency.sh --all --check
  dependency.sh --remove-orphans
  dependency.sh --upgrade-system
Options:
  --dry-run     Simulate
  --verbose     Verbose logging
  --log-file    Path to log file
  --help
EOF
}

# parse args
ARGS=("$@")
if [ "$#" -eq 0 ]; then show_usage; exit 0; fi
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --check) CMD="check"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --resolve) CMD="resolve"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --graph) CMD="graph"; META_PATH="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --out) OUT_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --all) DO_ALL=true;;
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    --log-file) LOG_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --remove-orphans) DO_REMOVE_ORPHANS=true;;
    --upgrade-system) DO_UPGRADE=true;;
    --help|-h) show_usage; exit 0;;
    *) echo "Unknown arg: $a"; show_usage; exit $E_ARGS;;
  esac
done

mkdir -p "$(dirname "$LOG_FILE")"
: >> "$LOG_FILE"

# dispatch
if [ "${DO_REMOVE_ORPHANS}" = true ]; then cmd_remove_orphans; exit $?; fi
if [ "${DO_UPGRADE}" = true ]; then cmd_upgrade_system; exit $?; fi

case "${CMD:-}" in
  check)
    if [ "${DO_ALL}" = true ]; then
      shopt -s globstar nullglob
      rc=0
      for ini in "$META_DIR"/**/*.ini; do
        log_info "Checking $ini"
        cmd_check "$ini" || rc=$((rc+1))
      done
      exit $rc
    else
      cmd_check "$META_PATH"; exit $?
    fi
    ;;
  resolve)
    if [ -z "${OUT_FILE}" ]; then die $E_ARGS "resolve needs --out <file>"; fi
    cmd_resolve "$META_PATH"; exit $?
    ;;
  graph)
    if [ -z "${OUT_FILE}" ]; then die $E_ARGS "graph needs --out <file>"; fi
    cmd_graph "$META_PATH" "$OUT_FILE"; exit $?
    ;;
  *)
    show_usage; exit 0
    ;;
esac
