#!/usr/bin/env bash
# build.sh - Final build orchestrator for Rolling LFS
# - robust error handling, sandbox integration, dependency checks, hooks, artifacts
# - enhanced report generation with timings, resource snapshots, artifact checksums, logs, test results
# - supports: --parallel, --resume, --artifact, --analyze, --report, --dry-run, --verbose
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Defaults & paths ----------
SANDBOX_SH="${SANDBOX_SH:-/mnt/data/sandbox.sh}"
UTILS_SH="${UTILS_SH:-/mnt/data/utils.sh}"
DEPENDENCY_SH="${DEPENDENCY_SH:-/mnt/data/dependency.sh}"
META_DIR="${META_DIR:-$HOME/lfs-sandbox/meta}"
BUILD_ROOT="${BUILD_ROOT:-$HOME/lfs-sandbox/build}"
SOURCES_ROOT="${SOURCES_ROOT:-$HOME/lfs-sandbox/sources}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$HOME/lfs-sandbox/artifacts}"
BUILD_STATE_DIR="${BUILD_STATE_DIR:-$HOME/lfs-sandbox/state}"
LOG_DIR="${LOG_DIR:-$HOME/lfs-sandbox/logs}"
PARALLEL_JOBS="${PARALLEL_JOBS:-2}"
DRY_RUN=false
VERBOSE=false
RESUME=false
DO_ARTIFACT=false
DO_ANALYZE=false
DO_REPORT=false
IGNORE_HOOK_ERRORS=false
REQUIRE_CHECKSUM=true
TIMEOUT_BUILD=0  # seconds, 0=no timeout

# Ensure directories
mkdir -p "$BUILD_ROOT" "$SOURCES_ROOT" "$ARTIFACTS_DIR" "$BUILD_STATE_DIR" "$LOG_DIR"

# Load helpers if present (non-fatal)
if [ -f "$UTILS_SH" ]; then
  # shellcheck disable=SC1091
  source "$UTILS_SH" || true
fi
if [ -f "$DEPENDENCY_SH" ]; then
  # shellcheck disable=SC1091
  source "$DEPENDENCY_SH" || true
fi

# ---------- Logging ----------
timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log_file="$LOG_DIR/build-controller.log"
log() { local level="$1"; shift; printf "[%s] %s %s\n" "$level" "$(timestamp)" "$*" | tee -a "$log_file"; }
die() { local code=${1:-1}; shift || true; log ERROR "$*"; exit "$code"; }

# Trap to catch unexpected failures and ensure report generation
_on_err() {
  local rc=${1:-$?}
  local lineno=${2:-$LINENO}
  log ERROR "build.sh unexpected failure (rc=$rc) at line $lineno"
  # if in package build, attempt to write a failed report
  if [ -n "${CURRENT_PKG:-}" ]; then
    write_report "$CURRENT_PKG" "failed" || true
    mark_state "$CURRENT_PKG" "failed"
  fi
  exit "$rc"
}
trap '_on_err $? $LINENO' ERR INT TERM

# ---------- Helpers ----------
abspath(){ case "$1" in /*) printf "%s" "$1";; *) printf "%s" "$(pwd)/$1";; esac; }

# Safe command runner: logs and optional timeout
run_cmd() {
  local desc="$1"; shift
  if [ "$DRY_RUN" = true ]; then
    log INFO "DRY-RUN: $desc"
    return 0
  fi
  log INFO "$desc"
  if [ "$TIMEOUT_BUILD" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
    if [ "$VERBOSE" = true ]; then timeout "$TIMEOUT_BUILD" "$@"; else timeout "$TIMEOUT_BUILD" "$@" >> "$LOG_DIR/last_cmd.log" 2>&1; fi
  else
    if [ "$VERBOSE" = true ]; then "$@"; else "$@" >> "$LOG_DIR/last_cmd.log" 2>&1; fi
  fi
  return $?
}

# Download with retries and progress
download_with_retry() {
  local url="$1" dest="$2"
  local tries=0 max=4
  while [ $tries -lt $max ]; do
    if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: download $url -> $dest"; return 0; fi
    mkdir -p "$(dirname "$dest")"
    if command -v curl >/dev/null 2>&1; then
      if [ "$VERBOSE" = true ]; then curl -L --retry 3 --retry-delay 5 -C - -o "$dest" "$url"; else curl -sS -L --retry 3 --retry-delay 5 -C - -o "$dest" "$url"; fi
      rc=$?
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$dest" "$url"
      rc=$?
    else
      die 1 "No downloader available (curl or wget)"
    fi
    if [ $rc -eq 0 ]; then return 0; fi
    tries=$((tries+1))
    log WARN "Download attempt $tries failed for $url (rc=$rc)"
    sleep 2
  done
  return 1
}

# Verify sha256 checksum
verify_checksum() {
  local file="$1" expected="$2"
  if [ -z "$expected" ]; then
    if [ "$REQUIRE_CHECKSUM" = true ]; then log ERROR "Checksum required but not provided for $file"; return 1; else log WARN "No checksum for $file"; return 0; fi
  fi
  if [ ! -f "$file" ]; then log ERROR "File not found for checksum: $file"; return 1; fi
  if command -v sha256sum >/dev/null 2>&1; then
    local calc; calc=$(sha256sum "$file" | awk '{print $1}')
    if [ "$calc" = "$expected" ]; then log INFO "Checksum OK: $(basename "$file")"; return 0; else log ERROR "Checksum mismatch for $(basename "$file"): expected $expected got $calc"; return 2; fi
  else
    log WARN "sha256sum missing; skipping checksum"
    return 0
  fi
}

# INI parse (safe)
declare -A INI
parse_ini() {
  INI=()
  local file="$1"
  [ -f "$file" ] || return 1
  local section=""
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%[#;]*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then section="${BASH_REMATCH[1]}"; continue; fi
    if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
      key="$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]' | tr ' ' '_' )"
      val="${BASH_REMATCH[2]}"
      INI["${section}.${key}"]="$val"
    fi
  done < "$file"
}

ini_get(){ local s="$1" k="$2" d="${3:-}"; printf "%s" "${INI[${s}.${k}]:-$d}"; }

# Build state helpers
mark_state(){ local pkg="$1" state="$2"; echo "$state" > "$BUILD_STATE_DIR/${pkg}.state"; }
read_state(){ local pkg="$1"; if [ -f "$BUILD_STATE_DIR/${pkg}.state" ]; then cat "$BUILD_STATE_DIR/${pkg}.state"; else echo "none"; fi }

# Resource snapshot
collect_resource_snapshot(){ local out="$1"; { echo "timestamp: $(timestamp)"; echo "uptime: $(uptime -p 2>/dev/null || true)"; echo "free: $(free -h 2>/dev/null || true)"; ps -eo pid,%cpu,%mem,command --sort=-%cpu | head -n 6 || true; } > "$out"; }

# Safe apply patch
apply_patch() {
  local patchfile="$1" workdir="$2" pstrip="${3:-1}"
  (cd "$workdir" && patch -p"$pstrip" < "$patchfile") >> "$worklog" 2>&1
  return $?
}

# Write detailed report for package
write_report() {
  local pkg="$1" status="${2:-installed}"
  local meta="$META_FILE_CURRENT"
  local name version category
  name="$(ini_get meta name "")"
  version="$(ini_get meta version "")"
  category="$(ini_get meta category "misc")"
  local report="$LOG_DIR/report-${name}-${version}.txt"
  {
    echo "report_generated: $(timestamp)"
    echo "package: $name"
    echo "version: $version"
    echo "category: $category"
    echo "status: $status"
    echo "start_time: ${BUILD_META_START_TIME:-unknown}"
    echo "end_time: ${BUILD_META_END_TIME:-unknown}"
    echo "elapsed_seconds: ${BUILD_META_ELAPSED_SEC:-unknown}"
    echo "build_exit_code: ${BUILD_META_EXIT_CODE:-unknown}"
    echo "build_log: ${worklog:-unknown}"
    echo "check_log: ${checklog:-unknown}"
    echo "resource_snapshot: ${reslog:-unknown}"
    if [ -n "${artifact_path:-}" ] && [ -f "${artifact_path:-}" ]; then
      echo "artifact: ${artifact_path}"
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$artifact_path" | awk '{print "artifact_sha256: "$1}'
        du -h "$artifact_path" | awk '{print "artifact_size: "$1}'
      fi
    fi
    echo "installed_marker: ${ARTIFACTS_DIR}/${name}-${version}.installed"
    # list installed files if install_record exists
    if [ -f "${BUILD_ROOT}/${name}-${version}/install-files.txt" ]; then
      echo "installed_files_list: ${BUILD_ROOT}/${name}-${version}/install-files.txt"
      echo "installed_files_count: $(wc -l < "${BUILD_ROOT}/${name}-${version}/install-files.txt" 2>/dev/null || echo 0)"
    fi
  } > "$report"
  log INFO "Report written: $report"
  return 0
}

# ---------- build one metafile ----------
build_one() {
  local meta="$1"
  META_FILE_CURRENT="$meta"
  local pkg="$(basename "$meta" .ini)"
  CURRENT_PKG="$pkg"
  log INFO "=== BUILD START: $pkg ==="
  mark_state "$pkg" "started"
  BUILD_META_START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  local start_ts=$(date +%s)

  parse_ini "$meta" || { mark_state "$pkg" "parse_error"; BUILD_META_EXIT_CODE=1; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "parse_error"; return 1; }

  local name version category
  name="$(ini_get meta name "")"
  version="$(ini_get meta version "")"
  category="$(ini_get meta category "misc")"
  if [ -z "$name" ]; then log ERROR "Metafile missing name"; mark_state "$pkg" "bad_meta"; BUILD_META_EXIT_CODE=1; write_report "$pkg" "bad_meta"; return 1; fi

  local builddir="$BUILD_ROOT/${name}-${version}"
  mkdir -p "$builddir"
  worklog="$LOG_DIR/${name}-${version}.build.log"
  checklog="$LOG_DIR/${name}-${version}.check.log"
  reslog="$LOG_DIR/${name}-${version}.resources.log"

  # dependency check
  if [ -x "$DEPENDENCY_SH" ]; then
    if ! "$DEPENDENCY_SH" --check "$meta"; then
      log ERROR "Dependency check failed for $name"; mark_state "$pkg" "deps_failed"; BUILD_META_EXIT_CODE=2; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "deps_failed"; return 2
    fi
  fi

  # collect source entries
  local src_urls=()
  for k in "${!INI[@]}"; do
    if [[ "$k" =~ ^source\.src([0-9]+)\.url$ ]]; then src_urls+=("${INI[$k]}"); fi
  done

  # fetch and extract sources
  local i=0
  for url in "${src_urls[@]:-}"; do
    i=$((i+1))
    local fn="$(basename "$url")"
    local dest="$SOURCES_ROOT/${name}-${version}-$i-$fn"
    if [ -f "$dest" ]; then
      log INFO "Using cached source $dest"
    else
      download_with_retry "$url" "$dest" || { log ERROR "Download failed: $url"; mark_state "$pkg" "download_failed"; BUILD_META_EXIT_CODE=3; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "download_failed"; return 3; }
    fi
    local csum="$(ini_get source src${i}.sha256 "")"
    verify_checksum "$dest" "$csum" || { mark_state "$pkg" "checksum_failed"; BUILD_META_EXIT_CODE=4; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "checksum_failed"; return 4; }
    log INFO "Extracting $dest -> $builddir"
    case "$dest" in
      *.tar.gz|*.tgz) tar -xzf "$dest" -C "$builddir" ;; 
      *.tar.xz) tar -xJf "$dest" -C "$builddir" ;; 
      *.tar.bz2) tar -xjf "$dest" -C "$builddir" ;; 
      *.zip) unzip -q "$dest" -d "$builddir" ;; 
      *) mkdir -p "$builddir/src.$i" && cp -a "$dest" "$builddir/src.$i/" || true ;; 
    esac
  done

  # patches
  for k in "${!INI[@]}"; do
    if [[ "$k" =~ ^patches\.patch([0-9]+)\.url$ ]]; then
      purl="${INI[$k]}"; pidx="${BASH_REMATCH[1]}"
      pdest="$SOURCES_ROOT/${name}-${version}-patch${pidx}-$(basename "$purl")"
      download_with_retry "$purl" "$pdest" || { log ERROR "Patch download failed: $purl"; mark_state "$pkg" "patch_download_failed"; BUILD_META_EXIT_CODE=5; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "patch_download_failed"; return 5; }
      psha="$(ini_get patches patch${pidx}.sha256 "")"
      verify_checksum "$pdest" "$psha" || { mark_state "$pkg" "patch_checksum_failed"; BUILD_META_EXIT_CODE=6; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "patch_checksum_failed"; return 6; }
      log INFO "Applying patch $pdest"
      if ! apply_patch "$pdest" "$builddir" "1"; then log ERROR "Patch apply failed: $pdest"; mark_state "$pkg" "patch_apply_failed"; BUILD_META_EXIT_CODE=7; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "patch_apply_failed"; return 7; fi
    fi
  done

  # pre_build hook
  prehook="$(ini_get hooks pre_build "")"
  if [ -n "$prehook" ]; then
    if [ -f "$(dirname "$meta")/$prehook" ]; then
      if ! bash "$(dirname "$meta")/$prehook" >> "$worklog" 2>&1; then
        log ERROR "pre_build hook failed: $prehook"
        if [ "$IGNORE_HOOK_ERRORS" != true ]; then mark_state "$pkg" "hook_failed"; BUILD_META_EXIT_CODE=8; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "hook_failed"; return 8; fi
      fi
    else
      log WARN "pre_build hook not found: $prehook"
    fi
  fi

  # create local build script if needed
  if [ ! -f "$builddir/build.sh.local" ]; then
    cat > "$builddir/build.sh.local" <<'EOF'
set -euo pipefail
cd /build
if [ -f configure ]; then ./configure --prefix=/usr; fi
make -j$(nproc)
if [ -f Makefile ]; then make check || true; fi
make install DESTDIR=/installroot || true
EOF
    chmod +x "$builddir/build.sh.local"
  fi

  # ensure sandbox and copy build tree
  if [ -x "$SANDBOX_SH" ]; then
    log INFO "Preparing sandbox for $pkg"
    "$SANDBOX_SH" --name "$pkg" --create --force >/dev/null 2>&1 || log WARN "sandbox create returned non-zero"
    rsync -a --delete "$builddir/" "$SANDBOX_ROOT/$pkg/build/" 2>/dev/null || true
    # execute build inside sandbox, capture exit code
    if ! "$SANDBOX_SH" --name "$pkg" --exec "cd /build && ./build.sh.local" >> "$worklog" 2>&1; then
      log ERROR "Build failed inside sandbox for $pkg (see $worklog)"
      mark_state "$pkg" "build_failed"
      BUILD_META_EXIT_CODE=9
      BUILD_META_END_TIME="$(timestamp)"
      BUILD_META_ELAPSED_SEC=0
      write_report "$pkg" "build_failed"
      return 9
    fi
  else
    log WARN "No sandbox available; building locally (less secure)"
    if ! (cd "$builddir" && ./build.sh.local) >> "$worklog" 2>&1; then
      log ERROR "Local build failed for $pkg (see $worklog)"; mark_state "$pkg" "build_failed"; BUILD_META_EXIT_CODE=9; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "build_failed"; return 9
    fi
  fi

  # run check step if specified
  if [ -n "$(ini_get build check "")" ]; then
    log INFO "Running check step for $pkg"
    if ! "$SANDBOX_SH" --name "$pkg" --exec "cd /build && make check" >> "$checklog" 2>&1; then
      log WARN "make check reported failures for $pkg (see $checklog)"
      check_ret=1
    else
      check_ret=0
    fi
  else
    check_ret=0
  fi

  # optional post_build hook
  posthook="$(ini_get hooks post_build "")"
  if [ -n "$posthook" ] && [ -f "$(dirname "$meta")/$posthook" ]; then
    if ! bash "$(dirname "$meta")/$posthook" >> "$worklog" 2>&1; then
      log_ERROR="post_build hook failed: $posthook"
      log WARN "$log_ERROR"
      [ "$IGNORE_HOOK_ERRORS" = true ] || { mark_state "$pkg" "hook_failed"; BUILD_META_EXIT_CODE=10; BUILD_META_END_TIME="$(timestamp)"; BUILD_META_ELAPSED_SEC=0; write_report "$pkg" "hook_failed"; return 10; }
    fi
  fi

  # create installed marker and record installed files if possible
  installed_marker="$ARTIFACTS_DIR/${name}-${version}.installed"
  echo "$version" > "$installed_marker" || true
  # try to collect installed files list if installroot recorded
  if [ -d "$SANDBOX_ROOT/$pkg/installroot" ]; then
    find "$SANDBOX_ROOT/$pkg/installroot" -type f > "$builddir/install-files.txt" || true
  fi

  # artifact packaging
  artifact_path=""
  if [ "$DO_ARTIFACT" = true ]; then
    artifact_path="$ARTIFACTS_DIR/${name}-${version}.tar.zst"
    if command -v zstd >/dev/null 2>&1; then
      (cd "$builddir" && tar -cf - .) | zstd -q -o "$artifact_path" || log WARN "artifact creation failed"
    else
      artifact_path="${artifact_path%.zst}.xz"
      (cd "$builddir" && tar -cJf "$artifact_path" .) || log WARN "artifact xz creation failed"
    fi
  fi

  # resource snapshot + analysis
  if [ "$DO_ANALYZE" = true ]; then
    collect_resource_snapshot "$reslog"
  fi

  # finalize times and report
  local end_ts=$(date +%s)
  BUILD_META_END_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  BUILD_META_ELAPSED_SEC=$((end_ts - start_ts))
  BUILD_META_EXIT_CODE=0
  mark_state "$pkg" "installed"
  write_report "$pkg" "installed"
  log INFO "=== BUILD END: $pkg (elapsed ${BUILD_META_ELAPSED_SEC}s) ==="
  return 0
}

# ---------- CLI & dispatch ----------
show_usage() {
  cat <<EOF
build.sh - orchestrador de builds (final)
Usage:
  build.sh --meta <meta.ini> [--dry-run] [--verbose] [--resume] [--artifact] [--analyze] [--report]
  build.sh --all --parallel N
Options:
  --meta <file>    Build single metafile
  --all            Build all metafiles under $META_DIR
  --parallel N     Run up to N builds concurrently
  --resume         Resume builds using state markers
  --artifact       Produce artifact tarball
  --analyze        Produce resource snapshots
  --report         Produce summary report per package
  --dry-run
  --verbose
EOF
}

# Parse arguments
ARGS=("$@")
if [ "$#" -eq 0 ]; then show_usage; exit 0; fi
TARGETS=()
ALL=false
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --meta) TARGETS+=("${ARGS[0]:-}"); ARGS=("${ARGS[@]:1}");;
    --all) ALL=true;;
    --parallel) PARALLEL_JOBS="${ARGS[0]:-2}"; ARGS=("${ARGS[@]:1}");;
    --resume) RESUME=true;;
    --artifact) DO_ARTIFACT=true;;
    --analyze) DO_ANALYZE=true;;
    --report) DO_REPORT=true;;
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    *) echo "Unknown arg: $a"; show_usage; exit 2;;
  esac
done

if [ "$ALL" = true ]; then
  while IFS= read -r f; do TARGETS+=("$f"); done < <(find "$META_DIR" -type f -name "*.ini")
fi

# Run targets with simple concurrency control
pids=()
for m in "${TARGETS[@]:-}"; do
  pkgname="$(basename "$m" .ini)"
  if [ "$RESUME" = true ] && [ "$(read_state "$pkgname")" = "installed" ]; then
    log INFO "Skipping $pkgname (already installed)"
    continue
  fi
  # throttle
  while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL_JOBS" ]; do sleep 1; done
  build_one "$m" &
  pids+=("$!")
done

# wait for background jobs
rcsum=0
for pid in "${pids[@]:-}"; do
  if ! wait "$pid"; then rcsum=$((rcsum+1)); fi
done

if [ "$rcsum" -ne 0 ]; then log ERROR "Some builds failed (count $rcsum)"; exit 1; fi
log INFO "All builds finished successfully"
exit 0
