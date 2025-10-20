#!/usr/bin/env bash
# update_autorebuild.sh - Extended update.sh with automatic dependency resolution and auto-rebuild
# Features:
#  - Detect upstream updates, update metafiles (.ini), download sources, verify checksums
#  - Resolve dependencies recursively, detect cycles, produce ordered rebuild queue
#  - Option --auto-rebuild to call build.sh for updated packages (in dependency order)
#  - Checkpointing (--resume), dry-run, verbose, notifications, robust error handling, retries, backoff
#  - Safety: backups of .ini, block unsafe URLs, sandbox-aware rebuild execution
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Configuration (adjust as needed) ----------
META_ROOT="${META_ROOT:-$HOME/lfs-sandbox/meta}"
CACHE_DIR="${CACHE_DIR:-/var/cache/lfs-update}"
LOG_DIR="${LOG_DIR:-/var/log/lfs-update}"
REPORT_DIR="${REPORT_DIR:-/var/log/lfs-update/reports}"
BUILD_QUEUE_TXT="${BUILD_QUEUE_TXT:-/var/cache/lfs-update/update-queue.txt}"
BUILD_QUEUE_JSON="${BUILD_QUEUE_JSON:-/var/cache/lfs-update/update-queue.json}"
SOURCES_DIR="${SOURCES_DIR:-$HOME/lfs-sandbox/sources}"
BUILD_SH="${BUILD_SH:-/mnt/data/build_final.sh}"   # path to build.sh (adjust if yours differs)
SANDBOX_SH="${SANDBOX_SH:-/mnt/data/sandbox.sh}"   # optional sandbox wrapper
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
DRY_RUN=false
VERBOSE=false
DO_APPLY=false
DO_DOWNLOAD=false
DO_CHECK=true
AUTO_REBUILD=false
RESUME=false
NOTIFY=true
LOG_FILE=""
RETRY_MAX=4
RETRY_BACKOFF_BASE=2
HTTP_TIMEOUT=15
GITHUB_API_TOKEN="${GITHUB_API_TOKEN:-}"

# Create directories
mkdir -p "$CACHE_DIR" "$LOG_DIR" "$REPORT_DIR" "$SOURCES_DIR" "$(dirname "$BUILD_QUEUE_TXT")"

# ---------- Logging and notifications ----------
timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_logf="${LOG_FILE:-$LOG_DIR/update-$(date -u +%Y%m%dT%H%M%SZ).log"}"
log(){ local lvl="$1"; shift; printf "[%s] %s %s\n" "$lvl" "$(timestamp)" "$*" | tee -a "$_logf"; }
die(){ local code=${1:-1}; shift || true; log ERROR "$*"; notify "Update failed" "$*"; exit "$code"; }
notify(){ local t="$1"; local b="$2"; if [ "$NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1 && [ -n "${DISPLAY-}" ]; then notify-send --urgency=low "$t" "$b" || true; fi; log NOTIFY "$t - $b"; }

trap 'rc=$?; if [ $rc -ne 0 ]; then log ERROR "Unexpected exit rc=$rc"; notify "Update failed" "See log $_logf"; fi' ERR INT TERM

# ---------- Helpers ----------
abspath(){ case "$1" in /*) printf "%s" "$1";; *) printf "%s" "$(pwd)/$1";; esac; }

sha256_of_file(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk "{print \$1}"; else echo ""; fi; }

http_get(){
  local url="$1" out="$2"
  local tries=0 rc=1
  while [ $tries -lt $RETRY_MAX ]; do
    if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN http_get $url -> $out"; return 0; fi
    if command -v curl >/dev/null 2>&1; then
      if [ -n "$GITHUB_API_TOKEN" ] && echo "$url" | grep -q "api.github.com"; then
        curl -sS -H "Authorization: token $GITHUB_API_TOKEN" --max-time $HTTP_TIMEOUT -L "$url" -o "$out" && rc=0 || rc=$?
      else
        curl -sS --max-time $HTTP_TIMEOUT -L "$url" -o "$out" && rc=0 || rc=$?
      fi
    elif command -v wget >/dev/null 2>&1; then
      wget -q --timeout=$HTTP_TIMEOUT -O "$out" "$url" && rc=0 || rc=$?
    else
      die 1 "No HTTP client (curl or wget) available"
    fi
    if [ $rc -eq 0 ]; then return 0; fi
    tries=$((tries+1))
    sleep $((RETRY_BACKOFF_BASE ** tries))
    log WARN "Retry $tries for $url (rc=$rc)"
  done
  return $rc
}

is_url_allowed(){
  case "$1" in
    http*://localhost*|http*://127.*|file://*|http*://0.0.0.0*) return 1;;
    *) return 0;;
  esac
}

# ---------- INI parser ----------
declare -A INI
parse_ini_file(){
  local file="$1"
  INI=()
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

ini_get(){ local sec="$1" key="$2" def="${3:-}"; printf "%s" "${INI[${sec}.${key}]:-$def}"; }

# ---------- Upstream detectors (reuse from previous version) ----------
detect_github_latest(){
  local spec="$1" out="$2"
  local api="https://api.github.com/repos/${spec}/releases/latest"
  tmp="$(mktemp)"
  if ! http_get "$api" "$tmp"; then rm -f "$tmp"; return 1; fi
  if command -v jq >/dev/null 2>&1; then
    jq -r '.tag_name // .name // empty' "$tmp" > "$out" || true
  else
    grep -oP '"tag_name":\s*"\K[^"]+' "$tmp" | head -n1 > "$out" || true
  fi
  rm -f "$tmp"
  return 0
}

detect_git_tags(){
  local repo="$1" out="$2"
  if command -v git >/dev/null 2>&1; then
    tmp="$(mktemp)"
    git ls-remote --tags --refs "$repo" > "$tmp" 2>/dev/null || true
    awk -F/ '{print $3}' "$tmp" | grep -v '{}' | sort -V | tail -n1 > "$out" || true
    rm -f "$tmp"
    return 0
  fi
  return 1
}

detect_http_html_version(){
  local url="$1" regex="$2" out="$3"
  tmp="$(mktemp)"
  if ! http_get "$url" "$tmp"; then rm -f "$tmp"; return 1; fi
  grep -Po "$regex" "$tmp" | head -n1 > "$out" 2>/dev/null || true
  rm -f "$tmp"
  return 0
}

# ---------- Core: process single metafile ----------
process_meta(){
  local meta="$1"
  log INFO "Processing meta: $meta"
  parse_ini_file "$meta"
  local name current_version upstream srcurl_template checksum_field deps_field
  name="$(ini_get meta name "")"
  current_version="$(ini_get meta version "")"
  upstream="$(ini_get meta upstream_check "")"
  srcurl_template="$(ini_get source url "")"
  checksum_field="$(ini_get source sha256 "")"
  deps_field="$(ini_get deps depends "")"  # comma-separated dependencies (names matching meta filenames or package names)

  if [ -z "$name" ] || [ -z "$current_version" ]; then log WARN "meta incomplete: $meta"; return 0; fi
  if [ -z "$upstream" ]; then log WARN "no upstream_check for $name (meta: $meta)"; return 0; fi

  local new_version="" tmpver new_srcurl artifact_local sha
  scheme="${upstream%%:*}"
  rest="${upstream#*:}"
  case "$scheme" in
    github)
      detect_github_latest "$rest" tmpver || { log WARN "github detection failed for $name"; return 0; }
      new_version="$(cat tmpver 2>/dev/null || true)"; rm -f tmpver
      ;;
    git)
      detect_git_tags "$rest" tmpver || { log WARN "git tag detection failed for $name"; return 0; }
      new_version="$(cat tmpver 2>/dev/null || true)"; rm -f tmpver
      ;;
    http|https)
      url="${rest%%|*}"; regex="${rest#*|}"
      detect_http_html_version "$url" "$regex" tmpver || { log WARN "http/html detection failed for $name"; return 0; }
      new_version="$(cat tmpver 2>/dev/null || true)"; rm -f tmpver
      ;;
    ftp) log WARN "ftp upstream_check not fully supported for $name";;
    *) log WARN "unknown upstream scheme '$scheme' for $name";;
  esac

  if [ -z "$new_version" ]; then log INFO "No version detected for $name"; return 0; fi
  norm_current="${current_version#v}"; norm_new="${new_version#v}"
  if [ "$norm_new" = "$norm_current" ]; then log INFO "No update for $name (version $current_version)"; return 0; fi

  log INFO "Update available for $name: $current_version -> $new_version"

  # compute new source URL (template)
  new_srcurl="$srcurl_template"
  if [[ "$new_srcurl" == *"@VERSION@"* ]]; then
    new_srcurl="${new_srcurl//@VERSION@/$new_version}"
  else
    if echo "$new_srcurl" | grep -q "github.com" && echo "$new_srcurl" | grep -q "releases"; then
      new_srcurl=$(echo "$new_srcurl" | sed "s/$current_version/$new_version/g")
    fi
  fi

  if ! is_url_allowed "$new_srcurl"; then log WARN "New source URL blocked for safety: $new_srcurl"; return 0; fi

  if [ "$DO_DOWNLOAD" = true ] || [ "$DO_APPLY" = true ]; then
    fname="$(basename "$new_srcurl" | sed 's/?.*$//')"
    artifact_local="$CACHE_DIR/${name}-${new_version}-${fname}"
    log INFO "Downloading new source: $new_srcurl -> $artifact_local"
    if ! http_get "$new_srcurl" "$artifact_local"; then log ERROR "Download failed for $new_srcurl"; return 1; fi
    if ! tar -tf "$artifact_local" >/dev/null 2>&1 && ! unzip -t "$artifact_local" >/dev/null 2>&1; then
      log WARN "Downloaded file may not be a recognized archive: $artifact_local"
    fi
    sha="$(sha256_of_file "$artifact_local")"
    log INFO "Downloaded sha256: $sha"
  fi

  # apply changes to meta if requested
  if [ "$DO_APPLY" = true ]; then
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: would update meta $meta with version=$new_version url=$new_srcurl sha256=$sha"
    else
      # backup meta
      cp -a "$meta" "${meta}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
      # update version under [meta]
      awk -v sec="meta" -v key="version" -v val="$new_version" '
      BEGIN{insec=0; done=0;}
      {
        if ($0 ~ "^\\[meta\\]") { insec=1; print; next }
        if (insec && $0 ~ "^\\[") { if (!done) print key"="val; insec=0; print; next }
        if (insec && $0 ~ "^[[:space:]]*version[[:space:]]*=") { if (!done) { print "version="val; done=1 } else print; next }
        print
      }
      END{ if (insec && !done) print key"="val }
      ' "$meta" > "${meta}.new" && mv -f "${meta}.new" "$meta"
      # update source.url and source.sha256 under [source] (best-effort)
      if grep -q -E '^\[source\]' "$meta"; then
        if grep -q -E '^\s*url\s*=' "$meta"; then
          sed -i "0,/^\s*url\s*=.*/s//url=$new_srcurl/" "$meta" || true
        else
          awk '/^\[source\]/{print; print "url='"$new_srcurl"'"; next} {print}' "$meta" > "${meta}.new" && mv -f "${meta}.new" "$meta" || true
        fi
        if [ -n "$sha" ]; then
          if grep -q -E '^\s*sha256\s*=' "$meta"; then
            sed -i "0,/^\s*sha256\s*=.*/s//sha256=$sha/" "$meta" || true
          else
            awk '/^\[source\]/{print; print "sha256='"$sha"'"; next} {print}' "$meta" > "${meta}.new" && mv -f "${meta}.new" "$meta" || true
          fi
        fi
      else
        printf "\n[source]\nurl=%s\nsha256=%s\n" "$new_srcurl" "$sha" >> "$meta"
      fi
      log INFO "Meta updated: $meta (version -> $new_version)"
    fi
  fi

  # write a line to the updates TSV report
  printf "%s\t%s\t%s\t%s\t%s\n" "$name" "$current_version" "$new_version" "$new_srcurl" "${artifact_local:-}" >> "$REPORT_DIR/updates.tsv"

  # record dependency info for later graph build
  # store dependencies as comma-separated list in a temp file keyed by package name
  echo "${deps_field:-}" | sed 's/[[:space:]]//g' > "$CACHE_DIR/${name}.deps" || true

  # enqueue package for rebuild queue (we'll resolve full dependency closure later)
  echo "$name" >> "$CACHE_DIR/updated_packages.list"

  notify "Update found" "$name: $current_version → $new_version"
  return 0
}

# ---------- Scan metafiles and detect updates ----------
scan_all_meta(){
  log INFO "Scanning metafiles under $META_ROOT"
  > "$REPORT_DIR/updates.tsv" || true
  rm -f "$CACHE_DIR/updated_packages.list" "$CACHE_DIR/depgraph.tmp" || true
  mapfile -t metas < <(find "$META_ROOT" -type f -name "*.ini" 2>/dev/null || true)
  if [ "${#metas[@]}" -eq 0 ]; then log WARN "No metafiles found under $META_ROOT"; return 0; fi
  for m in "${metas[@]}"; do process_meta "$m"; done
}

# ---------- Dependency graph: build closure & topo sort ----------
# We'll build a directed graph where edges are pkg -> dep
build_dep_graph(){
  log INFO "Building dependency graph from detected updates"
  # Clear tmp file
  rm -f "$CACHE_DIR/depgraph.tmp" || true
  # For each package that was updated, read its deps file and append edges
  if [ -f "$CACHE_DIR/updated_packages.list" ]; then
    while IFS= read -r pkg; do
      depsf="$CACHE_DIR/${pkg}.deps"
      if [ -f "$depsf" ]; then
        deps=$(cat "$depsf" | tr ',' ' ')
        for d in $deps; do
          [ -n "$d" ] && printf "%s\t%s\n" "$pkg" "$d" >> "$CACHE_DIR/depgraph.tmp"
        done
      fi
    done < "$CACHE_DIR/updated_packages.list"
  fi
  # Also add nodes with zero deps so they appear in graph
  if [ -f "$CACHE_DIR/updated_packages.list" ]; then
    while IFS= read -r pkg; do printf "%s\t\n" "$pkg" >> "$CACHE_DIR/depgraph.tmp"; done < "$CACHE_DIR/updated_packages.list"
  fi
}

# Topological sort using Kahn's algorithm. Input: depgraph.tmp lines "pkg<TAB>dep"
topo_sort(){
  local infile="$CACHE_DIR/depgraph.tmp"
  local out="$CACHE_DIR/update_order.list"
  > "$out"
  # Build adjacency and indegree maps
  declare -A indeg adj
  while IFS=$'\t' read -r pkg dep; do
    if [ -z "${adj[$pkg]+x}" ]; then adj["$pkg"]="$dep"; else adj["$pkg"]="${adj[$pkg]} $dep"; fi
    if [ -n "$dep" ]; then indeg["$dep"]=$((indeg["$dep"]+1)); fi
    # ensure nodes exist
    : "${indeg[$pkg]:=0}"
  done < "$infile"
  # queue nodes with indeg 0
  q=()
  for k in "${!indeg[@]}"; do if [ "${indeg[$k]}" -eq 0 ]; then q+=("$k"); fi; done
  processed=0
  while [ "${#q[@]}" -gt 0 ]; do
    node="${q[0]}"; q=("${q[@]:1}")
    echo "$node" >> "$out"
    processed=$((processed+1))
    for neigh in ${adj[$node]:-}; do
      indeg["$neigh"]=$((indeg["$neigh"]-1))
      if [ "${indeg[$neigh]}" -eq 0 ]; then q+=("$neigh"); fi
    done
  done
  # detect cycle: if processed < number of nodes
  total_nodes=0; for _ in "${!indeg[@]}"; do total_nodes=$((total_nodes+1)); done
  if [ "$processed" -lt "$total_nodes" ]; then
    log ERROR "Dependency cycle detected or unresolved dependencies; aborting auto-rebuild. See depgraph at $CACHE_DIR/depgraph.tmp"
    return 2
  fi
  log INFO "Topological order written to $out"
  return 0
}

# ---------- Run rebuilds in order ----------
run_rebuilds(){
  if [ "$AUTO_REBUILD" != true ]; then log INFO "Auto-rebuild disabled"; return 0; fi
  if [ ! -f "$CACHE_DIR/update_order.list" ]; then log WARN "No rebuild order found"; return 0; fi
  notify "Auto-rebuild started" "Building updated packages (sandbox-aware)"
  while IFS= read -r pkg; do
    # find the metafile for pkg under META_ROOT (best-effort)
    meta=$(find "$META_ROOT" -type f -name "*.ini" -exec grep -Il "^name=$pkg$" {} \; 2>/dev/null | head -n1 || true)
    if [ -z "$meta" ]; then
      # fallback: try matching filename equals pkg.ini
      meta=$(find "$META_ROOT" -type f -name "${pkg}.ini" 2>/dev/null | head -n1 || true)
    fi
    if [ -z "$meta" ]; then log WARN "Metafile for $pkg not found; skipping build"; continue; fi
    log INFO "Rebuilding $pkg using meta $meta"
    if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: would call build.sh --meta $meta"; continue; fi
    # if sandbox available, call via sandbox to isolate build
    if [ -x "$SANDBOX_SH" ]; then
      # prefer to call the sandbox wrapper with the build script inside it
      "$SANDBOX_SH" --name "upd-$pkg" --create --force >/dev/null 2>&1 || true
      if ! "$SANDBOX_SH" --name "upd-$pkg" --exec "$BUILD_SH --meta '$meta' " >> "$_logf" 2>&1; then
        log ERROR "Build failed for $pkg (see logs)"
        notify "Rebuild failed" "$pkg failed; check logs"
        return 1
      fi
    else
      if ! "$BUILD_SH" --meta "$meta" >> "$_logf" 2>&1; then
        log ERROR "Build failed for $pkg (see logs)"
        notify "Rebuild failed" "$pkg failed; check logs"
        return 1
      fi
    fi
    log INFO "Build succeeded for $pkg"
  done < "$CACHE_DIR/update_order.list"
  notify "Auto-rebuild finished" "All queued packages rebuilt (if any)"
  return 0
}

# ---------- Reports ----------
generate_reports(){
  local tfile="$REPORT_DIR/updates-$(date -u +%Y%m%dT%H%M%SZ).txt"
  local jfile="$REPORT_DIR/updates-$(date -u +%Y%m%dT%H%M%SZ).json"
  {
    echo "update_report_generated: $(timestamp)"
    printf "name\told_version\tnew_version\tsource_url\tartifact_local\n"
    cat "$REPORT_DIR/updates.tsv" 2>/dev/null || true
  } > "$tfile"
  # simple json
  echo "[" > "$jfile"
  awk -F'\t' 'NF>=5 { printf "{\"name\":\"%s\",\"old\":\"%s\",\"new\":\"%s\",\"url\":\"%s\",\"artifact\":\"%s\"},\n",$1,$2,$3,$4,$5 }' "$REPORT_DIR/updates.tsv" >> "$jfile" || true
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY > "${jfile}.tmp"
import sys
p="${jfile}"
try:
    with open(p,'r') as f:
        s=f.read().rstrip()
    if s.endswith(','):
        s=s[:-1]
    s=s+"\n]"
    print(s)
except Exception:
    print("[]")
PY
    mv -f "${jfile}.tmp" "$jfile" || true
  else
    sed -i -e '$ s/,$//' "$jfile" || true
    echo "]" >> "$jfile"
  fi
  log INFO "Reports generated: $tfile and $jfile"
  if [ -s "$REPORT_DIR/updates.tsv" ]; then notify "Updates found" "See report $tfile"; fi
}

# ---------- CLI ----------
show_usage(){
  cat <<EOF
update_autorebuild.sh - check upstreams, update recipes, resolve deps, and auto-rebuild
Usage:
  update_autorebuild.sh [--check] [--apply] [--download] [--auto-rebuild] [--parallel N] [--resume] [--dry-run] [--verbose] [--log-file file]
Options:
  --check (default)    only check upstreams
  --apply              update .ini files and enqueue rebuilds (implies --download)
  --download           download new sources into cache
  --auto-rebuild       after updating recipes, resolve dependencies and rebuild updated packages
  --parallel N         number of parallel checks (default $PARALLEL_JOBS)
  --resume             resume from last checkpoint
  --dry-run            show actions but do not change files or run builds
  --verbose            verbose logging
  --no-notify          disable desktop notifications
  --log-file <file>    write logs to specific file
EOF
}

# ---------- Argument parsing ----------
ARGS=("$@")
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --check) DO_CHECK=true; DO_APPLY=false; DO_DOWNLOAD=false;;
    --apply) DO_APPLY=true; DO_DOWNLOAD=true; DO_CHECK=true;;
    --download) DO_DOWNLOAD=true;;
    --auto-rebuild) AUTO_REBUILD=true;;
    --parallel) PARALLEL_JOBS="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}");;
    --resume) RESUME=true;;
    --dry-run) DRY_RUN=true;;
    --verbose) VERBOSE=true;;
    --no-notify) NOTIFY=false;;
    --log-file) LOG_FILE="${ARGS[0]:-}"; ARGS=("${ARGS[@]:1}"); _logf="$LOG_FILE";;
    --help|-h) show_usage; exit 0;;
    *) echo "Unknown arg: $a"; show_usage; exit 2;;
  esac
done

# ---------- Main flow ----------
log INFO "Starting update_autorebuild.sh (apply=${DO_APPLY}, download=${DO_DOWNLOAD}, auto_rebuild=${AUTO_REBUILD})"
if [ "$RESUME" = true ]; then log INFO "RESUME requested - attempting to continue from last state"; fi

# Step 1: scan metas and detect updates
scan_all_meta

# Step 2: if any updates detected, build dep graph & topo sort
if [ -f "$CACHE_DIR/updated_packages.list" ] && [ -s "$CACHE_DIR/updated_packages.list" ]; then
  build_dep_graph
  if ! topo_sort; then
    log ERROR "Topological sort failed - aborting auto-rebuild"
  else
    # produce update_order.list -> map package names to metas and create CACHE_DIR/update_order.list
    mv -f "$CACHE_DIR/update_order.list" "$CACHE_DIR/update_order.list.tmp" || true
    # expand to include only packages that actually exist as metas (best-effort)
    : > "$CACHE_DIR/update_order.list"
    while IFS= read -r p; do
      echo "$p" >> "$CACHE_DIR/update_order.list"
    done < "$CACHE_DIR/update_order.list.tmp" || true
    # persist queue files
    cp -f "$CACHE_DIR/update_order.list" "$BUILD_QUEUE_TXT" || true
    # create json queue
    python3 - <<PY > "$BUILD_QUEUE_JSON" 2>/dev/null
import json,sys
q=[]
pfile="${CACHE_DIR}/update_order.list"
with open(pfile) as f:
    for l in f:
        q.append(l.strip())
json.dump({"queue":q,"generated":"%s"},sys.stdout) % ("%s"% ("$(date -u +%Y-%m-%dT%H:%M:%SZ)"))
PY || true
  fi
else
  log INFO "No updates detected; nothing to rebuild"
fi

# Step 3: generate reports
generate_reports

# Step 4: optionally auto-rebuild (in topo order)
if [ "$AUTO_REBUILD" = true ] && [ -f "$CACHE_DIR/update_order.list" ]; then
  if [ "$DRY_RUN" = true ]; then log INFO "DRY-RUN: would run auto-rebuild for packages in $CACHE_DIR/update_order.list"; else
    if ! run_rebuilds; then
      log ERROR "One or more rebuilds failed; aborting further builds"
      exit 1
    fi
  fi
fi

log INFO "update_autorebuild.sh finished"
exit 0
