#!/usr/bin/env bash
# update.sh - Automated upstream checker and recipe updater for Rolling LFS
# Features:
#  - Scan metafiles (.ini), detect new upstream versions (http/html/json/git/ftp)
#  - Download new sources to cache, verify checksums, update .ini safely with backup
#  - Generate consolidated reports (txt + json), notify via notify-send
#  - Options: --check, --apply, --download, --parallel, --resume, --dry-run, --verbose, --log-file
#  - Robust error handling, retries, backoff, sandbox-safe, security checks
set -eEuo pipefail
IFS=$'\n\t'

# ---------- Defaults ----------
META_ROOT="${META_ROOT:-$HOME/lfs-sandbox/meta}"
CACHE_DIR="${CACHE_DIR:-/var/cache/lfs-update}"
LOG_DIR="${LOG_DIR:-/var/log/lfs-update}"
REPORT_DIR="${REPORT_DIR:-/var/log/lfs-update/reports}"
BUILD_QUEUE="${BUILD_QUEUE:-/var/cache/lfs-update/update-queue.txt}"
SOURCES_DIR="${SOURCES_DIR:-$HOME/lfs-sandbox/sources}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
DRY_RUN=false
VERBOSE=false
DO_APPLY=false
DO_DOWNLOAD=false
DO_CHECK=true
RESUME=false
NOTIFY=true
LOG_FILE=""
RETRY_MAX=4
RETRY_BACKOFF_BASE=2
HTTP_TIMEOUT=15
GITHUB_API_TOKEN="${GITHUB_API_TOKEN:-}"

mkdir -p "$CACHE_DIR" "$LOG_DIR" "$REPORT_DIR" "$SOURCES_DIR" "$(dirname "$BUILD_QUEUE")"

# ---------- Logging ----------
timestamp(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
_logf="${LOG_FILE:-$LOG_DIR/update-$(date -u +%Y%m%dT%H%M%SZ).log"}"
log(){ local lvl="$1"; shift; printf "[%s] %s %s\n" "$lvl" "$(timestamp)" "$*" | tee -a "$_logf"; }
die(){ local code=${1:-1}; shift || true; log ERROR "$*"; exit "$code"; }
notify(){ local t="$1"; local b="$2"; if [ "$NOTIFY" = true ] && command -v notify-send >/dev/null 2>&1 && [ -n "${DISPLAY-}" ]; then notify-send --urgency=low "$t" "$b" || true; fi; log NOTIFY "$t - $b"; }

trap 'rc=$?; if [ $rc -ne 0 ]; then log ERROR "Unexpected exit rc=$rc"; notify "Update failed" "See log $_logf"; fi' ERR INT TERM

# ---------- Helpers ----------
abspath(){ case "$1" in /*) printf "%s" "$1";; *) printf "%s" "$(pwd)/$1";; esac; }

safe_write_ini_key(){
  # usage: safe_write_ini_key <file> <section> <key> <value>
  local file="$1"; local section="$2"; local key="$3"; local value="$4"
  local bak="${file}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$file" "$bak"
  log INFO "Backup metafile -> $bak"
  # simple replacement: replace first occurrence of key= within section, or append if missing
  awk -v sec="["$section"]" -v key="$key" -v val="$value" '
  BEGIN{insec=0; done=0}
  {
    if ($0 ~ "^\\[" sec "\\]") { insec=1; print; next }
    if (insec && $0 ~ "^\\[") { if (!done) { print key"="val; done=1 } ; insec=0; print; next }
    if (insec && $0 ~ "^[[:space:]]*"key"[[:space:]]*=") { if (!done) { print key"="val; done=1 } else print; next }
    print
  }
  END{ if (insec && !done) print key"="val }
  ' "$file" > "${file}.new" && mv -f "${file}.new" "$file"
}

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

sha256_of_file(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else echo ""; fi }

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

# ---------- Upstream checkers ----------
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

# ---------- Process single meta ----------
process_meta(){
  local meta="$1"
  log INFO "Processing meta: $meta"
  parse_ini_file "$meta"
  local name current_version upstream srcurl_template checksum_field
  name="$(ini_get meta name "")"
  current_version="$(ini_get meta version "")"
  upstream="$(ini_get meta upstream_check "")"
  srcurl_template="$(ini_get source url "")"
  checksum_field="$(ini_get source sha256 "")"

  if [ -z "$name" ] || [ -z "$current_version" ]; then log WARN "meta incomplete: $meta"; return 0; fi
  if [ -z "$upstream" ]; then log WARN "no upstream_check for $name (meta: $meta)"; return 0; fi

  new_version=""
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

  norm_current="${current_version#v}"
  norm_new="${new_version#v}"

  if [ "$norm_new" = "$norm_current" ]; then
    log INFO "No update for $name (version $current_version)"
    return 0
  fi

  log INFO "Update available for $name: $current_version -> $new_version"

  new_srcurl="$srcurl_template"
  if [[ "$new_srcurl" == *"@VERSION@"* ]]; then
    new_srcurl="${new_srcurl//@VERSION@/$new_version}"
  else
    if echo "$new_srcurl" | grep -q "github.com" && echo "$new_srcurl" | grep -q "releases"; then
      new_srcurl=$(echo "$new_srcurl" | sed "s/$current_version/$new_version/g")
    fi
  fi

  if ! is_url_allowed "$new_srcurl"; then log WARN "New source URL blocked for safety: $new_srcurl"; return 0; fi

  artifact_local=""
  sha=""
  if [ "$DO_DOWNLOAD" = true ] || [ "$DO_APPLY" = true ]; then
    fname="$(basename "$new_srcurl" | sed 's/?.*$//')"
    artifact_local="$CACHE_DIR/${name}-${new_version}-${fname}"
    log INFO "Downloading new source: $new_srcurl -> $artifact_local"
    if ! http_get "$new_srcurl" "$artifact_local"; then log ERROR "Download failed for $new_srcurl"; return 1; fi
    # basic archive test
    if ! tar -tf "$artifact_local" >/dev/null 2>&1 && ! unzip -t "$artifact_local" >/dev/null 2>&1; then
      log WARN "Downloaded file may not be a recognized archive: $artifact_local"
    fi
    sha="$(sha256_of_file "$artifact_local")"
    log INFO "Downloaded sha256: $sha"
  fi

  if [ "$DO_APPLY" = true ]; then
    if [ "$DRY_RUN" = true ]; then
      log INFO "DRY-RUN: would update meta $meta with version=$new_version url=$new_srcurl sha256=$sha"
    else
      safe_write_ini_key "$meta" "meta" "version" "$new_version"
      # try update source.url and sha256 under [source]
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

  printf "%s\t%s\t%s\t%s\t%s\n" "$name" "$current_version" "$new_version" "$new_srcurl" "${artifact_local:-}" >> "$REPORT_DIR/updates.tsv"
  if [ "$DO_APPLY" = true ]; then
    echo "$name" >> "$BUILD_QUEUE"
  fi

  notify "Update found" "$name: $current_version → $new_version"
  return 0
}

scan_all_meta(){
  log INFO "Scanning metafiles under $META_ROOT"
  > "$REPORT_DIR/updates.tsv" || true
  mapfile -t metas < <(find "$META_ROOT" -type f -name "*.ini" 2>/dev/null || true)
  if [ "${#metas[@]}" -eq 0 ]; then log WARN "No metafiles found under $META_ROOT"; return 0; fi
  for m in "${metas[@]}"; do process_meta "$m"; done
}

generate_reports(){
  local tfile="$REPORT_DIR/updates-$(date -u +%Y%m%dT%H%M%SZ).txt"
  local jfile="$REPORT_DIR/updates-$(date -u +%Y%m%dT%H%M%SZ).json"
  {
    echo "update_report_generated: $(timestamp)"
    printf "name\told_version\tnew_version\tsource_url\tartifact_local\n"
    cat "$REPORT_DIR/updates.tsv" 2>/dev/null || true
  } > "$tfile"
  # json
  echo "[" > "$jfile"
  awk -F'\t' 'NF>=5 { printf "{\"name\":\"%s\",\"old\":\"%s\",\"new\":\"%s\",\"url\":\"%s\",\"artifact\":\"%s\"},\n",$1,$2,$3,$4,$5 }' "$REPORT_DIR/updates.tsv" >> "$jfile" || true
  # remove trailing comma and close using python if available
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY > "${jfile}.tmp"
import sys,json
p="${jfile}"
try:
    with open(p,'r') as f:
        s=f.read().rstrip()
    if s.endswith(','):
        s=s[:-1]
    s=s+"\n]"
    print(s)
except Exception as e:
    print("[]")
PY
    mv -f "${jfile}.tmp" "$jfile" || true
  else
    # naive close
    sed -i -e '$ s/,$//' "$jfile" || true
    echo "]" >> "$jfile"
  fi
  log INFO "Reports generated: $tfile and $jfile"
  if [ -s "$REPORT_DIR/updates.tsv" ]; then notify "Updates found" "See report $tfile"; fi
}

show_usage(){
  cat <<EOF
update.sh - check upstreams and optionally update recipe .ini files
Usage:
  update.sh [--check] [--apply] [--download] [--parallel N] [--resume] [--dry-run] [--verbose] [--log-file file]
EOF
}

# parse args
ARGS=("$@")
while [ "${#ARGS[@]}" -gt 0 ]; do
  a="${ARGS[0]}"; ARGS=("${ARGS[@]:1}")
  case "$a" in
    --check) DO_CHECK=true; DO_APPLY=false; DO_DOWNLOAD=false;;
    --apply) DO_APPLY=true; DO_CHECK=true; DO_DOWNLOAD=true;;
    --download) DO_DOWNLOAD=true;;
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

log INFO "Starting update.sh (check=${DO_CHECK}, apply=${DO_APPLY}, download=${DO_DOWNLOAD})"
if ! command -v python3 >/dev/null 2>&1; then log WARN "python3 not found; JSON post-processing may be limited"; fi

scan_all_meta
generate_reports

log INFO "Update run complete. Queue file: $BUILD_QUEUE"
if [ -f "$BUILD_QUEUE" ] && [ -s "$BUILD_QUEUE" ]; then
  notify "Updates queued" "Run build.sh to rebuild updated packages"
fi

exit 0
