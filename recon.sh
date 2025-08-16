#!/usr/bin/env bash
# safe-recon.sh — Consent-only reconnaissance helper (defensive/blue-team use)
#
# This script is designed for site owners and authorized testers to inventory
# web-facing technologies and gather vulnerability intelligence *safely*.
# It defaults to passive/light checks and refuses to run without explicit
# confirmation of authorization.
#
# IMPORTANT: Use only on assets you own or have written permission to test.
# The authors/maintainers accept no liability for misuse.
#
# Features (modular, runs what is available):
#  - Passive tech fingerprinting (HTTP headers, meta tags, asset hints)
#  - Optional Wappalyzer/WhatWeb if installed
#  - DNS inventory (A/AAAA/CNAME/TXT/MX/NS)
#  - Optional subdomain discovery via subfinder (passive APIs)
#  - Optional active service scan via nmap (light by default)
#  - Optional nikto and nuclei (off by default; rate-limited)
#  - Produces tidy /out folder with TXT/CSV plus a simple HTML summary
#
# Dependencies (auto-detected, all optional):
#  curl, dig, jq, whatweb, wappalyzer, subfinder, nmap, nikto, nuclei
#
set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
SCRIPT_NAME="safe-recon.sh"

# ----- defaults -----
OUTDIR=""
TARGETS=()
OWNERSHIP_CONFIRMED=false
ACTIVE=false
FULL_PORTS=false
WITH_NIKTO=false
WITH_NUCLEI=false
DELAY=0
RATE_LIMIT_NUCLEI=5
NMAP_TOP_PORTS=100

usage() {
  cat <<USAGE
${SCRIPT_NAME} v${VERSION}
Consent-only, safety-first recon for your *own* domains.

Usage:
  ${SCRIPT_NAME} --i-own-this -t example.com [options]
  ${SCRIPT_NAME} --i-own-this -l targets.txt [options]

Required:
  --i-own-this              Confirm you have authorization to test.

Target selection (choose one):
  -t, --target DOMAIN       Single domain (e.g., example.com)
  -l, --list FILE           File with one domain per line

Output:
  -o, --out DIR             Output directory (default: ./out-YYYYmmdd-HHMMSS)

Safety / scope controls:
  --active                  Enable light active checks (nmap top ${NMAP_TOP_PORTS})
  --full-ports              With --active, scan all TCP ports (-p-)
  --with-nikto              Include nikto (active HTTP checks)
  --with-nuclei             Include nuclei (HTTP CVE templates), rate-limited
  --delay SEC               Sleep between target domains (default: 0)

Other:
  -h, --help                Show this help
  -v, --version             Show version

Notes:
  • By default, only passive methods are used. Active tools are opt-in.
  • The script runs only tools that are present on your system.
  • Be considerate: respect robots.txt and legal boundaries.
USAGE
}

log()   { printf "[%%s] %%s\n" "$(date '+%F %T')" "$*"; }
warn()  { printf "[%%s] [WARN] %%s\n" "$(date '+%F %T')" "$*" >&2; }
fail()  { printf "[%%s] [FAIL] %%s\n" "$(date '+%F %T')" "$*" >&2; exit 1; }

die_if_missing() {
  local cmd="$1"; local msg="$2";
  command -v "$cmd" >/dev/null 2>&1 || warn "$msg (missing: $cmd)"
}

mkoutdir() {
  if [[ -z "$OUTDIR" ]]; then
    OUTDIR="out-$(date '+%Y%m%d-%H%M%S')"
  fi
  mkdir -p "$OUTDIR" || fail "Cannot create output dir $OUTDIR"
}

parse_args() {
  local argv=("$@")
  local i=0
  while [[ $i -lt ${#argv[@]} ]]; do
    case "${argv[$i]}" in
      --i-own-this) OWNERSHIP_CONFIRMED=true ;;
      -t|--target) ((i++)); TARGETS+=("${argv[$i]}") ;;
      -l|--list)   ((i++)); mapfile -t TARGETS < <(grep -vE '^(#|\s*$)' "${argv[$i]}") ;;
      -o|--out)    ((i++)); OUTDIR="${argv[$i]}" ;;
      --active)    ACTIVE=true ;;
      --full-ports) FULL_PORTS=true ;;
      --with-nikto) WITH_NIKTO=true ;;
      --with-nuclei) WITH_NUCLEI=true ;;
      --delay)     ((i++)); DELAY="${argv[$i]}" ;;
      -h|--help)   usage; exit 0 ;;
      -v|--version) echo "$VERSION"; exit 0 ;;
      *) fail "Unknown arg: ${argv[$i]}" ;;
    esac
    ((i++))
  done

  $OWNERSHIP_CONFIRMED || fail "Refusing to run without --i-own-this confirmation."
  [[ ${#TARGETS[@]} -gt 0 ]] || fail "Provide a target with -t or a list with -l."
}

normalize_domain() {
  local d="$1"; d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; echo "$d";
}

http_url_guess() {
  local d="$1"; echo "https://$d"; # prefer HTTPS; curl will follow
}

write_kv() { # key, value, file
  printf "%s: %s\n" "$1" "$2" >> "$3"
}

fingerprint_http() {
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  local url; url="$(http_url_guess "$domain")"
  local headers="$dstdir/http_headers.txt"
  local tech="$dstdir/tech_hints.txt"
  local cookies="$dstdir/cookies.txt"

  log "[${domain}] HTTP: fetching headers"
  curl -ksSIL --max-time 20 "$url" -o "$headers" || warn "curl -I failed for $url"

  log "[${domain}] HTTP: fetching body for meta and assets"
  local body; body="$(mktemp)"
  curl -ksSL --max-time 30 "$url" -o "$body" || true
  grep -Eoi '<meta[^>]+(generator|powered|framework)[^>]*>' "$body" | sed -E 's/\s+/ /g' > "$dstdir/meta_tags.txt" || true
  grep -Eoi '<script[^>]+src=[^>]+>' "$body" | sed -E 's/\s+/ /g' > "$dstdir/assets_js.txt" || true
  grep -Eoi '<link[^>]+(rel|href)=[^>]+>' "$body" | sed -E 's/\s+/ /g' > "$dstdir/assets_css.txt" || true
  rm -f "$body"

  log "[${domain}] HTTP: cookie probe"
  curl -ksSI "$url" | awk -F": " '/^Set-Cookie:/ {print $2}' > "$cookies" || true

  log "[${domain}] Passive tech hints"
  {
    awk -F": " '/^Server:/ {print "server=>"$2}' "$headers" || true
    awk -F": " '/^X-Powered-By:/ {print "x-powered-by=>"$2}' "$headers" || true
    grep -Eo 'wp-content|wp-includes' "$dstdir/assets_js.txt" >/dev/null && echo "cms=>wordpress"
    grep -Eo 'drupal|/sites/all/' "$dstdir/assets_js.txt" >/dev/null && echo "cms=>drupal"
    grep -Eo 'Joomla' "$dstdir/meta_tags.txt" >/dev/null && echo "cms=>joomla"
    grep -Eo 'React|Angular|Vue' "$dstdir/assets_js.txt" >/dev/null && echo "js-framework=>detected (check assets)"
  } > "$tech"
}

dns_inventory() {
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  log "[${domain}] DNS inventory"
  {
    echo "# A"
    dig +short A "$domain" || true
    echo "\n# AAAA"
    dig +short AAAA "$domain" || true
    echo "\n# CNAME"
    dig +short CNAME "$domain" || true
    echo "\n# MX"
    dig +short MX "$domain" || true
    echo "\n# NS"
    dig +short NS "$domain" || true
    echo "\n# TXT"
    dig +short TXT "$domain" || true
  } > "$dstdir/dns.txt"
}

whatweb_wappalyzer() {
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  if command -v whatweb >/dev/null 2>&1; then
    log "[${domain}] WhatWeb"
    whatweb -a 3 --log-brief="$dstdir/whatweb.txt" "$domain" >/dev/null 2>&1 || true
  else
    warn "whatweb not found; skipping"
  fi
  if command -v wappalyzer >/dev/null 2>&1; then
    log "[${domain}] Wappalyzer CLI"
    wappalyzer "$domain" > "$dstdir/wappalyzer.json" 2>/dev/null || true
  else
    warn "wappalyzer not found; skipping"
  fi
}

subdomain_passive() {
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  if command -v subfinder >/dev/null 2>&1; then
    log "[${domain}] Subfinder (passive)"
    subfinder -silent -all -nW -d "$domain" -o "$dstdir/subdomains.txt" || true
  else
    warn "subfinder not found; skipping"
  fi
}

nmap_scan() {
  $ACTIVE || return 0
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  if ! command -v nmap >/dev/null 2>&1; then warn "nmap not found; skipping"; return 0; fi
  log "[${domain}] Nmap service scan (light)"
  local portarg="--top-ports ${NMAP_TOP_PORTS}"
  $FULL_PORTS && portarg="-p-"
  nmap -Pn -sV -T3 --version-light ${portarg} "$domain" -oN "$dstdir/nmap.txt" -oX "$dstdir/nmap.xml" || true
}

nikto_scan() {
  $WITH_NIKTO || return 0
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  if ! command -v nikto >/dev/null 2>&1; then warn "nikto not found; skipping"; return 0; fi
  local url; url="$(http_url_guess "$domain")"
  log "[${domain}] Nikto (rate-limited)"
  nikto -host "$url" -maxtime 900 -Tuning 123b -output "$dstdir/nikto.txt" || true
}

nuclei_scan() {
  $WITH_NUCLEI || return 0
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  if ! command -v nuclei >/dev/null 2>&1; then warn "nuclei not found; skipping"; return 0; fi
  local url; url="$(http_url_guess "$domain")"
  log "[${domain}] Nuclei (HTTP CVE templates, rate ${RATE_LIMIT_NUCLEI}/s)"
  printf "%s\n" "$url" | nuclei -rate-limit "$RATE_LIMIT_NUCLEI" -timeout 10 -no-interact -silent \
    -severity medium,high,critical -target-cps "$RATE_LIMIT_NUCLEI" \
    -o "$dstdir/nuclei.txt" || true
}

build_findings() {
  local domain="$1"; local dstdir="$2"; mkdir -p "$dstdir"
  local csv="$dstdir/findings.csv"
  echo "category,signal,value,notes" > "$csv"
  # Headers
  if [[ -f "$dstdir/http_headers.txt" ]]; then
    local server; server=$(awk -F": " '/^Server:/ {print $2}' "$dstdir/http_headers.txt" | tr -d '\r') || true
    [[ -n "${server:-}" ]] && echo "http,server,${server},check vendor advisories" >> "$csv"
    local xpb; xpb=$(awk -F": " '/^X-Powered-By:/ {print $2}' "$dstdir/http_headers.txt" | tr -d '\r') || true
    [[ -n "${xpb:-}" ]] && echo "http,x-powered-by,${xpb},consider suppressing version leakage" >> "$csv"
  fi
  # Tech hints
  if [[ -f "$dstdir/tech_hints.txt" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "tech,hint,${line},verify manually" >> "$csv"
    done < "$dstdir/tech_hints.txt"
  fi
  # WhatWeb
  if [[ -f "$dstdir/whatweb.txt" ]]; then
    echo "tech,whatweb,$(tr '\n' ';' < "$dstdir/whatweb.txt" | sed 's/;/ | /g'),parse details" >> "$csv" || true
  fi
  # Wappalyzer
  if [[ -f "$dstdir/wappalyzer.json" ]]; then
    if command -v jq >/dev/null 2>&1; then
      jq -r '.technologies[] | [.name,(.version//"unknown")] | @csv' "$dstdir/wappalyzer.json" | \
      sed 's/^/tech,wappalyzer,/' >> "$csv" || true
    else
      echo "tech,wappalyzer,json,install jq to parse" >> "$csv"
    fi
  fi
  # Nmap services
  if [[ -f "$dstdir/nmap.txt" ]]; then
    awk '/open/ {print $0}' "$dstdir/nmap.txt" | while read -r l; do
      echo "service,nmap,${l},map to CVEs by product/version" >> "$csv"
    done
  fi
  # Nikto & Nuclei
  [[ -f "$dstdir/nikto.txt" ]] && echo "web,nikto,see nikto.txt,review" >> "$csv"
  [[ -f "$dstdir/nuclei.txt" ]] && echo "web,nuclei,see nuclei.txt,review" >> "$csv"
}

html_report() {
  local domain="$1"; local dstdir="$2"; local html="$dstdir/report.html"
  log "[${domain}] Writing HTML summary"
  cat > "$html" <<HTML
<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Recon report — ${domain}</title>
<style>body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:24px;}
code,pre{background:#f6f8fa;padding:8px;border-radius:8px;display:block;white-space:pre-wrap}
section{margin-bottom:24px} h1{margin:0 0 8px} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:6px;text-align:left} th{background:#fafafa}
small{color:#666}
</style>
<h1>Recon report</h1>
<p><strong>Domain:</strong> ${domain}<br><strong>Generated:</strong> $(date '+%F %T')</p>
<section>
<h2>HTTP headers</h2>
<pre>$(sed 's/&/&amp;/g;s/</&lt;/g' "$dstdir/http_headers.txt" 2>/dev/null || true)</pre>
</section>
<section>
<h2>Meta tags</h2>
<pre>$(sed 's/&/&amp;/g;s/</&lt;/g' "$dstdir/meta_tags.txt" 2>/dev/null || true)</pre>
</section>
<section>
<h2>Tech hints</h2>
<pre>$(sed 's/&/&amp;/g;s/</&lt;/g' "$dstdir/tech_hints.txt" 2>/dev/null || true)</pre>
</section>
<section>
<h2>DNS</h2>
<pre>$(sed 's/&/&amp;/g;s/</&lt;/g' "$dstdir/dns.txt" 2>/dev/null || true)</pre>
</section>
<section>
<h2>Nmap (if enabled)</h2>
<pre>$(sed 's/&/&amp;/g;s/</&lt;/g' "$dstdir/nmap.txt" 2>/dev/null || echo 'n/a')</pre>
</section>
<section>
<h2>Findings (CSV excerpt)</h2>
<pre>$(head -n 200 "$dstdir/findings.csv" 2>/dev/null || echo 'n/a')</pre>
</section>
<p><small>This report is informational. Validate findings and consult vendor advisories/CVEs.
Run only with authorization. © $(date '+%Y')</small></p>
</html>
HTML
}

process_domain() {
  local raw="$1"; local domain; domain="$(normalize_domain "$raw")"
  local dstdir="$OUTDIR/$domain"; mkdir -p "$dstdir"

  log "===== ${domain} ====="
  fingerprint_http "$domain" "$dstdir"
  dns_inventory "$domain" "$dstdir"
  whatweb_wappalyzer "$domain" "$dstdir"
  subdomain_passive "$domain" "$dstdir"
  nmap_scan "$domain" "$dstdir"
  nikto_scan "$domain" "$dstdir"
  nuclei_scan "$domain" "$dstdir"
  build_findings "$domain" "$dstdir"
  html_report "$domain" "$dstdir"
  log "[${domain}] Done → $dstdir"
}

main() {
  parse_args "$@"
  mkoutdir

  log "Output directory: $OUTDIR"
  log "Active checks: $ACTIVE | Full ports: $FULL_PORTS | Nikto: $WITH_NIKTO | Nuclei: $WITH_NUCLEI"

  # Soft dependency hints
  die_if_missing curl "curl recommended for HTTP checks"
  die_if_missing dig "dig recommended for DNS checks"
  command -v jq >/dev/null 2>&1 || warn "jq not found; JSON parsing limited"

  for t in "${TARGETS[@]}"; do
    process_domain "$t"
    if [[ "$DELAY" -gt 0 ]]; then sleep "$DELAY"; fi
  done

  log "All done. Reports are under: $OUTDIR"
}

main "$@"
