#!/usr/bin/env bash
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# php2shell-hostcheck-macos.sh - checks whether the PHP on this Mac is fixed
#                                for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
#
# WHAT IT DOES. It finds every PHP program and PHP web-server module on the
# Mac: from Homebrew, MacPorts, MAMP, XAMPP, Laravel Herd, or built by hand.
# It also finds PHP programs that are running right now. For each one it:
#   1. reads the version number stored inside the file, without running it;
#   2. works out how PHP is connected to the web server (its "SAPI"), for
#      example as PHP-FPM or as an Apache module;
#   3. works out where it came from (Homebrew, MacPorts, an app bundle, or
#      nothing) and, for Homebrew, makes sure the file matches its package;
#   4. compares the version with the fixed version for its branch.
# It only reads. It changes nothing.
#
# WHY THE VERSION DECIDES ON A MAC. Linux distributions often copy a fix
# into an older version and record it in a changelog that the Linux check
# reads. On a Mac, Homebrew, MacPorts and app bundles record which version
# is installed, but the Mac holds no changelog of CVE fixes. So on a Mac, a
# version older than the fix has no record of a fix, and the result is
# FAIL, the same rule the Linux check uses for unpackaged builds.
#
# RESULTS (one line for each PHP program or module):
#   PASS          The version is the fixed one or newer.
#   FAIL          The version is old enough to have the bugs, and nothing on
#                 the Mac records a fix.
#   CHECK FAILED  The proof could not be read either way. The line says why
#                 and what to do next. It never guesses.
#
# Example: Homebrew's php@8.3 at version 8.3.20 is older than the fix
# (8.3.36), so the result is FAIL with the advice "brew upgrade php@8.3".
#
# HOW TO USE
#   sudo ./php2shell-hostcheck-macos.sh              check this Mac
#   sudo ./php2shell-hostcheck-macos.sh --root DIR   check a mounted Mac disk
#
# Give your terminal app Full Disk Access first (System Settings > Privacy &
# Security > Full Disk Access). Without it, macOS hides some folders even
# from root, and the result is CHECK FAILED.
#
# Exit status: 0 = all PASS. 1 = at least one FAIL. 2 = no FAIL, but at least
# one CHECK FAILED. 64 = wrong command-line options. 69 = not bash.
# 70 = a temporary file could not be created.
#
# RULES dated 2026-11-04: fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (PHP
# security releases of 21 October 2026). PHP's warning covers branches 8.2
# to 8.5 only; for older branches the result is CHECK FAILED. A third bug,
# CVE-2026-115560, is NOT checked.
#
# This script works with the bash 3.2 that macOS includes. It uses only
# tools that macOS includes: find, grep, awk, sed, od, ls, lsof, mktemp.

if [ -z "${BASH_VERSION:-}" ]; then
  echo "php2shell-hostcheck-macos needs bash (macOS includes it as /bin/bash)." >&2
  exit 69
fi

set -o pipefail
export LC_ALL=C

CHECKER_VERSION="1.0"
RULES_DATE="2026-11-04"
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"

fixed_for() { # branch -> first fixed version, or nothing
  case $1 in
    8.2) echo 8.2.35 ;; 8.3) echo 8.3.36 ;; 8.4) echo 8.4.27 ;; 8.5) echo 8.5.12 ;;
  esac
}

ROOT=""
LIVE=1

usage() {
  cat <<'USAGE'
Usage: php2shell-hostcheck-macos.sh [--root DIR]

  (no options)  Check this Mac: running PHP processes and every PHP program
                or module on local disks. Run with sudo, from a terminal app
                that has Full Disk Access.
  --root DIR    Check a mounted Mac disk (for example a forensic image) at
                DIR. No processes are inspected. DIR must not be "/".

Output is pipe-delimited:
  host|result|sapi|path|seen|php_version|package|reason
USAGE
}

while [ $# -gt 0 ]; do
  case $1 in
    --root)
      [ -d "${2:-}" ] || { echo "--root needs a directory" >&2; exit 64; }
      ROOT=$(cd "$2" && pwd -P) || exit 64
      [ "$ROOT" = / ] && { echo "--root /: run with no options to check this Mac" >&2; exit 64; }
      LIVE=0; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

HOST=$(hostname 2>/dev/null || echo unknown)
[ $LIVE -eq 0 ] && HOST="image:$ROOT"
NFAIL=0; NCHK=0; NPASS=0

# esc TEXT: percent-encode the characters that could break the record:
# "%" -> %25, "|" -> %7C, carriage return -> %0D, line feed -> %0A.
# dec reverses it. Decode output with any URL decoder.
esc() {
  local t=${1//%/%25}
  t=${t//|/%7C}; t=${t//$'\r'/%0D}; t=${t//$'\n'/%0A}
  printf '%s' "$t"
}
dec() {
  local t=${1//%0A/$'\n'}
  t=${t//%0D/$'\r'}; t=${t//%7C/|}; t=${t//%25/%}
  printf '%s' "$t"
}

emit() { # result sapi path seen version package reason
  case $1 in PASS) NPASS=$((NPASS + 1)) ;; FAIL) NFAIL=$((NFAIL + 1)) ;; *) NCHK=$((NCHK + 1)) ;; esac
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$(esc "$HOST")" "$1" "$(esc "$2")" "$(esc "$3")" "$(esc "$4")" \
    "$(esc "${5:--}")" "$(esc "${6:--}")" "$(esc "$7")"
}

# ---------------------------------------------------------------- helpers

# vcmp A B: print -1, 0 or 1 comparing dotted numeric versions.
vcmp() {
  local IFS=. i x y n
  local -a a b
  a=($1); b=($2)
  n=${#a[@]}; [ ${#b[@]} -gt "$n" ] && n=${#b[@]}
  i=0
  while [ $i -lt "$n" ]; do
    x=$((10#${a[i]:-0})); y=$((10#${b[i]:-0}))
    [ $x -lt $y ] && { echo -1; return; }
    [ $x -gt $y ] && { echo 1; return; }
    i=$((i + 1))
  done
  echo 0
}

is_prerelease() {
  case $(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') in
    rc*|alpha*|beta*|dev*|-dev*) return 0 ;;
  esac
  return 1
}

# has_marker FILE: does FILE contain PHP's version marker?
MARKER='X-Powered-By: PHP/'
has_marker() { grep -aqF "$MARKER" "$1" 2>/dev/null; }

# Mach-O (64-bit, 32-bit, universal) or ELF, from the first four bytes.
is_program() {
  case $(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n') in
    cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|bebafeca|7f454c46) return 0 ;;
  esac
  return 1
}

# The PHP core embeds "X-Powered-By: PHP/<PHP_VERSION>" in every SAPI.
binary_version() {
  grep -aoE -m1 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9~.+-]*' "$1" 2>/dev/null \
    | head -1 | sed 's|^X-Powered-By: PHP/||'
}

is_php_name() {
  case ${1##*/} in
    php|php[0-9]*|php-fpm*|php-cgi*|phpdbg*|libphp*.so|libphp*.dylib|mod_php*.so) return 0 ;;
  esac
  return 1
}

sapi_of() {
  case ${1##*/} in
    php-fpm*) echo fpm-fcgi ;;
    php-cgi*) echo cgi-fcgi ;;
    libphp*|mod_php*) echo apache2handler ;;
    phpdbg*)  echo phpdbg ;;
    php|php[0-9]*) echo cli ;;
    *) echo unknown ;;
  esac
}

inode_of() { ls -di "$1" 2>/dev/null | awk '{print $1}'; }

# origin PATH (inside ROOT): prints "kind|package|version|detail".
#   brew      Homebrew keg:  .../Cellar/<formula>/<version>/...
#   macports  MacPorts:      /opt/local/...
#   bundle    An app bundle or bundled stack (MAMP, XAMPP, Herd, *.app)
#   none      Anything else
origin() {
  local p=$1 rest formula kegver kegdir
  case $p in
    */Cellar/*/*/*)
      rest=${p#*/Cellar/}
      formula=${rest%%/*}; rest=${rest#*/}
      kegver=${rest%%/*}
      kegdir=${p%%/Cellar/*}/Cellar/$formula/$kegver
      if [ -f "$ROOT$kegdir/INSTALL_RECEIPT.json" ]; then
        echo "brew|$formula|$kegver|$kegdir"
      else
        echo "none|||$kegdir has no Homebrew install receipt"
      fi
      return ;;
    /opt/local/*)
      echo "macports|||"; return ;;
    /Applications/MAMP*|/Applications/MAMP\ PRO*)
      echo "bundle|MAMP||"; return ;;
    /Applications/XAMPP*|/Applications/xampp*)
      echo "bundle|XAMPP||"; return ;;
    */Library/Application\ Support/Herd/*)
      echo "bundle|Laravel Herd||"; return ;;
    *.app/Contents/*)
      rest=${p%%.app/Contents/*}; echo "bundle|${rest##*/}.app||"; return ;;
  esac
  echo "none|||"
}

# MacPorts package and version for a live path, using the port tool.
macports_pkg() {
  local p=$1 pkg ver
  [ $LIVE -eq 1 ] || return 1
  command -v port >/dev/null 2>&1 || [ -x /opt/local/bin/port ] || return 1
  pkg=$( (port -q provides "$p" || /opt/local/bin/port -q provides "$p") 2>/dev/null \
         | sed -n 's/.*is provided by: *//p' | head -1)
  [ -n "$pkg" ] || return 1
  ver=$( (port -q installed "$pkg" || /opt/local/bin/port -q installed "$pkg") 2>/dev/null \
         | awk '/\(active\)/ {sub(/^@/, "", $2); print $2; exit}')
  echo "$pkg|$ver"
}

# Upstream part of a package version: "8.3.6_1" -> "8.3.6", "8.3.6_0+fpm" -> "8.3.6".
pkg_upstream() { local v=${1%%[_+-]*}; echo "${v%%[!0-9.]*}"; }

# ---------------------------------------------------------------- evaluate

# evaluate path file seen stale
evaluate() {
  local p=$1 file=$2 seen=$3 stale=$4
  local sapi full ver suffix branch fixed o kind pkg pkgver detail pkgdesc up c below mp
  sapi=$(sapi_of "$p")

  if [ -n "$stale" ]; then
    emit "CHECK FAILED" "$sapi" "$p" "$seen" "" "" \
      "The process uses a file that has since been replaced or deleted on disk, and macOS cannot show the running copy. Restart the service and re-run."
    return
  fi

  full=$(binary_version "$file")
  if [ -z "$full" ]; then
    emit "CHECK FAILED" "$sapi" "$p" "$seen" "" "" \
      "No PHP version string found in the file. Inspect it manually."
    return
  fi
  ver=${full%%[!0-9.]*}; ver=${ver%.}; suffix=${full#"$ver"}
  branch=$(echo "$ver" | cut -d. -f1-2)

  o=$(origin "$p")
  IFS='|' read -r kind pkg pkgver detail <<EOF
$o
EOF
  if [ "$kind" = macports ]; then
    mp=$(macports_pkg "$p") && { pkg=${mp%%|*}; pkgver=${mp#*|}; }
  fi
  case $kind in
    brew)     pkgdesc="brew:$pkg $pkgver" ;;
    macports) pkgdesc="macports:${pkg:-unknown} ${pkgver:-}" ;;
    bundle)   pkgdesc="bundle:$pkg" ;;
    *)        pkgdesc="-" ;;
  esac
  pkgdesc=${pkgdesc% }

  # A Homebrew file must match the version of the keg it sits in.
  if [ "$kind" = brew ] || { [ "$kind" = macports ] && [ -n "$pkgver" ]; }; then
    up=$(pkg_upstream "$pkgver")
    if [ -n "$up" ] && [ "$(vcmp "$ver" "$up")" -ne 0 ]; then
      emit "CHECK FAILED" "$sapi" "$p" "$seen" "$full" "$pkgdesc" \
        "The file reports PHP $ver but its package is version $pkgver, so the file is not the packaged one. Find out who replaced it."
      return
    fi
  fi

  if [ "$(vcmp "$branch" 8.2)" -lt 0 ]; then
    emit "CHECK FAILED" "$sapi" "$p" "$seen" "$full" "$pkgdesc" \
      "Branch $branch is outside the vendor advisory (8.2 to 8.5); sources disagree on whether it is affected, and no fix is recorded. Upgrade to a supported fixed release."
    return
  fi
  fixed=$(fixed_for "$branch")
  if [ -z "$fixed" ]; then
    emit "CHECK FAILED" "$sapi" "$p" "$seen" "$full" "$pkgdesc" \
      "Branch $branch is newer than this rule set ($RULES_DATE). Check for a later advisory."
    return
  fi

  c=$(vcmp "$ver" "$fixed")
  below=0
  if [ "$c" -lt 0 ]; then below=1; elif [ "$c" -eq 0 ] && is_prerelease "$suffix"; then below=1; fi
  if [ $below -eq 0 ]; then
    emit PASS "$sapi" "$p" "$seen" "$full" "$pkgdesc" "Upstream version is at or after the fixed release $fixed."
    return
  fi

  case $kind in
    brew)
      emit FAIL "$sapi" "$p" "$seen" "$full" "$pkgdesc" \
        "Version precedes $fixed, and the Mac holds no changelog showing a backported fix (Homebrew records the version, not CVE fixes). Run: brew upgrade $pkg, then restart PHP and the web server." ;;
    macports)
      emit FAIL "$sapi" "$p" "$seen" "$full" "$pkgdesc" \
        "Version precedes $fixed, and the Mac holds no changelog showing a backported fix (MacPorts records the version, not CVE fixes). Run: sudo port selfupdate && sudo port upgrade ${pkg:-outdated}, then restart PHP and the web server." ;;
    bundle)
      emit FAIL "$sapi" "$p" "$seen" "$full" "$pkgdesc" \
        "Version precedes $fixed, and the Mac holds no record of a backported fix for this copy bundled with $pkg. Update $pkg or switch it to a fixed PHP version, then restart it." ;;
    *)
      emit FAIL "$sapi" "$p" "$seen" "$full" "-" \
        "Unpackaged build, version precedes $fixed, and no package record of a fix exists. If it was patched by hand, document that; otherwise rebuild or upgrade.${detail:+ ($detail)}" ;;
  esac
}

# ---------------------------------------------------------------- discovery

printf '# php2shell-hostcheck-macos %s | rules %s | %s and %s | CVE-2026-115560 not covered\n' \
  "$CHECKER_VERSION" "$RULES_DATE" "$CVE_A" "$CVE_B"
printf '# host %s | checked %s | fields are percent-encoded (%%25 %%7C %%0D %%0A)\n' "$(esc "$HOST")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'host|result|sapi|path|seen|php_version|package|reason\n'

missing=""
for t in find grep awk sed od ls head cut sort tr mktemp date; do
  command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
if [ -n "$missing" ]; then
  emit "CHECK FAILED" "-" "-" "-" "" "" "Required tools are missing:$missing. Re-run on a standard macOS installation."
  printf '# summary: %d PASS, %d FAIL, %d CHECK FAILED\n' "$NPASS" "$NFAIL" "$NCHK"
  exit 2
fi

[ "$(id -u)" -ne 0 ] && emit "CHECK FAILED" "-" "-" "-" "" "" \
  "Not run as root: some processes or files may not have been inspected. Re-run with sudo."

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t php2shell) || exit 70
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/inventory"   # path|readfrom|seen|stale

# Running processes and the PHP modules they have loaded, through lsof.
# A process whose file has changed since it started is marked stale: the
# inode lsof reports differs from the file's inode now, or the file is gone.
if [ $LIVE -eq 1 ]; then
  if command -v lsof >/dev/null 2>&1; then
    US=$(printf '\037')
    lsof -nP -w -d txt -Fpin 2>/dev/null | awk -v US="$US" '
      /^p/ { pid = substr($0, 2) }
      /^i/ { ino = substr($0, 2) }
      /^n/ { print pid US ino US substr($0, 2) }' > "$TMP/lsof"
    # Decide once per file whether it is PHP: by name, or by PHP's version
    # marker inside (so renamed copies are found). Apple's sealed system
    # files are not searched for the marker.
    awk -F "$US" '{print $3}' "$TMP/lsof" | sort -u > "$TMP/lsofpaths"
    : > "$TMP/phppaths"
    while IFS= read -r path; do
      case $path in /System/*|/usr/lib/*) is_php_name "$path" || continue ;; esac
      if is_php_name "$path" || { is_program "$path" && has_marker "$path"; }; then
        printf '%s\n' "$path" >> "$TMP/phppaths"
      fi
    done < "$TMP/lsofpaths"
    awk -F "$US" 'NR == FNR { ok[$0] = 1; next } ($3 in ok)' "$TMP/phppaths" "$TMP/lsof" |
    while IFS="$US" read -r pid ino path; do
      st=""
      now=$(inode_of "$path")
      if [ -z "$now" ] || { [ -n "$ino" ] && [ "$now" != "$ino" ]; }; then st=1; fi
      printf '%s|%s|pid%s|%s\n' "$(esc "$path")" "$(esc "$path")" "$pid" "$st" >> "$TMP/inventory"
    done
  else
    emit "CHECK FAILED" "-" "-" "-" "" "" \
      "Running processes could not be inspected: lsof is not available. Only files on disk were checked."
  fi
fi

# Installed programs and modules. Apple's sealed system volume (/System),
# other volumes (/Volumes), network drives and Linux virtual-machine storage
# are skipped. Every folder that could not be read is counted.
base=${ROOT:-/}
VMSTORES="Library/Containers/com.docker.docker .colima .orbstack .lima .local/share/containers"
prune=(-path "$ROOT/System" -o -path "$ROOT/Volumes" -o -path "$ROOT/dev" -o -path "$ROOT/private/var/vm")
for s in $VMSTORES; do
  prune+=(-o -path "$ROOT/Users/*/$s" -o -path "$ROOT/private/var/root/$s")
done
find "$base" \( "${prune[@]}" -o -fstype nfs -o -fstype smbfs -o -fstype afpfs -o -fstype webdav \) -prune -o \
     -type f \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' -o -name 'phpdbg*' \
                -o -name 'libphp*.so' -o -name 'libphp*.dylib' -o -name 'mod_php*.so' \
                -o \( -size +1M \( -perm -100 -o -perm -010 -o -perm -001 -o -name '*.dylib' -o -name '*.so' \) \) \) \
     -print0 2>"$TMP/errors" \
  | while IFS= read -r -d '' f; do
      is_program "$f" || continue
      # Recognised by name, or by PHP's version marker inside (renamed copies).
      is_php_name "$f" || has_marker "$f" || continue
      rel=${f#"$ROOT"}
      printf '%s|%s|installed|\n' "$(esc "$rel")" "$(esc "$f")" >> "$TMP/inventory"
    done

# One line per (path, stale): join where each one was seen.
awk -F'|' '{ k = $1 "|" $4
             if (!(k in seen)) { order[++n] = k; from[k] = $2; seen[k] = $3 }
             else if (index("," seen[k] ",", "," $3 ",") == 0) seen[k] = seen[k] "," $3 }
           END { for (i = 1; i <= n; i++) { split(order[i], kk, "|"); print kk[1] "|" from[order[i]] "|" seen[order[i]] "|" kk[2] } }' \
  "$TMP/inventory" > "$TMP/runtimes"

while IFS='|' read -r p from seen st; do
  evaluate "$(dec "$p")" "$(dec "$from")" "$seen" "$st"
done < "$TMP/runtimes"

for s in $VMSTORES; do
  for d in "$ROOT"/Users/*/"$s" "$ROOT"/private/var/root/"$s"; do
    [ -d "$d" ] && emit "CHECK FAILED" "-" "${d#"$ROOT"}" "storage" "" "" \
      "Linux virtual-machine or container storage is not inspected. Run php2shell-hostcheck.sh inside each container."
  done
done

nerr=$(grep -cv 'No such file or directory' "$TMP/errors" 2>/dev/null)
nerr=${nerr:-0}
nruntimes=$(wc -l < "$TMP/runtimes" | tr -d ' ')
if [ "$nerr" -gt 0 ]; then
  emit "CHECK FAILED" "-" "-" "-" "" "" \
    "The disk search was incomplete: $nerr folder(s) could not be read, first: $(grep -v 'No such file or directory' "$TMP/errors" | head -1 | cut -c1-120). Give your terminal app Full Disk Access (System Settings > Privacy & Security > Full Disk Access), then re-run with sudo."
elif [ "$nruntimes" -eq 0 ] && [ "$(id -u)" -eq 0 ] && [ $NCHK -eq 0 ]; then
  emit PASS "-" "-" "-" "" "" "No PHP program, module or process found on the inspected disks."
fi

printf '# summary: %d PASS, %d FAIL, %d CHECK FAILED\n' "$NPASS" "$NFAIL" "$NCHK"
[ $NFAIL -gt 0 ] && exit 1
[ $NCHK -gt 0 ] && exit 2
exit 0
