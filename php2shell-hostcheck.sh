#!/usr/bin/env bash
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# php2shell-hostcheck.sh - checks whether the PHP on this server is fixed
#                          for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
#
# WHAT IT DOES. It finds every PHP program and PHP web-server module on the
# server, including ones that are running right now and ones inside running
# containers. For each one it:
#   1. reads the version number stored inside the file, without running it
#      (for a running program it reads the copy in memory, through
#      /proc/<pid>/exe, so it checks what is really running);
#   2. works out how PHP is connected to the web server (its "SAPI"), for
#      example as an Apache module or as PHP-FPM;
#   3. finds the software package that installed the file (dpkg, rpm or apk);
#   4. searches that package's changelog for both CVE numbers.
# It only reads. It changes nothing.
#
# RESULTS (one line for each PHP program or module):
#   PASS          There is proof of the fix: the changelog lists both CVE
#                 numbers, or the version is the fixed one or newer.
#   FAIL          The version is old enough to have the bugs, and nothing
#                 shows a fix: the changelog does not list them, or the
#                 program was built by hand with no package record.
#   CHECK FAILED  The proof could not be read either way. The line says why
#                 and what to do next. It never guesses.
#
# Example: Ubuntu's PHP 8.3.6 package is numbered below the fix (8.3.36),
# but its changelog lists both CVE numbers, so the result is PASS.
#
# HOW TO USE
#   sudo ./php2shell-hostcheck.sh              check this server
#   sudo ./php2shell-hostcheck.sh --root DIR   check a mounted disk or image
#
# Exit status: 0 = all PASS. 1 = at least one FAIL. 2 = no FAIL, but at least
# one CHECK FAILED. 64 = wrong command-line options.
#
# RULES dated 2026-11-04: fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (PHP
# security releases of 21 October 2026). PHP's warning covers branches 8.2
# to 8.5 only. Experts disagree about older branches, so for those the
# result is CHECK FAILED unless the changelog lists the fix. A third bug,
# CVE-2026-115560, is NOT checked.

set -o pipefail
export LC_ALL=C

CHECKER_VERSION="1.0"
RULES_DATE="2026-11-04"
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"
CVE_RE="${CVE_A}|${CVE_B}"
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)

ROOT=""   # --root DIR inspects a mounted disk or extracted image instead
LIVE=1

usage() {
  cat <<'EOF'
Usage: php2shell-hostcheck.sh [--root DIR]

  (no options)  Check the live host: running processes (including those in
                containers) and every PHP binary or libphp module on local
                filesystems. Run as root for complete results.
  --root DIR    Check a mounted disk or extracted container image at DIR.
                No processes are inspected.

Output is pipe-delimited:
  host|result|sapi|path|seen|php_version|package|reason
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --root) [[ -d ${2:-} ]] || { echo "--root needs a directory" >&2; exit 64; }
            ROOT=${2%/}; LIVE=0; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

HOST=$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname)
[[ $LIVE -eq 0 ]] && HOST="image:$ROOT"
NFAIL=0; NCHK=0; NPASS=0

emit() { # result sapi path seen version package reason
  case $1 in PASS) ((NPASS++)) ;; FAIL) ((NFAIL++)) ;; *) ((NCHK++)) ;; esac
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$HOST" "$1" "$2" "$3" "$4" "${5:--}" "${6:--}" "$7"
}

# ---------------------------------------------------------------- helpers

# vcmp A B: print -1, 0 or 1 comparing dotted numeric versions.
vcmp() {
  local IFS=. i x y
  local -a a=($1) b=($2)
  for ((i = 0; i < ${#a[@]} || i < ${#b[@]}; i++)); do
    x=$((10#${a[i]:-0})); y=$((10#${b[i]:-0}))
    ((x < y)) && { echo -1; return; }
    ((x > y)) && { echo 1; return; }
  done
  echo 0
}

is_prerelease() { [[ ${1,,} =~ ^(rc|alpha|beta|-?dev) ]]; }

is_elf() { [[ $(head -c4 "$1" 2>/dev/null | od -An -c | tr -d ' \n') == '177ELF' ]]; }

# The PHP core embeds "X-Powered-By: PHP/<PHP_VERSION>" in every SAPI.
binary_version() {
  grep -aoE -m1 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9~.+-]*' "$1" 2>/dev/null \
    | head -1 | sed 's|^X-Powered-By: PHP/||'
}

sapi_of() {
  case ${1##*/} in
    php-fpm*) echo fpm-fcgi ;;
    php-cgi*) echo cgi-fcgi ;;
    libphp*)  echo apache2handler ;;
    phpdbg*)  echo phpdbg ;;
    php|php[0-9]*) echo cli ;;
    *) echo unknown ;;
  esac
}

# Package ownership. Each prints "manager|package|version" for a path
# inside root $1. dpkg and apk databases are parsed directly, so an image
# can be checked from a host with a different package manager.
dpkg_owner() {
  local root=$1 p=$2 info="$1/var/lib/dpkg/info" f pkg ver
  [[ -d $info ]] || return 1
  f=$(grep -lxF -e "$p" -e "/usr$p" -e "${p#/usr}" "$info"/*.list 2>/dev/null | head -1)
  [[ -n $f ]] || return 1
  pkg=${f##*/}; pkg=${pkg%.list}; pkg=${pkg%%:*}
  ver=$(awk -v P="$pkg" '/^Package: /{m=($2==P)} m && /^Version: /{print $2; exit}' \
        "$root/var/lib/dpkg/status" 2>/dev/null)
  echo "dpkg|$pkg|$ver"
}

rpm_owner() {
  local root=$1 p=$2 out
  command -v rpm >/dev/null || return 1
  [[ -d $root/var/lib/rpm || -d $root/usr/lib/sysimage/rpm ]] || return 1
  out=$(rpm ${root:+--root "$root"} -qf --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' "$p" 2>/dev/null) || return 1
  echo "rpm|${out%%$'\n'*}"
}

apk_owner() {
  local db="$1/lib/apk/db/installed"
  [[ -r $db ]] || return 1
  awk -v want="${2#/}" '
    /^P:/ {pk = substr($0, 3)}  /^V:/ {v = substr($0, 3)}  /^F:/ {d = substr($0, 3)}
    /^R:/ { if (d "/" substr($0, 3) == want) { print "apk|" pk "|" v; found = 1; exit } }
    END { exit !found }' "$db"
}

pkg_owner() { dpkg_owner "$@" || rpm_owner "$@" || apk_owner "$@" || echo "none||"; }

# changelog_cves root manager package branch: print the PHP2Shell CVE IDs
# that the installed package's changelog mentions, or UNREADABLE.
changelog_cves() {
  local root=$1 mgr=$2 pkg=$3 branch=$4 d f
  case $mgr in
    dpkg)
      for d in "$pkg" "php${branch}-common"; do
        f="$root/usr/share/doc/$d/changelog.Debian.gz"
        if [[ -r $f ]]; then
          zgrep -ohE "$CVE_RE" "$f" 2>/dev/null | sort -u | tr '\n' ' '
          return
        fi
      done
      echo UNREADABLE ;;
    rpm)
      local cl
      cl=$(rpm ${root:+--root "$root"} -q --changelog "$pkg" 2>/dev/null) || { echo UNREADABLE; return; }
      grep -ohE "$CVE_RE" <<<"$cl" | sort -u | tr '\n' ' ' ;;
    *) echo UNREADABLE ;;
  esac
}

# ---------------------------------------------------------------- evaluate

# evaluate root path readfrom seen stale
evaluate() {
  local root=$1 path=$2 file=$3 seen=$4 stale=$5
  local sapi full ver suffix branch fixed owner mgr pkg pkgver pkgdesc cl below c
  sapi=$(sapi_of "$path")
  [[ $root == /proc/* ]] && path="$path (in container, root $root)"

  full=$(binary_version "$file")
  if [[ -z $full ]]; then
    emit "CHECK FAILED" "$sapi" "$path" "$seen" "" "" \
      "No PHP version string found in the file. Inspect it manually."
    return
  fi
  ver=${full%%[!0-9.]*}; ver=${ver%.}; suffix=${full#"$ver"}
  branch=$(cut -d. -f1-2 <<<"$ver")

  if [[ -n $stale ]]; then
    fixed=${FIXED[$branch]:-}
    if [[ -n $fixed && $(vcmp "$ver" "$fixed") -ge 0 ]] && ! is_prerelease "$suffix"; then
      emit PASS "$sapi" "$path" "$seen" "$full" "" \
        "Running image (file since replaced or deleted on disk) is at or after $fixed."
    else
      emit "CHECK FAILED" "$sapi" "$path" "$seen" "$full" "" \
        "The process runs a binary that has since been replaced or deleted on disk, so no package record describes it. Restart the service and re-run."
    fi
    return
  fi

  owner=$(pkg_owner "$root" "$2")
  IFS='|' read -r mgr pkg pkgver <<<"$owner"
  pkgdesc="-"; [[ $mgr != none ]] && pkgdesc="$mgr:$pkg $pkgver"
  cl="N/A"; [[ $mgr != none ]] && cl=$(changelog_cves "$root" "$mgr" "$pkg" "$branch")

  if [[ $cl == *"$CVE_A"* && $cl == *"$CVE_B"* ]]; then
    emit PASS "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Package changelog records the fix for both $CVE_A and $CVE_B."
    return
  fi

  if [[ $(vcmp "$branch" 8.2) -lt 0 ]]; then
    emit "CHECK FAILED" "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Branch $branch is outside the vendor advisory (8.2 to 8.5); sources disagree on whether it is affected, and no fix is recorded. Upgrade to a supported fixed release."
    return
  fi
  fixed=${FIXED[$branch]:-}
  if [[ -z $fixed ]]; then
    emit "CHECK FAILED" "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Branch $branch is newer than this rule set ($RULES_DATE). Check for a later advisory."
    return
  fi

  c=$(vcmp "$ver" "$fixed")
  below=0
  { [[ $c -lt 0 ]] || { [[ $c -eq 0 ]] && is_prerelease "$suffix"; }; } && below=1
  if [[ $below -eq 0 ]]; then
    emit PASS "$sapi" "$path" "$seen" "$full" "$pkgdesc" "Upstream version is at or after the fixed release $fixed."
    return
  fi

  if [[ $cl == *CVE-* ]]; then
    emit "CHECK FAILED" "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed and the changelog records only ${cl% }. Check the vendor advisory for the other CVE."
  elif [[ $mgr == none ]]; then
    emit FAIL "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Unpackaged build, version precedes $fixed, and no package record of a fix exists. If it was patched by hand, document that; otherwise rebuild or upgrade."
  elif [[ $mgr == apk ]]; then
    emit "CHECK FAILED" "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed. Alpine keeps no package changelog on the system, so a backported fix cannot be ruled out locally. Check the Alpine security database for $pkg $pkgver, or upgrade."
  elif [[ $cl == UNREADABLE ]]; then
    emit "CHECK FAILED" "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed and the package changelog could not be read (documentation may be excluded, or the package manager is absent). Check the vendor security notice for $pkg $pkgver."
  else
    emit FAIL "$sapi" "$path" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed and the package changelog has no record of either CVE. Update the package."
  fi
}

# ---------------------------------------------------------------- discovery

declare -A SEEN ROOTOF READFROM STALE
declare -a ORDER

add_rt() { # key root path readfrom seen stale
  if [[ -z ${SEEN[$1]+x} ]]; then
    ORDER+=("$1"); SEEN[$1]=$5; ROOTOF[$1]=$2; READFROM[$1]=$4; STALE[$1]=$6
  else
    SEEN[$1]+=",$5"
  fi
}

printf '# php2shell-hostcheck %s | rules %s | %s and %s | CVE-2026-115560 not covered\n' \
  "$CHECKER_VERSION" "$RULES_DATE" "$CVE_A" "$CVE_B"
printf '# host %s | checked %s\n' "$HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'host|result|sapi|path|seen|php_version|package|reason\n'

if [[ $LIVE -eq 1 ]]; then
  [[ $EUID -ne 0 ]] && emit "CHECK FAILED" "-" "-" "-" "" "" \
    "Not run as root: other users' processes and unreadable files were not inspected. Re-run as root."
  self_ns=$(readlink /proc/self/ns/mnt)
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    ns=$(readlink "$d/ns/mnt" 2>/dev/null) || continue
    r=""; [[ $ns != "$self_ns" ]] && r="/proc/$pid/root"
    exe=$(readlink "$d/exe" 2>/dev/null)
    if [[ -n $exe ]]; then
      st=""; [[ $exe == *" (deleted)" ]] && { exe=${exe% (deleted)}; st=1; }
      case ${exe##*/} in
        php|php[0-9]*|php-fpm*|php-cgi*|phpdbg*)
          add_rt "$ns|$exe|$st" "$r" "$exe" "/proc/$pid/exe" "pid$pid" "$st" ;;
      esac
    fi
    # Modules loaded into another process, such as mod_php in Apache.
    while IFS= read -r lib; do
      st=""; [[ $lib == *" (deleted)" ]] && { lib=${lib% (deleted)}; st=1; }
      add_rt "$ns|$lib|$st" "$r" "$lib" "$r$lib" "pid$pid" "$st"
    done < <(grep -oE '/[^ ]*/libphp[^ /]*\.so[^ ]*( \(deleted\))?' "$d/maps" 2>/dev/null | sort -u)
  done
fi

# Installed binaries and modules (also catches php-cgi, which only runs per
# request). Container storage and network filesystems are skipped.
base=${ROOT:-/}
host_ns=$( [[ $LIVE -eq 1 ]] && readlink /proc/self/ns/mnt || echo image )
while IFS= read -r -d '' f; do
  is_elf "$f" || continue
  rel=${f#"$ROOT"}
  add_rt "$host_ns|$rel|" "$ROOT" "$rel" "$f" "installed" ""
done < <(find "$base" \( -path "$ROOT/proc" -o -path "$ROOT/sys" -o -path "$ROOT/dev" \
           -o -path "$ROOT/run" -o -path "$ROOT/var/lib/docker" -o -path "$ROOT/var/lib/containers" \
           -o -path "$ROOT/var/lib/containerd" -o -fstype nfs -o -fstype nfs4 -o -fstype cifs \
           -o -fstype fuse.sshfs \) -prune -o -type f \
           \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
              -o -name 'phpdbg*' -o -name 'libphp*.so*' \) -print0 2>/dev/null)

for k in "${ORDER[@]}"; do
  IFS='|' read -r _ p _ <<<"$k"
  evaluate "${ROOTOF[$k]}" "$p" "${READFROM[$k]}" "${SEEN[$k]}" "${STALE[$k]}"
done

for s in var/lib/docker var/lib/containers var/lib/containerd; do
  [[ -d $base/$s ]] && emit "CHECK FAILED" "-" "/$s" "storage" "" "" \
    "Container image storage is not inspected. Run this checker inside each container, or with --root against each extracted image."
done

if [[ ${#ORDER[@]} -eq 0 ]]; then
  emit PASS "-" "-" "-" "" "" "No PHP binary, module or process found on the inspected filesystems."
fi

printf '# summary: %d PASS, %d FAIL, %d CHECK FAILED\n' "$NPASS" "$NFAIL" "$NCHK"
((NFAIL > 0)) && exit 1
((NCHK > 0)) && exit 2
exit 0
