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

CHECKER_VERSION="1.1"
RULES_DATE="2026-11-04"
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"
CVE_RE="${CVE_A}|${CVE_B}"
MARKER='X-Powered-By: PHP/'
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)

ROOT=""   # --root DIR inspects a mounted disk or extracted image instead
LIVE=1

usage() {
  cat <<'EOF'
Usage: php2shell-hostcheck.sh [--root DIR]

  (no options)  Check the live host: running processes (including those in
                containers) and every PHP binary or PHP web-server module on
                local filesystems. Run as root for complete results.
  --root DIR    Check a mounted disk or extracted container image at DIR.
                No processes are inspected. DIR must not be "/".

Output is pipe-delimited:
  host|result|sapi|path|seen|php_version|package|reason
EOF
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --root)
      [[ -d ${2:-} ]] || { echo "--root needs a directory" >&2; exit 64; }
      ROOT=$(cd "$2" && pwd -P) || exit 64
      [[ $ROOT == / ]] && { echo "--root /: run with no options to check the live host" >&2; exit 64; }
      LIVE=0; shift 2 ;;
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

# Upstream part of a package version: drop the epoch and the packaging
# revision. "1:8.3.6-0ubuntu0.24.04.13" -> "8.3.6", "8.3.20-r0" -> "8.3.20".
pkg_upstream() { local v=${1#*:}; v=${v%%[-+~]*}; echo "${v%%[!0-9.]*}"; }

sapi_of() {
  case ${1##*/} in
    php-fpm*) echo fpm-fcgi ;;
    php-cgi*) echo cgi-fcgi ;;
    libphp*|mod_php*) echo apache2handler ;;
    phpdbg*)  echo phpdbg ;;
    php|php[0-9]*) echo cli ;;
    *.so*)    echo embedded-module ;;
    *) echo unknown ;;
  esac
}

# safe_path ROOT ABSPATH: resolve ABSPATH inside ROOT, following symlinks the
# way a chroot would, so an absolute link in an image or container never
# reaches the checking host's own files. Prints ROOT+resolved path.
safe_path() {
  local root=$1 out="" comp link n=0
  local -a todo parts
  IFS=/ read -ra todo <<<"${2#/}"
  while ((${#todo[@]})); do
    comp=${todo[0]}; todo=("${todo[@]:1}")
    case $comp in ''|.) continue ;; ..) out=${out%/*}; continue ;; esac
    if [[ -L $root$out/$comp ]]; then
      ((++n > 40)) && return 1
      link=$(readlink "$root$out/$comp") || return 1
      [[ $link == /* ]] && out=""
      IFS=/ read -ra parts <<<"${link#/}"
      todo=("${parts[@]}" "${todo[@]}")
    else
      out="$out/$comp"
    fi
  done
  printf '%s\n' "$root$out"
}

# ---------------------------------------------------------------- packages
# Each *_owner prints "manager|package|version|evidence" for a path inside
# root $1. dpkg and apk databases are parsed directly. rpm needs the rpm tool.

dpkg_status_version() { # root pkg
  local st; st=$(safe_path "$1" /var/lib/dpkg/status) || return 1
  awk -v P="$2" '/^Package: /{m=($2==P)} m && /^Version: /{print $2; exit}' "$st" 2>/dev/null
}

dpkg_owner() {
  local root=$1 p=$2 info f pkg ver
  info=$(safe_path "$root" /var/lib/dpkg/info) || return 1
  [[ -d $info ]] || return 1
  f=$(grep -lxF -e "$p" -e "/usr$p" -e "${p#/usr}" "$info"/*.list 2>/dev/null | head -1)
  [[ -n $f ]] || return 1
  pkg=${f##*/}; pkg=${pkg%.list}
  ver=$(dpkg_status_version "$root" "${pkg%%:*}")
  echo "dpkg|$pkg|$ver|${f#"$root"}"
}

rpm_owner() {
  local root=$1 p=$2 out
  [[ -d $root/var/lib/rpm || -d $root/usr/lib/sysimage/rpm ]] || return 1
  command -v rpm >/dev/null || { echo "rpm-unavailable|||"; return 0; }
  out=$(rpm ${root:+--root "$root"} -qf --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' "$p" 2>/dev/null) || return 1
  echo "rpm|${out%%$'\n'*}|rpm database"
}

apk_owner() {
  local db; db=$(safe_path "$1" /lib/apk/db/installed) || return 1
  [[ -r $db ]] || return 1
  awk -v want="${2#/}" '
    /^P:/ {pk = substr($0, 3)}  /^V:/ {v = substr($0, 3)}  /^F:/ {d = substr($0, 3)}
    /^R:/ { if (d "/" substr($0, 3) == want) { print "apk|" pk "|" v "|/lib/apk/db/installed"; found = 1; exit } }
    END { exit !found }' "$db"
}

pkg_owner() { dpkg_owner "$@" || rpm_owner "$@" || apk_owner "$@" || echo "none|||"; }

# file_matches_package root mgr pkg path file: 0 match, 1 mismatch, 2 unknown.
file_matches_package() {
  local root=$1 mgr=$2 pkg=$3 p=$4 file=$5 sums want got
  [[ $mgr == dpkg ]] || return 2
  sums=$(safe_path "$root" "/var/lib/dpkg/info/$pkg.md5sums") || return 2
  [[ -r $sums ]] || return 2
  want=$(awk -v a="${p#/}" -v b="usr$p" -v c="${p#/usr/}" '$2==a || $2==b || $2==c {print $1; exit}' "$sums")
  [[ -n $want ]] || return 2
  got=$(md5sum < "$file" 2>/dev/null | cut -d' ' -f1)
  [[ $got == "$want" ]] && return 0 || return 1
}

# changelog_scan root mgr pkg branch pkgver: sets CL_STATE (FOUND, NONE,
# UNREADABLE), CL_IDS, CL_SRC, CL_QUOTE, CL_NEG.
changelog_scan() {
  local root=$1 mgr=$2 pkg=$3 branch=$4 pkgver=$5 d f text cand
  CL_STATE=UNREADABLE; CL_IDS=""; CL_SRC=""; CL_QUOTE=""; CL_NEG=""
  case $mgr in
    dpkg)
      for d in "${pkg%%:*}" "php${branch}-common"; do
        if [[ $d != "${pkg%%:*}" ]]; then
          cand=$(dpkg_status_version "$root" "$d")
          [[ -n $cand && $cand == "$pkgver" ]] || continue  # fallback only at the same version
        fi
        f=$(safe_path "$root" "/usr/share/doc/$d/changelog.Debian.gz") || continue
        [[ -r $f ]] || continue
        text=$(zcat "$f" 2>/dev/null) || continue
        CL_SRC=${f#"$root"}
        break
      done
      [[ -n $CL_SRC ]] || return ;;
    rpm)
      text=$(rpm ${root:+--root "$root"} -q --changelog "$pkg" 2>/dev/null) || return
      CL_SRC="rpm changelog of $pkg" ;;
    *) return ;;
  esac
  CL_IDS=$(grep -ohE "$CVE_RE" <<<"$text" | sort -u | tr '\n' ' ')
  CL_IDS=${CL_IDS% }
  if [[ -z $CL_IDS ]]; then CL_STATE=NONE; return; fi
  CL_STATE=FOUND
  CL_QUOTE=$(grep -m1 -E "$CVE_RE" <<<"$text" | sed 's/^[[:space:]]*//' | cut -c1-140)
  grep -E "$CVE_RE" <<<"$text" | grep -qiE "not (yet )?fixed|unfixed|not affected|does not fix|revert" && CL_NEG=1
}

# ---------------------------------------------------------------- evaluate

# evaluate root path readfrom seen stale label
evaluate() {
  local root=$1 p=$2 file=$3 seen=$4 stale=$5 label=$6
  local sapi full ver suffix branch fixed owner mgr pkg pkgver pkgev pkgdesc c below up m show
  sapi=$(sapi_of "$p")
  show=$p; [[ -n $label ]] && show="$p ($label)"

  full=$(binary_version "$file")
  if [[ -n $stale ]]; then
    fixed=""
    if [[ -n $full ]]; then
      ver=${full%%[!0-9.]*}; ver=${ver%.}; suffix=${full#"$ver"}
      fixed=${FIXED[$(cut -d. -f1-2 <<<"$ver")]:-}
    fi
    if [[ -n $fixed && $(vcmp "$ver" "$fixed") -ge 0 ]] && ! is_prerelease "$suffix"; then
      emit PASS "$sapi" "$show" "$seen" "$full" "" \
        "Running image (file since replaced or deleted on disk) is at or after $fixed."
    else
      emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "" \
        "The process uses a file that has since been replaced or deleted on disk, so no package record describes it. Restart the service and re-run."
    fi
    return
  fi
  if [[ -z $full ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "" "" \
      "No PHP version string found in the file. Inspect it manually."
    return
  fi
  ver=${full%%[!0-9.]*}; ver=${ver%.}; suffix=${full#"$ver"}
  branch=$(cut -d. -f1-2 <<<"$ver")

  owner=$(pkg_owner "$root" "$p")
  IFS='|' read -r mgr pkg pkgver pkgev <<<"$owner"
  pkgdesc="-"; [[ $mgr == dpkg || $mgr == rpm || $mgr == apk ]] && pkgdesc="$mgr:$pkg $pkgver"

  if [[ $mgr == rpm-unavailable ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "-" \
      "An rpm database is present but the rpm tool is not installed here, so package ownership cannot be read. Run the check on a system with rpm."
    return
  fi

  # The file must be the one the package installed.
  if [[ $pkgdesc != - ]]; then
    up=$(pkg_upstream "$pkgver")
    if [[ -n $up && $(vcmp "$ver" "$up") -ne 0 ]]; then
      emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
        "The file reports PHP $ver but its owning package is version $pkgver, so the file is not the packaged one. Find out who replaced it."
      return
    fi
    file_matches_package "$root" "$mgr" "$pkg" "$p" "$file"; m=$?
    if [[ $m -eq 1 ]]; then
      emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
        "The file's checksum differs from the one recorded for package $pkg, so the file is not the packaged one. Find out who changed it."
      return
    fi
    changelog_scan "$root" "$mgr" "$pkg" "$branch" "$pkgver"
  else
    CL_STATE=NA
  fi

  if [[ $CL_STATE == FOUND && -n $CL_NEG ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "The changelog ($CL_SRC) mentions the CVEs in wording that may not mean a fix: \"$CL_QUOTE\". Read the entry."
    return
  fi
  if [[ $CL_STATE == FOUND && $CL_IDS == *"$CVE_A"* && $CL_IDS == *"$CVE_B"* ]]; then
    emit PASS "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Changelog $CL_SRC records both $CVE_A and $CVE_B, e.g. \"$CL_QUOTE\"."
    return
  fi

  if [[ $(vcmp "$branch" 8.2) -lt 0 ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Branch $branch is outside the vendor advisory (8.2 to 8.5); sources disagree on whether it is affected, and no fix is recorded. Upgrade to a supported fixed release."
    return
  fi
  fixed=${FIXED[$branch]:-}
  if [[ -z $fixed ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Branch $branch is newer than this rule set ($RULES_DATE). Check for a later advisory."
    return
  fi

  c=$(vcmp "$ver" "$fixed")
  below=0
  { [[ $c -lt 0 ]] || { [[ $c -eq 0 ]] && is_prerelease "$suffix"; }; } && below=1
  if [[ $below -eq 0 ]]; then
    emit PASS "$sapi" "$show" "$seen" "$full" "$pkgdesc" "Upstream version is at or after the fixed release $fixed."
    return
  fi

  if [[ $CL_STATE == FOUND ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed and the changelog ($CL_SRC) records only $CL_IDS. Check the vendor advisory for the other CVE."
  elif [[ $CL_STATE == NA ]]; then
    emit FAIL "$sapi" "$show" "$seen" "$full" "-" \
      "Unpackaged build, version precedes $fixed, and no package record of a fix exists. If it was patched by hand, document that; otherwise rebuild or upgrade."
  elif [[ $mgr == apk ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed. Alpine keeps no package changelog on the system, so a backported fix cannot be ruled out locally. Check the Alpine security database for $pkg $pkgver, or upgrade."
  elif [[ $CL_STATE == UNREADABLE ]]; then
    emit "CHECK FAILED" "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed and the package changelog could not be read (documentation may be excluded). Check the vendor security notice for $pkg $pkgver."
  else
    emit FAIL "$sapi" "$show" "$seen" "$full" "$pkgdesc" \
      "Version precedes $fixed and the changelog ($CL_SRC) has no record of either CVE. Update the package."
  fi
}

# ---------------------------------------------------------------- discovery

declare -A SEEN ROOTOF READFROM STALE LABEL
declare -a ORDER

add_rt() { # key root path readfrom seen stale label
  if [[ -z ${SEEN[$1]+x} ]]; then
    ORDER+=("$1"); SEEN[$1]=$5; ROOTOF[$1]=$2; READFROM[$1]=$4; STALE[$1]=$6; LABEL[$1]=$7
  else
    SEEN[$1]+=",$5"
  fi
}

printf '# php2shell-hostcheck %s | rules %s | %s and %s | CVE-2026-115560 not covered\n' \
  "$CHECKER_VERSION" "$RULES_DATE" "$CVE_A" "$CVE_B"
printf '# host %s | checked %s\n' "$HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'host|result|sapi|path|seen|php_version|package|reason\n'

[[ $EUID -ne 0 ]] && emit "CHECK FAILED" "-" "-" "-" "" "" \
  "Not run as root: some processes or files may not have been inspected. Re-run as root."

if [[ $LIVE -eq 1 ]]; then
  self_ns=$(readlink /proc/self/ns/mnt)
  self_root=$(stat -L -c %d:%i / 2>/dev/null)
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    ns=$(readlink "$d/ns/mnt" 2>/dev/null) || continue
    r=""; lab=""
    # A separate mount namespace is a container only if its root directory
    # differs from ours (systemd sandboxing keeps the same root).
    if [[ $ns != "$self_ns" ]]; then
      if [[ $(stat -L -c %d:%i "$d/root" 2>/dev/null) != "$self_root" ]]; then
        r="/proc/$pid/root"; lab="container, root $r"
      else
        ns=$self_ns
      fi
    fi
    exe=$(readlink "$d/exe" 2>/dev/null)
    if [[ -n $exe ]]; then
      st=""; [[ $exe == *" (deleted)" ]] && { exe=${exe% (deleted)}; st=1; }
      case ${exe##*/} in
        php|php[0-9]*|php-fpm*|php-cgi*|phpdbg*)
          add_rt "$ns|$exe|$st" "$r" "$exe" "/proc/$pid/exe" "pid$pid" "$st" "$lab" ;;
      esac
    fi
    # PHP modules loaded into another process, such as mod_php in Apache.
    while read -r range _ _ _ _ lib; do
      [[ $lib =~ /(libphp|mod_php)[^/]*\.so ]] || continue
      st=""; [[ $lib == *" (deleted)" ]] && { lib=${lib% (deleted)}; st=1; }
      from="$r$lib"; [[ -n $st ]] && from="/proc/$pid/map_files/$range"
      add_rt "$ns|$lib|$st" "$r" "$lib" "$from" "pid$pid" "$st" "$lab"
    done 2>/dev/null < "$d/maps"
  done
fi

# Installed binaries and modules (this also finds php-cgi, which only runs
# per request). Container, VM and snap storage and network filesystems are
# skipped and reported separately.
base=${ROOT:-/}
host_ns=$( [[ $LIVE -eq 1 ]] && readlink /proc/self/ns/mnt || echo image )
STORES=(var/lib/docker var/lib/containers var/lib/containerd var/lib/lxc var/lib/lxd
        var/snap/lxd snap var/lib/snapd var/lib/machines var/lib/flatpak)
prune=()
for s in "${STORES[@]}"; do prune+=(-o -path "$ROOT/$s"); done
prune+=(-o -path "$ROOT/home/*/.local/share/containers" -o -path "$ROOT/root/.local/share/containers")
errlog=$(mktemp) || exit 70
trap 'rm -f "$errlog"' EXIT

while IFS= read -r -d '' f; do
  is_elf "$f" || continue
  case ${f##*/} in
    php|php[0-9]*|php-fpm*|php-cgi*|phpdbg*|libphp*|mod_php*) ;;
    *) grep -aqF "$MARKER" "$f" 2>/dev/null || continue ;;  # other web-server modules
  esac
  rel=${f#"$ROOT"}
  add_rt "$host_ns|$rel|" "$ROOT" "$rel" "$f" "installed" "" ""
done < <(find "$base" \( -path "$ROOT/proc" -o -path "$ROOT/sys" -o -path "$ROOT/dev" \
           -o -path "$ROOT/run" "${prune[@]}" -o -fstype nfs -o -fstype nfs4 -o -fstype cifs \
           -o -fstype smb3 -o -fstype fuse.sshfs \) -prune -o -type f \
           \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
              -o -name 'phpdbg*' -o -name 'libphp*.so*' -o -name 'mod_php*.so*' \
              -o \( -name '*.so' \( -path '*apache*' -o -path '*httpd*' \) \) \) -print0 2>"$errlog")

for k in "${ORDER[@]}"; do
  IFS='|' read -r _ p _ <<<"$k"
  evaluate "${ROOTOF[$k]}" "$p" "${READFROM[$k]}" "${SEEN[$k]}" "${STALE[$k]}" "${LABEL[$k]}"
done

for s in "${STORES[@]}"; do
  [[ -d $base/$s ]] && emit "CHECK FAILED" "-" "/$s" "storage" "" "" \
    "Container, VM or snap storage is not inspected. Run this checker inside each container, or with --root against each extracted image."
done
for s in "$ROOT"/home/*/.local/share/containers "$ROOT"/root/.local/share/containers; do
  [[ -d $s ]] && emit "CHECK FAILED" "-" "${s#"$ROOT"}" "storage" "" "" \
    "Rootless container storage is not inspected. Run this checker inside each container."
done

# An incomplete filesystem walk must never turn into "nothing found".
walk_errors=$(grep -v 'No such file or directory' "$errlog" | wc -l)
if ((walk_errors > 0)); then
  emit "CHECK FAILED" "-" "-" "-" "" "" \
    "The filesystem walk was incomplete: $walk_errors error(s), first: $(grep -v 'No such file or directory' "$errlog" | head -1 | cut -c1-120). Fix access and re-run."
elif [[ ${#ORDER[@]} -eq 0 ]]; then
  emit PASS "-" "-" "-" "" "" "No PHP binary, module or process found on the inspected filesystems."
fi

printf '# summary: %d PASS, %d FAIL, %d CHECK FAILED\n' "$NPASS" "$NFAIL" "$NCHK"
((NFAIL > 0)) && exit 1
((NCHK > 0)) && exit 2
exit 0
