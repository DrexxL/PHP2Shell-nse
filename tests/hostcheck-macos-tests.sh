#!/usr/bin/env bash
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# hostcheck-macos-tests.sh - self-checking tests for php2shell-hostcheck-macos.sh
#
# It builds small fake Mac disks in a temporary folder, runs the macOS host
# check on each one with --root, and compares every result with the expected
# one. The fake "PHP programs" are tiny files that start like a Mac program
# (Mach-O) and contain a PHP version string. A fake lsof is used to test the
# running-process checks. Nothing outside the temporary folder is changed.
#
# It runs on macOS (with the bash 3.2 that macOS includes) and on Linux.
#
# HOW TO USE
#   ./tests/hostcheck-macos-tests.sh          (from the repository folder)
# Exit status: 0 = all tests passed, 1 = at least one test failed.
# Run it as root (sudo) to include the root-only tests.

set -o pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "$0")/.." && pwd)
CHECK="$HERE/php2shell-hostcheck-macos.sh"
# Run the checker with the same bash as this suite, or with the shell named
# in PHP2SHELL_TEST_SHELL (for example a bash 3.2 build, to test old-bash use).
SH=${PHP2SHELL_TEST_SHELL:-${BASH:-bash}}
T=$(mktemp -d 2>/dev/null || mktemp -d -t php2shelltest) || exit 1
chmod 755 "$T"
trap 'rm -rf "$T"' EXIT
PASSED=0; FAILED=0

ok()   { PASSED=$((PASSED + 1)); printf 'ok    %s\n' "$1"; }
bad()  { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "$2"; }

# macho IMAGE PATH VERSION: a fake Mac PHP program or module.
macho() {
  mkdir -p "$(dirname "$1$2")"
  printf '\317\372\355\376\007\000\000\001junk\000X-Powered-By: PHP/%s\000end' "$3" > "$1$2"
}
receipt() { mkdir -p "$1$2"; echo '{"homebrew_version":"4.5.0"}' > "$1$2/INSTALL_RECEIPT.json"; }

# expect NAME IMAGE PATH RESULT [TEXT]
expect() {
  local line got
  line=$("$SH" "$CHECK" --root "$2" 2>/dev/null | awk -F'|' -v p="$3" '$4 == p' | head -1)
  got=$(echo "$line" | cut -d'|' -f2)
  if [ "$got" = "$4" ] && { [ -z "${5:-}" ] || case $line in *"$5"*) true ;; *) false ;; esac; }; then
    ok "$1"
  else
    bad "$1" "want $4 ${5:-} / got ${line:-<no line>}"
  fi
}

# --------------------------------------------------------------- Homebrew
I=$T/brew
macho "$I" /opt/homebrew/Cellar/php@8.3/8.3.20/bin/php 8.3.20
receipt "$I" /opt/homebrew/Cellar/php@8.3/8.3.20
expect "Homebrew below fix -> FAIL, brew upgrade advice" "$I" /opt/homebrew/Cellar/php@8.3/8.3.20/bin/php FAIL "brew upgrade php@8.3"
macho "$I" /opt/homebrew/Cellar/php/8.4.27_1/sbin/php-fpm 8.4.27
receipt "$I" /opt/homebrew/Cellar/php/8.4.27_1
expect "Homebrew at fix (with revision) -> PASS"          "$I" /opt/homebrew/Cellar/php/8.4.27_1/sbin/php-fpm PASS "brew:php 8.4.27_1"
macho "$I" /opt/homebrew/Cellar/php/8.4.27_1/lib/httpd/modules/libphp.so 8.4.27
expect "Homebrew Apache module -> apache2handler"         "$I" /opt/homebrew/Cellar/php/8.4.27_1/lib/httpd/modules/libphp.so PASS "|apache2handler|"
macho "$I" /usr/local/Cellar/php@8.2/8.2.30/bin/php 8.2.30
receipt "$I" /usr/local/Cellar/php@8.2/8.2.30
expect "Intel Homebrew (/usr/local) below fix -> FAIL"    "$I" /usr/local/Cellar/php@8.2/8.2.30/bin/php FAIL "brew upgrade php@8.2"
I=$T/brew-mismatch
macho "$I" /opt/homebrew/Cellar/php@8.3/8.3.36/bin/php 8.3.6
receipt "$I" /opt/homebrew/Cellar/php@8.3/8.3.36
expect "file differs from its Homebrew keg -> CHECK FAILED" "$I" /opt/homebrew/Cellar/php@8.3/8.3.36/bin/php "CHECK FAILED" "not the packaged one"
I=$T/brew-noreceipt
macho "$I" /opt/homebrew/Cellar/php@8.3/8.3.20/bin/php 8.3.20
expect "Cellar folder without receipt -> unpackaged FAIL" "$I" /opt/homebrew/Cellar/php@8.3/8.3.20/bin/php FAIL "no Homebrew install receipt"

# --------------------------------------------------------------- other sources
I=$T/others
macho "$I" /opt/local/bin/php83 8.3.20
expect "MacPorts below fix -> FAIL, port upgrade advice"  "$I" /opt/local/bin/php83 FAIL "port upgrade"
macho "$I" /Applications/MAMP/bin/php/php8.2.0/bin/php 8.2.0
expect "MAMP below fix -> FAIL"                           "$I" /Applications/MAMP/bin/php/php8.2.0/bin/php FAIL "bundle:MAMP"
macho "$I" "/Users/alice/Library/Application Support/Herd/bin/php84" 8.4.27
expect "Laravel Herd (path with spaces) at fix -> PASS"   "$I" "/Users/alice/Library/Application Support/Herd/bin/php84" PASS "bundle:Laravel Herd"
macho "$I" /Applications/XAMPP/xamppfiles/bin/php 8.1.30
expect "XAMPP on branch 8.1 -> CHECK FAILED"              "$I" /Applications/XAMPP/xamppfiles/bin/php "CHECK FAILED" "outside the vendor advisory"
macho "$I" /usr/local/php5/bin/php 8.2.35RC1
expect "release candidate of fix -> FAIL"                 "$I" /usr/local/php5/bin/php FAIL "Unpackaged build"
macho "$I" /opt/php-next/bin/php 8.6.0
expect "branch 8.6 -> CHECK FAILED"                       "$I" /opt/php-next/bin/php "CHECK FAILED" "newer than this rule set"
macho "$I" /usr/local/bin/php-cgi 8.5.12
expect "unpackaged at fix -> PASS"                        "$I" /usr/local/bin/php-cgi PASS "|cgi-fcgi|"

printf '#!/bin/sh\necho X-Powered-By: PHP/8.2.1\n' > "$I/usr/local/bin/php"
if "$SH" "$CHECK" --root "$I" 2>/dev/null | grep -q '|/usr/local/bin/php|'; then
  bad "shell script named php is ignored"
else ok "shell script named php is ignored"; fi

# --------------------------------------------------------------- skipped places
I=$T/skips
macho "$I" /System/Library/php 8.2.10
macho "$I" /Volumes/Backup/usr/bin/php 8.2.10
out=$("$SH" "$CHECK" --root "$I" 2>/dev/null)
case $out in
  *"/System/"*|*"/Volumes/"*) bad "/System and /Volumes are skipped" "$out" ;;
  *) ok "/System and /Volumes are skipped" ;;
esac
I=$T/docker
mkdir -p "$I/Users/alice/Library/Containers/com.docker.docker/Data/vms/0"
macho "$I" /Users/alice/Library/Containers/com.docker.docker/Data/vms/0/php 8.2.10
expect "Docker Desktop storage -> CHECK FAILED, not opened" "$I" /Users/alice/Library/Containers/com.docker.docker "CHECK FAILED" "not inspected"
case $("$SH" "$CHECK" --root "$I" 2>/dev/null) in
  *"vms/0/php"*) bad "files inside Docker Desktop storage are not judged" ;;
  *) ok "files inside Docker Desktop storage are not judged" ;;
esac

# --------------------------------------------------------------- adversarial
I=$T/renamed
macho "$I" /Users/alice/bin/worker 8.2.10
head -c 1100000 /dev/zero >> "$I/Users/alice/bin/worker"; chmod 755 "$I/Users/alice/bin/worker"
expect "renamed PHP binary is found by its marker -> FAIL" "$I" /Users/alice/bin/worker FAIL "|unknown|"
I=$T/hostile
macho "$I" '/opt/x|PASS|y/php' 8.2.10
macho "$I" "/opt/new
PASS line/php" 8.2.10
out=$("$SH" "$CHECK" --root "$I" 2>/dev/null)
rows=$(echo "$out" | grep -c '|FAIL|cli|/opt/')
badrows=$(echo "$out" | grep '^image:' | awk -F'|' 'NF != 8' | wc -l | tr -d ' ')
case $out in
  *"/opt/x%7CPASS%7Cy/php"*"/opt/new%0APASS line/php"*|*"/opt/new%0APASS line/php"*"/opt/x%7CPASS%7Cy/php"*)
    if [ "$rows" -eq 2 ] && [ "$badrows" -eq 0 ]; then ok "hostile file names are percent-encoded (2 rows, 8 fields each)"
    else bad "hostile file names are percent-encoded" "rows $rows, bad $badrows"; fi ;;
  *) bad "hostile file names are percent-encoded" "$out" ;;
esac

# --------------------------------------------------------------- whole run
I=$T/empty; mkdir -p "$I/usr/local/bin"
if [ "$(id -u)" -eq 0 ]; then
  out=$("$SH" "$CHECK" --root "$I" 2>/dev/null); rc=$?
  if [ $rc -eq 0 ] && case $out in *"No PHP program"*) true ;; *) false ;; esac; then ok "empty disk as root -> PASS, exit 0"
  else bad "empty disk as root -> PASS, exit 0" "exit $rc"; fi
fi
"$SH" "$CHECK" --root "$T/brew" >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && ok "any FAIL -> exit 1" || bad "any FAIL -> exit 1" "exit $rc"
"$SH" "$CHECK" --root "$T/docker" >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && ok "only CHECK FAILED -> exit 2" || bad "only CHECK FAILED -> exit 2" "exit $rc"
"$SH" "$CHECK" --root / >/dev/null 2>&1; rc=$?
[ $rc -eq 64 ] && ok "--root / is refused (exit 64)" || bad "--root / is refused" "exit $rc"
sh "$CHECK" >/dev/null 2>&1; rc=$?
if [ $rc -eq 69 ] || [ "$(readlink /bin/sh 2>/dev/null)" = bash ]; then ok "run with sh (not bash) -> exit 69, or sh is bash"
else bad "run with sh (not bash) -> exit 69" "exit $rc"; fi

# --------------------------------------------------------------- running processes
# A fake lsof reports three PHP processes: one current, one whose file was
# replaced after it started (different inode), and one whose file is gone.
I=$T/live
macho "$I" /opt/homebrew/Cellar/php/8.4.27/sbin/php-fpm 8.4.27
receipt "$I" /opt/homebrew/Cellar/php/8.4.27
macho "$I" /opt/homebrew/Cellar/php/8.4.20/sbin/php-fpm 8.4.20
FPM_OK="$I/opt/homebrew/Cellar/php/8.4.27/sbin/php-fpm"
FPM_OLD="$I/opt/homebrew/Cellar/php/8.4.20/sbin/php-fpm"
INO_OK=$(ls -di "$FPM_OK" | awk '{print $1}')
macho "$I" /Users/alice/srv/queue-worker 8.4.20
WORKER="$I/Users/alice/srv/queue-worker"
INO_W=$(ls -di "$WORKER" | awk '{print $1}')
mkdir -p "$T/fakebin"
cat > "$T/fakebin/lsof" <<FAKE
#!/bin/sh
printf 'p101\nftxt\ni$INO_OK\nn$FPM_OK\n'
printf 'p102\nftxt\ni1\nn$FPM_OLD\n'
printf 'p103\nftxt\ni2\nn$I/opt/homebrew/Cellar/php/8.4.19/sbin/php-fpm\n'
printf 'p104\nftxt\ni3\nn/usr/lib/libSystem.B.dylib\n'
printf 'p105\nftxt\ni$INO_W\nn$WORKER\n'
FAKE
chmod 755 "$T/fakebin/lsof"
out=$(PATH="$T/fakebin:$PATH" "$SH" "$CHECK" 2>/dev/null)
line=$(echo "$out" | awk -F'|' -v p="$FPM_OK" '$4 == p')
case $line in *"|PASS|"*"pid101"*) ok "running process, file unchanged -> judged (PASS)" ;; *) bad "running process, file unchanged" "$line" ;; esac
line=$(echo "$out" | awk -F'|' -v p="$FPM_OLD" '$4 == p && $5 ~ /pid102/')
case $line in *"CHECK FAILED"*"replaced or deleted"*) ok "running process, file replaced -> CHECK FAILED" ;; *) bad "running process, file replaced" "$line" ;; esac
line=$(echo "$out" | grep 'php/8.4.19/sbin/php-fpm')
case $line in *"CHECK FAILED"*"replaced or deleted"*) ok "running process, file deleted -> CHECK FAILED" ;; *) bad "running process, file deleted" "$line" ;; esac
case $out in *"libSystem"*) bad "non-PHP libraries are ignored" ;; *) ok "non-PHP libraries are ignored" ;; esac
line=$(echo "$out" | awk -F'|' -v p="$WORKER" '$4 == p && $5 ~ /pid105/')
case $line in *"|FAIL|unknown|"*) ok "renamed running PHP is found by its marker" ;; *) bad "renamed running PHP is found" "$line" ;; esac

printf '#!/bin/sh\nexit 127\n' > "$T/fakebin/lsof"; rm -f "$T/fakebin/lsof"
NOLSOF=$T/nolsof; mkdir -p "$NOLSOF"
for f in /usr/local/bin/* /usr/bin/* /bin/* /usr/sbin/* /sbin/*; do
  case ${f##*/} in lsof) continue ;; esac
  [ -e "$NOLSOF/${f##*/}" ] || ln -s "$f" "$NOLSOF/${f##*/}" 2>/dev/null
done
case $(PATH=$NOLSOF "$SH" "$CHECK" 2>/dev/null) in
  *"lsof is not available"*) ok "no lsof -> CHECK FAILED, processes not inspected" ;;
  *) bad "no lsof -> CHECK FAILED" ;;
esac

# --------------------------------------------------------------- permissions
if [ "$(id -u)" -eq 0 ] && command -v setpriv >/dev/null 2>&1; then
  I=$T/locked
  macho "$I" /opt/homebrew/Cellar/php/8.4.27/bin/php 8.4.27
  chmod 700 "$I/opt"
  cp "$CHECK" "$T/hc.sh"; chmod 755 "$T/hc.sh"
  out=$(setpriv --reuid=65534 --regid=65534 --clear-groups "$SH" "$T/hc.sh" --root "$I" 2>/dev/null); rc=$?
  case $out in
    *"search was incomplete"*"Full Disk Access"*)
      case $out in *"No PHP program"*) bad "unreadable folder -> never 'nothing found'" ;; *)
        [ $rc -eq 2 ] && ok "unreadable folder -> CHECK FAILED with Full Disk Access advice" || bad "unreadable folder" "exit $rc" ;; esac ;;
    *) bad "unreadable folder -> CHECK FAILED" "exit $rc" ;;
  esac
else
  echo "skip  unreadable-folder test (needs root and setpriv; on a Mac, test with a folder you lack access to)"
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ $FAILED -eq 0 ]
