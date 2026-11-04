#!/usr/bin/env bash
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# hostcheck-tests.sh - self-checking tests for php2shell-hostcheck.sh
#
# It builds small fake disk images in a temporary folder, runs the host
# check on each one with --root, and compares every result with the
# expected one. The fake "PHP programs" are tiny files that start like a
# Linux program (ELF) and contain a PHP version string. Nothing is
# installed and nothing outside the temporary folder is changed.
#
# HOW TO USE
#   ./tests/hostcheck-tests.sh          (from the repository folder)
# Exit status: 0 = all tests passed, 1 = at least one test failed.
# Run it as root to include the unreadable-folder test.

set -o pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "$0")/.." && pwd)
CHECK="$HERE/php2shell-hostcheck.sh"
T=$(mktemp -d) || exit 1
chmod 755 "$T"
trap 'rm -rf "$T"' EXIT
PASSED=0; FAILED=0

# fake IMAGE PATH VERSION: a fake PHP program or module.
fake() { mkdir -p "$(dirname "$1$2")"; printf '\177ELF\0\0junk\0X-Powered-By: PHP/%s\0end' "$3" > "$1$2"; }

# dpkg IMAGE PACKAGE VERSION PATH [CHANGELOG-TEXT]: register a Debian package.
dpkg_pkg() {
  local img=$1 pkg=$2 ver=$3 path=$4 text=${5-}
  mkdir -p "$img/var/lib/dpkg/info"
  echo "$path" > "$img/var/lib/dpkg/info/$pkg.list"
  printf 'Package: %s\nVersion: %s\n\n' "${pkg%%:*}" "$ver" >> "$img/var/lib/dpkg/status"
  if [[ -n $text ]]; then
    mkdir -p "$img/usr/share/doc/${pkg%%:*}"
    printf '%s\n' "$text" | gzip > "$img/usr/share/doc/${pkg%%:*}/changelog.Debian.gz"
  fi
}

# expect NAME IMAGE PATH RESULT [TEXT]: the line for PATH must have RESULT
# and, if given, contain TEXT in its reason.
expect() {
  local name=$1 img=$2 path=$3 want=$4 text=${5-} line got
  line=$(bash "$CHECK" --root "$img" 2>/dev/null | awk -F'|' -v p="$path" '$4 == p' | head -1)
  got=$(cut -d'|' -f2 <<<"$line")
  if [[ $got == "$want" && ( -z $text || $line == *"$text"* ) ]]; then
    PASSED=$((PASSED + 1)); printf 'ok    %s\n' "$name"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL  %s\n      want %s %s\n      got  %s\n' "$name" "$want" "$text" "${line:-<no line>}"
  fi
}

# --------------------------------------------------------------- version rules
I=$T/rules
fake "$I" /opt/a/php 8.2.10;      expect "unpackaged, below fix -> FAIL"           "$I" /opt/a/php FAIL "Unpackaged build"
fake "$I" /opt/b/php 8.2.35;      expect "unpackaged, at fix -> PASS"              "$I" /opt/b/php PASS "at or after"
fake "$I" /opt/c/php-cgi 8.2.35RC1; expect "release candidate of fix -> FAIL"      "$I" /opt/c/php-cgi FAIL
fake "$I" /opt/d/php-fpm 8.5.12-dev; expect "dev build of fix -> FAIL"             "$I" /opt/d/php-fpm FAIL
fake "$I" /opt/e/php 8.1.30;      expect "branch 8.1 -> CHECK FAILED"              "$I" /opt/e/php "CHECK FAILED" "outside the vendor advisory"
fake "$I" /opt/f/php 5.6.40;      expect "branch 5.6 -> CHECK FAILED"              "$I" /opt/f/php "CHECK FAILED" "outside the vendor advisory"
fake "$I" /opt/g/php 8.6.0;       expect "branch 8.6 -> CHECK FAILED"              "$I" /opt/g/php "CHECK FAILED" "newer than this rule set"
fake "$I" /opt/h/php 8.4.30;      expect "above fix -> PASS"                       "$I" /opt/h/php PASS
printf '#!/bin/sh\necho X-Powered-By: PHP/8.2.1\n' > "$I/opt/h/php-config"
line=$(bash "$CHECK" --root "$I" | grep -c '/opt/h/php-config')
if [[ $line -eq 0 ]]; then PASSED=$((PASSED + 1)); echo "ok    shell script named like PHP is ignored"
else FAILED=$((FAILED + 1)); echo "FAIL  shell script named like PHP is ignored"; fi

# --------------------------------------------------------------- packages
I=$T/pkg
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.6-0ubuntu0.24.04.13 /usr/bin/php8.3 $'php8.3 (8.3.6-0ubuntu0.24.04.13)\n  * SECURITY UPDATE: CVE-2026-109618\n  * SECURITY UPDATE: CVE-2026-109619'
expect "backport in changelog -> PASS"        "$I" /usr/bin/php8.3 PASS "records both"
fake "$I" /usr/sbin/php-fpm8.4 8.4.20
dpkg_pkg "$I" php8.4-fpm 8.4.20-1 /usr/sbin/php-fpm8.4 'php8.4 (8.4.20-1) * CVE-2026-00001'
expect "changelog without CVEs -> FAIL"       "$I" /usr/sbin/php-fpm8.4 FAIL "no record of either CVE"
fake "$I" /usr/bin/php-cgi8.3 8.3.6
dpkg_pkg "$I" php8.3-cgi 8.3.6-0ubuntu1 /usr/bin/php-cgi8.3 '  * CVE-2026-109618 only'
expect "only one CVE in changelog -> CHECK FAILED" "$I" /usr/bin/php-cgi8.3 "CHECK FAILED" "records only"
fake "$I" /usr/lib/apache2/modules/libphp8.2.so 8.2.20
dpkg_pkg "$I" libapache2-mod-php8.2:amd64 8.2.20-1 /usr/lib/apache2/modules/libphp8.2.so
expect "changelog missing -> CHECK FAILED"    "$I" /usr/lib/apache2/modules/libphp8.2.so "CHECK FAILED" "could not be read"
fake "$I" /usr/bin/php8.2 8.2.20
dpkg_pkg "$I" php8.2-cli 8.2.20-1 /usr/bin/php8.2 '  * CVE-2026-109618 and CVE-2026-109619 are NOT fixed in this upload'
expect "changelog says not fixed -> CHECK FAILED" "$I" /usr/bin/php8.2 "CHECK FAILED" "may not mean a fix"

# A file that does not match its package must never PASS.
I=$T/mismatch
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.36-1 /usr/bin/php8.3 '  * CVE-2026-109618 CVE-2026-109619'
expect "file version differs from package -> CHECK FAILED" "$I" /usr/bin/php8.3 "CHECK FAILED" "not the packaged one"
I=$T/checksum
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.6-1 /usr/bin/php8.3 '  * CVE-2026-109618 CVE-2026-109619'
echo "00000000000000000000000000000000  usr/bin/php8.3" > "$I/var/lib/dpkg/info/php8.3-cli.md5sums"
expect "file checksum differs from package -> CHECK FAILED" "$I" /usr/bin/php8.3 "CHECK FAILED" "checksum differs"
I=$T/checksum-ok
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.6-1 /usr/bin/php8.3 '  * CVE-2026-109618 CVE-2026-109619'
echo "$(md5sum < "$I/usr/bin/php8.3" | cut -d' ' -f1)  usr/bin/php8.3" > "$I/var/lib/dpkg/info/php8.3-cli.md5sums"
expect "file checksum matches package -> PASS" "$I" /usr/bin/php8.3 PASS

# An absolute link inside the image must stay inside the image.
I=$T/symlink
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.6-1 /usr/bin/php8.3
mkdir -p "$I/usr/share/doc"
ln -s /usr/share/doc/php8.3-common "$I/usr/share/doc/php8.3-cli"
mkdir -p "$I/usr/share/doc/php8.3-common"
printf '  * CVE-2026-109618 CVE-2026-109619\n' | gzip > "$I/usr/share/doc/php8.3-common/changelog.Debian.gz"
printf 'Package: php8.3-common\nVersion: 8.3.6-1\n\n' >> "$I/var/lib/dpkg/status"
expect "absolute doc link resolved inside image -> PASS" "$I" /usr/bin/php8.3 PASS "/usr/share/doc/php8.3-common/"
I=$T/symlink-out
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.6-1 /usr/bin/php8.3
mkdir -p "$I/usr/share/doc"
ln -s "$T/pkg/usr/share/doc/php8.3-cli" "$I/usr/share/doc/php8.3-cli"
expect "link pointing outside image is not followed" "$I" /usr/bin/php8.3 "CHECK FAILED" "could not be read"

# A package whose version cannot be read must not give PASS.
I=$T/nover
fake "$I" /usr/bin/php8.3 8.3.6
mkdir -p "$I/var/lib/dpkg/info" "$I/usr/share/doc/php8.3-cli"
echo /usr/bin/php8.3 > "$I/var/lib/dpkg/info/php8.3-cli.list"
: > "$I/var/lib/dpkg/status"
printf '  * CVE-2026-109618 CVE-2026-109619\n' | gzip > "$I/usr/share/doc/php8.3-cli/changelog.Debian.gz"
expect "package version unreadable -> CHECK FAILED" "$I" /usr/bin/php8.3 "CHECK FAILED" "version could not be read"

# Fallback to php<branch>-common only at the same package version.
I=$T/common
fake "$I" /usr/bin/php8.3 8.3.6
dpkg_pkg "$I" php8.3-cli 8.3.6-2 /usr/bin/php8.3
mkdir -p "$I/usr/share/doc/php8.3-common"
printf '  * CVE-2026-109618 CVE-2026-109619\n' | gzip > "$I/usr/share/doc/php8.3-common/changelog.Debian.gz"
printf 'Package: php8.3-common\nVersion: 8.3.6-1\n\n' >> "$I/var/lib/dpkg/status"
expect "common changelog at another version is refused" "$I" /usr/bin/php8.3 "CHECK FAILED" "could not be read"

# Alpine and rpm
I=$T/apk
fake "$I" /usr/lib/apache2/mod_php83.so 8.3.20
mkdir -p "$I/lib/apk/db"
printf 'P:php83-apache2\nV:8.3.20-r0\nF:usr/lib/apache2\nR:mod_php83.so\n\n' > "$I/lib/apk/db/installed"
expect "Alpine mod_php83.so is found -> CHECK FAILED" "$I" /usr/lib/apache2/mod_php83.so "CHECK FAILED" "Alpine keeps no package changelog"
I=$T/apk-fixed
fake "$I" /usr/bin/php83 8.3.36
mkdir -p "$I/lib/apk/db"
printf 'P:php83\nV:8.3.36-r0\nF:usr/bin\nR:php83\n\n' > "$I/lib/apk/db/installed"
expect "Alpine at fix -> PASS" "$I" /usr/bin/php83 PASS
# An rpm database checked from a computer without the rpm tool. If rpm is
# installed here, hide it by running with a PATH that leaves it out.
I=$T/rpm
fake "$I" /usr/bin/php 8.2.10
mkdir -p "$I/var/lib/rpm"; : > "$I/var/lib/rpm/Packages"
NORPM=$T/norpm-bin; mkdir -p "$NORPM"
for f in /usr/local/bin/* /usr/bin/* /bin/*; do
  case ${f##*/} in rpm*) continue ;; esac
  [[ -e $NORPM/${f##*/} ]] || ln -s "$f" "$NORPM/${f##*/}" 2>/dev/null
done
line=$(PATH=$NORPM bash "$CHECK" --root "$I" 2>/dev/null | awk -F'|' '$4 == "/usr/bin/php"')
if [[ $line == *"CHECK FAILED"*"rpm tool is not installed"* ]]; then
  PASSED=$((PASSED + 1)); echo "ok    rpm database without rpm tool -> CHECK FAILED"
else
  FAILED=$((FAILED + 1)); echo "FAIL  rpm database without rpm tool -> CHECK FAILED"
  echo "      got  ${line:-<no line>}"
fi

# Real rpm packages, built with rpmbuild and installed into test images,
# with the rpm database in each of its two standard places.
rpm_pkg() { # topdir name version release path binversion changelog-line
  local top=$1 spec="$1/$2.spec"
  mkdir -p "$top"
  {
    echo '%global debug_package %{nil}'
    echo '%global __os_install_post %{nil}'
    echo "Name: $2"; echo "Version: $3"; echo "Release: $4"
    echo 'Summary: test package'; echo 'License: Apache-2.0'
    echo '%description'; echo 'Test package for hostcheck-tests.sh.'
    echo '%install'
    echo "mkdir -p %{buildroot}$(dirname "$5")"
    echo "printf '\\177ELF\\0\\0junk\\0X-Powered-By: PHP/$6\\0end' > %{buildroot}$5"
    echo '%files'; echo "$5"
    echo '%changelog'
    echo "* Mon Oct 26 2026 Test <test@example.org> - $3-$4"
    echo "- $7"
  } > "$spec"
  rpmbuild -bb --define "_topdir $top" "$spec" >/dev/null 2>&1
}
if command -v rpm >/dev/null && command -v rpmbuild >/dev/null; then
  TOP=$T/rpmbuild
  rpm_pkg "$TOP" php-cli 8.2.10 1.el9 /usr/bin/php 8.2.10 "Backport fix for CVE-2026-109618 and CVE-2026-109619"
  rpm_pkg "$TOP" php-fpm 8.4.20 1.el9 /usr/sbin/php-fpm 8.4.20 "Rebuild"
  rpm_pkg "$TOP" php-cgi 8.3.36 1.el9 /usr/bin/php-cgi 8.3.6 "Update to 8.3.36"
  for db in /var/lib/rpm /usr/lib/sysimage/rpm; do
    I=$T/rpmimg${db//\//_}; mkdir -p "$I"
    rpm --root "$I" --dbpath "$db" --initdb
    rpm --root "$I" --dbpath "$db" -i --nodeps --noscripts --ignorearch "$TOP"/RPMS/*/*.rpm >/dev/null 2>&1
    expect "rpm ($db): backport in changelog -> PASS" "$I" /usr/bin/php PASS "rpm changelog of package php-cli"
    expect "rpm ($db): no fix in changelog -> FAIL"   "$I" /usr/sbin/php-fpm FAIL "no record of either CVE"
    expect "rpm ($db): file differs from package"     "$I" /usr/bin/php-cgi "CHECK FAILED" "not the packaged one"
  done
else
  echo "skip  rpm package tests (needs rpm and rpmbuild)"
fi

# An Apache module with an unusual name is found by its contents.
I=$T/module
fake "$I" /usr/lib/httpd/modules/custom_php.so 8.2.10
expect "PHP inside an oddly named module is found" "$I" /usr/lib/httpd/modules/custom_php.so FAIL

# --------------------------------------------------------------- whole-run results
I=$T/empty; mkdir -p "$I/usr/bin"
out=$(bash "$CHECK" --root "$I"); rc=$?
if [[ $rc -eq 0 && $out == *"No PHP binary, module or process found"* ]]; then
  PASSED=$((PASSED + 1)); echo "ok    empty image -> PASS, exit 0"
else FAILED=$((FAILED + 1)); echo "FAIL  empty image -> PASS, exit 0 (got exit $rc)"; fi

I=$T/storage; mkdir -p "$I/var/lib/docker"
expect "container storage is reported" "$I" /var/lib/docker "CHECK FAILED" "not inspected"

bash "$CHECK" --root "$T/rules" >/dev/null; rc=$?
if [[ $rc -eq 1 ]]; then PASSED=$((PASSED + 1)); echo "ok    any FAIL -> exit 1"
else FAILED=$((FAILED + 1)); echo "FAIL  any FAIL -> exit 1 (got $rc)"; fi
bash "$CHECK" --root / >/dev/null 2>&1; rc=$?
if [[ $rc -eq 64 ]]; then PASSED=$((PASSED + 1)); echo "ok    --root / is refused (exit 64)"
else FAILED=$((FAILED + 1)); echo "FAIL  --root / is refused (got $rc)"; fi

if [[ $EUID -eq 0 ]] && command -v setpriv >/dev/null; then
  I=$T/locked
  fake "$I" /usr/bin/php 8.2.10
  chmod 700 "$I/usr"
  cp "$CHECK" "$T/hc.sh"; chmod 755 "$T/hc.sh"
  out=$(setpriv --reuid=65534 --regid=65534 --clear-groups bash "$T/hc.sh" --root "$I" 2>/dev/null); rc=$?
  if [[ $rc -eq 2 && $out == *"walk was incomplete"* && $out != *"No PHP binary"* ]]; then
    PASSED=$((PASSED + 1)); echo "ok    unreadable folder -> CHECK FAILED, never 'nothing found'"
  else FAILED=$((FAILED + 1)); echo "FAIL  unreadable folder (exit $rc)"; fi
  I=$T/empty-user; mkdir -p "$I/usr/bin"
  out=$(setpriv --reuid=65534 --regid=65534 --clear-groups bash "$T/hc.sh" --root "$I" 2>/dev/null); rc=$?
  if [[ $rc -eq 2 && $out != *"No PHP binary"* ]]; then
    PASSED=$((PASSED + 1)); echo "ok    not root -> never 'nothing found', exit 2"
  else FAILED=$((FAILED + 1)); echo "FAIL  not root -> never 'nothing found' (exit $rc)"; fi
else
  echo "skip  unreadable folder and non-root tests (need root and setpriv)"
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
((FAILED == 0))
