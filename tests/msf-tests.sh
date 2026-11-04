#!/usr/bin/env bash
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# msf-tests.sh - self-checking tests for metasploit/php2shell_banner.rb
#
# It starts the same fake web servers as nse-tests.sh (127.0.0.1 only,
# ports 19001-19011), runs the Metasploit module against each one, and
# compares every result with the expected one. No other computer is
# contacted.
#
# HOW TO USE
#   ./tests/msf-tests.sh          (from the repository folder)
# Needs python3 and either msfconsole, or Docker with the official image
# metasploitframework/metasploit-framework. Exit status: 0 = all passed.

set -o pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "$0")/.." && pwd)
PASSED=0; FAILED=0
command -v python3 >/dev/null || { echo "python3 is not installed" >&2; exit 1; }

W=$(mktemp -d) || exit 1
chmod 777 "$W"
mkdir -p "$W/modules/auxiliary/scanner/http"
cp "$HERE/metasploit/php2shell_banner.rb" "$W/modules/auxiliary/scanner/http/"
chmod -R a+rwX "$W"

python3 -I "$HERE/tests/fake_http.py" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; rm -rf "$W"' EXIT
sleep 1

{
  echo "use auxiliary/scanner/http/php2shell_banner"
  echo "set RHOSTS 127.0.0.1"
  echo "set VERBOSE true"
  echo "set PATHS /app/"
  echo "set PROBE_INFO true"
  for p in 19001 19002 19003 19004 19005 19006 19007 19008 19009 19010 19011 19099; do
    echo "set RPORT $p"; echo "run"
  done
  echo "exit"
} > "$W/test.rc"

if command -v msfconsole >/dev/null; then
  OUT=$(msfconsole -q -m "$W/modules" -r "$W/test.rc" 2>&1)
elif command -v docker >/dev/null && docker image inspect metasploitframework/metasploit-framework >/dev/null 2>&1; then
  OUT=$(docker run --rm --network host -v "$W:/home/msf/.msf4" metasploitframework/metasploit-framework \
        ./msfconsole -q -r /home/msf/.msf4/test.rc 2>&1)
else
  echo "Neither msfconsole nor the Metasploit Docker image is available." >&2
  exit 1
fi

# expect NAME PORT TEXT: some output line for that port contains TEXT.
expect() {
  if grep -F "127.0.0.1:$2 " <<<"$OUT" | grep -qF -- "$3"; then
    PASSED=$((PASSED + 1)); printf 'ok    %s\n' "$1"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL  %s\n      want "%s"\n' "$1" "$3"
    grep -F "127.0.0.1:$2 " <<<"$OUT" | sed 's/^/      /'
  fi
}

runs=$(grep -c "Auxiliary module execution completed" <<<"$OUT")
if [[ $runs -eq 12 ]] && ! grep -qE "Failed to load|Unknown command|No results from search|Error:" <<<"$OUT"; then
  PASSED=$((PASSED + 1)); echo "ok    module loads and runs 12 times"
else
  FAILED=$((FAILED + 1)); echo "FAIL  module loads and runs 12 times (completed $runs)"
fi
expect "version below fix"                19001 "BANNER BELOW FIX: Disclosed PHP 8.2.10 precedes the fixed release 8.2.35"
expect "release candidate of fix"         19002 "BANNER BELOW FIX: Disclosed PHP 8.2.35RC1 is a pre-release"
expect "branch 8.1 is not judged"         19003 "CHECK FAILED: Disclosed PHP 8.1.30 is on unsupported branch 8.1"
expect "version at fix, not called safe"  19004 "BANNER AT OR ABOVE FIX"
expect "  ...and says it is not proof"    19004 "not proof"
expect "no version shown"                 19005 "were not verified"
expect "different versions on two pages"  19006 "Conflicting PHP versions were disclosed: 8.2.35, 8.2.34"
expect "phpinfo heading counts"           19007 "phpinfo() heading: PHP Version 8.4.20"
expect "ordinary page text is ignored"    19007 "GET / -> 200, no PHP version disclosed"
expect "redirect is not followed"         19008 "redirect to /login, not followed"
expect "distribution build is not judged" 19009 "CHECK FAILED: Disclosed PHP 8.2.20-1+deb12u3 is a distribution build"
expect "partial version is reported"      19010 "Only a partial PHP version was disclosed (8.2)"
expect "newer branch is not judged"       19011 "newer than the advisory's scope"
expect "Host header recorded"             19001 "Host: 127.0.0.1:19001"
expect "no response"                      19099 "No HTTP response was received on any requested path"
if grep -qiE "vulnerable|report_vuln" <<<"$(grep -F '127.0.0.1:' <<<"$OUT")"; then
  FAILED=$((FAILED + 1)); echo "FAIL  never says vulnerable"
else
  PASSED=$((PASSED + 1)); echo "ok    never says vulnerable"
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
((FAILED == 0))
