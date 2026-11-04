#!/usr/bin/env bash
# Copyright 2026 Drexx Laggui
# SPDX-License-Identifier: Apache-2.0
#
# nse-tests.sh - self-checking tests for php2shell-detect.nse
#
# It starts fake web servers on this computer only (127.0.0.1, ports
# 19001-19011), scans them with nmap and the script, and compares every
# result with the expected one. No other computer is contacted.
#
# HOW TO USE
#   ./tests/nse-tests.sh          (from the repository folder)
# Needs nmap and python3. Exit status: 0 = all passed, 1 = a test failed.

set -o pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "$0")/.." && pwd)
NSE="$HERE/php2shell-detect.nse"
PASSED=0; FAILED=0

command -v nmap >/dev/null || { echo "nmap is not installed" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is not installed" >&2; exit 1; }

python3 -I "$HERE/tests/fake_http.py" &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1

OUT=$(nmap -Pn -sV -p 19001-19011 --script "$NSE" \
      --script-args 'php2shell-detect.paths=/app/,php2shell-detect.probe-info' 127.0.0.1 2>/dev/null)

# block PORT: the script output for one port.
block() { awk -v p="$1/tcp" '$1 == p {on=1; next} /^[0-9]+\/tcp/ {on=0} on' <<<"$OUT"; }

# expect NAME PORT RESULT TEXT: the port's result must be RESULT and its
# output must contain TEXT.
expect() {
  local b; b=$(block "$2")
  if grep -q "result: $3\$" <<<"$b" && grep -qF -- "$4" <<<"$b"; then
    PASSED=$((PASSED + 1)); printf 'ok    %s\n' "$1"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL  %s\n      want "%s" and "%s"\n%s\n' "$1" "$3" "$4" "$b"
  fi
}

expect "version below fix"                 19001 "BANNER BELOW FIX"       "precedes the fixed release 8.2.35"
expect "release candidate of fix"          19002 "BANNER BELOW FIX"       "pre-release"
expect "branch 8.1 is not judged"          19003 "CHECK FAILED"           "unsupported branch 8.1"
expect "version at fix, not called safe"   19004 "BANNER AT OR ABOVE FIX" "not proof"
expect "no version shown"                  19005 "CHECK FAILED"           "were not verified"
expect "different versions on two pages"   19006 "CHECK FAILED"           "Conflicting PHP versions"
expect "phpinfo heading counts"            19007 "BANNER BELOW FIX"       "phpinfo() heading: PHP Version 8.4.20"
expect "ordinary page text is ignored"     19007 "BANNER BELOW FIX"       "GET / -> 200, no PHP version disclosed"
expect "redirect is not followed"          19008 "CHECK FAILED"           "redirect to /login, not followed"
expect "distribution build is not judged"  19009 "CHECK FAILED"           "distribution build"
expect "partial version is reported"       19010 "CHECK FAILED"           "partial PHP version"
expect "newer branch is not judged"        19011 "CHECK FAILED"           "newer than the advisory"
expect "transport recorded"                19001 "BANNER BELOW FIX"       "target: http://127.0.0.1:19001"
expect "rule date recorded"                19001 "BANNER BELOW FIX"       "rule set dated 2026-11-04"

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
((FAILED == 0))
