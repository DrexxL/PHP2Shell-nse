# Changelog

All notable changes to this project. Dates are in UTC.

## 2026-11-04

### Host checks, after the re-audit of a49b8f1

The re-audit still reported open findings (verdict: not satisfied). These
fixes were tested but, by the maintainer's choice, not re-audited:

- Changelog: an item that names a CVE without stating a fix that covers it
  (for example a newer "Undo the CVE changes") now blocks a changelog PASS,
  and is the item quoted. "back out", "undo", "not shipped" and "planned"
  were added to the deny words. (False PASS removed.)
- macOS: file names with control characters are decoded correctly again, so
  the right file is read. (A true FAIL was hidden before.)
- AI-ASSISTANCE.md no longer says the work passed an audit.
- Documented limits: a non-PHP program that contains PHP's version text is
  judged as PHP; on a Mac, Apple's system files are not searched for it.

### Host checks, after the Ralph Wiggum audit of 5d596ed

- Changelog rule: a CVE counts as fixed only in an item that opens with a fix
  statement, places the exact CVE ID where that statement covers it, and has
  no word from a longer list that denies, limits or postpones a fix. Whole
  IDs only (CVE-2026-1096180 is not CVE-2026-109618). A bare mention leaves
  the decision to the version. PASS messages ask a person to confirm the
  quoted item. (Nine misleading phrases that passed before now give CHECK
  FAILED.)
- Renamed PHP: every file over 1 MB that starts like a program or library is
  searched, whatever its name or permissions; on Linux, every file loaded by
  a running program is checked. (A non-executable module with an unusual
  name was missed before.)
- A candidate file that cannot be opened, including one under a path longer
  than the system allows, counts as an incomplete search. (It was dropped
  silently before.)
- Linux: every control character is percent-encoded; php-cgi in cgi-bin is
  labelled cgi-fcgi; implausible version numbers give CHECK FAILED; package
  database files must be regular files.

### Host checks, faster content search

- The search for renamed PHP reads large files in batches with one `grep`
  per batch, instead of starting programs for each file, in both host
  checks. Results are unchanged; files `grep` cannot read now count as an
  incomplete search.
- macOS: new `--search DIR` option to check running PHP and one folder only.
  A limited search is labelled in the output, adds a CHECK FAILED line, and
  never exits with status 0.
- CI: the macOS job has time limits and records how long a full check takes
  on a real Mac.

### Host checks, after an external review

- Renamed PHP is found: programs and libraries over 1 MB, and every running
  program and loaded library, are searched for PHP's version text, whatever
  their name. (False PASS removed.)
- Changelog evidence needs an item that names the CVE **and** states a fix,
  with no wording that denies or postpones one; whole words only. A bare
  mention gives CHECK FAILED. (False PASS removed.)
- Every output field is percent-encoded, so file names cannot add columns or
  fake result lines.
- Only regular dpkg `.list` files are read; a symlinked one is ignored.
- Tests: adversarial cases added; the suite now passes with and without root
  (at that time 46 as root, 44 without; see [Testing](docs/testing.md) for current counts).

### Metasploit module (new)

- `metasploit/php2shell_banner.rb`: Metasploit auxiliary scanner that ports
  the nmap script's banner triage, with the same results and wording.
  Findings are stored as notes, never as vulnerabilities.
- Self-checking tests in `tests/msf-tests.sh` (now 22 tests), run with the
  official Metasploit Docker image.
- New guide: `docs/metasploit-guide.md`.

### macOS host check 1.0 (new)

- `php2shell-hostcheck-macos.sh`: checks PHP on a Mac (Homebrew, MacPorts,
  MAMP, XAMPP, Laravel Herd and any other copy on the start-up disk) and
  running PHP processes (through `lsof`). Works with the bash 3.2 that macOS
  includes. `--root` checks a mounted Mac disk.
- Self-checking tests in `tests/hostcheck-macos-tests.sh` (now 37 tests), passing
  under bash 5 and a real bash 3.2.57. Not yet run on a real Mac.
- New guide: `docs/macos-guide.md`.

### Host check 1.1 (after the fourth audit)

- Snap folders are found through the `/snap` link used on Fedora, Arch and
  openSUSE, so PHP inside those snaps is reported (false PASS removed).

### Host check 1.1 (after the third audit)

- An rpm database that rpm cannot open gives CHECK FAILED, not "unpackaged".
- Snap archives that are not mounted (as in offline images) are reported.
- A missing `/proc` is reported as such, not as a missing tool.
- The "no PHP found" PASS appears only when nothing else is unresolved.
- Package names in reason text no longer carry the multiarch suffix.

### Host check 1.1 (after the second audit)

- rpm: the image's own database location (`/var/lib/rpm` or
  `/usr/lib/sysimage/rpm`) is passed to rpm, because rpm's built-in default
  differs between builds. Found by testing with real rpm packages.
- Stops with a clear message if bash is older than 4 (exit 69) or if GNU
  `find`/`stat` are missing (CHECK FAILED), for example on BusyBox systems.
- Reports when running processes cannot be inspected (for example WSL 1).
- Windows drives under WSL and folders shared into virtual machines are not
  searched; every skipped mount is listed. The filesystem holding the start
  folder is always searched.
- A package whose version cannot be read gives CHECK FAILED, not PASS.
- A running program that cannot be located inside its chroot gives CHECK
  FAILED.
- No "nothing found" PASS when not run as root.
- Snap storage is reported only if it contains PHP.

### Network scan (after the second audit)

- Works again on nmap releases before 7.94 (`url.ascii_hostname` is used only
  where it exists).
- When there is no response, the target line says so instead of showing a
  made-up transport.

### Host check 1.1

- A file must match its owning package (version, and dpkg checksum where
  recorded) before a changelog can give PASS.
- With `--root`, and for containers, links are resolved inside the image or
  container root.
- An rpm database without the rpm tool gives CHECK FAILED, not
  "unpackaged".
- Search errors give CHECK FAILED; an incomplete search never gives "no PHP
  found".
- Finds `mod_php*.so` and other web-server modules that contain PHP.
- systemd service sandboxes are no longer labelled "container".
- Deleted modules still in memory are read through
  `/proc/<process ID>/map_files/`.
- PASS lines name the changelog file and quote the entry; changelog entries
  worded as "not fixed" give CHECK FAILED; the `php<branch>-common`
  changelog is used only at the same package version.
- More container, VM and snap storage is skipped and reported.
- `--root /` is refused.

### Network scan

- Records the transport actually used, and the `Host` header actually sent.
- Reports "no HTTP response" and partial versions (such as `PHP/8.2`)
  correctly.
- Licensed under Apache-2.0; author set.

### Repository

- Moved from `DrexxL/user-manuals` to `DrexxL/PHP2Shell-nse`; tools at the
  repository root.
- Plain-English README and documentation in `docs/`.
- Self-checking test suites in `tests/`.

### Host check 1.0

- First version: finds PHP runtimes in running processes and on disk, reads
  versions without running PHP, checks package changelogs, reports only
  PASS, FAIL or CHECK FAILED.

### Network scan, banner triage rework

- Results renamed to BANNER BELOW FIX, BANNER AT OR ABOVE FIX and CHECK
  FAILED; never "vulnerable" or "not vulnerable".
- Branches before 8.2 are not judged; pre-releases count as older than the
  release; every page is examined and conflicts fail the check; redirects
  are not followed; the phpinfo match is limited to the page heading;
  release date corrected to 21 October 2026.

### Network scan, first version

- Version-based check of the PHP banner against the fixed releases.
