# Changelog

All notable changes to this project. Dates are in UTC.

## 2026-11-04

### Metasploit module (new)

- `metasploit/php2shell_banner.rb`: Metasploit auxiliary scanner that ports
  the nmap script's banner triage, with the same results and wording.
  Findings are stored as notes, never as vulnerabilities.
- Self-checking tests in `tests/msf-tests.sh` (17 tests), run with the
  official Metasploit Docker image.
- New guide: `docs/metasploit-guide.md`.

### macOS host check 1.0 (new)

- `php2shell-hostcheck-macos.sh`: checks PHP on a Mac (Homebrew, MacPorts,
  MAMP, XAMPP, Laravel Herd and any other copy on the start-up disk) and
  running PHP processes (through `lsof`). Works with the bash 3.2 that macOS
  includes. `--root` checks a mounted Mac disk.
- Self-checking tests in `tests/hostcheck-macos-tests.sh` (28 tests), passing
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
