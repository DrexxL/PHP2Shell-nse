# Testing

The `tests/` folder has two test suites. Each one builds its own test cases,
runs a tool on them, and checks every result. Anyone can run them to
confirm that the tools behave as documented.

## Run the tests

1. Open a terminal in the repository folder.
2. Run the host check tests:

   ```bash
   sudo ./tests/hostcheck-tests.sh
   ```

3. Run the macOS host check tests (on a Mac or on Linux):

   ```bash
   sudo ./tests/hostcheck-macos-tests.sh
   ```

4. Run the network scan tests (needs nmap and python3):

   ```bash
   ./tests/nse-tests.sh
   ```

5. Check the last line of each run. It says how many tests passed and
   failed. The exit status is 0 only if all tests passed.

Run the host check tests as root to include the "unreadable folder" test.
Without root, that test is skipped and the run says so.

## What the host check tests do

`hostcheck-tests.sh` makes small fake disk images in a temporary folder and
deletes them at the end. A fake "PHP program" is a tiny file that starts
like a Linux program and contains a version string, for example
`X-Powered-By: PHP/8.2.10`. Fake package records imitate dpkg and apk.

| Area | Examples of what is tested |
|---|---|
| Version rules | Below the fix is FAIL; the fix and newer is PASS; RC and dev builds of the fix count as older; branches 8.1, 5.6 and 8.6 are CHECK FAILED. |
| Package records | A backport in the changelog gives PASS; a changelog without the CVEs gives FAIL; one CVE only, a missing changelog, or "NOT fixed" wording gives CHECK FAILED. |
| Tampering | A file whose version or checksum differs from its package is never PASS. |
| Image safety | Links inside an image stay inside it; a link pointing outside is not followed. |
| Other systems | Alpine packages and modules; an rpm image checked without the rpm tool; real rpm packages built with `rpmbuild` and installed into images with the database in `/var/lib/rpm` and in `/usr/lib/sysimage/rpm` (backport gives PASS, no fix gives FAIL, a mismatched file gives CHECK FAILED). The rpm package tests run only if `rpm` and `rpmbuild` are installed. |
| Whole run | Empty image gives PASS with exit 0; container storage is reported; any FAIL gives exit 1; `--root /` is refused; an unreadable folder, or a run without root, is never reported as "nothing found". |
| Package version | A package whose version cannot be read never gives PASS. |

## What the macOS host check tests do

`hostcheck-macos-tests.sh` makes fake Mac disks in a temporary folder. A
fake "PHP program" is a tiny file that starts like a Mac program (Mach-O)
and contains a version string. A fake `lsof` stands in for the running
processes. The suite runs on a Mac or on Linux.

| Area | Examples of what is tested |
|---|---|
| Homebrew | Below the fix gives FAIL with `brew upgrade` advice; the fix (also with a revision such as `8.4.27_1`) gives PASS; Apple-silicon and Intel locations; an Apache module is reported as `apache2handler`; a file whose version differs from its Homebrew folder gives CHECK FAILED; a Cellar folder with no install receipt is treated as unpackaged. |
| Other sources | MacPorts, MAMP, XAMPP (branch 8.1 gives CHECK FAILED), Laravel Herd in a folder name with spaces, unpackaged builds, a release candidate of the fix, branch 8.6. |
| Skipped places | `/System` and `/Volumes` are not searched; Docker Desktop storage is reported and its files are not judged; a shell script named `php` is ignored. |
| Running processes | A process whose file is unchanged is judged; a process whose file was replaced or deleted gives CHECK FAILED; non-PHP libraries are ignored; with no `lsof`, the check says processes were not inspected. |
| Whole run | Empty disk gives PASS with exit 0 (as root); exit codes 1, 2, 64 and 69; an unreadable folder gives CHECK FAILED with Full Disk Access advice, never "nothing found". |

### How old-bash support was tested without a Mac

macOS includes bash 3.2, which lacks some features of newer bash. The suite
was run twice on Linux: once with bash 5, and once with a real bash 3.2.57
taken from the official `bash:3.2` Docker image, the same bash version macOS
includes. Both runs passed all 28 tests. To repeat the 3.2 run:

```bash
PHP2SHELL_TEST_SHELL=/path/to/bash-3.2 /path/to/bash-3.2 tests/hostcheck-macos-tests.sh
```

Breaking the 8.3 rule on purpose made 3 macOS tests fail, as expected.

## What the network scan tests do

`nse-tests.sh` starts fake web servers on this computer only (127.0.0.1,
ports 19001 to 19011), scans them, and checks each result. No other
computer is contacted.

| Fake server reports | Expected result |
|---|---|
| `PHP/8.2.10` | BANNER BELOW FIX |
| `PHP/8.2.35RC1` | BANNER BELOW FIX (pre-release) |
| `PHP/8.1.30` | CHECK FAILED (unsupported branch) |
| `PHP/8.3.36` | BANNER AT OR ABOVE FIX, "not proof" |
| No version | CHECK FAILED, "were not verified" |
| 8.2.35 on `/`, 8.2.34 on `/app/` | CHECK FAILED (conflict) |
| phpinfo heading 8.4.20; "PHP Version 8.2.1" in ordinary text | BANNER BELOW FIX from the heading; the ordinary text is ignored |
| A redirect | Recorded, not followed |
| `PHP/8.2.20-1+deb12u3` | CHECK FAILED (distribution build) |
| `PHP/8.2` | CHECK FAILED (partial version) |
| `PHP/8.6.0` | CHECK FAILED (newer branch) |
| `PHP/8.2.10`, with nmap made to behave like a release before 7.94 (`tests/old_nmap_helper.nse`) | BANNER BELOW FIX: the script still runs |

## Making sure the tests can fail

A test that can never fail proves nothing. Both suites were checked by
breaking a tool on purpose (changing the 8.2 fixed version to 8.2.5) and
running the suite again. The host check suite then reported 4 failures and
the network scan suite 6 failures, as expected.

## Other testing done during development

These were tested by hand, because they need a live system:

- The real Ubuntu PHP 8.3.6 package with a backported fix gave PASS from the
  host check, while the network scan of the same PHP gave BANNER BELOW FIX.
  This is the intended difference between the two tools.
- A running PHP program whose file was deleted gave CHECK FAILED with
  "restart the service".
- A deleted PHP module still loaded in memory was read through
  `/proc/<process ID>/map_files/`.
- A PHP process in a separate mount namespace with the host's root folder
  (as systemd sandboxing creates) was treated as part of the host.
- HTTPS scanning by name recorded the SNI name sent.
- With BusyBox `find` in place of GNU `find`, the check stopped with a
  CHECK FAILED line naming the missing tool. Run with `sh` instead of bash,
  it stopped with exit status 69.
- A first rpm test found a real bug: rpm's built-in database location
  differs between builds, so an image's database could be missed. The check
  now finds the image's own database and passes its location to rpm.
- An independent compliance audit re-ran these cases and others.

## Not yet tested

- The rpm code path on a real Red Hat or SUSE server, and the older Berkeley
  DB format used by Red Hat 7 and 8.
- Windows WSL 2 and WSL 1.
- The macOS host check on a real Mac: macOS's own `find`, `lsof`, `od` and
  `grep`, and reading the version from real Mac PHP programs.
- nmap versions other than 7.94. Older releases are imitated by
  `tests/old_nmap_helper.nse`, and every nmap function the script uses was
  checked against the nmap 7.80 source code.
