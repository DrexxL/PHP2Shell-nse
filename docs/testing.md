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

3. Run the network scan tests (needs nmap and python3):

   ```bash
   ./tests/nse-tests.sh
   ```

4. Check the last line of each run. It says how many tests passed and
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
| Other systems | Alpine packages and modules; an rpm image checked without the rpm tool. |
| Whole run | Empty image gives PASS with exit 0; container storage is reported; any FAIL gives exit 1; `--root /` is refused; an unreadable folder is never reported as "nothing found". |

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

## Making sure the tests can fail

A test that can never fail proves nothing. Both suites were checked by
breaking a tool on purpose (changing the 8.2 fixed version to 8.2.5) and
running the suite again. The host check suite then reported 4 failures and
the network scan suite 5 failures, as expected.

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
- An independent compliance audit re-ran these cases and others.

## Not yet tested

- The rpm code path on a real Red Hat or SUSE system.
- nmap versions other than 7.94.
