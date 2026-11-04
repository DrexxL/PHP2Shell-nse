# Changelog

All notable changes to this project. Dates are in UTC.

## 2026-11-04

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
