# PHP2Shell checks

Two tools for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell). Both work
offline, and both use a rule set dated 2026-11-04: fixed in 8.2.35, 8.3.36,
8.4.27 and 8.5.12. Neither covers CVE-2026-115560.

| Tool | Runs from | Answers | Results |
|---|---|---|---|
| `php2shell-detect.nse` | A scanning workstation | Which web services *claim* a vulnerable PHP version | BANNER BELOW FIX, BANNER AT OR ABOVE FIX, CHECK FAILED |
| `php2shell-hostcheck.sh` | Each host, as root | Whether each PHP runtime on the host is fixed | PASS, FAIL, CHECK FAILED |

Use the scan to decide where to look first. Use the host check for the
record. A web banner can be forged, stale, or wrong about distribution
backports, so the scan never reports a service as safe or vulnerable.

## Host check

```bash
sudo ./php2shell-hostcheck.sh              # live host, including running processes
sudo ./php2shell-hostcheck.sh --root /mnt/disk   # mounted disk or extracted image
```

It never executes a PHP binary. It reads the version from each file's
bytes (and from `/proc/<pid>/exe` for running processes), identifies the
SAPI, finds the owning package (dpkg, rpm or apk), and looks for both CVE
IDs in the installed package's changelog.

- **PASS**: the changelog records both fixes, or the upstream version is at
  or after the fix.
- **FAIL**: the version is in the affected range, and there is no record of a
  fix: no changelog entry, or the build is unpackaged.
- **CHECK FAILED**: the evidence could not be read. Each line states why and
  what to do next. Causes include an unsupported branch (before 8.2), an
  unreadable changelog, a binary deleted or replaced under a running process,
  container storage, or not running as root.

Exit status: 0 all PASS, 1 any FAIL, 2 otherwise any CHECK FAILED.

## Network scan

```bash
nmap -sV -p 80,443,8080,8443 --script ./php2shell-detect.nse 10.0.0.0/24
```

See the script header for its arguments (`paths`, `probe-info`, `vhost`).
