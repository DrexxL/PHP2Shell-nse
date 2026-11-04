# Notes for auditors and investigators

This page is for people who must defend a result: auditors, lawyers,
digital-forensics examiners and policy staff. It explains what evidence
each result rests on, what the tools do and do not prove, and how to keep a
clean record.

## What each result proves

| Tool and result | Evidence it rests on | What it proves | What it does not prove |
|---|---|---|---|
| Host check, PASS (changelog) | An item in the installed package's changelog names each CVE and states a fix ("security update", "fix", "patch", "backport" or "resolves", as whole words), with no wording that denies or postpones one; the file's version, and on Debian/Ubuntu its checksum where the package recorded one, match the package record. | The package maker states the fix is included in this package, and the file is that package's file. | That the fix works, or that no other copy of PHP exists outside the searched filesystems. |
| Host check, PASS (version) | The version stored inside the file is at or after the fixed release. | The file reports a fixed upstream version. | That the version string was not altered by someone who built the file. |
| Host check, FAIL | The version is in the affected range, and no changelog entry or package record shows a fix. | No remediation record exists for this file. | That an attacker can exploit it. Exploitability also depends on configuration. |
| macOS host check, PASS | The version stored inside the file is at or after the fixed release; for Homebrew, the file's version matches its Homebrew folder, which has an install receipt. | The file reports a fixed upstream version. | That the version string was not altered by whoever built the file. |
| macOS host check, FAIL | The version is in the affected range; the Mac holds no changelog of fixes. | No remediation record exists on the Mac. | That an attacker can exploit it. |
| Host check, CHECK FAILED | The evidence needed for PASS or FAIL was missing or contradictory. | Only that the check could not decide. | Anything about the bug. |
| Network scan, any BANNER result | A version string in a web response. | That the server *reported* that string. | Anything about the real PHP version or its fixes. |

Do not record a network scan result as a compliance finding. Use it to
choose which servers to examine with the host check.

## The rule set and its date

Both tools contain a fixed, dated rule set:

| Item | Value |
|---|---|
| Rule set date | 2026-11-04 |
| CVEs covered | CVE-2026-109618, CVE-2026-109619 |
| Fixed releases | 8.2.35, 8.3.36, 8.4.27, 8.5.12 (PHP security releases of 21 October 2026) |
| Branches judged | 8.2 to 8.5 |
| Branches not judged | 8.1 and older (disputed); 8.6 and newer (not yet covered) |
| Not covered | CVE-2026-115560 |

Each result line or block prints this date. A result is only as current as
its rule set. If a later advisory changes the fixed versions, update the
rules (see [Updating the rules](updating-the-rules.md)) and re-run.

### Sources and where they disagree

The fixed versions and the release date agree across the sources consulted,
including the AWS security bulletin, the Canadian Centre for Cyber
Security alert AL26-026 and the PHP 8.4.27 release notes. CISA's Known
Exploited Vulnerabilities catalog lists both CVEs; secondary sources date
their addition to 26 October 2026. Confirm that date in the catalog itself
before you quote it.

Sources disagree on whether branches older than 8.2 are affected. Abstract
Security and watchTowr say affected releases go back to PHP 5. Brandefense
notes that the advisories do not say. A reviewer reported that the official
CVE record lists only 8.2 to 8.5 as affected. The tools therefore report
those branches as CHECK FAILED and never as PASS or FAIL.

## Keeping a clean record

### The record cannot be forged by file names

Both host checks percent-encode every output field (`%25`, `%7C`, `%0D`,
`%0A`), so a crafted file name inside an image cannot add columns or fake
result lines. The header line says so. Decode with any URL decoder (see the
[host check guide](host-check-guide.md#read-the-output)).

### Record what you ran

Before a check, record the exact tool files used:

```bash
sha256sum php2shell-hostcheck.sh php2shell-detect.nse > tool-hashes.txt
```

Each output also names the tool version, the rule-set date, the computer
and the time (UTC). Keep the full output, not a summary.

### Examining evidence without changing it

The host check never runs a PHP program and never changes the files it
examines. It writes exactly one small temporary file (made with `mktemp`,
normally in `/tmp`) to collect search errors, and deletes it on exit. On a
live check, that file is on the system being examined. With `--root`,
nothing is written inside the image.

For a disk image:

1. Work on a copy, not the original.
2. Mount it read-only:

   ```bash
   sudo mount -o ro,noload,loop evidence.img /mnt/evidence
   ```

3. Run the check with `--root /mnt/evidence`.
4. Keep the output with your case notes.

Two behaviours protect the image's integrity:

- **Links stay inside the image.** Package records are read only from
  regular files: a symlinked dpkg `.list` file is ignored.
- **Links in documentation folders stay inside the image too.** A link such as
  `/usr/share/doc/x -> /usr/share/doc/y` is resolved inside
  `/mnt/evidence`, so the checking computer's own files are not read in
  place of the image's.
- **Incomplete searches are reported.** If any folder cannot be read, the
  result is CHECK FAILED. The tool never reports "no PHP found" after a
  partial search.

### Live systems

On a live system, the act of checking is itself an event. Note that:

- Reading `/proc` and running `find` over the disk changes file access times
  on filesystems that record them.
- The tool reads running programs through `/proc/<process ID>/exe` and,
  for deleted modules still in memory, `/proc/<process ID>/map_files/`.
  This needs root.
- Processes in a separate mount namespace are labelled "container" only if
  their root folder differs from the host's. systemd service sandboxes are
  treated as part of the host.

## Signs that deserve a closer look

Some CHECK FAILED results can point to tampering, not just missing data:

| Message contains | Why it matters |
|---|---|
| "the file is not the packaged one" | A PHP file differs from what its package installed. Someone or something replaced it. |
| "checksum differs" | The file's contents changed after installation. |
| "replaced or deleted on disk" | A running program no longer matches any file on disk. This is normal after an update without a restart, but it is also a known way to hide a program. |
| "No PHP version string found" | A file with a PHP-like name has no PHP version inside. |

If PHP2Shell was exploited before a fix was installed, patching closes the
hole but does not remove an intruder. On affected servers, also look for
unexpected `.php` files in web folders and for web-server processes that
start shells.

## How the tools were tested

See [Testing](testing.md). The test suites in `tests/` rebuild every test
case from scratch and check every result, so anyone can repeat the tests.
