# Results reference

This page lists every message the two tools can print, what it means and
what to do. Parts in `<angle brackets>` are filled in with real values.

## Host check (`php2shell-hostcheck.sh`)

### PASS

| Message | What it means | What to do |
|---|---|---|
| The changelog (`<file>`) records both CVE-2026-109618 and CVE-2026-109619, e.g. "`<quote>`". | The package's change history says both bugs are fixed. The file matches its package. | Keep the output as your record. Read the quoted entry if you want to confirm it. |
| Upstream version is at or after the fixed release `<version>`. | The version stored in the file is the fixed one or newer. | Keep the output as your record. |
| Running image (file since replaced or deleted on disk) is at or after `<version>`. | The program in memory is fixed, even though its file has changed since it started. | Restart the service when convenient, then re-run the check. |
| No PHP binary, module or process found on the inspected filesystems. | The search ran as root, had no errors, found no PHP, and left nothing unresolved (this line never appears together with a CHECK FAILED line). | Keep the output as your record. Skipped filesystems are listed as `# not searched` lines, and containers in storage are listed separately. |

### FAIL

| Message | What it means | What to do |
|---|---|---|
| Version precedes `<fix>` and the changelog (`<file>`) has no record of either CVE. Update the package. | The package is older than the fix, and its change history does not mention a backport. | Update the package. Restart PHP-FPM or the web server. Run the check again. |
| Unpackaged build, version precedes `<fix>`, and no package record of a fix exists. If it was patched by hand, document that; otherwise rebuild or upgrade. | The file was not installed by a package manager (it was built or copied by hand), and its version is older than the fix. | Rebuild or replace it with a fixed version. If someone applied the fix by hand, write down who, when and how. |

### CHECK FAILED

| Message | What it means | What to do |
|---|---|---|
| No PHP version string found in the file. Inspect it manually. | The file looks like PHP but has no readable version. | Look at the file by hand. Find out which package or person put it there. |
| The process uses a file that has since been replaced or deleted on disk, so no package record describes it. Restart the service and re-run. | A running program's file has been updated or removed since it started. The old copy is still running. | Restart the service. Run the check again. |
| An rpm database is present but the rpm tool is not installed here, so package ownership cannot be read. Run the check on a system with rpm. | You are checking a Red Hat-style image from a computer without `rpm`. | Run the check on a computer that has `rpm`. |
| The file reports PHP `<version>` but its owning package is version `<package version>`, so the file is not the packaged one. Find out who replaced it. | The file and the package record disagree. Someone may have copied another PHP over the packaged one. | Find out who changed the file and why. Reinstall the package. |
| The file's checksum differs from the one recorded for package `<package>`, so the file is not the packaged one. Find out who changed it. | The file's contents changed after the package installed it. | Treat this as a possible sign of tampering. Investigate, then reinstall the package. |
| The changelog (`<file>`) mentions the CVEs in wording that may not mean a fix: "`<quote>`". Read the entry. | The change history names the CVEs, but with words such as "not fixed". | Read the quoted entry. Check the distribution's security notice. |
| Branch `<branch>` is outside the vendor advisory (8.2 to 8.5); sources disagree on whether it is affected, and no fix is recorded. Upgrade to a supported fixed release. | The version is 8.1 or older. Nobody can say for sure whether it has these bugs. | Upgrade to a supported, fixed PHP version. |
| Branch `<branch>` is newer than this rule set (`<date>`). Check for a later advisory. | The version is newer than any branch the rules know about. | Check PHP's security notices. See [Updating the rules](updating-the-rules.md). |
| Version precedes `<fix>` and the changelog (`<file>`) records only `<CVE>`. Check the vendor advisory for the other CVE. | Only one of the two bugs is listed as fixed. | Check the distribution's security notice for the other CVE. |
| Version precedes `<fix>`. Alpine keeps no package changelog on the system, so a backported fix cannot be ruled out locally. Check the Alpine security database for `<package version>`, or upgrade. | Alpine does not store change histories on the computer. | Check Alpine's security database, or upgrade the package. |
| Version precedes `<fix>` and the package changelog could not be read (documentation may be excluded). Check the vendor security notice for `<package version>`. | The change history is missing. Small or "minimal" images often leave it out. | Check the distribution's security notice for that package version, or upgrade. |
| Not run as root: some processes or files may not have been inspected. Re-run as root. | The check ran as a normal user. | Run it again with `sudo`. |
| Required tools are missing or too limited: `<tools>`. Install GNU findutils and coreutils (on Alpine: apk add bash findutils coreutils grep gawk) and re-run. | A tool the check needs is missing, or is a cut-down version such as BusyBox. Nothing was checked. | Install the named tools and run again. |
| Running processes could not be inspected: /proc gives no mount-namespace information (as expected under WSL 1). Only files on disk were checked. | Running programs could not be examined. | Run on a full Linux system, such as WSL 2. |
| /proc is not mounted or not readable, so neither processes nor filesystems can be checked reliably. Mount /proc and re-run. | Linux's `/proc` system folder is missing. Nothing was checked. | Mount `/proc` and run again. |
| An rpm database is present (`<folder>`) but rpm could not open it (damaged, or a format this rpm cannot read), so package ownership cannot be read. Run the check with an rpm that matches the system. | The rpm database is damaged, or was made by a different rpm version. | Run the check with the system's own rpm, or one of the same version. |
| `<count>` snap package(s) are not mounted, so their contents (which may include PHP) were not inspected: `<names>`. Check on the running system, or unpack each snap and use --root. | Snap packages exist only as unopened archives, as in an offline disk image. | Check the running system, or unpack each snap and check it with `--root`. |
| The file cannot be found inside the process's root folder (for example, the program runs in a chroot), so its package record cannot be read. Run the checker inside that environment. | A running program's file could not be located inside its container or chroot. | Run the check inside that environment. |
| The file belongs to package `<package>`, but the package's version could not be read, so the file cannot be matched to it. Check the package database. | The package database is damaged or incomplete. | Check the package database by hand. |
| Snap packages that contain PHP are not inspected. Check each snap's PHP with its publisher's security notices, or upgrade the snap. | A snap package includes PHP. The line names `/snap`, or `/var/lib/snapd/snap` on systems where `/snap` is a link to it (Fedora, Arch, openSUSE). Snaps have no package record the check can read. | Check the snap's publisher, or upgrade the snap. |
| Container or VM storage is not inspected. Run this checker inside each container, or with --root against each extracted image. | Storage for containers or virtual machines was found but not opened. | Check each container or image separately. |
| Rootless container storage is not inspected. Run this checker inside each container. | A user's private container storage was found but not opened. | Check those containers separately. |
| The filesystem walk was incomplete: `<count>` error(s), first: `<error>`. Fix access and re-run. | Some folders could not be read, so PHP could be hiding there. | Fix the access problem (usually: run as root). Run the check again. |

## Network scan (`php2shell-detect.nse`)

### BANNER BELOW FIX

| Message | What it means | What to do |
|---|---|---|
| Disclosed PHP `<version>` precedes the fixed release `<fix>`. Some distribution builds show the bare upstream number even with the fix backported. | The server says it runs an older version. It may still have a backported fix. | Run the host check on that server. |
| Disclosed PHP `<version>` is a pre-release of `<version>` or earlier, which precedes the fix. | The server says it runs a test version (RC, alpha, beta or dev) made before the fix. | Run the host check. Replace test versions with a fixed release. |

### BANNER AT OR ABOVE FIX

| Message | What it means | What to do |
|---|---|---|
| Disclosed PHP `<version>` is at or after the fixed release `<fix>`. A banner can be set or stale, so this is not proof that the service is patched. | The server says it runs a fixed version. | Confirm with the host check before you record it as fixed. |

### CHECK FAILED

| Message | What it means | What to do |
|---|---|---|
| No PHP version was disclosed (expose_php may be Off, PHP may be absent, or a proxy may hide it). The active PHP runtime and package patch state were not verified. | The server shows no PHP version. | Run the host check. A hidden banner proves nothing. |
| Only a partial PHP version was disclosed (`<version>`), which cannot be compared with a fixed release. | The banner says, for example, `PHP/8.2`, without the last number. | Run the host check. |
| Conflicting PHP versions were disclosed: `<versions>`. Different paths may be served by different back ends. | Different pages report different versions. | Run the host check on each back-end server. |
| No HTTP response was received on any requested path. | The port is open but sent no web page. | Check the service by hand, or on the server. |
| Disclosed PHP `<version>` is on unsupported branch `<branch>`. The vendor advisory covers 8.2 to 8.5 only; whether older branches are affected is disputed between sources. | The server says it runs 8.1 or older. | Upgrade to a supported, fixed release, or isolate the service. |
| Disclosed PHP `<version>` is on branch `<branch>`, which is newer than the advisory's scope. | The server says it runs a branch newer than 8.5. | Check for a later advisory. |
| Disclosed PHP `<version>` is a distribution build numbered below `<fix>`. Distributions backport fixes without changing the upstream number, so the banner cannot decide it. | The banner has a distribution suffix such as `-1+deb12u3`. | Run the host check, which reads the package's change history. |
