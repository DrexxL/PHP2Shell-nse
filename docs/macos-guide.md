# macOS host check guide

`php2shell-hostcheck-macos.sh` checks whether the PHP on a Mac is fixed for
PHP2Shell. It is the Mac version of the Linux host check. Both give the same
three results: PASS, FAIL and CHECK FAILED.

**Example:** a web developer's MacBook has PHP 8.3.20 from Homebrew and PHP
8.4.27 inside Laravel Herd. The check reports FAIL for the Homebrew copy
(older than the fix, 8.3.36) and PASS for the Herd copy.

## Before you start

| Need | Why |
|---|---|
| macOS | The script uses the tools macOS includes. |
| The bash that macOS includes (`/bin/bash`, version 3.2) or a newer bash | The script is written for bash 3.2. You do not need to install anything. |
| Administrator access (`sudo`) | Without it, some processes and files stay hidden. |
| Full Disk Access for your terminal app | macOS hides some folders even from administrators. Without it, the check reports CHECK FAILED. |

**Give your terminal app Full Disk Access:**

1. Open **System Settings**.
2. Go to **Privacy & Security → Full Disk Access**.
3. Turn on the switch for your terminal app (for example **Terminal** or
   **iTerm**). If the app is not in the list, click **+** and add it from
   **Applications → Utilities**.
4. Quit the terminal app and open it again.

You can turn the switch off again after the check.

## Check this Mac

1. Download `php2shell-hostcheck-macos.sh` from this repository.
2. Open Terminal and go to the folder that contains it:

   ```bash
   cd ~/Downloads
   ```

3. Make the file executable:

   ```bash
   chmod +x php2shell-hostcheck-macos.sh
   ```

4. Run the check:

   ```bash
   sudo ./php2shell-hostcheck-macos.sh
   ```

5. Type your Mac password when asked. The password does not show as you
   type.
6. Wait for the summary line. A full disk search can take several minutes,
   or longer on a Mac with Xcode, because every program and library larger
   than 1 MB is also searched for renamed PHP.
7. Save the output for your records:

   ```bash
   sudo ./php2shell-hostcheck-macos.sh | tee "php2shell-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ).txt"
   ```

Run the script from Terminal as shown. Do not double-click it in Finder.
If `./php2shell-hostcheck-macos.sh` gives "permission denied", run it with
`bash` instead: `sudo bash php2shell-hostcheck-macos.sh`.

## Check only one folder

A full check reads every large program on the disk, which can take a long
time on a Mac with Xcode or other big apps installed. To check running PHP
and one folder only, use `--search`:

```bash
sudo ./php2shell-hostcheck-macos.sh --search /opt/homebrew
```

The output then says `# search limited to /opt/homebrew`, and adds a CHECK
FAILED line saying that the rest of the Mac was not searched. So a limited
search is never reported as a full pass: its exit status is never 0. Use a
full check, without `--search`, for your records.

You cannot use `--search` together with `--root`, or with `/`.

## Check a Mac disk that is not running

Use this for a forensic image or a disk from another Mac. No processes are
examined in this mode.

1. Attach or mount the disk **read-only**. For a disk image:

   ```bash
   hdiutil attach -readonly -nobrowse evidence.dmg
   ```

2. Find its data volume. It is usually named like `Macintosh HD - Data`:

   ```bash
   ls /Volumes
   ```

3. Run the check with `--root` and that folder:

   ```bash
   sudo ./php2shell-hostcheck-macos.sh --root "/Volumes/Macintosh HD - Data"
   ```

## How it decides

The check finds every PHP program and PHP web-server module on the Mac,
reads the version stored inside each file (it never runs PHP), and compares
it with the fixed version for its branch.

On Linux, a distribution can copy a fix into an older version (a backport)
and write that in a changelog the Linux check reads. On a Mac, Homebrew,
MacPorts and app bundles record **which version** is installed, but the Mac
holds no changelog of CVE fixes. So on a Mac:

- **PASS** means the version is the fixed one or newer.
- **FAIL** means the version is older than the fix, and nothing on the Mac
  records a fix. This is the same rule the Linux check uses for unpackaged
  builds.
- **CHECK FAILED** means the check could not decide. The line says why.

| Version found | Branch | Fixed version | Result |
|---|---|---|---|
| 8.3.20 | 8.3 | 8.3.36 | FAIL |
| 8.4.27 | 8.4 | 8.4.27 | PASS |
| 8.2.35RC1 | 8.2 | 8.2.35 | FAIL (a test version made before the fix) |
| 8.1.30 | 8.1 | none | CHECK FAILED (branch outside PHP's warning) |
| 8.6.0 | 8.6 | none | CHECK FAILED (branch newer than the rules) |

## Where it looks

The check searches the whole start-up disk. It recognises where each copy of
PHP came from, so it can give the right advice:

| Source | Typical location | Advice on FAIL |
|---|---|---|
| Homebrew (Apple silicon) | `/opt/homebrew/Cellar/php@8.3/8.3.20/` | `brew upgrade php@8.3` |
| Homebrew (Intel Mac) | `/usr/local/Cellar/php/8.4.20/` | `brew upgrade php` |
| MacPorts | `/opt/local/` | `sudo port upgrade` with the package name |
| MAMP or MAMP PRO | `/Applications/MAMP/` | Update MAMP, or switch it to a fixed PHP |
| XAMPP | `/Applications/XAMPP/` | Update XAMPP |
| Laravel Herd | `~/Library/Application Support/Herd/` | Update Herd, or switch it to a fixed PHP |
| Other app bundles | `*.app/Contents/...` | Update the app |
| Anything else | Anywhere on the disk | Rebuild or upgrade it (reported as an unpackaged build) |

The locations in this table are the usual ones. A copy of PHP in any other
place is still found, and so is a renamed copy, because every PHP build
carries its version text inside. It is then reported as an unpackaged build.
The output is percent-encoded in the same way as the Linux check's (see the
[host check guide](host-check-guide.md#read-the-output)).

For Homebrew, the check also makes sure the file belongs to its package: the
version inside the file must match the version of its Homebrew folder, and
the folder must have Homebrew's install receipt. **Example:** a file inside
`Cellar/php@8.3/8.3.36/` that reports 8.3.6 gives CHECK FAILED ("not the
packaged one").

### What it skips

- `/System`: Apple's sealed, read-only system volume. Folders you install
  into, such as `/Applications`, `/opt`, `/usr/local` and `/Users`, are
  searched.
- `/Volumes`: other disks. To check one, use `--root`.
- Network drives (NFS, SMB, AFP, WebDAV).
- Storage of Linux virtual machines used for containers: Docker Desktop,
  Colima, OrbStack, Lima and Podman. If these exist, the check lists them as
  CHECK FAILED. PHP inside a container runs on Linux: run the Linux host
  check, `php2shell-hostcheck.sh`, inside each container.

### Running PHP

The check asks `lsof` which programs are running and which libraries they
have loaded. This is expected to find PHP-FPM, PHP's built-in web server,
and PHP loaded into Apache (not yet tested on a real Mac). If a running program's file has been replaced by a new file, or deleted,
since it started, the check reports CHECK FAILED and asks you to restart the
service. macOS does not let the check read the running copy itself.

**Limit:** if the file was overwritten in place (so it keeps the same file
number, or "inode"), the check cannot tell. It then judges the new file on
disk, while the old program may still be running. After any PHP update,
restart PHP and the web server before you check.

## After a FAIL

1. Update PHP with the command in the result line. **Example:**

   ```bash
   brew upgrade php@8.3
   ```

2. Restart PHP and the web server. **Example** for Homebrew services:

   ```bash
   brew services restart php@8.3
   ```

3. Run the check again.

## Exit status

The exit status is the same as the Linux check: 0 = all PASS, 1 = at least one
FAIL, 2 = no FAIL but at least one CHECK FAILED, 64 = wrong options (including
`--search` with `--root` or with `/`), 69 = not run with bash, 70 = a
temporary folder could not be created.

## Limits

- **Not yet run on a real Mac.** The script was written for macOS and tested
  on Linux, with a real bash 3.2.57 (the version macOS includes) and with
  fake Mac disks and a fake `lsof`. Its use of macOS's own `find`, `lsof`,
  `od` and `grep` is based on their documented behaviour, not yet on a test
  run. Check the first results by hand.
- **Version reading in real Mac programs is not yet tested.** PHP's source
  code puts the text `X-Powered-By: PHP/<version>` into every build, and the
  Linux check reads it that way from Linux programs. The same is expected for
  Mac programs, but no real Mac program has been tested yet. If the check
  reports "No PHP version string found" for a real PHP, please report it.
- **A changelog is not available on a Mac.** A Mac package that includes a
  backported fix without changing its version would be reported as FAIL.
- **Apple's own PHP.** macOS 12 (Monterey) and later do not include PHP.
  Older macOS versions included an Apple-built PHP 5 or PHP 7, which the
  check reports as CHECK FAILED (branch outside PHP's warning).
- The check covers CVE-2026-109618 and CVE-2026-109619 only.
