# Host check guide

`php2shell-hostcheck.sh` checks whether the PHP on one server is fixed for
PHP2Shell. Use its results for your records. To learn how it decides, read
[How the tools work](how-it-works.md).

## What you need

| Need | Why |
|---|---|
| A Linux server | The tool reads Linux process and package information. |
| Bash 4 or newer | Standard on current Linux distributions. |
| Root access | Without root, some processes and files stay hidden. |
| GNU tools: `find`, `grep`, `awk`, `sed`, `zcat`, `md5sum`, `stat`, `od`, `readlink`, `mktemp` | Present on almost every Linux system. The BusyBox versions in small images lack some options. |
| `rpm` (Red Hat, SUSE and similar only) | Needed to read rpm package records. |

You do **not** need internet access, PHP knowledge or extra software. If a
tool is missing, the check stops with a CHECK FAILED line that names it.

## Supported systems

| System | Status |
|---|---|
| Debian, Ubuntu and other dpkg systems | Supported. Tested live on Ubuntu 24.04 and with test images. |
| Red Hat, Rocky, AlmaLinux, Fedora, SUSE (rpm) | Supported. Tested with real rpm packages and rpm 4.18 databases in `/var/lib/rpm` and `/usr/lib/sysimage/rpm`. Not yet run on a real Red Hat or SUSE server, or on the older Red Hat 7 and 8 database format. |
| Alpine (apk) | Supported, if bash and the GNU tools are installed: `apk add bash findutils coreutils grep gawk`. Tested with test images. |
| Containers | Running containers are checked from the host. Inside a container, the same rules apply as for its distribution. |
| Windows WSL 2 | Expected to work: WSL 2 runs a real Linux kernel. Checks the PHP inside the WSL Linux system only. Windows drives are not searched. Not yet tested. |
| Windows WSL 1 | Expected: files only. WSL 1 is expected not to provide the process information the check needs; the check then reports a CHECK FAILED line and checks only files on disk. Not yet tested. |
| macOS | Use the separate macOS host check, `php2shell-hostcheck-macos.sh`. See the [macOS guide](macos-guide.md). |
| Windows itself, BSD | Not supported. The check needs Linux's `/proc` and bash 4. Use `--root` from a Linux computer to check a mounted Linux disk instead. |

**Example (Alpine container):**

```bash
apk add bash findutils coreutils grep gawk
./php2shell-hostcheck.sh
```

## Check a running server

1. Copy `php2shell-hostcheck.sh` to the server.
2. Make the file executable:

   ```bash
   chmod +x php2shell-hostcheck.sh
   ```

3. Run the check as root:

   ```bash
   sudo ./php2shell-hostcheck.sh
   ```

4. Wait for the summary line. A full disk search can take a few minutes,
   because large programs and libraries are also searched for renamed PHP.
5. Save the output for your records:

   ```bash
   sudo ./php2shell-hostcheck.sh | tee "php2shell-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ).txt"
   ```

## Check a disk or an image that is not running

Use this for a forensic disk image, a backup, or an extracted container
image. No processes are examined in this mode.

1. Mount the disk **read-only**, or extract the image into a folder.

   ```bash
   sudo mount -o ro,noload /dev/sdb1 /mnt/evidence     # ext4 example
   ```

2. Run the check with `--root` and the folder:

   ```bash
   sudo ./php2shell-hostcheck.sh --root /mnt/evidence
   ```

3. Read the results as usual. The host field shows `image:/mnt/evidence`.

Inside the image, links are followed only inside the image. A link such as
`/usr/share/doc/php8.3-cli -> /usr/share/doc/php8.3-common` is resolved
against `/mnt/evidence`, never against the checking computer's own files.

Do not use `--root /`. To check the computer you are on, use no options.

## Check containers

- **Running containers** are checked automatically. Their PHP processes are
  found, and their files and package records are read through the
  container's own root folder. Their lines say
  `(container, root /proc/<process ID>/root)`.
- **Stopped containers and images** are not opened. The storage folders
  (for example `/var/lib/docker`) are listed as CHECK FAILED. To check
  them, extract each image and use `--root`:

  ```bash
  mkdir /tmp/img && docker export "$(docker create my-image)" | tar -x -C /tmp/img
  sudo ./php2shell-hostcheck.sh --root /tmp/img
  ```

## Read the output

The output has three parts:

```
# php2shell-hostcheck 1.1 | rules 2026-11-04 | CVE-2026-109618 and CVE-2026-109619 | CVE-2026-115560 not covered
# host web01 | checked 2026-11-04T06:32:04Z | fields are percent-encoded (%25 %7C %0D %0A)
host|result|sapi|path|seen|php_version|package|reason
web01|PASS|cli|/usr/bin/php8.3|pid201,installed|8.3.6|dpkg:php8.3-cli 8.3.6-0ubuntu0.24.04.13|The changelog (/usr/share/doc/php8.3-common/changelog.Debian.gz) records a fix for both CVE-2026-109618 and CVE-2026-109619: "SECURITY UPDATE: Remote RCE via state corruption issue ... - CVE-2026-109618". Confirm the quoted item.
# summary: 1 PASS, 0 FAIL, 0 CHECK FAILED
```

1. **Header lines** start with `#`. They name the tool version, the date of
   its rules, the computer and the time of the check (in UTC).
2. **Result lines** have eight fields, separated by `|`:

   | Field | Meaning | Example |
   |---|---|---|
   | host | The computer's name, or `image:<folder>` | `web01` |
   | result | PASS, FAIL or CHECK FAILED | `PASS` |
   | sapi | How PHP connects to the web server | `fpm-fcgi` |
   | path | The file that was checked | `/usr/sbin/php-fpm8.4` |
   | seen | Where it was found: process IDs and/or `installed` | `pid812,pid813,installed` |
   | php_version | The version stored inside the file | `8.4.20` |
   | package | Package manager, package name and version | `dpkg:php8.4-fpm 8.4.20-1` |
   | reason | Why this result was given, and what to do | |

3. **The summary line** counts each result.

**Special characters are encoded.** A file name could contain `|` or a line
break, which would otherwise add columns or fake result lines. So every field
is percent-encoded: `%` becomes `%25`, `|` becomes `%7C`, a carriage return
becomes `%0D` and a line break becomes `%0A`. **Example:** a file named
`/opt/x|y/php` appears as `/opt/x%7Cy/php`. To decode a saved output file:

```bash
python3 -c "import sys,urllib.parse; [print(urllib.parse.unquote(l), end='') for l in sys.stdin]" < php2shell-web01.txt
```

The `sapi` field can be:

| Value | What it is |
|---|---|
| `cli` | The command-line `php` program |
| `fpm-fcgi` | PHP-FPM, a separate PHP service that the web server talks to |
| `cgi-fcgi` | `php-cgi`, started by the web server for each request |
| `apache2handler` | PHP loaded inside Apache as a module (`libphp*.so` or `mod_php*.so`) |
| `phpdbg` | PHP's debugger |
| `unknown` | A file that carries PHP's version text but has an unusual name, such as a renamed PHP binary |

## Exit status

Scripts and monitoring tools can use the exit status:

| Exit status | Meaning |
|---|---|
| 0 | Every line is PASS. |
| 1 | At least one FAIL. |
| 2 | No FAIL, but at least one CHECK FAILED. |
| 64 | The command-line options were wrong. |
| 69 | The shell is not bash 4 or newer. |
| 70 | A temporary file could not be created. |

**Example:** run the check from a scheduler and alert on anything but 0:

```bash
sudo ./php2shell-hostcheck.sh > /var/log/php2shell.txt || echo "PHP2Shell check needs attention" | mail -s "$(hostname)" admin@example.org
```

## What to do with each result

- **PASS:** keep the output as your record. No action is needed for that
  file.
- **FAIL:** update the package, or upgrade PHP to a fixed version. Then
  restart the service that uses it, and run the check again.
- **CHECK FAILED:** read the reason. It always says what to do next. The
  [results reference](results-reference.md) explains every message.

After any update, **restart** PHP-FPM or the web server. Until you do, the
old program keeps running in memory. The host check notices this: it
reports the running copy as "replaced or deleted on disk".

## Limits

- The rpm part was tested with real rpm packages and databases, but not yet
  on a real Red Hat or SUSE server.
- Network drives, Windows drives under WSL (`9p`, `drvfs`) and folders shared
  into virtual machines (`virtiofs`, `vboxsf`, `vmhgfs`) are not searched.
  Each one is listed in the output as `# not searched: <mount point> (<type>)`.
  The filesystem that holds the starting folder is always searched. If that
  filesystem is itself one of these types (for example `--root` on a
  network drive), other mounts of the same type are searched too.
- The check covers CVE-2026-109618 and CVE-2026-109619 only. It does not
  cover CVE-2026-115560.
- A PASS from a changelog means the tool read an item as stating a fix for
  both CVEs. The tool matches wording; it does not understand it. Read the
  quoted item to confirm it.
- Renamed PHP is found by the version text inside every program or library
  over 1 MB. A PHP build edited so that its version text is gone is found only
  by its name.
  The tool does not test the fix itself.
