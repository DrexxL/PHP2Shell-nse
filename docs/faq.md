# Frequently asked questions

### Is the network scan safe to run?

It sends only ordinary page requests, like a web browser, and no attack.
nmap's `-sV` step also sends standard identification probes. Any request can
still upset a badly broken application, so scan fragile systems during a
maintenance window. Scan only systems you are responsible for.

### Why does the network scan never say "vulnerable" or "safe"?

Because it only sees what a server *says* about itself. A banner can be
changed, faked, hidden or out of date, and it cannot show backported fixes.
**Example:** a real Ubuntu server with the fix reported `PHP/8.3.6`, which
looks unfixed. Only the host check can see the truth.

### The scan says BANNER AT OR ABOVE FIX. Can I mark the server as fixed?

No. The banner could be wrong. Confirm with the host check first.

### The scan says CHECK FAILED, "No PHP version was disclosed". Is the server safe?

You cannot tell. Many servers hide their PHP version on purpose. Run the
host check on that server.

### Why does the host check say CHECK FAILED for PHP 8.1?

PHP's official warning covers branches 8.2 to 8.5. Experts disagree about
8.1 and older. The tool will not guess, so it reports CHECK FAILED and
advises an upgrade. Branches 8.1 and older no longer get regular PHP
updates anyway.

### My distribution's PHP number is lower than the fix, but the host check says PASS. Is that right?

Probably yes. Distributions often copy a fix into an older version
(a backport). The PASS line names the changelog file and quotes the entry
that states a fix for both CVEs, so you can read it yourself.

### I updated PHP but the host check still reports a problem.

Restart PHP-FPM and the web server. Until you do, the old program keeps
running in memory. The host check reads the running copy, so it reports
"replaced or deleted on disk" until the restart.

### Does the host check run any PHP code?

No. It reads version numbers from the files' bytes. It never starts PHP.

### Does it change anything on my server?

It changes no files it examines. On a live check it writes one small
temporary file (normally in `/tmp`) and deletes it when it finishes.

### Why is root needed?

Without root, the tool cannot see every running program or read every
folder. If anything stays hidden, the tool says CHECK FAILED instead of
claiming that it found nothing.

### Can I check a Docker image?

Yes. Export or extract it into a folder, then run the host check with
`--root`. See the [host check guide](host-check-guide.md#check-containers).

### Does it work on a Mac?

Yes, with the macOS host check, `php2shell-hostcheck-macos.sh`. It checks
PHP from Homebrew, MacPorts, MAMP, XAMPP, Laravel Herd and anywhere else on
the disk, using the bash and tools that macOS includes. It has not yet run on
a real Mac. See the [macOS guide](macos-guide.md).

The network scan also works on a Mac: install nmap (for example with
`brew install nmap`) and run it as shown in the
[network scan guide](network-scan-guide.md).

### Why does the macOS check give FAIL where the Linux check might give PASS?

On Linux, a distribution can copy a fix into an older version and record it
in a changelog that the check reads. On a Mac, Homebrew, MacPorts and app
bundles record the version, but no changelog of CVE fixes. So on a Mac, a
version older than the fix has no record of a fix, and the result is FAIL.

### Does it work on Windows?

- **The network scan** works on any computer that runs nmap, including
  Windows. It can scan any web server, whatever system the server runs.
- **The host check** runs on Linux only. On Windows, it runs inside WSL 2
  and checks the PHP installed **in that WSL Linux system**. It cannot check
  PHP for Windows (`php.exe`), because that is a different kind of program
  with no Linux package record. Windows drives (`/mnt/c` and so on) are not
  searched, and the output lists them as `# not searched`.
- **WSL 1** is expected not to support checking running processes. In that
  case the check says so with a CHECK FAILED line, and checks only files on
  disk. Neither WSL version has been tested yet.

### Which Linux systems does the host check support?

See [Supported systems](host-check-guide.md#supported-systems).

### Does it cover CVE-2026-115560?

No. That is a separate bug with different conditions. These tools cover
CVE-2026-109618 and CVE-2026-109619 only.

### How do I know the tools do what this documentation says?

Run the test suites in `tests/`. They rebuild every test case and check
every result. See [Testing](testing.md).

### Who wrote these tools?

Drexx Laggui, with assistance from Claude (Anthropic). The commit history
records each change.
