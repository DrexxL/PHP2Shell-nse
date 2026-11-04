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
that lists both CVEs, so you can read it yourself.

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

### Does it work on Windows?

No. Both tools are for Linux servers. You can run the network scan from any
computer that runs nmap, including Windows, against Linux web servers.

### Does it cover CVE-2026-115560?

No. That is a separate bug with different conditions. These tools cover
CVE-2026-109618 and CVE-2026-109619 only.

### How do I know the tools do what this documentation says?

Run the test suites in `tests/`. They rebuild every test case and check
every result. See [Testing](testing.md).

### Who wrote these tools?

Drexx Laggui, with assistance from Claude (Anthropic). The commit history
records each change.
