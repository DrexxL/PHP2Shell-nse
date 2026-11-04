# PHP2Shell-nse
PHP2Shell script for use with nmap scanner; Safe, no aggressive vulnerability checking nor exploitations

## What is PHP2Shell?

PHP is a programming language that runs many websites. In October 2026,
researchers made public two serious bugs in PHP. Together they are called
**PHP2Shell**:

- **CVE-2026-109618**: a memory bug.
- **CVE-2026-109619**: a bug where data left over from one web visitor's
  request can be reused during the next visitor's request.

A "CVE" is an ID number that the security world gives each known bug, so
everyone can talk about the same one. Both bugs can let an attacker run
their own commands on the server. Attackers are already using them. That is
why both appear in the U.S. government's list of known exploited bugs (the
CISA KEV catalog).

PHP fixed the bugs on **21 October 2026**. These are the first fixed
versions:

| PHP branch | First fixed version |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

**Example:** a server running PHP 8.3.20 is older than 8.3.36, so it needs
the fix. A server running 8.3.36 or later already has it.

These tools do **not** check a third, separate bug, CVE-2026-115560.

## Two tools, two jobs

This repository has two tools. They answer different questions.

| Tool | Where you run it | The question it answers | Possible results |
|---|---|---|---|
| `php2shell-detect.nse` | One computer that scans your network | "Which websites *say* they run an old PHP?" | BANNER BELOW FIX, BANNER AT OR ABOVE FIX, CHECK FAILED |
| `php2shell-hostcheck.sh` | On each server, as the administrator (root) | "Is the PHP on this server actually fixed?" | PASS, FAIL, CHECK FAILED |

Both tools work with no internet connection. Neither tool attacks anything.

### Why the network scan cannot give the final answer

Many websites send a short label with every page, such as
`X-Powered-By: PHP/8.3.6`. This label is called a **banner**. The network
scan reads it. But a banner is like a name tag: anyone can write anything on
it, it can be out of date, or it can be missing.

Here is a real example from testing. A Linux server ran Ubuntu's PHP
package, version `8.3.6-0ubuntu0.24.04.13`. Its banner said only
`PHP/8.3.6`, which looks older than the fix (8.3.36). But Ubuntu had already
copied the fix into its own 8.3.6 package. Copying a fix into an older
version like this is called a **backport**. The banner made a fixed server
look unfixed.

So the network scan tells you **where to look first**. The host check gives
the answer you can put in a report.

### How the host check decides

The host check looks at the PHP files on the server itself. It never runs
them. It reads the version number stored inside each file, finds out which
software package installed the file, and searches that package's history of
changes (its "changelog") for the two CVE numbers.

- **PASS** means there is proof of the fix. Either the changelog lists both
  CVE numbers, or the version is at or after the fixed one.
- **FAIL** means the version is old enough to have the bugs, and nothing
  shows that a fix was added.
- **CHECK FAILED** means the tool could not find proof either way. It never
  guesses. Every CHECK FAILED line says what went wrong and what to do next.

**Example:** PHP 8.1 is older than the versions in PHP's official warning.
Experts disagree about whether 8.1 has these bugs. So the host check reports
CHECK FAILED for 8.1, not FAIL or PASS, and tells you to upgrade.

## How to use the host check

1. Copy `php2shell-hostcheck.sh` to the server.
2. Log in as root, or use `sudo`.
3. Run the check:

   ```bash
   sudo ./php2shell-hostcheck.sh
   ```

4. Read the result lines. Each line has eight fields, separated by `|`:
   `host|result|sapi|path|seen|php_version|package|reason`.
5. Use the exit status in your own scripts. 0 means all PASS. 1 means at
   least one FAIL. 2 means no FAIL, but at least one CHECK FAILED.

To check a disk or a container image that is not running, mount or extract
it first. Then run:

```bash
sudo ./php2shell-hostcheck.sh --root /mnt/disk
```

**Example output line:**

```
web01|PASS|cli|/usr/bin/php8.3|pid201,installed|8.3.6|dpkg:php8.3-cli 8.3.6-0ubuntu0.24.04.13|Package changelog records the fix for both CVE-2026-109618 and CVE-2026-109619.
```

The run can take a minute, because the tool searches the whole disk. That
search also finds PHP programs that only start when a web page asks for
them.

## How to use the network scan

1. Install nmap on a computer that can reach your servers.
2. Copy `php2shell-detect.nse` to that computer.
3. Scan your network. Change `10.0.0.0/24` to your own address range:

   ```bash
   nmap -sV -p 80,443,8080,8443 --script ./php2shell-detect.nse 10.0.0.0/24
   ```

4. Keep `-sV` in the command. Without it, nmap can miss websites on unusual
   ports.
5. Run the host check on every server that the scan lists. Run it on the
   other servers too, because a missing banner proves nothing.

Optional settings go after `--script-args`:

| Setting | What it does | Example |
|---|---|---|
| `php2shell-detect.paths` | Also checks these pages | `php2shell-detect.paths=/app/,/login.php` |
| `php2shell-detect.probe-info` | Also looks for PHP's information page (phpinfo) | `php2shell-detect.probe-info` |
| `php2shell-detect.vhost` | Sends this website name to a server that hosts several sites | `php2shell-detect.vhost=intranet.example` |

The scan only asks for normal web pages and sends no attack. Even so, any
web request can upset a badly broken application. If you are unsure, scan
during a maintenance window.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Credits

Written by Drexx Laggui with assistance from Claude (Anthropic); the commit
history records the sessions.
