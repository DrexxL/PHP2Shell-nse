# PHP2Shell-nse
PHP2Shell script for use with nmap scanner; Safe, no aggressive vulnerability checking nor exploitations

## What is PHP2Shell?

PHP is a programming language that runs many websites. In October 2026,
two serious bugs in PHP became public. Together they are called
**PHP2Shell**. Published summaries of PHP's advisory describe them like
this (see [Sources](#sources)):

- **CVE-2026-109618**: memory corruption.
- **CVE-2026-109619**: data left over from one web visitor's request can be
  reused during a later request on the same PHP worker.

A "CVE" is an ID number that the security world gives each known bug, so
everyone can talk about the same one. The same summaries describe both as
"remote code execution" bugs: an attacker could run their own commands on
the server. Both appear in the U.S. government's list of bugs that attackers
are known to be using (the CISA KEV catalog).

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

This repository has two kinds of tools. They answer different questions.

| Tool | Where you run it | The question it answers | Possible results |
|---|---|---|---|
| `php2shell-detect.nse` | One computer that scans your network, with nmap | "Which websites *say* they run an old PHP?" | BANNER BELOW FIX, BANNER AT OR ABOVE FIX, CHECK FAILED |
| `metasploit/php2shell_banner.rb` | The same, inside Metasploit | The same question, with the same answers | The same three results |
| `php2shell-hostcheck.sh` | On each Linux server, as the administrator (root) | "Is the PHP on this server actually fixed?" | PASS, FAIL, CHECK FAILED |
| `php2shell-hostcheck-macos.sh` | On each Mac, with `sudo` | "Is the PHP on this Mac actually fixed?" | PASS, FAIL, CHECK FAILED |

All the tools work with no internet connection. None of them attacks anything.

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

- **PASS** means a fix is recorded. Either the version is at or after the
  fixed one, or the changelog has an item that the tool reads as stating a
  fix for both CVE numbers. In the second case, the result line quotes that
  item, and a person should read it to confirm. A changelog that only
  *mentions* the CVE numbers is not enough. The tool matches wording; it does
  not understand it.
- **FAIL** means the version is old enough to have the bugs, and nothing
  shows that a fix was added.
- **CHECK FAILED** means the tool could not find a record either way. It never
  guesses. Every CHECK FAILED line says what went wrong and what to do next.

Before it trusts a changelog, the host check also makes sure the file really
is the one the package installed. **Example:** if someone copies an old PHP
program over a packaged one, the file's version number no longer matches the
package record, so the result is CHECK FAILED, not PASS. On Debian and Ubuntu,
the file's checksum is compared too, so a copy with the same version number is
also caught. On rpm and apk systems, only the version number is compared.

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
web01|PASS|cli|/usr/bin/php8.3|pid201,installed|8.3.6|dpkg:php8.3-cli 8.3.6-0ubuntu0.24.04.13|The changelog (/usr/share/doc/php8.3-common/changelog.Debian.gz) records a fix for both CVE-2026-109618 and CVE-2026-109619: "SECURITY UPDATE: Remote RCE via state corruption issue ... - CVE-2026-109618". Confirm the quoted item.
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
   ports. Nmap also skips some ports, such as 9100, during this step. Add
   `--allports` to include them.
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

## Documentation

| Page | Read it to... |
|---|---|
| [How the tools work](docs/how-it-works.md) | understand the ideas: versions, backports, banners and how each tool decides |
| [Host check guide](docs/host-check-guide.md) | run the host check on a server, a disk image or a container, and read its output |
| [macOS host check guide](docs/macos-guide.md) | check the PHP on a Mac: Homebrew, MacPorts, MAMP, XAMPP, Laravel Herd |
| [Network scan guide](docs/network-scan-guide.md) | run the network scan with nmap and read its output |
| [Metasploit module guide](docs/metasploit-guide.md) | run the network scan inside Metasploit |
| [Results reference](docs/results-reference.md) | look up any message either tool prints, and what to do about it |
| [Notes for auditors and investigators](docs/for-auditors-and-investigators.md) | know what each result proves, and keep a clean record |
| [Updating the rules](docs/updating-the-rules.md) | change the fixed versions when PHP publishes a new advisory |
| [Testing](docs/testing.md) | run the test suites and see what was tested |
| [FAQ](docs/faq.md) | find quick answers to common questions |
| [Glossary](docs/glossary.md) | look up a technical word |
| [Changelog](CHANGELOG.md) | see what changed and when |
| [Security policy](SECURITY.md) | report a problem with the tools |
| [AI assistance](AI-ASSISTANCE.md) | see which AI tools helped, with what, and how their work was checked |

## Limits

Read these before you rely on a result.

- **Linux and macOS.** The Linux host check runs on Linux, including
  Windows' WSL 2, and needs bash 4 and the standard GNU tools. The macOS host
  check runs with the bash 3.2 that macOS includes. Neither can check PHP for
  Windows. See [Supported systems](docs/host-check-guide.md#supported-systems).
- **The macOS check has not yet run on a real Mac.** It was tested on Linux
  with a real bash 3.2.57 (the version macOS includes), fake Mac disks and a
  fake `lsof`. Check its first results by hand. See the
  [macOS guide](docs/macos-guide.md#limits).
- **rpm tested with built packages, not a real Red Hat host.** The rpm part
  was tested with real rpm packages and databases (rpm 4.18), in both
  standard database locations. It has not yet run on an actual Red Hat,
  Rocky or SUSE server, or on the older database format of Red Hat 7 and 8.
- **Container storage is not opened.** Docker, Podman, LXD and similar
  storage folders are listed as CHECK FAILED. So are snap packages that
  contain PHP, and snap packages that are not mounted (as in an offline disk
  image). Run the host check inside each container, or use `--root` on each
  extracted image. Running containers are checked through their processes.
- **Root is needed.** Without root, some files and processes stay hidden, so
  the run reports CHECK FAILED, never says "nothing found", and never exits
  with status 0.
- **Some filesystems are not searched.** Network drives, Windows drives under
  WSL and folders shared into virtual machines are skipped. The Linux check
  lists each skipped mount in the output as `# not searched: ...`. The macOS
  check skips network drives, `/System` and `/Volumes`, as its guide
  describes, but does not list them one by one.
- **Images stay sealed.** With `--root`, links inside the image are followed
  only inside the image, and package records are read only from regular
  files, so the checking computer's own files are not read in place of the
  image's.
- **A changelog is a record, not a test.** PASS from a changelog means an
  entry in the package's changelog states a fix for both CVEs. The tools do
  not test the fix itself.
- **nmap 7.94 was used for testing here.** Every nmap function the script
  uses was checked against the nmap 7.80 source code. An external review
  (Codex, November 2026) reports that the network scan tests also passed on
  nmap 7.80; that run was not repeated here.

## Sources

These are the sources for the facts about the bugs. Most are secondary: they
summarise PHP's advisory. Check PHP's own security announcements and the CVE
records before you quote them.

- PHP 8.4.27 release notes (a security release for both CVEs):
  https://github.com/php/php-src/releases/tag/php-8.4.27
- CVE records: https://www.cve.org/CVERecord?id=CVE-2026-109618 and
  https://www.cve.org/CVERecord?id=CVE-2026-109619
- CISA Known Exploited Vulnerabilities catalog:
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- AWS security bulletin 2026-143 (affected and fixed versions):
  https://aws.amazon.com/security/security-bulletins/2026-143-aws/
- Canadian Centre for Cyber Security alert AL26-026:
  https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619
- SOCRadar summary (bug types, KEV date):
  https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/
- Abstract Security summary (affected branches):
  https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Credits

Written by Drexx Laggui with assistance from Claude (Anthropic's Opus 5.5) and Codex (OpenAI's Daybreak Blue); the commit
history records the sessions.
