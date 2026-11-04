# Network scan guide

`php2shell-detect.nse` is a script for **nmap**, the network scanner. It
asks web servers on your network which PHP version they report, and
compares that with the fixed versions. Use it to decide where to look
first. Then confirm each server with the [host check](host-check-guide.md).

## What you need

| Need | Why |
|---|---|
| nmap (tested with 7.94) | The script runs inside nmap. On a Mac, install it with `brew install nmap` or from nmap.org. |
| A computer that can reach your web servers | The script connects to them. |
| Permission to scan those servers | Scan only systems you are responsible for. |

You do **not** need internet access. Everything the script needs is in the
one file.

## Scan your network

1. Copy `php2shell-detect.nse` to the scanning computer.
2. Run nmap with the script. Replace `10.0.0.0/24` with your own address
   range:

   ```bash
   nmap -sV -p 80,443,8080,8443 --script ./php2shell-detect.nse 10.0.0.0/24
   ```

3. Save the results in all of nmap's formats for your records:

   ```bash
   nmap -sV -p 80,443,8080,8443 --script ./php2shell-detect.nse -oA php2shell-scan 10.0.0.0/24
   ```

   This creates `php2shell-scan.nmap` (text), `php2shell-scan.xml` (for
   other tools) and `php2shell-scan.gnmap` (one line per host).

4. Run the host check on every server, starting with those that show
   BANNER BELOW FIX or CHECK FAILED.

### Why `-sV` matters

nmap runs the script only on ports it recognizes as web servers. Without
`-sV` (service detection), nmap recognizes web servers only on well-known
ports such as 80 and 443. With `-sV`, it also finds web servers on unusual
ports.

nmap skips a few ports during service detection, such as 9100 (printers).
To include them, add `--allports`.

## Optional settings

Add settings after `--script-args`. Separate several settings with commas.

| Setting | What it does |
|---|---|
| `php2shell-detect.paths=/a/,/b.php` | Also checks these pages. `/` is always checked. |
| `php2shell-detect.probe-info` | Also checks `/index.php`, `/info.php` and `/phpinfo.php` for a PHP information page. |
| `php2shell-detect.vhost=name` | Sends this website name to the server. Use it when one server hosts several websites. |

**Example:** check two extra pages and the information pages on one server:

```bash
nmap -sV -p 443 --script ./php2shell-detect.nse \
  --script-args 'php2shell-detect.paths=/app/,/login.php,php2shell-detect.probe-info' \
  intranet.example
```

### Websites that share a server

One server can host many websites. It decides which one to show from the
name in the request. To check a specific website:

- For plain HTTP, use `php2shell-detect.vhost=www.example.org`.
- For HTTPS, scan by the website's **name** instead of its IP address. Then
  nmap sends the name during the secure connection setup too (this is
  called **SNI**). The output records the name sent.

## Read the output

Each web service gets one block:

```
80/tcp open  http
| php2shell-detect:
|   result: BANNER BELOW FIX
|   reason: Disclosed PHP 8.2.10 precedes the fixed release 8.2.35. Some distribution builds show the bare upstream number even with the fix backported.
|   action: Confirm on the host: identify the PHP binary and SAPI that serve this site and check the package changelog for the CVE IDs. Patch if the fix is absent.
|   target: http://10.0.0.5:80  Host: 10.0.0.5  SNI: none
|   evidence:
|     GET / -> 200, x-powered-by: PHP/8.2.10
|   rules: PHP security releases of 2026-10-21 (8.2.35, 8.3.36, 8.4.27, 8.5.12); rule set dated 2026-11-04
|   checked_at: 2026-11-04T14:02:11Z
|   cves: CVE-2026-109618, CVE-2026-109619 (both in the CISA KEV catalog)
|   references:
|     https://www.cve.org/CVERecord?id=CVE-2026-109618
|     https://www.cve.org/CVERecord?id=CVE-2026-109619
|_    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

| Field | Meaning |
|---|---|
| result | BANNER BELOW FIX, BANNER AT OR ABOVE FIX or CHECK FAILED |
| reason | Why this result was given |
| action | What to do next |
| target | The connection actually used (`http` or `https`), the address and port, the `Host` header sent, and the SNI name sent |
| evidence | One line for each page request: the page, the status code and what was found |
| rules | Which fixed versions were used, and the date of the rule set |
| checked_at | When the check ran (UTC) |

In the evidence lines, the number after `->` is the web server's status
code. `200` means the page was found, `302` means "go to another address"
(the script does not follow it), `404` means "not found".

## What the scan sends

The scan sends ordinary page requests (HTTP `GET`), like a web browser. It
sends no attack and does not try to break in. nmap's `-sV` step also sends
its own standard probes to identify each service.

Even so, any request can upset a badly broken application. If you are
unsure about a system, scan it during a maintenance window.

## Limits

- **A banner is a claim, not proof.** A proxy, a program or a person can
  change, hide or fake it. So the scan never says "safe" or "vulnerable".
- **Many servers hide the banner.** With PHP's `expose_php` setting off,
  the result is CHECK FAILED. That says nothing about whether the server is
  fixed.
- **Backports are invisible.** A distribution can fix the bug without
  changing the number in the banner.
- **Tested here with nmap 7.94.** Every nmap function the script uses was
  checked against the nmap 7.80 source code. An external review (Codex,
  November 2026) reports that the tests also passed on nmap 7.80; that run
  was not repeated here.
