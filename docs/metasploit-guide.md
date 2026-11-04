# Metasploit module guide

`metasploit/php2shell_banner.rb` is the network scan for Metasploit users. It
does the same job as the nmap script, `php2shell-detect.nse`: it asks each
web server which PHP version it reports, and compares that with the fixed
versions. It gives the same three results, with the same wording.

It is an **auxiliary scanner** module. It sends ordinary page requests only:
no exploit, no attack. It never reports a host as "vulnerable". It stores its
findings as Metasploit **notes**, not as vulnerabilities, because a banner is
a claim, not proof.

**Example:** a server that reports `X-Powered-By: PHP/8.2.10` gives
`BANNER BELOW FIX: Disclosed PHP 8.2.10 precedes the fixed release 8.2.35.`
Then you confirm it on the server with the host check.

## Install the module

1. Make a folder for your own modules, if you do not have one:

   ```bash
   mkdir -p ~/.msf4/modules/auxiliary/scanner/http
   ```

2. Copy the module into it:

   ```bash
   cp metasploit/php2shell_banner.rb ~/.msf4/modules/auxiliary/scanner/http/
   ```

3. Start Metasploit, or type `reload_all` if it is already running:

   ```bash
   msfconsole -q
   ```

4. Make sure Metasploit found it:

   ```
   msf6 > search php2shell
   ```

   The list shows `auxiliary/scanner/http/php2shell_banner`.

## Scan

1. Select the module:

   ```
   msf6 > use auxiliary/scanner/http/php2shell_banner
   ```

2. Set the targets. Change the range to your own:

   ```
   msf6 auxiliary(scanner/http/php2shell_banner) > set RHOSTS 10.0.0.0/24
   ```

3. Set the port. Use 443 with `set SSL true` for HTTPS:

   ```
   msf6 auxiliary(scanner/http/php2shell_banner) > set RPORT 80
   ```

4. Optional: show the evidence for each result:

   ```
   msf6 auxiliary(scanner/http/php2shell_banner) > set VERBOSE true
   ```

5. Run it:

   ```
   msf6 auxiliary(scanner/http/php2shell_banner) > run
   ```

6. Run the host check on every server it lists.

### Options

| Option | What it does | Default |
|---|---|---|
| `RHOSTS` | The servers to check | (none) |
| `RPORT` | The web server port | 80 |
| `SSL` | Use HTTPS | false |
| `VHOST` | The website name to send, for servers that host several sites | (none) |
| `TARGETURI` | The first page to check | `/` |
| `PATHS` | Extra pages to check, separated by commas, for example `/app/,/login.php` | (none) |
| `PROBE_INFO` | Also check `/index.php`, `/info.php` and `/phpinfo.php` for a PHP information page | false |
| `THREADS` | How many servers to check at the same time | 1 |

## Read the results

Each server gets one line:

```
[!] 10.0.0.5:80 - BANNER BELOW FIX: Disclosed PHP 8.2.10 precedes the fixed release 8.2.35. ...
[+] 10.0.0.6:80 - BANNER AT OR ABOVE FIX: Disclosed PHP 8.3.36 is at or after the fixed release 8.3.36. ...
[*] 10.0.0.7:80 - CHECK FAILED: No PHP version was disclosed ...
```

The results and messages are the same as the nmap script's. See the
[results reference](results-reference.md#network-scan-php2shell-detectnse).
With `VERBOSE true`, each result also shows the action to take, the target
(transport, address and the `Host` header actually sent) and one evidence
line for each page request.

### Notes in the database

If Metasploit has a database connected, each result is saved as a note of
type `php2shell.banner`, with the result, reason, action, target, evidence,
rule set and time. To list them:

```
msf6 > notes -t php2shell.banner
```

Without a database, the module still runs and prints its results.

## Limits

- **A banner is a claim, not proof.** The same limits apply as for the nmap
  script: see the [network scan guide](network-scan-guide.md#limits).
- **Transport.** The module reports `https` or `http` from the `SSL` option,
  not from the connection itself.
- **Tested with** the official Metasploit Docker image
  (`metasploitframework/metasploit-framework`, Ruby 3.3), on 4 November 2026.
  See [Testing](testing.md).
- **License.** The module is under Apache-2.0, like the rest of this
  repository. Modules included in Metasploit itself use Metasploit's BSD
  license, so sending it to the Metasploit project would need the owner's
  agreement to that license.
