# Glossary

**Advisory**: an official warning about a security bug, with the fixed
versions. Example: PHP's security releases of 21 October 2026.

**Backport**: copying a fix into an older version instead of moving to the
new version. Example: Ubuntu's PHP 8.3.6 package contains the PHP2Shell
fix, although PHP's own fix arrived in 8.3.36.

**Banner**: a label a server sends about itself with each response.
Example: `X-Powered-By: PHP/8.2.10`.

**Branch**: the first two parts of a version number. Each branch gets its
own fixes. Example: 8.3.20 is on branch 8.3.

**Changelog**: a package's list of changes, version by version. Debian and
Ubuntu store it as `/usr/share/doc/<package>/changelog.Debian.gz`.

**Checksum**: a short fingerprint computed from a file's contents. If one
byte of the file changes, the checksum changes. Debian records an MD5
checksum for each file a package installs.

**CISA KEV catalog**: the U.S. Cybersecurity and Infrastructure Security
Agency's list of Known Exploited Vulnerabilities: bugs that attackers are
known to use.

**Container**: a program packaged with its own files, running separately
from other programs on the same computer. Examples: Docker and Podman
containers.

**CVE**: Common Vulnerabilities and Exposures, a public ID number for a
known security bug. Example: CVE-2026-109618.

**ELF**: the file format of Linux programs. ELF files start with the bytes
`7F 45 4C 46` ("\177ELF").

**Exit status**: a number a program returns when it finishes. Scripts use it
to tell what happened. Example: the host check returns 1 if any line is
FAIL.

**`expose_php`**: a PHP setting. When it is off, PHP does not send its
version banner.

**Mount namespace**: the set of folders a process can see. Containers have
their own. systemd also gives some services their own, as a safety measure.

**nmap**: a widely used, free network scanner. It can run add-on scripts
written in Lua, called NSE scripts.

**NSE**: the Nmap Scripting Engine. `php2shell-detect.nse` is an NSE script.

**Package manager**: the program that installs and tracks software on Linux.
`dpkg` (Debian, Ubuntu), `rpm` (Red Hat, SUSE), `apk` (Alpine).

**phpinfo**: a PHP information page that shows PHP's settings and version.
Leaving it on a public website is a security risk.

**Pre-release**: a test version made before the final release. Its name ends
in RC (release candidate), alpha, beta or dev. Example: 8.2.35RC1 comes
before 8.2.35.

**Process ID (PID)**: the number Linux gives each running program.

**Redirect**: a server response that says "go to another address". Its
status code is in the 300s, such as 302.

**Root**: the administrator account on Linux.

**Rule set**: the list of fixed versions the tools compare against, with its
date.

**Runtime**: any program or module that can run PHP code.

**SAPI**: Server Application Programming Interface: the way PHP is connected
to the web server. Examples: Apache module (`apache2handler`), PHP-FPM
(`fpm-fcgi`), command line (`cli`).

**SNI**: Server Name Indication: the website name a client sends while
setting up an HTTPS connection, so a shared server knows which site is
wanted.

**Status code**: the number a web server returns with each response.
Examples: 200 (found), 302 (redirect), 404 (not found).

**Upstream**: the original makers of a program, here the PHP project, as
opposed to a distribution that repackages it.

**Virtual host (vhost)**: one of several websites served by the same server,
told apart by the name in the request's `Host` header.
