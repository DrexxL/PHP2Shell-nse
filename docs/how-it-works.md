# How the tools work

This page explains the ideas behind the two tools, step by step. You do not
need to be a programmer to follow it. Words in **bold** are explained in the
[glossary](glossary.md).

## 1. The problem: two bugs in PHP

PHP is a programming language. A web server uses it to build web pages. When
you visit a website, the server may run a PHP program that builds the page
just for you.

In October 2026, two serious bugs in PHP were made public:

| ID | What kind of bug |
|---|---|
| CVE-2026-109618 | Memory corruption: PHP can be tricked into writing data where it should not. |
| CVE-2026-109619 | Stale request state: data left over from one visitor's request can be reused during the next visitor's request. |

Together they are called **PHP2Shell**, because they can give an attacker a
"shell": the power to run their own commands on the server. Attackers are
already using them. The U.S. Cybersecurity and Infrastructure Security
Agency (CISA) lists both in its catalog of known exploited bugs.

PHP published fixed versions on 21 October 2026: 8.2.35, 8.3.36, 8.4.27 and
8.5.12.

## 2. Reading a version number

A PHP version number has three parts:

```
8 . 3 . 20
│   │   └── patch number: goes up with each bug-fix release
│   └────── minor number
└────────── major number
```

The first two parts together, such as `8.3`, are the **branch**. Each branch
gets its own fixes. To decide whether a version is fixed, the tools compare
it with the fixed version **of the same branch**:

| Version found | Branch | Fixed version for that branch | Older than the fix? |
|---|---|---|---|
| 8.3.20 | 8.3 | 8.3.36 | Yes |
| 8.3.36 | 8.3 | 8.3.36 | No (this is the fix) |
| 8.4.30 | 8.4 | 8.4.27 | No |
| 8.2.35RC1 | 8.2 | 8.2.35 | Yes: "RC1" means a test version made *before* 8.2.35 |

Numbers are compared part by part, as numbers, not as text. So 8.3.6 is
older than 8.3.36, because 6 is less than 36.

### What about older branches?

PHP's official warning covers branches 8.2 to 8.5. Branches 8.1 and older no
longer get regular updates. Sources disagree about whether those older
branches have these bugs. Some researchers say yes; the official CVE record,
according to one reviewer, lists only 8.2 to 8.5.

When experts disagree, the tools do not pick a side. They report
**CHECK FAILED** for those branches and advise an upgrade. That way, no
report claims something that nobody can prove.

## 3. Why a version number is not enough on its own

Linux distributions, such as Debian, Ubuntu and Red Hat, often fix a bug
**without** changing to PHP's new version number. They copy just the fix
into the version they already ship. This is called a **backport**.

**Example from testing:** Ubuntu ships PHP `8.3.6`. That looks older than
the fix (8.3.36). But Ubuntu's package `8.3.6-0ubuntu0.24.04.13` already
contains the fix. Its change history says so:

```
debian/patches/CVE-2026-109618_109619.patch: Avoid state corruption via ...
```

So a tool that looks only at the number `8.3.6` would call this fixed server
broken. To get the right answer, you must read the package's change history.
Only the host check can do that.

## 4. The network scan: looking from outside

The network scan (`php2shell-detect.nse`) runs inside **nmap**, a common
network scanning program. It works like a visitor to each website:

1. It asks for the home page (`/`) and any other pages you name.
2. It reads the **banner**, the label a server may send with each page,
   such as `X-Powered-By: PHP/8.2.10`.
3. If you ask, it also looks for a PHP information page (**phpinfo**).
   It trusts only the page's official heading, not other text on the page.
4. It compares each version it found with the fixed version.

It always reports one of three results:

| Result | Meaning |
|---|---|
| BANNER BELOW FIX | The server says it runs a version older than the fix. |
| BANNER AT OR ABOVE FIX | The server says it runs the fixed version or newer. |
| CHECK FAILED | There is nothing reliable to compare. |

Notice the word **banner** in the first two results. They describe what the
server *says*, not what is true. A banner is like a name tag: anyone can
write on it. For that reason, the scan never says "safe" or "vulnerable".

### Rules the scan follows

- **Every page counts.** If the home page says 8.2.35 but `/app/` says
  8.2.34, the result is CHECK FAILED. Two different back-end servers may be
  answering.
- **Redirects are not followed.** If a page says "go to another address",
  the scan records that and stops. This keeps each piece of evidence tied to
  the page that produced it.
- **Partial numbers do not count.** A banner such as `PHP/8.2` cannot be
  compared with 8.2.35, so the result is CHECK FAILED.
- **Distribution builds are not judged.** A banner such as
  `PHP/8.2.20-1+deb12u3` comes from a Debian package that may contain a
  backport, so the result is CHECK FAILED.

## 5. The host check: looking from inside

The host check (`php2shell-hostcheck.sh`) runs on the server itself, as the
administrator (root). It can see things the network scan cannot.

### Step 1: Find every PHP runtime

A PHP **runtime** is any program or module that can run PHP code. The host
check finds them in two ways:

- **Running processes.** It looks at every program that is running now,
  including programs inside containers. For each PHP program, and for each
  PHP module loaded into a web server (such as Apache's `mod_php`), it notes
  the process ID.
- **Files on disk.** It searches the disks for PHP programs and modules.
  This also finds `php-cgi`, which runs only for a moment when a web page
  asks for it.

### Step 2: Read the version without running anything

Every PHP program contains its own version number, stored as the text
`X-Powered-By: PHP/8.3.6`. The host check reads this text from the file's
bytes. It **never runs** the program. This matters for two reasons:

- Running an unknown program on a server that might be under attack is
  risky.
- Investigators must not change the evidence they examine.

For a program that is running, the host check reads the copy in memory
(through `/proc/<process ID>/exe`). This checks what is **really** running,
even if someone has since replaced the file on disk.

### Step 3: Find the package and confirm the file is genuine

Most PHP programs are installed by a **package manager**: `dpkg` on Debian
and Ubuntu, `rpm` on Red Hat and SUSE, `apk` on Alpine. The package manager
keeps a record of every file it installed.

The host check finds the package that owns each file. Then it checks that the
file really is the one the package installed:

- The file's version number must match the package's version number.
- On Debian and Ubuntu, the file's checksum must match the recorded one.

**Example:** someone copies an old PHP program over `/usr/bin/php8.3`. The
package record still says "8.3.36, fixed". But the file says 8.3.6. The host
check notices the mismatch and reports CHECK FAILED instead of trusting the
package record.

### Step 4: Read the package's change history

Debian, Ubuntu and Red Hat packages include a **changelog**: a list of
changes in each version. When a distribution backports a fix, it names the
CVE in the changelog. The host check searches the changelog for both CVE
numbers.

It also guards against wrong readings:

- If only one CVE is listed, the result is CHECK FAILED.
- If the entry uses words such as "not fixed", the result is CHECK FAILED,
  and the report quotes the entry so a person can read it.
- Every PASS names the changelog file it used and quotes the entry.

### Step 5: Decide

The host check applies these rules in order. The first rule that matches
decides the result.

```
Could the version be read?
├─ No  ──────────────────────────────────────────────► CHECK FAILED
└─ Yes
   Is the file still the one that is running? (not replaced or deleted)
   ├─ No: running version at/after fix ──────────────► PASS
   ├─ No: otherwise ─────────────────────────────────► CHECK FAILED (restart, re-run)
   └─ Yes
      Does the file match its package?
      ├─ No ─────────────────────────────────────────► CHECK FAILED
      └─ Yes, or no package
         Does the changelog list both CVEs as fixed?
         ├─ Yes ─────────────────────────────────────► PASS
         └─ No
            Is the branch 8.2 to 8.5?
            ├─ No ───────────────────────────────────► CHECK FAILED
            └─ Yes
               Is the version at or after the fix?
               ├─ Yes ───────────────────────────────► PASS
               └─ No
                  Unpackaged build? ─────────────────► FAIL
                  Changelog read, no CVEs? ──────────► FAIL
                  Changelog not readable? ───────────► CHECK FAILED
                  Alpine (no local changelog)? ──────► CHECK FAILED
                  Only one CVE listed? ──────────────► CHECK FAILED
```

(The diagram leaves out a few special cases, such as an rpm database with no
rpm tool, or a package whose version cannot be read. The [results reference](results-reference.md) lists every
message.)

## 6. Why "CHECK FAILED" is a good answer

It can feel unhelpful when a tool says "I could not tell". But a wrong
answer is worse:

- A wrong **PASS** leaves a broken server unfixed.
- A wrong **FAIL** wastes effort, and can damage trust in every other
  result.

Each CHECK FAILED line says exactly what was missing and what to do next.
The tools are built so that every PASS and every FAIL can be defended from
the evidence printed on the same line.
