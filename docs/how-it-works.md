# How the tools work

This page explains the ideas behind the two tools, step by step. You do not
need to be a programmer to follow it. Words in **bold** are explained in the
[glossary](glossary.md).

## 1. The problem: two bugs in PHP

PHP is a programming language. A web server uses it to build web pages. When
you visit a website, the server may run a PHP program that builds the page
just for you.

In October 2026, two serious bugs in PHP were made public:

Published summaries of PHP's advisory (listed under
[Sources](../README.md#sources)) describe them like this:

| ID | What kind of bug |
|---|---|
| CVE-2026-109618 | Memory corruption. |
| CVE-2026-109619 | Stale request state: data left over from one request can be reused by a later request on the same PHP worker. |

Together they are called **PHP2Shell**. The same summaries describe both as
remote code execution bugs: an attacker could gain a "shell", the power to
run their own commands on the server. The U.S. Cybersecurity and
Infrastructure Security Agency (CISA) lists both in its catalog of bugs that
attackers are known to be using.

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

It recognises PHP in two ways: by its usual file names (`php`, `php8.3`,
`php-fpm`, `libphp.so` and so on), and by the version text that every PHP
build carries inside it (see step 2). **Example:** a PHP binary renamed to
`/opt/app/worker` has no PHP-like name, but it still carries
`X-Powered-By: PHP/8.2.10`, so it is found.

To keep the search fast, the version text is looked for in every file larger
than 1 MB whose first bytes mark it as a program or library (ELF on Linux,
Mach-O on a Mac), whatever its name or permissions; every PHP build is much
larger than 1 MB. On a live system, every file loaded by a running program is
checked the same way, except that on a Mac, Apple's own system files under
`/System` and `/usr/lib` are not searched for the text. **Limits:** a PHP
build that has been packed, encrypted or edited so that its version text is
gone is found only by its name. And a program that is not PHP but happens to
contain the text `X-Powered-By: PHP/<version>` would be judged as if it were
PHP.

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
- On Debian and Ubuntu, the file's checksum must also match, where the
  package recorded one.

**Example:** someone copies an old PHP program over `/usr/bin/php8.3`. The
package record still says "8.3.36, fixed". But the file says 8.3.6. The host
check notices the mismatch and reports CHECK FAILED instead of trusting the
package record.

### Step 4: Read the package's change history

Debian, Ubuntu and Red Hat packages include a **changelog**: a list of
changes in each version. When a distribution backports a fix, it names the
CVE in the changelog. The host check reads the changelog **item by item**:
a "  * " bullet with its sub-lines in Debian and Ubuntu, or a "- " line in
Red Hat.

A CVE counts as fixed only if one item passes all three of these tests:

1. **The item opens with a fix.** Its first sentence starts with "SECURITY
   UPDATE", "Security fix", "Fix", "Fixes", "Fixed", "Backport", "Resolves",
   "Patch", "Apply" or "Address", or with the CVE ID itself followed by a
   colon ("CVE-2026-109618: ...").
2. **The CVE is where that fix statement covers it.** The exact ID appears in
   that first sentence, or on its own line inside the item, such as
   "- CVE-2026-109618" or "- CVE-2026-109618: ...". A look-alike number, such
   as CVE-2026-1096180, does not count.
3. **Nothing in the item denies, limits or postpones the fix.** The words
   checked are: not fixed (also not fixing, not included, not addressed, not
   applied, not backported, not patched, not resolved, not complete, not
   covered, not handled, with "yet" or "currently" allowed in between),
   unfixed, not affected, does not fix, remains vulnerable, still vulnerable,
   investigate, pending, revert, to be fixed, todo, no fix, will, next, later,
   future, defer, postpone, dropped, removed, partial, incomplete, disabled,
   without, tbd, wontfix, won't fix, skip, ignore, back out, undo, not
   shipped, planned. They count only as whole
   words, so a file name such as `oom_pending_at_shutdown.phpt` does not
   count as "pending".

**Example (PASS):** Ubuntu's item starts with `SECURITY UPDATE: Remote RCE via
state corruption issue`, and lists `- CVE-2026-109618` and
`- CVE-2026-109619` on their own lines at its end.

**Examples (not PASS):**

| Changelog item | Why it is not accepted |
|---|---|
| "Investigate exposure to CVE-2026-109618 and CVE-2026-109619." | "investigate" |
| "Fixes for CVE-2026-109618 and CVE-2026-109619 will be included in the next upload." | "will", "next" |
| "Fixed typo in README. CVE-2026-109618 is not addressed." | "not addressed" |
| "Patch for CVE-2026-109618/CVE-2026-109619 dropped" | "dropped" (it opens with "Patch", but the patch was dropped) |

What happens when the changelog names the CVEs but no item passes:

- If an item that names a CVE has a word from test 3, the result is CHECK
  FAILED, whatever the version.
- If any other item names a CVE without passing tests 1 and 2, for example a
  newer "Undo the CVE-2026-109618 changes", there is no changelog PASS, even
  if an older item states the fix. That item is the one quoted, and the
  version decides.
- If the CVEs are only mentioned, as in "New upstream version 8.3.36
  (CVE-2026-109618, CVE-2026-109619)", the version decides: PASS at or after
  the fix, CHECK FAILED below it.
- If only one CVE has an accepted fix, the result is CHECK FAILED.

Every changelog PASS names the changelog file and quotes the item, and asks
a person to confirm it. **This is a careful reading of plain text, not an
understanding of it.** The tool matches wording; an unusual changelog can
still mislead it. That is why the quote is there.

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

### On a Mac

The macOS host check follows the same steps, with two differences. It finds
running programs with `lsof`, because macOS has no `/proc`. And it decides
by version alone, because Homebrew, MacPorts and app bundles keep no
changelog of CVE fixes on the Mac. See the [macOS guide](macos-guide.md).

## 6. Why "CHECK FAILED" is a good answer

It can feel unhelpful when a tool says "I could not tell". But a wrong
answer is worse:

- A wrong **PASS** leaves a broken server unfixed.
- A wrong **FAIL** wastes effort, and can damage trust in every other
  result.

Each CHECK FAILED line says exactly what was missing and what to do next.
The tools are built so that every PASS and every FAIL can be defended from
the evidence printed on the same line.
