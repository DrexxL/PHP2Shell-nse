# Updating the rules

Both tools carry a small, dated rule set: the first fixed version on each
PHP branch. If PHP publishes a new advisory for these CVEs, for example a
fix for a new branch, update both tools the same way.

## Where the rules are

| File | What to change |
|---|---|
| `php2shell-hostcheck.sh` | `RULES_DATE="..."` and `declare -A FIXED=(...)` near the top |
| `php2shell-detect.nse` | `local RULES_DATE = "..."` and the `FIXED` table near the top, plus the `rules` text line in `action` and the release list in `description` |

**Example:** in the host check, the rules look like this:

```bash
RULES_DATE="2026-11-04"
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
```

## Steps

1. Read the new advisory from PHP. Note each branch and its first fixed
   version.
2. Open `php2shell-hostcheck.sh`.
3. Change `RULES_DATE` to today's date, written as `YYYY-MM-DD`.
4. Add or change entries in `FIXED`. Write each entry as
   `[branch]=first-fixed-version`.
5. Open `php2shell-detect.nse`.
6. Make the same changes to `RULES_DATE` and `FIXED`.
7. Update the `out.rules` text in `action` so it lists the same versions.
8. Update the version list in the `description` text and in `README.md`.
9. Run both test suites (see [Testing](testing.md)). Update any test that
   expects an old fixed version.
10. Record the change in `CHANGELOG.md`, with the advisory's name and date.

## Rules that are not just a table

Two decisions are written into the code, not the table:

- **Branches older than 8.2 are CHECK FAILED.** This is because sources
  disagree about them. If PHP or the CVE record later settles the question,
  change the branch check in `evaluate` (host check) and `classify` (network
  scan), and say why in `CHANGELOG.md`.
- **Branches newer than the table are CHECK FAILED.** This happens
  automatically for any branch that has no entry in `FIXED`.

## Covering another CVE

These tools cover CVE-2026-109618 and CVE-2026-109619 only. A different
CVE, such as CVE-2026-115560, has different fixed versions and conditions.
Do not add it to these rule tables. Write separate rules and tests for it.
