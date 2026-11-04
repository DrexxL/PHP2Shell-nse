# AI assistance

This page says which AI tools helped make this project, what each one did,
and how their work was checked. It is here because readers who rely on these
tools for audits, legal work or forensics should be able to judge where the
code and the words came from.

## Who did what

| Who | What they did |
|---|---|
| **Drexx Laggui** (maintainer) | Set the goals and the rules for the project; chose the audience and the writing style; made the decisions; created and manages the GitHub repositories; merged pull request #1; made the repository public; edited the README credits. |
| **Claude (Anthropic's Opus 5.5)**, working with Codex (OpenAI's Daybreak Blue); the decisions and some audits were run on Anthropic's Fable 5.1 | Wrote the code, the tests and the documentation; ran the tests; researched the advisories; ran the independent audits described below; made the commits on the maintainer's instructions. |
| **External AI reviewers** | Two reviews were forwarded by the maintainer, who identified them as from GPT-6.1 Sol and from Codex (OpenAI's Daybreak Blue). Their findings were checked and fixed; see [CHANGELOG.md](CHANGELOG.md). |

## How the work was checked

AI tools can be confidently wrong, so nothing here was accepted on the word of
the tool that wrote it:

- **Test suites.** Every tool has a self-checking test suite in `tests/`. Each
  suite was also run against a deliberately broken copy of its tool, to make
  sure the tests can fail. See [Testing](docs/testing.md).
- **Independent audits.** Separate AI auditor sessions, which did not write
  the code, reviewed the work against the maintainer's directives and ran
  their own tests. The work was revised until an audit passed it.
- **External reviews.** The two reviews listed above found real problems,
  which were fixed and then tested.
- **Automatic tests on GitHub.** The workflow in `.github/workflows/tests.yml`
  runs the suites on every change, including on a real Mac.

## What this does not mean

These checks lower the risk of mistakes. They do not remove it. The tools have
not been reviewed by a human security specialist line by line. Read the limits
in the [README](README.md#limits) and in each guide before you rely on a
result.

## In the commit history

Early commits end with a `Co-Authored-By: Claude ...` line and a
`Claude-Session` link. Later commits do not: from 4 November 2026, AI help is
recorded on this page instead.
