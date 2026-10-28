# dep-review

A Claude Code plugin (also usable as a plain Agent Skill in Codex and other skill-aware agents) that reviews PyPI and npm dependency **source** for supply chain attacks before you install or upgrade, and records every verdict in a SQLite database so each package version is reviewed once.

It looks for:

- install-time and import-time execution: `setup.py`, `.pth` files, npm lifecycle scripts, entry-point side effects
- credential harvesting, network exfiltration, encoded payloads, obfuscation
- known live-campaign IOCs (`skills/dep-review/references/known-iocs.md`)
- **text aimed at AI agents**, in several languages: prompt injection telling the reviewer to find nothing, fake chat/tool markup, requests to run commands or leak secrets, hidden Unicode (tag-character smuggling, bidi overrides), and code that drives local AI CLIs with permission bypasses or plants `CLAUDE.md` / `AGENTS.md` / `.mcp.json`

Packages are only ever downloaded and extracted, never installed or executed.

## Install

Claude Code:

```
/plugin marketplace add a4899e/dep-review
/plugin install dep-review@dep-review
```

Codex or another agent that reads `SKILL.md` skills: copy `skills/dep-review/` into that agent's skills directory (for Codex, `~/.codex/skills/`).

Requires Python 3.11+, `sqlite3`, `jq`, `curl`, `git`; `ripgrep` recommended.

## Use

```
/dep-review requests==2.32.3          # one PyPI package
/dep-review left-pad@1.3.0            # one npm package
/dep-review ~/code/my-app             # every unreviewed locked dep in a repo
/dep-review my-app --update           # only versions without a review
/dep-review --status                  # coverage across registered repos
/dep-review impact npm lodash         # which repos use it
```

## The review database

| | Default | Override |
|---|---|---|
| Database | `${XDG_DATA_HOME:-~/.local/share}/dep-review/reviews.db` | `DEP_REVIEW_DB` (or `DEP_REVIEW_HOME` for the directory) |
| Repo registry | `<home>/repos.json` | `DEP_REVIEW_CONFIG` |
| Reviewer name | none; required per record | `"reviewer"` in the record, or `DEP_REVIEW_REVIEWER` |

The schema (`skills/dep-review/scripts/schema.sql`) is applied idempotently, so pointing at an existing database reuses its reviews and a new path starts empty.

To share reviews with a team, keep the database in a git repo and point `DEP_REVIEW_DB` at it; `check-uncommitted.sh` reports which rows a working copy adds, removes or changes, since a binary diff shows none of that. A shared database is only as trustworthy as everyone who can write to it. Treat a `pass` from a reviewer you do not know as a claim, and re-review.

Verdicts are written by `record-review.py` from a JSON file, never through a shell, because review notes quote attacker-written text. A `fail` is sticky: the database itself refuses to replace, downgrade or delete it until a person records a resolution with `resolve-failure.py`, and a failing artifact vetoes its whole release.

Coverage is artifact-level: a version `pass` authorises a locked dependency only when every artifact the lockfile admits (each wheel, sdist, or tarball hash) also has a passing artifact review. See `query-coverage.sh` for the rules.

## Limits

The prompt-injection scanner matches literal phrases in English and seven other language groups, and surfaces any non-Latin-script prose and Latin/Cyrillic homoglyph words for the agent to read. Paraphrased directives, Latin-script languages it has no phrases for, and runtime-assembled strings still get past it, which is why the skill also tells the agent to treat all package text as untrusted data and never let it lower a verdict. An LLM reviewer can still be fooled. This tool reduces supply chain risk; it does not certify a package safe.

## Development

```bash
skills/dep-review/scripts/test-invariants.py      # coverage/authorization rules
skills/dep-review/scripts/test-agent-directives.py  # scanner positives and negatives
```

## License

MIT
