# Contributing this skill to getkern/kern

Use this reference when the requested work changes the Kern source repository or proposes these adapters upstream. GitHub calls the review object a pull request; it is not a GitLab merge request.

## Repository rules read from main

The repository's `.github/PULL_REQUEST_TEMPLATE.md` requires a short “What & why” section and asks the contributor to check:

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features` with CI's `-D warnings`
- `cargo test --all`, with hardware-gated tests skipping only with a reason
- `python3 scripts/no-ai-slop.py`, `scripts/stale-numbers.py`, and `scripts/test-count.py`
- `cargo deny check` and `cargo audit`
- no U+2014 em dash anywhere
- characterization and real-syscall coverage for sandbox or OCI behavior changes
- synthetic, minimal, self-contained security fixtures
- a `CHANGELOG` entry
- agreement with `CLA.md`

`CONTRIBUTING.md` also requires reading `ARCHITECTURE.md`, keeping tests with behavior changes, and running the repository gate script after staging files. The CI workflow is authoritative if the local checkout has moved on.

## Fork and pull request workflow

Use a fork unless the maintainer has granted direct write access:

```sh
git clone https://github.com/YOUR_GITHUB_USER/kern.git
cd kern
git remote add upstream https://github.com/getkern/kern.git
git fetch upstream
git switch -c docs/ai-skill-adapters upstream/main
```

Copy the selected adapter directory into the repository. Keep the Claude Code copy at `.claude/skills/kern/` and the Copilot copy at `.github/skills/kern/`. Do not overwrite an existing project skill without checking its ownership and intended scope.

Run the gates from the repository checkout, review the diff, and make a signed-off commit:

```sh
git add .claude/skills/kern .github/skills/kern CHANGELOG.md
git diff --cached --check
git commit -s -m "docs: add Kern agent skills"
git push -u origin docs/ai-skill-adapters
```

The `-s` flag adds the DCO `Signed-off-by:` line required by `CLA.md`. The CLA Assistant also requires posting exactly:

```text
I have read the CLA Document and I hereby sign the CLA
```

on the pull request when the bot asks.

Create the pull request with `gh` after authenticating, or use GitHub's compare page. Replace the placeholder owner and branch:

```sh
gh pr create --repo getkern/kern --base main --head YOUR_GITHUB_USER:docs/ai-skill-adapters --title "docs: add Kern agent skills" --body-file PR_BODY.md
```

The equivalent browser entry point is `https://github.com/getkern/kern/compare/main...YOUR_GITHUB_USER:docs/ai-skill-adapters?quick_pull=1`. Set the base repository to `getkern/kern`, base branch to `main`, head repository to your fork, and head branch to the feature branch. Do not push to `getkern/kern` unless you have explicit write permission.

## Scope of this adapter proposal

This is documentation and agent-skill content. It should not alter runtime code, security boundaries, CLI behavior, or release automation. For this scope, the sandbox and OCI checklist item is not applicable, but the remaining documentation gates still are. Add a concise changelog entry only if the maintainer wants skill packaging recorded in the next release notes; otherwise ask before changing `CHANGELOG.md`.
