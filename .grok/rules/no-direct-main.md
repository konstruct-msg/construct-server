# No direct commits to main

**Forbidden:** `git commit` or `git push` while on `main` / `master`, and any
push that updates `origin/main` from a non-PR path (including
`git push origin HEAD:main` or merging locally then pushing `main`).

**Required workflow:**

1. Create a topic branch (`feat/`, `fix/`, `chore/`, `docs/`, …) from current `main`
2. Commit only on that branch
3. Push the branch and open a PR targeting `main`
4. Land via PR merge (prefer squash)

If the working tree is dirty on `main`, switch to a new branch before committing.
There is no agent exception for “tiny” or “docs-only” changes.
