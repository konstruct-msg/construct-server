# Branch + Pull Request required (no direct main)

**Forbidden**

- `git commit` or `git push` while on `main` / `master`
- Updating `origin/main` outside a GitHub PR merge (including
  `git push origin HEAD:main`, local merge into `main` then push, force-push to `main`)
- Shipping work on a topic branch **without** opening/updating a Pull Request when
  the user asked to commit and/or push

**Required workflow**

1. Create a topic branch (`feat/`, `fix/`, `chore/`, `docs/`, …) from current `main`
2. Commit only on that branch
3. Push the branch and **open a PR targeting `main`** (`gh pr create`), or push more
   commits to the existing PR branch
4. Land via **PR merge on GitHub** (prefer squash)

If the working tree is dirty on `main`, switch to a new branch before committing.
There is no agent exception for “tiny” or “docs-only” changes: always branch + PR.
