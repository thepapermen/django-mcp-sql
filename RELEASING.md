# Releasing django-mcp-sql

Maintainer runbook: how this repository was created from the source
monorepo, and how to cut a release to PyPI. Deliberately NOT under
`docs/` — the `docs/*.md` package-data glob ships consumer-facing
documentation in the wheel, and this file is maintainer-only.

All packaging tooling (`uv`, `build`) runs on the host. Publishing to PyPI
happens in GitHub Actions via Trusted Publishing (OIDC) — no API tokens.

## 1. One-time: how this repo was created (clean-room, no history)

This repository was created **without importing any git history** from the
source monorepo — the published code is a fresh start. The package
directory became the repo root; the example became `example/`.

From the monorepo, the tracked tree was exported at a single ref with
`git archive` (which emits only the tracked files of one tree — no commit
objects, no history) into a fresh repo created **outside** the monorepo:

```sh
DEST=~/projects/django-mcp-sql            # outside the monorepo
mkdir -p "$DEST/example"
git archive HEAD:source/mcp_sql         | tar -x -C "$DEST"
git archive HEAD:source/mcp_sql_example | tar -x -C "$DEST/example"
cd "$DEST" && git init -b main
```

### Post-extraction fixups (already applied in this repo)

- [x] `example/pyproject.toml`: `[tool.uv.sources]` path `"../mcp_sql"` →
      `".."` and `example/uv.lock` regenerated (`cd example && uv lock`).
- [x] Deleted the italic *"(Pre-extraction, in the monorepo, …)"* notes in
      `README.md` and `example/README.md`.
- [x] `CLAUDE.md`: dropped the monorepo-only `make mcp_sql_test` wording —
      only the standalone `make test` run exists here.
- [x] Uncommented the badges at the top of `README.md`.
- [x] Single co-authored initial commit; `gh repo create thepapermen/
      django-mcp-sql --public --source=. --push`; `.github/workflows/ci.yml`
      green (test matrix + min-versions + build).

## 2. Per release

### Version bump

- [ ] Bump `__version__` in `__init__.py` — the single source;
      `pyproject.toml` reads it via `dynamic = ["version"]` and
      `make test-install` cross-checks the installed dist metadata
      against it.
- [ ] Move the `CHANGELOG.md` `Unreleased` content under a new
      `## <version> - <YYYY-MM-DD>` heading (stamp the publish date).
- [ ] When leaving alpha/beta, update the `Development Status` classifier
      in `pyproject.toml`.

### Build & verify (host-side)

```sh
make test           # standalone suite against a local PG (see README "Development")
make build          # dist/django_mcp_sql-<version>-py3-none-any.whl + .tar.gz
make test-install   # fresh-venv install + import & package-data smoke
```

### Publish — GitHub Actions Trusted Publishing (`.github/workflows/release.yml`)

One-time setup (browser):

- On **pypi.org** and **test.pypi.org**: *Publishing → Add a pending
  publisher* → project `django-mcp-sql`, owner `thepapermen`, repo
  `django-mcp-sql`, workflow `release.yml`, environment `pypi` /
  `testpypi` respectively.
- On GitHub: *Settings → Environments* → create `pypi` and `testpypi`
  (add a required-reviewer rule on `pypi` for a manual gate if desired).

Per release:

```sh
# 1. TestPyPI dry-run — manual workflow run:
gh workflow run release.yml
# verify the dry-run install (pin the exact version; pip never selects a
# pre-release implicitly):
pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ django-mcp-sql==<version>
python -c "import mcp_sql; print(mcp_sql.__version__)"

# 2. Real release — push the tag, which triggers the `pypi` job:
git tag v<version> && git push --tags
```

The example project is never uploaded: `python -m build` runs at the repo
root and builds only the root package, and the example additionally carries
a `Private :: Do Not Upload` classifier that PyPI hard-rejects.
