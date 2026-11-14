# Publishing DanishRecon

A checklist for the maintainer. Run everything from the repository root.

## 0. Before the first public push

- [ ] `LICENSE` names the right copyright holder(s). It currently says
      "The DanishRecon contributors"; the project started as CyberRecon-Pro with another
      author's commits, so agree the wording with them and credit them in the README.
- [ ] Rotate the Gemini API key and the Twilio auth token that were in the old `.env`.
- [ ] `git status` shows no `results/`, `.env`, `*.db`, `*.pcap` or third-party tool folders.

## 1. First push to GitHub

```bash
git add .
git status                 # read the list once
git commit -m "Initial public release: DanishRecon 0.7.0"
git push -u origin main
```

Then check the **Actions** tab: the `tests` workflow must be green.

## 2. Check the package name

Open https://pypi.org/project/danishrecon/ . A 404 means the name is free. If it is taken,
change `name` in `pyproject.toml` (and the `pip install` lines in the README) before going on.

## 3. Build and test locally

```bash
pip install -e ".[dev]"
python -m unittest discover -s tests -v
python -m build                      # creates dist/*.whl and dist/*.tar.gz
twine check dist/*
```

## 4. Dry run on TestPyPI (recommended)

1. Create an account on https://test.pypi.org and enable 2FA.
2. Account settings > API tokens > create a token.
3. Upload and try it in a clean environment:

```bash
twine upload --repository testpypi dist/*          # user: __token__   password: the token
python -m venv /tmp/try && /tmp/try/bin/pip install \
    --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ danishrecon
/tmp/try/bin/danishrecon scan --help
```

## 5. Real PyPI with trusted publishing (no token stored anywhere)

One-time setup:

1. Create an account on https://pypi.org and enable 2FA.
2. https://pypi.org/manage/account/publishing/ > "Add a new pending publisher":
   - PyPI project name: `danishrecon`
   - Owner: `DanishDhanjal15`   Repository: `DanishRecon-Main`
   - Workflow name: `publish.yml`   Environment name: `pypi`
3. On GitHub: Settings > Environments > New environment > `pypi`
   (optionally add yourself as a required reviewer).

Every release after that:

```bash
# 1. bump the version in pyproject.toml AND src/danishrecon/__init__.py
# 2. add a section to docs/CHANGES_AND_ROADMAP.md
git commit -am "Release 0.7.1"
git tag v0.7.1
git push origin main --tags
```

The `publish` workflow builds the package and uploads it to PyPI. A version number can be
published only once, so always bump it.

## 6. After publishing

```bash
pip install danishrecon
danishrecon-preflight
```

- Create a GitHub Release from the tag and paste the changelog section.
- Add repository topics (security, vulnerability-scanner, pentest) so people can find it.

## Versioning

`0.x` while the command line and report formats may still change. Bump the patch number
for fixes (0.7.1), the minor number for features (0.8.0).
