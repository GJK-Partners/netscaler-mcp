# Contributing

Thanks for looking. This is a small project with a strong opinion about
evidence, so a few things are worth knowing before you write code.

## The three invariants

These are the product's public promise. A change that breaks one of them is
not a trade-off, it is a defect:

1. **Twenty-five of the twenty-seven reading tools never open a socket.**
   `status_ververs` and `status_update_preflight` reach the appliance through
   a child process. The seven writing tools use separate processes too: five
   use the write script, one the phase runner and one its own SSH save
   script. See
   [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Guarded by
   `tests/test_no_network.py` over a real MCP session.
2. **Nothing is `[vastgesteld]` without a successful read.** A source that
   could not be read becomes a read gap with a named reason - never a silent
   green. Guarded by `tests/test_answer.py` and the `Finding` type itself.
3. **The confirmation code never reaches the model.** A writing tool returns a
   proposal without a code; the code goes to the operator through a separate
   channel. Guarded by `tests/test_handelen_zonder_code.py`.

Each of the three has a mutation proof: switch the guard off and a test with a
name fails. If you add a gate of your own, add that proof too.

## Language

- **Code is English**: identifiers, docstrings, comments, test names.
- **The product surface is Dutch**: tool names, tool parameters, answer texts,
  error messages and configuration keys. The customers and their AI assistants
  are Dutch.
- `tests/test_product_surface.py` pins that Dutch surface byte for byte. If you
  change a user-visible sentence on purpose, change the pin in the same commit
  and say why in the commit message. A pin exists to stop accidental drift.
- Code, tests and scripts are ASCII: every tracked file under `src/`,
  `scripts/` and `tests/`, held by `tests/test_repo_hygiene.py`. No em dashes,
  no accented characters, no section signs: this code runs on Windows hosts
  whose PowerShell reads a file without a byte order mark in the ANSI code
  page. A character a test needs goes in as an escape (`"\u00ef"`), which is
  the same string at run time. The Dutch customer documents under
  `docs/klant/` may carry accents.

## Running the tests

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-build.txt
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps --no-build-isolation
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check --no-cache src tests scripts
.\.venv\Scripts\python.exe -m ruff format --check --no-cache src tests scripts
```

The three install lines are the install lines of CI (`.github/workflows/ci.yml`),
in the same order; `tests/test_repo_hygiene.py` holds that both ways. Both
requirements files are hash-locked, so the install fails closed on a
supply-chain mismatch instead of silently resolving something else.
`--no-build-isolation` makes the editable install use exactly the toolchain
of `requirements-build.txt`; without it, pip would fetch setuptools from the
index into a throwaway build environment, outside the hash check.

The suite never writes the real anchor of the pseudonym table: every test
gets an in-memory anchor store (`tests/conftest.py`), and the proofs on the
real HKCU store write only under
`HKCU\Software\GJK\netscaler-mcp\Test\<uuid4>` and remove it. A server you
start yourself at `openheid: beperkt` is different: its first start writes
`HKCU\Software\GJK\netscaler-mcp\vertaaltabel\anker-<slot>` in your own
registry, next to a signed table and a DPAPI key file in the configuration's
directory. For a development table you may remove that `anker-<slot>` key
together with its table and key file; never remove the anchor of a table
that is in use (that is what `python -m nsmcp.disclosure --reset` is for).

## Dependencies: uv.lock and its two exports

`uv.lock` is the one source. Both requirements files are exports of it, each
with an explicit selection, made with uv 0.12.13 (the version whose
`uv export --help` was checked for both option sets):

```powershell
uv export --frozen --all-extras --no-group build --no-emit-project -o requirements-dev.txt
uv export --frozen --only-group build --no-emit-project -o requirements-build.txt
```

`requirements-dev.txt` is the project's dependencies plus the extra `dev`,
never the dependency group `build`; `requirements-build.txt` is only the group
`build` from `[dependency-groups]` in `pyproject.toml` (pip, setuptools, wheel)
and what those ask for. In uv, extras and dependency groups are different
selections - `--all-extras` takes no group along - so each command names its
selection. Run both after every change to `pyproject.toml` or `uv lock`, and
commit `uv.lock` and the two files together.

`tests/test_repo_hygiene.py` computes the closure of each selection from
`uv.lock` and compares it with the export per package on version, markers and
the full hash set, and compares what `uv.lock` records of the project's own
input with `pyproject.toml`.

Dependabot updates `uv.lock` (ecosystem `uv`), not the exports. A Dependabot
pull request therefore fails that comparison, visibly, until a maintainer runs
the two commands above on its branch and commits the result. `mcp` stays
excluded from Dependabot on purpose (see `.github/dependabot.yml`).

Some hygiene guards search the tree for names of the maintainers' own
environment, read from a list outside the tree: the file named in the
environment variable `NSMCP_PRIVATE_NEEDLES`, or an ignored
`.private-needles.txt` in the repository root (see `tests/private_needles.py`).
Without the list those guards skip with a reason (`pytest -rs` shows it). A
maintainer runs the hygiene suite with the list before every release; CI does
the same on every push from the repository secret `NSMCP_PRIVATE_NEEDLES`, and
a pull request from a fork runs without it.

The suite is Windows-only throughout: the collector, the write path,
the confirmation window and the reader all depend on Windows. The
reader imports `nsmcp.disclosure`, which unconditionally imports
`msvcrt` (Windows stdlib), so reading fails at import on Linux or macOS.
See the README's Platform section for the full argument.

## Style

- Write the failing test first, then the smallest change that makes it pass.
- Say WHY in a comment, not what. This codebase is 45% explanation on purpose;
  the measurement behind a choice is worth more than the choice.
- `ruff check` and `ruff format --check` (both over `src tests scripts`, same as
  CI) must pass. The selected rule set is in `pyproject.toml` and is
  deliberately narrow: real defects, not style preferences. Do not reformat
  files you are not otherwise touching.
- One commit per coherent change, with a message that says what was measured.

## Adding something

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces
below fit together; the list below is the short version.

- **A new CVE rule** - `src/nsmcp/cve.py`; the module docstring there explains
  the two-layer verdict (build layer and config layer) and where each
  condition's evidence comes from. Add a fixture that proves both the
  affected and the not-affected verdict.
- **A new tool** - `src/nsmcp/mcp_server.py`, plus its Dutch description in
  `tests/test_product_surface.py`, plus its entry in the no-socket guard.
- **A new confirmation channel** - one branch in
  `code_channel.presenter_for()` and its own presenter. Nothing else changes.
- **A new export source** - `src/nsmcp/export.py`, and a read-gap fixture for
  the case where the source cannot be read.

## Release

The tag equals `version` in `pyproject.toml`. Before tagging: set the date on
the matching `[version]` heading in `CHANGELOG.md` to the tag day, attach the
SBOM artifact (`sbom-<python-version>.cdx.json`, uploaded by CI - see
`.github/workflows/ci.yml`) from the green run being tagged as a release
asset, and do not tag without a green CI run on exactly that commit plus a green
full local suite on the same commit. CI runs on the release branch and on a
pushed `v*` tag (the Windows runner is billed at twice the Linux rate, so not on
master: master receives a fast-forward of a commit that already passed, so it
does not run again). The run on the tag is the run that belongs to the release:
the release notes follow `.github/release-notes-template.md` and name the URL of
that green tag run, and the SBOM assets come from its artifacts.

Open on purpose: the SBOM is a plain workflow artifact, not attested or signed.
A provenance attestation (`actions/attest-build-provenance`) needs the
`id-token: write` permission on the release branch, where CI now runs with
`contents: read` only. Whether to grant that is a maintainer decision, left
open for 1.1; until then the SBOM proves which environment the green run
used, not who built it.

## Reporting a security issue

Do not open an issue. See [SECURITY.md](SECURITY.md).
