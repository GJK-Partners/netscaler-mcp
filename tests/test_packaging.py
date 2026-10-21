"""The packaging metadata is product surface too: it is what a PyPI page and
a distribution builder show. This pins the fields a public release needs, so
a later edit cannot quietly drop the license or the OS classifiers."""

from __future__ import annotations

import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _document() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _project() -> dict:
    return _document()["project"]


def test_the_license_is_declared_as_an_spdx_expression():
    assert _project()["license"] == "Apache-2.0"


def test_the_readme_and_the_authors_are_declared():
    project = _project()
    assert project["readme"] == "README.md"
    assert project["authors"] == [{"name": "GJK Partners"}]


def test_the_project_urls_point_a_visitor_at_the_three_places_that_matter():
    urls = _project()["urls"]
    assert set(urls) == {"Repository", "Issues", "Security"}
    for value in urls.values():
        assert value.startswith("https://github.com/GJK-Partners/netscaler-mcp")


def test_the_classifiers_name_the_windows_half_and_never_claim_os_independence():
    classifiers = _project()["classifiers"]
    # Core metadata 2.4 makes License-Expression and a "License ::" classifier
    # mutually exclusive: setuptools 78+ refuses the combination and PyPI
    # rejects the upload. This project declares the SPDX expression
    # (license = "Apache-2.0"), so no legacy license classifier may remain.
    assert not any(c.startswith("License ::") for c in classifiers)
    assert "Operating System :: Microsoft :: Windows" in classifiers
    # The collector, the write path and the confirmation window are Windows
    # only; "OS Independent" would be a claim this product cannot keep.
    assert "Operating System :: OS Independent" not in classifiers
    assert "Programming Language :: Python :: 3.11" in classifiers
    assert "Programming Language :: Python :: 3.12" in classifiers


def test_the_dev_extra_carries_every_tool_the_gates_use():
    dev = " ".join(_project()["optional-dependencies"]["dev"])
    for tool in ("pytest", "pytest-cov", "ruff", "mypy", "pip-audit"):
        assert tool in dev


def test_the_lint_gate_is_pinned_in_the_project_file_and_not_only_in_ci():
    selected = _document()["tool"]["ruff"]["lint"]["select"]
    # The set that was widened once, deliberately, in the style commit that
    # reformatted the whole tree. Narrowing it silently would make the CI
    # gate meaningless; widening it again is a conscious change to this pin.
    assert selected == ["E", "F", "W", "B", "I", "UP", "S102", "S307", "PLE"]


def test_the_version_is_the_public_one_dot_zero():
    assert _project()["version"] == "1.0.1"


def test_the_changelog_carries_that_same_version():
    changelog = (PYPROJECT.parent / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [1.0.1]" in changelog
