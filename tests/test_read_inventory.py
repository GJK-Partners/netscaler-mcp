"""1.1 B.3, completeness (S-4): every file operation of the product goes
through `nsmcp.localpath`, mechanically proven instead of promised.

1. A static inventory over `src/nsmcp/*.py` (an AST walk, not a text search):
   every call of `open`, `io.open`, `os.open`, `os.fdopen`, `Path.open`
   (any `.open(...)`), `read_text`, `read_bytes`, `write_text`,
   `write_bytes`, `json.load`, `shutil.copy*`/`shutil.move`, `os.replace`,
   `os.rename` and `Path.rename`/`Path.replace` (a `.rename(...)` call, and a
   `.replace(...)` call with exactly one positional argument and no keyword:
   the shape of `Path.replace(target)`; `str.replace` takes two, a
   `datetime`/dataclass `replace` takes keywords). Every finding must be in
   `localpath.py` or in `PYTHON_EXCEPTIONS` below - with its reason and the
   number of the pinned exception of B.3 it falls under. A new finding fails.
2. A PowerShell inventory over `scripts/*.ps1` (a regular expression over
   the lines that are not comments): `Get-Content`, `Get-FileHash`,
   `Set-Content`, `Add-Content`, `Out-File`, `[System.IO.File]::`,
   `[System.IO.FileStream]`, `Import-Csv`, `Get-Item` and `Set-SFTPItem ...
   -Path`. The PowerShell route (`Open-GjkLokaalBestand`) is part 3 of this
   batch: the findings of today are pinned here by count and marked
   `deel 3`; part 3 takes them out.
3. The runtime seam check is the `open_audit` fixture in tests/conftest.py;
   `runtime_exception` below is the one list it consults.

The four exceptions of B.3, the only ones (any other is a review point):
1. the import system and the files of the installed environment;
2. the EXECUTION of pinned scripts by powershell.exe;
3. files an external process reads on its own authority (Posh-SSH, Windows);
4. standard input and output and the pipes of child processes.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRODUCT = ROOT / "src" / "nsmcp"
SCRIPTS = ROOT / "scripts"


@dataclass(frozen=True)
class Exempt:
    file: str
    function: str
    call: str
    number: int
    reason: str
    # At run time only an open of a path ending in this text is exempt (the
    # red review of part 2, F-4: not every open of the function).
    path_suffix: str = ""


PYTHON_EXCEPTIONS: tuple[Exempt, ...] = (
    Exempt(
        "knowledge_regression.py",
        "engine_identity",
        "distribution.read_text",
        1,
        "`importlib.metadata` reads `direct_url.json` of this engine's own installed distribution: a file of the"
        " installed environment, not data a customer supplies; the installation place falls under the existing"
        " management boundary in SECURITY.md",
        "direct_url.json",
    ),
)

# scripts/*.ps1: (script, operation) -> count. All of them are the PowerShell
# route of part 3 (`Open-GjkLokaalBestand`, B.2); none is a pinned exception.
POWERSHELL_PART_3: dict[tuple[str, str], int] = {
    ("Get-GjkPoshSshManifest.ps1", "[System.IO.File]::"): 1,
    ("GjkUpgrade-Ssh.ps1", "[System.IO.File]::"): 1,
    ("GjkUpgrade-Ssh.ps1", "Set-SFTPItem -Path"): 1,
    ("Invoke-GjkUpgradeFase.ps1", "Get-Content"): 2,
    ("Invoke-GjkUpgradeFase.ps1", "Get-FileHash"): 1,
    ("Invoke-GjkUpgradeFase.ps1", "Get-Item"): 1,
}
POWERSHELL_PART_3_MARK = "deel 3"

# Herstelronde 1 (I-1 of the red review): metadata questions and listings BY
# NAME count too - they follow a link to a share before the walk refuses it
# (measured: 21 s and an SMB contact per call). What remains outside
# `localpath`, by (file, function, call) with its count and reason:
_START_CHECK = (
    "the start check of the configuration (no reading tool, before the server answers); its walk with the root"
    " rule of every approved directory is M-3 of the red review of part 2, part 3"
)
METADATA_EXCEPTIONS: dict[tuple[str, str, str], tuple[int, str]] = {
    ("knowledge_regression.py", "engine_identity", "Path(nsmcp.__file__).resolve"): (
        1,
        "exception 1: the place of this engine's own installed package (the regression runner compares it with"
        " the recorded commit); the installed environment, no customer data",
    ),
    ("knowledge_regression.py", "engine_identity", "root / 'src'.resolve"): (
        1,
        "exception 1: the source directory of this engine's own checkout, beside the installed package",
    ),
    ("start.py", "_onderhoud_config", "runner.is_file"): (1, _START_CHECK),
    ("start.py", "_onderhoud_config", "ledgermap.is_dir"): (1, _START_CHECK),
    ("start.py", "_comparable", "path.resolve"): (1, _START_CHECK),
    ("start.py", "_comparable", "Path(plain).resolve"): (1, _START_CHECK),
    ("start.py", "_lies_within", "os.stat"): (2, _START_CHECK),
    ("start.py", "_lies_within", "inner.resolve"): (1, _START_CHECK),
    ("start.py", "_check_code_path", "path.is_dir"): (1, _START_CHECK),
    ("start.py", "build_server_from_config", "path.resolve"): (3, _START_CHECK),
    ("start.py", "build_server_from_config", "fixture_dir.is_dir"): (1, _START_CHECK),
    ("start.py", "build_server_from_config", "export_dir.exists"): (1, _START_CHECK),
    ("start.py", "build_server_from_config", "export_dir.is_dir"): (2, _START_CHECK),
}

_ANY_BASE = frozenset({"open", "read_text", "read_bytes", "write_text", "write_bytes", "fdopen", "rename"})
# Metadata and listings by name (herstelronde 1): any base.
_METADATA = frozenset(
    {"exists", "is_file", "is_dir", "is_symlink", "glob", "rglob", "iterdir", "resolve", "stat", "lstat", "mkdir"}
)
_OS = frozenset(
    {
        "open",
        "fdopen",
        "replace",
        "rename",
        "renames",
        "scandir",
        "listdir",
        "stat",
        "lstat",
        "mkdir",
        "makedirs",
        "walk",
    }
)
# The `os.path` functions that ask the file system (the others are text only:
# `join`, `abspath`, `normcase`, `samestat` on two results already in hand).
_OS_PATH = frozenset(
    {
        "exists",
        "lexists",
        "isfile",
        "isdir",
        "islink",
        "ismount",
        "getsize",
        "getmtime",
        "getatime",
        "getctime",
        "realpath",
        "samefile",
    }
)
_SHUTIL = re.compile(r"copy.*|move")


def _flagged(call: ast.Call, imported: dict[str, tuple[str, str]]) -> str | None:
    """The text of a file operation this inventory counts, or None."""
    function = call.func
    if isinstance(function, ast.Name):
        origin, name = imported.get(function.id, (None, function.id))
        if name == "open" and origin is None:
            return "open"
        if origin in ("os", "io") and name in _OS | {"open"}:
            return f"{origin}.{name}"
        if origin == "shutil" and _SHUTIL.fullmatch(name):
            return f"shutil.{name}"
        if origin == "json" and name == "load":
            return "json.load"
        if origin == "os.path" and name in _OS_PATH:
            return f"os.path.{name}"
        return None
    if not isinstance(function, ast.Attribute):
        return None
    base = ast.unparse(function.value)
    attribute = function.attr
    module = imported.get(base, (base, base))[1] if base in imported else base
    if module in ("os", "io") and attribute in _OS | {"open"}:
        return f"{module}.{attribute}"
    if module == "os.path" and attribute in _OS_PATH:
        return f"os.path.{attribute}"
    if module == "shutil" and _SHUTIL.fullmatch(attribute):
        return f"shutil.{attribute}"
    if module == "json" and attribute == "load":
        return "json.load"
    if attribute in _ANY_BASE or attribute in _METADATA:
        return f"{base}.{attribute}"
    if attribute == "replace" and len(call.args) == 1 and not call.keywords:
        return f"{base}.replace"
    return None


def scan_python(source: str) -> list[tuple[str, str, int]]:
    """(function, call, line) for every counted file operation in `source`."""
    tree = ast.parse(source)
    imported: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("os", "io", "shutil", "json", "os.path"):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module, alias.name)
        if isinstance(node, ast.Import):
            # `import os as x` (the red review: the first scanner missed that form)
            for alias in node.names:
                if alias.name in ("os", "io", "shutil", "json", "os.path") and alias.asname:
                    imported[alias.asname] = (alias.name, alias.name)
    found: list[tuple[str, str, int]] = []
    stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def _scoped(self, node):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

        def visit_Call(self, node: ast.Call):
            text = _flagged(node, imported)
            if text is not None:
                found.append((".".join(stack) or "<module>", text, node.lineno))
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def python_findings() -> Counter:
    counted: Counter = Counter()
    for path in sorted(PRODUCT.glob("*.py")):
        if path.name == "localpath.py":
            continue
        for function, call, _line in scan_python(path.read_text(encoding="utf-8")):
            counted[(path.name, function, call)] += 1
    return counted


_PS_OPERATIONS = (
    ("Get-Content", re.compile(r"\bGet-Content\b")),
    ("Get-FileHash", re.compile(r"\bGet-FileHash\b")),
    ("Set-Content", re.compile(r"\bSet-Content\b")),
    ("Add-Content", re.compile(r"\bAdd-Content\b")),
    ("Out-File", re.compile(r"\bOut-File\b")),
    ("[System.IO.File]::", re.compile(r"\[System\.IO\.File\]::", re.IGNORECASE)),
    ("[System.IO.FileStream]", re.compile(r"\[System\.IO\.FileStream\]", re.IGNORECASE)),
    ("Import-Csv", re.compile(r"\bImport-Csv\b")),
    ("Get-Item", re.compile(r"\bGet-Item\b(?!Property)")),
    ("Set-SFTPItem -Path", re.compile(r"\bSet-SFTPItem\b.*\s-Path\b")),
)


def scan_powershell(text: str) -> Counter:
    counted: Counter = Counter()
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if in_block:
            in_block = "#>" not in stripped
            continue
        if stripped.startswith("<#"):
            in_block = "#>" not in stripped
            continue
        if stripped.startswith("#"):
            continue
        for name, pattern in _PS_OPERATIONS:
            counted[name] += len(pattern.findall(line))
    return +counted


def powershell_findings() -> dict[tuple[str, str], int]:
    found: dict[tuple[str, str], int] = {}
    for path in sorted(SCRIPTS.glob("*.ps1")):
        for name, count in scan_powershell(path.read_text(encoding="utf-8")).items():
            found[(path.name, name)] = count
    return found


# Exception 4 at run time: `subprocess` opens the null device for a child's
# standard input (`stdin=subprocess.DEVNULL`, `handelen.start_detached`, the
# collector and the presenters). That is no file the product reads or
# writes: it is the standard input of a child process.
RUNTIME_NULL_DEVICE = Exempt(
    "subprocess",
    "Popen",
    "os.open(os.devnull)",
    4,
    "the null device as the standard input of a child process (`subprocess.DEVNULL`): no file, no product read",
)


def runtime_exception(module: str, function: str, path: str = "") -> bool:
    """For the audit hook in tests/conftest.py: may this product function
    open this path (a pinned exception)?"""
    import os

    if path and os.path.normcase(path) == os.path.normcase(os.devnull):
        return True
    return any(
        e.file == module and e.function == function and (not e.path_suffix or path.endswith(e.path_suffix))
        for e in PYTHON_EXCEPTIONS
    )


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


def _allowed() -> Counter:
    allowed = Counter({(e.file, e.function, e.call): 1 for e in PYTHON_EXCEPTIONS})
    for key, (count, _reason) in METADATA_EXCEPTIONS.items():
        allowed[key] += count
    return allowed


def test_every_python_file_operation_is_in_localpath_or_a_pinned_exception():
    allowed = _allowed()
    found = python_findings()
    new = {key: count for key, count in found.items() if count > allowed.get(key, 0)}
    assert new == {}, (
        "bestandsbewerkingen buiten nsmcp.localpath en buiten de vastgepinde uitzonderingen:\n"
        + "\n".join(f"  {file}:{function}: {call} x{count}" for (file, function, call), count in sorted(new.items()))
    )


def test_every_pinned_python_exception_is_still_there_and_names_its_reason():
    found = python_findings()
    for exempt in PYTHON_EXCEPTIONS:
        assert found[(exempt.file, exempt.function, exempt.call)] == 1, f"verouderde uitzondering: {exempt}"
        assert exempt.number in (1, 2, 3, 4), exempt
        assert len(exempt.reason) > 40, exempt
    for key, (count, reason) in METADATA_EXCEPTIONS.items():
        assert found[key] == count, f"verouderde of gewijzigde metadata-uitzondering: {key}"
        assert len(reason) > 40, key


def test_the_inventory_counts_the_reads_the_spec_names():
    """The scanner itself, on a source that does every counted thing once
    (and the look-alikes that are not file operations)."""
    source = (
        "import json, os, shutil\n"
        "from pathlib import Path\n"
        "from os import replace as swap\n"
        "def lezer(p, s, moment, rij):\n"
        "    open(p)\n"
        "    os.open(p, 0)\n"
        "    os.fdopen(3)\n"
        "    Path(p).open()\n"
        "    Path(p).read_text()\n"
        "    p.read_bytes()\n"
        "    p.write_text('x')\n"
        "    p.write_bytes(b'x')\n"
        "    json.load(p)\n"
        "    shutil.copyfile(p, p)\n"
        "    shutil.copy2(p, p)\n"
        "    os.replace(p, p)\n"
        "    os.rename(p, p)\n"
        "    swap(p, p)\n"
        "    p.rename(p)\n"
        "    p.replace(p)\n"
        "    s.replace('a', 'b')\n"
        "    moment.replace(tzinfo=None)\n"
        "    json.loads(s)\n"
    )
    calls = [call for _function, call, _line in scan_python(source)]
    assert len(calls) == 16, calls
    metadata = (
        "import os as besturing\n"
        "import os.path\n"
        "from os.path import isdir\n"
        "def kijker(p, d):\n"
        "    p.exists()\n"
        "    p.is_file()\n"
        "    p.is_dir()\n"
        "    d.glob('*.jsonl')\n"
        "    d.rglob('*')\n"
        "    d.iterdir()\n"
        "    p.resolve()\n"
        "    p.stat()\n"
        "    p.lstat()\n"
        "    d.mkdir(parents=True, exist_ok=True)\n"
        "    besturing.listdir(d)\n"
        "    besturing.scandir(d)\n"
        "    os.path.exists(p)\n"
        "    isdir(d)\n"
        "    besturing.open(p, 0)\n"
        "    os.path.join(d, 'x')\n"
        "    os.path.normcase(p)\n"
    )
    seen = [call for _function, call, _line in scan_python(metadata)]
    assert len(seen) == 15, seen
    assert "os.listdir" in seen and "os.open" in seen and "os.path.exists" in seen and "os.path.isdir" in seen
    assert not any("join" in call or "normcase" in call for call in seen)
    assert "s.replace" not in calls and "moment.replace" not in calls and "json.loads" not in calls


def test_a_new_read_text_outside_localpath_is_a_new_finding(monkeypatch, tmp_path):
    """The mutation of B.5, on a copy: one `read_text` added to a product
    module makes the inventory report exactly that line."""
    import shutil

    copy = tmp_path / "nsmcp"
    shutil.copytree(PRODUCT, copy, ignore=shutil.ignore_patterns("__pycache__"))
    with (copy / "export.py").open("a", encoding="utf-8") as stream:
        stream.write("\n\ndef _mutant(p):\n    return p.read_text()\n")
    monkeypatch.setattr(__import__(__name__), "PRODUCT", copy)
    allowed = _allowed()
    new = {key for key, count in python_findings().items() if count > allowed.get(key, 0)}
    assert new == {("export.py", "_mutant", "p.read_text")}


def test_every_powershell_file_operation_is_counted_and_marked_for_part_3():
    assert powershell_findings() == POWERSHELL_PART_3, (
        "de PowerShell-inventaris wijkt af: een nieuwe vondst gaat door Open-GjkLokaalBestand (deel 3) of"
        " staat met reden in de uitzonderingslijst"
    )
    assert POWERSHELL_PART_3_MARK == "deel 3"


def test_the_powershell_scanner_skips_comments_and_counts_the_operations():
    text = (
        "# Get-Content in een commentaar telt niet\n"
        "<#\n"
        "Get-FileHash in een blokcommentaar ook niet\n"
        "#>\n"
        "$a = Get-Content -LiteralPath $p\n"
        "$h = (Get-FileHash -LiteralPath $p).Hash\n"
        "Set-SFTPItem -SFTPSession $s -Path $p -Destination $d\n"
        "$i = Get-ItemProperty -LiteralPath $p\n"
        "[System.IO.File]::ReadAllBytes($p)\n"
    )
    assert scan_powershell(text) == Counter(
        {"Get-Content": 1, "Get-FileHash": 1, "Set-SFTPItem -Path": 1, "[System.IO.File]::": 1}
    )


def test_the_runtime_check_flags_a_product_open_by_path_and_never_a_localpath_read(tmp_path):
    """The audit hook of tests/conftest.py, proven on itself: code that runs
    as product code (compiled under a file name in src/nsmcp) and opens a
    file by path is a violation; a `localpath` read of the same file raises
    no `open` event at all; the null device of a child's standard input is
    exception 4."""
    import os
    import subprocess
    import sys

    import conftest

    from nsmcp import localpath

    target = tmp_path / "x.txt"
    target.write_bytes(b"x")
    product_code = compile(
        "def lees(p):\n    with open(p, 'rb') as stream:\n        return stream.read()\n"
        "def kind():\n    import subprocess, sys\n"
        "    subprocess.run([sys.executable, '-c', 'pass'], stdin=subprocess.DEVNULL, check=True)\n",
        str(PRODUCT / "export.py"),
        "exec",
    )
    namespace: dict = {}
    exec(product_code, namespace)  # noqa: S102 - this test's own constant source, compiled as product code
    conftest._OPEN_AUDIT["violations"] = []
    conftest._OPEN_AUDIT["active"] = True
    try:
        assert namespace["lees"](str(target)) == b"x"
        if sys.platform == "win32":
            assert localpath.read_local(str(target), root=str(tmp_path), max_bytes=10).data == b"x"
        namespace["kind"]()
    finally:
        conftest._OPEN_AUDIT["active"] = False
    violations = list(conftest._OPEN_AUDIT["violations"])
    conftest._OPEN_AUDIT["violations"] = []
    assert len(violations) == 1, violations
    assert violations[0].startswith("export.py:lees opende ") and repr(os.fspath(target)) in violations[0]
    assert subprocess.DEVNULL  # the child above really took the null device
