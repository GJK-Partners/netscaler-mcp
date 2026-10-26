"""1.1 D.3: the regression matrix per bulletin.

The synthetic package in tests/fixtures/kennis-regressie/ carries the shapes
the matrix has to cover: a plain predicate, a build-dependent condition
(`vanaf`), a FIPS branch the `vanaf` rule does not name, `altijd`, and a CVE
with `naconfiguratieVerplicht`, over two bulletins on one branch (so the
floor is the higher fix). Its matrix lists the v1.0.3 tag commit and one
1.1.0 commit; the tests stand in the 1.1.0 identity, because a matrix in
this repository cannot name the commit that adds it. A real release matrix
names the released commits (docs/klant/AUTOMATISERING.md).
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import json
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from nsmcp import cve, knowledge_regression
from nsmcp.export import load_export, payload_digest
from nsmcp.knowledge import canonical_digest, load_knowledge, main
from nsmcp.knowledge_regression import EngineIdentity, run_regression
from nsmcp.update_advice import floor_for

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "kennis-regressie"
PACKAGE = FIXTURE / "kennis.json"
MATRIX = FIXTURE / "kennis-regressie.json"
LIVE_EXPORT = ROOT / "tests" / "fixtures" / "lab-export-vpx-20260826"
TODAY = date(2026, 10, 26)
NEEDLE = "naald-3f9a-matrixinhoud"


def _matrix() -> dict:
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def _package() -> dict:
    return json.loads(PACKAGE.read_text(encoding="utf-8"))


def _engine() -> EngineIdentity:
    entry = next(e for e in _matrix()["engines"] if e["versie"] == "1.1.0")
    return EngineIdentity(entry["versie"], entry["commit"])


def _write(tmp_path: Path, name: str, document: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run(tmp_path: Path, package: dict | None = None, matrix: dict | None = None, engine=None, **kwargs):
    package_path = PACKAGE if package is None else _write(tmp_path, "kennis.json", package)
    matrix_path = MATRIX if matrix is None else _write(tmp_path, "kennis-regressie.json", matrix)
    return run_regression(
        package_path, matrix_path, engine=_engine() if engine is None else engine, today=TODAY, **kwargs
    )


def test_the_fixture_matrix_holds_on_this_engine(tmp_path):
    result = _run(tmp_path)
    assert result.refusal == ""
    assert result.passed
    assert len(result.lines) == len(_matrix()["gevallen"]) == 19
    assert all(line.endswith(": klopt") for line in result.lines)


def test_the_fixture_package_belongs_to_the_existing_line():
    """No minimaleEngine: the same package and matrix also run on the 1.0.3
    tag through tools/regressie-1.0.x/."""
    package = _package()
    assert "minimaleEngine" not in package
    assert canonical_digest(package) == _matrix()["pakketdigest"]
    assert not load_knowledge(PACKAGE, TODAY).missing


def test_regression_matrix_requires_full_coverage(tmp_path):
    """Every case of the fixture matrix is needed: drop any one and the
    runner refuses the matrix, naming what is missing, before any case runs."""
    full = _matrix()
    for index in range(len(full["gevallen"])):
        matrix = copy.deepcopy(full)
        del matrix["gevallen"][index]
        result = _run(tmp_path, matrix=matrix)
        assert not result.passed, index
        assert result.lines == (), index
        assert result.refusal.startswith("de matrix dekt het pakket niet volledig; ontbrekend: "), (index, result)
    # Four of them by name.
    named = {
        ("CTX900001", "14.1", "73.20", None): "CTX900001 tak 14.1: de fix-build zelf (73.20)",
        ("CTX900002", "14.1", "73.40", True): (
            "CTX900002 tak 14.1, CVE-2026-90004: naconfiguratie, voorwaarde = true op of boven de fix"
        ),
        (
            "CTX900001",
            "14.1",
            "70.10",
            None,
        ): "CTX900001 tak 14.1, CVE-2026-90002: een build op de vanaf-drempel (70.10)",
        ("CTX900001", "13.1-FIPS", "37.251", None): "CTX900001 tak 13.1-FIPS: een build boven de fix (37.250)",
    }
    for (bulletin, branch, build, http2), phrase in named.items():
        matrix = copy.deepcopy(full)
        matrix["gevallen"] = [
            case
            for case in full["gevallen"]
            if not (
                case["bulletin"] == bulletin
                and case["tak"] == branch
                and case["build"] == build
                and (http2 is None or case["voorwaarden"].get("heeft_http2_profiel") == http2)
            )
        ]
        assert len(matrix["gevallen"]) == len(full["gevallen"]) - 1
        assert phrase in _run(tmp_path, matrix=matrix).refusal, phrase


def _lowered() -> dict:
    package = _package()
    bulletin = package["cve"][1]
    bulletin["getroffen"]["14.1"] = "< 73.39"
    bulletin["fix"]["14.1"] = "73.39"
    return package


def test_regression_matrix_detects_a_lowered_fix(tmp_path):
    """A package whose fix build was lowered (73.40 -> 73.39, coherent with
    its affected range, so every loader check passes) fails its matrix."""
    package = _lowered()
    assert not load_knowledge(_write(tmp_path, "laag.json", package), TODAY).missing
    matrix = _matrix()
    matrix["pakketdigest"] = canonical_digest(package)
    result = _run(tmp_path, package=package, matrix=matrix)
    assert not result.passed
    assert "ontbrekend" in result.refusal
    # And per case, on the same lowered package: the vulnerable 73.39 is now
    # called fixed, and the floor of the branch moved.
    knowledge = load_knowledge(_write(tmp_path, "laag2.json", package), TODAY)
    cases, problem = knowledge_regression._cases(matrix, knowledge)
    assert problem == ""
    failures, lines = knowledge_regression._run_cases(cases, knowledge)
    assert failures > 0
    first_b2 = next(line for line in lines if "(CTX900002, tak 14.1, build 73.39)" in line)
    assert ": wijkt af: CVE-2026-90003 verwacht GERAAKT, engine geeft NIET GERAAKT" in first_b2
    assert "vloer verwacht 14.1-73.40, engine geeft 14.1-73.39" in lines[0]


class _Spy:
    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("een geval draaide")


def test_regression_matrix_refuses_a_digest_or_engine_mismatch_before_any_case(tmp_path, monkeypatch):
    spy = _Spy()
    monkeypatch.setattr(cve, "cve_verdicts", spy)
    monkeypatch.setattr(cve, "imposed_predicates", spy)

    wrong_digest = _matrix()
    wrong_digest["pakketdigest"] = "0" * 64
    changed_package = _package()
    changed_package["cve"][0]["cves"][0]["cvss"] = 9.2
    wrong_version = _matrix()
    wrong_version["pakketversie"] = "regressie-proef-2026.11"
    cases = [
        (
            dict(matrix=wrong_digest),
            "de matrix hoort niet bij dit pakket: pakketdigest is niet de canonieke digest van het aangeboden pakket",
        ),
        (
            dict(package=changed_package),
            "de matrix hoort niet bij dit pakket: pakketdigest is niet de canonieke digest van het aangeboden pakket",
        ),
        (
            dict(matrix=wrong_version),
            "de matrix hoort niet bij dit pakket: pakketversie is niet de versie van het pakket",
        ),
        (
            dict(engine=EngineIdentity("1.1.1", _engine().commit)),
            f"deze engine (versie 1.1.1, commit {_engine().commit}) staat niet in de engines van de matrix",
        ),
        (
            dict(engine=EngineIdentity("1.1.0", "f" * 40)),
            f"deze engine (versie 1.1.0, commit {'f' * 40}) staat niet in de engines van de matrix",
        ),
        (
            # The 1.0.3 pair is in the matrix, but not as the 1.1.0 engine.
            dict(engine=EngineIdentity("1.1.0", "41c85229edb6b9f78983fef09d03ebd15ef85641")),
            "deze engine (versie 1.1.0, commit 41c85229edb6b9f78983fef09d03ebd15ef85641) staat niet in de engines"
            " van de matrix",
        ),
    ]
    for arguments, reason in cases:
        result = _run(tmp_path, **arguments)
        assert result.refusal == reason, arguments
        assert result.lines == ()
    unknown = run_regression(PACKAGE, MATRIX, engine=None, engine_reason="geen commit", today=TODAY)
    assert unknown.refusal == "de draaiende engine is niet vast te stellen: geen commit"
    assert spy.calls == 0


def _first_case(**change) -> dict:
    matrix = _matrix()
    matrix["gevallen"][0].update(change)
    return matrix


def test_the_matrix_refuses_a_case_that_does_not_fit_the_package(tmp_path):
    expectations = [
        (_first_case(bulletin="CTX999999"), "regressiematrix: gevallen[0].bulletin noemt geen bulletin uit het pakket"),
        (
            _first_case(verwacht={"CVE-2026-90001": "GERAAKT"}),
            "regressiematrix: gevallen[0].verwacht noemt niet precies de CVE's van dit bulletin",
        ),
        (
            _first_case(voorwaarden={"heeft_gateway_vserver": True, "heeft_saml_action": True, "altijd": True}),
            "regressiematrix: gevallen[0].voorwaarden noemt iets dat geen op te leggen predicaat is"
            " (toegestaan: de predicaten van deze engine behalve altijd)",
        ),
        (
            _first_case(voorwaarden={"heeft_gateway_vserver": True, "heeft_saml_action": True, "is_saml_idp": True}),
            "regressiematrix: gevallen[0].voorwaarden noemt een predicaat dat in geen CVE van dit bulletin staat",
        ),
        (
            _first_case(voorwaarden={"heeft_gateway_vserver": True}),
            "regressiematrix: gevallen[0].voorwaarden mist de waarde van heeft_saml_action, de voorwaarde van"
            " CVE-2026-90002 op deze build",
        ),
    ]
    for matrix, reason in expectations:
        assert _run(tmp_path, matrix=matrix).refusal == reason


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda m: m.update(extra=NEEDLE), "regressiematrix: het document draagt precies de sleutels"),
        (lambda m: m.update(pakketdigest=NEEDLE), "regressiematrix: pakketdigest is geen digest"),
        (
            lambda m: m["engines"][0].update(commit=NEEDLE),
            "regressiematrix: engines[0].commit is geen volledige commit",
        ),
        (lambda m: m["engines"][0].update(versie=NEEDLE), "regressiematrix: engines[0].versie heeft niet de vorm"),
        (lambda m: m.update(engines=[]), "regressiematrix: engines moet een niet-lege lijst zijn"),
        (lambda m: m.update(gevallen=[]), "regressiematrix: gevallen moet een niet-lege lijst zijn"),
        (lambda m: m["gevallen"][1].update(tak=NEEDLE), "regressiematrix: gevallen[1].tak heeft niet de vorm"),
        (lambda m: m["gevallen"][1].update(build="73"), "regressiematrix: gevallen[1].build heeft niet de vorm X.Y"),
        (lambda m: m["gevallen"][1].update(build="\uff17\uff13.19"), "regressiematrix: gevallen[1].build heeft niet"),
        (
            lambda m: m["gevallen"][1]["voorwaarden"].update(heeft_gateway_vserver=1),
            "regressiematrix: gevallen[1].voorwaarden draagt een waarde die niet true, false of onleesbaar is",
        ),
        (
            lambda m: m["gevallen"][1]["verwacht"].update({"CVE-2026-90001": NEEDLE}),
            "regressiematrix: gevallen[1].verwacht draagt een oordeel dat niet",
        ),
        (lambda m: m["gevallen"][1].update(verwachteVloer=NEEDLE), "regressiematrix: gevallen[1].verwachteVloer"),
        (lambda m: m["gevallen"][1].update({NEEDLE: 1}), "regressiematrix: gevallen[1] draagt precies de sleutels"),
    ],
)
def test_the_matrix_shape_is_strict_and_never_echoes_a_value(tmp_path, change, reason):
    matrix = _matrix()
    change(matrix)
    result = _run(tmp_path, matrix=matrix)
    assert result.refusal.startswith(reason), result.refusal
    assert NEEDLE not in result.refusal
    assert "\n" not in result.refusal


# ---------------------------------------------------------------------------
# The seam
# ---------------------------------------------------------------------------


def test_the_predicate_seam_is_reached_only_by_the_regression_runner():
    """No configuration, ledger or server path can impose a condition: the
    seam's names occur in cve.py (its owner) and the regression runner only."""
    names = {"imposed_predicates", "_IMPOSED_PREDICATES"}
    users = set()
    for path in sorted((ROOT / "src" / "nsmcp").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Name) and node.id in names) or (
                isinstance(node, ast.Attribute) and node.attr in names
            ):
                users.add(path.name)
    assert users == {"cve.py", "knowledge_regression.py"}
    # And only the --regressie branch of the knowledge CLI imports the runner.
    importers = set()
    for path in sorted((ROOT / "src" / "nsmcp").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and any(alias.name == "knowledge_regression" for alias in node.names):
                importers.add(path.name)
            if isinstance(node, (ast.Import, ast.ImportFrom)) and "knowledge_regression" in (
                getattr(node, "module", None) or ""
            ):
                importers.add(path.name)
            if isinstance(node, ast.Import) and any("knowledge_regression" in alias.name for alias in node.names):
                importers.add(path.name)
    assert importers == {"knowledge.py"}


def test_the_seam_refuses_a_condition_the_case_does_not_state():
    export = load_export(LIVE_EXPORT)
    with cve.imposed_predicates({"heeft_saml_action": "aanwezig"}):
        assert cve.evaluate_predicate(export, "heeft_saml_action") == ("aanwezig", cve.IMPOSED_EVIDENCE)
        assert cve.evaluate_predicate(export, "altijd")[0] == "aanwezig"
        with pytest.raises(cve.PredicateNotImposed):
            cve.evaluate_predicate(export, "heeft_gateway_vserver")
    # Outside the block the export is read again.
    assert cve.evaluate_predicate(export, "heeft_saml_action")[1] != cve.IMPOSED_EVIDENCE
    with pytest.raises(ValueError):
        with cve.imposed_predicates({"heeft_saml_action": "ja"}):
            pass


# ---------------------------------------------------------------------------
# End to end on the existing fixtures: the seam and the real export agree
# ---------------------------------------------------------------------------


def _with_version(tmp_path: Path, version: str) -> Path:
    target = tmp_path / "export"
    shutil.copytree(LIVE_EXPORT, target)
    path = target / "objects" / "nsversion.json"
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    document["nsversion"]["version"] = version
    raw = json.dumps(document, indent=2).encode("utf-8")
    path.write_bytes(raw)
    manifest_path = target / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    manifest["resources"]["config/nsversion"]["payloadSha256"] = payload_digest(raw).upper()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return target


def _seam_agrees_with_the_export(export, branch: str, build: tuple[int, int]):
    knowledge = load_knowledge(PACKAGE, TODAY)
    for bulletin in knowledge.cve:
        only = dataclasses.replace(knowledge, cve=(bulletin,))
        records, _ = cve.cve_verdicts(export, only)
        real = {str(entry["id"]): record.verdict for entry, record in zip(bulletin["cves"], records, strict=True)}
        needed = {knowledge_regression._effective(entry["voorwaarde"], branch, build) for entry in bulletin["cves"]}
        conditions = {name: cve.evaluate_predicate(export, name)[0] for name in needed - {None, "altijd"}}
        floor = floor_for(branch, knowledge)
        case = knowledge_regression._Case(
            number=1,
            bulletin=str(bulletin["bulletin"]),
            branch=branch,
            build=build,
            conditions=conditions,
            expected=real,
            floor=f"{branch}-{floor[0]}" if floor else None,
        )
        held, line = knowledge_regression._run_case(case, knowledge)
        assert held, line
        yield real


def test_end_to_end_on_the_plain_branch_of_the_lab_export():
    export = load_export(LIVE_EXPORT)
    verdicts = {}
    for real in _seam_agrees_with_the_export(export, "14.1", (72, 57)):
        verdicts.update(real)
    # 72.57 is below both fixes; altijd is present.
    assert verdicts["CVE-2026-90003"] == cve.GERAAKT
    assert set(verdicts) == {"CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003", "CVE-2026-90004"}


def test_end_to_end_on_the_fips_branch(tmp_path):
    version = "NetScaler NS13.1: Build 37.249.nc, Date: Jun 3 2026, 09:12:11   (64-bit) (NS13.1-FIPS)"
    export = load_export(_with_version(tmp_path, version))
    verdicts = {}
    for real in _seam_agrees_with_the_export(export, "13.1-FIPS", (37, 249)):
        verdicts.update(real)
    # The vanaf rule does not name the FIPS branch; CTX900002 does not name it.
    assert verdicts["CVE-2026-90002"] == cve.NIET_VASTGESTELD
    assert verdicts["CVE-2026-90003"] == verdicts["CVE-2026-90004"] == cve.NIET_VASTGESTELD


def test_end_to_end_with_unknown_platform_information(tmp_path):
    """A version string whose train marker contradicts its own build: no
    matrix case can state this (a case names a branch); the engine calls
    every CVE NIET VASTGESTELD with the platform as the reason."""
    version = "NetScaler NS14.1: Build 72.57.nc, Date: May 21 2026, 18:20:32   (64-bit) (NS13.1-FIPS)"
    export = load_export(_with_version(tmp_path, version))
    records, gaps = cve.cve_verdicts(export, load_knowledge(PACKAGE, TODAY))
    assert [record.verdict for record in records] == [cve.NIET_VASTGESTELD] * 4
    assert any(gap.source == "config/nsversion" for gap in gaps)


# ---------------------------------------------------------------------------
# The CLI and the engine identity
# ---------------------------------------------------------------------------


def test_the_regression_command_runs_the_matrix(monkeypatch, capsys):
    monkeypatch.setattr(knowledge_regression, "engine_identity", lambda: (_engine(), ""))
    assert main(["--regressie", str(PACKAGE), str(MATRIX)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 20
    assert out[-1] == f"regressiematrix: 19 gevallen, alle kloppen (engine 1.1.0, commit {_engine().commit})"


def test_the_regression_command_refuses_on_an_engine_it_cannot_place(tmp_path, capsys):
    """With the real identity: either the commit of this checkout cannot be
    established, or it is not the one in the matrix - refused either way."""
    matrix = _matrix()
    matrix["engines"] = [{"versie": "1.1.0", "commit": "0" * 40}]
    path = _write(tmp_path, "kennis-regressie.json", matrix)
    assert main(["--regressie", str(PACKAGE), str(path)]) == 1
    printed = capsys.readouterr()
    assert printed.out == ""
    assert printed.err.startswith("regressiematrix geweigerd: ")


class _Distribution:
    def __init__(self, version: str, direct_url: str | None):
        self.version = version
        self._direct_url = direct_url

    def read_text(self, name: str):
        assert name == "direct_url.json"
        return self._direct_url


def _identity_with(monkeypatch, distribution, git=None):
    monkeypatch.setattr(knowledge_regression.importlib.metadata, "distribution", lambda name: distribution)
    if git is not None:
        monkeypatch.setattr(knowledge_regression, "_run_git", git)
    return knowledge_regression.engine_identity()


def test_the_engine_identity_comes_from_the_installation(monkeypatch):
    commit = "a" * 40
    vcs = json.dumps({"url": "https://example.invalid/r.git", "vcs_info": {"vcs": "git", "commit_id": commit}})
    assert _identity_with(monkeypatch, _Distribution("1.1.0", vcs)) == (EngineIdentity("1.1.0", commit), "")
    # Wheel or copied directory: no commit.
    identity, reason = _identity_with(monkeypatch, _Distribution("1.1.0", None))
    assert identity is None and "gepinde commit" in reason
    plain_dir = json.dumps({"url": ROOT.as_uri(), "dir_info": {}})
    assert _identity_with(monkeypatch, _Distribution("1.1.0", plain_dir))[0] is None
    # A version that is not the engine's own.
    assert _identity_with(monkeypatch, _Distribution("1.0.3", vcs))[0] is None
    short = json.dumps({"url": "x", "vcs_info": {"vcs": "git", "commit_id": "abc123"}})
    assert _identity_with(monkeypatch, _Distribution("1.1.0", short))[0] is None


def test_an_editable_checkout_counts_only_when_its_code_is_its_commit(monkeypatch):
    editable = json.dumps({"url": ROOT.as_uri(), "dir_info": {"editable": True}})
    head = "b" * 40

    def clean(root, *arguments):
        assert Path(root) == ROOT
        return head + "\n" if arguments[0] == "rev-parse" else ""

    def dirty(root, *arguments):
        return head + "\n" if arguments[0] == "rev-parse" else " M src/nsmcp/cve.py\n"

    assert _identity_with(monkeypatch, _Distribution("1.1.0", editable), clean) == (EngineIdentity("1.1.0", head), "")
    identity, reason = _identity_with(monkeypatch, _Distribution("1.1.0", editable), dirty)
    assert identity is None and "wijkt af van zijn commit" in reason
    elsewhere = json.dumps({"url": (ROOT / "elders").as_uri(), "dir_info": {"editable": True}})
    identity, reason = _identity_with(monkeypatch, _Distribution("1.1.0", elsewhere), clean)
    assert identity is None and "niet uit de checkout" in reason
    assert _identity_with(monkeypatch, _Distribution("1.1.0", editable), lambda root, *a: None)[0] is None


# ---------------------------------------------------------------------------
# The old-line harness (tools/regressie-1.0.x/): names that exist on the tag
# ---------------------------------------------------------------------------

HARNESS_DIR = ROOT / "tools" / "regressie-1.0.x"


def _tag_names() -> dict:
    """The harness's own table, read without importing the harness."""
    tree = ast.parse((HARNESS_DIR / "harnas.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "TAG_NAMES" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("harnas.py draagt geen TAG_NAMES")


def _tag_pins() -> dict:
    tree = ast.parse((HARNESS_DIR / "harnas.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "TAG_PINS" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("harnas.py draagt geen TAG_PINS")


_CHECK = """
import importlib, json, sys
root, table = sys.argv[1], json.loads(sys.argv[2])
sys.path.insert(0, root)
missing = []
for module, names in table.items():
    loaded = importlib.import_module(module)
    if not loaded.__file__.startswith(root):
        raise SystemExit("niet de bron van de tag: " + module)
    missing += [module + "." + name for name in names if not hasattr(loaded, name)]
print(json.dumps(missing))
"""


def _missing_on(commit: str, table: dict, tmp_path: Path) -> list[str]:
    """Import `table` against the source of `commit` (git archive), in an
    isolated child process, and return every name that is not there."""
    present = subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=ROOT, capture_output=True)
    assert present.returncode == 0, (
        f"commit {commit} ontbreekt in deze clone; haal de tags op (CI: checkout met fetch-depth 0)"
    )
    target = tmp_path / commit
    target.mkdir(parents=True)
    archive = subprocess.run(["git", "archive", "--format=tar", commit, "src/nsmcp"], cwd=ROOT, capture_output=True)
    assert archive.returncode == 0
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(target, filter="data")
    child = subprocess.run(
        [sys.executable, "-I", "-c", _CHECK, str(target / "src"), json.dumps(table)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert child.returncode == 0, child.stderr
    return json.loads(child.stdout)


def test_old_line_harness_imports_only_names_that_exist_on_the_tag(tmp_path):
    pins = _tag_pins()
    assert pins == {
        "v1.0.1": "39a0d0a61c8c8d81a08465610b2f229ad7206e92",
        "v1.0.2": "eb42816e9adb3f021e20f9bba871a59f53d92773",
        "v1.0.3": "41c85229edb6b9f78983fef09d03ebd15ef85641",
    }
    table = _tag_names()
    assert set(table) == set(pins)
    for tag, commit in pins.items():
        assert _missing_on(commit, table[tag], tmp_path) == [], tag
    # The check can fail: a name that only 1.1 has is missing on the tag.
    assert _missing_on(pins["v1.0.3"], {"nsmcp.cve": ["imposed_predicates"]}, tmp_path / "neg") == [
        "nsmcp.cve.imposed_predicates"
    ]


def test_the_harness_reaches_the_engine_only_through_its_table():
    """No `import nsmcp` or `from nsmcp` anywhere in the harness: every name
    of the old engine comes through TAG_NAMES, which the test above checks
    against the tags."""
    for path in sorted(HARNESS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(alias.name.split(".")[0] == "nsmcp" for alias in node.names), path.name
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] != "nsmcp", path.name


def _harness_module():
    import importlib.util

    name = "regressie_harnas_onder_test"
    spec = importlib.util.spec_from_file_location(name, HARNESS_DIR / "harnas.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up there
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


def test_the_harness_applies_the_same_matrix_rules_as_the_runner(tmp_path):
    """Parity: the harness's copy of the matrix rules, driven through its own
    name table on THIS engine (every name in it exists here too), gives the
    same refusal or the same lines as `knowledge_regression` - on the
    fixture, on every matrix with one case dropped, and on a lowered fix."""
    harness = _harness_module()
    engine = harness.load_engine("v1.0.3")
    identity = (_engine().version, _engine().commit)

    def both(package: Path, matrix: Path):
        refusal, lines, failures = harness.run_matrix(engine, package, matrix, identity, "", TODAY)
        mine = run_regression(package, matrix, engine=_engine(), today=TODAY)
        assert refusal == mine.refusal
        assert tuple(lines) == mine.lines
        assert failures == mine.failures
        return mine

    assert both(PACKAGE, MATRIX).passed
    full = _matrix()
    for index in range(len(full["gevallen"])):
        matrix = copy.deepcopy(full)
        del matrix["gevallen"][index]
        assert not both(PACKAGE, _write(tmp_path, f"m{index}.json", matrix)).passed
    lowered = _lowered()
    matrix = _matrix()
    matrix["pakketdigest"] = canonical_digest(lowered)
    assert not both(_write(tmp_path, "laag.json", lowered), _write(tmp_path, "mlaag.json", matrix)).passed
    # The fixed expectation is a fact about 1.0.x only: this engine knows
    # the field and loads the package, so the expectation does not hold here.
    holds, line = harness.refusal_expectation(harness.load_engine("v1.0.1"), "proef", TODAY)
    assert not holds and "kennispakket vraagt" not in line
