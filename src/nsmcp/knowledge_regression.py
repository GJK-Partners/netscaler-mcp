"""1.1 D.3: the regression matrix of a knowledge package, per bulletin.

A package maker states, per bulletin and per branch, what verdict a build
should get under which condition outcomes; this module runs those cases
through the engine's OWN rule path and says whether every one holds. The
matrix (`kennis-regressie.json`) travels with the package, not with this
repository; `tests/fixtures/kennis-regressie/` carries a synthetic package
and its matrix.

    python -m nsmcp.knowledge --regressie <pakket> <matrix>

Exit code 0 only when the matrix is bound to this package and this engine,
its coverage is complete and every case holds; 1 otherwise; 2 on a wrong
call. The CLI exists from engine 1.1.0 on - a 1.0.x engine ends the call
with exit code 2 (its usage line); the existing package line is checked
with the separate harness in `tools/regressie-1.0.x/`.

BEFORE ANY CASE RUNS the matrix is refused when:
- `pakketdigest` is not the canonical digest (`knowledge.canonical_digest`)
  of the very document that is then judged, or `pakketversie` is not its
  `versie`;
- the running engine - its version AND the commit it was installed from -
  is not one of `engines` (`engine_identity`);
- the package does not load on this engine;
- a case does not fit the package, or the coverage is incomplete.

COVERAGE, per bulletin per branch (the refusal names every missing case):
a build directly below the fix, the fix build itself and a build above it;
for every condition predicate both truth values and `onleesbaar`, below the
fix where that predicate applies there; both sides of every `vanaf`
threshold (the threshold itself and the build directly below it); and for
every CVE with `naconfiguratieVerplicht: true`, on or above the fix, the
condition absent, present and `onleesbaar`.

THE BOUNDARY: the condition outcomes are imposed through the seam in
`cve._evaluate_condition`. A case proves the choice of rule and the merge;
it does not prove that an export predicate recognises a real appliance
shape - that stays the work of the predicate tests on real exports.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import nsmcp
from nsmcp import cve
from nsmcp.knowledge import (
    POST_UPGRADE_CONFIG_FIELD,
    PREDICATES,
    Knowledge,
    _engine_version,
    canonical_digest,
    knowledge_from_document,
    read_package_document,
)
from nsmcp.limits import MAX_FILE_BYTES, MAX_JSON_DEPTH, exceeds_depth
from nsmcp.powershell import child_working_directory
from nsmcp.update_advice import floor_for

MATRIX_FILE_NAME = "kennis-regressie.json"
DISTRIBUTION = "netscaler-mcp"

_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_BRANCH = re.compile(r"[0-9]+\.[0-9]+(?:-FIPS)?")
_BUILD = re.compile(r"[0-9]+\.[0-9]+")
_FLOOR = re.compile(r"[0-9]+\.[0-9]+(?:-FIPS)?-[0-9]+\.[0-9]+")
_FIPS_SUFFIX = "-FIPS"

_MATRIX_KEYS = frozenset({"pakketversie", "pakketdigest", "engines", "gevallen"})
_ENGINE_KEYS = frozenset({"versie", "commit"})
_CASE_KEYS = frozenset({"bulletin", "tak", "build", "voorwaarden", "verwacht", "verwachteVloer"})
_VERDICTS = (cve.GERAAKT, cve.NIET_GERAAKT, cve.NIET_VASTGESTELD)
_PRESENT, _ABSENT, _UNKNOWN = "aanwezig", "niet gevonden", "niet vastgesteld"
_UNREADABLE = "onleesbaar"
# How the matrix writes each outcome, in the order the coverage names them.
_MATRIX_WORD = {_PRESENT: "true", _ABSENT: "false", _UNKNOWN: _UNREADABLE}
_ALWAYS = "altijd"


@dataclass(frozen=True)
class EngineIdentity:
    """The running engine: its version and the commit it was installed from."""

    version: str
    commit: str


@dataclass(frozen=True)
class _Case:
    number: int
    bulletin: str
    branch: str
    build: tuple[int, int]
    conditions: dict
    expected: dict
    floor: str | None


@dataclass(frozen=True)
class RegressionResult:
    """`refusal` is the reason the matrix did not run ("" when it ran);
    `lines` one line per case; `failures` the number of cases that did not
    hold."""

    refusal: str
    lines: tuple[str, ...] = ()
    failures: int = 0

    @property
    def passed(self) -> bool:
        return not self.refusal and self.failures == 0


def _build_text(pair: tuple[int, int]) -> str:
    return f"{pair[0]}.{pair[1]}"


def _pair(text: str) -> tuple[int, int]:
    major, minor = text.split(".")
    return int(major), int(minor)


def _just_below(pair: tuple[int, int]) -> tuple[int, int] | None:
    """The build directly below `pair` within its major, or None for X.0."""
    return (pair[0], pair[1] - 1) if pair[1] > 0 else None


# ---------------------------------------------------------------------------
# The engine identity
# ---------------------------------------------------------------------------


def _run_git(root: Path, *arguments: str) -> str | None:
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=child_working_directory(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _file_url_path(url) -> Path | None:
    if not isinstance(url, str):
        return None
    parsed = urlparse(url)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        return None
    text = unquote(parsed.path)
    if re.match(r"/[A-Za-z]:/", text):
        text = text[1:]
    return Path(text)


def engine_identity() -> tuple[EngineIdentity | None, str]:
    """(identity, "") of the RUNNING engine, or (None, reason) when its
    commit cannot be established from the installation. Fail-closed: an
    engine whose code may differ from a commit has no commit.

    - Installed from git (`pip install git+...@<commit>`): the commit pip
      recorded in `direct_url.json`.
    - An editable install of a checkout: the checkout's HEAD, and only when
      nothing under `src/` or `pyproject.toml` differs from it (the code
      that runs is the code of the tree).
    - Anything else (a wheel, a copy of a directory): no commit.
    """
    version = nsmcp.__version__
    try:
        distribution = importlib.metadata.distribution(DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return None, "de installatie van deze engine is niet te vinden; de commit is niet vast te stellen"
    if distribution.version != version:
        return None, "de installatie en de engine noemen een andere versie; de commit is niet vast te stellen"
    try:
        recorded = json.loads(distribution.read_text("direct_url.json") or "null")
    except ValueError:
        recorded = None
    if not isinstance(recorded, dict):
        return None, (
            "de installatie zegt niet van welke commit zij komt; installeer de engine vanaf een gepinde commit"
        )
    vcs = recorded.get("vcs_info")
    if isinstance(vcs, dict):
        commit = vcs.get("commit_id")
        if vcs.get("vcs") == "git" and isinstance(commit, str) and _COMMIT.fullmatch(commit):
            return EngineIdentity(version, commit), ""
        return None, "de installatie noemt geen volledige git-commit; de commit is niet vast te stellen"
    directory = recorded.get("dir_info")
    root = _file_url_path(recorded.get("url"))
    if not (isinstance(directory, dict) and directory.get("editable") is True and root is not None):
        return None, (
            "deze installatie is geen gepinde commit (geen git-installatie en geen bewerkbare checkout);"
            " de commit is niet vast te stellen"
        )
    try:
        inside = Path(nsmcp.__file__).resolve().is_relative_to((root / "src").resolve())
    except (OSError, ValueError):
        inside = False
    if not inside:
        return None, "de draaiende code komt niet uit de checkout van de installatie; de commit is niet vast te stellen"
    head = _run_git(root, "rev-parse", "HEAD")
    commit = head.strip() if head is not None else ""
    if not _COMMIT.fullmatch(commit):
        return None, "de commit van de checkout is niet te lezen; de commit is niet vast te stellen"
    status = _run_git(root, "status", "--porcelain", "--untracked-files=all", "--", "src", "pyproject.toml")
    if status is None:
        return None, "de stand van de checkout is niet te lezen; de commit is niet vast te stellen"
    if status.strip():
        return None, "de code van de checkout wijkt af van zijn commit; de commit is niet vast te stellen"
    return EngineIdentity(version, commit), ""


# ---------------------------------------------------------------------------
# The matrix file
# ---------------------------------------------------------------------------


def _read_matrix(path: Path) -> tuple[dict | None, str]:
    if not path.is_file():
        return None, f"regressiematrix niet gevonden op {path}"
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"regressiematrix onleesbaar: {exc.__class__.__name__}"
    if size > MAX_FILE_BYTES:
        return None, f"regressiematrix is groter dan het plafond ({size} bytes tegen {MAX_FILE_BYTES}); niet gelezen"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, RecursionError, MemoryError, ValueError) as exc:
        return None, f"regressiematrix onleesbaar: {exc.__class__.__name__}"
    if not isinstance(raw, dict):
        return None, "regressiematrix moet een object zijn"
    if exceeds_depth(raw):
        return None, f"regressiematrix is te diep genest (meer dan {MAX_JSON_DEPTH} niveaus)"
    problem = _matrix_shape_problem(raw)
    return (None, problem) if problem else (raw, "")


def _keys_problem(value, keys: frozenset, place: str) -> str:
    if not isinstance(value, dict):
        return f"regressiematrix: {place} moet een object zijn"
    if value.keys() != keys:
        return f"regressiematrix: {place} draagt precies de sleutels {', '.join(sorted(keys))}"
    return ""


def _matrix_shape_problem(raw: dict) -> str:
    """The first place the matrix is not of its fixed shape, named by its
    path - never by a value out of the file."""
    problem = _keys_problem(raw, _MATRIX_KEYS, "het document")
    if problem:
        return problem
    if not isinstance(raw["pakketversie"], str):
        return "regressiematrix: pakketversie moet tekst zijn"
    if not isinstance(raw["pakketdigest"], str) or not _DIGEST.fullmatch(raw["pakketdigest"]):
        return "regressiematrix: pakketdigest is geen digest van 64 kleine hexadecimale tekens"
    engines = raw["engines"]
    if not isinstance(engines, list) or not engines:
        return "regressiematrix: engines moet een niet-lege lijst zijn"
    for index, engine in enumerate(engines):
        place = f"engines[{index}]"
        problem = _keys_problem(engine, _ENGINE_KEYS, place)
        if problem:
            return problem
        if _engine_version(engine["versie"]) is None:
            return f"regressiematrix: {place}.versie heeft niet de vorm MAJOR.MINOR.PATCH"
        if not isinstance(engine["commit"], str) or not _COMMIT.fullmatch(engine["commit"]):
            return f"regressiematrix: {place}.commit is geen volledige commit van 40 kleine hexadecimale tekens"
    cases = raw["gevallen"]
    if not isinstance(cases, list) or not cases:
        return "regressiematrix: gevallen moet een niet-lege lijst zijn"
    for index, case in enumerate(cases):
        place = f"gevallen[{index}]"
        problem = _keys_problem(case, _CASE_KEYS, place)
        if problem:
            return problem
        if not isinstance(case["bulletin"], str):
            return f"regressiematrix: {place}.bulletin moet tekst zijn"
        if not isinstance(case["tak"], str) or not _BRANCH.fullmatch(case["tak"]):
            return f"regressiematrix: {place}.tak heeft niet de vorm X.Y of X.Y-FIPS"
        if not isinstance(case["build"], str) or not _BUILD.fullmatch(case["build"]):
            return f"regressiematrix: {place}.build heeft niet de vorm X.Y"
        conditions = case["voorwaarden"]
        if not isinstance(conditions, dict):
            return f"regressiematrix: {place}.voorwaarden moet een object zijn"
        for value in conditions.values():
            if type(value) is not bool and value != _UNREADABLE:
                return f"regressiematrix: {place}.voorwaarden draagt een waarde die niet true, false of onleesbaar is"
        expected = case["verwacht"]
        if not isinstance(expected, dict) or not expected:
            return f"regressiematrix: {place}.verwacht moet een niet-leeg object zijn"
        for value in expected.values():
            if value not in _VERDICTS:
                return f"regressiematrix: {place}.verwacht draagt een oordeel dat niet {', '.join(_VERDICTS)} is"
        floor = case["verwachteVloer"]
        if floor is not None and (not isinstance(floor, str) or not _FLOOR.fullmatch(floor)):
            return f"regressiematrix: {place}.verwachteVloer heeft niet de vorm <tak>-X.Y of null"
    return ""


# ---------------------------------------------------------------------------
# Cases against the package
# ---------------------------------------------------------------------------


def _predicates_of(condition) -> set[str]:
    if isinstance(condition, dict):
        return {str(condition["predicaat"]), str(condition["anders"])}
    return {str(condition)}


def _effective(condition, branch: str, build: tuple[int, int]) -> str | None:
    """The predicate the engine's own choice rule applies to this CVE on
    this branch and build (`cve._resolve_condition`), or None."""
    predicate, _, _ = cve._resolve_condition(condition, branch, build)
    return predicate


def _bulletins(knowledge: Knowledge) -> dict[str, dict]:
    return {str(bulletin["bulletin"]): bulletin for bulletin in knowledge.cve}


def _cases(raw: dict, knowledge: Knowledge) -> tuple[list[_Case], str]:
    bulletins = _bulletins(knowledge)
    cases: list[_Case] = []
    for index, case in enumerate(raw["gevallen"]):
        place = f"gevallen[{index}]"
        bulletin = bulletins.get(case["bulletin"])
        if bulletin is None:
            return [], f"regressiematrix: {place}.bulletin noemt geen bulletin uit het pakket"
        identities = {str(entry["id"]) for entry in bulletin["cves"]}
        if set(case["verwacht"]) != identities:
            return [], f"regressiematrix: {place}.verwacht noemt niet precies de CVE's van dit bulletin"
        build = _pair(case["build"])
        named = set().union(*(_predicates_of(entry["voorwaarde"]) for entry in bulletin["cves"]))
        for name in case["voorwaarden"]:
            if name == _ALWAYS or name not in PREDICATES:
                return [], (
                    f"regressiematrix: {place}.voorwaarden noemt iets dat geen op te leggen predicaat is"
                    f" (toegestaan: de predicaten van deze engine behalve {_ALWAYS})"
                )
            if name not in named:
                return (
                    [],
                    f"regressiematrix: {place}.voorwaarden noemt een predicaat dat in geen CVE van dit bulletin staat",
                )
        for entry in bulletin["cves"]:
            needed = _effective(entry["voorwaarde"], case["tak"], build)
            if needed is not None and needed != _ALWAYS and needed not in case["voorwaarden"]:
                return [], (
                    f"regressiematrix: {place}.voorwaarden mist de waarde van {needed}, de voorwaarde van"
                    f" {entry['id']} op deze build"
                )
        conditions = {
            name: (_UNKNOWN if value == _UNREADABLE else _PRESENT if value is True else _ABSENT)
            for name, value in case["voorwaarden"].items()
        }
        cases.append(
            _Case(
                number=index + 1,
                bulletin=case["bulletin"],
                branch=case["tak"],
                build=build,
                conditions=conditions,
                expected=dict(case["verwacht"]),
                floor=case["verwachteVloer"],
            )
        )
    return cases, ""


def _missing_coverage(knowledge: Knowledge, cases: list[_Case]) -> list[str]:
    missing: list[str] = []
    for bulletin in knowledge.cve:
        name = str(bulletin["bulletin"])
        if not bulletin["getroffen"]:
            # A bulletin without a branch would need no case at all.
            missing.append(f"{name}: ten minste een tak (getroffen en fix noemen geen tak)")
            continue
        for branch in sorted(bulletin["getroffen"]):
            if not _BRANCH.fullmatch(branch):
                missing.append(f"{name}: een tak die een matrixgeval niet kan noemen (vorm X.Y of X.Y-FIPS)")
                continue
            fix = cve._parse_fix(bulletin["fix"][branch])
            if fix is None:
                missing.append(f"{name} tak {branch}: een leesbare fix-build")
                continue
            label = f"{name} tak {branch}"
            here = [case for case in cases if case.bulletin == name and case.branch == branch]
            builds = {case.build for case in here}
            below = _just_below(fix)
            if below is not None and below not in builds:
                missing.append(f"{label}: een build direct onder de fix ({_build_text(below)})")
            if below is None and fix > (0, 0) and not any(build < fix for build in builds):
                missing.append(f"{label}: een build onder de fix ({_build_text(fix)})")
            if fix not in builds:
                missing.append(f"{label}: de fix-build zelf ({_build_text(fix)})")
            if not any(build > fix for build in builds):
                missing.append(f"{label}: een build boven de fix ({_build_text(fix)})")
            for entry in bulletin["cves"]:
                missing.extend(_condition_coverage(label, entry, branch, fix, here, builds))
    return missing


def _condition_coverage(label, entry, branch, fix, here, builds) -> list[str]:
    missing: list[str] = []
    identity = str(entry["id"])
    condition = entry["voorwaarde"]
    threshold = None
    if isinstance(condition, dict):
        since = condition["vanaf"]
        if branch in since:
            threshold = cve._parse_fix(since[branch])
            if threshold is not None:
                if threshold not in builds:
                    missing.append(f"{label}, {identity}: een build op de vanaf-drempel ({_build_text(threshold)})")
                under = _just_below(threshold)
                if under is not None and under not in builds:
                    missing.append(
                        f"{label}, {identity}: een build direct onder de vanaf-drempel ({_build_text(under)})"
                    )
                if under is None and threshold > (0, 0) and not any(build < threshold for build in builds):
                    missing.append(f"{label}, {identity}: een build onder de vanaf-drempel ({_build_text(threshold)})")
    for predicate in sorted(_predicates_of(condition) - {_ALWAYS}):
        applying = [case for case in here if _effective(condition, branch, case.build) == predicate]
        if not _applies_below(condition, predicate, branch, fix, threshold):
            where, relevant = "waar die voorwaarde geldt", applying
            if isinstance(condition, dict) and threshold is None:
                continue  # the rule never names this branch: no predicate applies here
        else:
            where, relevant = "onder de fix", [case for case in applying if case.build < fix]
        for outcome in (_PRESENT, _ABSENT, _UNKNOWN):
            if not any(case.conditions.get(predicate) == outcome for case in relevant):
                missing.append(f"{label}, {identity}: {predicate} = {_MATRIX_WORD[outcome]} {where}")
    if entry.get(POST_UPGRADE_CONFIG_FIELD) is True:
        on_or_above = [case for case in here if case.build >= fix]
        real = [
            (case, predicate)
            for case in on_or_above
            for predicate in [_effective(condition, branch, case.build)]
            if predicate is not None and predicate != _ALWAYS
        ]
        if _real_predicate_possible_above(condition, branch, fix, threshold):
            for outcome in (_PRESENT, _ABSENT, _UNKNOWN):
                if not any(case.conditions.get(predicate) == outcome for case, predicate in real):
                    missing.append(
                        f"{label}, {identity}: naconfiguratie, voorwaarde = {_MATRIX_WORD[outcome]} op of boven de fix"
                    )
        elif not on_or_above:
            missing.append(f"{label}, {identity}: naconfiguratie, een build op of boven de fix")
    return missing


def _applies_below(condition, predicate, branch, fix, threshold) -> bool:
    """Can `predicate` decide a verdict below the fix on this branch?"""
    if not isinstance(condition, dict):
        return fix > (0, 0)
    if threshold is None:
        return False
    regions = []
    if predicate == condition["predicaat"]:
        regions.append(threshold < fix)
    if predicate == condition["anders"]:
        regions.append(min(threshold, fix) > (0, 0))
    return any(regions)


def _real_predicate_possible_above(condition, branch, fix, threshold) -> bool:
    if not isinstance(condition, dict):
        return condition != _ALWAYS
    if threshold is None:
        return False
    return condition["predicaat"] != _ALWAYS or (condition["anders"] != _ALWAYS and threshold > fix)


class _CaseExport:
    """The one thing a case needs from an export: the version string that
    names its branch and build (and, for a FIPS branch, the vendor's own
    train marker). Every condition comes from the seam; anything else this
    stand-in is asked for is refused, so a case can never be judged on an
    export it does not have."""

    def __init__(self, branch: str, build: tuple[int, int]) -> None:
        base = branch[: -len(_FIPS_SUFFIX)] if branch.endswith(_FIPS_SUFFIX) else branch
        marker = f" (NS{base}{_FIPS_SUFFIX})" if branch.endswith(_FIPS_SUFFIX) else ""
        self._version = f"NetScaler NS{base}: Build {build[0]}.{build[1]}.nc{marker}"

    def single(self, resource: str):
        if resource == "config/nsversion":
            return {"version": self._version}, None
        return None, None

    def __getattr__(self, name: str):
        raise AttributeError(f"een matrixgeval leest geen {name} uit een export")


def _run_case(case: _Case, knowledge: Knowledge) -> tuple[bool, str]:
    bulletin = _bulletins(knowledge)[case.bulletin]
    head = f"geval {case.number} ({case.bulletin}, tak {case.branch}, build {_build_text(case.build)})"
    only = replace(knowledge, cve=(bulletin,), unpinned_reason="")
    try:
        with cve.imposed_predicates(case.conditions):
            records, _ = cve.cve_verdicts(_CaseExport(case.branch, case.build), only)
    except cve.PredicateNotImposed as exc:
        return False, f"{head}: de engine vroeg de voorwaarde {exc.name}, die het geval niet noemt"
    got = {str(entry["id"]): record.verdict for entry, record in zip(bulletin["cves"], records, strict=True)}
    floor = floor_for(case.branch, knowledge)
    floor_text = f"{case.branch}-{floor[0]}" if floor is not None else None
    differences = [
        f"{identity} verwacht {case.expected[identity]}, engine geeft {got[identity]}"
        for identity in sorted(case.expected)
        if got.get(identity) != case.expected[identity]
    ]
    if floor_text != case.floor:
        differences.append(f"vloer verwacht {case.floor or 'geen'}, engine geeft {floor_text or 'geen'}")
    if differences:
        return False, f"{head}: wijkt af: {'; '.join(differences)}"
    return True, f"{head}: klopt"


def _run_cases(cases: list[_Case], knowledge: Knowledge) -> tuple[int, list[str]]:
    failures = 0
    lines: list[str] = []
    for case in cases:
        held, line = _run_case(case, knowledge)
        failures += 0 if held else 1
        lines.append(line)
    return failures, lines


def run_regression(
    package: Path, matrix: Path, *, engine: EngineIdentity | None, engine_reason: str = "", today: date
) -> RegressionResult:
    """Run `matrix` against `package` on the engine `engine` (see the module
    docstring for the order of the refusals)."""
    raw_matrix, problem = _read_matrix(matrix)
    if raw_matrix is None:
        return RegressionResult(problem)
    document, problem = read_package_document(package)
    if document is None:
        return RegressionResult(problem)
    if canonical_digest(document) != raw_matrix["pakketdigest"]:
        return RegressionResult(
            "de matrix hoort niet bij dit pakket: pakketdigest is niet de canonieke digest van het aangeboden pakket"
        )
    if document.get("versie") != raw_matrix["pakketversie"]:
        return RegressionResult("de matrix hoort niet bij dit pakket: pakketversie is niet de versie van het pakket")
    if engine is None:
        return RegressionResult(f"de draaiende engine is niet vast te stellen: {engine_reason}")
    pinned = {(entry["versie"], entry["commit"]) for entry in raw_matrix["engines"]}
    if (engine.version, engine.commit) not in pinned:
        return RegressionResult(
            f"deze engine (versie {engine.version}, commit {engine.commit}) staat niet in de engines van de matrix"
        )
    knowledge = knowledge_from_document(document, today)
    if knowledge.missing:
        return RegressionResult(f"het pakket laadt niet op deze engine: {knowledge.reason}")
    cases, problem = _cases(raw_matrix, knowledge)
    if problem:
        return RegressionResult(problem)
    missing = _missing_coverage(knowledge, cases)
    if missing:
        return RegressionResult(f"de matrix dekt het pakket niet volledig; ontbrekend: {'; '.join(missing)}")
    failures, lines = _run_cases(cases, knowledge)
    return RegressionResult("", tuple(lines), failures)


def main(package: str, matrix: str) -> int:
    """`python -m nsmcp.knowledge --regressie <pakket> <matrix>`."""
    identity, reason = engine_identity()
    result = run_regression(
        Path(package), Path(matrix), engine=identity, engine_reason=reason, today=datetime.now(UTC).date()
    )
    if result.refusal:
        print(f"regressiematrix geweigerd: {result.refusal}", file=sys.stderr)
        return 1
    for line in result.lines:
        print(line)
    total = len(result.lines)
    if result.failures or identity is None:
        print(
            f"regressiematrix: {total} gevallen, {result.failures} {'wijkt' if result.failures == 1 else 'wijken'} af"
        )
        return 1
    print(f"regressiematrix: {total} gevallen, alle kloppen (engine {identity.version}, commit {identity.commit})")
    return 0
