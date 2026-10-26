"""The regression matrix for the EXISTING package line, on engine v1.0.3.

`python -m nsmcp.knowledge --regressie` exists from engine 1.1.0 on; a 1.0.x
engine ends that call with exit code 2. Customers on 1.0.x get packages of
the existing line (no `minimaleEngine`), and such a package is checked here,
against the engine they run: v1.0.3, installed from its tag in an
environment of its own by `opzetten.py` (never imported into the 1.1
environment).

Two commands, both run INSIDE that environment (`python -I harnas.py ...`):

    regressie <pakket> <matrix>   the matrix of kennis-regressie.json, same
                                  format and the same `pakketdigest` and
                                  `engines` binding as the 1.1 runner
    weigering                     the fixed expectation: this engine refuses
                                  a package with `minimaleEngine` at the top
                                  level, also with a matching canonical pin

THE ENGINE IS REACHED ONLY THROUGH `TAG_NAMES`: every name below exists on
its tag (tests/test_knowledge_regression.py imports each of them against the
tag source and fails on a missing one); nothing else of `nsmcp` is
imported. The 1.1 predicate seam does not exist on the tag, so the case
outcomes are imposed by replacing `nsmcp.cve._evaluate_condition` in this
process for the duration of one case - the same function the 1.1 seam
lives in, with the same refusal of an outcome the case does not state.

The matrix rules (shape, binding, coverage, comparison) are the rules of
`nsmcp.knowledge_regression`, written out here because this file may not
import 1.1 code; a parity test in the 1.1 suite runs both on the same
matrices and requires the same outcome.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urlparse

# The full commit id of each tag (`git rev-parse <tag>^{commit}`).
TAG_PINS = {
    "v1.0.1": "39a0d0a61c8c8d81a08465610b2f229ad7206e92",
    "v1.0.2": "eb42816e9adb3f021e20f9bba871a59f53d92773",
    "v1.0.3": "41c85229edb6b9f78983fef09d03ebd15ef85641",
}

# Every engine name this harness uses, per tag. A literal on purpose: the
# 1.1 suite reads it with `ast.literal_eval` and imports each name against
# the source of the tag.
TAG_NAMES = {
    "v1.0.1": {"nsmcp.knowledge": ["load_knowledge", "canonical_digest", "KnowledgePin"]},
    "v1.0.2": {"nsmcp.knowledge": ["load_knowledge", "canonical_digest", "KnowledgePin"]},
    "v1.0.3": {
        "nsmcp": ["__version__"],
        "nsmcp.knowledge": [
            "load_knowledge",
            "canonical_digest",
            "KnowledgePin",
            "PREDICATES",
            "POST_UPGRADE_CONFIG_FIELD",
        ],
        "nsmcp.cve": [
            "cve_verdicts",
            "_evaluate_condition",
            "_resolve_condition",
            "_parse_fix",
            "GERAAKT",
            "NIET_GERAAKT",
            "NIET_VASTGESTELD",
        ],
        "nsmcp.update_advice": ["floor_for"],
        "nsmcp.answer": ["ReadGap"],
    },
}
MATRIX_TAG = "v1.0.3"
DISTRIBUTION = "netscaler-mcp"

_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_ENGINE_FORM = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_BRANCH = re.compile(r"[0-9]+\.[0-9]+(?:-FIPS)?")
_BUILD = re.compile(r"[0-9]+\.[0-9]+")
_FLOOR = re.compile(r"[0-9]+\.[0-9]+(?:-FIPS)?-[0-9]+\.[0-9]+")
_FIPS_SUFFIX = "-FIPS"
_MAX_BYTES = 10 * 1024 * 1024
_MATRIX_KEYS = frozenset({"pakketversie", "pakketdigest", "engines", "gevallen"})
_ENGINE_KEYS = frozenset({"versie", "commit"})
_CASE_KEYS = frozenset({"bulletin", "tak", "build", "voorwaarden", "verwacht", "verwachteVloer"})
_PRESENT, _ABSENT, _UNKNOWN = "aanwezig", "niet gevonden", "niet vastgesteld"
_UNREADABLE = "onleesbaar"
_MATRIX_WORD = {_PRESENT: "true", _ABSENT: "false", _UNKNOWN: _UNREADABLE}
_ALWAYS = "altijd"
IMPOSED_EVIDENCE = "opgelegd door de regressiematrix"


def load_engine(tag: str) -> SimpleNamespace:
    """The names of TAG_NAMES[tag], imported from the running environment,
    as `engine.<module>_<name>` with the dots of the module turned into
    underscores (`engine.nsmcp_cve_cve_verdicts`)."""
    names = {}
    for module_name, attributes in TAG_NAMES[tag].items():
        module = importlib.import_module(module_name)
        for attribute in attributes:
            names[f"{module_name.replace('.', '_')}_{attribute}"] = getattr(module, attribute)
        names[f"module_{module_name.replace('.', '_')}"] = module
    return SimpleNamespace(**names)


@dataclass(frozen=True)
class _Case:
    number: int
    bulletin: str
    branch: str
    build: tuple
    conditions: dict
    expected: dict
    floor: object


class PredicateNotImposed(LookupError):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def _build_text(pair) -> str:
    return f"{pair[0]}.{pair[1]}"


def _pair(text: str) -> tuple:
    major, minor = text.split(".")
    return int(major), int(minor)


def _just_below(pair):
    return (pair[0], pair[1] - 1) if pair[1] > 0 else None


def _engine_version(text):
    if not isinstance(text, str) or _ENGINE_FORM.fullmatch(text) is None:
        return None
    return tuple(int(part) for part in text.split("."))


# ---------------------------------------------------------------------------
# The engine identity: the tag's version, and the commit of the checkout the
# environment was installed from (direct_url.json), clean.
# ---------------------------------------------------------------------------


def _git(root: Path, *arguments: str):
    try:
        done = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def installed_identity(tag: str) -> tuple:
    """((version, commit), "") of the installed engine, or (None, reason)."""
    try:
        distribution = importlib.metadata.distribution(DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return None, "geen geinstalleerde engine"
    if distribution.version != tag[1:]:
        return None, f"de geinstalleerde engine is {distribution.version}, niet {tag[1:]}"
    try:
        recorded = json.loads(distribution.read_text("direct_url.json") or "null")
    except ValueError:
        recorded = None
    if not isinstance(recorded, dict):
        return None, "de installatie zegt niet waar zij vandaan komt"
    parsed = urlparse(str(recorded.get("url", "")))
    if parsed.scheme != "file":
        return None, "de installatie komt niet uit een lokale checkout"
    text = unquote(parsed.path)
    if re.match(r"/[A-Za-z]:/", text):
        text = text[1:]
    root = Path(text)
    head = (_git(root, "rev-parse", "HEAD") or "").strip()
    if head != TAG_PINS[tag]:
        return None, f"de checkout van de installatie staat niet op de pin van {tag}"
    # Tracked files only: installing from the checkout writes build/ into it.
    status = _git(root, "status", "--porcelain", "--untracked-files=no")
    if status is None or status.strip():
        return None, "de checkout van de installatie wijkt af van zijn commit"
    return (distribution.version, head), ""


# ---------------------------------------------------------------------------
# The matrix (the rules of nsmcp.knowledge_regression)
# ---------------------------------------------------------------------------


def read_json(path: Path, what: str) -> tuple:
    if not path.is_file():
        return None, f"{what} niet gevonden op {path}"
    if path.stat().st_size > _MAX_BYTES:
        return None, f"{what} is groter dan het plafond; niet gelezen"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, RecursionError, MemoryError, ValueError) as exc:
        return None, f"{what} onleesbaar: {exc.__class__.__name__}"
    if not isinstance(raw, dict):
        return None, f"{what} moet een object zijn"
    return raw, ""


def _keys_problem(value, keys, place: str) -> str:
    if not isinstance(value, dict):
        return f"regressiematrix: {place} moet een object zijn"
    if value.keys() != keys:
        return f"regressiematrix: {place} draagt precies de sleutels {', '.join(sorted(keys))}"
    return ""


def matrix_shape_problem(raw: dict, verdicts: tuple) -> str:
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
            if value not in verdicts:
                return f"regressiematrix: {place}.verwacht draagt een oordeel dat niet {', '.join(verdicts)} is"
        floor = case["verwachteVloer"]
        if floor is not None and (not isinstance(floor, str) or not _FLOOR.fullmatch(floor)):
            return f"regressiematrix: {place}.verwachteVloer heeft niet de vorm <tak>-X.Y of null"
    return ""


def _predicates_of(condition) -> set:
    if isinstance(condition, dict):
        return {str(condition["predicaat"]), str(condition["anders"])}
    return {str(condition)}


def _effective(engine, condition, branch: str, build):
    predicate, _, _ = engine.nsmcp_cve__resolve_condition(condition, branch, build)
    return predicate


def _bulletins(knowledge) -> dict:
    return {str(bulletin["bulletin"]): bulletin for bulletin in knowledge.cve}


def cases_of(engine, raw: dict, knowledge) -> tuple:
    bulletins = _bulletins(knowledge)
    predicates = engine.nsmcp_knowledge_PREDICATES
    cases = []
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
            if name == _ALWAYS or name not in predicates:
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
            needed = _effective(engine, entry["voorwaarde"], case["tak"], build)
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
                index + 1,
                case["bulletin"],
                case["tak"],
                build,
                conditions,
                dict(case["verwacht"]),
                case["verwachteVloer"],
            )
        )
    return cases, ""


def missing_coverage(engine, knowledge, cases: list) -> list:
    parse_fix = engine.nsmcp_cve__parse_fix
    missing = []
    for bulletin in knowledge.cve:
        name = str(bulletin["bulletin"])
        for branch in sorted(bulletin["getroffen"]):
            if not _BRANCH.fullmatch(branch):
                missing.append(f"{name}: een tak die een matrixgeval niet kan noemen (vorm X.Y of X.Y-FIPS)")
                continue
            fix = parse_fix(bulletin["fix"][branch])
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
                missing.extend(_condition_coverage(engine, label, entry, branch, fix, here, builds))
    return missing


def _condition_coverage(engine, label, entry, branch, fix, here, builds) -> list:
    parse_fix = engine.nsmcp_cve__parse_fix
    missing = []
    identity = str(entry["id"])
    condition = entry["voorwaarde"]
    threshold = None
    if isinstance(condition, dict):
        since = condition["vanaf"]
        if branch in since:
            threshold = parse_fix(since[branch])
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
        applying = [case for case in here if _effective(engine, condition, branch, case.build) == predicate]
        if not _applies_below(condition, predicate, fix, threshold):
            where, relevant = "waar die voorwaarde geldt", applying
            if isinstance(condition, dict) and threshold is None:
                continue
        else:
            where, relevant = "onder de fix", [case for case in applying if case.build < fix]
        for outcome in (_PRESENT, _ABSENT, _UNKNOWN):
            if not any(case.conditions.get(predicate) == outcome for case in relevant):
                missing.append(f"{label}, {identity}: {predicate} = {_MATRIX_WORD[outcome]} {where}")
    if entry.get(engine.nsmcp_knowledge_POST_UPGRADE_CONFIG_FIELD) is True:
        on_or_above = [case for case in here if case.build >= fix]
        real = [
            (case, predicate)
            for case in on_or_above
            for predicate in [_effective(engine, condition, branch, case.build)]
            if predicate is not None and predicate != _ALWAYS
        ]
        if _real_predicate_possible_above(condition, fix, threshold):
            for outcome in (_PRESENT, _ABSENT, _UNKNOWN):
                if not any(case.conditions.get(predicate) == outcome for case, predicate in real):
                    missing.append(
                        f"{label}, {identity}: naconfiguratie, voorwaarde = {_MATRIX_WORD[outcome]} op of boven de fix"
                    )
        elif not on_or_above:
            missing.append(f"{label}, {identity}: naconfiguratie, een build op of boven de fix")
    return missing


def _applies_below(condition, predicate, fix, threshold) -> bool:
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


def _real_predicate_possible_above(condition, fix, threshold) -> bool:
    if not isinstance(condition, dict):
        return condition != _ALWAYS
    if threshold is None:
        return False
    return condition["predicaat"] != _ALWAYS or (condition["anders"] != _ALWAYS and threshold > fix)


class _CaseExport:
    def __init__(self, branch: str, build) -> None:
        base = branch[: -len(_FIPS_SUFFIX)] if branch.endswith(_FIPS_SUFFIX) else branch
        marker = f" (NS{base}{_FIPS_SUFFIX})" if branch.endswith(_FIPS_SUFFIX) else ""
        self._version = f"NetScaler NS{base}: Build {build[0]}.{build[1]}.nc{marker}"

    def single(self, resource: str):
        if resource == "config/nsversion":
            return {"version": self._version}, None
        return None, None

    def __getattr__(self, name: str):
        raise AttributeError(f"een matrixgeval leest geen {name} uit een export")


def run_case(engine, case: _Case, knowledge) -> tuple:
    bulletin = _bulletins(knowledge)[case.bulletin]
    head = f"geval {case.number} ({case.bulletin}, tak {case.branch}, build {_build_text(case.build)})"
    only = replace(knowledge, cve=(bulletin,), unpinned_reason="")
    module = engine.module_nsmcp_cve
    original = module._evaluate_condition
    read_gap = engine.nsmcp_answer_ReadGap

    def imposed(export, name):
        if name == _ALWAYS:
            return original(export, name)
        if name not in case.conditions:
            raise PredicateNotImposed(name)
        outcome = case.conditions[name]
        gap = None
        if outcome == _UNKNOWN:
            gap = read_gap(source="regressiematrix", reason=f"voorwaarde {name} opgelegd als niet vast te stellen")
        return outcome, IMPOSED_EVIDENCE, gap, 0

    module._evaluate_condition = imposed
    try:
        records, _ = engine.nsmcp_cve_cve_verdicts(_CaseExport(case.branch, case.build), only)
    except PredicateNotImposed as exc:
        return False, f"{head}: de engine vroeg de voorwaarde {exc.name}, die het geval niet noemt"
    finally:
        module._evaluate_condition = original
    got = {str(entry["id"]): record.verdict for entry, record in zip(bulletin["cves"], records, strict=True)}
    floor = engine.nsmcp_update_advice_floor_for(case.branch, knowledge)
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


def run_matrix(engine, package: Path, matrix: Path, identity, identity_reason: str, today: date) -> tuple:
    """(refusal, lines, failures) - the same order of refusals as the 1.1
    runner: matrix shape, digest and version, engine, package, cases,
    coverage; only then the cases."""
    verdicts = (engine.nsmcp_cve_GERAAKT, engine.nsmcp_cve_NIET_GERAAKT, engine.nsmcp_cve_NIET_VASTGESTELD)
    raw_matrix, problem = read_json(matrix, "regressiematrix")
    if raw_matrix is None:
        return problem, [], 0
    problem = matrix_shape_problem(raw_matrix, verdicts)
    if problem:
        return problem, [], 0
    document, problem = read_json(package, "kennispakket")
    if document is None:
        return problem, [], 0
    if engine.nsmcp_knowledge_canonical_digest(document) != raw_matrix["pakketdigest"]:
        return (
            "de matrix hoort niet bij dit pakket: pakketdigest is niet de canonieke digest van het aangeboden pakket",
            [],
            0,
        )
    if document.get("versie") != raw_matrix["pakketversie"]:
        return "de matrix hoort niet bij dit pakket: pakketversie is niet de versie van het pakket", [], 0
    if identity is None:
        return f"de draaiende engine is niet vast te stellen: {identity_reason}", [], 0
    pinned = {(entry["versie"], entry["commit"]) for entry in raw_matrix["engines"]}
    if tuple(identity) not in pinned:
        return f"deze engine (versie {identity[0]}, commit {identity[1]}) staat niet in de engines van de matrix", [], 0
    # The engine's own pin binds what it loads to the same digest.
    pin = engine.nsmcp_knowledge_KnowledgePin(version=raw_matrix["pakketversie"], digest=raw_matrix["pakketdigest"])
    knowledge = engine.nsmcp_knowledge_load_knowledge(package, today, pin=pin)
    if knowledge.missing:
        return f"het pakket laadt niet op deze engine: {knowledge.reason}", [], 0
    cases, problem = cases_of(engine, raw_matrix, knowledge)
    if problem:
        return problem, [], 0
    missing = missing_coverage(engine, knowledge, cases)
    if missing:
        return f"de matrix dekt het pakket niet volledig; ontbrekend: {'; '.join(missing)}", [], 0
    failures, lines = 0, []
    for case in cases:
        held, line = run_case(engine, case, knowledge)
        failures += 0 if held else 1
        lines.append(line)
    return "", lines, failures


def refusal_expectation(engine, tag: str, today: date) -> tuple:
    """(holds, line): this engine refuses a package with `minimaleEngine` at
    the top level as an unknown field - with a matching canonical pin."""
    document = {"versie": "weigering-proef", "datum": (today - timedelta(days=1)).isoformat(), "cve": []}
    document["minimaleEngine"] = "1.1.0"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "kennis.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        pin = engine.nsmcp_knowledge_KnowledgePin(
            version="weigering-proef", digest=engine.nsmcp_knowledge_canonical_digest(document)
        )
        loaded = engine.nsmcp_knowledge_load_knowledge(path, today, pin=pin)
    holds = bool(loaded.missing) and "onbekend veld" in loaded.reason and "minimaleEngine" in loaded.reason
    verdict = "weigert" if loaded.missing else "LAADT"
    return holds, f"{tag}: pakket met minimaleEngine {verdict} ({loaded.reason or 'geen reden'})"


def main(arguments: list) -> int:
    today = datetime.now(UTC).date()
    if len(arguments) == 3 and arguments[0] == "regressie":
        engine = load_engine(MATRIX_TAG)
        identity, reason = installed_identity(MATRIX_TAG)
        if identity is not None and engine.nsmcp___version__ != identity[0]:
            identity, reason = None, "de versie van de module is niet die van de installatie"
        refusal, lines, failures = run_matrix(engine, Path(arguments[1]), Path(arguments[2]), identity, reason, today)
        if refusal:
            print(f"regressiematrix geweigerd: {refusal}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        if failures:
            print(f"regressiematrix: {len(lines)} gevallen, {failures} wijken af")
            return 1
        print(f"regressiematrix: {len(lines)} gevallen, alle kloppen (engine {identity[0]}, commit {identity[1]})")
        return 0
    if len(arguments) == 2 and arguments[0] == "weigering" and arguments[1] in TAG_PINS:
        tag = arguments[1]
        identity, reason = installed_identity(tag)
        if identity is None:
            print(f"weigering niet te toetsen: {reason}", file=sys.stderr)
            return 1
        holds, line = refusal_expectation(load_engine(tag), tag, today)
        print(f"{line} - commit {identity[1]}")
        return 0 if holds else 1
    print(
        "Gebruik: python -I harnas.py regressie <pakket> <matrix>\n"
        "         python -I harnas.py weigering <v1.0.1|v1.0.2|v1.0.3>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
