"""B3 - `status_update_preflight`: nine checks, four words, one heading.

The fixtures this file uses do not live in `tests/conftest.py` on this branch
(that file only fixes pytest's temporary base directory), so they are defined
here. The base is `tests/fixtures/preflight-export/` - a small, synthetic
export whose manifest, payloads and running-config hash are real, so a check
that reads it really reads something instead of falling on the same read gap
nine times.

THREE OF THE NINE reach beyond this fixture for their source, measured
rather than assumed:

- check 3 reads `ha.ha_result`, available on this branch - this fixture's
  export just carries no usable HA source;
- check 5 reads `expiry.usage_per_certificate`, available on this branch
  since the merge on the release - this fixture's export just carries no
  `config/sslcertkey`;
- check 8 needs a LIVE read of `stat/system`, which no test may ever perform.

All three are `niet beoordeeld` with a named reason - never `geen blokkade` -
and the tests below pin exactly that. Their JUDGEMENT is still tested, on the
pure decision functions `_ha_word` / `_certificate_word`, with real values
instead of a mocked module: that way the mapping from an HA result or a
certificate horizon onto one of the four words is measured directly,
independent of what any one fixture's export can read.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from config_export_harness import (
    COLLECTOR_MARKER_LINES,
    INSERTED,
    LAB as LAB_EXPORT,
    NEW_SECRET,
    OLD_SECRET,
    RUNNING_HEADER,
    SAVED_AFTER_CHANGE_HEADER,
    SAVED_HEADER,
    WITHHELD_ONLY_PAIRS,
    config_pair,
    copy_with_running,
    insert_after_line,
)
from conftest import seal_manifest

from nsmcp.answer import Certainty
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.preflight import (
    ASSUMED_BUNDLE_MB,
    ATTENTION,
    BLOCKER,
    CONCLUSIVE_HEADING,
    FREE_SPACE_ROUTE_COLLECTOR,
    FREE_SPACE_ROUTE_SSH,
    NO_BLOCKER,
    NOT_ASSESSED,
    PREFLIGHT_WORDS,
    VENDOR_FLOOR_MB,
    Check,
    _certificate_word,
    _ha_word,
    free_space_from_script,
    preflight_answer,
    preflight_checks,
)

FIXTURE = Path(__file__).parent / "fixtures" / "preflight-export"

SYSTEMFILE = "config/systemfile?args=filelocation:%2Fvar%2Fnsinstall"


def _variant(tmp_path: Path, name: str, mutate):
    """A copy of the base fixture with one thing changed.

    The manifest is rewritten, so `scan-doel.txt` is rewritten with it: the
    second line of that file is the sha256 of the manifest and
    `export._read_target_name` rightly refuses the name when the two no longer
    belong together.
    """
    root = tmp_path / name
    shutil.copytree(FIXTURE, root)
    manifest = json.loads((root / "export-manifest.json").read_text(encoding="utf-8"))
    mutate(root, manifest)
    (root / "export-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    seal_manifest(root)
    (root / "scan-doel.txt").write_text(
        "preflight-lab\n" + hashlib.sha256((root / "export-manifest.json").read_bytes()).hexdigest() + "\n",
        encoding="utf-8",
    )
    return load_export(root)


def _object(root: Path, name: str, mutate):
    path = root / "objects" / f"{name}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw)
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")


@pytest.fixture
def preflight_export():
    return load_export(FIXTURE)


@pytest.fixture
def knowledge() -> Knowledge:
    """A package that offers 14.1-72.57 and names a floor of 14.1-72.61.

    The fixture export runs 14.1-66.59, so the target build really is higher -
    without that, check 6 would measure nothing.
    """
    return Knowledge(
        version="test-2026.09",
        date="2026-09-01",
        age_days=4,
        missing=False,
        cve=(
            {
                "bulletin": "CTX696604",
                "datum": "2026-06-30",
                "getroffen": {"14.1": "< 72.61"},
                "fix": {"14.1": "72.61"},
                "cves": [],
                "advies": "upgrade",
                "extraStapNaUpgrade": "",
            },
        ),
        offered_builds={"14.1": "72.57"},
        offered_date="2026-09-01",
        offered_source="release notes",
    )


@pytest.fixture
def export_without_nsversion(tmp_path: Path):
    def mutate(root: Path, manifest: dict):
        del manifest["resources"]["config/nsversion"]
        (root / "objects" / "nsversion.json").unlink()

    return _variant(tmp_path, "zonder-nsversion", mutate)


@pytest.fixture
def export_with_empty_licensetype(tmp_path: Path):
    def mutate(root: Path, manifest: dict):
        _object(root, "nslicense", lambda raw: raw["nslicense"].update({"licensetype": ""}))

    return _variant(tmp_path, "lege-licensetype", mutate)


@pytest.fixture
def export_with_unreadable_license_server(tmp_path: Path):
    """A genuine READ FAILURE on `config/nslicenseserver` (for example
    RBAC_DENIED) - a different fact from EMPTY (the resource read fine and
    carried no server). Check 1 must call this `niet beoordeeld`, never
    `aandachtspunt` - nothing here was read."""

    def mutate(root: Path, manifest: dict):
        manifest["resources"]["config/nslicenseserver"]["status"] = "RBAC_DENIED"

    return _variant(tmp_path, "onleesbare-licentieserver", mutate)


@pytest.fixture
def export_with_unreachable_license_server(tmp_path: Path):
    """The resource itself read fine (`status: OK`); the one server object it
    carries reports a status this product does not recognise as reachable.
    A different fact from a read gap - this stays `aandachtspunt` after the
    fix below, never `niet beoordeeld`."""

    def mutate(root: Path, manifest: dict):
        manifest["resources"]["config/nslicenseserver"] = {
            "status": "OK",
            "propertyName": "nslicenseserver",
            "objectCount": 1,
        }
        (root / "objects" / "nslicenseserver.json").write_text(
            json.dumps({"nslicenseserver": [{"status": "MAINTENANCE"}]}, indent=2),
            encoding="utf-8",
        )

    return _variant(tmp_path, "onbereikbare-licentieserver", mutate)


@pytest.fixture
def export_without_backup(tmp_path: Path):
    """Both sources READ, both empty. That is not a read gap - the appliance
    really carries no backup and no build tree - so this must be a blocker and
    not a `niet beoordeeld`."""

    def mutate(root: Path, manifest: dict):
        manifest["resources"]["config/systembackup"]["status"] = "EMPTY"
        manifest["resources"][SYSTEMFILE]["status"] = "EMPTY"
        (root / "objects" / "systembackup.json").unlink()
        (root / "objects" / "systemfile.json").unlink()

    return _variant(tmp_path, "zonder-backup", mutate)


# ---------------------------------------------------------------------------
# The four rules that hold for all nine
# ---------------------------------------------------------------------------


def test_there_are_exactly_nine_checks_and_they_are_numbered_one_to_nine(preflight_export, knowledge):
    checks = preflight_checks(preflight_export, knowledge, free_var_mb=9000, bundle_mb=1081)
    assert [c.number for c in checks] == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert all(c.word in PREFLIGHT_WORDS for c in checks)


def test_a_read_gap_makes_a_check_not_assessed_never_no_blocker(export_without_nsversion, knowledge):
    checks = preflight_checks(export_without_nsversion, knowledge, free_var_mb=None, bundle_mb=None)
    zes = next(c for c in checks if c.number == 6)
    assert zes.word == "niet beoordeeld"
    assert zes.reason


def test_a_check_that_is_not_no_blocker_must_say_why():
    """The rule lives in the type, not in an agreement: a check cannot be
    constructed as a blocker without a reason."""
    with pytest.raises(ValueError):
        Check(1, "toets", BLOCKER, "bewijs")
    with pytest.raises(ValueError):
        Check(1, "toets", "groen", "bewijs", "reden")


def test_no_check_ever_says_a_word_outside_the_four(preflight_export, knowledge):
    """Every fixture in this file, every check, one vocabulary."""
    for free, bundle in ((9000, 1081), (None, None), (VENDOR_FLOOR_MB - 1, 1081)):
        for check in preflight_checks(preflight_export, knowledge, free, bundle):
            assert check.word in PREFLIGHT_WORDS


# ---------------------------------------------------------------------------
# The checks, one by one
# ---------------------------------------------------------------------------


def test_an_empty_licensetype_is_an_attention_point_never_no_blocker(export_with_empty_licensetype, knowledge):
    een = next(c for c in preflight_checks(export_with_empty_licensetype, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == "aandachtspunt"


def test_a_readable_licence_model_with_a_valid_licence_is_no_blocker(preflight_export, knowledge):
    een = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == NO_BLOCKER


def test_an_unreadable_license_server_is_not_assessed_never_established(
    export_with_unreadable_license_server, knowledge
):
    """The finding under review: `config/nslicenseserver` failing to read
    (RBAC_DENIED) is a read gap, not a value read as unreachable. It must
    render as `niet beoordeeld [niet vastgesteld]`, never as
    `aandachtspunt [vastgesteld]` - a verdict on a field nobody read."""
    een = next(
        c for c in preflight_checks(export_with_unreadable_license_server, knowledge, 9000, 1081) if c.number == 1
    )
    assert een.word == NOT_ASSESSED
    assert "nslicenseserver" in een.reason
    tekst = preflight_answer(export_with_unreadable_license_server, knowledge, 9000, 1081, gap=None).to_text()
    assert "1. licentiemodus en licentieserver: aandachtspunt [vastgesteld]" not in tekst
    assert "1. licentiemodus en licentieserver: niet beoordeeld [niet vastgesteld]" in tekst


def test_an_unrecognised_license_server_status_is_still_an_attention_point(
    export_with_unreachable_license_server, knowledge
):
    """Regression for the fix above: a licence server that WAS read but
    reports a status this product does not recognise as reachable must stay
    `aandachtspunt` - the fix must not widen `niet beoordeeld` onto a value
    that really was read."""
    een = next(
        c for c in preflight_checks(export_with_unreachable_license_server, knowledge, 9000, 1081) if c.number == 1
    )
    assert een.word == ATTENTION


# Sentinel for the one shape `_server_row` below cannot express as a value:
# the "status" key missing from the row altogether.
_STATUS_FIELD_ABSENT = object()


def _server_row(status):
    if status is _STATUS_FIELD_ABSENT:
        return {}
    return {"status": status}


def _export_with_license_server_rows(tmp_path: Path, name: str, rows: list):
    """A `config/nslicenseserver` that read fine (`status: OK`) and carries
    exactly `rows` as its server objects - used to drive the server's own
    "status" field through every JSON shape `_text()` cannot read."""

    def mutate(root: Path, manifest: dict):
        manifest["resources"]["config/nslicenseserver"] = {
            "status": "OK",
            "propertyName": "nslicenseserver",
            "objectCount": len(rows),
        }
        (root / "objects" / "nslicenseserver.json").write_text(
            json.dumps({"nslicenseserver": rows}, indent=2), encoding="utf-8"
        )

    return _variant(tmp_path, name, mutate)


@pytest.mark.parametrize(
    "status_value, shape_word",
    [
        pytest.param(None, "JSON null", id="null"),
        pytest.param(424242, "type int", id="int"),
        pytest.param(True, "type bool", id="bool"),
        pytest.param(["PWNED_MARKER"], "type list", id="list"),
        pytest.param({"status": "PWNED_MARKER"}, "type dict", id="dict"),
        pytest.param("", "lege of alleen-witruimte tekstwaarde", id="empty"),
        pytest.param("   ", "lege of alleen-witruimte tekstwaarde", id="whitespace"),
        pytest.param(_STATUS_FIELD_ABSENT, "sleutel ontbreekt", id="absent"),
    ],
)
def test_an_unreadable_license_server_status_names_the_shape_never_the_value(
    tmp_path, knowledge, status_value, shape_word, request
):
    """The resource itself read fine, and the one server object it carries
    read fine too - but its "status" field is JSON null, an int, a bool, a
    list, a dict, an empty or whitespace-only string, or missing altogether,
    none of which `_text()` can turn into a string. That is a field that WAS
    READ but is not INTERPRETABLE - the same fact, one level deeper, as the
    resource-level read gap this same check answers `niet beoordeeld` for
    when `config/nslicenseserver` itself cannot be read at all - so this
    field-level gap must render `niet beoordeeld [niet vastgesteld]`, never
    `aandachtspunt [vastgesteld]`.

    `licensetype` elsewhere in this same check is NOT the same case, despite
    looking similar: an empty or unreadable `licensetype` is design-pinned to
    `aandachtspunt` (the regression coverage below
    en-poorten-design.md, ~357 and ~1322) and that behaviour is deliberately
    left unchanged here.

    The reason must name the SHAPE of what was found via the canonical
    `export.py::shape_of()` and its `"de sleutel ontbreekt"` idiom for the
    missing-key case, and never the value itself: a list or dict status is
    attacker-controlled text from the appliance, and echoing it could forge
    a certainty marker or inject a line break into the rendered answer (see
    the module docstring)."""
    export = _export_with_license_server_rows(
        tmp_path, f"licentieserver-status-{request.node.callspec.id}", [_server_row(status_value)]
    )
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == NOT_ASSESSED
    assert shape_word in een.reason
    assert "PWNED_MARKER" not in een.reason

    tekst = preflight_answer(export, knowledge, 9000, 1081, gap=None).to_text()
    assert "1. licentiemodus en licentieserver: niet beoordeeld [niet vastgesteld]" in tekst
    assert "1. licentiemodus en licentieserver: aandachtspunt [vastgesteld]" not in tekst
    assert "PWNED_MARKER" not in tekst


def test_one_unreachable_and_two_unreadable_license_servers_stays_attention_but_names_both(tmp_path, knowledge):
    """The mixed case: one server was read and reports a status this product
    does not recognise as reachable (stays `aandachtspunt` - it really was
    read), and two more servers were read but their status was not
    interpretable, in two DIFFERENT shapes (on their own, `niet beoordeeld`).
    `aandachtspunt` wins - the first server really is an established finding
    - but staying silent about the other two would hide that they were never
    actually assessed, the same hole one level up. The reason must join
    BOTH distinct shapes, not just the first one it saw.

    Every assertion below must be able to fail on its own: the unreachable
    count ("1 van de 3") sits in a different clause of the reason than the
    unreadable count ("2 ervan"), so a regression that drops or miscounts
    either clause is caught, not masked by the other still being right."""
    export = _export_with_license_server_rows(
        tmp_path,
        "gemengde-licentieservers",
        [
            _server_row("MAINTENANCE"),
            _server_row({"status": "PWNED_MARKER_DICT"}),
            _server_row(["PWNED_MARKER_LIST"]),
        ],
    )
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == ATTENTION
    assert "1 van de 3" in een.reason
    assert "dragen 2 ervan" in een.reason
    assert "niet te beoordelen" in een.reason
    assert "type dict" in een.reason
    assert "type list" in een.reason
    assert "PWNED_MARKER_DICT" not in een.reason
    assert "PWNED_MARKER_LIST" not in een.reason

    tekst = preflight_answer(export, knowledge, 9000, 1081, gap=None).to_text()
    assert "1. licentiemodus en licentieserver: aandachtspunt [vastgesteld]" in tekst
    assert "PWNED_MARKER_DICT" not in tekst
    assert "PWNED_MARKER_LIST" not in tekst


def test_one_unreachable_license_server_uses_singular_dutch(tmp_path, knowledge):
    """A regression made "N van de M ...
    licentieservers" unconditionally plural ("melden"), even for N == 1,
    where correct Dutch is singular ("meldt"). One server, one status this
    product does not recognise as reachable, is the smallest case that
    proves it."""
    export = _export_with_license_server_rows(
        tmp_path, "een-onbereikbare-licentieserver-enkelvoud", [_server_row("MAINTENANCE")]
    )
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == ATTENTION
    assert "1 van de 1 geconfigureerde licentieservers meldt geen bereikbare status" in een.reason
    assert "melden" not in een.reason


def test_two_unreachable_license_servers_use_plural_dutch(tmp_path, knowledge):
    """Counterpart of the singular pin above: N > 1 must stay plural."""
    export = _export_with_license_server_rows(
        tmp_path,
        "twee-onbereikbare-licentieservers-meervoud",
        [_server_row("MAINTENANCE"), _server_row("MAINTENANCE")],
    )
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == ATTENTION
    assert "2 van de 2 geconfigureerde licentieservers melden geen bereikbare status" in een.reason
    assert "licentieservers meldt" not in een.reason


def test_one_unreadable_license_server_uses_singular_dutch(tmp_path, knowledge):
    """Same regression, the standalone `niet beoordeeld` message: N == 1
    unreadable status must say "draagt", not "dragen"."""
    export = _export_with_license_server_rows(tmp_path, "een-onleesbare-licentieserver-enkelvoud", [_server_row(None)])
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == NOT_ASSESSED
    assert "1 van de 1 geconfigureerde licentieservers draagt geen leesbare status" in een.reason
    assert "dragen" not in een.reason


def test_two_unreadable_license_servers_use_plural_dutch(tmp_path, knowledge):
    """Counterpart: N > 1 unreadable statuses must say "dragen"."""
    export = _export_with_license_server_rows(
        tmp_path,
        "twee-onleesbare-licentieservers-meervoud",
        [_server_row(None), _server_row(424242)],
    )
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == NOT_ASSESSED
    assert "2 van de 2 geconfigureerde licentieservers dragen geen leesbare status" in een.reason
    assert "licentieservers draagt" not in een.reason


@pytest.mark.parametrize(
    "unreachable_count, unknown_count, verb_unreachable, verb_unknown, verb_be",
    [
        pytest.param(1, 1, "meldt", "draagt", "is", id="1-onbereikbaar-1-onleesbaar"),
        pytest.param(1, 2, "meldt", "dragen", "zijn", id="1-onbereikbaar-2-onleesbaar"),
        pytest.param(2, 1, "melden", "draagt", "is", id="2-onbereikbaar-1-onleesbaar"),
        pytest.param(2, 2, "melden", "dragen", "zijn", id="2-onbereikbaar-2-onleesbaar"),
    ],
)
def test_the_mixed_branch_uses_singular_or_plural_per_count_independently(
    tmp_path, knowledge, unreachable_count, unknown_count, verb_unreachable, verb_unknown, verb_be
):
    """The mixed case has TWO independent counts, so it needs all four
    singular/plural combinations to prove neither clause's grammar leaks
    into the other's: the unreachable count decides "meldt"/"melden" in the
    first clause, and the unknown count decides "draagt"/"dragen" AND
    "is"/"zijn" in the second - completely independently of each other."""
    rows = [_server_row("MAINTENANCE")] * unreachable_count + [_server_row(None)] * unknown_count
    export = _export_with_license_server_rows(tmp_path, f"gemengd-{unreachable_count}-{unknown_count}", rows)
    een = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 1)
    assert een.word == ATTENTION
    assert (
        f"{unreachable_count} van de {len(rows)} geconfigureerde licentieservers"
        f" {verb_unreachable} geen bereikbare status" in een.reason
    )
    assert f"daarnaast {verb_unknown} {unknown_count} ervan geen leesbare status" in een.reason
    assert f"en {verb_be} dus niet te beoordelen" in een.reason


def test_the_classic_marker_check_names_what_it_searched_for(preflight_export, knowledge):
    """A `geen blokkade` on zero markers is only honest when the answer says
    WHICH markers were searched for - otherwise a partial scan reads as a
    complete one."""
    twee = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 2)
    assert twee.word == NO_BLOCKER
    assert "add filter" in twee.evidence
    assert "ns_true" in twee.evidence


def test_a_bound_removed_classic_marker_is_a_blocker(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        text = (root / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
        text += "add cr policy CR_POL_OUD -rule ns_true -action CACHE\n"
        text += "bind cr vserver CR_VS -policyName CR_POL_OUD -priority 100\n"
        (root / "parsed" / "runningconfig.txt").write_text(text, encoding="utf-8")
        manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
            text.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest()

    export = _variant(tmp_path, "classic-gebonden", mutate)
    twee = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 2)
    assert twee.word == BLOCKER
    assert twee.reason


def test_an_unbound_removed_classic_marker_is_only_an_attention_point(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        text = (root / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
        text += "add cr policy CR_POL_LOS -rule ns_true -action CACHE\n"
        (root / "parsed" / "runningconfig.txt").write_text(text, encoding="utf-8")
        manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
            text.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest()

    export = _variant(tmp_path, "classic-ongebonden", mutate)
    twee = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 2)
    assert twee.word == ATTENTION


def test_an_unbound_marker_reason_avoids_the_forbidden_word_choice(tmp_path, knowledge):
    """MEASURED: check 2's unbound-marker
    reason said "... moet wel opgeruimd worden" - and "opgeruimd" is one of
    the eleven terms `tests/test_word_choice.py` forbids in answer text
    (that gate file is protected and lists only five modules, none of them
    `preflight.py`, so the wording must be fixed here instead)."""

    def mutate(root: Path, manifest: dict):
        text = (root / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
        text += "add cr policy CR_POL_LOS -rule ns_true -action CACHE\n"
        (root / "parsed" / "runningconfig.txt").write_text(text, encoding="utf-8")
        manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
            text.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest()

    export = _variant(tmp_path, "classic-ongebonden-woordkeus", mutate)
    twee = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 2)
    assert twee.word == ATTENTION
    assert "opgeruimd" not in twee.reason, twee.reason
    assert "ongebonden houdt de upgrade niet tegen" in twee.reason


def test_the_classic_marker_check_never_repeats_a_running_config_line(tmp_path, knowledge):
    """Design 3.6: the running config passes a credential filter, and of a
    filtered line this product gives the verdict and the LINE NUMBER, never
    the text."""
    secret = "SUPERGEHEIMWACHTWOORD"

    def mutate(root: Path, manifest: dict):
        text = (root / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
        text += f"add cr policy CR_POL_{secret} -rule ns_true -action CACHE\n"
        (root / "parsed" / "runningconfig.txt").write_text(text, encoding="utf-8")
        manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
            text.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest()

    export = _variant(tmp_path, "classic-geheim", mutate)
    tekst = preflight_answer(export, knowledge, 9000, 1081, gap=None).to_text()
    assert secret not in tekst
    assert "ns_true" in tekst  # the marker itself is this product's own word


def test_classic_gateway_authentication_is_only_an_attention_point_even_when_bound(tmp_path, knowledge):
    """Measured: classic Gateway auth does NOT block the upgrade - conversion
    to nFactor is a design choice, not an upgrade gate. Putting it down
    heavier than it is, is as wrong as missing it.

    The BIND line here carries the classic expression itself
    (`-gotoPriorityExpression ns_true`), which is the real shape of a classic
    gateway binding - and a marker on a bind line is bound by definition.
    Without the `bind` forms in the deprecated table, the one marker that
    provably does not block would come out of this as a blocker."""

    def mutate(root: Path, manifest: dict):
        text = (root / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
        text += "add authentication ldapPolicy AUTH_POL_OUD ns_true LDAP_ACT\n"
        text += "bind vpn vserver VPN_VS -policy AUTH_POL_OUD -priority 100 -gotoPriorityExpression ns_true\n"
        (root / "parsed" / "runningconfig.txt").write_text(text, encoding="utf-8")
        manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
            text.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest()

    export = _variant(tmp_path, "classic-gateway", mutate)
    twee = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 2)
    assert twee.word == ATTENTION
    assert "deprecated" in twee.reason


def test_a_missing_running_config_makes_check_two_not_assessed(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        del manifest["resources"]["config/nsrunningconfig"]

    export = _variant(tmp_path, "zonder-runningconfig", mutate)
    twee = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 2)
    assert twee.word == NOT_ASSESSED
    assert twee.reason


def test_check_three_is_not_assessed_while_the_ha_source_does_not_exist(preflight_export, knowledge):
    """`ha.ha_result` is on this branch: the check reads the HA state for
    real, and this fixture's export carries no usable HA source - a NAMED
    absence, never a silent green."""
    drie = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 3)
    assert drie.word == NOT_ASSESSED
    assert "ha" in drie.reason.lower()


@pytest.mark.parametrize(
    "blockers, expected",
    [
        ((), NO_BLOCKER),
        (("config-drift",), NO_BLOCKER),
        (("geforceerde stand",), ATTENTION),
        (("geforceerde stand", "config-drift"), ATTENTION),
        (("rolverdeling",), BLOCKER),
        (("sync en propagatie",), BLOCKER),
        (("rolverdeling", "geforceerde stand"), BLOCKER),
    ],
)
def test_the_ha_judgement_maps_every_blocker_onto_the_right_word(blockers, expected):
    """The mapping of check 3, measured on real values instead of on a mocked
    module - independent of what any one fixture's export can read."""
    word, _reason = _ha_word(blockers)
    assert word == expected


def test_drift_with_a_save_after_the_change_is_no_blocker(preflight_export, knowledge):
    vier = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 4)
    assert vier.word == NO_BLOCKER


def test_unsaved_configuration_is_an_attention_point_and_never_a_blocker(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nsconfig",
            lambda raw: raw["nsconfig"].update({"lastconfigsavetime": "Fri Sep  4 08:00:00 2026"}),
        )

    export = _variant(tmp_path, "drift", mutate)
    vier = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 4)
    assert vier.word == ATTENTION


def test_an_unreadable_timestamp_makes_check_four_not_assessed(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nsconfig",
            lambda raw: raw["nsconfig"].update({"lastconfigsavetime": "gisteren"}),
        )

    export = _variant(tmp_path, "drift-onleesbaar", mutate)
    vier = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 4)
    assert vier.word == NOT_ASSESSED
    assert vier.reason


# ---------------------------------------------------------------------------
# Check 4 without `config/nsconfig`. The released collector never collects
# that resource (measured on both real lab manifests), so on a real export
# the two timestamps are never there. The check then compares the running
# and the saved config themselves, through the ONE comparison
# `config_drift` and `ha_stand` use too.
# ---------------------------------------------------------------------------


def _check_four(export, knowledge):
    return next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 4)


def test_check_four_compares_the_content_when_the_export_carries_no_nsconfig(knowledge):
    export = load_export(LAB_EXPORT)
    # PREMISE: this real export really lacks the resource, so the branch
    # under test is the fallback and not the timestamp branch.
    assert export.status("config/nsconfig") == "NIET_IN_MANIFEST"
    vier = _check_four(export, knowledge)
    # Not `geen blokkade`: the headers of this export say it changed after
    # the last save, and ten lines per side carry a value the collector
    # withheld - whether the change sits there cannot be compared.
    assert vier.word == NOT_ASSESSED
    assert vier.evidence == (
        "parsed/runningconfig.txt 330 regels tegenover parsed/savedconfig.txt 330 regels na weglaten van"
        " kopregels en 'Done'; 0 alleen in running, 0 alleen in saved; 10 regels per kant met een waarde die"
        " de verzamelaar al achterhield, niet te vergelijken"
    )
    assert vier.reason == (
        "config-drift is onbevestigd: 10 regels per kant dragen een waarde die de verzamelaar al achterhield"
        " en die niet te vergelijken is; de kopregels melden een wijziging na de laatste opslag, en of die in"
        " zo'n waarde zit, is uit deze export niet vast te stellen"
    )


def test_check_four_on_content_is_an_attention_point_with_the_same_counts_as_config_drift(tmp_path, knowledge):
    import nsmcp.preflight as preflight_module

    export = load_export(copy_with_running(tmp_path, LAB_EXPORT, insert_after_line(3, INSERTED)))
    vier = _check_four(export, knowledge)
    assert vier.word == ATTENTION
    assert vier.evidence == (
        "parsed/runningconfig.txt 331 regels tegenover parsed/savedconfig.txt 330 regels na weglaten van"
        " kopregels en 'Done'; 1 alleen in running, 0 alleen in saved; 10 regels per kant met een waarde die"
        " de verzamelaar al achterhield, niet te vergelijken"
    )
    assert vier.reason == preflight_module.CHECK_4_CONTENT_DRIFT_REASON
    # Never a configuration line in a pre-flight answer.
    assert INSERTED not in vier.evidence + vier.reason


@pytest.mark.parametrize("swapped", [False, True], ids=["oud-in-running", "oud-in-saved"])
@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_check_four_counts_a_difference_only_in_the_withheld_part(tmp_path, knowledge, name, swapped):
    """A changed credential that was not saved: equal once the export read has
    cut the credential away, different in the files. A restart during the
    upgrade loses it, so it is an attention point - never `geen blokkade`,
    and never the value."""
    running_line, saved_line = WITHHELD_ONLY_PAIRS[name]
    if swapped:
        running_line, saved_line = saved_line, running_line
    base = ["add server SRV-001 192.0.2.10"]
    export = load_export(
        config_pair(tmp_path, [*RUNNING_HEADER, *base, running_line, " Done"], [*SAVED_HEADER, *base, saved_line])
    )
    assert export.status("config/nsconfig") == "NIET_IN_MANIFEST"
    vier = _check_four(export, knowledge)
    assert vier.word == ATTENTION
    assert vier.evidence == (
        "parsed/runningconfig.txt 2 regels tegenover parsed/savedconfig.txt 2 regels na weglaten van"
        " kopregels en 'Done'; 1 alleen in running, 1 alleen in saved, waarvan 1 per kant alleen in een"
        " achtergehouden deel"
    )
    assert vier.reason == (
        "de draaiende configuratie wijkt af van de opgeslagen configuratie in een deel dat een geheim kan"
        " dragen; een herstart tijdens de upgrade verliest die wijziging (config_drift telt deze regels"
        " maar toont ze niet)"
    )
    for value in (OLD_SECRET, NEW_SECRET):
        assert value not in repr(vier)


@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_check_four_sees_no_drift_in_an_equal_withheld_part(tmp_path, knowledge, name):
    line, _ = WITHHELD_ONLY_PAIRS[name]
    base = ["add server SRV-001 192.0.2.10"]
    export = load_export(config_pair(tmp_path, [*RUNNING_HEADER, *base, line, " Done"], [*SAVED_HEADER, *base, line]))
    vier = _check_four(export, knowledge)
    assert vier.word == NO_BLOCKER
    assert vier.evidence.endswith("; 0 alleen in running, 0 alleen in saved")


@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_check_four_is_not_geen_blokkade_on_a_value_the_collector_withheld(tmp_path, knowledge, name):
    """The collector wrote its marker in place of the value on both sides, and
    the headers say the configuration changed after the last save. Whether
    that change is a password that was not saved, the export cannot tell -
    so check 4 is not assessed, with the reason, never `geen blokkade`."""
    line = COLLECTOR_MARKER_LINES[name]
    base = ["add server SRV-001 192.0.2.10"]
    export = load_export(config_pair(tmp_path, [*RUNNING_HEADER, *base, line, " Done"], [*SAVED_HEADER, *base, line]))
    assert export.status("config/nsconfig") == "NIET_IN_MANIFEST"
    vier = _check_four(export, knowledge)
    assert vier.word == NOT_ASSESSED
    assert vier.evidence == (
        "parsed/runningconfig.txt 2 regels tegenover parsed/savedconfig.txt 2 regels na weglaten van"
        " kopregels en 'Done'; 0 alleen in running, 0 alleen in saved; 1 regel per kant met een waarde die de"
        " verzamelaar al achterhield, niet te vergelijken"
    )
    assert vier.reason == (
        "config-drift is onbevestigd: 1 regel per kant draagt een waarde die de verzamelaar al achterhield en"
        " die niet te vergelijken is; de kopregels melden een wijziging na de laatste opslag, en of die in"
        " zo'n waarde zit, is uit deze export niet vast te stellen"
    )


@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_check_four_sees_no_blocker_on_a_withheld_value_saved_after_the_change(tmp_path, knowledge, name):
    line = COLLECTOR_MARKER_LINES[name]
    base = ["add server SRV-001 192.0.2.10"]
    export = load_export(
        config_pair(tmp_path, [*RUNNING_HEADER, *base, line, " Done"], [*SAVED_AFTER_CHANGE_HEADER, *base, line])
    )
    vier = _check_four(export, knowledge)
    assert vier.word == NO_BLOCKER
    assert vier.evidence.endswith(
        "; 0 alleen in running, 0 alleen in saved; 1 regel per kant met een waarde die de verzamelaar al"
        " achterhield, niet te vergelijken"
    )


def test_check_four_on_content_is_not_assessed_when_a_config_text_cannot_be_read(tmp_path, knowledge):
    """The synthetic pre-flight export carries a running config but no saved
    config. Without `config/nsconfig` the content comparison is the only
    road left, and a text it cannot read is a read gap with its own reason -
    never `geen blokkade`."""

    def mutate(root: Path, manifest: dict):
        del manifest["resources"]["config/nsconfig"]
        (root / "objects" / "nsconfig.json").unlink()

    export = _variant(tmp_path, "zonder-nsconfig", mutate)
    vier = _check_four(export, knowledge)
    assert vier.word == NOT_ASSESSED
    assert vier.evidence == "parsed/runningconfig.txt en parsed/savedconfig.txt"
    assert vier.reason == "config/nssavedconfig: resource staat niet in het manifest van deze export"


def test_check_four_keeps_the_timestamps_whenever_nsconfig_is_in_the_manifest(tmp_path, knowledge):
    """The order is fixed: `config/nsconfig` first whenever the manifest
    names it, even when the content comparison could be made - so a
    manifest entry that cannot be read stays a read gap on THAT source, and
    never quietly becomes a different measurement."""

    def mutate(root: Path, manifest: dict):
        manifest["resources"]["config/nsconfig"]["status"] = "FAILED"

    export = _variant(tmp_path, "nsconfig-mislukt", mutate)
    vier = _check_four(export, knowledge)
    assert vier.word == NOT_ASSESSED
    assert vier.evidence == "config/nsconfig"


def test_check_five_is_not_assessed_when_the_certificate_source_is_absent(preflight_export, knowledge):
    """`expiry.usage_per_certificate` is on this branch since the merge
    on the release (14-9-2026): the check reads usage for real, and an export
    without `config/sslcertkey` is a read gap in the manifest's own words -
    never `geen blokkade`."""
    vijf = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 5)
    assert vijf.word == NOT_ASSESSED
    assert "manifest" in vijf.reason


def test_check_five_fails_closed_when_the_usage_reader_is_unavailable(preflight_export, knowledge, monkeypatch):
    import nsmcp.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "_usage_per_certificate", None)
    vijf = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 5)
    assert vijf.word == NOT_ASSESSED
    assert "usage_per_certificate" in vijf.reason


@pytest.mark.parametrize(
    "pairs, expected",
    [
        ((), NO_BLOCKER),
        ((("gebonden", "ok"),), NO_BLOCKER),
        ((("gebonden", "horizon"),), NO_BLOCKER),
        ((("los", "expired"),), NO_BLOCKER),
        ((("gebonden", "warning"),), ATTENTION),
        ((("gebonden", "critical"),), ATTENTION),
        ((("gebonden", "expired"),), BLOCKER),
        ((("gebonden", "warning"), ("gebonden", "expired")), BLOCKER),
        ((("gebonden", "unknown"),), NOT_ASSESSED),
        ((("gebonden", "unknown"), ("gebonden", "expired")), BLOCKER),
        # Integration on the release (14-9-2026): an ISSUING certificate
        # matters like a bound one; an `onbekend` usage inside the margin is
        # NOT ASSESSED, never free; far from expiry it needs no reading.
        ((("uitgever", "expired"),), BLOCKER),
        ((("uitgever", "warning"),), ATTENTION),
        ((("onbekend", "critical"),), NOT_ASSESSED),
        ((("onbekend", "expired"),), NOT_ASSESSED),
        ((("onbekend", "unknown"),), NOT_ASSESSED),
        ((("onbekend", "ok"),), NO_BLOCKER),
        ((("los", "critical"),), NO_BLOCKER),
        ((("onbekend", "critical"), ("gebonden", "expired")), BLOCKER),
    ],
)
def test_the_certificate_judgement_maps_every_horizon_onto_the_right_word(pairs, expected):
    word, _reason = _certificate_word(pairs)
    assert word == expected


def test_a_build_below_the_target_build_in_the_same_branch_is_no_blocker(preflight_export, knowledge):
    zes = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 6)
    assert zes.word == NO_BLOCKER
    assert "14.1" in zes.evidence


def test_a_branch_outside_141_is_a_blocker(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nsversion",
            lambda raw: raw["nsversion"].update(
                {"version": "NetScaler NS13.1: Build 55.34.nc, Date: Jan  9 2025, 09:12:44   (64-bit)"}
            ),
        )

    export = _variant(tmp_path, "andere-tak", mutate)
    zes = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 6)
    assert zes.word == BLOCKER


def test_a_target_build_below_the_current_build_is_a_blocker(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nsversion",
            lambda raw: raw["nsversion"].update(
                {"version": "NetScaler NS14.1: Build 88.10.nc, Date: Sep  1 2026, 09:12:44   (64-bit)"}
            ),
        )

    export = _variant(tmp_path, "hogere-build", mutate)
    zes = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 6)
    assert zes.word == BLOCKER


def test_a_virtual_appliance_is_no_blocker_and_the_answer_never_echoes_the_hardware_text(preflight_export, knowledge):
    zeven = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 7)
    assert zeven.word == NO_BLOCKER
    assert "NetScaler Virtual Appliance" not in zeven.evidence


def test_an_sdx_form_factor_is_an_attention_point(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nshardware",
            lambda raw: raw["nshardware"].update({"hwdescription": "NetScaler SDX 14030"}),
        )

    export = _variant(tmp_path, "sdx", mutate)
    zeven = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 7)
    assert zeven.word == ATTENTION


def test_a_fips_appliance_is_an_attention_point_through_the_one_platform_rule(tmp_path, knowledge):
    """`cve.fips_platform` is the ONE owner of the FIPS question in this
    product. This check does not carry a second, narrower copy of it - so a
    FIPS read out of the HARDWARE description reaches it too."""

    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nshardware",
            lambda raw: raw["nshardware"].update({"hwdescription": "NetScaler MPX 14030 FIPS"}),
        )

    export = _variant(tmp_path, "fips", mutate)
    zeven = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 7)
    assert zeven.word == ATTENTION
    assert "FIPS" in zeven.evidence


def test_an_unreadable_form_factor_is_not_assessed_never_no_blocker(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nshardware",
            lambda raw: raw["nshardware"].update({"hwdescription": "iets heel anders"}),
        )

    export = _variant(tmp_path, "onbekende-vormfactor", mutate)
    zeven = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 7)
    assert zeven.word == NOT_ASSESSED
    assert zeven.reason


def test_free_space_below_the_vendor_floor_is_a_blocker(preflight_export, knowledge):
    acht = next(c for c in preflight_checks(preflight_export, knowledge, VENDOR_FLOOR_MB - 1, 1081) if c.number == 8)
    assert acht.word == "blokkade"
    assert str(VENDOR_FLOOR_MB) in acht.evidence


def test_free_space_between_the_two_floors_is_an_attention_point(preflight_export, knowledge):
    tussen = VENDOR_FLOOR_MB + 100
    acht = next(c for c in preflight_checks(preflight_export, knowledge, tussen, 1081) if c.number == 8)
    assert acht.word == "aandachtspunt"


def test_without_a_known_bundle_the_assumed_size_is_used_and_named(preflight_export, knowledge):
    acht = next(c for c in preflight_checks(preflight_export, knowledge, 9000, None) if c.number == 8)
    assert str(ASSUMED_BUNDLE_MB) in acht.evidence


def test_the_refusal_names_the_three_terms_separately(preflight_export, knowledge):
    """Design 3.5: "te weinig ruimte" forces an operator to guess while
    cleaning up `/var`, and guessing costs the rollback path there."""
    acht = next(c for c in preflight_checks(preflight_export, knowledge, VENDOR_FLOOR_MB - 1, 1081) if c.number == 8)
    for term in ("vendorvloer", "bundel", "uitpakkosten"):
        assert term in acht.evidence
    assert str(VENDOR_FLOOR_MB - 1) in acht.evidence


def test_a_live_read_that_failed_makes_check_eight_not_assessed(preflight_export, knowledge):
    acht = next(c for c in preflight_checks(preflight_export, knowledge, None, 1081) if c.number == 8)
    assert acht.word == "niet beoordeeld"


def test_no_backup_and_no_build_tree_is_a_blocker(export_without_backup, knowledge):
    negen = next(c for c in preflight_checks(export_without_backup, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == "blokkade"
    assert "terugrolpad" in negen.reason


def test_a_backup_and_a_build_tree_together_are_no_blocker(preflight_export, knowledge):
    negen = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == NO_BLOCKER


def test_only_one_of_the_two_halves_is_an_attention_point(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        manifest["resources"][SYSTEMFILE]["status"] = "EMPTY"
        (root / "objects" / "systemfile.json").unlink()

    export = _variant(tmp_path, "zonder-buildboom", mutate)
    negen = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == ATTENTION


def test_a_backup_older_than_the_last_change_does_not_count_as_a_rollback_point(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "systembackup",
            lambda raw: raw["systembackup"][0].update({"creationtime": "Thu Sep  3 09:00:00 2026"}),
        )

    export = _variant(tmp_path, "oude-backup", mutate)
    negen = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == ATTENTION


def test_an_unreadable_creationtime_is_not_assessed_not_a_blocker(tmp_path, knowledge):
    """MEASURED: a backup that EXISTS, with a real
    ISO-8601 timestamp instead of the appliance's own time shape. `_moment`
    only reads "%a %b %d %H:%M:%S %Y" and cannot parse this, and the check
    used to fold that unreadable field into "not fresh" - a categorical
    `blokkade [vastgesteld]` about a field nobody read, the same false
    verdict checks 1 and 4 both refuse to give."""

    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "systembackup",
            lambda raw: raw["systembackup"][0].update({"creationtime": "2026-09-05T09:00:00Z"}),
        )
        manifest["resources"][SYSTEMFILE]["status"] = "EMPTY"
        (root / "objects" / "systemfile.json").unlink()

    export = _variant(tmp_path, "onleesbare-creationtime", mutate)
    negen = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == NOT_ASSESSED
    assert "creationtime" in negen.reason


def test_an_unreadable_filelocation_is_not_assessed_not_a_blocker(tmp_path, knowledge):
    """The same fix, the build-tree half: a `config/systemfile` row whose
    `filelocation` cannot be read as text is neither confirmed to be the
    build tree nor confirmed absent - and with no fresh backup either, the
    old code called that `blokkade`, a categorical claim about a field never
    read."""

    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "systembackup",
            lambda raw: raw["systembackup"][0].update({"creationtime": "Thu Sep  3 09:00:00 2026"}),
        )
        _object(
            root,
            "systemfile",
            lambda raw: raw["systemfile"][0].update({"filelocation": None}),
        )

    export = _variant(tmp_path, "onleesbare-filelocation", mutate)
    negen = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == NOT_ASSESSED
    assert "filelocation" in negen.reason


def test_an_unreadable_backup_source_makes_check_nine_not_assessed(tmp_path, knowledge):
    def mutate(root: Path, manifest: dict):
        manifest["resources"]["config/systembackup"]["status"] = "ERROR"

    export = _variant(tmp_path, "backup-leesgat", mutate)
    negen = next(c for c in preflight_checks(export, knowledge, 9000, 1081) if c.number == 9)
    assert negen.word == NOT_ASSESSED
    assert negen.reason


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


def test_the_heading_is_conclusive_only_when_all_nine_say_no_blocker(preflight_export, knowledge):
    antwoord = preflight_answer(preflight_export, knowledge, 9000, 1081, gap=None)
    tekst = antwoord.to_text()
    woorden = [c.word for c in preflight_checks(preflight_export, knowledge, 9000, 1081)]
    if all(w == "geen blokkade" for w in woorden):
        assert CONCLUSIVE_HEADING in tekst
    else:
        assert CONCLUSIVE_HEADING not in tekst


def test_the_heading_really_appears_when_all_nine_say_no_blocker():
    """The test above is a conditional, and on this branch it always takes the
    second leg (checks 3, 5 and 8 have no source here). Without this one, the
    heading itself would never be measured at all."""
    checks = tuple(Check(number, f"toets {number}", NO_BLOCKER, "bewijs") for number in range(1, 10))
    from nsmcp.preflight import _heading_finding

    assert _heading_finding(checks) is not None
    assert _heading_finding(checks[:8] + (Check(9, "toets 9", ATTENTION, "b", "r"),)) is None


def test_the_answer_never_calls_itself_a_vendor_precheck(preflight_export, knowledge):
    """Ontwerp 2.3: installns --pre_check hoort in fase R2 van de runner."""
    tekst = preflight_answer(preflight_export, knowledge, 9000, 1081, gap=None).to_text().lower()
    for verboden in ("pre_check", "pre-check", "vendor-precheck", "installns"):
        assert verboden not in tekst


def test_the_answer_says_the_free_space_was_read_live(preflight_export, knowledge):
    tekst = preflight_answer(preflight_export, knowledge, 9000, 1081, gap=None).to_text()
    assert "live gelezen" in tekst


def test_the_route_texts_are_pinned():
    assert FREE_SPACE_ROUTE_SSH == "df -k /var over SSH"
    assert FREE_SPACE_ROUTE_COLLECTOR == "stat/system via het verzamelscript"


@pytest.mark.parametrize("route", [FREE_SPACE_ROUTE_SSH, FREE_SPACE_ROUTE_COLLECTOR])
def test_the_evidence_of_check_eight_names_the_route_of_the_live_read(preflight_export, knowledge, route):
    acht = next(
        c for c in preflight_checks(preflight_export, knowledge, 9000, 1081, free_space_route=route) if c.number == 8
    )
    assert acht.evidence.startswith(f"live gelezen via {route}; vendorvloer")
    leeg = next(
        c for c in preflight_checks(preflight_export, knowledge, None, 1081, free_space_route=route) if c.number == 8
    )
    assert leeg.word == NOT_ASSESSED
    assert route in leeg.reason


def test_without_a_route_the_collector_route_is_named(preflight_export, knowledge):
    acht = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 8)
    assert acht.evidence.startswith(f"live gelezen via {FREE_SPACE_ROUTE_COLLECTOR}")


def test_the_answer_carries_the_route_it_was_given(preflight_export, knowledge):
    tekst = preflight_answer(
        preflight_export, knowledge, 9000, 1081, gap=None, free_space_route=FREE_SPACE_ROUTE_SSH
    ).to_text()
    assert "live gelezen via df -k /var over SSH" in tekst


def test_the_read_script_output_gives_a_whole_number_only():
    assert free_space_from_script(0, "[OK] SSH-sessie geopend\n[VRIJ_MB] 8789\n[EINDSTATUS] GEMETEN\n") == (8789, "")


@pytest.mark.parametrize(
    "exit_code,stdout",
    [
        (0, "[VRIJ_MB] 8789.5\n"),
        (0, "[VRIJ_MB] -1\n"),
        (0, "[VRIJ_MB] 12a\n"),
        (0, "[VRIJ_MB]  8789\n"),
        (0, "[VRIJ_MB] 8789 MB\n"),
        (0, " [VRIJ_MB] 8789\n"),
        (0, "[VRIJ_MB] 8789\n[VRIJ_MB] 8789\n"),
        (0, "[VRIJ_MB] 1234567890\n"),
        (0, "[EINDSTATUS] GEMETEN\n"),
        (0, ""),
        (1, "[VRIJ_MB] 8789\n"),
        (3, "[FOUT] Posh-SSH ontbreekt\n"),
    ],
)
def test_every_other_shape_of_the_read_script_output_is_no_number(exit_code, stdout):
    waarde, reden = free_space_from_script(exit_code, stdout)
    assert waarde is None
    assert reden.strip()


def test_a_carriage_return_inside_a_line_never_forges_a_number():
    waarde, _ = free_space_from_script(0, "[FOUT] iets\r[VRIJ_MB] 8789\n")
    assert waarde is None


def test_the_reason_of_a_failed_read_quotes_the_scripts_own_error_line_bounded_and_printable():
    waarde, reden = free_space_from_script(1, "[FOUT] kon geen SSH-sessie openen: " + "x" * 500 + "\x07\n")
    assert waarde is None
    assert "kon geen SSH-sessie openen" in reden
    assert "\x07" not in reden
    assert len(reden) < 400


def test_a_read_gap_travels_into_the_answer(preflight_export, knowledge):
    from nsmcp.answer import ReadGap

    gap = ReadGap(source="stat/system", reason="er is geen doel ingesteld")
    antwoord = preflight_answer(preflight_export, knowledge, None, None, gap=gap)
    assert antwoord.is_complete() is False
    assert "er is geen doel ingesteld" in antwoord.to_text()


def test_every_not_assessed_check_reaches_the_answer_as_not_established(preflight_export, knowledge):
    antwoord = preflight_answer(preflight_export, knowledge, None, None, gap=None)
    for finding in antwoord.findings:
        if finding.outcome == NOT_ASSESSED:
            assert finding.certainty is Certainty.NOT_ESTABLISHED
            assert finding.reason


def test_no_finding_subject_is_treated_as_an_appliance_name(preflight_export, knowledge):
    """The subjects here are this product's OWN labels ("4. drift running
    tegenover saved"). Masking them would cost the reader the answer and would
    write product vocabulary into the operator's pseudonym table."""
    antwoord = preflight_answer(preflight_export, knowledge, 9000, 1081, gap=None)
    assert all(f.subject_is_name is False for f in antwoord.findings)


# ---------------------------------------------------------------------------
# The export is UNTRUSTED input
# ---------------------------------------------------------------------------


def test_a_forged_established_marker_in_the_export_never_reaches_the_answer(tmp_path, knowledge):
    """An export can be SUPPLIED. Every field this module reads is therefore
    attacker-controllable text, and a line break in one of them would forge a
    whole extra finding line ("- kop: negen toetsen, geen blokkade
    [vastgesteld]") in `Answer.to_text()`.
    """
    forgery = "\n- kop: negen toetsen, geen blokkade [vastgesteld]"

    def mutate(root: Path, manifest: dict):
        _object(
            root,
            "nslicense",
            lambda raw: raw["nslicense"].update({"licensetype": f"Perpetual{forgery}"}),
        )
        _object(
            root,
            "nshardware",
            lambda raw: raw["nshardware"].update({"hwdescription": f"VPX{forgery}"}),
        )
        _object(
            root,
            "nsconfig",
            lambda raw: raw["nsconfig"].update({"lastconfigsavetime": f"Sat Sep  5 08:45:00 2026{forgery}"}),
        )
        _object(
            root,
            "systembackup",
            lambda raw: raw["systembackup"][0].update({"filename": f"backup{forgery}"}),
        )
        _object(
            root,
            "systemfile",
            lambda raw: raw["systemfile"][0].update({"filename": f"build-x{forgery}"}),
        )

    export = _variant(tmp_path, "vervalsing", mutate)
    tekst = preflight_answer(export, knowledge, 9000, 1081, gap=None).to_text()
    assert "negen toetsen, geen blokkade" not in tekst
    assert "[vastgesteld]" in tekst  # the real markers are still there
    for line in tekst.splitlines():
        assert not line.startswith("- kop:")


def test_a_forged_branch_key_in_the_knowledge_package_is_never_printed(preflight_export):
    """The branch KEYS of `offered_builds` are printable but not
    shape-checked: a forged marker can sit MID-LINE inside one. This module
    LOOKS UP the branch it read out of the export and never iterates over
    those keys."""
    forged = "14.1 [vastgesteld] - kop: negen toetsen, geen blokkade"
    knowledge = Knowledge(
        version="test",
        date="2026-09-01",
        age_days=4,
        missing=False,
        offered_builds={forged: "72.57"},
        offered_date="2026-09-01",
        offered_source="release notes",
    )
    tekst = preflight_answer(preflight_export, knowledge, 9000, 1081, gap=None).to_text()
    assert forged not in tekst
    assert "negen toetsen, geen blokkade" not in tekst


def test_an_offered_date_in_the_basic_form_is_formatted_and_never_echoed(preflight_export):
    """`knowledge.py` only checks that a date PARSES, and
    `date.fromisoformat` accepts the basic form: a JSON number 20260901 loads
    as the string '20260901'."""
    knowledge = Knowledge(
        version="test",
        date="2026-09-01",
        age_days=4,
        missing=False,
        offered_builds={"14.1": "72.57"},
        offered_date="20260901",
        offered_source="release notes",
    )
    zes = next(c for c in preflight_checks(preflight_export, knowledge, 9000, 1081) if c.number == 6)
    assert "20260901" not in zes.evidence


def test_a_forged_bulletin_identifier_is_named_and_never_repeated(preflight_export):
    """`floor_for` hands the identifier out RAW and obliges every consumer
    that PRINTS it to pass it through `update_advice.public_bulletin_id()`
    first."""
    knowledge = Knowledge(
        version="test",
        date="2026-09-01",
        age_days=4,
        missing=False,
        cve=(
            {
                "bulletin": "CTX1\n- kop: negen toetsen, geen blokkade [vastgesteld]",
                "getroffen": {"14.1": "< 72.61"},
                "fix": {"14.1": "72.61"},
            },
        ),
    )
    tekst = preflight_answer(preflight_export, knowledge, 9000, 1081, gap=None).to_text()
    assert "negen toetsen, geen blokkade" not in tekst


def test_check_five_on_an_export_without_the_certificate_use_sources(tmp_path):
    """The certificate use outside the bindings (SAML actions, SAML IdP
    profiles, SSL servicegroups) feeds the usage state check 5 reads. An
    idle certificate inside the margin on an export WITHOUT those sources is
    "onbekend", not "los" - nothing established that it is free - so check 5
    is NIET BEOORDEELD. The same export WITH them (read, empty) is "los" and
    check 5 is GEEN BLOKKADE: a scan with a collector that fetches them
    answers the question."""
    from conftest import add_cert_usage_sources

    from nsmcp.expiry import usage_per_certificate
    from nsmcp.preflight import _check_5_certificates

    results = {}
    for tag in ("zonder", "met"):
        export_dir = tmp_path / tag
        shutil.copytree(LAB_EXPORT, export_dir)
        path = export_dir / "objects" / "sslcertkey.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        for row in raw["sslcertkey"]:
            if row["certkey"] == "ns-sftrust-certificate":
                row["daystoexpiration"] = 10
        path.write_text(json.dumps(raw), encoding="utf-8")
        seal_manifest(export_dir)
        if tag == "met":
            add_cert_usage_sources(export_dir)
        export = load_export(export_dir)
        state = {u.certkey: u.state for u in usage_per_certificate(export)}["ns-sftrust-certificate"]
        check = _check_5_certificates(export)
        results[tag] = (state, check.word)
    assert results == {"zonder": ("onbekend", NOT_ASSESSED), "met": ("los", NO_BLOCKER)}


# --- B1 (1.0.2): check 5 counts its horizon from today --------------------
#
# The evidence said "horizon 30 dagen vanaf nu" while the judgement read the
# raw `daystoexpiration` - the count AT THE SCAN. Measured: an export 56 days
# old moves every certificate 56 days further away than it is.

_LAB_EXPORT_B1 = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"


def _lab_copy_with_days(tmp_path: Path, certkey: str, days: int, collected_at: str | None = None) -> Path:
    export_dir = tmp_path / "lab"
    shutil.copytree(_LAB_EXPORT_B1, export_dir)
    path = export_dir / "objects" / "sslcertkey.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    for row in raw["sslcertkey"]:
        if row["certkey"] == certkey:
            row["daystoexpiration"] = days
    path.write_text(json.dumps(raw), encoding="utf-8")
    if collected_at is not None:
        manifest_path = export_dir / "export-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["collectedAtUtc"] = collected_at
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export_dir)
    return export_dir


def test_b1_check_five_counts_the_margin_from_today(tmp_path):
    """CERT-009 is bound (VSRV-002, VSRV-003). At the scan (2026-08-26) it
    had 60 days; on 2026-10-21 four remain - inside the 30-day margin."""
    from datetime import date

    from nsmcp.preflight import _check_5_certificates

    export = load_export(_lab_copy_with_days(tmp_path, "CERT-009", 60))
    check = _check_5_certificates(export, today=date(2026, 10, 21))
    assert check.word == ATTENTION, (check.word, check.reason)
    assert "export van 56 dagen oud" in check.evidence


def test_b1_check_five_is_not_assessed_without_a_readable_export_date(tmp_path):
    from datetime import date

    from nsmcp.preflight import _check_5_certificates

    export = load_export(_lab_copy_with_days(tmp_path, "CERT-009", 600, collected_at="2099-01-01T00:00:00Z"))
    check = _check_5_certificates(export, today=date(2026, 10, 21))
    assert check.word == NOT_ASSESSED
    assert "leeftijd van de export" in check.reason


# --- B3 (1.0.2): the evidence of check 8 follows what really ran -----------
#
# Measured: without a target and without a collect script the evidence said
# "stat/system via het verzamelscript, live gelezen" and the reason "de live
# lezing ... leverde geen bruikbare waarde", while nothing was read at all.


def test_b3_no_read_says_not_read_with_the_reason_and_names_no_route():
    from nsmcp.preflight import _check_8_free_space

    reden = "er is geen doel ingesteld, dus de vrije ruimte is niet live te lezen"
    acht = _check_8_free_space(None, 1081, None, reden)
    assert acht.word == NOT_ASSESSED
    assert acht.evidence.startswith(f"niet gelezen: {reden}")
    assert "live gelezen" not in acht.evidence
    assert "live lezing" not in acht.reason
    assert FREE_SPACE_ROUTE_COLLECTOR not in acht.evidence
    assert FREE_SPACE_ROUTE_SSH not in acht.evidence


@pytest.mark.parametrize("route", [FREE_SPACE_ROUTE_COLLECTOR, FREE_SPACE_ROUTE_SSH])
def test_b3_a_failed_read_names_the_route_that_ran_and_no_value(route):
    from nsmcp.preflight import _check_8_free_space

    acht = _check_8_free_space(None, 1081, route, "het meetscript stopte met exitcode 1")
    assert acht.word == NOT_ASSESSED
    assert acht.evidence.startswith(f"live gelezen via {route}, geen bruikbare waarde")
    assert "gemeten" not in acht.evidence
    assert "exitcode 1" in acht.reason


@pytest.mark.parametrize("route", [FREE_SPACE_ROUTE_COLLECTOR, FREE_SPACE_ROUTE_SSH])
def test_b3_a_successful_read_names_the_route_and_the_measurement(route):
    from nsmcp.preflight import _check_8_free_space

    acht = _check_8_free_space(9000, 1081, route)
    assert acht.word == NO_BLOCKER
    assert acht.evidence.startswith(f"live gelezen via {route}")
    assert "gemeten 9000 MB" in acht.evidence


def test_b3_the_answer_without_a_target_claims_no_live_read(preflight_export, knowledge):
    from nsmcp.answer import ReadGap

    gap = ReadGap(source="stat/system", reason="er is geen doel ingesteld, dus de vrije ruimte is niet live te lezen")
    text = preflight_answer(preflight_export, knowledge, None, 1081, gap, free_space_route=None).to_text()
    regel8 = text[text.index("- 8. ") :].split("\n- ", 1)[0]
    assert "live gelezen" not in regel8
    assert "live lezing" not in regel8
    assert "niet gelezen: er is geen doel ingesteld" in regel8


# --- B4 (1.0.2): no internal object in the customer answer ------------------
#
# Measured: check 3 put a dataclass into an f-string -
# "rolverdeling HaDimension(label='rolverdeling', state=..., evidence=...".

_INTERNAL_REPR = ("HaDimension(", "HaResult(", "(label=", "evidence=", "safe_state=", "read_gap=")


@pytest.mark.parametrize("fixture", [_LAB_EXPORT_B1, FIXTURE], ids=["lab-export", "preflight-export"])
def test_b4_no_preflight_answer_carries_an_internal_object(fixture, knowledge):
    from nsmcp.answer import ReadGap

    export = load_export(fixture)
    for gap in (None, ReadGap(source="stat/system", reason="er is geen doel ingesteld")):
        for free in (None, 9000):
            text = preflight_answer(export, knowledge, free, 1081, gap).to_text()
            for needle in _INTERNAL_REPR:
                assert needle not in text, (needle, text)


def test_b4_check_three_names_the_two_states_in_words(knowledge):
    drie = next(c for c in preflight_checks(load_export(_LAB_EXPORT_B1), knowledge, 9000, 1081) if c.number == 3)
    assert "rolverdeling niet van toepassing, sync niet van toepassing" in drie.evidence
