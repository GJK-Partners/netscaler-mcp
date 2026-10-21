"""The boundary with NSHC, guarded here.

netscaler-mcp does not rebuild the NITRO read path but calls NSHC 1.0's.
That saves a second reader and guarantees parity by construction - but it
also means a change on the other side can silently propagate here.

Known limitation (deliberate): the test below is a TEXTUAL ANCHOR GREP on
the script source, not a semantic parser - it looks for a fixed list of
tokens ("collectedAtUtc", "'OK'", ...) literally in the file, and does not
check WHETHER those tokens are actually live code. If a token disappears
from the real export logic but happens to survive in a comment line or dead
code, this test stays green while the export format really has changed.
This is a tripwire on six anchors, not a guarantee that every format change
is noticed. A semantic parser (actually running the script or reading its
AST) would cover that, but is disproportionate for this purpose - a textual
anchor grep is a deliberate, cheap choice that catches the most likely
changes (a key or status value being renamed) just fine.

The test skips when the NSHC working file is absent (a bare clone of this
repo must be able to run), but it invents nothing - it says what it could
not check.
"""

import json
import os
from pathlib import Path

import pytest

from nsmcp.export import load_export

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"


def _script_path() -> Path | None:
    value = os.environ.get("NSMCP_VERZAMELSCRIPT")
    return Path(value) if value else None


_configured_script = _script_path()

requires_script = pytest.mark.skipif(
    _configured_script is None or not _configured_script.exists(),
    reason=(
        "NSMCP_VERZAMELSCRIPT niet gezet of wijst niet naar een bestaand "
        "bestand; exportvorm van het verzamelscript is NIET gecontroleerd. "
        "Zet NSMCP_VERZAMELSCRIPT op het pad naar het verzamelscript om dit "
        "lokaal te controleren."
    ),
)


@requires_script
def test_the_collect_script_still_writes_the_agreed_format():
    """Six anchors. If one disappears, the engine will soon read thin air.

    The last two anchors cover the STATUS VOCABULARY that both the export
    reader (export.py::USABLE) and the swap gate
    (collect.py::_has_usable_resource) fully lean on. If the collector
    script renamed 'EMPTY' to, say, 'NONE', every empty resource would
    silently become a read gap AND the swap gate would start rejecting good
    scans (no resource would count as usable any more) - the anchors exist
    to notice exactly that.
    """
    text = _script_path().read_text(encoding="utf-8", errors="replace")
    for anchor in ("collectedAtUtc", "export-manifest.json", "'objects'", "'bindings'", "'OK'", "'EMPTY'"):
        assert anchor in text, (
            f"anker '{anchor}' staat niet meer in het verzamelscript; de exportvorm is gewijzigd "
            "en de motor van netscaler-mcp moet opnieuw beoordeeld worden"
        )


@requires_script
def test_the_collect_script_knows_the_switches_we_use():
    text = _script_path().read_text(encoding="utf-8", errors="replace")
    for switch in ("SkipTransport", "CredentialTarget", "ExpectedCertThumbprint", "OutDir", "NetScaler"):
        assert switch in text, f"schakelaar -{switch} bestaat niet meer in het verzamelscript"


def test_the_engine_reads_the_timestamp_from_the_agreed_key(tmp_path):
    """This half always runs, even without NSHC: it pins that the engine
    reads collectedAtUtc and nothing else."""
    (tmp_path / "export-manifest.json").write_text(
        json.dumps({"collectedAtUtc": "2026-08-20T12:00:00.0000000Z", "resources": {}, "files": {}}),
        encoding="utf-8",
    )
    assert load_export(tmp_path).collected_at == "2026-08-20T12:00:00.0000000Z"


def test_a_manifest_with_a_different_key_yields_no_timestamp(tmp_path):
    """Negative check: if load_export also looked anywhere else, the test
    above would prove nothing."""
    (tmp_path / "export-manifest.json").write_text(
        json.dumps({"generatedAt": "2026-08-20T12:00:00Z", "resources": {}, "files": {}}),
        encoding="utf-8",
    )
    assert load_export(tmp_path).collected_at is None


# ---------------------------------------------------------------------------
# LIVE ANCHOR (fixture lab-export-vpx-20260826): the six text anchors above
# are a grep on the collector SCRIPT and say themselves (see the module
# docstring) that they give no semantic guarantee.
# `tests/fixtures/lab-export-vpx-20260826/` is not a grep but a REAL export
# the collector actually wrote - these anchors run the engine against it,
# and so also trip when the CODE (not the script) silently diverges from
# what the collector really puts on disk. Neither text anchor looks at file
# names, and until this fixture existed every fixture in
# `tests/test_export.py` shared the same (by now outdated) assumption with
# the code it tested.
# ---------------------------------------------------------------------------


def test_the_engine_reads_exactly_the_object_file_name_the_real_collector_writes():
    export = load_export(FIXTURE)
    certs, gap = export.objects("config/sslcertkey")
    assert gap is None, f"onverwacht leesgat tegen de echte export: {gap}"
    assert {c["certkey"] for c in certs} == {
        "ns-sftrust-certificate",
        "ns-server-certificate",
        "CERT-004",
        "CERT-009",
    }
    # The WRONG, old name must not even exist on disk - otherwise this
    # fixture no longer proves the point.
    assert not (FIXTURE / "objects" / "config_sslcertkey.json").exists()
    assert (FIXTURE / "objects" / "sslcertkey.json").exists()


def test_the_engine_reads_exactly_the_binding_file_the_real_collector_writes():
    export = load_export(FIXTURE)
    bindings, gap = export.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is None, f"onverwacht leesgat tegen de echte export: {gap}"
    assert len(bindings) == 2
    assert {b["vservername"] for b in bindings} == {"VSRV-003", "VSRV-002"}
    assert {b["certkeyname"] for b in bindings} == {"CERT-009"}
    # The WRONG, old name/shape must not even exist on disk.
    assert not (FIXTURE / "bindings" / "sslvserver_sslcertkey_binding.json").exists()
    assert (FIXTURE / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").exists()
