"""1.0.3 K-3: a required configuration step after the upgrade does not vanish
above the firmware floor.

MEASURED before (1.0.2): the engine showed `extraStapNaUpgrade` only BELOW
the fix-build, and from the fix-build on every CVE of the bulletin read
`NIET GERAAKT [vastgesteld]`. For two bulletin lines firmware alone is not
the remedy: CVE-2026-13474 (CTX696604) also needs the HTTP/2 small-window
timeout on profiles without HTTP Strict Profiles, CVE-2026-88778 (CTX697096)
needs Enhanced ISN Generation. 14.1-72.61 with an active HTTP/2 profile at
timeout 0, and 14.1-73.37 with a TCP vserver and Enhanced ISN off, both came
out `NIET GERAAKT [vastgesteld]` without the advice.

The package tells the engine which CVE carries such a step with the
optional, per-CVE field `naconfiguratieVerplicht: true`. The bulletin-level
`extraStapNaUpgrade` is not unambiguous for that: it is one sentence for
all CVEs of a bulletin (CTX697096 has eight, one needs the step), and the
package uses it for investigation advice and for "no extra step known"
too. On or above the floor such a CVE is `NIET VASTGESTELD`, with a typed
read gap and the advice visible, unless its condition is positively absent.
A package without the field behaves exactly as before.

The three synthetic cases of the review are tests here: HTTP/2 at the floor,
Enhanced ISN at the floor, and DTLS on a load-balancing vserver below the
floor under the conservative condition `altijd`.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from nsmcp.answer import Certainty
from nsmcp.cve import NIET_GERAAKT, NIET_VASTGESTELD, cve_check, cve_verdicts
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge, load_knowledge

HTTP2_STEP = "Na de upgrade op profielen zonder HTTP Strict Profiles http2SmallWndTimeout 30 zetten."
ISN_STEP = "Na de upgrade Enhanced ISN Generation inschakelen in de TCP-parameters."

_CTX696604 = {
    "bulletin": "CTX696604",
    "datum": "2026-06-30",
    "getroffen": {"14.1": "< 72.61", "13.1": "< 63.18"},
    "fix": {"14.1": "72.61", "13.1": "63.18"},
    "cves": [
        {
            "id": "CVE-2026-13474",
            "cvss": 8.7,
            "kern": "HTTP/2-profiel",
            "voorwaarde": "heeft_http2_profiel",
            "naconfiguratieVerplicht": True,
        }
    ],
    "advies": "Upgrade naar 14.1-72.61 of 13.1-63.18.",
    "extraStapNaUpgrade": HTTP2_STEP,
}
_CTX697096 = {
    "bulletin": "CTX697096",
    "datum": "2026-09-27",
    "getroffen": {"14.1": "< 73.37", "13.1": "< 64.23"},
    "fix": {"14.1": "73.37", "13.1": "64.23"},
    "cves": [
        {"id": "CVE-2026-88771", "cvss": 9.5, "kern": "geen extra feature", "voorwaarde": "altijd"},
        {"id": "CVE-2026-88772", "cvss": 9.5, "kern": "DTLS", "voorwaarde": "altijd"},
        {
            "id": "CVE-2026-88778",
            "cvss": 8.8,
            "kern": "TCP en ISN",
            "voorwaarde": "altijd",
            "naconfiguratieVerplicht": True,
        },
    ],
    "advies": "Upgrade naar 14.1-73.37 of 13.1-64.23.",
    "extraStapNaUpgrade": ISN_STEP,
}


def _knowledge(*bulletins) -> Knowledge:
    return Knowledge(version="test", date="2026-10-21", age_days=1, missing=False, cve=tuple(bulletins))


def _without_field(bulletin: dict) -> dict:
    other = copy.deepcopy(bulletin)
    for cve in other["cves"]:
        cve.pop("naconfiguratieVerplicht", None)
    return other


def _export(root: Path, build: str, resources: dict, lines: list[str]):
    """The synthetic export shape of the review's probe: a hash-valid manifest,
    one object file per resource and a parsed running config."""
    (root / "objects").mkdir(parents=True)
    (root / "parsed").mkdir()
    resources = {
        "config/nsversion": {"version": f"NetScaler NS14.1: Build {build}.nc", "mode": "1"},
        "config/nshardware": {"hwdescription": "Synthetic VPX"},
        "config/systemparameter": {"fipsusermode": "DISABLED"},
        **resources,
    }
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-10-22T00:00:00.0000000Z",
        "resources": {},
        "files": {},
    }
    for resource, rows in resources.items():
        key = resource.rsplit("/", 1)[-1]
        payload = {"errorcode": 0, "message": "Done"}
        if rows:
            payload[key] = rows
        blob = json.dumps(payload).encode("ascii")
        (root / "objects" / f"{key}.json").write_bytes(blob)
        manifest["resources"][resource] = {
            "status": "OK" if rows else "EMPTY",
            "payloadSha256": hashlib.sha256(blob).hexdigest().upper(),
        }
    blob = ("\n".join(lines) + "\n").encode("ascii")
    (root / "parsed" / "runningconfig.txt").write_bytes(blob)
    manifest["resources"]["config/nsrunningconfig"] = {"status": "OK"}
    manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(blob).hexdigest()
    (root / "export-manifest.json").write_text(json.dumps(manifest), encoding="ascii")
    return load_export(root)


def _http2(root: Path, build: str = "72.61", *, http2: str = "ENABLED"):
    resources = {
        "config/nshttpprofile": [{"name": "P1", "http2": http2, "http2smallwndtimeout": "0"}],
        "config/nsparam": {"httpprofilename": "P1"},
        "config/lbvserver": [{"name": "LBHTTP", "servicetype": "SSL", "httpprofilename": "P1"}],
        "config/csvserver": [],
        "config/vpnvserver": [],
        "config/service": [],
        "config/servicegroup": [],
    }
    lines = [
        f"#NS14.1 Build {build}",
        f"add ns httpProfile P1 -http2 {http2} -http2SmallWndTimeout 0",
        "set ns param -httpProfileName P1",
        "add lb vserver LBHTTP SSL 192.0.2.10 443 -httpProfileName P1",
    ]
    return _export(root, build, resources, lines)


def _isn(root: Path, build: str = "73.37"):
    resources = {
        "config/nstcpparam": {"enhancedisngeneration": "DISABLED"},
        "config/lbvserver": [{"name": "LBTCP", "servicetype": "TCP"}],
    }
    lines = [
        f"#NS14.1 Build {build}",
        "set ns tcpParam -enhancedISNgeneration DISABLED",
        "add lb vserver LBTCP TCP 192.0.2.10 443",
    ]
    return _export(root, build, resources, lines)


def _dtls_lb(root: Path, build: str = "73.36"):
    resources = {
        "config/vpnvserver": [],
        "config/authenticationvserver": [],
        "config/lbvserver": [{"name": "LBDTLS", "servicetype": "DTLS"}],
    }
    lines = [f"#NS14.1 Build {build}", "add lb vserver LBDTLS DTLS 192.0.2.10 443"]
    return _export(root, build, resources, lines)


def _verdict_line(answer, cve_id):
    # The first finding of a CVE is its verdict line, the second its condition.
    return next(f for f in answer.findings if f.subject == cve_id)


def _advice(answer, bulletin):
    return [f for f in answer.findings if f.subject == f"{bulletin} advies"]


def test_http2_at_the_floor_is_not_established_with_the_step_visible(tmp_path):
    answer = cve_check(_http2(tmp_path), _knowledge(_CTX696604))
    line = _verdict_line(answer, "CVE-2026-13474")
    assert line.outcome.startswith(NIET_VASTGESTELD), line
    assert line.certainty is Certainty.NOT_ESTABLISHED
    assert "naconfiguratie" in line.outcome
    advice = _advice(answer, "CTX696604")
    assert advice and HTTP2_STEP in advice[0].outcome, answer.findings
    assert advice[0].certainty is Certainty.NOT_ESTABLISHED
    assert any(gap.source == "CVE-2026-13474 (naconfiguratie)" for gap in answer.read_gaps), answer.read_gaps
    text = answer.to_text()
    assert HTTP2_STEP in text
    assert "NIET GERAAKT [vastgesteld]" not in text


def test_isn_at_the_floor_is_not_established_with_the_step_visible(tmp_path):
    answer = cve_check(_isn(tmp_path), _knowledge(_CTX697096))
    line = _verdict_line(answer, "CVE-2026-88778")
    assert line.outcome.startswith(NIET_VASTGESTELD), line
    advice = _advice(answer, "CTX697096")
    assert advice and ISN_STEP in advice[0].outcome
    # The other CVEs of the SAME bulletin carry no step: firmware is their fix.
    assert _verdict_line(answer, "CVE-2026-88771").outcome.startswith(NIET_GERAAKT)
    assert _verdict_line(answer, "CVE-2026-88772").outcome.startswith(NIET_GERAAKT)


def test_the_typed_verdict_follows_the_text(tmp_path):
    records, gaps = cve_verdicts(_isn(tmp_path), _knowledge(_CTX697096))
    verdicts = [r.verdict for r in records]
    assert verdicts == [NIET_GERAAKT, NIET_GERAAKT, NIET_VASTGESTELD], verdicts
    flagged = records[2]
    assert flagged.read_gap is not None and flagged.read_gap.source == "CVE-2026-88778 (naconfiguratie)"
    assert flagged.read_gap in gaps


def test_a_positively_absent_condition_stays_not_affected(tmp_path):
    """No HTTP/2 profile in use: the step does not apply, and the established
    NIET GERAAKT stands - the step does not demote every answer."""
    answer = cve_check(_http2(tmp_path, http2="DISABLED"), _knowledge(_CTX696604))
    line = _verdict_line(answer, "CVE-2026-13474")
    assert line.outcome.startswith(NIET_GERAAKT), line
    assert line.certainty is Certainty.ESTABLISHED
    assert _advice(answer, "CTX696604") == []


def test_below_the_floor_the_verdict_is_unchanged_and_the_step_shown(tmp_path):
    answer = cve_check(_http2(tmp_path, build="72.58"), _knowledge(_CTX696604))
    assert _verdict_line(answer, "CVE-2026-13474").outcome.startswith("GERAAKT")
    advice = _advice(answer, "CTX696604")
    assert advice and HTTP2_STEP in advice[0].outcome and advice[0].certainty is Certainty.ESTABLISHED


def test_a_package_without_the_field_behaves_as_before(tmp_path):
    """Backwards compatible: no field, no change - also above the floor."""
    answer = cve_check(_isn(tmp_path), _knowledge(_without_field(_CTX697096)))
    assert _verdict_line(answer, "CVE-2026-88778").outcome.startswith(NIET_GERAAKT)
    assert _advice(answer, "CTX697096") == []


def test_dtls_on_a_load_balancing_vserver_below_the_floor_is_affected(tmp_path):
    """The third case of the review: under the conservative condition
    `altijd` (the repaired package), a DTLS LB vserver below the floor is
    GERAAKT - no Gateway needed."""
    answer = cve_check(_dtls_lb(tmp_path), _knowledge(_CTX697096))
    assert _verdict_line(answer, "CVE-2026-88772").outcome.startswith("GERAAKT")


def _package(tmp_path: Path, value) -> Path:
    bulletin = copy.deepcopy(_CTX697096)
    bulletin["cves"][2]["naconfiguratieVerplicht"] = value
    path = tmp_path / "kennis.json"
    path.write_text(json.dumps({"versie": "t", "datum": "2026-10-21", "cve": [bulletin]}), encoding="utf-8")
    return path


def test_the_loader_accepts_the_field_and_an_older_package_without_it(tmp_path):
    loaded = load_knowledge(_package(tmp_path, True), date(2026, 10, 22))
    assert not loaded.missing, loaded.reason
    assert loaded.cve[0]["cves"][2]["naconfiguratieVerplicht"] is True
    older = tmp_path / "ouder.json"
    older.write_text(
        json.dumps({"versie": "t", "datum": "2026-10-21", "cve": [_without_field(_CTX697096)]}), encoding="utf-8"
    )
    assert not load_knowledge(older, date(2026, 10, 22)).missing


@pytest.mark.parametrize("value", ["true", 1, None, [True]])
def test_the_loader_refuses_a_field_that_is_not_a_boolean(tmp_path, value):
    loaded = load_knowledge(_package(tmp_path, value), date(2026, 10, 22))
    assert loaded.missing
    assert "naconfiguratieVerplicht" in loaded.reason
