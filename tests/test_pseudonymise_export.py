"""Offline privacy gate: real bytes, negative inputs and unchanged CVE verdicts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from test_cve import BULLETIN, LIVE_EXPORT, _knowledge

from nsmcp.cve import cve_check
from nsmcp.export import load_export


@pytest.fixture
def tmp_path():
    """tests/conftest.py gives
    pytest a base directory INSIDE the repository (so the suite never depends
    on the state of the shared system temp), while the script under test
    refuses a mapping directory inside a repository BY DESIGN (`_in_repo`:
    the mapping is the one file that must never be committed). This module
    therefore works in a fresh directory under the system temp - created
    and removed per test, so it still depends on nothing that was there."""
    made = Path(tempfile.mkdtemp(prefix="nsmcp-pseudo-"))
    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pseudonymise_export.py"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def tree(path: Path) -> dict[str, bytes]:
    return {p.relative_to(path).as_posix(): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def seed(path: Path) -> Path:
    """Entirely synthetic, deliberately overlapping names, addresses and cases."""
    resources = {}
    data = {
        "lbvserver": [
            {"name": "Private-LB", "ipv46": "10.8.0.1", "servicetype": "SSL"},
            {"name": "Private-LB-long", "ipv46": "10.8.0.10", "servicetype": "HTTP"},
            {"name": "gjkdoh_lb_ssl_doh", "ipv46": "192.0.2.1", "servicetype": "SSL"},
        ],
        "nshttpprofile": [{"name": "nshttp_default_profile"}, {"name": "gjkdoh_http2"}],
        "lbmonitor": [{"monitorname": "http", "type": "HTTP"}],
        "server": [{"name": "Private-SRV", "domain": "edge.example.local"}],
        "nshostname": {"hostname": "APPLIANCE-PRIVATE"},
        "nshardware": {
            "serialno": "PRIVATE-SERIAL-123",
            "encodedserialno": "abcd1234abcd1234abcd",
            "hostid": 876543219,
            "netscaleruuid": "11111111-2222-3333-4444-555555555555",
            "host": "aabbccddeeff",
        },
    }
    for kind, rows in data.items():
        p = path / "objects" / f"{kind}.json"
        write_json(p, {kind: rows})
        resources[f"config/{kind}"] = {
            "status": "OK",
            "httpStatus": 200,
            "propertyName": kind,
            "objectCount": len(rows) if isinstance(rows, list) else 1,
            "payloadSha256": digest(p.read_bytes()),
        }
    config = (
        "set ns hostname APPLIANCE-PRIVATE\n"
        "add lb vserver Private-LB SSL 10.8.0.1 443\n"
        "add lb vserver Private-LB-long HTTP 10.8.0.10 80\n"
        "add server Private-SRV edge.example.local\n"
        "bind serviceGroup Private-SRV another.example.local 443\n"
        "add dns nameServer 192.0.2.1\n"
        "add server root a.root-servers.net\n"
        "# nsbotsignatures.s3.amazonaws.com device-posture-controller.cloud.com netscaler.com\n"
        "# PUBLIC 127.0.0.1 0.0.0.0 255.255.255.0\n"
        "# EXAMPLECUSTOMER aa:bb:cc:dd:ee:ff aabbccddeeff PRIVATE-SERIAL-123 876543219\n"
    )
    files = {}
    for name in ("runningconfig", "savedconfig"):
        p = path / "parsed" / f"{name}.txt"
        p.parent.mkdir(exist_ok=True)
        p.write_text(config, encoding="utf-8")
        files[f"parsed/{name}.txt"] = digest(p.read_bytes())
        resources[f"config/ns{name}"] = {
            "status": "OK",
            "httpStatus": 200,
            "objectCount": 1,
            "propertyName": f"ns{name}",
            "payloadSha256": digest(p.read_bytes()),
        }
    write_json(path / "bindings" / "sample.json", {"Private-LB": ["Private-LB-long", "10.8.0.10"]})
    files["bindings/sample.json"] = digest((path / "bindings/sample.json").read_bytes())
    write_json(path / "parsed/systemuser.json", {"systemuser": [{"username": "Private-SRV"}]})
    files["parsed/systemuser.json"] = digest((path / "parsed/systemuser.json").read_bytes())
    (path / "collect-log.txt").write_text("APPLIANCE-PRIVATE private-serial-123 EXAMPLECUSTOMER", encoding="utf-8")
    write_json(
        path / "export-manifest.json",
        {
            "manifestVersion": "1.1",
            "collectorVersion": "1.0.1",
            "resources": resources,
            "files": files,
        },
    )
    (path / "scan-doel.txt").write_text(
        "APPLIANCE-PRIVATE\n" + digest((path / "export-manifest.json").read_bytes()) + "\n", encoding="utf-8"
    )
    return path


def run(source: Path, target: Path, mapping: Path, extra: Path | None = None):
    assert SCRIPT.is_file(), "pseudonimiseringsscript ontbreekt"
    args = [sys.executable, str(SCRIPT), "--source", str(source), "--target", str(target), "--mapping", str(mapping)]
    if extra is not None:
        args += ["--extra-forbidden", str(extra)]
    return subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)


def extra_file(tmp_path: Path) -> Path:
    p = tmp_path / "extra.txt"
    p.write_text("ExampleCustomer\n", encoding="utf-8")
    return p


def assert_no_originals(target: Path, mapping: Path) -> None:
    table = json.loads((mapping / "mapping.json").read_text(encoding="utf-8"))
    all_text = "\n".join(
        name
        + "\n"
        + p.decode("utf-8-sig")
        + ("\n" + json.dumps(json.loads(p), ensure_ascii=False) if name.endswith(".json") else "")
        for name, p in tree(target).items()
    ).casefold()
    for original in table:
        assert original.casefold() not in all_text
    for pattern in (
        r"\b10\.\d+\.\d+\.\d+\b",
        r"\b192\.168\.\d+\.\d+\b",
        r"\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+\b",
        r"\.nl\b",
        r"\.local\b",
    ):
        assert not re.search(pattern, all_text)


def assert_hashes(target: Path) -> None:
    m = json.loads((target / "export-manifest.json").read_text(encoding="utf-8-sig"))
    specials = {
        "config/nsrunningconfig": "parsed/runningconfig.txt",
        "config/nssavedconfig": "parsed/savedconfig.txt",
        "config/systemuser": "parsed/systemuser.json",
        "config/authenticationldapaction": "parsed/authenticationldapaction.json",
    }
    for resource, entry in m["resources"].items():
        if entry.get("payloadSha256"):
            file = specials.get(resource, f"objects/{resource.split('/')[-1].split('?')[0]}.json")
            data = (target / file).read_bytes()
            if file in {"parsed/runningconfig.txt", "parsed/savedconfig.txt"}:
                data = data.decode("utf-8-sig").replace("\r\n", "\n").encode()
            assert digest(data) == entry["payloadSha256"].upper()
    for file, sha in m["files"].items():
        data = (target / file).read_bytes()
        if file in {"parsed/runningconfig.txt", "parsed/savedconfig.txt"}:
            data = data.decode("utf-8-sig").replace("\r\n", "\n").encode()
        assert digest(data) == sha.upper()


def test_cli_is_deterministic_consistent_and_retains_the_exceptions(tmp_path):
    source = seed(tmp_path / "source")
    before = tree(source)
    extra = extra_file(tmp_path)
    outputs = []
    for index, mapping in enumerate((tmp_path / "map", tmp_path / "map", tmp_path / "fresh")):
        target = tmp_path / f"out-{index}"
        result = run(source, target, mapping, extra)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "[eindstatus] GESLAAGD" in result.stdout
        assert_no_originals(target, mapping)
        assert_hashes(target)
        outputs.append(tree(target))
    assert outputs[0] == outputs[1] == outputs[2]
    assert tree(source) == before
    table = json.loads((tmp_path / "map/mapping.json").read_text())
    assert table["10.8.0.1"] != table["10.8.0.10"]
    assert "192.0.2.1" not in (table["10.8.0.1"], table["10.8.0.10"])
    text = outputs[0]["parsed/runningconfig.txt"].decode()
    for value in (
        "a.root-servers.net",
        "nsbotsignatures.s3.amazonaws.com",
        "netscaler.com",
        "device-posture-controller.cloud.com",
        "127.0.0.1",
        "255.255.255.0",
        "0.0.0.0",
    ):
        assert value in text
    assert "nshttp_default_profile" in outputs[0]["objects/nshttpprofile.json"].decode()
    assert "gjkdoh_http2" in outputs[0]["objects/nshttpprofile.json"].decode()
    assert "gjkdoh_lb_ssl_doh" in outputs[0]["objects/lbvserver.json"].decode()
    assert json.loads(outputs[0]["objects/lbmonitor.json"])["lbmonitor"][0] == {"monitorname": "http", "type": "HTTP"}
    hardware = json.loads(outputs[0]["objects/nshardware.json"])["nshardware"]
    assert hardware["serialno"] == "LABSERIAL1"
    assert hardware["encodedserialno"] == "00000000000000000000"
    assert hardware["hostid"] == 100000001
    assert hardware["netscaleruuid"] == "00000000-0000-0000-0000-020000000001"
    assert hardware["host"] == "020000000001"
    assert load_export(tmp_path / "out-0").target_name == table["APPLIANCE-PRIVATE"]


@pytest.mark.parametrize(
    "damage", ["json", "shape", "entry", "status", "missing", "hash", "filehash", "traversal", "count"]
)
def test_invalid_source_manifest_is_refused_without_partial_output(tmp_path, damage):
    source = seed(tmp_path / "source")
    mp = source / "export-manifest.json"
    m = json.loads(mp.read_text())
    if damage == "json":
        mp.write_text("{")
    elif damage == "shape":
        write_json(mp, {"resources": []})
    else:
        entry = m["resources"]["config/lbvserver"]
        if damage == "entry":
            m["resources"]["config/lbvserver"] = None
        elif damage == "status":
            entry["status"] = "INVENTED"
        elif damage == "missing":
            (source / "objects/lbvserver.json").unlink()
        elif damage == "hash":
            entry["payloadSha256"] = "0" * 64
        elif damage == "filehash":
            m["files"]["bindings/sample.json"] = "0" * 64
        elif damage == "traversal":
            m["files"]["../outside.txt"] = "0" * 64
        else:
            entry["objectCount"] = 999
        write_json(mp, m)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 1
    assert "[eindstatus] MISLUKT" in result.stderr
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "map/mapping.json").exists()
    assert "PRIVATE-SERIAL" not in result.stdout + result.stderr


def test_existing_target_and_overlapping_paths_are_never_destroyed(tmp_path):
    source = seed(tmp_path / "source")
    before = tree(source)
    for target in (source, source / "child", tmp_path):
        result = run(source, target, tmp_path / "map")
        assert result.returncode == 1
        assert tree(source) == before


def test_mapping_and_extra_literals_cannot_be_stored_in_a_repository(tmp_path):
    source = seed(tmp_path / "source")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    result = run(source, tmp_path / "out", repo / "map")
    assert result.returncode == 1 and not (tmp_path / "out").exists()
    extra = repo / "extra.txt"
    extra.write_text("ExampleCustomer")
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 1 and not (tmp_path / "out").exists()


@pytest.mark.parametrize(
    "bad_table",
    [
        {"Private-LB": "Private-LB"},
        {"Private-LB": "LBV-001", "Private-LB-long": "LBV-001"},
        {"Private-LB": 42},
        {"Private-LB": "arbitrary"},
        {"10.8.0.1": "LBV-999"},
        {"APPLIANCE-PRIVATE": "203.0.113.199"},
        {"Private-LB": "SRV-999"},
    ],
)
def test_invalid_reused_mapping_is_refused(tmp_path, bad_table):
    source = seed(tmp_path / "source")
    write_json(tmp_path / "map/mapping.json", bad_table)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 1 and not (tmp_path / "out").exists()
    assert json.loads((tmp_path / "map/mapping.json").read_text()) == bad_table


def test_a_source_name_already_in_alias_form_is_refused_not_silently_re_aliased(tmp_path):
    """Before this fix (measured, 18-9-2026) a source object
    genuinely named like this tool's own alias form (`LBV-001`) was simply
    re-aliased away, so the OUTPUT never collided with the fixed pool -
    what this test used to pin. The fix cannot tell that case apart from a
    real historical output carrying the very same name, and chooses
    fail-closed for both (documented trade-off, scripts/README.md): the
    run is refused before any mapping is built; the operator renames the
    object on the source."""
    source = seed(tmp_path / "source")
    p = source / "objects/lbvserver.json"
    data = json.loads(p.read_text())
    data["lbvserver"].append({"name": "LBV-001", "ipv46": "10.8.0.2", "servicetype": "SSL"})
    write_json(p, data)
    mp = source / "export-manifest.json"
    m = json.loads(mp.read_text())
    m["resources"]["config/lbvserver"]["payloadSha256"] = digest(p.read_bytes())
    m["resources"]["config/lbvserver"]["objectCount"] = 4
    write_json(mp, m)
    (source / "scan-doel.txt").unlink()
    before = tree(source)
    result = run(source, tmp_path / "out", tmp_path / "map", extra_file(tmp_path))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "vorm van een pseudoniem" in result.stdout + result.stderr
    assert not (tmp_path / "out").exists()
    assert tree(source) == before


def test_synthetic_verdicts_counts_and_binding_coverage_are_preserved(tmp_path):
    source = seed(tmp_path / "reference")
    write_json(source / "objects/nsversion.json", {"nsversion": {"version": "NetScaler NS14.1: Build 99.99.nc"}})
    mp = source / "export-manifest.json"
    manifest = json.loads(mp.read_text())
    manifest["resources"]["config/nsversion"] = {
        "status": "OK",
        "propertyName": "nsversion",
        "objectCount": 1,
        "payloadSha256": digest((source / "objects/nsversion.json").read_bytes()),
    }
    write_json(mp, manifest)
    for name in ("runningconfig", "savedconfig"):
        config = source / f"parsed/{name}.txt"
        config.write_bytes(config.read_bytes().replace(b"\r\n", b"\n"))
    refresh_manifest(source)
    before = tree(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stdout + result.stderr
    original = cve_check(load_export(source), _knowledge(BULLETIN)).to_text()
    changed = cve_check(load_export(tmp_path / "out"), _knowledge(BULLETIN)).to_text()

    def verdict(text):
        return [line for line in text.splitlines() if re.match(r"- CVE-(?:\d|oordeel:)", line)]

    assert "0 geraakt, 2 niet geraakt, 0 niet vastgesteld" in changed
    assert verdict(original) and verdict(original) == verdict(changed)
    assert_hashes(tmp_path / "out")
    assert_no_originals(tmp_path / "out", tmp_path / "map")
    assert tree(source) == before
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert len(json.loads((tmp_path / "out/objects/lbvserver.json").read_text())["lbvserver"]) == 3
    binding = json.loads((tmp_path / "out/bindings/sample.json").read_text())
    assert binding == {mapping["Private-LB"]: [mapping["Private-LB-long"], mapping["10.8.0.10"]]}


def test_final_leak_gate_runs_before_target_publication(tmp_path, monkeypatch):
    assert SCRIPT.is_file(), "pseudonimiseringsscript ontbreekt"
    spec = importlib.util.spec_from_file_location("pseudo_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = seed(tmp_path / "source")
    # Deliberately leave one mapped original behind: the final gate must catch it.
    real_transform = module.apply_mapping

    def damaged(text, mapping):
        return (
            real_transform(text, mapping) + " PRIVATE-SERIAL-123"
            if text.startswith("APPLIANCE-PRIVATE private-")
            else real_transform(text, mapping)
        )

    monkeypatch.setattr(module, "apply_mapping", damaged)
    result = module.main(
        [
            "--source",
            str(source),
            "--target",
            str(tmp_path / "out"),
            "--mapping",
            str(tmp_path / "map"),
            "--extra-forbidden",
            str(extra_file(tmp_path)),
        ]
    )
    assert result == 1
    assert not (tmp_path / "out").exists()


def load_script():
    spec = importlib.util.spec_from_file_location("pseudo_regression", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("kind,field,literal", [("lbvserver", "name", "SSL")])
def test_names_cannot_change_protected_profiles_or_protocols(tmp_path, kind, field, literal):
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    path = f"objects/{kind}.json"
    payload = json.loads(blobs[path])
    payload[kind].append({field: literal})
    blobs[path] = module._encode(payload)
    mapping = module.build_mapping(blobs, [], {})
    with pytest.raises(module.Refused, match="beschermde naam|protocol"):
        module.transform(blobs, mapping)


def test_explicit_host_literals_override_allowlist_but_ip_types_are_preserved(tmp_path):
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    blobs["collect-log.txt"] += b" custom.lab.example"
    mapping = module.build_mapping(blobs, ["custom.lab.example", "10.8.0.1"], {})
    assert mapping["custom.lab.example"].startswith("TERM-")
    assert module._address(mapping["10.8.0.1"]) is not None
    module.verify(module.transform(blobs, mapping), mapping)


def test_legacy_hash_empty_payload_and_monitor_protocols_are_supported(tmp_path):
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    monitor = {
        "lbmonitor": [{"monitorname": "dns", "type": "DNS"}, {"monitorname": "sta", "type": "CITRIX-STA-SERVICE"}]
    }
    blobs["objects/lbmonitor.json"] = module._encode(monitor)
    blobs["objects/service.json"] = module._encode({"errorcode": 0})
    manifest = json.loads(blobs["export-manifest.json"])
    manifest["resources"]["config/lbmonitor"].update(payloadSha256="", objectCount=2)
    manifest["resources"]["config/service"] = {
        "status": "EMPTY",
        "objectCount": 0,
        "propertyName": "service",
        "payloadSha256": digest(blobs["objects/service.json"]),
    }
    manifest["resources"]["config/systemfile?args=filelocation:/var/log"] = {
        "status": "NOT_SUPPORTED",
        "objectCount": 0,
        "payloadSha256": "",
    }
    blobs["export-manifest.json"] = module._encode(manifest)
    del blobs["scan-doel.txt"]
    module.validate_manifest(blobs, source_newlines=True)
    mapping = module.build_mapping(blobs, [], {})
    assert "dns" not in mapping and "sta" not in mapping
    output = module.transform(blobs, mapping)
    assert json.loads(output["objects/lbmonitor.json"]) == monitor
    assert json.loads(output["export-manifest.json"])["resources"]["config/lbmonitor"]["payloadSha256"] == ""


def test_hostname_cannot_reappear_inside_neutral_aliases(tmp_path, capsys):
    """Addendum 4: LAB is three characters, so a
    fresh identity_hostnames() never re-discovers it as a candidate (that
    path is covered by
    test_addendum4_short_hostname_from_nshostname_json_stays_with_warning).
    But a mapping.json written before addendum 4 existed can still hold a
    three-character original as a REUSED entry - the only way production
    code can still put a name this short in front of build_mapping - so this
    test targets that legacy path directly via `existing`, not an
    identity={"LAB"} injection the real pipeline can never produce. Before
    this fix the legacy entry was carried through unfiltered: the
    serial-escape only inspects collect_candidates' own fresh candidates
    (never `existing`), so it kept the default LABSERIAL1 neutral serial,
    and that fixed alias then tripped the boundary-free end gate as a false
    leak of the legacy "lab" original it still tracked. The fix drops the
    legacy entry (warning, never the name) instead of reusing it, so it can
    no longer poison alias generation or the leak check."""
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    for name, data in blobs.items():
        blobs[name] = data.replace(b"APPLIANCE-PRIVATE", b"LAB")
    mapping = module.build_mapping(blobs, [], {"LAB": "host-001.invalid"})
    assert "LAB" not in mapping
    captured = capsys.readouterr()
    assert (
        captured.out.count(
            "[waarschuwing] bestaande mapping bevat een naam korter dan vier tekens; "
            "niet als substring te bewaken; overgeslagen"
        )
        == 1
    )
    output = module.transform(blobs, mapping)
    module.verify(output, mapping, set())  # must not raise: no more false leak


def test_addendum4_long_hostname_overlapping_serial_alias_still_uses_escape(tmp_path):
    """Both alias-generation escape hatches are still reachable and correct
    for a name at or above the floor - addendum 4 only closes the
    short-name path, not these mechanisms themselves."""
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    for name, data in blobs.items():
        blobs[name] = data.replace(b"APPLIANCE-PRIVATE", b"LABSER")
    mapping = module.build_mapping(blobs, [], {})
    assert mapping["PRIVATE-SERIAL-123"] == "SERIAL1"
    assert all("labser" not in alias.casefold() for alias in mapping.values())
    output = module.transform(blobs, mapping)
    module.verify(output, mapping, set())  # must not raise

    # The suffix escape (.invalid instead of .lab.example): a fresh hostname
    # overlapping the fixed alias domain itself. Pinned at mapping level
    # only - the shared seed fixture's own 'example.local' hosts and
    # 'EXAMPLECUSTOMER' literal collide with this particular word by
    # coincidence, a separate, documented substring gap (a generic word of
    # four-plus characters, scripts/README.md) unrelated to this escape
    # hatch, so this case does not go through verify().
    blobs2 = tree(seed(tmp_path / "source2"))
    for name, data in blobs2.items():
        blobs2[name] = data.replace(b"APPLIANCE-PRIVATE", b"EXAMPLE")
    mapping2 = module.build_mapping(blobs2, [], {})
    assert mapping2["EXAMPLE"].endswith(".invalid")
    assert all("example" not in alias.casefold() for alias in mapping2.values())


def test_addendum4_retired_legacy_alias_is_not_reissued(tmp_path):
    """A skipped legacy mapping entry (original below the floor) still
    reserves its alias: handing that same alias text to an unrelated fresh
    candidate in the same run would silently break alias stability for
    anyone still holding the old mapping.json, even though the retired
    original itself is gone."""
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    for name, data in blobs.items():
        blobs[name] = data.replace(b"APPLIANCE-PRIVATE", b"EXAMPLE")
    existing = {"LAB": "host-001.invalid"}
    mapping = module.build_mapping(blobs, [], existing)
    assert "LAB" not in mapping
    assert "host-001.invalid" not in mapping.values()


def test_addendum5_builtin_vendor_names_stay_unreplaced(tmp_path):
    """Regel A (a non-empty NITRO 'builtin' list) and regel B
    (VENDOR_BUILTIN_NAMES, the fixed fallback list) both keep a
    NetScaler-shipped name out of the mapping - pinned independently here
    Custom-Shipped-Mon carries only regel A, no listed
    name, so this would fail if _is_builtin_row were ever disabled or
    bypassed (unlike ping-default, which both rules would catch on their
    own). Custom-Shipped-Mon-2 is the negative pin - identical shape, no
    'builtin' - and still gets replaced. Regel A on the
    sslcertkey row only ever protects the certkey NAME (via NAME_SOURCES/
    regel B below), never the whole row - an operator-chosen cert/key
    file name under a builtin certkey must still become a real candidate
    and get replaced, never left literal (the exact fail-open that was
    measured)."""
    source = seed(tmp_path / "source")
    lbmonitor_path = source / "objects/lbmonitor.json"
    monitors = json.loads(lbmonitor_path.read_text())
    monitors["lbmonitor"].append({"monitorname": "ping-default", "type": "PING", "builtin": ["MODIFIABLE"]})
    monitors["lbmonitor"].append({"monitorname": "Custom-Shipped-Mon", "type": "TCP", "builtin": ["MODIFIABLE"]})
    monitors["lbmonitor"].append({"monitorname": "Custom-Shipped-Mon-2", "type": "TCP"})
    write_json(lbmonitor_path, monitors)
    write_json(
        source / "objects/sslcertkey.json",
        {
            "sslcertkey": [
                {
                    "certkey": "ns-server-certificate",
                    "builtin": ["MODIFIABLE"],
                    "cert": "/nsconfig/ssl/customer-mgmt-20260818.cert",
                    "key": "/nsconfig/ssl/customer-mgmt-20260818.key",
                },
            ]
        },
    )
    write_json(source / "objects/rewriteaction.json", {"rewriteaction": [{"name": "NOREWRITE"}]})
    write_json(source / "objects/sslprofile.json", {"sslprofile": [{"name": "ns_default_ssl_profile_frontend"}]})
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/lbmonitor"]["objectCount"] = 4
    for kind in ("sslcertkey", "rewriteaction", "sslprofile"):
        manifest["resources"][f"config/{kind}"] = {
            "status": "OK",
            "httpStatus": 200,
            "propertyName": kind,
            "objectCount": 1,
            "payloadSha256": "0" * 64,
        }
    write_json(manifest_path, manifest)
    refresh_manifest(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stdout + result.stderr
    output = tree(tmp_path / "out")
    assert b'"ping-default"' in output["objects/lbmonitor.json"]
    assert b'"Custom-Shipped-Mon"' in output["objects/lbmonitor.json"]
    assert b"Custom-Shipped-Mon-2" not in output["objects/lbmonitor.json"]
    assert b'"ns-server-certificate"' in output["objects/sslcertkey.json"]
    assert b"customer-mgmt-20260818" not in output["objects/sslcertkey.json"]
    assert b'"NOREWRITE"' in output["objects/rewriteaction.json"]
    assert b'"ns_default_ssl_profile_frontend"' in output["objects/sslprofile.json"]
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    keys_cf = {key.casefold() for key in mapping}
    for vendor_name in (
        "ping-default",
        "custom-shipped-mon",
        "ns-server-certificate",
        "norewrite",
        "ns_default_ssl_profile_frontend",
    ):
        assert vendor_name not in keys_cf
    assert "custom-shipped-mon-2" in keys_cf
    assert "customer-mgmt-20260818.cert" in keys_cf
    assert "customer-mgmt-20260818.key" in keys_cf


def test_addendum5_existing_mapping_with_vendor_builtin_name_is_skipped(tmp_path, capsys):
    """A legacy mapping.json entry for a NetScaler built-in name is dropped
    the same way as a too-short one (addendum 4) - except the name itself
    is safe to name (vendor vocabulary is public). Its alias stays
    reserved (not handed to an unrelated fresh candidate) and the other
    entry survives reuse unchanged."""
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    blobs["objects/sslcertkey.json"] = module._encode(
        {
            "sslcertkey": [
                {"certkey": "Private-CERT", "cert": "/nsconfig/ssl/private.cert"},
            ]
        }
    )
    existing = {"ns-server-certificate": "CERT-001", "Private-LB": "LBV-777"}
    mapping = module.build_mapping(blobs, [], existing)
    assert "ns-server-certificate" not in mapping
    assert mapping["Private-LB"] == "LBV-777"
    assert "CERT-001" not in mapping.values()
    captured = capsys.readouterr()
    assert (
        captured.out.count(
            "[waarschuwing] bestaande mapping bevat een ingebouwde leveranciersnaam "
            "(ns-server-certificate); overgeslagen"
        )
        == 1
    )


@pytest.mark.parametrize("field", ["timestamp", "dnsoverhttps"])
def test_cve_predicate_values_cannot_be_replaced_by_extra_literals(tmp_path, field):
    module = load_script()
    blobs = tree(seed(tmp_path / "source"))
    blobs["objects/parameter.json"] = module._encode({"parameter": {field: "DISABLED"}})
    mapping = module.build_mapping(blobs, ["DISABLED"], {})
    with pytest.raises(module.Refused, match="protocol- of statuswaarde"):
        module.transform(blobs, mapping)


@pytest.mark.parametrize("literal", ["cloud", "netscaler", "https", "a.root-servers.net"])
def test_extra_literals_cannot_destroy_technical_exceptions(tmp_path, literal):
    source = seed(tmp_path / "source")
    extra = tmp_path / "extra.txt"
    extra.write_text(literal, encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 1
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "map/mapping.json").exists()


def refresh_manifest(source):
    path = source / "export-manifest.json"
    manifest = json.loads(path.read_text())
    for resource, entry in manifest["resources"].items():
        if entry.get("payloadSha256"):
            file = load_script().resource_file(resource)
            entry["payloadSha256"] = digest((source / file).read_bytes())
    for file in manifest["files"]:
        manifest["files"][file] = digest((source / file).read_bytes())
    write_json(path, manifest)
    (source / "scan-doel.txt").unlink(missing_ok=True)


def test_B1_config_hostname_casing_is_detected_without_other_name_sources(tmp_path):
    source = seed(tmp_path / "source")
    p = source / "parsed/runningconfig.txt"
    p.write_bytes(p.read_bytes() + b"set ns hostName NODE-CASE-ONLY\n")
    refresh_manifest(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    assert b"NODE-CASE-ONLY" not in tree(tmp_path / "out")["parsed/runningconfig.txt"]


def test_B1_identity_hostname_gate_is_independent_of_mapping(tmp_path, monkeypatch, capsys):
    """The stand-in must accept and forward the `identity` kwarg execute()
    has passed to build_mapping() since addendum 4 - a stand-in that drops
    it raises a TypeError the generic except in main() also turns into
    exit 1, which made this test pass without the identity gate in verify()
    ever running (found while measuring addendum 4). Asserting on
    the actual diagnosis, not just the exit code, is what catches that."""
    module = load_script()
    source = seed(tmp_path / "source")
    write_json(source / "objects/hanode.json", {"hanode": [{"name": "NODE-IDENTITY-ONLY"}]})
    original = module.build_mapping

    def omit_identity(blobs, extra, existing, identity=None):
        mapping = original(blobs, extra, existing, identity=identity)
        return {key: value for key, value in mapping.items() if key != "NODE-IDENTITY-ONLY"}

    monkeypatch.setattr(module, "build_mapping", omit_identity)
    assert (
        module.main(["--source", str(source), "--target", str(tmp_path / "out"), "--mapping", str(tmp_path / "map")])
        == 1
    )
    assert not (tmp_path / "out").exists()
    captured = capsys.readouterr()
    assert "oorspronkelijke apparaathostnaam achtergebleven" in captured.err


def test_B2_short_names_inside_words_cert_files_and_readme_tokens_refuse_publication(tmp_path):
    source = seed(tmp_path / "source")
    (source / "collect-log.txt").write_bytes(
        b"LAB lab policylabel /nsconfig/ssl/lab-cert.pem lab-export-vpx example_lab.label"
    )
    extra = tmp_path / "extra.txt"
    extra.write_text("lab", encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 1
    assert "MISLUKT" in result.stderr
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "map/mapping.json").exists()


def test_crlf_checkout_is_accepted_and_source_line_endings_are_preserved(tmp_path):
    source = seed(tmp_path / "source")
    for file in source.rglob("*"):
        if file.is_file():
            file.write_bytes(file.read_bytes().replace(b"\r\n", b"\n"))
    refresh_manifest(source)
    # Simulate a checkout: manifest pins LF bytes, files are now CRLF.
    for file in source.rglob("*"):
        if file.is_file():
            file.write_bytes(file.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    before = tree(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    for name, data in tree(tmp_path / "out").items():
        if b"\r\n" in before[name]:
            assert b"\r\n" in data
            assert b"\n" not in data.replace(b"\r\n", b"")
    assert tree(source) == before
    assert_hashes(tmp_path / "out")


@pytest.mark.parametrize("missing", ["", None, "absent"])
def test_missing_source_monitor_hash_stays_missing(tmp_path, missing):
    source = seed(tmp_path / "source")
    path = source / "export-manifest.json"
    manifest = json.loads(path.read_text())
    if missing == "absent":
        del manifest["resources"]["config/lbmonitor"]["payloadSha256"]
    else:
        manifest["resources"]["config/lbmonitor"]["payloadSha256"] = missing
    write_json(path, manifest)
    (source / "scan-doel.txt").unlink()
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    output = json.loads((tmp_path / "out/export-manifest.json").read_text())
    assert output["resources"]["config/lbmonitor"].get("payloadSha256", "absent") == missing


def test_all_protected_extra_lines_are_diagnosed_with_categories(tmp_path):
    source = seed(tmp_path / "source")
    extra = tmp_path / "extra.txt"
    extra.write_text(
        "\ncloud\nA.ROOT-SERVERS.NET\npcrf\npcrfrealm\nYouTube.com\ncloud\ngjkdoh_http2\n", encoding="utf-8"
    )
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 1
    for line, category in (
        (2, "leverancier"),
        (3, "rootserver"),
        (4, "configparameter"),
        (5, "configparameter"),
        (6, "publiek platform"),
        (7, "leverancier"),
        (8, "configparameter"),
    ):
        assert any(f"regel {line}:" in value and category in value for value in result.stderr.splitlines())
    assert "pcrfrealm" in result.stderr and "YouTube.com" in result.stderr
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "map/mapping.json").exists()


def test_B2_protected_name_substrings_refuse_publication(tmp_path):
    source = seed(tmp_path / "source")
    path = source / "objects/nshttpprofile.json"
    payload = json.loads(path.read_text())
    payload["nshttpprofile"].append({"name": "default"})
    write_json(path, payload)
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/nshttpprofile"]["objectCount"] = 3
    write_json(manifest_path, manifest)
    refresh_manifest(source)
    extra = tmp_path / "extra.txt"
    extra.write_text("a.root", encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 1
    assert "MISLUKT" in result.stderr
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("suffix", ["nl", "local"])
def test_unmapped_internal_domain_is_refused(suffix):
    module = load_script()
    with pytest.raises(module.Refused, match="interne domeinverwijzing"):
        module.verify({"unlisted.txt": f"unknown.{suffix}".encode()}, {})


def test_platform_suffix_boundaries_do_not_protect_customer_domains():
    module = load_script()
    assert module.protected_category("YouTube.com.customer.example") is None
    assert module.protected_category("privateyoutube.com") is None
    assert module.protected_category("manifest.googlevideo.com") == "publiek platform"


@pytest.mark.parametrize("missing", ["", None])
def test_empty_file_hash_is_preserved_as_an_evidence_gap(tmp_path, missing):
    source = seed(tmp_path / "source")
    path = source / "export-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["files"]["bindings/sample.json"] = missing
    write_json(path, manifest)
    (source / "scan-doel.txt").unlink()
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    output = json.loads((tmp_path / "out/export-manifest.json").read_text())
    assert output["files"]["bindings/sample.json"] == missing


@pytest.mark.parametrize(
    "content",
    [
        "Private-LB.crt",
        "Private-LB_backup",
        "xPrivate-LB",
        "Private-LB.example.com",
        "CN=PRIVATE-LB.crt",
        "preStraSSeSuffix",
    ],
)
@pytest.mark.parametrize("identity_only", [False, True])
def test_addendum3_substring_gates_are_casefolded_and_independent(content, identity_only):
    module = load_script()
    original = "Stra\u00dfe" if "StraSSe" in content else "Private-LB"
    mapping = {} if identity_only else {original: "LBV-001"}
    identities = [original] if identity_only else []
    with pytest.raises(module.Refused) as error:
        module.verify({"objects/sslcertkey.json": json.dumps({"subject": content}).encode()}, mapping, identities)
    assert "objects/sslcertkey.json" in str(error.value)
    assert ("apparaathostnaam" if identity_only else "gemapt origineel") in str(error.value)
    assert ("familie host" if identity_only else "familie LBV") in str(error.value)
    assert original.casefold() not in str(error.value).casefold()


def test_addendum3_escaped_json_and_sensitive_filename_are_not_echoed():
    module = load_script()
    for name, content in [
        ("objects/sslcertkey.json", b'{"subject":"CN=preS\\u0065cretSuffix"}'),
        ("Secret_backup.txt", b"benign"),
    ]:
        with pytest.raises(module.Refused) as error:
            module.verify({name: content}, {"Secret": "CERT-001"})
        assert "secret" not in str(error.value).casefold()
        assert "bestand" in str(error.value)


@pytest.mark.parametrize("original", ['Synthetic"Cert.crt', "Synthetic\\Cert.crt", "Synthetic\tCert.crt"])
@pytest.mark.parametrize("identity_only", [False, True])
def test_addendum3_decoded_json_is_scanned_raw_without_a_reencoding_step(original, identity_only):
    """A re-serialization of decoded JSON re-escapes quotes, backslashes and
    control characters, so an original carrying one of those characters can
    stay hidden inside a decoded string value while both end gates pass. The
    end gate must read the already-decoded JSON literally instead."""
    module = load_script()
    blob = json.dumps({"subject": "pre" + original + "_backup"}).encode()
    mapping = {} if identity_only else {original: "CERT-001"}
    identities = [original] if identity_only else []
    with pytest.raises(module.Refused) as error:
        module.verify({"objects/sslcertkey.json": blob}, mapping, identities)
    assert "objects/sslcertkey.json" in str(error.value)
    assert ("apparaathostnaam" if identity_only else "gemapt origineel") in str(error.value)
    assert original.casefold() not in str(error.value).casefold()


@pytest.mark.parametrize("location", ["content", "filename"])
def test_addendum3_cli_leak_keeps_source_and_existing_mapping_unchanged(tmp_path, location):
    source = seed(tmp_path / "source")
    mapping = tmp_path / "map"
    write_json(mapping / "mapping.json", {"Private-LB": "LBV-501"})
    (mapping / "verboden.txt").write_text("Private-LB\n")
    if location == "content":
        (source / "collect-log.txt").write_text("/nsconfig/ssl/Private-LB.crt")
    else:
        (source / "Private-LB_backup.txt").write_text("benign")
    before_source, before_map = tree(source), tree(mapping)
    result = run(source, tmp_path / "out", mapping)
    assert result.returncode == 1
    assert "MISLUKT" in result.stderr
    assert "gemapt origineel" in result.stderr and "bestand" in result.stderr
    assert "private-lb" not in (result.stdout + result.stderr).casefold()
    assert tree(source) == before_source and tree(mapping) == before_map
    assert not (tmp_path / "out").exists()


def add_certificate(source, cert, key):
    write_json(
        source / "objects/sslcertkey.json",
        {"sslcertkey": [{"certkey": "Private-Certificate", "cert": cert, "key": key}]},
    )
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/sslcertkey"] = {
        "status": "OK",
        "propertyName": "sslcertkey",
        "objectCount": 1,
        "payloadSha256": digest((source / "objects/sslcertkey.json").read_bytes()),
    }
    write_json(manifest_path, manifest)
    refresh_manifest(source)


@pytest.mark.parametrize("prefix", ["/nsconfig/ssl/", ""])
def test_addendum3_certificate_basename_is_complete_and_reusable(tmp_path, prefix):
    source = seed(tmp_path / "source")
    add_certificate(source, prefix + "Private-LB.crt", prefix + "Private-LB.key")
    (source / "collect-log.txt").write_text(prefix + "Private-LB.crt " + prefix + "Private-LB.key")
    before = tree(source)
    outputs = []
    for index in range(2):
        target = tmp_path / f"out-{index}"
        result = run(source, target, tmp_path / "map")
        assert result.returncode == 0, result.stderr
        mapping = json.loads((tmp_path / "map/mapping.json").read_text())
        assert mapping["Private-LB.crt"].startswith("CERT-")
        assert mapping["Private-LB.key"].startswith("CERT-")
        assert mapping["Private-LB.crt"] != mapping["Private-LB.key"]
        cert = json.loads((target / "objects/sslcertkey.json").read_text())["sslcertkey"][0]
        assert cert["cert"] == prefix + mapping["Private-LB.crt"]
        assert cert["key"] == prefix + mapping["Private-LB.key"]
        assert_no_originals(target, tmp_path / "map")
        assert_hashes(target)
        outputs.append(tree(target))
    assert outputs[0] == outputs[1] and tree(source) == before


def test_addendum3_cert_stem_without_extension_is_also_a_candidate(tmp_path):
    """cert/key delivered only basename.ext as an original, so a sibling
    with a different or missing extension (a .pem twin, a .pfx twin, or the
    bare stem in free text) passed both the replacer (name boundary) and
    the end gate (no known original): exit 0, GESLAAGD, stem still literal
    in the target. The stem must become its own CERT candidate so the end
    gate - which has no boundaries - catches it, even though the
    boundary-respecting replacer still cannot touch a name immediately
    followed by a dot and leaves the .pem/.pfx twins themselves alone."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/Priv-Wild.crt", "/nsconfig/ssl/Priv-Wild.key")
    (source / "collect-log.txt").write_text("Priv-Wild.pem /nsconfig/ssl/Priv-Wild.pfx Priv-Wild")
    before = tree(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 1
    assert "MISLUKT" in result.stderr
    assert "priv-wild" not in (result.stdout + result.stderr).casefold()
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "map/mapping.json").exists()
    assert tree(source) == before
    # The operator route: naming the remaining siblings closes the gap.
    extra = tmp_path / "extra.txt"
    extra.write_text("Priv-Wild.pem\nPriv-Wild.pfx\nPriv-Wild\n", encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert mapping["Priv-Wild.crt"] != mapping["Priv-Wild"]
    assert mapping["Priv-Wild.crt"].startswith("CERT-") and mapping["Priv-Wild"].startswith("CERT-")
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == "/nsconfig/ssl/" + mapping["Priv-Wild.crt"]
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_cert_path_folder_is_harvested_unless_it_is_a_technical_segment(tmp_path):
    """A folder component of a cert/key path (e.g. a customer name under
    /nsconfig/ssl/<folder>/) is a candidate unless it is a standard,
    non-customer path segment (ssl, nsconfig, ...)."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/CustomerCorp/site.crt", "/nsconfig/ssl/CustomerCorp/site.key")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "CustomerCorp" in mapping and mapping["CustomerCorp"].startswith("CERT-")
    assert "ssl" not in mapping and "nsconfig" not in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == f"/nsconfig/ssl/{mapping['CustomerCorp']}/{mapping['site.crt']}"
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_protected_cert_basename_is_skipped_with_a_warning_not_a_crash(tmp_path):
    """A cert basename that is itself a known technical/vendor term (here
    the allowed vendor domain netscaler.com) must not make the whole run
    fail on an unrelated mapping-consistency error: it is simply not a
    candidate, and the operator sees why."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/netscaler.com", "/nsconfig/ssl/Private-LB.key")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    assert any("waarschuwing" in line and "netscaler.com" in line for line in result.stdout.splitlines())
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "netscaler.com" not in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == "/nsconfig/ssl/netscaler.com"


def test_addendum3_generic_cert_stem_root_is_not_harvested(tmp_path):
    """H1 probe 1: seed() already carries 'add server root a.root-servers.net'.
    Before the fix, the derived stem 'root' (from cert=.../root.crt) became
    its own CERT candidate and collided with the protected root-servers.net
    suffix everywhere it appears in running/saved config - exit 1 on a
    completely generic, non-leaking certificate name. The full basename
    root.crt must still become a candidate and be replaced."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/root.crt", "/nsconfig/ssl/root.key")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "root" not in mapping
    assert mapping["root.crt"].startswith("CERT-") and mapping["root.key"].startswith("CERT-")
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == "/nsconfig/ssl/" + mapping["root.crt"]
    text = (tmp_path / "out/parsed/runningconfig.txt").read_text()
    assert "a.root-servers.net" in text
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_generic_cert_folder_ca_is_not_harvested(tmp_path):
    """H1 probe 2: a two-letter folder name (here 'ca', as in
    /nsconfig/ssl/ca/<file>) is exactly the kind of fragment that turns up
    as a substring inside almost any hex hash in the export - too short to
    trust as a customer folder name."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/ca/site.crt", "/nsconfig/ssl/ca/site.key")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "ca" not in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == "/nsconfig/ssl/ca/" + mapping["site.crt"]
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_generic_cert_folder_old_is_not_harvested(tmp_path):
    """H1 probe 3 (the 'old' half of 'backup/old'): a three-letter folder
    name is too short to trust as a customer folder name on its own."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/old/site2.crt", "/nsconfig/ssl/old/site2.key")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "old" not in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == "/nsconfig/ssl/old/" + mapping["site2.crt"]
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_generic_word_that_only_collides_elsewhere_is_a_documented_residual_gap(tmp_path):
    """Not one of the four required-green probes: a longer generic word
    (here 'backup', 6 characters, so the length rule does not apply) that
    is not itself a substring of any fixed technical/public literal is
    still harvested. If unrelated config text happens to share that
    substring (a real NetScaler flag like -backupVServer), the run still
    fails closed. Documented in scripts/README.md as intentional: rename
    the folder on the source, the same route as any other collision."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/backup/site3.crt", "/nsconfig/ssl/backup/site3.key")
    p = source / "parsed/runningconfig.txt"
    p.write_bytes(p.read_bytes() + b"set lb vserver Private-LB -backupVServer Private-LB-long\n")
    refresh_manifest(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 1
    assert "MISLUKT" in result.stderr
    assert "familie CERT" in result.stderr
    assert not (tmp_path / "out").exists()


def test_addendum3_generic_cert_stem_ssl_no_longer_collides_with_the_protocol_value(tmp_path):
    """H1 probe 4: the derived stem 'ssl' (from cert=.../ssl.crt) used to
    collide with the SEMANTIC_FIELDS-protected servicetype value SSL that
    seed() already carries on Private-LB - a completely generic
    certificate name made the run fail on an unrelated protocol value."""
    source = seed(tmp_path / "source")
    add_certificate(source, "/nsconfig/ssl/ssl.crt", "/nsconfig/ssl/ssl.key")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "ssl" not in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())["sslcertkey"][0]
    assert output["cert"] == "/nsconfig/ssl/" + mapping["ssl.crt"]
    lbvserver = json.loads((tmp_path / "out/objects/lbvserver.json").read_text())["lbvserver"]
    assert any(row["servicetype"] == "SSL" for row in lbvserver)
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_untracked_bindings_or_parsed_file_is_not_shown_by_name(tmp_path):
    """H2: only a manifest-derived name (a files key, or a resource_file()
    result) is schema-shaped enough to show plainly in a hash-gap warning.
    A blob that merely starts with bindings/ or parsed/ but is not
    declared in the manifest at all is not manifest-derived, and must fall
    back to the same conservative allowlist verify() itself uses."""
    source = seed(tmp_path / "source")
    (source / "parsed" / "Unknown-Corp.txt").write_text("benign", encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    warnings = [line for line in result.stdout.splitlines() if "[waarschuwing]" in line]
    assert not any("Unknown-Corp" in line for line in warnings)
    assert any("naam afgeschermd" in line and "fileSha256" in line for line in warnings)


def test_addendum3_family_in_diagnosis_is_deterministic_regardless_of_mapping_order(tmp_path):
    """H3: verify() picked the family to name via dict-iteration order over
    the mapping, so two originals matching the same file could flip which
    family got named between two otherwise-identical runs (e.g. a reused,
    hand-edited mapping.json with a different insertion order). The family
    named must be deterministic: the alphabetically-first matching
    original wins, regardless of mapping order."""
    module = load_script()
    blob = b"AlphaLeak-BetaLeak"
    forward = {"AlphaLeak": "LBV-001", "BetaLeak": "CERT-002"}
    backward = {"BetaLeak": "CERT-002", "AlphaLeak": "LBV-001"}
    messages = []
    for mapping in (forward, backward):
        with pytest.raises(module.Refused) as error:
            module.verify({"collect-log.txt": blob}, mapping)
        messages.append(str(error.value))
    assert messages[0] == messages[1]


def add_sslcertkey_row(source: Path, row: dict) -> None:
    write_json(source / "objects/sslcertkey.json", {"sslcertkey": [row]})
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/sslcertkey"] = {
        "status": "OK",
        "propertyName": "sslcertkey",
        "objectCount": 1,
        "payloadSha256": digest((source / "objects/sslcertkey.json").read_bytes()),
    }
    write_json(manifest_path, manifest)
    refresh_manifest(source)


def test_addendum3_host_named_certificate_subject_and_issuer_is_pseudonymizable(tmp_path):
    """Practice measurement (on a real export not available
    here): a certificate named after its host embeds the stem in
    subject/issuer as CN=<stem>.<domain> - one unbroken dotted token, since
    `.` is never a name-boundary. Harvesting only the stem (an object name
    or a cert basename) leaves it dangling inside that token: the replacer
    cannot touch a name immediately followed by a dot, so the stem stays
    and the end gate - correctly - refuses. The whole FQDN must become its
    own host candidate whenever its first label matches an already-known
    original, so the replacer removes it in one piece."""
    source = seed(tmp_path / "source")
    p = source / "objects/lbvserver.json"
    payload = json.loads(p.read_text())
    payload["lbvserver"].append({"name": "web01", "ipv46": "10.8.0.9", "servicetype": "SSL"})
    write_json(p, payload)
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/lbvserver"]["objectCount"] = 4
    write_json(manifest_path, manifest)
    add_sslcertkey_row(
        source,
        {
            "certkey": "web01",
            "cert": "/nsconfig/ssl/web01.crt",
            "key": "/nsconfig/ssl/web01.key",
            "subject": "CN=web01.klant.corp,O=X",
            "issuer": "CN=web01.klant.corp,O=X",
        },
    )
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    output = tree(tmp_path / "out")
    all_text = "\n".join(name + "\n" + data.decode("utf-8-sig") for name, data in output.items()).casefold()
    assert "web01" not in all_text
    cert = json.loads(output["objects/sslcertkey.json"])["sslcertkey"][0]
    assert cert["subject"].startswith("CN=host-") and cert["subject"].endswith(".lab.example,O=X")
    assert cert["issuer"] == cert["subject"]
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_fqdn_with_unknown_first_label_keeps_existing_behavior(tmp_path):
    """A generic FQDN whose first label is not a known original is
    unaffected by the new host-harvest rule: a public host stays untouched
    (existing behaviour, ntp.pool.example is not in PUBLIC_SUFFIXES so this
    also confirms it is not swept up as a false positive by the new rule)."""
    source = seed(tmp_path / "source")
    log = source / "collect-log.txt"
    log.write_text(log.read_text() + " ntp.pool.example", encoding="utf-8")
    refresh_manifest(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    assert b"ntp.pool.example" in (tmp_path / "out/collect-log.txt").read_bytes()


def test_addendum3_link_certkey_name_is_also_harvested_as_a_certificate_candidate(tmp_path):
    source = seed(tmp_path / "source")
    add_sslcertkey_row(
        source,
        {
            "certkey": "Private-Certificate",
            "cert": "Private-LB.crt",
            "key": "Private-LB.key",
            "linkcertkeyname": "Private-Root-CA",
        },
    )
    (source / "collect-log.txt").write_text("Private-Root-CA")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "Private-Root-CA" in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())
    assert output["sslcertkey"][0]["linkcertkeyname"] == mapping["Private-Root-CA"]
    assert_no_originals(tmp_path / "out", tmp_path / "map")


def test_addendum3_cert_basename_matching_a_protected_literal_is_not_harvested(tmp_path):
    source = seed(tmp_path / "source")
    add_sslcertkey_row(
        source, {"certkey": "Private-Certificate", "cert": "/nsconfig/ssl/https", "key": "Private-LB.key"}
    )
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    assert any("waarschuwing" in line and "https" in line for line in result.stdout.splitlines())
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "https" not in mapping
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())
    assert output["sslcertkey"][0]["cert"] == "/nsconfig/ssl/https"


def test_addendum3_subject_organisation_is_an_honest_documented_gap(tmp_path):
    """No automatic rule covers sslcertkey subject/issuer O= or L=: only
    --extra-forbidden closes it. This is the documented boundary in
    scripts/README.md, not an oversight - the test pins that the gap is
    real."""
    source = seed(tmp_path / "source")
    add_sslcertkey_row(
        source,
        {
            "certkey": "Private-Certificate",
            "cert": "Private-LB.crt",
            "key": "Private-LB.key",
            "subject": "O=Acme Organisatie,L=Voorbeeldstad",
        },
    )
    before = tree(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    output = json.loads((tmp_path / "out/objects/sslcertkey.json").read_text())
    assert output["sslcertkey"][0]["subject"] == "O=Acme Organisatie,L=Voorbeeldstad"
    assert_hashes(tmp_path / "out")
    assert tree(source) == before


@pytest.mark.parametrize("missing", ["", None, "absent"])
def test_addendum3_each_missing_source_hash_has_its_own_warning(tmp_path, missing):
    source = seed(tmp_path / "source")
    path = source / "export-manifest.json"
    manifest = json.loads(path.read_text())
    for resource in ("config/lbvserver", "config/nsrunningconfig", "config/lbmonitor"):
        if missing == "absent":
            del manifest["resources"][resource]["payloadSha256"]
        else:
            manifest["resources"][resource]["payloadSha256"] = missing
    if missing == "absent":
        del manifest["files"]["parsed/runningconfig.txt"]
    else:
        manifest["files"]["parsed/runningconfig.txt"] = missing
    write_json(path, manifest)
    (source / "scan-doel.txt").unlink()
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    warnings = [line for line in result.stdout.splitlines() if "[waarschuwing]" in line]
    for name in ("objects/lbvserver.json", "parsed/runningconfig.txt", "objects/lbmonitor.json"):
        assert sum(name in line and "payloadSha256" in line for line in warnings) == 1
    assert sum("parsed/runningconfig.txt" in line and "fileSha256" in line for line in warnings) == 1
    after = json.loads((tmp_path / "out/export-manifest.json").read_text())
    for resource in ("config/lbvserver", "config/nsrunningconfig", "config/lbmonitor"):
        assert after["resources"][resource].get("payloadSha256", "absent") == missing
    assert after["files"].get("parsed/runningconfig.txt", "absent") == missing


def test_addendum3_hash_warning_names_a_bindings_file_not_an_ordinal(tmp_path):
    """A files-entry name is manifest-derived (NITRO-schema, never customer
    content), so warn_missing_hashes may show it plainly - unlike verify()'s
    conservative allowlist for arbitrary blob names, which stays as-is."""
    source = seed(tmp_path / "source")
    path = source / "export-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["files"]["bindings/sample.json"] = None
    write_json(path, manifest)
    (source / "scan-doel.txt").unlink()
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    warnings = [line for line in result.stdout.splitlines() if "[waarschuwing]" in line]
    assert any("bindings/sample.json" in line and "fileSha256" in line for line in warnings)
    assert not any("naam afgeschermd" in line for line in warnings)


def test_addendum3_a_leak_only_inside_a_schema_key_says_so_and_still_fails_closed(tmp_path):
    """An object name that happens to be a substring of a NITRO schema field
    name (here 'netscaler' inside nshardware.json's netscaleruuid key) is
    unsolvable via --extra-forbidden: the key is schema, never data. The
    diagnosis must say so instead of leaving the operator chasing a fix
    that cannot work - while still failing closed."""
    source = seed(tmp_path / "source")
    path = source / "objects/lbvserver.json"
    payload = json.loads(path.read_text())
    payload["lbvserver"].append({"name": "netscaler", "ipv46": "10.8.0.5", "servicetype": "SSL"})
    write_json(path, payload)
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/lbvserver"]["objectCount"] = 4
    write_json(manifest_path, manifest)
    refresh_manifest(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 1
    assert "MISLUKT" in result.stderr
    assert "familie LBV" in result.stderr
    assert "sleutel of bestandsnaam" in result.stderr
    assert "netscaler" not in (result.stdout + result.stderr).casefold()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("bom", [True, False])
def test_addendum3_bom_is_preserved_per_file_and_hashes_match_actual_output(tmp_path, bom):
    source = seed(tmp_path / "source")
    selected = [
        "objects/lbvserver.json",
        "parsed/runningconfig.txt",
        "export-manifest.json",
        "collect-log.txt",
        "scan-doel.txt",
    ]
    prefix = b"\xef\xbb\xbf" if bom else b""
    for name in selected:
        path = source / name
        path.write_bytes(prefix + path.read_bytes())
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["resources"]["config/lbvserver"]["payloadSha256"] = digest(
        (source / "objects/lbvserver.json").read_bytes()
    )
    config = (source / "parsed/runningconfig.txt").read_bytes().decode("utf-8-sig").replace("\r\n", "\n").encode()
    manifest["resources"]["config/nsrunningconfig"]["payloadSha256"] = digest(config)
    manifest["files"]["parsed/runningconfig.txt"] = digest(config)
    manifest_path.write_bytes(prefix + json.dumps(manifest).encode())
    (source / "scan-doel.txt").write_bytes(
        prefix + b"APPLIANCE-PRIVATE\n" + digest(manifest_path.read_bytes()).encode() + b"\n"
    )
    extra = tmp_path / "extra.txt"
    extra.write_bytes(prefix + b"ExampleCustomer\n")
    before = tree(source)
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 0, result.stderr
    output = tree(tmp_path / "out")
    for name, data in output.items():
        assert data.startswith(b"\xef\xbb\xbf") == (bom and name in selected)
    assert_hashes(tmp_path / "out")
    assert output["scan-doel.txt"].decode("utf-8-sig").splitlines()[1] == digest(output["export-manifest.json"]).lower()
    assert_no_originals(tmp_path / "out", tmp_path / "map")
    assert tree(source) == before


def test_addendum3_public_suffix_order_does_not_change_protected_categories(monkeypatch):
    module = load_script()
    monkeypatch.setattr(module, "PUBLIC_SUFFIXES", ("new.public.example", *reversed(module.PUBLIC_SUFFIXES)))
    for term, category in [
        ("nsbotsignatures.s3.amazonaws.com", "leverancier"),
        ("device-posture-controller.cloud.com", "leverancier"),
        ("netscaler.com", "leverancier"),
        ("youtube.com", "publiek platform"),
        ("googlevideo.com", "publiek platform"),
        ("a.root-servers.net", "rootserver"),
    ]:
        assert module.protected_category(term) == category


def test_reference_fixture_is_already_pseudonymised_and_a_second_pass_is_refused(tmp_path, monkeypatch):
    """The shipped reference fixture IS the output of this tool (a fresh
    mapping, 35+ originals replaced: hostnames, addresses, lab certificates,
    the identifiers of the appliance; mapping and forbidden list kept outside
    every repository). Two things follow and both are pinned here.

    First, the vendor-shipped names stay literally in it - the built-in
    certkeys, the NOREWRITE action, the default SSL profiles and the default
    monitors are NetScaler vocabulary, not an identity, and product code
    compares against them by name.

    Second, a second pass over an already pseudonymised export is refused
    instead of quietly re-aliasing it.

    THE REAL REASON, measured with a spy on `_allowed_alias()` (external
    review, 18-9-2026): the fixture's own re-harvested candidate
    names - `VSRV-001`, `CERT-004`, ... - already carry this tool's OWN
    per-family alias form, so `collect_candidates()` refuses on the first
    one it meets, before any mapping is even attempted. This fires whether
    or not the fixture happens to carry a host alias too (the previous,
    narrower guarantee this test used to pin): a pseudonymised export
    WITHOUT one is caught exactly the same way, by the very same candidate-
    name check - no real gap remains here."""
    source = tmp_path / "reference"
    shutil.copytree(LIVE_EXPORT, source)
    mapping = tmp_path / "map"
    write_json(mapping / "mapping.json", {})
    before_source = tree(source)
    fixture_text = "\n".join(
        name + "\n" + data.decode("utf-8-sig") for name, data in before_source.items() if not name.endswith(".json")
    ) + "\n".join(
        json.dumps(json.loads(data.decode("utf-8-sig")), ensure_ascii=False)
        for name, data in before_source.items()
        if name.endswith(".json")
    )
    for vendor_name in (
        "ns-server-certificate",
        "ns-sftrust-certificate",
        "NOREWRITE",
        "ns_default_ssl_profile_frontend",
        "ping-default",
        "tcp-default",
    ):
        assert vendor_name in fixture_text
    assert "host-00" in fixture_text and "192.0.2." in fixture_text
    # STRENGTHENED premise: no private address and no
    # non-neutral identity field survives in the fixture text either - the
    # same classes `assert_no_originals()` checks on a fresh run's OUTPUT,
    # asserted here on the shipped fixture itself.
    for pattern in (
        r"\b10\.\d+\.\d+\.\d+\b",
        r"\b192\.168\.\d+\.\d+\b",
        r"\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+\b",
        r"\.nl\b",
        r"\.local\b",
    ):
        assert not re.search(pattern, fixture_text.casefold())

    # THE REAL DIAGNOSIS, measured directly through the module's own
    # guard - not inferred from the CLI's shared message text below. A spy
    # on `_allowed_alias()` (the same function `_validate_mapping_shape()`
    # already uses to police a mapping.json alias) records every candidate
    # name it is asked about and which ones it recognises as this tool's
    # own alias form; `collect_candidates()` raises on the FIRST match,
    # before any mapping is even attempted, so the empty `existing={}`
    # mapping here means every recorded call came from that one check.
    module = load_script()
    blobs = tree(source)
    identity = module.identity_hostnames(blobs)

    matched: list[str] = []
    echte_allowed_alias = module._allowed_alias

    def _spion(value):
        allowed = echte_allowed_alias(value)
        if allowed:
            matched.append(value)
        return allowed

    monkeypatch.setattr(module, "_allowed_alias", _spion)
    with pytest.raises(module.Refused, match="vorm van een pseudoniem"):
        module.build_mapping(blobs, [], {}, identity)
    assert matched, "geen kandidaatnaam in aliasvorm gemeten - de premisse van deze test klopt niet"
    assert re.fullmatch(r"[A-Z]+-\d{3,}", matched[0]), matched[0]

    # Since the free-text after-treatment (`--free-text-only`) the fixture
    # also carries the marker in its manifest, so the CLI now refuses on
    # that marker first - before the alias-form check above is reached.
    result = run(source, tmp_path / "out", mapping)
    assert result.returncode == 1, result.stdout + result.stderr
    combined = result.stdout + result.stderr  # the refusal and the end status go to stderr
    assert "Bron is al gepseudonimiseerd (marker in manifest)" in combined
    assert "[eindstatus] MISLUKT" in combined
    assert not (tmp_path / "out").exists()
    assert tree(source) == before_source
    assert json.loads((mapping / "mapping.json").read_text(encoding="utf-8")) == {}


def test_addendum3_staged_substring_leak_is_refused_before_mapping_publication(tmp_path, monkeypatch, capsys):
    module = load_script()
    source = seed(tmp_path / "source")
    mapping = tmp_path / "map"
    write_json(mapping / "mapping.json", {"Private-LB": "LBV-501"})
    before_source, before_map = tree(source), tree(mapping)
    original_read = module.read_source

    def corrupt_stage(path):
        blobs = original_read(path)
        if path != source:
            blobs["collect-log.txt"] += b" prePRIVATE-LB_backup"
        return blobs

    monkeypatch.setattr(module, "read_source", corrupt_stage)
    result = module.main(["--source", str(source), "--target", str(tmp_path / "out"), "--mapping", str(mapping)])
    assert result == 1
    output = capsys.readouterr()
    assert "MISLUKT" in output.err and "collect-log.txt" in output.err
    assert "private-lb" not in (output.out + output.err).casefold()
    assert tree(source) == before_source and tree(mapping) == before_map
    assert not (tmp_path / "out").exists()
    assert not list(tmp_path.glob(".pseudonymise-*"))


def test_addendum3_replacement_boundaries_remain_stricter_than_final_gate():
    module = load_script()
    table = module.MappingTable({"lab": "TERM-001"})
    text = "lab policylabel /nsconfig/ssl/lab-cert.pem"
    assert module.apply_mapping(text, table) == "TERM-001 policylabel /nsconfig/ssl/lab-cert.pem"
    with pytest.raises(module.Refused):
        module.verify({"collect-log.txt": module.apply_mapping(text, table).encode()}, table)


def test_addendum4_short_target_name_stays_unreplaced_with_a_warning(tmp_path):
    """A three-character scan-doel.txt target name is also a substring of a
    NetScaler CLI keyword (policylabel) the replacer correctly never
    touches, and of every '.lab.example' host alias in the rest of the
    output (the script's own fixed neutral-alias domain, PUBLIC_SUFFIXES).
    Before the fix, harvesting it as a host candidate made the
    boundary-free end gate flag that keyword as a leaked original:
    MISLUKT. With the fix the name is never harvested; the run succeeds and
    the target name is left exactly as-is."""
    source = seed(tmp_path / "source")
    running = source / "parsed/runningconfig.txt"
    running.write_bytes(running.read_bytes() + b"-invoke policylabel _x\n")
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/nsrunningconfig"]["payloadSha256"] = digest(running.read_bytes())
    manifest["files"]["parsed/runningconfig.txt"] = digest(running.read_bytes())
    write_json(manifest_path, manifest)
    (source / "scan-doel.txt").write_text("lab\n" + digest(manifest_path.read_bytes()) + "\n", encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        result.stdout.count(
            "[waarschuwing] doelnaam korter dan vier tekens; niet als substring te bewaken; blijft staan"
        )
        == 1
    )
    output = tree(tmp_path / "out")
    assert b"-invoke policylabel _x" in output["parsed/runningconfig.txt"]
    assert output["scan-doel.txt"].decode("utf-8").splitlines()[0] == "lab"
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "lab" not in {key.casefold() for key in mapping}


def test_addendum4_four_character_target_name_is_still_replaced(tmp_path):
    """Existing (pinned) behaviour: a target name at or above the floor is
    still harvested and replaced like any other host candidate."""
    source = seed(tmp_path / "source")
    (source / "scan-doel.txt").write_text(
        "node\n" + digest((source / "export-manifest.json").read_bytes()) + "\n", encoding="utf-8"
    )
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "doelnaam korter dan vier tekens" not in result.stdout
    output = tree(tmp_path / "out")
    assert output["scan-doel.txt"].decode("utf-8").splitlines()[0] != "node"
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "node" in {key.casefold() for key in mapping}


def test_addendum4_short_hostname_from_nshostname_json_stays_with_warning(tmp_path):
    """Same floor, hostname variant, on the realistic shape of a real export:
    objects/nshostname.json AND the 'set ns hostname' line in both
    running and saved config carry the same three-character hostname, one
    of them next to a NetScaler CLI keyword (policylabel) the replacer must
    never touch. Every one of those harvest paths shares the same floor, so
    the name is neither a candidate nor identity evidence anywhere, with a
    single hostname-flavoured warning - not one per source - instead of the
    target-name one."""
    source = seed(tmp_path / "source")
    write_json(source / "objects/nshostname.json", {"nshostname": {"hostname": "lab"}})
    for name in ("runningconfig", "savedconfig"):
        p = source / "parsed" / f"{name}.txt"
        p.write_bytes(p.read_bytes() + b"set ns hostname lab\n-invoke policylabel _x\n")
    refresh_manifest(source)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        result.stdout.count(
            "[waarschuwing] hostnaam korter dan vier tekens; niet als substring te bewaken; blijft staan"
        )
        == 1
    )
    output = tree(tmp_path / "out")
    hostname_out = json.loads(output["objects/nshostname.json"].decode("utf-8-sig"))["nshostname"]["hostname"]
    assert hostname_out == "lab"
    for name in ("runningconfig", "savedconfig"):
        text = output[f"parsed/{name}.txt"].decode("utf-8-sig")
        assert "set ns hostname lab" in text
        assert "-invoke policylabel _x" in text
    mapping = json.loads((tmp_path / "map/mapping.json").read_text())
    assert "lab" not in {key.casefold() for key in mapping}


def _minimal_export_without_hostname(path: Path) -> Path:
    """A valid, minimal, entirely synthetic export with no hostname or
    hardware identity anywhere - no nshostname/nshardware/hanode, no
    'set ns hostname' line, no scan-doel.txt. The one shape the existing
    alias-collision fallback (pinned elsewhere for the shipped reference
    fixture, which DOES carry a host alias) cannot catch on a second pass:
    there is no host alias here to re-harvest and collide with, so a
    general second-pass invariant needs its OWN check, not a coincidental
    side effect."""
    path.mkdir(parents=True)
    (path / "objects").mkdir()
    data = json.dumps({"lbvserver": [{"name": "Synthetic-Gateway", "servicetype": "HTTP"}]}).encode()
    (path / "objects/lbvserver.json").write_bytes(data)
    write_json(
        path / "export-manifest.json",
        {
            "manifestVersion": "1.1",
            "collectorVersion": "1.0.1",
            "resources": {
                "config/lbvserver": {
                    "status": "OK",
                    "httpStatus": 200,
                    "propertyName": "lbvserver",
                    "objectCount": 1,
                    "payloadSha256": digest(data),
                }
            },
            "files": {},
        },
    )
    return path


def test_addendum6_second_pass_is_refused_by_manifest_marker_even_without_a_hostname(tmp_path):
    """transform() stamps manifest["pseudonymisation"] = {"version": 1} on
    every fresh output; execute() refuses immediately - before building any
    mapping or touching a target - once a SOURCE manifest already carries
    that key. Proven on a source with no hostname anywhere, so the existing
    alias-collision fallback (proven elsewhere to depend on a fixture's own
    host alias) cannot be what is doing the work here."""
    source = _minimal_export_without_hostname(tmp_path / "source")
    first = tmp_path / "first"
    result = run(source, first, tmp_path / "map1")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[eindstatus] GESLAAGD" in result.stdout
    manifest = json.loads((first / "export-manifest.json").read_text(encoding="utf-8-sig"))
    assert manifest["pseudonymisation"] == {"version": 1}
    assert_hashes(first)

    second = tmp_path / "second"
    result2 = run(first, second, tmp_path / "map2")
    assert result2.returncode == 1, result2.stdout + result2.stderr
    assert "[eindstatus] MISLUKT" in result2.stderr
    assert "gepseudonimiseerd" in result2.stderr
    assert not second.exists()


HISTORICAL_NO_MARKER_FIXTURE = ROOT / "tests" / "fixtures" / "pseudonymised-historical-no-marker"


def _copy_export_fixture(fixture: Path, dest: Path) -> Path:
    """Copies a fixture export directory to `dest`, byte for byte, skipping
    the fixture's own `README.md` (documentation about the fixture, not
    part of the export payload the real tool ever produced)."""
    for file in sorted(fixture.rglob("*")):
        if not file.is_file():
            continue
        rel = file.relative_to(fixture)
        if rel == Path("README.md"):
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file.read_bytes())
    return dest


def test_historical_output_from_before_the_marker_existed_is_refused_on_a_second_pass(tmp_path):
    """The manifest-marker check (proven above) only ever catches a FRESH
    marked output. A REAL historical export - made by the tool as it stood
    before that marker existed, that tool's own `execute()` on the synthetic minimal
    export `_minimal_export_without_hostname` builds, not a hand-written
    imitation of its output shape - carries no `pseudonymisation` key, so
    that check alone lets a second pass through silently: `LBV-001`, the
    alias the old run already handed out, looks exactly like a fresh
    original to `collect_candidates()`.

    That historical output is pinned once as
    `tests/fixtures/pseudonymised-historical-no-marker/` (see its README)
    rather than regenerated here from that earlier commit: a shallow CI
    checkout does not carry it, and the public history does not contain it
    at all - the test must not depend on either.

    The fix recognises the candidate NAME itself instead of a manifest key:
    `_allowed_alias()` (the same function `_validate_mapping_shape()` already
    uses to police a mapping.json alias) knows every shape this tool ever
    hands out - the per-family `FAMILIE-NNN` form (derived from
    `NAME_SOURCES`, so already general across every family, not just
    `LBV`), the `host-NNN.(lab.example|invalid)` form, and the fixed
    id-aliases. A candidate name in exactly one of those shapes is never a
    fresh customer original; it is this tool's own OUTPUT, historical or
    fresh, marker or not - refused before any mapping is built, with its
    own diagnosis, no target directory, mapping unchanged."""
    historical = _copy_export_fixture(HISTORICAL_NO_MARKER_FIXTURE, tmp_path / "historical")
    old_manifest = json.loads((historical / "export-manifest.json").read_text(encoding="utf-8-sig"))
    assert "pseudonymisation" not in old_manifest, "premisse: de oude tool zette nog geen marker"
    old_lbvserver = json.loads((historical / "objects/lbvserver.json").read_text(encoding="utf-8-sig"))
    assert old_lbvserver["lbvserver"][0]["name"] == "LBV-001", "premisse: de oude tool gaf dit precieze alias uit"

    second = tmp_path / "second"
    result = run(historical, second, tmp_path / "new-map")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "[eindstatus] MISLUKT" in result.stderr
    assert not second.exists()


def test_a_genuinely_fresh_name_in_alias_form_is_refused_too(tmp_path):
    """The documented trade-off (scripts/README.md) for the fix above: a
    FIRST-time source that happens to name an object exactly like this
    tool's own alias form is refused as well, with the same diagnosis - the
    tool cannot tell that case apart from a real historical output, and the
    fail-closed choice is the same one addendum 6 already made for a
    marker. Proven directly through the module (no old tool involved), and
    across more than one family - the fix is not hardcoded to `LBV`."""
    module = load_script()
    for family, path, key, field, value in (
        ("LBV", "objects/lbvserver.json", "lbvserver", "name", "LBV-001"),
        ("MON", "objects/lbmonitor.json", "lbmonitor", "monitorname", "MON-042"),
        ("CERT", "objects/sslcertkey.json", "sslcertkey", "certkey", "CERT-007"),
    ):
        blobs = tree(seed(tmp_path / f"source-{family}"))
        payload = json.loads(blobs[path]) if path in blobs else {key: []}
        payload[key] = [{field: value}]
        blobs[path] = module._encode(payload)
        with pytest.raises(module.Refused, match="pseudoniem"):
            module.build_mapping(blobs, [], {})


def _append_attribute_builtin_monitor(source: Path, name: str) -> None:
    """Adds an lbmonitor row carrying NITRO's own `builtin: true` (regel A)
    under a name NOT in the fixed VENDOR_BUILTIN_NAMES list - the shape the
    static list structurally cannot cover, so only builtin_names(blobs)'s
    fresh per-export harvest catches it."""
    lbmonitor_path = source / "objects/lbmonitor.json"
    monitors = json.loads(lbmonitor_path.read_text())
    monitors["lbmonitor"].append({"monitorname": name, "type": "TCP", "builtin": True})
    write_json(lbmonitor_path, monitors)
    manifest_path = source / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["resources"]["config/lbmonitor"]["objectCount"] = len(monitors["lbmonitor"])
    write_json(manifest_path, manifest)
    refresh_manifest(source)


def test_addendum6_legacy_mapping_with_attribute_builtin_name_is_skipped_namelessly(tmp_path):
    """A legacy mapping.json entry for an attribute-marked builtin name (not
    in VENDOR_BUILTIN_NAMES) is dropped exactly like a listed vendor name
    (addendum5) - alias reserved, name kept out of the rewritten mapping -
    but since an arbitrary attribute-marked name is not known-safe
    vocabulary the way a VENDOR_BUILTIN_NAMES entry is, the warning stays
    nameless."""
    source = seed(tmp_path / "source")
    _append_attribute_builtin_monitor(source, "Synthetic-Shipped-Monitor")
    mapping_dir = tmp_path / "map"
    write_json(mapping_dir / "mapping.json", {"Synthetic-Shipped-Monitor": "MON-501"})
    result = run(source, tmp_path / "out", mapping_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        result.stdout.count(
            "[waarschuwing] bestaande mapping bevat een ingebouwde naam (niet in de vaste lijst); overgeslagen"
        )
        == 1
    )
    assert "Synthetic-Shipped-Monitor" not in result.stdout
    output = tree(tmp_path / "out")
    assert b'"Synthetic-Shipped-Monitor"' in output["objects/lbmonitor.json"]
    mapping = json.loads((mapping_dir / "mapping.json").read_text())
    assert "Synthetic-Shipped-Monitor" not in mapping
    assert "MON-501" not in mapping.values()


def test_addendum6_extra_literal_matching_an_attribute_builtin_name_is_refused(tmp_path):
    """check_extra_lines() only screens a --extra-forbidden literal against
    the FIXED VENDOR_BUILTIN_NAMES list (protected_category) - it never
    sees the blobs, so it cannot know an attribute-marked builtin name from
    THIS export. collect_candidates()'s extra-literal route is the
    backstop: it must refuse instead of silently making the name a
    candidate (which would then get replaced, hiding the object the
    product's own hardcoded comparisons rely on)."""
    source = seed(tmp_path / "source")
    _append_attribute_builtin_monitor(source, "Synthetic-Shipped-Monitor")
    extra = tmp_path / "extra.txt"
    extra.write_text("Synthetic-Shipped-Monitor", encoding="utf-8")
    result = run(source, tmp_path / "out", tmp_path / "map", extra)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "[eindstatus] MISLUKT" in result.stderr
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "map/mapping.json").exists()


def test_addendum6_legacy_mapping_with_generic_vendor_name_is_skipped_not_refused(tmp_path):
    """Before this fix, validate_mapping() ran on the RAW `existing` mapping
    BEFORE the short-name/builtin filter loop: a legacy 'http'/'https'
    entry (both in VENDOR_BUILTIN_NAMES/KEEP_NAMES) hit its 'low in
    KEEP_NAMES' branch immediately and refused the WHOLE run, even though
    the filter loop right below would otherwise skip that exact entry with
    a warning like any other vendor-builtin name. Moving the semantic
    validate_mapping() call to run on the FILTERED mapping, after the
    filter loop, lets the filter do its job first."""
    source = seed(tmp_path / "source")
    mapping_dir = tmp_path / "map"
    write_json(mapping_dir / "mapping.json", {"http": "MON-501", "https": "MON-502"})
    result = run(source, tmp_path / "out", mapping_dir)
    assert result.returncode == 0, result.stdout + result.stderr
    for original in ("http", "https"):
        assert (
            result.stdout.count(
                f"[waarschuwing] bestaande mapping bevat een ingebouwde leveranciersnaam ({original}); overgeslagen"
            )
            == 1
        )
    mapping = json.loads((mapping_dir / "mapping.json").read_text())
    assert "http" not in mapping and "https" not in mapping
    assert "MON-501" not in mapping.values()
    assert "MON-502" not in mapping.values()


def test_addendum6_damaged_legacy_alias_form_still_refused(tmp_path):
    """Moving the semantic validate_mapping() call only changes WHEN it
    runs, never the structural checks: a syntactically invalid alias must
    still refuse the whole run before any short/builtin filtering happens."""
    source = seed(tmp_path / "source")
    mapping_dir = tmp_path / "map"
    write_json(mapping_dir / "mapping.json", {"Private-LB": "not-a-valid-alias-form"})
    result = run(source, tmp_path / "out", mapping_dir)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "[eindstatus] MISLUKT" in result.stderr
    assert not (tmp_path / "out").exists()
    assert json.loads((mapping_dir / "mapping.json").read_text()) == {"Private-LB": "not-a-valid-alias-form"}


# ---------------------------------------------------------------------------
# Free text. The alias mapping replaces NAMES and ADDRESSES; a comment, a
# monitor string, a store name, a rewrite expression, a time zone or a
# Gateway home URL is text an operator typed, and no alias family covers it.
# Measured on a real export: dozens of comment fields and monitor strings
# survived a passing run. These fields are neutralised by FIELD, not by
# value, so the tool never needs to know the original.
# ---------------------------------------------------------------------------


def test_free_text_fields_in_objects_are_neutralised_and_vendor_rows_are_not():
    module = load_script()
    document = {
        "server": [{"name": "SRV-1", "comment": "Some App PRD"}, {"name": "SRV-2", "comment": "<REDACTED>"}],
        "nsparam": {"timezone": "GMT+02:00-CEST-Europe/Somewhere"},
        "auditsyslogparams": {"timezone": "GMT_TIME"},
        "lbmonitor": [
            {"monitorname": "MON-1", "send": "GET /app/status.json", "recv": "OK app", "storename": "PRD"},
            {"monitorname": "xnc", "builtin": ["IMMUTABLE"], "recv": "vendor text"},
            {"monitorname": "http-ecv", "send": "GET /"},
        ],
        "rewriteaction": [
            {"name": "RW-1", "stringbuilderexpr": '"/app/api"'},
            {"name": "ns_cvpn_x", "isdefault": True, "stringbuilderexpr": '"vendor"'},
        ],
    }
    result = module.neutralise_json(document)
    assert result["server"][0]["comment"] == "LAB synthetic comment"
    assert result["server"][1]["comment"] == "<REDACTED>", "een markering van de verzamelaar blijft staan"
    assert result["nsparam"]["timezone"] == "CoordinatedUniversalTime"
    assert result["auditsyslogparams"]["timezone"] == "GMT_TIME", "een tijdzonewoord zonder plaats blijft"
    monitor = result["lbmonitor"][0]
    assert (monitor["send"], monitor["recv"], monitor["storename"]) == (
        "GET /lab/health",
        "LAB synthetic response",
        "LabStore",
    )
    assert result["lbmonitor"][1]["recv"] == "vendor text", "een ingebouwde rij is leveranciersvocabulaire"
    assert result["lbmonitor"][2]["send"] == "GET /", "een standaardmonitor zonder builtin-veld ook"
    assert result["rewriteaction"][0]["stringbuilderexpr"] == '"LAB synthetic"'
    assert result["rewriteaction"][1]["stringbuilderexpr"] == '"vendor"'
    assert module.neutralise_json(result) == result, "een tweede pas verandert niets"


def test_free_text_flags_in_the_config_text_are_neutralised():
    module = load_script()
    text = "\n".join(
        [
            'add server SRV-1 192.0.2.1 -comment "Some App PRD"',
            "add server SRV-2 192.0.2.2 -comment <REDACTED>",
            r'add lb monitor MON-1 HTTP-ECV -send "GET /app/status.json" -recv q/{\"Status\":0}/ -LRTM DISABLED',
            "add lb monitor MON-2 STOREFRONT -storename PRD -dispatcherIP 0.0.0.0",
            'set ns param -timezone "GMT+02:00-CEST-Europe/Somewhere"',
            'add vpn sessionAction S1 -wihome "https://host-003.lab.example/Citrix/SomeStoreWeb" -ntDomain CORP -SSO ON',
            "add ns ip6 fe80::200:5eff:fe00:5301/64 -scope link-local -type NSIP",
            "add server SRV-3 192.0.2.3",
            r'add rewrite action RW-1 replace HTTP.REQ.URL.PATH "\"/app/api/v1\""',
            "add rewrite action RW-2 delete_http_header X-App-Trace",
            "",
        ]
    )
    result = module.neutralise_config_text(text)
    assert result.splitlines() == [
        'add server SRV-1 192.0.2.1 -comment "LAB synthetic comment"',
        "add server SRV-2 192.0.2.2 -comment <REDACTED>",
        'add lb monitor MON-1 HTTP-ECV -send "GET /lab/health" -recv "LAB synthetic response" -LRTM DISABLED',
        "add lb monitor MON-2 STOREFRONT -storename LabStore -dispatcherIP 0.0.0.0",
        'set ns param -timezone "CoordinatedUniversalTime"',
        'add vpn sessionAction S1 -wihome "https://host-003.lab.example/lab/store" -ntDomain LAB -SSO ON',
        "add ns ip6 fe80::ff:fe00:1/64 -scope link-local -type NSIP",
        "add server SRV-3 192.0.2.3",
        r'add rewrite action RW-1 replace HTTP.REQ.URL.PATH "\"LAB synthetic\""',
        "add rewrite action RW-2 delete_http_header X-App-Trace",
    ]
    assert result.endswith("\n")
    assert module.neutralise_config_text(result) == result, "een tweede pas verandert niets"


def test_the_neutral_link_local_address_is_the_eui64_of_the_neutral_mac():
    """A link-local address in EUI-64 form spells the MAC address back out
    (fe80::200:5eff:fe00:5301 IS 00:00:5E:00:53:01, a documentation MAC). The tool aliases the MAC
    to NEUTRAL_MAC_COLON, so the address it writes is the EUI-64 of that
    neutral MAC - never a value derived from the original."""
    import ipaddress

    module = load_script()
    mac = bytes(int(part, 16) for part in module.NEUTRAL_MAC_COLON.split(":"))
    eui64 = bytes([mac[0] ^ 0x02]) + mac[1:3] + b"\xff\xfe" + mac[3:]
    expected = ipaddress.IPv6Address(b"\xfe\x80" + b"\x00" * 6 + eui64)
    assert module.NEUTRAL_LINK_LOCAL == str(expected)
    # A link-local address that is NOT in EUI-64 form carries no MAC and stays.
    assert module.neutralise_config_text("add ns ip6 fe80::1/64\n") == "add ns ip6 fe80::1/64\n"


def test_the_leak_check_refuses_free_text_that_survived():
    module = load_script()
    with pytest.raises(module.Refused, match="vrije tekst"):
        module.verify({"parsed/runningconfig.txt": b'add server S 192.0.2.1 -comment "Some App"\n'}, {})
    with pytest.raises(module.Refused, match="vrije tekst"):
        module.verify({"objects/server.json": json.dumps({"server": [{"comment": "Some App"}]}).encode()}, {})


def _append_config_line(root: Path, line: str, *, stamp_lower: bool) -> None:
    """Adds one line to both config texts of an export and reseals the
    manifest and the scan stamp, so the export is valid input again."""
    for name in ("runningconfig", "savedconfig"):
        path = root / "parsed" / f"{name}.txt"
        path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")
    manifest = json.loads((root / "export-manifest.json").read_text(encoding="utf-8"))
    for name in ("runningconfig", "savedconfig"):
        data = (root / "parsed" / f"{name}.txt").read_bytes()
        manifest["files"][f"parsed/{name}.txt"] = digest(data)
        manifest["resources"][f"config/ns{name}"]["payloadSha256"] = digest(data)
    write_json(root / "export-manifest.json", manifest)
    stamp = (root / "scan-doel.txt").read_text(encoding="utf-8").splitlines()[0]
    sealed = digest((root / "export-manifest.json").read_bytes())
    (root / "scan-doel.txt").write_text(stamp + "\n" + (sealed.lower() if stamp_lower else sealed) + "\n", "utf-8")


def test_a_full_pass_neutralises_free_text_and_rehashes(tmp_path):
    source = seed(tmp_path / "source")
    _append_config_line(source, 'add server SRV-X 192.0.2.9 -comment "App PRD"', stamp_lower=False)
    result = run(source, tmp_path / "out", tmp_path / "map")
    assert result.returncode == 0, result.stderr
    text = (tmp_path / "out" / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
    assert '-comment "LAB synthetic comment"' in text and "App PRD" not in text
    _lines, gap = load_export(tmp_path / "out").running_config_lines()
    assert gap is None, gap


def test_the_free_text_pass_runs_on_an_already_pseudonymised_export(tmp_path):
    """`--free-text-only` is the after-treatment of an export that was
    pseudonymised before these fields were covered: no alias mapping, no
    mapping directory; free text neutralised, hashes and the scan stamp
    recomputed, and an optional extra-terms file mapped to TERM aliases."""
    source = seed(tmp_path / "source")
    first = run(source, tmp_path / "once", tmp_path / "map")
    assert first.returncode == 0, first.stderr
    once = tmp_path / "once"
    _append_config_line(once, 'add server SRV-Y 192.0.2.8 -comment "App ACC"', stamp_lower=True)
    extra = tmp_path / "extra.txt"
    extra.write_text("SRV-Y\n", encoding="utf-8")
    args = [sys.executable, str(SCRIPT), "--free-text-only", "--source", str(once), "--target", str(tmp_path / "twice")]
    args += ["--extra-forbidden", str(extra)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert "[eindstatus] GESLAAGD" in result.stdout
    text = (tmp_path / "twice" / "parsed" / "runningconfig.txt").read_text(encoding="utf-8")
    assert "App ACC" not in text and "SRV-Y" not in text
    assert 'add server TERM-001 192.0.2.8 -comment "LAB synthetic comment"' in text
    _lines, gap = load_export(tmp_path / "twice").running_config_lines()
    assert gap is None, gap
    stamp = (tmp_path / "twice" / "scan-doel.txt").read_text(encoding="utf-8").splitlines()[1]
    assert stamp == hashlib.sha256((tmp_path / "twice" / "export-manifest.json").read_bytes()).hexdigest()


def test_the_free_text_pass_refuses_a_mapping_directory(tmp_path):
    source = seed(tmp_path / "source")
    args = [sys.executable, str(SCRIPT), "--free-text-only", "--source", str(source), "--target", str(tmp_path / "x")]
    args += ["--mapping", str(tmp_path / "map")]
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode != 0
    assert not (tmp_path / "x").exists()
