"""Exports with a running and a saved config, for the tests of the one
running-against-saved comparison (`nsmcp.config_drift`) and its readers.

A harness module rather than helpers inside one test file: a test file in
this codebase does not import from another test module, and both
tests/test_config_drift.py and tests/test_preflight.py build these exports.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
LAB = FIXTURES / "lab-export-vpx-20260826"
DOH = FIXTURES / "lab-export-vpx-doh-synthetic"

# A deliberate, harmless change of the kind an operator makes on the CLI.
# Synthetic names only (`LBV-`), never a real object.
INSERTED = "set lb vserver LBV-001 -comment acceptatietest"

# The header lines the appliance writes, in the shape of the two real lab
# exports, for a synthetic pair that should read like a real one.
RUNNING_HEADER = ["#NS14.1 Build 72.57", "# Last modified Thu Sep 24 10:12:03 2026"]
SAVED_HEADER = ["#NS14.1 Build 72.57", "# Last modified by `save config`, Wed Sep 23 12:59:15 2026"]

# Two synthetic credential values - never a real secret - that must never
# reach an answer, an evidence sentence or a check.
OLD_SECRET = "Q7W1OUDWAARDE"
NEW_SECRET = "Q7W1NIEUWWAARDE"

# Per name a running line and a saved line that differ ONLY in the part the
# credential filter of the export read (`redact.py`) cuts away: a changed
# password that was not saved. The last case also changes a flag AFTER the
# credential, which the filter cuts away with it. Synthetic names and
# TEST-NET addresses only.
WITHHELD_ONLY_PAIRS = {
    "system-user": (
        f"add system user SYSU-01 {OLD_SECRET} -encrypted -encryptmethod ENCMTHD_3",
        f"add system user SYSU-01 {NEW_SECRET} -encrypted -encryptmethod ENCMTHD_3",
    ),
    "ldap-bind-password": (
        "add authentication ldapAction LDAP-01 -serverIP 192.0.2.5 -ldapBindDn cn=svc"
        f" -ldapBindDnPassword {OLD_SECRET} -encrypted -encryptmethod ENCMTHD_3",
        "add authentication ldapAction LDAP-01 -serverIP 192.0.2.5 -ldapBindDn cn=svc"
        f" -ldapBindDnPassword {NEW_SECRET} -encrypted -encryptmethod ENCMTHD_3",
    ),
    "rpcnode-password": (
        f"set ns rpcNode 192.0.2.6 -password {OLD_SECRET} -encrypted -encryptmethod ENCMTHD_3 -srcIP 192.0.2.7",
        f"set ns rpcNode 192.0.2.6 -password {NEW_SECRET} -encrypted -encryptmethod ENCMTHD_3 -srcIP 192.0.2.7",
    ),
    "monitor-password": (
        f"add lb monitor MON-01 LDAP -password {OLD_SECRET} -encrypted -encryptmethod ENCMTHD_3 -baseDN dc=a",
        f"add lb monitor MON-01 LDAP -password {NEW_SECRET} -encrypted -encryptmethod ENCMTHD_3 -baseDN dc=a",
    ),
    "monitor-password-and-a-flag-after-it": (
        f"add lb monitor MON-01 LDAP -password {OLD_SECRET} -encrypted -encryptmethod ENCMTHD_3 -baseDN dc=a",
        f"add lb monitor MON-01 LDAP -password {NEW_SECRET} -encrypted -encryptmethod ENCMTHD_3 -baseDN dc=b",
    ),
}

# The literal the released collector writes on the jumphost in place of a
# credential value, in the running AND the saved config alike: measured on
# the lab export (ten lines per side), `collect-log.txt` "geredigeerd op de
# jumphost", and the README of that export. The synthetic DoH export
# (scripts/make_doh_fixture.py) carries the same marker on eight lines per
# side.
COLLECTOR_MARKER = "<REDACTED>"

# Per name ONE line, in the shape the collector writes it - the value already
# replaced by its marker - so the running and the saved side carry the same
# text whether or not the value on the appliance changed. The three shapes of
# the lab exports (a system user, the RPC node, a monitor password), with
# synthetic names and TEST-NET addresses.
COLLECTOR_MARKER_LINES = {
    "system-user": (
        f"set system user SYSU-01 {COLLECTOR_MARKER} -encrypted -externalAuth DISABLED"
        f" -lastpwdchangetimestamp {COLLECTOR_MARKER}"
    ),
    "rpcnode-password": (
        f"set ns rpcNode 192.0.2.6 -password {COLLECTOR_MARKER} -encrypted -encryptmethod ENCMTHD_4 -kek"
        f" -suffix 2026_05_20_10_54_36 -srcIP 192.0.2.6 -isPasswdIntSet {COLLECTOR_MARKER}"
    ),
    "monitor-password": (
        f"set lb monitor MON-01 CITRIX-XDM -userName svc-01 -password {COLLECTOR_MARKER} -encrypted"
        " -encryptmethod ENCMTHD_4 -kek -suffix 2026_05_20_10_54_36 -deviation 0 -interval 5 -resptimeout 2"
    ),
}

# A saved header whose moment is AFTER the running header's: saved after the
# last change, the other order of the two moments than `SAVED_HEADER`.
SAVED_AFTER_CHANGE_HEADER = ["#NS14.1 Build 72.57", "# Last modified by `save config`, Thu Sep 24 10:14:40 2026"]


def copy_with_running(tmp_path: Path, source: Path, transform) -> Path:
    """A copy of a real export whose running config went through `transform`.

    Hashed the way the collector hashes it (sha256 over the LF-normalized
    text, see `Export.running_config_lines`), and the new hash is put in
    place of the old one in the manifest TEXT - not by re-serializing the
    manifest, so nothing else about the real export changes. `scan-doel.txt`
    is re-anchored to the new manifest so the target name stays readable.
    """
    root = tmp_path / source.name
    shutil.copytree(source, root)
    path = root / "parsed" / "runningconfig.txt"
    old_text = path.read_bytes().decode("utf-8-sig")
    new_text = transform(old_text)
    path.write_bytes(new_text.encode("utf-8"))
    old_hash = hashlib.sha256(old_text.replace("\r\n", "\n").encode("utf-8")).hexdigest()
    new_hash = hashlib.sha256(new_text.replace("\r\n", "\n").encode("utf-8")).hexdigest().upper()
    manifest_path = root / "export-manifest.json"
    manifest = manifest_path.read_bytes().decode("utf-8")
    # PREMISE: the hash being replaced is really the one the manifest keeps
    # for this file - otherwise this helper would build an export that fails
    # on its own manifest instead of on the behaviour under test. The real
    # collector writes the same hash twice (under `files` and as the
    # resource's `payloadSha256`); every copy moves along.
    assert re.search(rf'"parsed/runningconfig\.txt"\s*:\s*"{old_hash}"', manifest, flags=re.IGNORECASE)
    manifest = re.sub(old_hash, new_hash, manifest, flags=re.IGNORECASE)
    manifest_path.write_bytes(manifest.encode("utf-8"))
    target = root / "scan-doel.txt"
    name = target.read_text(encoding="utf-8").splitlines()[0]
    target.write_text(f"{name}\n{hashlib.sha256(manifest.encode('utf-8')).hexdigest()}\n", encoding="utf-8")
    return root


def insert_after_line(number: int, *lines: str):
    """A `copy_with_running` transform that puts `lines` after line `number`,
    in the file's own line endings."""

    def transform(text: str) -> str:
        newline = "\r\n" if "\r\n" in text else "\n"
        existing = text.split(newline)
        existing[number:number] = list(lines)
        return newline.join(existing)

    return transform


def config_pair(tmp_path: Path, running: list[str], saved: list[str], *, name: str = "export") -> Path:
    """A synthetic export carrying exactly a running and a saved config, both
    hashed the way the real collector hashes them."""
    export_dir = tmp_path / name
    (export_dir / "parsed").mkdir(parents=True, exist_ok=True)
    (export_dir / "objects").mkdir(parents=True, exist_ok=True)
    files = {}
    for file_name, lines in (("runningconfig.txt", running), ("savedconfig.txt", saved)):
        text = "\n".join(lines) + "\n"
        (export_dir / "parsed" / file_name).write_bytes(text.encode("utf-8"))
        files[f"parsed/{file_name}"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-24T10:30:00.0000000Z",
        "resources": {
            "config/nsrunningconfig": {"status": "OK"},
            "config/nssavedconfig": {"status": "OK"},
        },
        "files": files,
    }
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return export_dir
