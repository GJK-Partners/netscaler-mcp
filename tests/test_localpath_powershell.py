"""1.1 B.2, the PowerShell route: `Open-GjkLokaalBestand` in
`scripts/GjkUpgrade-LokaalPad.ps1`, on the same test vectors as the Python
walk (`tests/test_localpath_windows.py`).

Every case runs in a fresh Windows PowerShell 5.1 that dot-sources the script
and records its seam (`[GjkLokaalPad.Naad]`): every native open with its
parent handle, every close, the native calls counted. The proofs read that
record the way the Python proofs read `localpath._native`: each open after the
volume root is one component relative to a handle that is held at that
moment, with `FILE_OPEN_REPARSE_POINT`, and every handle is closed exactly
once. A refusal that only comes after an open of the place outside the root
does not count: that is why every race test asserts on the opens.

Junctions need no administrator right; a symbolic link needs the right or
Developer Mode, otherwise its test is skipped with the reason."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from nsmcp import localpath

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("powershell.exe") is None,
    reason="de PowerShell-wandeling vraagt Windows PowerShell 5.1",
)

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "GjkUpgrade-LokaalPad.ps1"
_VOLUME_ROOT = re.compile(r"\\Device\\HarddiskVolume[0-9]+\\", re.IGNORECASE)

FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_DIRECTORY_FILE = 0x1
FILE_NON_DIRECTORY_FILE = 0x40
DIR_ACCESS = 0x0020 | 0x0080 | 0x00100000
DIR_SHARE = 0x1 | 0x2


def ps_text(value: str) -> str:
    """A PowerShell single-quoted string literal of `value`."""
    return "'" + str(value).replace("'", "''") + "'"


_PROLOGUE = r"""
$ErrorActionPreference = 'Stop'
. __SCRIPT__
[GjkLokaalPad.Naad]::Opnemen = $true
$script:uitkomsten = [ordered]@{}
function Uitkomst {
    param([string] $Naam, [scriptblock] $Doe)
    $r = [ordered]@{ soort = $null; detail = $null; gevolgd = $null; reden = $null; data = $null; pad = $null; ontbreekt = $false }
    try {
        $s = & $Doe
        if ($null -eq $s) { $r.ontbreekt = $true }
        else {
            $r.data = [System.Text.Encoding]::ASCII.GetString((Read-GjkLokaleBytes -Stroom $s -Max 1000))
            $r.pad = $s.Pad
            Close-GjkLokaalBestand $s
        }
    }
    catch {
        $w = $_.Exception
        if ($w -isnot [GjkLokaalPad.PadGeweigerd]) { throw }
        $r.soort = $w.Soort; $r.detail = $w.Detail; $r.gevolgd = $w.Gevolgd; $r.reden = $w.Message; $r.pad = $w.Pad
    }
    $script:uitkomsten[$Naam] = $r
}
function Notitie { param([string] $Naam, $Waarde) $script:uitkomsten[$Naam] = $Waarde }
"""

_EPILOGUE = r"""
$naad = [ordered]@{
    opens = @([GjkLokaalPad.Naad]::Opens | ForEach-Object {
        [ordered]@{ ouder = $_.Ouder; naam = $_.Naam; status = $_.Status; handle = $_.Handle;
                    toegang = $_.Toegang; deling = $_.Deling; dispositie = $_.Dispositie; opties = $_.Opties } })
    gebeurtenissen = @([GjkLokaalPad.Naad]::Gebeurtenissen)
    aanroepen = [GjkLokaalPad.Naad]::Aanroepen
}
Write-Output ('JSON:' + (ConvertTo-Json -Depth 6 -Compress ([ordered]@{ uitkomsten = $script:uitkomsten; naad = $naad })))
"""


class Run:
    def __init__(self, data: dict, stderr: str) -> None:
        self.results = data["uitkomsten"]
        self.seam = data["naad"]
        self.stderr = stderr

    def __getitem__(self, name: str) -> dict:
        return self.results[name]

    def calls(self, name: str) -> int:
        return int((self.seam["aanroepen"] or {}).get(name, 0))

    @property
    def opens(self) -> list[dict]:
        return list(self.seam["opens"] or [])


def run_ps(tmp_path: Path, body: str, *, env: dict | None = None) -> Run:
    script = tmp_path / "proef.ps1"
    text = _PROLOGUE.replace("__SCRIPT__", ps_text(str(SCRIPT))) + body + _EPILOGUE
    script.write_text(text, encoding="ascii")
    environment = dict(os.environ)
    environment.pop("NSMCP_DEBUG", None)
    if env:
        environment.update(env)
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env=environment,
        cwd=str(tmp_path),
    )
    lines = [line for line in proc.stdout.splitlines() if line.startswith("JSON:")]
    assert proc.returncode == 0 and lines, proc.stdout + proc.stderr
    return Run(json.loads(lines[-1][5:]), proc.stderr)


def audit(run: Run) -> list[str]:
    """Every open is the volume root by its device name, or one component
    relative to a handle that was opened earlier and is still open; every
    handle is closed exactly once. Returns the opened names in order."""
    opens = run.opens
    live: set[int] = set()
    names = []
    for event in run.seam["gebeurtenissen"] or []:
        kind, value = event.split(":", 1)
        if kind == "close":
            handle = int(value)
            assert handle in live, f"handle {handle} gesloten zonder open of tweemaal"
            live.discard(handle)
            continue
        record = opens[int(value)]
        names.append(record["naam"])
        if record["ouder"] == 0:
            assert _VOLUME_ROOT.fullmatch(record["naam"]), record["naam"]
        else:
            assert record["ouder"] in live, f"open relatief aan een handle die niet vastgehouden is: {record}"
            name = record["naam"]
            assert name not in ("", ".", "..") and "\\" not in name and "/" not in name and ":" not in name, name
            assert record["opties"] & FILE_OPEN_REPARSE_POINT, record
        if record["toegang"] == DIR_ACCESS:
            assert record["deling"] == DIR_SHARE, record
        assert not record["deling"] & 0x4, f"nooit FILE_SHARE_DELETE: {record}"
        if record["handle"]:
            live.add(record["handle"])
    assert live == set(), f"handles niet gesloten: {live}"
    return names


def _junction(link: Path, target: Path) -> None:
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def _symlink(link: Path, target: str, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as exc:  # pragma: no cover - depends on the symlink right of the account
        pytest.skip(f"symbolische link niet toegestaan op deze machine: {exc.__class__.__name__}")


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    """`wortel\\P\\C\\leaf.txt` ("binnen") and outside the root
    `buiten\\leaf.txt` plus `buiten\\C\\leaf.txt` ("buiten")."""
    root = tmp_path / "wortel"
    (root / "P" / "C").mkdir(parents=True)
    (root / "P" / "C" / "leaf.txt").write_text("binnen", encoding="ascii")
    outside = tmp_path / "buiten"
    (outside / "C").mkdir(parents=True)
    (outside / "leaf.txt").write_text("buiten", encoding="ascii")
    (outside / "C" / "leaf.txt").write_text("buiten", encoding="ascii")
    return root, outside


def _open(name: str, path, *, root=None, klasse: str = "bundel", extra: str = "") -> str:
    where = f"-Wortel {ps_text(root)}" if root is not None else "-ZonderWortel"
    return (
        f"Uitkomst {ps_text(name)} {{ Open-GjkLokaalBestand -Pad {ps_text(path)} {where} -Klasse {klasse} {extra} }}\n"
    )


# ---------------------------------------------------------------------------
# The fixed sentences are the Python ones, byte for byte
# ---------------------------------------------------------------------------


def test_every_kind_and_its_fixed_sentence_equal_the_python_walk(tmp_path):
    run = run_ps(
        tmp_path,
        "Notitie soorten @([GjkLokaalPad.Wandeling]::Soorten)\n"
        "Notitie redenen ([GjkLokaalPad.Wandeling]::Redenen)\n"
        "Notitie grens ([GjkLokaalPad.Wandeling]::KoppelingGrens)\n"
        "Notitie defect ([GjkLokaalPad.Wandeling]::DefectRegel)\n",
    )
    assert run["soorten"] == list(localpath.SOORTEN)
    assert run["redenen"] == localpath.REASONS
    assert run["grens"] == localpath.LINK_LIMIT
    assert run["defect"] == localpath.DEFECT_LINE


def test_the_script_is_ascii_and_parses_on_windows_powershell_5_1(tmp_path):
    SCRIPT.read_text(encoding="ascii")
    run = run_ps(
        tmp_path,
        "$fouten = $null\n"
        f"$null = [System.Management.Automation.Language.Parser]::ParseFile({ps_text(SCRIPT)}, [ref]$null, [ref]$fouten)\n"
        "Notitie fouten @($fouten).Count\n",
    )
    assert run["fouten"] == 0


# ---------------------------------------------------------------------------
# The walk itself
# ---------------------------------------------------------------------------


def test_a_plain_file_is_read_component_by_component_and_every_handle_closes_once(tmp_path):
    root, _ = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"
    run = run_ps(tmp_path, _open("lees", leaf, root=root))
    assert run["lees"]["data"] == "binnen" and run["lees"]["soort"] is None
    names = audit(run)
    assert names[1:] == list(leaf.parts[1:])
    opened = [record["handle"] for record in run.opens if record["handle"]]
    closes = [int(e.split(":")[1]) for e in run.seam["gebeurtenissen"] if e.startswith("close:")]
    assert closes == list(reversed(opened)), "sluiten in omgekeerde volgorde, blad eerst"


def test_the_root_is_walked_on_its_own_text_and_the_rest_relative_to_it(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(tmp_path, _open("lees", root / "P" / "C" / "leaf.txt", root=root))
    names = audit(run)
    root_parts = list(root.parts[1:])
    assert names[1 : 1 + len(root_parts)] == root_parts
    assert names[1 + len(root_parts) :] == ["P", "C", "leaf.txt"]


def test_the_leaf_share_mode_follows_the_file_class(tmp_path):
    """Ledger and runner log share writing (an append runs while it is read);
    bundle, sidecar and package share reading only. Directories never share
    delete."""
    root, _ = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"
    body = "".join(_open(klasse, leaf, root=root, klasse=klasse) for klasse in localpath_classes())
    run = run_ps(tmp_path, body)
    leaves = [record for record in run.opens if record["naam"] == "leaf.txt"]
    shares = dict(zip(localpath_classes(), [record["deling"] for record in leaves], strict=True))
    assert shares == {"bundel": 1, "sidecar": 1, "pakket": 1, "ledger": 3, "runnerlog": 3}
    for record in leaves:
        assert record["toegang"] == 0x0001 | 0x0080 | 0x00100000
        assert record["opties"] & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE) == 0, "geen typevlag op het blad"
    for record in run.opens:
        if record["naam"] in ("P", "C"):
            assert record["toegang"] == DIR_ACCESS and record["deling"] == DIR_SHARE
    audit(run)


def localpath_classes() -> tuple[str, ...]:
    return ("bundel", "sidecar", "pakket", "ledger", "runnerlog")


def test_a_missing_file_is_unreadable_unless_absence_is_allowed(tmp_path):
    root, _ = _tree(tmp_path)
    missing = root / "P" / "nergens.txt"
    run = run_ps(
        tmp_path,
        _open("streng", missing, root=root) + _open("mag", missing, root=root, extra="-MagOntbreken"),
    )
    assert run["streng"]["soort"] == "onleesbaar" and run["streng"]["detail"] == "afwezig"
    assert run["mag"]["ontbreekt"] is True and run["mag"]["soort"] is None
    audit(run)


def test_a_directory_where_a_file_is_expected_is_no_regular_file(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(tmp_path, _open("map", root / "P" / "C", root=root))
    assert run["map"]["soort"] == "geen_gewoon_bestand"
    audit(run)


def test_the_refusal_names_no_path_and_the_debug_log_only_with_nsmcp_debug(tmp_path):
    root, outside = _tree(tmp_path)
    _junction(root / "J", outside)
    body = _open("weg", root / "J" / "leaf.txt", root=root)
    quiet = run_ps(tmp_path, body)
    assert quiet["weg"]["reden"] == localpath.REASONS["koppeling"]
    assert str(tmp_path) not in quiet["weg"]["reden"]
    assert str(tmp_path) not in quiet.stderr and "geweigerd" not in quiet.stderr
    loud = run_ps(tmp_path, body, env={"NSMCP_DEBUG": "1"})
    lines = [line for line in loud.stderr.splitlines() if line.startswith("[nsmcp-pad] geweigerd")]
    assert len(lines) == 1 and "soort=koppeling" in lines[0] and str(root) in lines[0]


# ---------------------------------------------------------------------------
# Links and reparse points
# ---------------------------------------------------------------------------


def test_junction_inside_the_root_is_a_link_and_nothing_below_it_is_opened(tmp_path):
    root, outside = _tree(tmp_path)
    _junction(root / "J", outside)
    run = run_ps(tmp_path, _open("weg", root / "J" / "leaf.txt", root=root))
    assert run["weg"]["soort"] == "koppeling"
    names = audit(run)
    assert names[-1] == "J" and "leaf.txt" not in names
    assert run.calls("DeviceIoControl") == 0, "binnen de wortel wordt een koppeling niet gelezen of gevolgd"


def test_the_root_itself_being_a_junction_is_refused(tmp_path):
    _, outside = _tree(tmp_path)
    linked_root = tmp_path / "wortel-koppeling"
    _junction(linked_root, outside)
    run = run_ps(tmp_path, _open("weg", linked_root / "leaf.txt", root=linked_root))
    assert run["weg"]["soort"] == "koppeling"
    assert audit(run)[-1] == "wortel-koppeling"


def test_a_junction_in_the_place_of_a_file_is_a_link_not_a_wrong_type(tmp_path):
    root, outside = _tree(tmp_path)
    _junction(root / "P" / "plek.json", outside)
    run = run_ps(tmp_path, _open("weg", root / "P" / "plek.json", root=root))
    assert run["weg"]["soort"] == "koppeling"
    leaf_open = [record for record in run.opens if record["naam"] == "plek.json"][0]
    assert leaf_open["opties"] & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE) == 0
    audit(run)


def test_a_junction_above_the_root_is_followed_to_its_local_target(tmp_path):
    root, _ = _tree(tmp_path)
    above = tmp_path / "boven"
    _junction(above, root.parent)
    via = above / "wortel" / "P" / "C" / "leaf.txt"
    run = run_ps(tmp_path, _open("wortel", via, root=above / "wortel") + _open("zonder", via))
    assert run["wortel"]["data"] == "binnen" and run["zonder"]["data"] == "binnen"
    assert run["wortel"]["pad"] == str(root / "P" / "C" / "leaf.txt"), "het pad is de plek waar de wandeling uitkwam"
    audit(run)
    assert run.calls("DeviceIoControl") == 2


def test_a_file_symlink_inside_the_root_is_a_link(tmp_path):
    root, outside = _tree(tmp_path)
    _symlink(root / "P" / "s.txt", str(outside / "leaf.txt"), directory=False)
    run = run_ps(tmp_path, _open("weg", root / "P" / "s.txt", root=root))
    assert run["weg"]["soort"] == "koppeling"
    assert "tag 0xA000000C" in run["weg"]["detail"]
    audit(run)


def test_a_symlink_above_the_root_to_a_share_is_refused_before_anything_of_it_opens(tmp_path):
    above = tmp_path / "gedeeld"
    _symlink(above, r"\\192.0.2.10\x", directory=True)
    run = run_ps(tmp_path, _open("weg", above / "export" / "x.json"))
    assert run["weg"]["soort"] == "netwerkpad"
    assert run["weg"]["gevolgd"] is True
    names = audit(run)
    assert names[-1] == "gedeeld"
    assert not any("192.0.2.10" in name for name in names)
    assert run.calls("GetDriveTypeW") == 1, "het doel kwam niet verder dan de spellingstap"


def test_a_relative_symlink_above_the_root_is_composed_against_its_parent(tmp_path):
    _tree(tmp_path)
    (tmp_path / "a").mkdir()
    _symlink(tmp_path / "a" / "terug", r"..\wortel", directory=True)
    run = run_ps(tmp_path, _open("lees", tmp_path / "a" / "terug" / "P" / "C" / "leaf.txt"))
    assert run["lees"]["data"] == "binnen"
    audit(run)


def test_more_links_than_the_limit_is_refused(tmp_path):
    target = tmp_path / "doel"
    target.mkdir()
    (target / "x.txt").write_text("x", encoding="ascii")
    previous = target
    for index in range(localpath.LINK_LIMIT + 1):
        link = tmp_path / f"j{index}"
        _junction(link, previous)
        previous = link
    just_enough = tmp_path / f"j{localpath.LINK_LIMIT - 1}"
    run = run_ps(tmp_path, _open("te_veel", previous / "x.txt") + _open("net", just_enough / "x.txt"))
    assert run["te_veel"]["soort"] == "te_veel_koppelingen"
    assert run["net"]["data"] == "x"
    audit(run)


def test_a_cloud_placeholder_is_a_reparse_point_inside_and_above_the_root(tmp_path):
    root, _ = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"
    run = run_ps(
        tmp_path,
        "[GjkLokaalPad.Naad]::Tag['P'] = [uint32]2415943706\n"
        + _open("binnen", leaf, root=root)
        + _open("boven", leaf),
    )
    assert run["binnen"]["soort"] == "herparseerpunt"
    assert run["boven"]["soort"] == "herparseerpunt"
    assert run.calls("DeviceIoControl") == 0
    audit(run)


def test_an_alternate_data_stream_is_refused_before_any_open(tmp_path):
    (tmp_path / "objects").mkdir()
    (tmp_path / "objects" / "x.json").write_text("{}", encoding="ascii")
    stream = str(tmp_path / "objects" / "x.json") + ":zijstroom"
    run = run_ps(tmp_path, _open("stroom", stream, root=tmp_path) + _open("zonder", stream))
    assert run["stroom"]["soort"] == "stroom" and run["zonder"]["soort"] == "stroom"
    assert run.calls("NtCreateFile") == 0


# ---------------------------------------------------------------------------
# The volume: network drive, device targets
# ---------------------------------------------------------------------------


def test_a_network_drive_letter_is_refused_without_any_open(tmp_path):
    run = run_ps(
        tmp_path,
        "[GjkLokaalPad.Naad]::Stationstype = [Func[string,uint32]]{ param($w) [uint32]4 }\n"
        + _open("weg", tmp_path / "x.json"),
    )
    assert run["weg"]["soort"] == "netwerkstation"
    assert run.calls("NtCreateFile") == 0


@pytest.mark.parametrize(
    ("targets", "soort"),
    [
        (["\\Device\\Mup\\;LanmanRedirector\\server\\share"], "netwerkstation"),
        (["\\Device\\LanmanRedirector\\;Z:0\\server\\share"], "netwerkstation"),
        (["\\??\\UNC\\server\\share"], "netwerkstation"),
        (["\\??\\C:\\subst-doel"], "apparaatpad"),
        (["\\Device\\HarddiskVolumeShadowCopy3"], "apparaatpad"),
        (["\\Device\\HarddiskVolume3", "\\Device\\HarddiskVolume4"], "apparaatpad"),
        ([], "apparaatpad"),
    ],
    ids=["mup", "redirector", "unc", "subst", "schaduwkopie", "twee-doelen", "geen-doel"],
)
def test_a_drive_letter_that_is_not_one_local_volume_is_refused_without_any_open(tmp_path, targets, soort):
    array = "@(" + ", ".join(ps_text(t) for t in targets) + ")"
    run = run_ps(
        tmp_path,
        f"$doelen = [string[]]{array}\n"
        "[GjkLokaalPad.Naad]::Apparaatdoel = [Func[string,string[]]]{ param($n) ,$doelen }.GetNewClosure()\n"
        + _open("weg", tmp_path / "x.json"),
    )
    assert run["weg"]["soort"] == soort
    assert run.calls("NtCreateFile") == 0


@pytest.mark.parametrize("drive_type", [0, 1, 2, 5, 6])
def test_a_drive_that_is_not_a_fixed_disk_is_a_device(tmp_path, drive_type):
    run = run_ps(
        tmp_path,
        f"[GjkLokaalPad.Naad]::Stationstype = [Func[string,uint32]]{{ param($w) [uint32]{drive_type} }}\n"
        + _open("weg", tmp_path / "x.json"),
    )
    assert run["weg"]["soort"] == "apparaatpad"
    assert run.calls("NtCreateFile") == 0


def test_a_network_status_mid_walk_is_a_network_path_with_a_defect_line(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(
        tmp_path,
        "[GjkLokaalPad.Naad]::Status = [Func[string,uint32]]{ param($n) if ($n -eq 'C') { [uint32]3221225662 } else { [uint32]0 } }\n"
        + _open("weg", root / "P" / "C" / "leaf.txt", root=root),
    )
    assert run["weg"]["soort"] == "netwerkpad"
    assert localpath.DEFECT_LINE in run.stderr
    audit(run)


def test_a_status_nobody_named_is_unreadable_and_closes_the_chain(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(
        tmp_path,
        "[GjkLokaalPad.Naad]::Status = [Func[string,uint32]]{ param($n) if ($n -eq 'C') { [uint32]3221227929 } else { [uint32]0 } }\n"
        + _open("weg", root / "P" / "C" / "leaf.txt", root=root),
    )
    assert run["weg"]["soort"] == "onleesbaar"
    audit(run)


@pytest.mark.parametrize(
    ("status", "soort"),
    [
        (0xC0000034, "onleesbaar"),
        (0xC000003A, "onleesbaar"),
        (0xC0000022, "onleesbaar"),
        (0xC0000043, "onleesbaar"),
        (0xC0000103, "geen_gewoon_bestand"),
        (0xC00000BA, "geen_gewoon_bestand"),
        (0x00000104, "koppeling"),
        (0x8000002D, "koppeling"),
        (0xC0000280, "koppeling"),
        (0xC0000281, "koppeling"),
        (0xC00000CC, "netwerkpad"),
        (0xC000CF02, "onleesbaar"),
    ],
)
def test_every_status_has_the_kind_of_the_python_table(tmp_path, status, soort):
    root, _ = _tree(tmp_path)
    run = run_ps(
        tmp_path,
        f"[GjkLokaalPad.Naad]::Status = [Func[string,uint32]]{{ param($n) if ($n -eq 'P') {{ [uint32]{status} }} else {{ [uint32]0 }} }}\n"
        + _open("weg", root / "P" / "C" / "leaf.txt", root=root),
    )
    assert run["weg"]["soort"] == soort
    assert localpath._status_refusal(status, "x", allow_missing=False).soort == soort
    audit(run)


# ---------------------------------------------------------------------------
# Containment is structural
# ---------------------------------------------------------------------------


def test_a_different_case_of_the_root_text_is_outside_it(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(tmp_path, _open("weg", tmp_path / "WORTEL" / "P" / "C" / "leaf.txt", root=root))
    assert run["weg"]["soort"] == "buiten_wortel"
    assert run.calls("NtCreateFile") == 0


def test_a_dot_dot_out_of_the_root_is_refused_before_any_open(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(tmp_path, _open("weg", str(root) + "\\..\\buiten\\leaf.txt", root=root))
    assert run["weg"]["soort"] in ("onleesbaar", "buiten_wortel")
    assert run.calls("NtCreateFile") == 0


def test_a_sibling_of_the_root_is_outside_it(tmp_path):
    root, outside = _tree(tmp_path)
    run = run_ps(tmp_path, _open("weg", outside / "leaf.txt", root=root))
    assert run["weg"]["soort"] == "buiten_wortel"
    assert run.calls("NtCreateFile") == 0


# ---------------------------------------------------------------------------
# Races, with real junctions, swapped through the seam between two components
# ---------------------------------------------------------------------------


def _swap_before(component: str, swap: str) -> str:
    """PowerShell that runs `swap` once, just before `component` is opened."""
    return (
        "$script:gewisseld = $false\n"
        "[GjkLokaalPad.Naad]::Tussen = [Action[int,string]]{ param($i, $n)\n"
        f"    if ($n -eq {ps_text(component)} -and -not $script:gewisseld) {{ $script:gewisseld = $true\n"
        f"        {swap}\n"
        "    } }\n"
    )


def _swap_for_junction(directory: Path, outside: Path) -> str:
    return (
        f"Rename-Item -LiteralPath {ps_text(directory)} -NewName {ps_text(directory.name + '-weg')}; "
        f"$null = New-Item -ItemType Junction -Path {ps_text(directory)} -Target {ps_text(outside)}"
    )


def test_ancestor_swap_never_opens_outside_the_root(tmp_path):
    """Race (a): while the walk holds `P`, a second actor replaces the
    ancestor `C` (inside the root, not yet opened) by a junction to a
    directory outside the root that holds a plain `leaf.txt`."""
    root, outside = _tree(tmp_path)
    run = run_ps(
        tmp_path,
        _swap_before("C", _swap_for_junction(root / "P" / "C", outside))
        + _open("weg", root / "P" / "C" / "leaf.txt", root=root),
    )
    assert run["weg"]["soort"] == "koppeling"
    assert "tag 0xA0000003" in run["weg"]["detail"], "de geopende C is de koppeling zelf, niet haar doel"
    names = audit(run)
    assert names[-1] == "C"
    assert "leaf.txt" not in names, "het bestand buiten de wortel had geen open-poging"
    assert os.lstat(root / "P" / "C").st_file_attributes & 0x400, "de wissel is echt gebeurd"


def test_root_swap_never_opens_outside_the_root(tmp_path):
    """Race (b): the root itself is replaced by a junction just before the walk opens it."""
    root, outside = _tree(tmp_path)
    run = run_ps(
        tmp_path,
        _swap_before("wortel", _swap_for_junction(root, outside))
        + _open("weg", root / "P" / "C" / "leaf.txt", root=root),
    )
    assert run["weg"]["soort"] == "koppeling"
    names = audit(run)
    assert names[-1] == "wortel"
    assert not {"P", "C", "leaf.txt"} & set(names)


def test_leaf_swap_opens_the_link_itself_and_never_its_target(tmp_path):
    """Race (c): the leaf is replaced by a junction to a directory outside the root."""
    root, outside = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"
    swap = (
        f"Rename-Item -LiteralPath {ps_text(leaf)} -NewName 'leaf-weg.txt'; "
        f"$null = New-Item -ItemType Junction -Path {ps_text(leaf)} -Target {ps_text(outside)}"
    )
    run = run_ps(tmp_path, _swap_before("leaf.txt", swap) + _open("weg", leaf, root=root))
    assert run["weg"]["soort"] == "koppeling"
    assert "tag 0xA0000003" in run["weg"]["detail"]
    names = audit(run)
    assert names[-1] == "leaf.txt"
    assert run["weg"]["data"] is None


def test_a_held_chain_and_leaf_cannot_be_renamed_deleted_or_rewritten(tmp_path):
    """The hold that race (d) rests on: while the stream is open, no held
    directory can be renamed or deleted and a bundle-class leaf cannot be
    written, replaced or deleted; after Close-GjkLokaalBestand all of it can."""
    root, _ = _tree(tmp_path)
    leaf = root / "P" / "C" / "leaf.txt"
    body = f"""
$s = Open-GjkLokaalBestand -Pad {ps_text(leaf)} -Wortel {ps_text(root)} -Klasse bundel
$pogingen = [ordered]@{{}}
foreach ($map in @({ps_text(root / "P")}, {ps_text(root / "P" / "C")}, {ps_text(root)})) {{
    try {{ Rename-Item -LiteralPath $map -NewName ((Split-Path -Leaf $map) + '-x'); $pogingen['hernoem ' + $map] = 'gelukt' }}
    catch {{ $pogingen['hernoem ' + $map] = 'geweigerd' }}
}}
try {{ [System.IO.File]::WriteAllText({ps_text(leaf)}, 'ander'); $pogingen['schrijf'] = 'gelukt' }} catch {{ $pogingen['schrijf'] = 'geweigerd' }}
try {{ [System.IO.File]::Delete({ps_text(leaf)}); $pogingen['verwijder'] = 'gelukt' }} catch {{ $pogingen['verwijder'] = 'geweigerd' }}
try {{ [System.IO.File]::Move({ps_text(leaf)}, {ps_text(root / "P" / "C" / "weg.txt")}); $pogingen['verplaats'] = 'gelukt' }} catch {{ $pogingen['verplaats'] = 'geweigerd' }}
$lezer = [System.IO.File]::Open({ps_text(leaf)}, 'Open', 'Read', 'Read'); $pogingen['lezen op naam'] = 'gelukt'; $lezer.Dispose()
Notitie sha (Get-GjkLokaleSha256 -Stroom $s)
Close-GjkLokaalBestand $s
Notitie gesloten $s.Gesloten
Notitie pogingen $pogingen
Rename-Item -LiteralPath {ps_text(root / "P")} -NewName 'P-na'
Notitie na 'hernoemd'
"""
    run = run_ps(tmp_path, body)
    assert set(run["pogingen"].values()) == {"geweigerd", "gelukt"}
    assert [k for k, v in run["pogingen"].items() if v == "gelukt"] == ["lezen op naam"], run["pogingen"]
    import hashlib

    assert run["sha"] == hashlib.sha256(b"binnen").hexdigest()
    assert run["gesloten"] is True and run["na"] == "hernoemd"
    audit(run)


def test_a_ledger_class_leaf_still_takes_an_append_while_it_is_held(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("een\n", encoding="ascii")
    body = f"""
$s = Open-GjkLokaalBestand -Pad {ps_text(ledger)} -Wortel {ps_text(tmp_path)} -Klasse ledger
$w = [System.IO.File]::Open({ps_text(ledger)}, 'Append', 'Write', 'ReadWrite'); $b = [byte[]][char[]]"twee`n"; $w.Write($b, 0, $b.Length); $w.Dispose()
Notitie inhoud ([System.Text.Encoding]::ASCII.GetString((Read-GjkLokaleBytes -Stroom $s -Max 100)))
Close-GjkLokaalBestand $s
"""
    run = run_ps(tmp_path, body)
    assert run["inhoud"].replace("\r", "") == "een\ntwee\n"
    audit(run)


def test_an_ancestor_with_only_the_traverse_right_is_walked_and_still_held(tmp_path):
    root, _ = _tree(tmp_path)
    user = os.environ["USERNAME"]
    hardened = root / "P"
    denied = subprocess.run(["icacls", str(hardened), "/deny", f"{user}:(RD)"], capture_output=True, text=True)
    assert denied.returncode == 0, denied.stdout + denied.stderr
    try:
        body = f"""
$s = Open-GjkLokaalBestand -Pad {ps_text(root / "P" / "C" / "leaf.txt")} -Wortel {ps_text(root)} -Klasse bundel
Notitie inhoud ([System.Text.Encoding]::ASCII.GetString((Read-GjkLokaleBytes -Stroom $s -Max 100)))
try {{ $null = Get-ChildItem -LiteralPath {ps_text(hardened)}; Notitie lijst 'gelukt' }} catch {{ Notitie lijst 'geweigerd' }}
try {{ Rename-Item -LiteralPath {ps_text(hardened)} -NewName 'P-x'; Notitie hernoem 'gelukt' }} catch {{ Notitie hernoem 'geweigerd' }}
Close-GjkLokaalBestand $s
"""
        run = run_ps(tmp_path, body)
    finally:
        restored = subprocess.run(["icacls", str(hardened), "/remove:d", user], capture_output=True, text=True)
        assert restored.returncode == 0, restored.stdout + restored.stderr
    assert run["inhoud"] == "binnen"
    assert run["lijst"] == "geweigerd" and run["hernoem"] == "geweigerd"
    assert {record["toegang"] for record in run.opens if record["naam"] in ("P", "C")} == {DIR_ACCESS}
    audit(run)


def test_exactly_one_of_root_or_no_root_is_required(tmp_path):
    body = (
        "try { $null = Open-GjkLokaalBestand -Pad 'C:\\x' -Klasse bundel; Notitie geen 'gelukt' } "
        "catch { Notitie geen $_.Exception.GetType().Name }\n"
        "try { $null = Open-GjkLokaalBestand -Pad 'C:\\x' -Wortel 'C:\\' -ZonderWortel -Klasse bundel; Notitie beide 'gelukt' } "
        "catch { Notitie beide $_.Exception.GetType().Name }\n"
    )
    run = run_ps(tmp_path, body)
    assert run["geen"] == "ArgumentException" and run["beide"] == "ArgumentException"
    assert run.calls("NtCreateFile") == 0


# ---------------------------------------------------------------------------
# A second name on the disk, and listing a directory on its held handle
# ---------------------------------------------------------------------------


def test_a_hardlink_inside_the_root_is_refused_and_read_without_a_root(tmp_path):
    """B.2 step 6 (revision 3), as `localpath`: a file outside the root with a
    second name inside it is refused before a byte is read; the same file
    without a root (a configured path) is read."""
    root = tmp_path / "wortel"
    root.mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    (outside / "geheim.txt").write_bytes(b"GEHEIM")
    os.link(outside / "geheim.txt", root / "tweede-naam.txt")
    run = run_ps(
        tmp_path,
        _open("binnen", root / "tweede-naam.txt", root=root) + _open("zonder", root / "tweede-naam.txt"),
    )
    assert run["binnen"]["soort"] == "hardlink"
    assert run["binnen"]["reden"] == localpath.REASONS["hardlink"]
    assert run["binnen"]["data"] is None
    assert run["zonder"]["data"] == "GEHEIM"
    audit(run)


def _names(name: str, path, extra: str = "") -> str:
    return (
        "$sw = [System.Diagnostics.Stopwatch]::StartNew()\n"
        f"try {{ $n = @(Get-GjkLokaleNamen -Map {ps_text(path)} {extra}); "
        f"Notitie {ps_text(name)} ([ordered]@{{ namen = @($n); soort = $null; ms = $sw.Elapsed.TotalMilliseconds }}) }}\n"
        "catch { if ($_.Exception -isnot [GjkLokaalPad.PadGeweigerd]) { throw }; "
        f"Notitie {ps_text(name)} ([ordered]@{{ namen = $null; soort = $_.Exception.Soort; ms = $sw.Elapsed.TotalMilliseconds }}) }}\n"
    )


def test_a_directory_is_listed_on_its_held_handle_and_nothing_in_it_is_opened(tmp_path):
    root, _ = _tree(tmp_path)
    (root / "P" / "een.tgz").write_bytes(b"1")
    (root / "P" / "twee.tgz").write_bytes(b"2")
    run = run_ps(tmp_path, _names("lijst", root / "P"))
    assert sorted(run["lijst"]["namen"]) == ["C", "een.tgz", "twee.tgz"]
    assert run.calls("NtQueryDirectoryFile") >= 1
    names = audit(run)
    assert names[-1] == "P", "alleen de map zelf is geopend, niets erin"
    listed = [record for record in run.opens if record["naam"] == "P"][0]
    assert listed["toegang"] == DIR_ACCESS | 0x0001, "lijstrecht alleen op de gevraagde map"


def test_a_missing_directory_lists_nothing_only_when_absence_is_allowed(tmp_path):
    root, _ = _tree(tmp_path)
    run = run_ps(tmp_path, _names("mag", root / "weg", "-MagOntbreken") + _names("streng", root / "weg"))
    assert run["mag"]["namen"] == [] and run["mag"]["soort"] is None
    assert run["streng"]["soort"] == "onleesbaar"
    audit(run)


def test_a_directory_that_is_itself_a_junction_is_refused_without_listing(tmp_path):
    _, outside = _tree(tmp_path)
    gekoppeld = tmp_path / "map-koppeling"
    _junction(gekoppeld, outside)
    run = run_ps(tmp_path, _names("weg", gekoppeld))
    assert run["weg"]["soort"] == "koppeling"
    assert run.calls("NtQueryDirectoryFile") == 0
    audit(run)


def test_listing_below_a_link_to_a_share_never_contacts_the_network(tmp_path):
    """I-1 of the red review of this part, the PowerShell side of the
    measurement of part 2: `Get-ChildItem` on a map below a symbolic link to
    `\\\\192.0.2.10\\x` let the redirector go to that host before anything
    refused. The listing on the walk refuses at the spelling step of the link
    target: `netwerkpad`, no open naming the share, no listing, well under the
    100 ms a network contact never makes."""
    above = tmp_path / "gedeeld"
    _symlink(above, r"\\192.0.2.10\x", directory=True)
    run = run_ps(tmp_path, _names("weg", above / "firmware", "-MagOntbreken"))
    assert run["weg"]["soort"] == "netwerkpad"
    assert run.calls("NtQueryDirectoryFile") == 0
    assert run.calls("GetDriveTypeW") == 1, "het doel kwam niet verder dan de spellingstap"
    names = audit(run)
    assert not any("192.0.2.10" in name or "mup" in name.lower() for name in names)
    assert run["weg"]["ms"] < 100, run["weg"]["ms"]
