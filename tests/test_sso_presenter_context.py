"""The real presenter must show and require approval context."""

import json

import pytest
from test_sso_presenter_windows import (
    IDENTITY,
    PLANTED_CODE,
    SCRIPTS_DIR,
    _load_module,
    _request_line,
    _run,
)

from nsmcp import code_channel


def _context_payload(**overrides):
    payload = json.loads(_request_line())
    payload.update(
        gereedschap="onderhoud_upgrade_fase",
        doel="[TARGET] node-a",
        fase="R3",
        voorstel="Installeer de bevestigde build op node-a.",
    )
    payload.update(overrides)
    return payload


def _real_channel(tmp_path):
    window = tmp_path / "window.txt"
    wrapper = tmp_path / "context_presenter.py"
    wrapper.write_text(
        "import sys\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(SCRIPTS_DIR)!r})\n"
        "import sso_presenter_windows as sp\n"
        "def show(text):\n"
        f"    Path({str(window)!r}).write_text(text, encoding='utf-8')\n"
        "    return sp.IDOK\n"
        "sp._show_window = show\n"
        f"sp._get_identity = lambda: {IDENTITY!r}\n"
        "sys.exit(sp.main())\n",
        encoding="utf-8",
    )
    channel = code_channel.SsoCodeChannel(wrapper, "https://voorbeeld.invalid/goedkeuren", 15)
    return channel, window


def test_phase_context_reaches_main_window_from_real_channel(tmp_path):
    channel, window = _real_channel(tmp_path)
    channel(
        "onderhoud_upgrade_fase",
        "[TARGET] node-a",
        {"fase": "R3"},
        PLANTED_CODE,
        "Installeer de bevestigde build op node-a.",
        "B",
        "lab",
    )
    text = window.read_text(encoding="utf-8")
    assert "doel: [TARGET] node-a" in text
    assert "fase: R3" in text
    assert "Installeer de bevestigde build op node-a." in text
    assert text.index("fase: R3") < text.index("bevestigingscode:")
    assert text.index("doel:") < text.index("bevestigingscode:")
    assert channel.bevestiger_for(PLANTED_CODE) == IDENTITY


@pytest.mark.parametrize("length", [200, 201, 256, 257])
def test_real_channel_keeps_complete_target_or_refuses(length, tmp_path):
    channel, window = _real_channel(tmp_path)
    target = "x" * (length - 4) + "TAIL"
    if length <= 256:
        channel("onderhoud_upgrade_fase", target, {"fase": "R3"}, PLANTED_CODE, "Een voorstel.", "B", "lab")
        assert f"doel: {target}\n" in window.read_text(encoding="utf-8")
        assert channel.bevestiger_for(PLANTED_CODE) == IDENTITY
    else:
        with pytest.raises(code_channel.CodeChannelError):
            channel("onderhoud_upgrade_fase", target, {"fase": "R3"}, PLANTED_CODE, "Een voorstel.", "B", "lab")
        assert not window.exists()
        assert channel.bevestiger_for(PLANTED_CODE) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", "node-a\n"),
        ("target", "node-a\u2028"),
        ("target", []),
        ("phase", "R3\n"),
        ("phase", "R3\u2028"),
        ("phase", None),
        ("tool", "onderhoud_upgrade_fase\n"),
        ("tool", []),
    ],
)
def test_real_channel_refuses_invalid_identity_context(field, value, tmp_path):
    channel, window = _real_channel(tmp_path)
    context = {"target": "node-a", "phase": "R3", "tool": "onderhoud_upgrade_fase"}
    context[field] = value
    with pytest.raises(code_channel.CodeChannelError):
        channel(
            context["tool"], context["target"], {"fase": context["phase"]}, PLANTED_CODE, "Een voorstel.", "B", "lab"
        )
    assert not window.exists()
    assert channel.bevestiger_for(PLANTED_CODE) is None


@pytest.mark.parametrize("field", ["doel", "sectie", "fase", "voorstel", "gereedschap"])
@pytest.mark.parametrize("mode", ["missing", "blank", "wrong_type", "control", "oversized"])
def test_invalid_phase_context_opens_no_window_and_delivers_nothing(field, mode):
    module = _load_module()
    payload = _context_payload()
    values = {"blank": "", "wrong_type": [], "control": "bad\u2028context", "oversized": "x" * 4097}
    if mode == "missing":
        payload.pop(field)
    else:
        payload[field] = values[mode]
    windows = []
    result, out, err = _run(
        module,
        json.dumps(payload) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == 1
    assert not windows
    assert not out
    assert PLANTED_CODE not in err
    assert "bad" not in err


@pytest.mark.parametrize("phase", ["R7", "r3", " R3", "R3 ", "install"])
def test_phase_name_must_be_an_actual_upgrade_phase(phase):
    module = _load_module()
    windows = []
    result, out, _ = _run(
        module,
        json.dumps(_context_payload(fase=phase)) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == 1 and not windows and not out


def test_the_window_shows_the_section_on_its_own_line_under_the_target():
    """Two sections that allow the same action get the same label from the
    write script. The window names the section the code is bound to on a
    line of its own, directly under the label, so two such requests differ
    before the code is handed over."""
    module = _load_module()
    vensters = {}
    for sectie in ("lab-a", "lab-b"):
        windows = []
        result, _, _ = _run(
            module,
            json.dumps(_context_payload(sectie=sectie)) + "\n",
            show_window=lambda text, opvang=windows: opvang.append(text) or module.IDOK,
            get_identity=lambda: IDENTITY,
        )
        assert result == 0
        vensters[sectie] = windows[0]
    assert vensters["lab-a"] != vensters["lab-b"]
    for sectie, tekst in vensters.items():
        regels = tekst.splitlines()
        assert regels[regels.index("doel: [TARGET] node-a") + 1] == f"sectie: {sectie}"
        assert tekst.index(f"sectie: {sectie}") < tekst.index("bevestigingscode:")


@pytest.mark.parametrize("length,expected_exit", [(256, 0), (257, 1)])
def test_section_is_fully_shown_or_rejected_instead_of_silently_cut(length, expected_exit):
    module = _load_module()
    windows = []
    sectie = "x" * (length - 4) + "TAIL"
    result, out, _ = _run(
        module,
        json.dumps(_context_payload(sectie=sectie)) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == expected_exit
    if expected_exit == 0:
        assert f"sectie: {sectie}\n" in windows[0]
    else:
        assert not windows and not out


def test_non_phase_action_keeps_its_context_without_inventing_a_phase():
    module = _load_module()
    windows = []
    payload = _context_payload(gereedschap="certificaat_vervangen", fase="")
    result, _, _ = _run(
        module,
        json.dumps(payload) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == 0
    assert "doel: [TARGET] node-a" in windows[0]
    assert "fase:" not in windows[0]


@pytest.mark.parametrize("phase", ["R0", "R6"])
def test_long_proposal_is_bounded_but_target_phase_and_code_remain_visible(phase):
    module = _load_module()
    windows = []
    proposal = "Een leesbare toelichting. " * 150
    result, _, _ = _run(
        module,
        json.dumps(_context_payload(fase=phase, voorstel=proposal)) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == 0
    text = windows[0]
    assert "doel: [TARGET] node-a" in text and f"fase: {phase}" in text
    assert "Een leesbare toelichting." in text and PLANTED_CODE in text
    assert len(text) < 2000
    assert "..." in text


def test_every_argument_line_is_shown_apart_from_the_bounded_proposal(tmp_path):
    """The confirmer sees every action argument the code is bound to - the
    snapshot reference and the acceptance switches of an R0 proposal
    included - each on a line of its own above the code. They are shown
    apart from the proposal prose, so cutting a long proposal at its display
    bound can no longer take them off the screen."""
    channel, window = _real_channel(tmp_path)
    arguments = {
        "fase": "R0",
        "run": "",
        "snapshotverwijzing": "snap-x",
        "doelbuild_geaccepteerd": False,
        "drift_geaccepteerd": False,
        "oude_buildbomen_opruimen": False,
        "standalone_geaccepteerd": True,
    }
    proposal = "Een leesbare toelichting. " * 150
    channel("onderhoud_upgrade_fase", "[TARGET] node-a", arguments, PLANTED_CODE, proposal, "B", "lab")
    text = window.read_text(encoding="utf-8")
    for line in (
        "snapshotverwijzing: snap-x",
        "standalone_geaccepteerd: True",
        "drift_geaccepteerd: False",
        "doelbuild_geaccepteerd: False",
        "oude_buildbomen_opruimen: False",
    ):
        assert f"\n  {line}\n" in text, line
        assert text.index(line) < text.index("Een leesbare toelichting.")
        assert text.index(line) < text.index("bevestigingscode:")
    assert "..." in text
    assert channel.bevestiger_for(PLANTED_CODE) == IDENTITY


@pytest.mark.parametrize(
    "value",
    [
        None,
        "snapshotverwijzing: snap-x",
        [1],
        ["snapshotverwijzing: snap\u2028x"],
        ["x" * 4097],
        ["fase: R3"] * 33,
    ],
    ids=["missing", "not-a-list", "not-text", "control", "oversized", "too-many"],
)
def test_an_unusable_argument_list_opens_no_window_and_delivers_nothing(value):
    module = _load_module()
    payload = _context_payload()
    if value is None:
        payload.pop("argumenten")
    else:
        payload["argumenten"] = value
    windows = []
    result, out, err = _run(
        module,
        json.dumps(payload) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == 1
    assert not windows
    assert not out
    assert PLANTED_CODE not in err
    assert "snap" not in err


@pytest.mark.parametrize("length,expected_exit", [(256, 0), (257, 1)])
def test_target_is_fully_shown_or_rejected_instead_of_silently_cut(length, expected_exit):
    module = _load_module()
    windows = []
    target = "x" * (length - 4) + "TAIL"
    result, out, _ = _run(
        module,
        json.dumps(_context_payload(doel=target)) + "\n",
        show_window=lambda text: windows.append(text) or module.IDOK,
        get_identity=lambda: IDENTITY,
    )
    assert result == expected_exit
    if expected_exit == 0:
        assert f"doel: {target}\n" in windows[0]
    else:
        assert not windows and not out
