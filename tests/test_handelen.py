"""The four actions are a thin, hard-edged wrapper around the reviewed
PowerShell write tool. What is tested here is the EDGE: which objects may be
touched, how the argument list is built, that a preview always carries
-WatIs, and how the script's output is read back."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from nsmcp.handelen import (
    ActionError,
    Allowlist,
    build_arguments,
    perform,
    validate,
)

SCRIPT = Path(r"C:\demo\film\Invoke-GjkLabWrite.ps1")
FIXTURES = Path(r"C:\demo\certs")

# The demo objects that used to be the module constant ALLOWED, now where
# they belong: in a list this test HANDS to the code instead of one the code
# knows by heart. ONE list for the whole file - what is measured below is the
# edge (grammar, denylist, argument building, output reading), not the list.
# That the list itself arrives correctly is measured in tests/test_start.py,
# where it comes out of a real configuration document.
DOEL = "lab"
DEMO = Allowlist(
    per_target={
        DOEL: {
            "certificaat_klaarzetten": {"certnaam": ("gjk-zaakportaal-2027",)},
            "certificaat_vervangen": {
                "dienst": ("lb_vs_gjk_zaakportaal_443",),
                "nieuwcert": ("gjk-zaakportaal-2027", "gjk-zaakportaal-2026"),
            },
            "dienst_lid_uitschakelen": {
                "dienst": ("gjkdemo_sg_proefdienst",),
                "lid": ("gjkdemo_web01", "gjkdemo_web02"),
            },
            "dienst_lid_inschakelen": {
                "dienst": ("gjkdemo_sg_proefdienst",),
                "lid": ("gjkdemo_web01", "gjkdemo_web02"),
            },
        }
    }
)


@pytest.mark.parametrize(
    "tool, arguments, fragment",
    [
        ("dienst_lid_uitschakelen", {"dienst": "sg_portaal", "lid": "gjkdemo_web01"}, "allowlist"),
        ("dienst_lid_uitschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": "backend2"}, "allowlist"),
        ("dienst_lid_uitschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": "GJKDEMO_WEB01"}, "allowlist"),
        (
            "certificaat_vervangen",
            {"dienst": "lb_vs_gjk_statuspagina_443", "nieuwcert": "gjk-zaakportaal-2027"},
            "allowlist",
        ),
        ("certificaat_vervangen", {"dienst": "lb_vs_gjk_zaakportaal_443", "nieuwcert": "CERT-009"}, "allowlist"),
        ("certificaat_klaarzetten", {"certnaam": "gjk-zaakportaal-2026"}, "allowlist"),
        (
            "certificaat_vervangen",
            {"dienst": "../lbvserver/victim", "nieuwcert": "gjk-zaakportaal-2027"},
            "naamgrammatica",
        ),
        (
            "certificaat_vervangen",
            {"dienst": "nshttps-127.0.0.1-443", "nieuwcert": "gjk-zaakportaal-2027"},
            "beheerdienst",
        ),
        ("certificaat_klaarzetten", {"certnaam": "ns-server-certificate"}, "appliance-eigen"),
        ("dienst_lid_uitschakelen", {"dienst": "gjkdemo_sg_proefdienst"}, "ontbreekt"),
        (
            "dienst_lid_uitschakelen",
            {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01", "extra": 1},
            "onbekend",
        ),
        ("dienst_lid_uitschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": 7}, "moet tekst zijn"),
        ("onbekende_tool", {}, "onbekende handeling"),
    ],
)
def test_out_of_scope_is_refused(tool, arguments, fragment):
    with pytest.raises(ActionError, match=fragment):
        validate(tool, arguments, target=DOEL, allowlist=DEMO)


def test_validate_normalizes_whitespace_but_not_case():
    clean = validate(
        "dienst_lid_uitschakelen",
        {"dienst": " gjkdemo_sg_proefdienst ", "lid": "gjkdemo_web01"},
        target=DOEL,
        allowlist=DEMO,
    )
    assert clean == {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"}


def test_argument_lists_map_onto_the_powershell_tool():
    common = dict(
        script=SCRIPT,
        fixture_dir=FIXTURES,
        bundle="demo-x",
        target=DOEL,
        allowlist=DEMO,
    )
    assert build_arguments(
        "certificaat_klaarzetten", {"certnaam": "gjk-zaakportaal-2027"}, preview=False, **common
    ) == [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCRIPT),
        "-Actie",
        "stage-cert",
        "-CertNaam",
        "gjk-zaakportaal-2027",
        "-CertBestand",
        str(FIXTURES / "film" / "gjk-zaakportaal-2027.cer"),
        "-SleutelBestand",
        str(FIXTURES / "film" / "gjk-zaakportaal-2027.key"),
        "-Bundel",
        "demo-x",
    ]
    assert build_arguments(
        "certificaat_vervangen",
        {"dienst": "lb_vs_gjk_zaakportaal_443", "nieuwcert": "gjk-zaakportaal-2027"},
        preview=True,
        **common,
    )[6:] == [
        "-Actie",
        "replace-cert",
        "-VirtueleServer",
        "lb_vs_gjk_zaakportaal_443",
        "-NieuwCert",
        "gjk-zaakportaal-2027",
        "-Bundel",
        "demo-x",
        "-WatIs",
    ]
    uit = build_arguments(
        "dienst_lid_uitschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"}, preview=False, **common
    )
    assert uit[6:] == [
        "-Actie",
        "disable-member",
        "-ServiceGroep",
        "gjkdemo_sg_proefdienst",
        "-Server",
        "gjkdemo_web01",
        "-Poort",
        "3389",
        "-Bundel",
        "demo-x",
    ]
    aan = build_arguments(
        "dienst_lid_inschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"}, preview=False, **common
    )
    assert aan[6:] == uit[6:] + ["-Ongedaan"]


def test_preview_always_carries_watis():
    for tool, args in (
        ("certificaat_klaarzetten", {"certnaam": "gjk-zaakportaal-2027"}),
        ("certificaat_vervangen", {"dienst": "lb_vs_gjk_zaakportaal_443", "nieuwcert": "gjk-zaakportaal-2027"}),
        ("dienst_lid_uitschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"}),
        ("dienst_lid_inschakelen", {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"}),
    ):
        assert "-WatIs" in build_arguments(
            tool,
            args,
            script=SCRIPT,
            fixture_dir=FIXTURES,
            target=DOEL,
            allowlist=DEMO,
            preview=True,
            bundle="b",
        )


class Spy:
    def __init__(self, exit_code: int, stdout: str, stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self.reply = (exit_code, stdout, stderr)

    def __call__(self, arguments: list[str], timeout_s: int):
        self.calls.append(list(arguments))
        return self.reply


def test_perform_reads_actie_id_target_and_eindstatus():
    spy = Spy(
        0,
        "[START] actie: disable-member\n[ACTIEID] 20260902-1\n[TARGET] servicegroup/gjkdemo_sg_proefdienst/gjkdemo_web01:3389\n[OK] teruggelezen en bevestigd: lid gjkdemo_web01 disabled\n[EINDSTATUS] actie disable-member uitgevoerd en teruggelezen\n",
    )
    r = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=False,
        bundle="b",
        run=spy,
    )
    assert r.ok is True and r.preview is False
    assert r.actie_id == "20260902-1"
    assert r.target == "servicegroup/gjkdemo_sg_proefdienst/gjkdemo_web01:3389"
    assert r.eindstatus.startswith("actie disable-member uitgevoerd")
    assert len(spy.calls) == 1 and "-WatIs" not in spy.calls[0]


def test_perform_preview_reports_the_plan_without_an_actie_id():
    spy = Spy(
        0,
        "[START] actie: disable-member [WAT-IS, niets wordt gewijzigd]\n[OK] zou doen: servicegroup 'gjkdemo_sg_proefdienst': lid 'gjkdemo_web01:3389' op OUT OF SERVICE zetten\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n",
    )
    r = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=True,
        bundle="b",
        run=spy,
    )
    assert r.ok is True and r.preview is True and r.actie_id is None
    assert "zou doen" in r.text
    assert "-WatIs" in spy.calls[0]


def test_perform_preview_reads_target_when_the_script_reports_it():
    """A -WatIs run's ActionResult.target must reflect the script's own
    [TARGET] marker when present, and stay None when the script (like the
    real one before its own fix) does not report one on a preview."""
    spy_with = Spy(
        0,
        "[OK] zou doen: iets\n[TARGET] servicegroup/gjkdemo_sg_proefdienst/gjkdemo_web01:3389\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n",
    )
    r_with = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=True,
        bundle="b",
        run=spy_with,
    )
    assert r_with.ok is True and r_with.preview is True
    assert r_with.target == "servicegroup/gjkdemo_sg_proefdienst/gjkdemo_web01:3389"

    spy_without = Spy(0, "[OK] zou doen: iets\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n")
    r_without = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=True,
        bundle="b",
        run=spy_without,
    )
    assert r_without.ok is True and r_without.preview is True
    assert r_without.target is None


def test_nonzero_exit_is_a_failure_with_the_script_text():
    spy = Spy(1, "[FOUT] de terugleescontrole klopt NIET\n[EINDSTATUS] ACTIE MISLUKT\n")
    r = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=False,
        bundle="b",
        run=spy,
    )
    assert r.ok is False
    assert "ACTIE MISLUKT" in r.eindstatus


def test_zero_exit_without_actie_id_is_a_failure_not_a_success():
    spy = Spy(0, "[EINDSTATUS] iets vaags\n")
    r = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=False,
        bundle="b",
        run=spy,
    )
    assert r.ok is False
    assert "geen actie-id" in r.text


def test_perform_refuses_before_running_anything_when_out_of_scope():
    spy = Spy(0, "")
    with pytest.raises(ActionError):
        perform(
            "dienst_lid_uitschakelen",
            {"dienst": "sg_portaal", "lid": "gjkdemo_web01"},
            script=SCRIPT,
            fixture_dir=FIXTURES,
            target=DOEL,
            allowlist=DEMO,
            preview=False,
            bundle="b",
            run=spy,
        )
    assert spy.calls == []


def test_timeout_is_a_failure_inside_the_result_contract():
    def slow(arguments, timeout_s):
        raise subprocess.TimeoutExpired(cmd=arguments, timeout=timeout_s, output="[START] actie\n")

    r = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=SCRIPT,
        fixture_dir=FIXTURES,
        target=DOEL,
        allowlist=DEMO,
        preview=False,
        bundle="demo-x",
        run=slow,
    )
    assert r.ok is False and r.actie_id is None
    assert "tijdslimiet" in r.eindstatus
    assert "NIET vastgesteld" in r.text


# ---------------------------------------------------------------------------
# The timeout path, measured against a REAL child PowerShell instead of a
# stub. `subprocess.run(timeout=...)` ends a child with kill() and nothing
# else: no chance for the write script's own `finally` block (compensation in
# reverse order plus a read-back) to run. `default_runner` therefore starts
# the script as a Popen child and, on the time limit, ends it politely FIRST
# and only kills what is still alive after the grace period.
# ---------------------------------------------------------------------------

_SLOW_SCRIPT = (
    "param([Parameter(ValueFromRemainingArguments=$true)]$Rest)\n"
    "Write-Output '[OK] gestart'\n"
    "Start-Sleep -Seconds 3\n"
    "Set-Content -LiteralPath '{marker}' -Value 'het kind draaide door'\n"
    "Write-Output '[EINDSTATUS] klaar'\n"
)


def _slow_script(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "kind-draaide-door.txt"
    script = tmp_path / "traag.ps1"
    script.write_text(_SLOW_SCRIPT.format(marker=str(marker).replace("\\", "\\\\")), encoding="utf-8")
    return script, marker


def test_a_timed_out_write_script_is_ended_politely_before_it_is_killed(tmp_path, monkeypatch):
    """MEASURED against a REAL child PowerShell, not a stub.

    `subprocess.run(timeout=...)` ends its child with `kill()` and nothing
    else - the write script's own `finally` block (compensation in reverse
    order plus a read-back) never gets asked. This test records the ORDER in
    which the child is told to stop, and pins the polite step in front.

    Platform note, stated rather than hidden: on Windows `terminate()` IS
    `TerminateProcess`, the same call as `kill()` (see the Python docs and
    `collect._stop_child_process`), so the polite step changes nothing THERE.
    The order is what this product controls, and on POSIX it is the
    difference between SIGTERM (trappable by the script) and SIGKILL.
    """
    from nsmcp.handelen import default_runner

    calls: list[str] = []
    real_popen = subprocess.Popen

    class RecordingPopen(real_popen):
        def terminate(self):
            calls.append("terminate")
            return super().terminate()

        def kill(self):
            calls.append("kill")
            return super().kill()

    monkeypatch.setattr(subprocess, "Popen", RecordingPopen)

    script, marker = _slow_script(tmp_path)
    command = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)]

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        default_runner(command, 1)
    elapsed = time.monotonic() - started
    assert elapsed < 15, f"de runner bleef {elapsed:.1f}s hangen op een tijdslimiet van 1s"
    assert calls, "het kindproces is helemaal niet gestopt"
    assert calls[0] == "terminate", f"het kind werd hard gekild zonder nette stap: {calls}"

    # And it really is gone: the marker it would have written after its sleep
    # never appears.
    time.sleep(4)
    assert not marker.exists(), "het kindproces liep gewoon door na de tijdslimiet"


def test_a_timed_out_write_script_is_reported_honestly(tmp_path):
    """`perform()` on the same real child: no invented outcome, an explicit
    'NIET vastgesteld', and the time limit named."""
    script, _ = _slow_script(tmp_path)

    def short_runner(arguments, timeout_s):
        from nsmcp.handelen import default_runner

        return default_runner(arguments, 1)

    result = perform(
        "dienst_lid_uitschakelen",
        {"dienst": "gjkdemo_sg_proefdienst", "lid": "gjkdemo_web01"},
        script=script,
        fixture_dir=tmp_path,
        target=DOEL,
        allowlist=DEMO,
        preview=False,
        bundle="test",
        run=short_runner,
    )
    assert result.ok is False
    assert result.actie_id is None and result.target is None
    assert "tijdslimiet" in result.eindstatus
    assert "NIET vastgesteld" in result.text


def test_an_unknown_dienst_says_a_virtual_server_name_does_not_apply_here():
    """`dienst` means two different things in this product: for the READING
    tool `dienst_status` it is the virtual server, for the two writing tools
    it is the SERVICEGROUP. A caller who hands the virtual server here gets a
    bare "staat niet op de allowlist" and no idea why - so the refusal says
    which of the two names belongs here."""
    with pytest.raises(ActionError) as info:
        validate(
            "dienst_lid_uitschakelen",
            {"dienst": "lb_vs_gjk_zaakportaal_443", "lid": "gjkdemo_web01"},
            target=DOEL,
            allowlist=DEMO,
        )
    message = str(info.value)
    assert "servicegroup" in message
    assert "virtuele server" in message


def test_an_unknown_certificate_refusal_stays_a_plain_allowlist_message():
    """Counter-probe: the servicegroup sentence belongs ONLY on the `dienst`
    argument of the two member tools, not on every refusal."""
    with pytest.raises(ActionError) as info:
        validate("certificaat_klaarzetten", {"certnaam": "iets-anders"}, target=DOEL, allowlist=DEMO)
    assert "virtuele server" not in str(info.value)


# ---------------------------------------------------------------------------
# C2 abolishes the "bedoelt u ...?" question, and with it the eight tests
# that pinned it (regression A4, regression, regression). The question answered
# something ABOUT THE TYPED TERM - which allowlisted names carry it - and
# that is an adaptive substring oracle, the same one `Finding.only_in_full`
# keeps out of the reading tools. `hints=False` made it a switch; C2 makes it
# a property, because `_act()` now turns a refusal into text through
# `render()` and what stays in a refusal must be safe at EVERY openheid
# level. The refusal no longer names the allowed values either, for the same
# reason: they are facts about the configuration, not about the call.
#
# What replaces the guidance is not silence but a route that is not an
# oracle: the reading advice (advice.py) says per item whether this server
# can carry it out, with the real name, at the level where real names are
# allowed.
# ---------------------------------------------------------------------------


def test_a_refusal_names_nothing_the_caller_did_not_supply():
    """The replacement for the eight deleted tests, in one measurement: the
    typed term comes back (the caller supplied it), the allowlist does not."""
    with pytest.raises(ActionError) as info:
        validate(
            "certificaat_vervangen",
            {"dienst": "lb_vs_gjk_zaakportaal_443", "nieuwcert": "zaakportaal"},
            target=DOEL,
            allowlist=DEMO,
        )
    melding = str(info.value)
    assert "zaakportaal" in melding
    assert "bedoelt u" not in melding
    for naam in ("gjk-zaakportaal-2026", "gjk-zaakportaal-2027"):
        assert naam not in melding, f"de allowlist staat in de weigering:\n{melding}"


def test_the_hints_switch_is_gone_because_it_is_now_a_property():
    """`hints` was a keyword argument on validate(). A property is not a
    keyword argument: passing it must be an error, not a silently ignored
    word."""
    with pytest.raises(TypeError):
        validate(
            "certificaat_klaarzetten",
            {"certnaam": "gjk-zaakportaal-2027"},
            target=DOEL,
            allowlist=DEMO,
            hints=False,
        )


# --------------------------------------------------------------------------
# Defence in depth: a doelnaam that bypasses start.py's startup gate
# (`_allowlist()`, which now imports the same grammar `backup_name()` uses)
# must still be refused HONESTLY here, as an ActionError - this module's own
# error vocabulary - never as a raw ValueError that a caller of
# build_arguments()/perform() would have to know to catch separately.
# --------------------------------------------------------------------------


def test_a_target_that_fails_the_backup_name_grammar_is_an_actionerror_not_a_valueerror():
    """Constructs the Allowlist directly, bypassing start.py's `_allowlist()`
    entirely - exactly the "path that bypasses the start gate" the fix
    covers. Before this fix, `backup_name()`'s `ValueError` propagated out
    of `build_arguments()` unchanged."""
    allowlist = Allowlist(per_target={"lab noord": {"onderhoud_backup_maken": True}})
    with pytest.raises(ActionError) as info:
        build_arguments(
            "onderhoud_backup_maken",
            {},
            script=SCRIPT,
            fixture_dir=FIXTURES,
            preview=False,
            bundle="b",
            target="lab noord",
            allowlist=allowlist,
        )
    # `assert not isinstance(info.value, ValueError)`
    # is vacuous here - `ActionError` never subclasses `ValueError`, so
    # `pytest.raises(ActionError)` above already guarantees it. This
    # measures something real instead: the ActionError carries the SAME
    # target text `backup_name()`'s own ValueError names, so build_arguments()
    # did not swap in a different, less honest message on the way through.
    assert "lab noord" in str(info.value)


# ---------------------------------------------------------------------------
# The firmware bundle in onderhoud.firmwaremap: ONE source for the target
# build and for its size, so the pre-flight's size estimate and the runner's
# target build read the same file under the same rule.
# ---------------------------------------------------------------------------


def test_the_one_bundle_gives_the_target_build_and_its_size(tmp_path):
    from nsmcp.handelen import firmware_target_build

    (tmp_path / "build-14.1-72.57_nc_64.tgz").write_bytes(b"\0" * (5 * 1024 * 1024 + 10))
    (tmp_path / "build-14.1-72.57_nc_64.tgz.sha256").write_text("x", encoding="ascii")
    bundel = firmware_target_build(tmp_path)
    assert bundel.build == "14.1-72.57"
    assert bundel.naam == "build-14.1-72.57_nc_64.tgz"
    assert bundel.mb == 5


@pytest.mark.parametrize("namen", [(), ("build-14.1-72.57_nc_64.tgz", "build-14.1-73.32_nc_64.tgz")])
def test_zero_or_two_bundles_give_no_size_either(tmp_path, namen):
    from nsmcp.handelen import firmware_target_build

    for naam in namen:
        (tmp_path / naam).write_bytes(b"x")
    with pytest.raises(ActionError):
        firmware_target_build(tmp_path)


def test_the_bundle_form_ends_at_the_end_of_the_name_and_not_before_a_line_break():
    """`$` in a Python pattern also matches just before a trailing newline,
    so a name ending in one read as a bundle. The form ends at `\\Z`, the
    real end - the same rule the runner's own bundle check (`\\z`) keeps."""
    from nsmcp.handelen import _FIRMWARE_BUNDLE_RE

    assert _FIRMWARE_BUNDLE_RE.match("build-14.1-73.37_nc_64.tgz")
    assert not _FIRMWARE_BUNDLE_RE.match("build-14.1-73.37_nc_64.tgz\n")


def _lab_target(pinned: bool = True):
    from nsmcp.target import CertAgreement, Target

    return Target(
        name="lab",
        address="192.0.2.10",
        credential_target="GJK/Test/lab",
        agreement=CertAgreement.CHAIN,
        ssh_hostsleutel_vingerafdruk="AA:BB:CC:0D" if pinned else None,
    )


def _lab_onderhoud(runner: Path = Path(r"C:\x\scripts\Invoke-GjkUpgradeFase.ps1")):
    from nsmcp.handelen import MaintenanceConfig

    return MaintenanceConfig(
        runner=runner,
        ledgermap=Path(r"C:\x\ledger"),
        firmwaremap=Path(r"C:\x\firmware"),
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )


def _assert_ssh_head(args):
    assert args[args.index("-Doel") + 1] == "lab"
    assert args[args.index("-Adres") + 1] == "192.0.2.10"
    assert args[args.index("-Gebruiker") + 1] == "nsroot"
    assert args[args.index("-CredentialTarget") + 1] == "GJK/Test/lab"
    assert args[args.index("-HostsleutelVingerafdruk") + 1] == "aa:bb:cc:d"


def test_the_live_read_arguments_carry_the_pinned_key_in_wire_form_and_no_preview_flag():
    from nsmcp.handelen import build_live_measure_arguments

    target, onderhoud = _lab_target(), _lab_onderhoud()
    # Two forbidden addresses travel as ONE comma-joined token: measured,
    # `powershell.exe -File` binds only the first of two space-separated
    # values to a [string[]] parameter and treats the second as a stray
    # positional argument.
    twee = build_live_measure_arguments(target, onderhoud, forbidden_addresses=("203.0.113.9", "198.51.100.7"))
    assert twee[twee.index("-VerbodenAdressen") + 1] == "203.0.113.9,198.51.100.7"
    assert twee[-2] == "-VerbodenAdressen"
    args = build_live_measure_arguments(target, onderhoud, forbidden_addresses=("203.0.113.9",))
    assert args[:2] == ["-Meting", "vrije-ruimte"]
    _assert_ssh_head(args)
    assert args[args.index("-VerbodenAdressen") + 1] == "203.0.113.9"
    assert "-WatIs" not in args and "-Actieid" not in args


# ---------------------------------------------------------------------------
# config_opslaan: the objectless write tool that saves the running
# configuration over SSH (scripts/Invoke-GjkConfigOpslaan.ps1). What is
# measured here is its edge: the shape in the tool tables, the argument list,
# and how the script's output is read - never the saving itself.
# ---------------------------------------------------------------------------

SAVE_ALLOWLIST = Allowlist(per_target={"lab": {"config_opslaan": True}})


def test_config_opslaan_is_an_objectless_write_tool_without_arguments():
    from nsmcp.handelen import ARGUMENTS, OBJECTLESS_TOOLS, WRITE_TOOLS

    assert "config_opslaan" in WRITE_TOOLS
    assert "config_opslaan" in OBJECTLESS_TOOLS
    assert ARGUMENTS["config_opslaan"] == ()
    assert validate("config_opslaan", {}, target="lab", allowlist=SAVE_ALLOWLIST) == {}


def test_config_opslaan_never_goes_through_the_demo_argument_builder():
    with pytest.raises(ActionError):
        build_arguments(
            "config_opslaan",
            {},
            script=SCRIPT,
            fixture_dir=FIXTURES,
            preview=True,
            bundle="b",
            target="lab",
            allowlist=SAVE_ALLOWLIST,
        )


def test_the_save_arguments_of_a_preview_carry_watis_and_no_action_id():
    import sys

    from nsmcp.handelen import build_save_arguments

    args = build_save_arguments(
        _lab_target(), _lab_onderhoud(), preview=True, actie_id="", forbidden_addresses=("203.0.113.9",)
    )
    _assert_ssh_head(args)
    assert args[args.index("-GatePython") + 1] == sys.executable
    assert args[args.index("-VerbodenAdressen") + 1] == "203.0.113.9"
    assert args[-1] == "-WatIs"
    assert "-Actieid" not in args


def test_the_save_arguments_of_a_real_run_carry_the_action_id_and_no_watis():
    from nsmcp.handelen import build_save_arguments

    args = build_save_arguments(_lab_target(), _lab_onderhoud(), preview=False, actie_id="config-opslaan-x")
    assert args[args.index("-Actieid") + 1] == "config-opslaan-x"
    assert "-WatIs" not in args
    assert "-VerbodenAdressen" not in args


def test_the_save_arguments_refuse_a_target_without_a_pinned_host_key():
    from nsmcp.handelen import build_save_arguments

    with pytest.raises(ActionError, match="ssh_hostsleutel_vingerafdruk"):
        build_save_arguments(_lab_target(pinned=False), _lab_onderhoud(), preview=True, actie_id="")


def _save_script(tmp_path: Path) -> Path:
    runner = tmp_path / "scripts" / "Invoke-GjkUpgradeFase.ps1"
    runner.parent.mkdir(parents=True, exist_ok=True)
    runner.write_text("# runner", encoding="ascii")
    (runner.parent / "Invoke-GjkConfigOpslaan.ps1").write_text("# opslaan", encoding="ascii")
    return runner


def _perform_save(tmp_path, run, *, preview, allowlist=SAVE_ALLOWLIST, target=None):
    from nsmcp.handelen import perform_save

    return perform_save(
        target=target or _lab_target(),
        onderhoud=_lab_onderhoud(_save_script(tmp_path)),
        allowlist=allowlist,
        preview=preview,
        run=run,
    )


def test_a_save_preview_starts_the_script_next_to_the_runner_with_watis(tmp_path):
    calls = []

    def run(arguments, timeout_s):
        calls.append((arguments, timeout_s))
        return 0, "[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\n[OK] zou doen: save ns config op lab\n", ""

    result = _perform_save(tmp_path, run, preview=True)
    assert result.ok and result.preview
    assert result.target == "nsconfig/lab (192.0.2.10) - config opslaan"
    arguments, timeout_s = calls[0]
    assert timeout_s == 300
    assert arguments[arguments.index("-File") + 1].endswith(str(Path("scripts") / "Invoke-GjkConfigOpslaan.ps1"))
    assert "-WatIs" in arguments


def test_a_real_save_run_must_echo_the_action_id_this_side_commanded(tmp_path):
    def run(arguments, timeout_s):
        actie = arguments[arguments.index("-Actieid") + 1]
        return 0, f"[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\n[ACTIEID] {actie}\n[EINDSTATUS] x\n", ""

    result = _perform_save(tmp_path, run, preview=False)
    assert result.ok is True
    assert result.actie_id.startswith("config-opslaan-")
    assert result.object_name is None


@pytest.mark.parametrize(
    "stdout,exit_code",
    [
        ("[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\n[ACTIEID] een-ander-id\n", 0),
        ("[ACTIEID] {actie}\n", 0),
        ("[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\n[ACTIEID] {actie}\n[GEWEIGERD] secondary\n", 1),
    ],
)
def test_a_real_save_run_without_its_own_action_id_or_target_or_with_an_error_exit_is_not_ok(
    tmp_path, stdout, exit_code
):
    def run(arguments, timeout_s):
        actie = arguments[arguments.index("-Actieid") + 1]
        return exit_code, stdout.replace("{actie}", actie), ""

    result = _perform_save(tmp_path, run, preview=False)
    assert result.ok is False


def test_a_save_run_that_times_out_says_the_outcome_is_not_established(tmp_path):
    def run(arguments, timeout_s):
        raise subprocess.TimeoutExpired(cmd=arguments, timeout=timeout_s, output="[ACTIEID] x\n")

    result = _perform_save(tmp_path, run, preview=False)
    assert result.ok is False
    assert "NIET vastgesteld" in result.text


def test_a_save_is_refused_without_the_allowlist_before_any_script_runs(tmp_path):
    calls = []

    def run(arguments, timeout_s):
        calls.append(arguments)
        return 0, "", ""

    with pytest.raises(ActionError):
        _perform_save(tmp_path, run, preview=True, allowlist=Allowlist(per_target={"lab": {}}))
    assert calls == []


def test_a_missing_save_script_is_an_honest_error_not_a_start(tmp_path):
    from nsmcp.handelen import perform_save

    calls = []
    with pytest.raises(ActionError, match="Invoke-GjkConfigOpslaan.ps1"):
        perform_save(
            target=_lab_target(),
            onderhoud=_lab_onderhoud(tmp_path / "leeg" / "runner.ps1"),
            allowlist=SAVE_ALLOWLIST,
            preview=True,
            run=lambda a, t: calls.append(a),
        )
    assert calls == []


# --- 1.0.2: the faserunner and its transport against their pins -----


def test_sr5_the_runner_command_is_refused_when_its_transport_changed(tmp_path, monkeypatch):
    import hashlib

    from nsmcp import powershell as powershell_module
    from nsmcp.handelen import upgrade_command
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    monkeypatch.setattr(powershell_module, "_policy", powershell_module._policy)
    runner = tmp_path / "Invoke-GjkUpgradeFase.ps1"
    runner.write_text("# runner\n", encoding="ascii")
    transport = tmp_path / "GjkUpgrade-Ssh.ps1"
    transport.write_text("# transport\n", encoding="ascii")
    pins = {path.name.casefold(): hashlib.sha256(path.read_bytes()).hexdigest() for path in (runner, transport)}
    set_script_policy(ScriptPolicy(pins=pins))
    assert upgrade_command(runner, ["-WatIs"])
    transport.write_text("# transport, aangepast\n", encoding="ascii")
    with pytest.raises(ScriptPinMismatch, match="GjkUpgrade-Ssh.ps1"):
        upgrade_command(runner, ["-WatIs"])
