"""Markers behind the appliance's shell banner - measured on lab-02 (8-9-2026).

Every `shell ...` answer from the box starts with
`Warning: [ One or more RPC nodes are configured with default passwords ...]`.
An exact-equality check on our own marker word (`AFWEZIG` for the precheck
result path) therefore closed R2 on a real appliance. The marker is judged as
a WHOLE LINE of the output - never as the entire output, never as a substring.
"""

from __future__ import annotations

from nsmcp.upgrade import precheck_gate, precheck_path_gate

# The MEASURED text (lab-02, 8-9-2026), line breaks included: the vendor's
# second sentence names the DEFAULT password, and the bracket closes on a
# line of its own.
BANNER = (
    "Warning: [\nOne or more RPC nodes are configured with default passwords. "
    "For enhanced security, you must change the default RPC node password.\n]\n"
)


def test_the_marker_is_read_as_a_whole_line_behind_the_banner():
    assert precheck_path_gate("/var/tmp/x.json", 0, BANNER + "AFWEZIG\n").outcome == "open"
    assert precheck_path_gate("/var/tmp/x.json", 0, "  AFWEZIG  \n").outcome == "open"


def test_without_the_marker_line_the_gate_is_not_assessed():
    assert precheck_path_gate("/var/tmp/x.json", 0, BANNER).outcome == "niet beoordeeld"
    assert precheck_path_gate("/var/tmp/x.json", 0, "AFWEZIGHEID\n").outcome == "niet beoordeeld"
    assert precheck_path_gate("/var/tmp/x.json", 0, "x AFWEZIG y\n").outcome == "niet beoordeeld"
    assert precheck_path_gate("/var/tmp/x.json", 1, "AFWEZIG\n").outcome == "niet beoordeeld"
    assert precheck_path_gate("/var/tmp/x.json", None, "AFWEZIG\n").outcome == "niet beoordeeld"


def test_the_vendor_json_is_read_from_its_first_brace_behind_the_banner():
    """`shell cat <resultaat>` on the box: banner first, then the vendor JSON."""
    ok = BANNER + '{"global_status": "success", "checks": [{"name": "disk", "status": "passed"}]}\n'
    assert precheck_gate(ok).outcome == "open"
    failed = BANNER + '{"global_status": "failed", "checks": []}\n'
    assert precheck_gate(failed).outcome == "dicht"
    assert precheck_gate(BANNER).outcome == "dicht"
    assert precheck_gate(BANNER + "{niet json").outcome == "dicht"
    assert precheck_gate('{"global_status": "success", "checks": []}').outcome == "open"


def test_the_vendor_json_survives_the_cli_done_line_after_it():
    """Measured on lab-02: `shell cat <resultaat>` = banner, " Done", the JSON, " Done"."""
    tekst = (
        BANNER
        + " Done\n"
        + '{"global_status": "warning", "checks": [{"name": "x", "status": "warning"}]}\n'
        + " Done\n"
    )
    gate = precheck_gate(tekst)
    assert gate.outcome == "open", gate
    assert "global_status=warning" in gate.evidence
    dicht = BANNER + " Done\n" + '{"global_status": "failed"}\n' + " Done\n"
    assert precheck_gate(dicht).outcome == "dicht"
