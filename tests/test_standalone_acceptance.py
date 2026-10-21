"""A standalone appliance is always Primary - measured on lab-02 (8-9-2026).

`show ha node` on a box without a peer lists exactly one node (Node ID 0) with
`Master State: Primary`, so the secondary gate closed on every standalone
appliance and R1 could never start. There is no secondary to upgrade first and
the upgrade means downtime: a human decision, carried as
`standalone_geaccepteerd` through the tool, the argument builder, the runner and
into the gate. With a peer present the flag changes nothing.
"""

from __future__ import annotations

from nsmcp.handelen import validate_phase_arguments
from nsmcp.upgrade import secondary_gate

STANDALONE = (
    "1)\tNode ID:      0\n\tIP:\t203.0.113.11 (host-002.lab.example)\n\tNode State: UP\n"
    "\tMaster State: Primary\n\tFail-Safe Mode: OFF\n\tINC State: DISABLED\n Done\n"
)
PAIR_LOCAL_PRIMARY = STANDALONE.replace(" Done\n", "") + (
    "2)\tNode ID:      1\n\tIP:\t203.0.113.12\n\tNode State: UP\n\tMaster State: Secondary\n Done\n"
)


def test_a_standalone_box_stays_closed_without_the_human_decision():
    gate = secondary_gate(STANDALONE, "203.0.113.11")
    assert gate.outcome == "dicht"
    assert "standalone" in gate.evidence and "standalone_geaccepteerd" in gate.reason


def test_a_standalone_box_opens_only_with_the_explicit_acceptance():
    gate = secondary_gate(STANDALONE, "203.0.113.11", standalone_accepted=True)
    assert gate.outcome == "open", gate
    assert "geen peer" in gate.evidence and "downtime bewust geaccepteerd" in gate.evidence
    # Only a real True counts - never a truthy string from untrusted JSON.
    assert secondary_gate(STANDALONE, "203.0.113.11", standalone_accepted="True").outcome == "dicht"


def test_a_primary_with_a_peer_stays_closed_even_when_accepted():
    gate = secondary_gate(PAIR_LOCAL_PRIMARY, "203.0.113.11", standalone_accepted=True)
    assert gate.outcome == "dicht"
    assert "primary" in gate.reason.lower()


def test_the_phase_arguments_carry_the_flag_for_every_phase():
    for fase in ("R1", "R2", "R3", "R4", "R5"):
        clean = validate_phase_arguments({"fase": fase, "run": "run-1", "standalone_geaccepteerd": "True"})
        assert clean["standalone_geaccepteerd"] is True
    clean = validate_phase_arguments({"fase": "R1", "run": "run-1"})
    assert clean["standalone_geaccepteerd"] is False
