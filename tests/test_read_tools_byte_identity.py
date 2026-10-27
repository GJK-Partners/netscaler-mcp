"""1.1 spec section 2, rule 5: within 14.1 the read tools say exactly what 1.0.3 said.

The hashes below were measured on the tree BEFORE `src/nsmcp/classic.py`
existed, with `tests/read_tools_harness.py`: per export fixture the full
answer text of `status_update_preflight`, `onderhoud_upgrade_plan` and
`status_update_advies` (fixed knowledge package, fixed day, fixed free-space
figure). Any change in any word or verdict of any of the three, on any of
these exports, changes a hash. A deliberate change elsewhere in 1.1 that
touches these texts must re-measure and say so in the CHANGELOG; the classic
module must not.

A new export fixture is not silently skipped: the set of fixtures is pinned
too, so adding one means adding its measured hash here.
"""

from __future__ import annotations

import pytest
from read_tools_harness import export_fixtures, read_tool_hash

READ_TOOL_HASHES_1_0_3 = {
    "a14-export": "ec4f6c670e9d038a65ba653185d2724d0f5c3965452407ac497463e4f43d1d55",
    "certgebruik-saml": "9e91c1e1ed0a4b1769e48536a869a015a30d578ef71b796f8c37c2b616967fa4",
    "keten-cs": "d3dd563c87678315fa9ac6a70a35328a7225b14632c8262bff5327bbdd18a2d9",
    "lab-export-vpx-20260826": "aec29c9126411ba3d88e68d16c69d730b13ca50bc450975bc9573c6d59a022d4",
    "lab-export-vpx-doh-synthetic": "7bb641de728048992138570fe525514dbd3c998ef7600e4c228323636b5b70f5",
    "na-upgrade-met-veld": "2dc6f1d315c21b208e0cf656a9a21d83bfef6a615bb610f1441f0fe0d06fb64e",
    "na-upgrade-zonder-veld": "2dc6f1d315c21b208e0cf656a9a21d83bfef6a615bb610f1441f0fe0d06fb64e",
    "preflight-export": "30edb61cdd0820ac058fa32bb6753138f26b0e09c2917ad71b440cee0a8b1d1d",
    "pseudonymised-historical-no-marker": "6f73e62fe41b325c6da31de6b9ea8a8673cc744e545c93f0433dfaf408d1e41f",
    "r0-export": "e78f8c3af028c1eb4f79e4529a24f99b3ab71e24b02a78eb90e928665affc2e2",
}


def test_the_measured_fixture_set_is_every_export_fixture():
    assert sorted(d.name for d in export_fixtures()) == sorted(READ_TOOL_HASHES_1_0_3)


@pytest.mark.parametrize("fixture", export_fixtures(), ids=lambda p: p.name)
def test_the_three_read_tools_are_byte_identical_to_1_0_3(fixture, monkeypatch):
    assert read_tool_hash(fixture, monkeypatch) == READ_TOOL_HASHES_1_0_3[fixture.name]
