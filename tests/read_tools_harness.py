"""The full answer text of the three read tools on one export, deterministic.

The three tools that read the upgrade path (`status_update_preflight`,
`onderhoud_upgrade_plan`, `status_update_advies`) each wrap ONE domain
function (`preflight.preflight_answer`, `upgrade_plan.upgrade_plan`,
`update_advice.update_advice`) and hand its `Answer` to the unchanged
rendering layer. Comparing the domain answer text byte for byte is
therefore comparing what the tools say, minus the live free-space read
(check 8 gets a fixed figure here) and minus the clock: the only clock on
this path is `expiry.age_of`, and it is frozen to one fixed UTC day.

Used by the byte-identity test in `tests/test_classic.py`, and the same
function produced the hash per fixture BEFORE the classic module existed.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from pathlib import Path

from nsmcp import expiry
from nsmcp.export import load_export
from nsmcp.knowledge import load_knowledge
from nsmcp.preflight import FREE_SPACE_ROUTE_COLLECTOR, preflight_answer
from nsmcp.update_advice import update_advice
from nsmcp.upgrade_plan import MINIMUM_SOAK_HOURS, upgrade_plan

FIXTURES = Path(__file__).parent / "fixtures"
KNOWLEDGE = FIXTURES / "kennis-aangeboden.json"
FIXED_DAY = date(2026, 10, 27)
FREE_VAR_MB = 9000
BUNDLE_MB = 1081


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(FIXED_DAY.year, FIXED_DAY.month, FIXED_DAY.day, 12, 0, 0, tzinfo=tz or UTC)


def export_fixtures() -> list[Path]:
    """Every export under tests/fixtures: a directory with an export manifest."""
    return sorted(p.parent for p in FIXTURES.rglob("export-manifest.json"))


def read_tool_texts(export_dir: Path, monkeypatch) -> dict[str, str]:
    monkeypatch.setattr(expiry, "datetime", _FrozenDateTime)
    export = load_export(export_dir)
    knowledge = load_knowledge(KNOWLEDGE, today=FIXED_DAY)
    return {
        "status_update_preflight": preflight_answer(
            export, knowledge, FREE_VAR_MB, BUNDLE_MB, None, free_space_route=FREE_SPACE_ROUTE_COLLECTOR
        ).to_text(),
        "onderhoud_upgrade_plan": upgrade_plan(export, knowledge, MINIMUM_SOAK_HOURS, doelbuild=None).to_text(),
        "status_update_advies": update_advice(export, knowledge).to_text(),
    }


def read_tool_hash(export_dir: Path, monkeypatch) -> str:
    texts = read_tool_texts(export_dir, monkeypatch)
    digest = hashlib.sha256()
    for tool in sorted(texts):
        digest.update(tool.encode("ascii") + b"\x00" + texts[tool].encode("utf-8") + b"\x00")
    return digest.hexdigest()
