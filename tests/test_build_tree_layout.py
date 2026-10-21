"""The build tree as the appliance really lays it out.

Measured on lab-02 (8-9-2026, `config/systemfile?args=filelocation:%2Fvar%2Fnsinstall`
plus the branch directories): `installns` unpacks a build to
`/var/nsinstall/<tak>/build_<build>` - nested, with an underscore - and the
runner uploads to that same path. Every reader of this source (preflight
check 9, R0's `vorige buildboom aanwezig` gate, the rollback-point evidence)
used to accept only a flat `build-...` entry directly under `/var/nsinstall`,
which no real box has: the gate said `dicht` on every appliance. One shared
helper now defines what a build tree is; these tests pin both layouts and
the things that are NOT a build tree.

Only a DIRECTORY entry can be a build tree.
The measured export carries `filemode` on every row (`"DIRECTORY"` for the
branch and build directories); a file that merely carries the name, or a
row without a type, is unknown evidence and never counts.
"""

from __future__ import annotations

from nsmcp.preflight import BUILD_TREE_LOCATION, build_tree_entries
from nsmcp.upgrade import _build_tree_paths, build_tree_gate

MEASURED_ROWS = [
    {"filelocation": "/var/nsinstall", "filename": "13.1", "filemode": "DIRECTORY"},
    {"filelocation": "/var/nsinstall", "filename": "installns_state", "filemode": "REGULAR"},
    {"filelocation": "/var/nsinstall", "filename": "installns_state_post_reboot", "filemode": "REGULAR"},
    {"filelocation": "/var/nsinstall", "filename": "14.1", "filemode": "DIRECTORY"},
    {"filelocation": "/var/nsinstall/13.1", "filename": "build_63.16", "filemode": "DIRECTORY"},
    {"filelocation": "/var/nsinstall/14.1", "filename": "build_66.59", "filemode": "DIRECTORY"},
]


class _Export:
    def __init__(self, rows, gap=None):
        self._rows, self._gap = rows, gap

    def objects(self, resource):
        return (list(self._rows), self._gap)


def test_the_measured_nested_layout_counts_as_two_build_trees():
    entries = build_tree_entries(MEASURED_ROWS)
    assert [pad for pad, _ in entries] == [
        "/var/nsinstall/13.1/build_63.16",
        "/var/nsinstall/14.1/build_66.59",
    ]


def test_the_flat_layout_still_counts():
    rows = [{"filelocation": "/var/nsinstall", "filename": "build-14.1-66.59_nc_64", "filemode": "DIRECTORY"}]
    assert [pad for pad, _ in build_tree_entries(rows)] == ["/var/nsinstall/build-14.1-66.59_nc_64"]


def test_what_is_not_a_build_tree():
    D = {"filemode": "DIRECTORY"}
    rows = [
        {"filelocation": "/var/nsinstall", "filename": "14.1", **D},  # a branch dir
        {"filelocation": "/var/nsinstall/14.1/build_66.59", "filename": "build_x", **D},  # too deep
        {"filelocation": "/var/tmp", "filename": "build_66.59", **D},  # elsewhere
        {"filelocation": "/var/nsinstall/backup", "filename": "build_1", **D},  # not a branch dir
        {"filelocation": "/var/nsinstall/14.1", "filename": "installns", **D},  # not a tree
        {"filelocation": "/var/nsinstall/14.1", "filename": "build_66.59", "filemode": "REGULAR"},  # a FILE
        {"filelocation": "/var/nsinstall/14.1", "filename": "build_66.59"},  # type unknown
        {"filelocation": " /var/nsinstall/14.1", "filename": "build_66.59", **D},  # padded location
        {"filelocation": None, "filename": "build_1", **D},
        {"filelocation": "/var/nsinstall/14.1", "filename": 7, **D},
        "geen object",
    ]
    assert build_tree_entries(rows) == []


def test_r0_gate_opens_on_the_measured_layout_and_names_the_trees():
    gate = build_tree_gate(_Export(MEASURED_ROWS))
    assert gate.outcome == "open", gate
    assert "14.1/build_66.59" in gate.evidence
    assert BUILD_TREE_LOCATION in gate.evidence


def test_r0_gate_is_closed_without_a_tree_and_unassessed_without_a_read():
    assert build_tree_gate(_Export(MEASURED_ROWS[:4])).outcome == "dicht"
    from nsmcp.answer import ReadGap

    gate = build_tree_gate(_Export([], ReadGap(source="x", reason="niet gelezen")))
    assert gate.outcome == "niet beoordeeld"


def test_rollback_point_names_the_full_nested_path():
    assert _build_tree_paths(_Export(MEASURED_ROWS)) == (
        "/var/nsinstall/13.1/build_63.16, /var/nsinstall/14.1/build_66.59"
    )
