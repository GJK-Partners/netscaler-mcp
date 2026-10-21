"""Regressie: een export met meer dan 99 namen krijgt bij openheid beperkt stabiele pseudoniemen.

Synthetische namen; geen export of mapping uit een echte omgeving.
"""

from nsmcp.disclosure import _load_table


def test_one_export_can_allocate_more_than_99_stable_pseudonyms(tmp_path):
    path = tmp_path / "pseudoniemen.json"
    names = [f"LBV_SYNTH_{number:04d}" for number in range(120)]

    first = _load_table(path, names)

    assert len(first) == len(names)
    assert set(first.values()) == set(names)
    assert "object-100" in first
    assert _load_table(path, names) == first
    expanded = _load_table(path, [*names, "LBV_SYNTH_NEW"])
    assert len(expanded) == 121
    assert all(expanded[key] == value for key, value in first.items())
    assert not any(real in alias or alias in real for alias in expanded for real in expanded.values())
