"""Synthetic evidence for tests of closing rules unrelated to pre-write measurement."""

from nsmcp.upgrade import append_line


def pre_gate_context(phase, *, action="a-1", started="2026-09-06T00:00:00Z", run="r1", target="lab-02"):
    identity = dict(run=run, doel=target, actieid=action, gestart=started, poging="a" * 32)
    names = ["hostsleutel gepind", "doel is secondary", f"R{int(phase[1:]) - 1} gesloten"]
    if phase == "R1":
        names += ["vrije ruimte op /var", "lokale bundel en sidecar", "drift afwezig of bewust geaccepteerd"]
    if phase == "R2":
        names += ["precheck-resultaatpad nieuw"]
    gates = [
        {"naam": name, "type": "bewijs", "uitkomst": "open", "bewijs": "synthetic successful read", "reden": ""}
        for name in names
    ]
    return dict(
        identity,
        lines=[
            dict(identity, fase=phase, gebeurtenis="fase_gestart", uitkomst="gestart"),
            dict(identity, fase=phase, gebeurtenis="voorpoort", uitkomst="open", poort=gates),
        ],
    )


def seed_pre_gate(path, phase, **kwargs):
    context = pre_gate_context(phase, **kwargs)
    for row in context["lines"]:
        append_line(path, row)
    return context["poging"]
