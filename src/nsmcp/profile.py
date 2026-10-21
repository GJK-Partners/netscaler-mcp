"""One build, three profiles.

The difference between the delivery modes is a setting, not a separate build.
An unknown profile does NOT fall back to a default - that would let a typo in
a configuration file silently allow outbound internet traffic.

`may_use_network()` is about OUTBOUND INTERNET TRAFFIC - fetching knowledge
autonomously (not built yet), not about management traffic to an appliance
inside the customer's own network. Only the online profile may eventually go
out (internet) to fetch knowledge itself; shielded and service may not.

Scanning a NetScaler is a different thing and independent of this: that is
management traffic, aimed at the address the operator configures in the
targets file - which is precisely the PURPOSE of the shielded profile (see
the design document, section "Drie profielen"). `may_use_network()` does not
govern that.

HONESTY BOUNDARY: whether that management traffic STAYS inside the customer
network is not enforced by this code - that is not a typo, it is a deliberate
choice. It follows from the address the operator picks and from the
customer's own outbound network policy (egress policy); that is the
enforcement layer, not `may_use_network()` or anything else here. There is
deliberately NO homegrown address filter (CIDR/allowlist check) to enforce
that promise after all: without a reliable local DNS/proxy picture such a
filter is itself bypassable, so it would add false certainty instead of a
real boundary (see README.md, section "Running / configuration", for the
same trade-off for the operator). That the service profile does not scan
today does not come from here: that is a separate, dedicated rule in
start.py (service answers exclusively on a supplied export), not a network
restriction.
"""

from __future__ import annotations

from enum import Enum


class Profile(Enum):
    ONLINE = "online"
    SHIELDED = "afgeschermd"
    SERVICE = "dienst"


def load_profile(name: str) -> Profile:
    try:
        return Profile(str(name).strip().lower())
    except ValueError:
        allowed = ", ".join(p.value for p in Profile)
        raise ValueError(f"onbekend profiel {name!r}; toegestaan: {allowed}") from None


def may_use_network(p: Profile) -> bool:
    """May this profile do OUTBOUND INTERNET TRAFFIC (fetch knowledge itself,
    not built yet)? This says nothing about scanning: querying a NetScaler is
    management traffic to the address the operator configures, not internet
    traffic governed by this function (shielded does scan - that is its
    purpose, see the module docstring above). Whether that management traffic
    stays inside the customer network depends on that address and on the
    customer's own egress policy - this function does not enforce it (see the
    HONESTY BOUNDARY in the module docstring above). That service does not
    scan comes from a separate, dedicated rule in start.py - not from this
    function."""
    return p is Profile.ONLINE
