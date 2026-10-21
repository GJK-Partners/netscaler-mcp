"""Writes the synthetic DNS over HTTPS export, tests/fixtures/lab-export-vpx-doh-synthetic/.

Nothing in it was ever collected from an appliance. Every name, address and
value below is invented for this fixture: names in the `LBV-DOH-001` style,
addresses on the TEST-NET ranges of RFC 5737 (192.0.2.0/24 for the appliance
side, 198.51.100.0/24 for the back end, 203.0.113.0/24 for management peers),
host names under `lab.example`. The only words that are not invented are the
vocabulary of the appliance itself: resource and field names, service types,
states, the names of its built-in objects (`ns-server-certificate`,
`ping-default`, `nshttp_default_profile`, the internal `nshttps-...` services)
and the redaction marker the collector writes.

The export has the SHAPE the released collector writes - an
export-manifest.json with a payloadSha256 per resource and a hash per file,
objects/*.json with the NITRO envelope and CRLF line endings, aggregate and
list-shaped bindings/*.by-parent.json files, parsed/runningconfig.txt and
parsed/savedconfig.txt with LF line endings, parsed/systemuser.json and
parsed/authenticationldapaction.json, and a collect-log.txt - so the tests
that need a full export of that shape can run on it.

It carries the four DNS over HTTPS shapes `nsmcp.cve` reads for the
condition `heeft_lb_oracle_of_dns`: an SSL lb vserver and an SSL cs vserver
added with `-dnsOverHttps ENABLED`, the `set lb vserver` / `set cs vserver`
form that switches it on afterwards, and a DNS profile with
`-recursiveResolution ENABLED`; next to them two classic DNS proxies and an
SSL lb vserver with DNS over HTTPS DISABLED as the negative control.

The hashes in the manifest are computed with the functions the product
reads them with (`nsmcp.export.payload_digest` and
`nsmcp.export.config_text_digest`), never with a copy of them.

Deterministic: the same script writes the same bytes every time; no clock,
no randomness, no appliance, no network.

Usage (from the repository root, in the project's virtual environment):

    python scripts/make_doh_fixture.py
    python scripts/make_doh_fixture.py --target <map> --force
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from nsmcp.export import config_text_digest, load_export, payload_digest

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = ROOT / "tests" / "fixtures" / "lab-export-vpx-doh-synthetic"

MARKER = "<REDACTED>"
COLLECTED_AT = "2026-09-06T10:00:00.0000000Z"
APPLIANCE_TIME = "Sun Sep  6 12:00:00 2026"
VERSION = "NetScaler NS14.1: Build 72.57.nc, Date: May 21 2026, 18:20:32   (64-bit)"
NSIP = "192.0.2.2"
SNIP = "192.0.2.3"
SNIP_BACKEND = "198.51.100.254"
KEK_SUFFIX = "LAB_SYNTHETIC_KEY"

# ---------------------------------------------------------------------------
# The configuration, as data.
# ---------------------------------------------------------------------------

# name, servicetype, address, port, curstate, dnsoverhttps (object), how DoH
# is switched on in the running config ("add", "set" or None), http profile
LB_VSERVERS = [
    ("LBV-DOH-001", "SSL", "192.0.2.10", 443, "DOWN", "ENABLED", "add", "HTTPPROF-H2-001"),
    ("LBV-DOH-002", "SSL", "192.0.2.11", 443, "DOWN", "ENABLED", "set", None),
    ("LBV-NODOH-001", "SSL", "192.0.2.12", 443, "DOWN", "DISABLED", None, None),
    ("LBV-DNS-001", "DNS", "192.0.2.13", 53, "DOWN", "DISABLED", None, None),
    ("LBV-DNS-002", "DNS_TCP", "192.0.2.14", 53, "DOWN", "DISABLED", None, None),
    ("LBV-WEB-001", "HTTP", "192.0.2.20", 80, "UP", "DISABLED", None, None),
    ("LBV-APP-001", "SSL", "192.0.2.21", 443, "DOWN", "DISABLED", None, None),
    ("LBV-APP-002", "SSL", "192.0.2.22", 443, "UP", "DISABLED", None, None),
    ("LBV-TCP-001", "TCP", "192.0.2.23", 8443, "UP", "DISABLED", None, None),
    ("LBV-UDP-001", "UDP", "192.0.2.24", 514, "DOWN", "DISABLED", None, None),
    ("LBV-OOS-001", "SSL", "192.0.2.25", 443, "OUT OF SERVICE", "DISABLED", None, None),
    ("LBV-BRIDGE-001", "SSL_BRIDGE", "192.0.2.26", 443, "DOWN", "DISABLED", None, None),
]

# name, address, dnsoverhttps (object), how DoH is switched on, default lb
CS_VSERVERS = [
    ("CSV-DOH-001", "192.0.2.40", "ENABLED", "add", None),
    ("CSV-DOH-002", "192.0.2.41", "ENABLED", "set", None),
    ("CSV-WEB-001", "192.0.2.42", "DISABLED", None, "LBV-APP-002"),
    ("CSV-WEB-002", "192.0.2.43", "DISABLED", None, None),
    ("CSV-EMPTY-001", "192.0.2.44", "DISABLED", None, None),
]

# cs policy -> (cs action, target lb vserver, cs vserver it is bound to, priority)
CS_POLICIES = [
    ("CSPOL-001", "CSACT-001", "LBV-APP-001", "CSV-WEB-001", 100),
    ("CSPOL-002", "CSACT-002", "LBV-TCP-001", "CSV-WEB-001", 110),
    ("CSPOL-003", "CSACT-003", "LBV-WEB-001", "CSV-WEB-002", 100),
]

# servers: name -> address. A server whose name IS its address is the form
# the appliance creates for a member added by address.
SERVERS = {
    "SRV-DOH-001": "198.51.100.1",
    "SRV-DOH-002": "198.51.100.2",
    "SRV-DNS-001": "198.51.100.3",
    "SRV-DNS-002": "198.51.100.4",
    "SRV-APP-001": "198.51.100.10",
    "SRV-APP-002": "198.51.100.11",
    "SRV-APP-003": "198.51.100.12",
    "SRV-APP-004": "198.51.100.13",
    "SRV-APP-005": "198.51.100.14",
    "SRV-APP-006": "198.51.100.15",
    "198.51.100.20": "198.51.100.20",
    "SRV-APP-008": "198.51.100.16",
    "SRV-APP-009": "198.51.100.17",
    "SRV-TCP-001": "198.51.100.21",
    "SRV-TCP-002": "198.51.100.22",
    "SRV-BRIDGE-001": "198.51.100.23",
    "SRV-WEB-001": "198.51.100.40",
    "198.51.100.41": "198.51.100.41",
    "198.51.100.42": "198.51.100.42",
}

# servicegroup -> (servicetype, monitor, [(server, port, member state)])
SERVICEGROUPS = {
    "SG-DOH-001": ("SSL", "MON-ECV-001", [("SRV-DOH-001", 443, "DOWN"), ("SRV-DOH-002", 443, "DOWN")]),
    "SG-DNS-001": ("DNS", "MON-DNS-001", [("SRV-DNS-001", 53, "DOWN"), ("SRV-DNS-002", 53, "DOWN")]),
    "SG-APP-001": (
        "SSL",
        "MON-ECV-002",
        [
            ("SRV-APP-001", 443, "DOWN"),
            ("SRV-APP-002", 443, "DOWN"),
            ("SRV-APP-003", 443, "OUT OF SERVICE"),
            ("SRV-APP-004", 443, "UP"),
        ],
    ),
    "SG-APP-002": (
        "SSL",
        "MON-ECV-003",
        [("SRV-APP-005", 443, "UP"), ("SRV-APP-006", 443, "UP"), ("198.51.100.20", 443, "DOWN")],
    ),
    "SG-APP-003": (
        "SSL",
        "MON-HTTP-001",
        [("SRV-APP-008", 443, "OUT OF SERVICE"), ("SRV-APP-009", 443, "OUT OF SERVICE")],
    ),
    "SG-TCP-001": ("TCP", "tcp-default", [("SRV-TCP-001", 8443, "UP"), ("SRV-TCP-002", 8443, "UP")]),
    "SG-BRIDGE-001": ("SSL_BRIDGE", "tcp-default", [("SRV-BRIDGE-001", 443, "DOWN")]),
    "SG-SPARE-001": ("HTTP", "http", []),
}

# lb vserver -> servicegroup it is bound to
LB_TO_GROUP = {
    "LBV-DOH-001": "SG-DOH-001",
    "LBV-DNS-001": "SG-DNS-001",
    "LBV-APP-001": "SG-APP-001",
    "LBV-APP-002": "SG-APP-002",
    "LBV-OOS-001": "SG-APP-003",
    "LBV-TCP-001": "SG-TCP-001",
    "LBV-BRIDGE-001": "SG-BRIDGE-001",
}

# service -> (server, servicetype, port, state, monitor)
SERVICES = {
    "SVC-WEB-001": ("SRV-WEB-001", "HTTP", 80, "UP", "http"),
    "SVC-SYS-001": ("198.51.100.41", "UDP", 514, "DOWN", "ping-default"),
    "SVC-SPARE-001": ("198.51.100.42", "HTTP", 8080, "DOWN", "tcp-default"),
}

# lb vserver -> service it is bound to
LB_TO_SERVICE = {"LBV-WEB-001": "SVC-WEB-001", "LBV-UDP-001": "SVC-SYS-001"}

# The internal services of the appliance itself, as it binds its own
# certificate to them.
INTERNAL_SERVICES = [
    "nsrpcs-127.0.0.1-3008",
    "nshttps-127.0.0.1-443",
    "nshttps-certauth-127.0.0.1-8443",
    "nsrpcs-::1l-3008",
    "nshttps-::1l-443",
    "nshttps-certauth-::1l-8443",
    "nskrpcs-127.0.0.1-3009",
    "nsrnatsip-127.0.0.1-5061",
]

# certificate -> (days to expiration, certificate type, ssl vservers it is bound to)
CERTIFICATES = {
    "ns-server-certificate": (3650, ["SRVR_CERT"], []),
    "ns-sftrust-certificate": (999000, ["CLNT_CERT", "SRVR_CERT"], []),
    "CERT-DOH-001": (400, ["SRVR_CERT"], ["LBV-DOH-001"]),
    "CERT-DOH-002": (410, ["SRVR_CERT"], ["LBV-DOH-002", "CSV-DOH-001", "CSV-DOH-002"]),
    "CERT-NODOH-001": (420, ["SRVR_CERT"], ["LBV-NODOH-001"]),
    "CERT-WEB-001": (500, ["SRVR_CERT"], ["CSV-WEB-001", "LBV-APP-001", "LBV-APP-002"]),
    "CERT-WEB-002": (510, ["SRVR_CERT"], ["CSV-WEB-002", "CSV-EMPTY-001", "LBV-OOS-001"]),
    "CERT-SPARE-001": (600, ["SRVR_CERT"], []),
    "CERT-CA-001": (3000, ["ROOT_CERT"], []),
}

SSL_PROFILES = [
    # name, type, tls12, tls13, cipher aliases
    ("ns_default_ssl_profile_frontend", "FrontEnd", "ENABLED", "DISABLED", ["CIPHERGRP-LAB-001", "DEFAULT"]),
    ("ns_default_ssl_profile_backend", "BackEnd", "ENABLED", "DISABLED", ["DEFAULT_BACKEND"]),
    ("SSLPROF-FE-001", "FrontEnd", "ENABLED", "ENABLED", ["CIPHERGRP-LAB-001"]),
]

CIPHER_GROUPS = {
    "CIPHERGRP-LAB-001": [
        "TLS1.2-ECDHE-RSA-AES256-GCM-SHA384",
        "TLS1.2-ECDHE-RSA-AES128-GCM-SHA256",
    ],
}

# Built-in monitors of the appliance, plus the user monitors of this config.
BUILTIN_MONITORS = [
    ("ping-default", "PING"),
    ("tcp-default", "TCP"),
    ("arp", "ARP"),
    ("nd6", "ND6"),
    ("ping", "PING"),
    ("tcp", "TCP"),
    ("http", "HTTP"),
    ("tcp-ecv", "TCP-ECV"),
    ("http-ecv", "HTTP-ECV"),
    ("udp-ecv", "UDP-ECV"),
    ("dns", "DNS"),
    ("dns-tcp", "DNS-TCP"),
    ("https", "HTTP"),
    ("tcps", "TCP"),
    ("https-ecv", "HTTP-ECV"),
    ("sta", "CITRIX-STA-SERVICE"),
]
USER_MONITORS = [
    ("MON-ECV-001", "HTTP-ECV"),
    ("MON-ECV-002", "HTTP-ECV"),
    ("MON-ECV-003", "HTTP-ECV"),
    ("MON-HTTP-001", "HTTP"),
    ("MON-DNS-001", "DNS"),
    ("MON-LDAP-001", "LDAP"),
]

HTTP_PROFILES = [
    ("nshttp_default_profile", "DISABLED", True),
    ("nshttp_default_strict_validation", "DISABLED", True),
    ("HTTPPROF-H2-001", "ENABLED", False),
]

REWRITE_ACTIONS = [
    ("NOREWRITE", "noop", True),
    ("RESET", "noop", True),
    ("DROP", "noop", True),
    ("RWACT-001", "insert_http_header", False),
    ("RWACT-002", "delete_http_header", False),
]
REWRITE_POLICIES = [
    ("RWPOL-001", "HTTP.REQ.IS_VALID", "RWACT-001"),
    ("RWPOL-002", "true", "RWACT-002"),
]
RESPONDER_POLICIES = [("RSPOL-001", "HTTP.REQ.IS_VALID.NOT", "RESET")]

CMD_POLICIES = [
    ("operator", "ALLOW", "(^show\\s+lb\\s+.*)|(^stat\\s+.*)"),
    ("read-only", "ALLOW", "(^show\\s+(?!system).*)|(^stat\\s+.*)"),
    ("network", "ALLOW", "^(show|set|add|rm)\\s+(vlan|route|interface)\\s+.*"),
    ("sysadmin", "ALLOW", "^(?!shell)(?!set\\s+system).*"),
    ("superuser", "ALLOW", ".*"),
]

# ---------------------------------------------------------------------------
# Rows.
# ---------------------------------------------------------------------------


def _lb_row(name, kind, address, port, state, doh, _how, profile) -> dict:
    up = state == "UP"
    return {
        "name": name,
        "insertvserveripport": "OFF",
        "ipv46": address,
        "ippattern": "0.0.0.0",
        "ipmask": "*",
        "listenpolicy": "NONE",
        "port": port,
        "range": "1",
        "servicetype": kind,
        "type": "ADDRESS",
        "curstate": state,
        "effectivestate": "UP" if up else "DOWN",
        "status": 3 if up else 1,
        "lbrrreason": 0,
        "cachetype": "SERVER",
        "authentication": "OFF",
        "authn401": "OFF",
        "somethod": "NONE",
        "sopersistence": "DISABLED",
        "redirect": "",
        "lbmethod": "LEASTCONNECTION",
        "health": "100" if up else "0",
        "persistencetype": "NONE",
        "timeout": 2,
        "sessionless": "DISABLED",
        "version": 0,
        "dnsoverhttps": doh,
        "httpprofilename": profile if profile else "",
        "td": "0",
    }


def _cs_row(name, address, doh, _how, default_lb) -> dict:
    row = {
        "name": name,
        "ip": address,
        "ipv46": address,
        "port": 443,
        "range": "1",
        "servicetype": "SSL",
        "type": "CONTENT",
        "curstate": "UP",
        "stateupdate": "DISABLED",
        "status": 1,
        "cachetype": "SERVER",
        "authentication": "OFF",
        "somethod": "NONE",
        "persistencetype": "NONE",
        "timeout": 2,
        "version": 0,
        "dnsoverhttps": doh,
        "td": "0",
    }
    if default_lb:
        row["lbvserver"] = default_lb
    return row


def _member_rows(group: str) -> list[dict]:
    _kind, _monitor, members = SERVICEGROUPS[group]
    rows = []
    for server, port, state in members:
        rows.append(
            {
                "servicegroupname": group,
                "ip": SERVERS[server],
                "port": port,
                "svrstate": state,
                "statechangetimesec": APPLIANCE_TIME,
                "weight": "1",
                "servername": server,
                "customserverid": "None",
                "serverid": "0",
                "state": "DISABLED" if state == "OUT OF SERVICE" else "ENABLED",
                "hashid": "0",
                "graceful": "NO",
                "delay": 0,
                "orderstr": "Default",
            }
        )
    return rows


def _group_state(group: str) -> str:
    states = [state for _server, _port, state in SERVICEGROUPS[group][2]]
    if not states:
        return "DOWN"
    if "UP" in states:
        return "UP"
    if all(state == "OUT OF SERVICE" for state in states):
        return "OUT OF SERVICE"
    return "DOWN"


def objects() -> dict[str, object]:
    """Per resource the payload under its property name, or None for an
    empty read. Ordered as the collector fetches them."""
    lb = [_lb_row(*row) for row in LB_VSERVERS]
    cs = [_cs_row(*row) for row in CS_VSERVERS]
    certs = []
    for certkey, (days, kinds, _bound) in CERTIFICATES.items():
        builtin = certkey.startswith("ns-")
        stem = certkey.split("-certificate")[0] if builtin else certkey.lower()
        issuer = " CN=LAB Synthetic Root CA,O=Example Lab" if not builtin else " CN=default LAB,O=Example Lab"
        subject = (
            issuer if certkey in ("CERT-CA-001",) or builtin else f" CN={certkey.lower()}.lab.example,O=Example Lab"
        )
        certs.append(
            {
                "certkey": certkey,
                "cert": f"{stem}.cert",
                "key": f"{stem}.key",
                "inform": "PEM",
                "signaturealg": "sha256WithRSAEncryption",
                "certificatetype": kinds,
                "serial": "01",
                "issuer": issuer,
                "daystoexpiration": days,
                "subject": subject,
                "publickey": "rsaEncryption",
                "publickeysize": 2048,
                "version": 3,
                "priority": "0",
                "status": "Valid",
                "passcrypt": "",
                "data": "0",
                "expirymonitor": "DISABLED",
                "feature": "SSL",
            }
        )
    vips = [row[2] for row in LB_VSERVERS] + [row[1] for row in CS_VSERVERS]
    nsip = [
        _nsip_row(NSIP, "NSIP", "ENABLED"),
        _nsip_row(SNIP, "SNIP", "DISABLED"),
        _nsip_row(SNIP_BACKEND, "SNIP", "DISABLED"),
    ] + [_nsip_row(address, "VIP", "DISABLED") for address in vips]
    ssl_names = [row[0] for row in LB_VSERVERS if row[1] == "SSL"] + [row[0] for row in CS_VSERVERS]
    return {
        "config/nsversion": {"installedversion": False, "version": VERSION, "mode": "1"},
        "config/lbvserver": lb,
        "config/csvserver": cs,
        "config/sslcertkey": certs,
        "config/nshardware": {
            "hwdescription": "NetScaler Virtual Appliance",
            "sysid": "450070",
            "manufactureday": 1,
            "manufacturemonth": 1,
            "manufactureyear": 2020,
            "cpufrequncy": 2000,
            "hostid": 100000001,
            "host": "020000000001",
            "serialno": "LABSERIAL1",
            "encodedserialno": "00000000000000000000",
            "netscaleruuid": "00000000-0000-0000-0000-020000000001",
        },
        "config/hanode": [
            {
                "id": "0",
                "ipaddress": NSIP,
                "flags": "129",
                "hastatus": "UP",
                "state": "Primary",
                "hasync": "ENABLED",
                "haprop": "ENABLED",
                "enaifaces": "0/1 1/1",
                "netmask": "0.0.0.0",
                "inc": "DISABLED",
                "ssl2": "NOT PRESENT",
                "hellointerval": 200,
                "deadinterval": 3,
                "failsafe": "ON",
                "maxflips": "0",
                "maxfliptime": "0",
                "curflips": "0",
                "syncstatusstrictmode": "DISABLED",
                "secureheartbeatstate": "DISABLED",
            }
        ],
        "config/vpnvserver": None,
        "config/servicegroup": [
            {
                "servicegroupname": group,
                "servicetype": kind,
                "td": "0",
                "cachetype": "SERVER",
                "cip": "DISABLED",
                "usip": "NO",
                "useproxyport": "YES",
                "cmp": "NO",
                "state": "ENABLED",
                "svrstate": _group_state(group),
                "ip": "0.0.0.0",
                "monstate": "ENABLED",
                "healthmonitor": "YES",
                "autoscale": "DISABLED",
                "downstateflush": "ENABLED",
            }
            for group, (kind, _monitor, _members) in SERVICEGROUPS.items()
        ],
        "config/service": [
            {
                "name": service,
                "servername": server,
                "policyname": server,
                "servicetype": kind,
                "port": port,
                "gslb": "NONE",
                "cachetype": "SERVER",
                "cip": "DISABLED",
                "usip": "NO",
                "useproxyport": "YES",
                "cmp": "NO",
                "svrstate": state,
                "ipaddress": SERVERS[server],
                "monstate": "ENABLED",
                "healthmonitor": "YES",
                "td": "0",
                "feature": "LB",
            }
            for service, (server, kind, port, state, _monitor) in SERVICES.items()
        ],
        "config/server": [
            {
                "name": name,
                "ipaddress": address,
                "state": "ENABLED",
                "translationip": "0.0.0.0",
                "translationmask": "0.0.0.0",
                "port": 0,
                "svrstate": "Unknown",
                "ipv6address": "NO",
                "td": "0",
                "usip": "NO",
                "cmp": "NO",
            }
            for name, address in SERVERS.items()
        ],
        "config/lbmonitor": [
            {
                "monitorname": name,
                "type": kind,
                "interval": 5,
                "units3": "SEC",
                "resptimeout": 2,
                "units4": "SEC",
                "retries": 3,
                "state": "ENABLED",
                "action": "Not applicable",
                "secure": "YES" if name.startswith("MON-ECV") else "NO",
            }
            for name, kind in BUILTIN_MONITORS + USER_MONITORS
        ],
        "config/cspolicy": [
            {
                "policyname": policy,
                "rule": f'HTTP.REQ.HOSTNAME.EQ("{target.lower()}.lab.example")',
                "action": action,
                "vstype": "2",
                "hits": "0",
                "bindhits": "0",
                "priority": "0",
                "activepolicy": True,
            }
            for policy, action, target, _cs, _priority in CS_POLICIES
        ],
        "config/csaction": [
            {
                "name": action,
                "targetlbvserver": target,
                "hits": "0",
                "referencecount": "1",
                "undefhits": "0",
                "feature": "CS",
            }
            for _policy, action, target, _cs, _priority in CS_POLICIES
        ],
        "config/nsip": nsip,
        "config/systemcmdpolicy": [
            {"policyname": name, "action": action, "cmdspec": spec, "feature": "SYSTEM"}
            for name, action, spec in CMD_POLICIES
        ],
        "config/sslparameter": {
            "quantumsize": "8192",
            "crlmemorysizemb": "256",
            "strictcachecks": "NO",
            "denysslreneg": "ALL",
            "insertionencoding": "Unicode",
            "defaultprofile": "ENABLED",
            "hybridfipsmode": "DISABLED",
        },
        "config/systemparameter": {
            "rbaonresponse": "ENABLED",
            "timeout": 900,
            "maxclient": "40",
            "localauth": "ENABLED",
            "minpasswordlen": "8",
            "strongpassword": "enablelocal",
            "restrictedtimeout": "DISABLED",
            "fipsusermode": "DISABLED",
            "forcepasswordchange": "ENABLED",
            "basicauth": "DISABLED",
            "maxsessionperuser": "20",
            "wafprotection": ["DEFAULT"],
        },
        "config/authenticationldapaction": [
            {
                "name": "LDAP-ACT-001",
                "serverip": "203.0.113.20",
                "serverport": 636,
                "sectype": "SSL",
                "authentication": "ENABLED",
                "authtimeout": "3",
            }
        ],
        "config/aaaparameter": {
            "defaultauthtype": "LOCAL",
            "maxloginattempts": "3",
            "failedlogintimeout": 15,
            "persistentloginattempts": "DISABLED",
            "feature": "SYSTEM",
            "loginencryption": "DISABLED",
            "httponlycookie": "ENABLED",
            "wafprotection": ["AUTH", "VPN"],
        },
        "config/nsparam": {
            "maxconn": "0",
            "maxreq": "0",
            "cip": "DISABLED",
            "cookieversion": "0",
            "securecookie": "ENABLED",
            "timezone": "CoordinatedUniversalTime",
            "useproxyport": "ENABLED",
            "internaluserlogin": "ENABLED",
            "proxyprotocol": "DISABLED",
        },
        "config/sslprofile": [
            {
                "name": name,
                "dh": "DISABLED",
                "ersa": "DISABLED",
                "sessreuse": "ENABLED",
                "sesstimeout": "120",
                "clientauth": "DISABLED",
                "sslredirect": "DISABLED",
                "ssl3": "DISABLED",
                "tls1": "DISABLED",
                "tls11": "DISABLED",
                "tls12": tls12,
                "tls13": tls13,
                "snienable": "DISABLED",
                "ocspstapling": "DISABLED",
                "serverauth": "DISABLED",
                "denysslreneg": "FRONTEND_CLIENT" if kind == "FrontEnd" else "ALL",
                "snicert": False,
                "sslprofiletype": kind,
                "hsts": "DISABLED",
                "maxage": "0",
                "feature": "SSL",
            }
            for name, kind, tls12, tls13, _aliases in SSL_PROFILES
        ],
        "config/auditsyslogparams": {
            "serverip": "127.0.0.1",
            "serverport": 514,
            "dateformat": "MMDDYYYY",
            "loglevel": ["ALL"],
            "logfacility": "LOCAL0",
            "tcp": "NONE",
            "timezone": "GMT_TIME",
            "feature": "SYSTEM",
            "lsn": "DISABLED",
            "dns": "DISABLED",
        },
        "config/rewritepolicy": [
            {
                "name": name,
                "rule": rule,
                "action": action,
                "hits": "0",
                "undefhits": "0",
                "activepolicy": 1,
                "priority": "0",
                "isdefault": False,
                "feature": "REWRITE",
            }
            for name, rule, action in REWRITE_POLICIES
        ],
        "config/rewriteaction": [
            {
                "name": name,
                "type": kind,
                "hits": "0",
                "undefhits": "0",
                "referencecount": "1",
                "isdefault": default,
                "feature": "SYSTEM" if default else "REWRITE",
            }
            for name, kind, default in REWRITE_ACTIONS
        ],
        "config/responderpolicy": [
            {
                "name": name,
                "rule": rule,
                "action": action,
                "hits": "0",
                "undefhits": "0",
                "activepolicy": 1,
                "priority": "0",
                "feature": "RESPONDER",
            }
            for name, rule, action in RESPONDER_POLICIES
        ],
        "config/nsfeature": {
            "feature": ["WL", "SP", "LB", "CS", "SSL", "REWRITE", "RESPONDER"],
            "wl": True,
            "sp": True,
            "lb": True,
            "cs": True,
            "cr": False,
            "cmp": False,
            "ssl": True,
            "gslb": False,
            "aaa": False,
            "rewrite": True,
            "appfw": False,
            "responder": True,
            "appflow": False,
            "appqoe": False,
            "feo": False,
            "lsn": False,
            "rep": False,
            "videooptimization": False,
            "bot": False,
        },
        "config/nslicense": {
            "wl": True,
            "sp": True,
            "lb": True,
            "cs": True,
            "cr": True,
            "cmp": True,
            "ssl": True,
            "gslb": True,
            "aaa": True,
            "rewrite": True,
            "appfw": True,
            "responder": True,
            "appflow": True,
            "cluster": True,
            "appqoe": True,
            "isstandardlic": False,
            "isenterpriselic": False,
            "isplatinumlic": True,
            "issgwylic": False,
            "isswglic": False,
            "feo": True,
            "lsn": True,
            "licensingmode": "EXPRESS",
            "rep": True,
            "urlfiltering": False,
            "videooptimization": True,
            "bot": True,
        },
        "config/nslicenseserver": None,
        "config/systemuser": [
            {
                "username": "nsroot",
                "externalauth": "DISABLED",
                "logging": "ENABLED",
                "timeout": 900,
                "allowedmanagementinterface": ["CLI", "API"],
            },
            {
                "username": "labadmin",
                "externalauth": "DISABLED",
                "logging": "ENABLED",
                "maxsession": "4",
                "timeout": 900,
                "allowedmanagementinterface": ["CLI"],
            },
        ],
        "config/mgmtparam": "NOT_SUPPORTED",
        "config/ntpserver": None,
        "config/dnsnameserver": None,
        "config/snmpcommunity": "EMPTY_WITHOUT_FILE",
        "config/snmpmanager": [
            {"ipaddress": "203.0.113.40", "netmask": "255.255.255.255", "ip": "0.0.0.0", "domain": "203.0.113.40"}
        ],
        "config/auditsyslogpolicy": [
            {
                "name": "SYSLOGPOL-001",
                "rule": "true",
                "action": "SYSLOGACT-001",
                "activepolicy": "0",
                "priority": "0",
                "feature": "SYSTEM",
                "expressiontype": "Advanced Policy",
            }
        ],
        "config/auditsyslogaction": [
            {
                "name": "SYSLOGACT-001",
                "serverip": "203.0.113.30",
                "ip": "203.0.113.30",
                "serverport": 514,
                "loglevel": ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE"],
                "dateformat": "MMDDYYYY",
                "logfacility": "LOCAL0",
                "tcp": "NONE",
                "timezone": "GMT_TIME",
                "feature": "SYSTEM",
                "lsn": "DISABLED",
                "transport": "UDP",
                "dns": "DISABLED",
            }
        ],
        "config/appfwpolicy": None,
        "config/appfwprofile": [
            {"name": "APPFW-LAB-001", "type": ["HTML"], "state": "DISABLED", "builtin": False},
            {"name": "APPFW_BYPASS", "type": ["HTML", "XML", "JSON"], "state": "DISABLED", "builtin": True},
            {"name": "APPFW_BLOCK", "type": ["HTML", "XML", "JSON"], "state": "DISABLED", "builtin": True},
        ],
        "config/botpolicy": None,
        "config/botprofile": [{"name": "BOT-LAB-001", "errorurl": "/", "feature": "SYSTEM"}],
        "config/botsettings": {
            "defaultprofile": "BOT-LAB-001",
            "sessiontimeout": "900",
            "signatureautoupdate": "OFF",
            "feature": "SYSTEM",
        },
        "config/nshttpprofile": [
            {
                "name": name,
                "dropinvalreqs": "ENABLED" if builtin else "DISABLED",
                "markhttp09inval": "DISABLED",
                "conmultiplex": "ENABLED",
                "websocket": "DISABLED",
                "http2": http2,
                "builtin": ["IMMUTABLE"] if builtin else [],
                "feature": "SYSTEM",
            }
            for name, http2, builtin in HTTP_PROFILES
        ],
        "config/sslvserver": [
            {
                "vservername": name,
                "cleartextport": 0,
                "service": "0",
                "quicflag": False,
                "sslprofile": "SSLPROF-FE-001" if name == "LBV-APP-001" else "ns_default_ssl_profile_frontend",
            }
            for name in ssl_names
        ],
        "config/authenticationvserver": None,
        "config/reputationsettings": {"proxyserver": " ", "proxyport": "0"},
        "config/botglobal_botpolicy_binding": None,
        "config/rewriteglobal_rewritepolicy_binding": None,
        "config/vpnvserver_botpolicy_binding": "NOT_SUPPORTED",
        "config/lbvserver_rewritepolicy_binding?bulkbindings=yes": [
            {
                "name": "LBV-APP-001",
                "policyname": "RWPOL-001",
                "stateflag": "536936449",
                "priority": "100",
                "gotopriorityexpression": "END",
                "bindpoint": "REQUEST",
                "invoke": False,
            }
        ],
        "config/lbvserver_botpolicy_binding?bulkbindings=yes": None,
        "config/csvserver_rewritepolicy_binding?bulkbindings=yes": [
            {
                "name": "CSV-WEB-002",
                "policyname": "RWPOL-001",
                "stateflag": "536936449",
                "priority": "100",
                "gotopriorityexpression": "END",
                "bindpoint": "REQUEST",
                "invoke": False,
            },
            {
                "name": "CSV-WEB-002",
                "policyname": "RWPOL-002",
                "stateflag": "536936449",
                "priority": "100",
                "gotopriorityexpression": "NEXT",
                "bindpoint": "RESPONSE",
                "invoke": False,
            },
        ],
        "config/csvserver_botpolicy_binding?bulkbindings=yes": None,
        "config/vpnvserver_rewritepolicy_binding?bulkbindings=yes": None,
        "config/vpnvserver_appfwpolicy_binding?bulkbindings=yes": None,
        "config/authenticationvserver_appfwpolicy_binding?bulkbindings=yes": "NOT_SUPPORTED",
        "config/systemfile?args=filename:iprep.log,filelocation:%2Fvar%2Flog": "NOT_SUPPORTED",
    }


def _nsip_row(address: str, kind: str, mgmt: str) -> dict:
    management = kind == "NSIP"
    return {
        "ipaddress": address,
        "td": "0",
        "type": kind,
        "netmask": "255.255.255.0" if kind != "VIP" else "255.255.255.255",
        "arp": "ENABLED",
        "icmp": "ENABLED",
        "vserver": "ENABLED" if kind == "VIP" else "DISABLED",
        "telnet": "DISABLED",
        "ssh": "ENABLED" if management else "DISABLED",
        "gui": "SECUREONLY" if management else "DISABLED",
        "snmp": "ENABLED" if management else "DISABLED",
        "ftp": "DISABLED",
        "mgmtaccess": mgmt,
        "state": "ENABLED",
        "iptype": [kind],
    }


# ---------------------------------------------------------------------------
# Bindings.
# ---------------------------------------------------------------------------


def _aggregate(resource: str, parent_resource: str, parent_key: str, documents: list[tuple[str, dict]]) -> dict:
    return {
        "bindingResource": resource,
        "parentResource": parent_resource,
        "parentKey": parent_key,
        "shape": "aggregate",
        "parents": [
            {"parentName": name, "outcome": "OK", "data": {resource: document}} for name, document in documents
        ],
    }


def _list(resource: str, parent_resource: str, parent_key: str, parents: list[tuple[str, list[dict] | None]]) -> dict:
    return {
        "bindingResource": resource,
        "parentResource": parent_resource,
        "parentKey": parent_key,
        "shape": "list",
        "parents": [
            {"parentName": name, "outcome": "OK", "data": {resource: rows}}
            if rows
            else {"parentName": name, "outcome": "EMPTY", "data": None}
            for name, rows in parents
        ],
    }


def bindings() -> dict[str, dict]:
    lb_documents = []
    for name, _kind, _address, _port, _state, _doh, _how, _profile in LB_VSERVERS:
        document: dict = {"name": name}
        group = LB_TO_GROUP.get(name)
        service = LB_TO_SERVICE.get(name)
        if group:
            document["lbvserver_servicegroup_binding"] = [
                {"name": name, "servicegroupname": group, "stateflag": "536936464", "servicename": group}
            ]
            document["lbvserver_servicegroupmember_binding"] = [
                {
                    "name": name,
                    "servicegroupname": group,
                    "ipv46": SERVERS[server],
                    "port": port,
                    "servicetype": SERVICEGROUPS[group][0],
                    "curstate": state,
                    "weight": "1",
                    "dynamicweight": "0",
                    "orderstr": "None",
                }
                for server, port, state in SERVICEGROUPS[group][2]
            ]
        if service:
            server, service_kind, port, state, _monitor = SERVICES[service]
            document["lbvserver_service_binding"] = [
                {
                    "name": name,
                    "servicename": service,
                    "stateflag": "536936451",
                    "ipv46": server,
                    "port": port,
                    "servicetype": service_kind,
                    "curstate": state,
                    "weight": "1",
                    "dynamicweight": "0",
                    "vsvrbindsvcip": server,
                    "vsvrbindsvcport": port,
                    "orderstr": "None",
                }
            ]
        if name == "LBV-WEB-001":
            document["lbvserver_responderpolicy_binding"] = [
                {
                    "name": name,
                    "policyname": "RSPOL-001",
                    "stateflag": "536936450",
                    "priority": "100",
                    "gotopriorityexpression": "END",
                    "invoke": False,
                    "bindpoint": "REQUEST",
                }
            ]
        if name == "LBV-APP-001":
            document["lbvserver_rewritepolicy_binding"] = [
                {
                    "name": name,
                    "policyname": "RWPOL-001",
                    "stateflag": "536936449",
                    "priority": "100",
                    "gotopriorityexpression": "END",
                    "bindpoint": "REQUEST",
                    "invoke": False,
                }
            ]
        lb_documents.append((name, document))

    cs_documents = []
    for name, _address, _doh, _how, default_lb in CS_VSERVERS:
        document = {"name": name}
        policies = [row for row in CS_POLICIES if row[3] == name]
        if policies:
            document["csvserver_cspolicy_binding"] = [
                {
                    "name": name,
                    "policyname": policy,
                    "stateflag": "536937473",
                    "priority": str(priority),
                    "invoke": False,
                    "hits": "0",
                    "pipolicyhits": "0",
                    "rule": "true",
                }
                for policy, _action, _target, _cs, priority in policies
            ]
        if default_lb:
            document["csvserver_lbvserver_binding"] = [
                {"name": name, "lbvserver": default_lb, "stateflag": "536937476", "hits": "0"}
            ]
        if name == "CSV-WEB-002":
            document["csvserver_rewritepolicy_binding"] = [
                {
                    "name": name,
                    "policyname": "RWPOL-001",
                    "stateflag": "536936449",
                    "priority": "100",
                    "gotopriorityexpression": "END",
                    "bindpoint": "REQUEST",
                    "invoke": False,
                },
                {
                    "name": name,
                    "policyname": "RWPOL-002",
                    "stateflag": "536936449",
                    "priority": "100",
                    "gotopriorityexpression": "NEXT",
                    "bindpoint": "RESPONSE",
                    "invoke": False,
                },
            ]
            document["csvserver_responderpolicy_binding"] = [
                {
                    "name": name,
                    "policyname": "RSPOL-001",
                    "stateflag": "536936450",
                    "priority": "100",
                    "gotopriorityexpression": "END",
                    "invoke": False,
                    "bindpoint": "REQUEST",
                }
            ]
        cs_documents.append((name, document))

    group_documents = []
    for group, (_kind, monitor, members) in SERVICEGROUPS.items():
        document = {"servicegroupname": group}
        document["servicegroup_lbmonitor_binding"] = [
            {
                "servicegroupname": group,
                "monitor_name": monitor,
                "monweight": "0",
                "monstate": "ENABLED",
                "weight": "1",
                "state": "ENABLED",
                "passive": False,
            }
        ]
        if members:
            document["servicegroup_servicegroupmember_binding"] = _member_rows(group)
            document["servicegroup_servicegroupentitymonbindings_binding"] = [
                {
                    "servicegroupname": group,
                    "servicegroupentname2": f"{group}?{server}?{port}",
                    "monitor_name": monitor,
                    "monitor_state": "UP" if state == "UP" else "DOWN",
                    "passive": False,
                    "lastresponse": "Success - synthetic probe." if state == "UP" else "Failure - synthetic probe.",
                    "responsetime": "0",
                }
                for server, port, state in members
            ]
        group_documents.append((group, document))

    service_documents = []
    for service, (_server, _kind, _port, state, monitor) in SERVICES.items():
        service_documents.append(
            (
                service,
                {
                    "name": service,
                    "service_lbmonitor_binding": [
                        {
                            "name": service,
                            "monitor_name": monitor,
                            "stateflag": "7168",
                            "monstate": "ENABLED",
                            "monitor_state": "UP" if state == "UP" else "DOWN",
                            "weight": "1",
                            "passive": False,
                        }
                    ],
                },
            )
        )

    monitor_documents = [(name, {"monitorname": name}) for name, _kind in BUILTIN_MONITORS + USER_MONITORS]

    cert_documents = []
    for certkey, (_days, _kinds, bound) in CERTIFICATES.items():
        document = {"certkey": certkey}
        if certkey == "ns-server-certificate":
            document["sslcertkey_service_binding"] = [
                {"certkey": certkey, "servicename": service, "data": str(index), "version": 2, "stateflag": "4"}
                for index, service in enumerate(INTERNAL_SERVICES, 1)
            ]
        if bound:
            document["sslcertkey_sslvserver_binding"] = [
                {"certkey": certkey, "servername": vserver, "data": str(index), "version": 2, "stateflag": "2"}
                for index, vserver in enumerate(bound, 1)
            ]
        cert_documents.append((certkey, document))

    ssl_names = [row[0] for row in LB_VSERVERS if row[1] == "SSL"] + [row[0] for row in CS_VSERVERS]
    cert_of = {}
    for certkey, (_days, _kinds, bound) in CERTIFICATES.items():
        for vserver in bound:
            cert_of.setdefault(vserver, []).append(certkey)
    vserver_certs = [
        (
            name,
            [
                {
                    "vservername": name,
                    "certkeyname": certkey,
                    "stateflag": "2",
                    "cleartextport": 0,
                    "ca": False,
                    "snicert": False,
                }
                for certkey in cert_of.get(name, [])
            ]
            or None,
        )
        for name in ssl_names
    ]

    return {
        "lbvserver_binding": _aggregate("lbvserver_binding", "lbvserver", "name", lb_documents),
        "csvserver_binding": _aggregate("csvserver_binding", "csvserver", "name", cs_documents),
        "servicegroup_binding": _aggregate("servicegroup_binding", "servicegroup", "servicegroupname", group_documents),
        "service_binding": _aggregate("service_binding", "service", "name", service_documents),
        "lbmonitor_binding": _aggregate("lbmonitor_binding", "lbmonitor", "monitorname", monitor_documents),
        "sslcertkey_binding": _aggregate("sslcertkey_binding", "sslcertkey", "certkey", cert_documents),
        "sslvserver_sslcertkey_binding": _list(
            "sslvserver_sslcertkey_binding", "sslvserver", "vservername", vserver_certs
        ),
        "sslvserver_sslciphersuite_binding": _list(
            "sslvserver_sslciphersuite_binding", "sslvserver", "vservername", [(name, None) for name in ssl_names]
        ),
        "sslvserver_ecccurve_binding": _list(
            "sslvserver_ecccurve_binding", "sslvserver", "vservername", [(name, None) for name in ssl_names]
        ),
        "sslprofile_sslcipher_binding": _list(
            "sslprofile_sslcipher_binding",
            "sslprofile",
            "name",
            [
                (
                    name,
                    [
                        {
                            "name": name,
                            "cipheraliasname": alias,
                            "stateflag": "8",
                            "cipherpriority": str(priority),
                            "description": "User Created Cipher Group"
                            if alias.startswith("CIPHERGRP-")
                            else "Predefined Cipher Alias",
                        }
                        for priority, alias in enumerate(aliases, 1)
                    ],
                )
                for name, _kind, _tls12, _tls13, aliases in SSL_PROFILES
            ],
        ),
        "sslcipher_binding": _list(
            "sslcipher_binding",
            "sslcipher",
            "ciphergroupname",
            [
                (
                    group,
                    [
                        {
                            "ciphergroupname": group,
                            "sslcipher_sslciphersuite_binding": [
                                {
                                    "ciphergroupname": group,
                                    "ciphername": cipher,
                                    "stateflag": "512",
                                    "cipherpriority": str(priority),
                                    "peflags": "4",
                                }
                                for priority, cipher in enumerate(ciphers, 1)
                            ],
                        }
                    ],
                )
                for group, ciphers in CIPHER_GROUPS.items()
            ],
        ),
    }


# ---------------------------------------------------------------------------
# The running and the saved config.
# ---------------------------------------------------------------------------

ECV_RECV = r"-recv q/{\"Status\":0}/"


def config_body() -> list[str]:
    """The configuration lines both config texts share, in the order the
    appliance writes them."""
    lines = [
        f"set ns config -IPAddress {NSIP} -netmask 255.255.255.0",
        "enable ns feature WL SP LB CS SSL REWRITE RESPONDER",
        "enable ns mode FR L3 Edge USNIP PMTUD",
        f"set system parameter -minpasswordlen {MARKER} -strongpassword {MARKER} -forcePasswordChange {MARKER}",
        f"set system user nsroot {MARKER} -encrypted -externalAuth DISABLED -lastpwdchangetimestamp {MARKER}",
        f"add system user labadmin {MARKER} -encrypted -externalAuth DISABLED -logging ENABLED -maxsession 4"
        f" -allowedManagementInterface CLI -lastpwdchangetimestamp {MARKER}",
        "add system group LAB-ADMIN-GRP",
        "set HA node -failSafe ON",
        f"add ns ip {SNIP} 255.255.255.0 -vServer DISABLED",
        f"add ns ip {SNIP_BACKEND} 255.255.255.0 -vServer DISABLED",
        "add snmp manager 203.0.113.40",
        f"add snmp trap generic 203.0.113.41 -communityName {MARKER}",
        "add audit syslogAction SYSLOGACT-001 203.0.113.30 -loglevel EMERGENCY ALERT CRITICAL ERROR WARNING NOTICE",
        "add audit syslogPolicy SYSLOGPOL-001 true SYSLOGACT-001",
        f"set ns encryptionParams -method AES256 -keyValue {MARKER} -encrypted -encryptmethod ENCMTHD_4 -kek"
        f" -suffix {KEK_SUFFIX}",
        f"set ns rpcNode {NSIP} -password {MARKER} -encrypted -encryptmethod ENCMTHD_4 -kek -suffix {KEK_SUFFIX}"
        f" -srcIP {NSIP}",
        "add ns httpProfile HTTPPROF-H2-001 -http2 ENABLED",
        "add dns profile DNSPROF-001 -recursiveResolution ENABLED",
        "add authentication ldapAction LDAP-ACT-001 -serverIP 203.0.113.20 -serverPort 636"
        ' -ldapBase "dc=lab,dc=example" -ldapBindDn "cn=svc-lab,dc=lab,dc=example"'
        f" -ldapBindDnPassword {MARKER} -encrypted -encryptmethod ENCMTHD_4 -kek -suffix {KEK_SUFFIX}"
        " -ldapLoginName sAMAccountName -secType SSL",
    ]
    for name, address in SERVERS.items():
        if name != address:
            lines.append(f"add server {name} {address}")
        else:
            lines.append(f"add server {address} {address}")
    for service, (server, kind, port, _state, _monitor) in SERVICES.items():
        lines.append(f"add service {service} {server} {kind} {port} -gslb NONE -maxClient 0 -maxReq 0 -usip NO")
    for group, (kind, _monitor, _members) in SERVICEGROUPS.items():
        lines.append(f"add serviceGroup {group} {kind} -maxClient 0 -maxReq 0 -usip NO -useproxyport YES")
    lines.append(
        f'add lb monitor MON-ECV-001 HTTP-ECV -send "GET /lab/health" {ECV_RECV} -LRTM DISABLED -interval 30'
        " -resptimeout 10 -secure YES"
    )
    lines.append(
        f'add lb monitor MON-ECV-002 HTTP-ECV -send "GET /lab/health" {ECV_RECV} -LRTM DISABLED -interval 30'
        " -resptimeout 10 -secure YES"
    )
    lines.append(
        f'add lb monitor MON-ECV-003 HTTP-ECV -send "GET /lab/health" {ECV_RECV} -LRTM DISABLED -interval 30'
        r" -resptimeout 10 -destPort 443 -secure YES -trofsstring q/{\"Status\":1}/"
    )
    lines.append('add lb monitor MON-HTTP-001 HTTP -respCode 200 -httpRequest "HEAD /lab/ready" -LRTM DISABLED')
    lines.append("add lb monitor MON-DNS-001 DNS -query lab.example -queryType Address -LRTM DISABLED")
    lines.append(
        f"add lb monitor MON-LDAP-001 LDAP -password {MARKER} -encrypted -encryptmethod ENCMTHD_4 -kek"
        f' -suffix {KEK_SUFFIX} -LRTM DISABLED -baseDN "dc=lab,dc=example" -bindDN "cn=svc-lab,dc=lab,dc=example"'
    )
    for name, kind, address, port, _state, _doh, how, profile in LB_VSERVERS:
        line = f"add lb vserver {name} {kind} {address} {port} -persistenceType NONE -cltTimeout 180"
        if profile:
            line += f" -httpProfileName {profile}"
        if how == "add":
            line += " -dnsOverHttps ENABLED"
        lines.append(line)
    for name, address, _doh, how, _default in CS_VSERVERS:
        line = f"add cs vserver {name} SSL {address} 443 -cltTimeout 180 -persistenceType NONE"
        if name == "CSV-DOH-001":
            line += " -httpProfileName HTTPPROF-H2-001"
        if how == "add":
            line += " -dnsOverHttps ENABLED"
        lines.append(line)
    for _policy, action, target, _cs, _priority in CS_POLICIES:
        lines.append(f"add cs action {action} -targetLBVserver {target}")
    for policy, action, target, _cs, _priority in CS_POLICIES:
        lines.append(
            f'add cs policy {policy} -rule "HTTP.REQ.HOSTNAME.EQ(\\"{target.lower()}.lab.example\\")" -action {action}'
        )
    for name, _kind, _address, _port, _state, _doh, how, _profile in LB_VSERVERS:
        if how == "set":
            lines.append(f"set lb vserver {name} -dnsOverHttps ENABLED")
    for name, _address, _doh, how, _default in CS_VSERVERS:
        if how == "set":
            lines.append(f"set cs vserver {name} -dnsOverHttps ENABLED")
    lines.append('add rewrite action RWACT-001 insert_http_header X-Lab-Synthetic "\\"1\\""')
    lines.append("add rewrite action RWACT-002 delete_http_header X-Lab-Trace")
    for name, rule, action in REWRITE_POLICIES:
        lines.append(f"add rewrite policy {name} {rule} {action}")
    for name, rule, action in RESPONDER_POLICIES:
        lines.append(f"add responder policy {name} {rule} {action}")
    for name, _kind, _address, _port, _state, _doh, _how, _profile in LB_VSERVERS:
        group = LB_TO_GROUP.get(name)
        service = LB_TO_SERVICE.get(name)
        if group:
            lines.append(f"bind lb vserver {name} {group}")
        if service:
            lines.append(f"bind lb vserver {name} {service}")
    lines.append(
        "bind lb vserver LBV-WEB-001 -policyName RSPOL-001 -priority 100 -gotoPriorityExpression END -type REQUEST"
    )
    lines.append(
        "bind lb vserver LBV-APP-001 -policyName RWPOL-001 -priority 100 -gotoPriorityExpression END -type REQUEST"
    )
    for name, _address, _doh, _how, default_lb in CS_VSERVERS:
        if default_lb:
            lines.append(f"bind cs vserver {name} -lbvserver {default_lb}")
    for policy, _action, _target, cs, priority in CS_POLICIES:
        lines.append(f"bind cs vserver {cs} -policyName {policy} -priority {priority}")
    lines.append(
        "bind cs vserver CSV-WEB-002 -policyName RWPOL-001 -priority 100 -gotoPriorityExpression END -type REQUEST"
    )
    lines.append(
        "bind cs vserver CSV-WEB-002 -policyName RWPOL-002 -priority 100 -gotoPriorityExpression NEXT -type RESPONSE"
    )
    lines.append(
        "bind cs vserver CSV-WEB-002 -policyName RSPOL-001 -priority 100 -gotoPriorityExpression END -type REQUEST"
    )
    for service, (_server, _kind, _port, _state, monitor) in SERVICES.items():
        lines.append(f"bind service {service} -monitorName {monitor}")
    for group, (_kind, monitor, members) in SERVICEGROUPS.items():
        for server, port, _state in members:
            lines.append(f"bind serviceGroup {group} {server} {port}")
        lines.append(f"bind serviceGroup {group} -monitorName {monitor}")
    for certkey in CERTIFICATES:
        builtin = certkey.startswith("ns-")
        stem = certkey.split("-certificate")[0] if builtin else certkey.lower()
        lines.append(f"add ssl certKey {certkey} -cert {stem}.cert -key {stem}.key")
    for name, _kind, _tls12, tls13, _aliases in SSL_PROFILES:
        if name.startswith("ns_default"):
            continue
        lines.append(f"add ssl profile {name} -tls13 {tls13} -denySSLReneg FRONTEND_CLIENT")
    for group, ciphers in CIPHER_GROUPS.items():
        lines.append(f"add ssl cipher {group}")
        for cipher in ciphers:
            lines.append(f"bind ssl cipher {group} -cipherName {cipher}")
    ssl_names = [row[0] for row in LB_VSERVERS if row[1] == "SSL"] + [row[0] for row in CS_VSERVERS]
    for name in ssl_names:
        profile = "SSLPROF-FE-001" if name == "LBV-APP-001" else "ns_default_ssl_profile_frontend"
        lines.append(f"set ssl vserver {name} -sslProfile {profile}")
    for name, _kind, _tls12, _tls13, aliases in SSL_PROFILES:
        for priority, alias in enumerate(aliases, 1):
            lines.append(f"bind ssl profile {name} -cipherName {alias} -cipherPriority {priority}")
    for certkey, (_days, _kinds, bound) in CERTIFICATES.items():
        for vserver in bound:
            lines.append(f"bind ssl vserver {vserver} -certkeyName {certkey}")
    return lines


def running_config() -> str:
    lines = ["#NS14.1 Build 72.57", f"# Last modified {APPLIANCE_TIME}", *config_body(), " Done"]
    return "\n".join(lines) + "\n"


def saved_config() -> str:
    lines = ["#NS14.1 Build 72.57", f"# Last modified by `save config`, {APPLIANCE_TIME}", *config_body()]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Writing.
# ---------------------------------------------------------------------------

ENVELOPE = {"errorcode": 0, "message": "Done", "severity": "NONE"}

# Resources whose payload the collector writes under parsed/, not objects/.
PARSED = {
    "config/systemuser": "parsed/systemuser.json",
    "config/authenticationldapaction": "parsed/authenticationldapaction.json",
}


def _json_bytes(value) -> bytes:
    """JSON as the collector writes it: two spaces, CRLF, a final CRLF."""
    text = json.dumps(value, indent=2, ensure_ascii=True)
    return (text.replace("\n", "\r\n") + "\r\n").encode("ascii")


def _property(resource: str) -> str:
    return resource.split("/")[-1].split("?", 1)[0]


README = """# Synthetic DNS over HTTPS export

Written by `scripts/make_doh_fixture.py`; regenerate with that script, never by
hand. Nothing in this directory was collected from an appliance: every name,
address and value is invented for the tests, in the shape the released
collector writes (manifest with a hash per resource and per file, objects/,
aggregate and list-shaped bindings/, parsed/ config texts, collect-log.txt).

- Addresses only on the TEST-NET ranges of RFC 5737 (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24); host names under lab.example.
- No free text from any real configuration: comments, monitor strings,
  rewrite targets and the time zone are synthetic or absent.
- The device identity (serial number, host id, uuid) carries fixed neutral
  values; no MAC address and no IPv6 address is present.
- Credential values are absent: the lines that would carry one carry the
  collector's `<REDACTED>` marker, on both config texts.

It carries the four DNS over HTTPS shapes the CVE check reads (an SSL lb and
an SSL cs vserver added with `-dnsOverHttps ENABLED`, the `set lb vserver` and
`set cs vserver` form, a DNS profile with `-recursiveResolution ENABLED`), two
classic DNS proxies and an SSL lb vserver with DNS over HTTPS DISABLED as the
negative control.
"""


def write(target: Path) -> dict:
    """Writes the export into `target` (which must not exist) and returns
    the counts the collect log names."""
    target.mkdir(parents=True)
    (target / "objects").mkdir()
    (target / "bindings").mkdir()
    (target / "parsed").mkdir()

    resources: dict[str, dict] = {}
    log = [f"collect-start {COLLECTED_AT[:10]} 12:00:00"]
    for resource, payload in objects().items():
        prop = _property(resource)
        entry = {"status": "OK", "httpStatus": None, "propertyName": prop, "objectCount": 0, "payloadSha256": ""}
        if payload == "NOT_SUPPORTED":
            entry.update(status="NOT_SUPPORTED", httpStatus=400)
            log.append(f"WARN optional objects/{prop} WEGGELATEN (NOT_SUPPORTED)")
        elif payload == "EMPTY_WITHOUT_FILE":
            entry.update(status="EMPTY")
            log.append(f"OK objects/{prop} count=0")
        elif resource in PARSED:
            data = _json_bytes({prop: payload})
            (target / PARSED[resource]).write_bytes(data)
            entry.update(objectCount=len(payload), payloadSha256=payload_digest(data))
            log.append(f"OK {PARSED[resource].rsplit('.', 1)[0]} count={len(payload)}")
        elif resource == "config/lbmonitor":
            # The collector removes the password field of a monitor and then
            # writes the file WITHOUT the envelope and WITHOUT a hash: a
            # source this product reads as "geen hash is geen vertrouwen".
            data = _json_bytes({prop: payload})
            (target / "objects" / f"{prop}.json").write_bytes(data)
            entry.update(objectCount=len(payload))
            log.append("R-redactie lbmonitor: velden verwijderd = password")
            log.append(f"OK niet-geexporteerd/lbmonitor count={len(payload)}")
        else:
            document = dict(ENVELOPE)
            count = 0
            if payload is not None:
                document[prop] = payload
                count = len(payload) if isinstance(payload, list) else 1
            else:
                entry.update(status="EMPTY")
            data = _json_bytes(document)
            (target / "objects" / f"{prop}.json").write_bytes(data)
            entry.update(objectCount=count, payloadSha256=payload_digest(data))
            log.append(f"OK objects/{prop} count={count}")
        resources[resource] = entry

    files: dict[str, str] = {}
    for name, document in bindings().items():
        data = _json_bytes(document)
        rel = f"bindings/{name}.by-parent.json"
        (target / rel).write_bytes(data)
        files[rel] = payload_digest(data)
        outcomes = [parent["outcome"] for parent in document["parents"]]
        log.append(
            f"OK {rel.rsplit('.by-parent', 1)[0]} ok={outcomes.count('OK')} empty={outcomes.count('EMPTY')} readgap=0"
        )

    for resource, rel, text in (
        ("config/nsrunningconfig", "parsed/runningconfig.txt", running_config()),
        ("config/nssavedconfig", "parsed/savedconfig.txt", saved_config()),
    ):
        data = text.encode("ascii")
        (target / rel).write_bytes(data)
        digest = config_text_digest(data)
        files[rel] = digest
        resources[resource] = {
            "status": "OK",
            "httpStatus": None,
            "propertyName": _property(resource),
            "objectCount": 1,
            "payloadSha256": digest,
        }
        log.append(f"OK {rel} (geredigeerd op de jumphost)")

    log.append(f"OK export-manifest resources={len(resources)}")
    warns = sum(1 for line in log if line.startswith("WARN"))
    log.append(f"collect-einde warns={warns}")
    (target / "collect-log.txt").write_bytes(("\r\n".join(log) + "\r\n").encode("ascii"))

    manifest = {
        "manifestVersion": "1.1",
        "collectorVersion": "1.0.1",
        "collectedAtUtc": COLLECTED_AT,
        "resources": resources,
        "files": files,
    }
    (target / "export-manifest.json").write_bytes(_json_bytes(manifest))
    (target / "README.md").write_bytes(README.replace("\n", "\r\n").encode("ascii"))
    return {"resources": len(resources), "files": len(files)}


def self_check(target: Path) -> list[str]:
    """Reads the export back through the product's own reader and names
    every source that does not read as written. Empty when all is well."""
    export = load_export(target)
    problems = []
    if export.manifest_missing:
        problems.append("export-manifest.json niet leesbaar")
    for reader, label in (
        (export.running_config_lines, "parsed/runningconfig.txt"),
        (export.saved_config_lines, "parsed/savedconfig.txt"),
    ):
        _lines, gap = reader()
        if gap is not None:
            problems.append(f"{label}: {gap.reason}")
    for resource, payload in objects().items():
        if resource in PARSED or resource == "config/lbmonitor" or isinstance(payload, str):
            continue
        reader = export.single if isinstance(payload, dict) else export.objects
        _rows, gap = reader(resource)
        if gap is not None:
            problems.append(f"{resource}: {gap.reason}")
    _rows, gap = export.systemuser_rows()
    if gap is not None:
        problems.append(f"config/systemuser: {gap.reason}")
    for name in bindings():
        _rows, gap = export.bindings(f"{name}.by-parent.json")
        if gap is not None and "aggregate" not in gap.reason:
            problems.append(f"{name}: {gap.reason}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Schrijf de synthetische DoH-export (geen appliance, geen netwerk).")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET, help="Doelmap (standaard de testfixture)")
    parser.add_argument("--force", action="store_true", help="Een bestaande doelmap eerst verwijderen")
    args = parser.parse_args(argv)
    print(f"[start] synthetische DoH-export naar {args.target.name}")
    if args.target.exists():
        if not args.force:
            print("[fout] de doelmap bestaat al; gebruik --force om hem te vervangen", file=sys.stderr)
            print("[eindstatus] MISLUKT - niets geschreven", file=sys.stderr)
            return 1
        shutil.rmtree(args.target)
        print("[waarschuwing] bestaande doelmap verwijderd")
    try:
        counts = write(args.target)
    except OSError as exc:
        print(f"[fout] schrijven mislukt: {exc.strerror}", file=sys.stderr)
        print("[eindstatus] MISLUKT", file=sys.stderr)
        return 1
    print(f"[ok] {counts['resources']} resources, {counts['files']} bestanden met een hash in het manifest")
    problems = self_check(args.target)
    if problems:
        for problem in problems:
            print(f"[fout] {problem}", file=sys.stderr)
        print("[eindstatus] MISLUKT - de export leest niet terug zoals geschreven", file=sys.stderr)
        return 1
    print("[eindstatus] GESLAAGD - elke bron leest terug zonder leesgat")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
