#!/usr/bin/env python3
"""Deterministic, offline pseudonymisation of a validated NSHC export.

The CLI writes a new target only after validation and the final leak check.
mapping.json and verboden.txt remain outside every repository. This is an
operator tool, not part of the installed product or a general secret scanner.

Generic HTTP/HTTPS/HTTP2DIRECT and protocol-named monitors are retained.
NetScaler-shipped built-in objects (a non-empty NITRO "builtin" attribute, or
VENDOR_BUILTIN_NAMES for the ones that attribute does not cover) are never a
candidate or identity either; a legacy mapping.json entry for one is dropped.
Conflicts with schema keys, protected names or semantic values fail closed.
If a source hostname overlaps the prescribed lab aliases, host aliases use
.invalid and the neutral serial uses SERIAL1. Explicit empty legacy lbmonitor
hashes remain empty. Source LF/CRLF differences are accepted only when the
normalized bytes reproduce the recorded hash; source line endings are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath

MANIFEST = "export-manifest.json"
KEEP_NAMES = frozenset(
    {
        "nshttp_default_profile",
        "gjkdoh_http2",
        "gjkdoh_lb_ssl_doh",
        "gjkdoh_cs_ssl_doh",
        "gjkdoh_lb_dns",
        "gjkdoh_lb_ssl_nodoh",
        # These measured generic names are also protocol/schema literals.
        "http",
        "https",
        "http2direct",
    }
)
# The certificate-related vendor names only, kept separate so
# _GENERIC_DERIVED_VOCABULARY (below) can stay narrow: a derived cert stem
# (ns-server from ns-server.cert, never the full basename, which is
# always its own candidate) must not become a candidate just because it
# is a substring of ns-server-certificate, but a customer cert plausibly
# named runtime.crt or edge.crt must stay one - pulling in the FULL
# VENDOR_BUILTIN_NAMES list (the CVPN/AppFW names carry ordinary English
# words too) would silently lose that protection for real customer names.
VENDOR_CERT_NAMES = frozenset(
    {
        # object names
        "ns-server-certificate",
        "ns-sftrust-certificate",
        "ns-sftrust-root-certificate",
        "ns-sftrust",
        # the vendor's own cert/key file basenames
        "ns-server.cert",
        "ns-server.key",
        "ns-sftrust.cert",
        "ns-sftrust.key",
        "ns-root.cert",
        "ns-root.key",
    }
)
# NetScaler-shipped built-in objects (certkeys, rewrite/SSL/monitor
# defaults, the Citrix VPN/Unified Gateway rewrite ruleset): present on
# every appliance, compared HARDCODED by product code (handelen.py
# DENIED_NAMES, mgmt_plane.py DEFAULT_MGMT_CERT, hidden_rules.py
# _BUILTIN_SSL_PROFILES/_BUILTIN_REWRITE_ACTIONS/the built-in-monitor
# regex) - never a customer or lab identity. Exact casefold match only: a
# prefix/substring match risks treating a genuine customer object that
# merely starts with "ns_"/"ns-" as vendor vocabulary. Measured from
# tests/fixtures/lab-export-vpx-20260826 (the ns_cvpn_* block is the
# built-in CVPN/Unified Gateway rewrite ruleset NetScaler ships whenever
# that feature is configured) plus the controller's minimum list. This is
# an exact-match allowlist, not a growth path: an unlisted built-in name
# (a newer firmware/CVPN generation, a different standard monitor set)
# gets replaced like any other candidate - noise, not a leak, and
# expanding this list happens by measuring a new export, never by adding
# a prefix rule (see scripts/README.md).
VENDOR_BUILTIN_NAMES = VENDOR_CERT_NAMES | frozenset(
    {
        # rewrite actions (built-in, protocol-level)
        "NOREWRITE",
        "NOOP",
        "DROP",
        "RESET",
        # default SSL profiles
        "ns_default_ssl_profile_frontend",
        "ns_default_ssl_profile_backend",
        "ns_default_ssl_profile_internal_frontend_service",
        "ns_default_ssl_profile_secure_frontend",
        "ns_default_ssl_profile_frontend_spa_cep",
        "ns_default_ssl_profile_quic_backend",
        "ns_default_ssl_profile_quic_frontend",
        "ns_default_ssl_profile_secure_frontend_cloud",
        "ns_default_ssl_certauth_profile_internal_frontend_service",
        # default monitors
        "ping-default",
        "tcp-default",
        # standard protocol-named monitors
        "ping",
        "tcp",
        "http",
        "https",
        "arp",
        "nd6",
        "dns",
        "ftp",
        "smtp",
        "pop3",
        "nntp",
        "rtsp",
        "radius",
        "snmp",
        "ldns-ping",
        "ldns-tcp",
        "ldns-dns",
        "http-ecv",
        "https-ecv",
        "tcp-ecv",
        "udp-ecv",
        "dns-tcp",
        "sip-udp",
        "sip-tcp",
        "mysql",
        "mssql",
        # further built-in monitors without an "ns" prefix, measured still
        # replaced on the reference fixture
        "quic-default",
        "tcps",
        "tcps-ecv",
        "http2ssl",
        "mqtt-tls",
        "stasecure",
        "VPN_INT_MON-0",
        # NOTE: the four genuinely built-in AppFW profiles (APPFW_BYPASS/RESET/
        # DROP/BLOCK) are NOT listed here - _is_builtin_row() already excludes
        # them structurally (NITRO's "builtin": true on this object type).
        # default AppFW profiles (one per bound feature, built-in on every appliance)
        "ns-aaa-default-appfw-profile",
        "ns-aaatm-default-appfw-profile",
        "ns-edge-default-appfw-profile",
        "ns-mgmt-gui-default-appfw-profile",
        "ns-vpn-default-appfw-profile",
        "ns-web-default-appfw-profile",
        # built-in rewrite insertion points
        "ns_aaatm_def_insert_after_onload",
        "ns_rw_default_insert_after_body",
        # built-in CVPN (Citrix VPN / Unified Gateway) rewrite ruleset
        "ns_cvpn_default_bypass_url_pol",
        "ns_cvpn_default_inet_url_pol",
        "ns_cvpn_default_url_decode_act",
        "ns_cvpn_default_url_encode_act",
        "ns_cvpn_owa_ct_rw_act",
        "ns_cvpn_owa_ct_rw_pol",
        "ns_cvpn_owa_js_EcpUgeVD_rw_act",
        "ns_cvpn_owa_js_EcpUgeVD_rw_act1",
        "ns_cvpn_owa_js_EcpUgeVD_rw_act2",
        "ns_cvpn_owa_js_EcpUgeVD_rw_pol",
        "ns_cvpn_owa_js_EcpUgeVD_rw_pol1",
        "ns_cvpn_owa_js_EcpUgeVD_rw_pol2",
        "ns_cvpn_owa_js_boot.0.mouse.act",
        "ns_cvpn_owa_js_boot.0.mouse.pol",
        "ns_cvpn_owa_js_cac_rw_act",
        "ns_cvpn_owa_js_cac_rw_pol",
        "ns_cvpn_owa_q_body_dest_rw_act",
        "ns_cvpn_owa_q_body_dest_rw_pol",
        "ns_cvpn_owa_q_body_href_rw_act",
        "ns_cvpn_owa_q_body_href_rw_pol",
        "ns_cvpn_owa_q_body_range_rw_act",
        "ns_cvpn_owa_q_body_range_rw_pol",
        "ns_cvpn_owa_q_body_val_rw_act",
        "ns_cvpn_owa_q_body_val_rw_pol",
        "ns_cvpn_owa_q_desthdr_rw_act",
        "ns_cvpn_owa_q_desthdr_rw_pol",
        "ns_cvpn_owa_q_iisadmpwd_act",
        "ns_cvpn_owa_q_iisadmpwd_pol",
        "ns_cvpn_owa_s_body_ev_owa_pol",
        "ns_cvpn_q_body_dest_rw_pol",
        "ns_cvpn_req_query_rw_0_act",
        "ns_cvpn_req_query_rw_0_pol",
        "ns_cvpn_sp_body_decode_act",
        "ns_cvpn_sp_body_decode_act1",
        "ns_cvpn_sp_body_decode_form",
        "ns_cvpn_sp_bypass_url_pol",
        "ns_cvpn_sp_contentType_act",
        "ns_cvpn_sp_contentType_pol",
        "ns_cvpn_sp_ct_rw_act",
        "ns_cvpn_sp_hdr_sa_rw_act",
        "ns_cvpn_sp_hdr_sa_rw_pol",
        "ns_cvpn_sp_inet_url_pol",
        "ns_cvpn_sp_js_cac_rw_act",
        "ns_cvpn_sp_js_cac_rw_pol",
        "ns_cvpn_sp_js_checkout_rw_act",
        "ns_cvpn_sp_js_checkout_rw_pol",
        "ns_cvpn_sp_js_du_rw_act",
        "ns_cvpn_sp_js_du_rw_pol",
        "ns_cvpn_sp_js_guk_rw_act",
        "ns_cvpn_sp_js_guk_rw_pol",
        "ns_cvpn_sp_js_localStorage_act",
        "ns_cvpn_sp_js_localStorage_pol",
        "ns_cvpn_sp_js_runtime_rw_act",
        "ns_cvpn_sp_js_runtime_rw_pol",
        "ns_cvpn_sp_js_rurl_rw_act",
        "ns_cvpn_sp_js_rurl_rw_pol",
        "ns_cvpn_sp_js_slwp_rw_act",
        "ns_cvpn_sp_js_slwp_rw_pol",
        "ns_cvpn_sp_js_source_rw_act",
        "ns_cvpn_sp_js_source_rw_act2",
        "ns_cvpn_sp_js_source_rw_pol",
        "ns_cvpn_sp_js_source_rw_pol2",
        "ns_cvpn_sp_js_vgp_pol",
        "ns_cvpn_sp_mobile_pol",
        "ns_cvpn_sp_mobile_pol_1",
        "ns_cvpn_sp_q_body_dest_rw_pol",
        "ns_cvpn_sp_q_body_dest_rw_pol1",
        "ns_cvpn_sp_q_body_up_rw_pol",
        "ns_cvpn_sp_q_url_dlg_rw_act",
        "ns_cvpn_sp_q_url_dlg_rw_pol",
        "ns_cvpn_sp_q_url_fn_rw_act",
        "ns_cvpn_sp_q_url_fn_rw_pol",
        "ns_cvpn_sp_q_url_fontSchemeUrl_rw_act",
        "ns_cvpn_sp_q_url_fontSchemeUrl_rw_pol",
        "ns_cvpn_sp_q_url_imageUrl_rw_act",
        "ns_cvpn_sp_q_url_imageUrl_rw_pol",
        "ns_cvpn_sp_q_url_loc_rw_act",
        "ns_cvpn_sp_q_url_loc_rw_pol",
        "ns_cvpn_sp_q_url_lvu_rw_act",
        "ns_cvpn_sp_q_url_lvu_rw_pol",
        "ns_cvpn_sp_q_url_masterUrl_rw_act",
        "ns_cvpn_sp_q_url_masterUrl_rw_pol",
        "ns_cvpn_sp_q_url_nu_rw_act",
        "ns_cvpn_sp_q_url_nu_rw_pol",
        "ns_cvpn_sp_q_url_ofr_rw_act",
        "ns_cvpn_sp_q_url_ofr_rw_pol",
        "ns_cvpn_sp_q_url_rf_rw_act",
        "ns_cvpn_sp_q_url_rf_rw_pol",
        "ns_cvpn_sp_q_url_ru_rw_act",
        "ns_cvpn_sp_q_url_ru_rw_pol",
        "ns_cvpn_sp_q_url_src_rw_act",
        "ns_cvpn_sp_q_url_src_rw_pol",
        "ns_cvpn_sp_q_url_su_rw_act",
        "ns_cvpn_sp_q_url_su_rw_pol",
        "ns_cvpn_sp_q_url_themeUrl_rw_act",
        "ns_cvpn_sp_q_url_themeUrl_rw_pol",
        "ns_cvpn_sp_q_url_url1_rw_act",
        "ns_cvpn_sp_q_url_url1_rw_pol",
        "ns_cvpn_sp_q_url_url2_rw_act",
        "ns_cvpn_sp_q_url_url2_rw_pol",
        "ns_cvpn_sp_q_url_url_rw_act",
        "ns_cvpn_sp_q_url_url_rw_pol",
        "ns_cvpn_sp_ribbon_js_rw_act",
        "ns_cvpn_sp_ribbon_js_rw_act_1",
        "ns_cvpn_sp_s_post_body_pol",
        "ns_cvpn_sp_src_qurl_encode_act",
        "ns_cvpn_sp_src_qurl_pol1",
        "ns_cvpn_sp_src_qurl_pol2",
        "ns_cvpn_sp_ui_dia_1_pol",
        "ns_cvpn_sp_ui_dia_1_rw_act",
        "ns_cvpn_sp_ui_dia_2_rw_act",
        "ns_cvpn_sp_ui_dia_2_rw_pol",
        "ns_cvpn_sp_ui_dia_3_act",
        "ns_cvpn_sp_ui_dia_3_pol",
        "ns_cvpn_sp_xcmp_vti_act",
        "ns_cvpn_sp_xcmp_vti_pol",
        "ns_cvpn_v2_bypass_url_pol",
        "ns_cvpn_v2_inet_url_pol",
        "ns_cvpn_v2_req_body_decode_act",
        "ns_cvpn_v2_req_body_decode_pol",
        "ns_cvpn_v2_req_query_rw_0_act",
        "ns_cvpn_v2_req_query_rw_0_pol",
        "ns_cvpn_v2_req_query_rw_1_act",
        "ns_cvpn_v2_req_query_rw_1_pol",
        "ns_cvpn_v2_req_query_rw_2_act",
        "ns_cvpn_v2_req_query_rw_2_pol",
        "ns_cvpn_v2_req_query_rw_3_act",
        "ns_cvpn_v2_req_query_rw_3_pol",
        "ns_cvpn_v2_req_query_rw_4_act",
        "ns_cvpn_v2_req_query_rw_4_pol",
        "ns_cvpn_v2_req_query_rw_5_act",
        "ns_cvpn_v2_req_query_rw_5_pol",
        "ns_cvpn_v2_req_query_rw_6_act",
        "ns_cvpn_v2_req_query_rw_6_pol",
    }
)
_VENDOR_BUILTIN_NAMES_CF = frozenset(name.casefold() for name in VENDOR_BUILTIN_NAMES)
NAME_SOURCES = [
    ("lbvserver.json", "lbvserver", "name", "LBV"),
    ("csvserver.json", "csvserver", "name", "CSV"),
    ("sslvserver.json", "sslvserver", "vservername", "VSRV"),
    ("server.json", "server", "name", "SRV"),
    ("servicegroup.json", "servicegroup", "servicegroupname", "SVCGRP"),
    ("service.json", "service", "name", "SVC"),
    ("lbmonitor.json", "lbmonitor", "monitorname", "MON"),
    ("sslcertkey.json", "sslcertkey", "certkey", "CERT"),
    ("sslprofile.json", "sslprofile", "name", "SSLPROF"),
    ("nshttpprofile.json", "nshttpprofile", "name", "HTTPPROF"),
    ("rewritepolicy.json", "rewritepolicy", "name", "RWPOL"),
    ("rewriteaction.json", "rewriteaction", "name", "RWACT"),
    ("cspolicy.json", "cspolicy", "policyname", "CSPOL"),
    ("csaction.json", "csaction", "name", "CSACT"),
    ("responderpolicy.json", "responderpolicy", "name", "RSPOL"),
    ("appfwprofile.json", "appfwprofile", "name", "APPFW"),
    ("botprofile.json", "botprofile", "name", "BOT"),
    ("auditsyslogaction.json", "auditsyslogaction", "name", "SYSLOGACT"),
    ("auditsyslogpolicy.json", "auditsyslogpolicy", "name", "SYSLOGPOL"),
]
HOST_LINE_PREFIXES = (
    "add server ",
    "add dns addRec ",
    "add dns nsRec ",
    "bind policy patset ",
    "bind policy stringmap ",
    "set dps parameter ",
    "set ns diameter ",
    "set subscriber gxInterface ",
)
ROOTSERVER_SUFFIXES = ("root-servers.net",)
VENDOR_SUFFIXES = ("nsbotsignatures.s3.amazonaws.com", "device-posture-controller.cloud.com", "netscaler.com")
PLATFORM_SUFFIXES = ("youtube.com", "googlevideo.com")
PROTECTED_PUBLIC_SUFFIXES = frozenset(ROOTSERVER_SUFFIXES + VENDOR_SUFFIXES + PLATFORM_SUFFIXES)
PUBLIC_SUFFIXES = tuple(sorted(PROTECTED_PUBLIC_SUFFIXES | {"lab.example"}))
CONFIG_TERMS = frozenset({"pcrf", "pcrfrealm"}) | frozenset(
    {
        "http",
        "https",
        "http2direct",
        "dnsoverhttps",
        "timestamp",
    }
)
PLATFORM_TERMS = frozenset({"youtube", "googlevideo"})
FILE_SUFFIXES = (".json", ".txt", ".conf", ".log", ".crt", ".key", ".pem", ".cer", ".der", ".pfx", ".cert")
# Standard NetScaler certificate-storage path segments: never a customer
# name, so a cert/key path's immediate folder is only harvested past these.
CERT_PATH_IGNORED_SEGMENTS = frozenset({"nsconfig", "ssl", "var", "tmp", "flash"})
HOST_RX = re.compile(r"(?<![\w.-])[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+(?![\w-])")
IP_RX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC_RX = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
PRIVATE_NETS = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
TESTNETS = tuple(ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
NEUTRAL_IDENTITY = {
    "serialno": "LABSERIAL1",
    "encodedserialno": "00000000000000000000",
    "hostid": 100000001,
    "netscaleruuid": "00000000-0000-0000-0000-020000000001",
    "host": "020000000001",
}
NEUTRAL_MAC_COLON = "02:00:00:00:00:01"
FIXED_ALIASES = {str(v) for v in NEUTRAL_IDENTITY.values()} | {NEUTRAL_MAC_COLON, "SERIAL1"}


def _eui64_link_local(mac: str) -> str:
    """The IPv6 link-local address an interface with this MAC derives for
    itself (modified EUI-64, RFC 4291 appendix A)."""
    octets = bytes(int(part, 16) for part in mac.split(":"))
    interface_id = bytes([octets[0] ^ 0x02]) + octets[1:3] + b"\xff\xfe" + octets[3:]
    return str(ipaddress.IPv6Address(b"\xfe\x80" + b"\x00" * 6 + interface_id))


# A link-local address in EUI-64 form spells the MAC address back out, so it
# is replaced by the address the NEUTRAL MAC derives - never one derived from
# the original.
NEUTRAL_LINK_LOCAL = _eui64_link_local(NEUTRAL_MAC_COLON)
_LINK_LOCAL_RX = re.compile(r"(?i)(?<![0-9a-f:])fe80::[0-9a-f:]*[0-9a-f](?![0-9a-f:])")

# FREE TEXT. The alias mapping replaces names and addresses; a comment, a
# monitor send/receive string, a StoreFront store name, a rewrite
# string-builder expression, a time zone with a place name, a Gateway home
# URL or an NT domain is text an operator typed, and no alias family covers
# it. Measured on a real export: dozens of comment fields and monitor strings
# survived a passing run. These fields are neutralised by FIELD - the tool
# never needs to know the original - on every row that is not a vendor row,
# in objects/ and parsed/ JSON alike and on the matching flags of the two
# config texts.
FREE_TEXT_NEUTRAL = {
    "comment": "LAB synthetic comment",
    "send": "GET /lab/health",
    "recv": "LAB synthetic response",
    "storename": "LabStore",
    "stringbuilderexpr": '"LAB synthetic"',
    "timezone": "CoordinatedUniversalTime",
    "ntdomain": "LAB",
}
# A URL keeps its scheme and (already aliased) host; the path is replaced.
FREE_TEXT_URL_FIELDS = frozenset({"wihome", "citrixreceiverhome"})
FREE_TEXT_URL_PATH = "/lab/store"
FREE_TEXT_FIELDS = frozenset(FREE_TEXT_NEUTRAL) | FREE_TEXT_URL_FIELDS
# Time-zone words that carry no place.
TIMEZONE_WORDS = frozenset({"gmt_time", "local_time", "coordinateduniversaltime"})
# The collector's own marker is not free text.
COLLECTOR_MARKER = "<REDACTED>"
CONFIG_TEXT_FILES = frozenset({"parsed/runningconfig.txt", "parsed/savedconfig.txt"})
# Rewrite action types whose LAST positional argument is a string-builder
# expression (`add rewrite action <name> <type> [<target>] <expression>`).
REWRITE_BUILDER_TYPES = frozenset(
    {
        "insert_http_header",
        "insert_before",
        "insert_after",
        "replace",
        "replace_all",
        "insert_before_all",
        "insert_after_all",
        "replace_http_res",
        "insert_sip_header",
        "replace_sip_res",
    }
)
_Q_DELIMITERS = {"/": "/", "{": "}", "(": ")", "[": "]", "<": ">", "|": "|"}
_FREE_TEXT_FLAG_RX = re.compile(r"(?i)-(" + "|".join(sorted(FREE_TEXT_FIELDS)) + r")")


def _neutral_free_text(field: str, value: str) -> str:
    key = field.casefold()
    stripped = value.strip()
    if stripped in ("", COLLECTOR_MARKER):
        return value
    if key in FREE_TEXT_URL_FIELDS:
        match = re.match(r"(?i)[a-z][a-z0-9+.-]*://[^/\s]*", stripped)
        return (match.group() if match else "") + FREE_TEXT_URL_PATH
    if key == "timezone" and stripped.casefold() in TIMEZONE_WORDS:
        return value
    return FREE_TEXT_NEUTRAL[key]


def _neutral_link_local(text: str) -> str:
    def replace(match):
        try:
            address = ipaddress.IPv6Address(match.group())
        except ValueError:
            return match.group()
        if (int(address) >> 24) & 0xFFFF != 0xFFFE:
            return match.group()  # not EUI-64: no MAC in it
        return NEUTRAL_LINK_LOCAL

    return _LINK_LOCAL_RX.sub(replace, text)


_ROW_NAME_FIELDS = ("name", "monitorname", "policyname", "certkey", "servicegroupname")


def _vendor_row(row: dict) -> bool:
    """A row the appliance ships on every box: `builtin` (see
    `_is_builtin_row`), the `isdefault: true` the rewrite and responder
    resources carry for their vendor rule sets, or a row named after one of
    the measured VENDOR_BUILTIN_NAMES (the stock monitors carry no builtin
    attribute)."""
    if _is_builtin_row(row) or row.get("isdefault") is True:
        return True
    return any(
        isinstance(row.get(field), str) and row[field].casefold() in _VENDOR_BUILTIN_NAMES_CF
        for field in _ROW_NAME_FIELDS
    )


def neutralise_json(value):
    """Every free-text field of a non-vendor row replaced by its neutral
    value; every EUI-64 link-local address replaced by NEUTRAL_LINK_LOCAL.
    Idempotent: a second pass changes nothing."""
    if isinstance(value, list):
        return [neutralise_json(item) for item in value]
    if isinstance(value, dict):
        vendor = _vendor_row(value)
        result = {}
        for key, item in value.items():
            if not vendor and isinstance(item, str) and key.casefold() in FREE_TEXT_FIELDS:
                result[key] = _neutral_free_text(key, item)
            else:
                result[key] = neutralise_json(item)
        return result
    if isinstance(value, str):
        return _neutral_link_local(value)
    return value


def _token_end(line: str, start: int) -> int:
    """End of the CLI token that starts at `start`: a double-quoted string
    with backslash escapes, a q-delimited string, or a bare word. An
    unterminated quote runs to the end of the line."""
    if line[start] == '"':
        index = start + 1
        while index < len(line):
            if line[index] == "\\":
                index += 2
                continue
            if line[index] == '"':
                return index + 1
            index += 1
        return len(line)
    if line[start] == "q" and start + 1 < len(line) and line[start + 1] in _Q_DELIMITERS:
        closer = line.find(_Q_DELIMITERS[line[start + 1]], start + 2)
        return len(line) if closer < 0 else closer + 1
    end = start
    while end < len(line) and not line[end].isspace():
        end += 1
    return end


def _unquote(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return re.sub(r"\\(.)", r"\1", raw[1:-1])
    if len(raw) >= 3 and raw[0] == "q" and raw[1] in _Q_DELIMITERS:
        return raw[2:-1]
    return raw


def _cli_quote(value: str, raw: str) -> str:
    """`value` as a CLI token: quoted when the token it replaces was quoted,
    or when it would not survive as a bare word."""
    bare = re.fullmatch(r'[^\s"\\]+', value) and not (value[0] == "q" and len(value) > 1 and value[1] in _Q_DELIMITERS)
    if bare and not raw.startswith('"'):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spans(line: str) -> list[tuple[int, int]]:
    spans, index = [], 0
    while index < len(line):
        if line[index].isspace():
            index += 1
            continue
        end = _token_end(line, index)
        spans.append((index, end))
        index = end
    return spans


def _neutralise_line(line: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    spans = _spans(line)
    for position, (start, end) in enumerate(spans):
        flag = _FREE_TEXT_FLAG_RX.fullmatch(line[start:end])
        if flag is not None and position + 1 < len(spans):
            value_start, value_end = spans[position + 1]
            raw = line[value_start:value_end]
            value = _unquote(raw)
            neutral = _neutral_free_text(flag.group(1), value)
            if neutral != value:
                replacements.append((value_start, value_end, _cli_quote(neutral, raw)))
    words = [line[start:end].casefold() for start, end in spans]
    if words[:3] == ["add", "rewrite", "action"] and len(words) > 5 and words[4] in REWRITE_BUILDER_TYPES:
        # Only the arguments before the first flag are positional; the last
        # of them is the expression.
        first_flag = next((index for index in range(5, len(spans)) if words[index].startswith("-")), len(spans))
        if first_flag > 5:
            start, end = spans[first_flag - 1]
            raw = line[start:end]
            neutral = FREE_TEXT_NEUTRAL["stringbuilderexpr"]
            if _unquote(raw) != neutral:
                replacements.append((start, end, _cli_quote(neutral, raw)))
    for start, end, text in sorted(replacements, reverse=True):
        line = line[:start] + text + line[end:]
    return _neutral_link_local(line)


def neutralise_config_text(text: str) -> str:
    """The config-text counterpart of `neutralise_json`: the value after
    every free-text flag, the string-builder expression of a rewrite
    action, and every EUI-64 link-local address. Line endings are kept;
    idempotent."""
    parts = []
    # Split on LF alone, as the product reads the config text.
    for line in text.split("\n"):
        ending = "\r" if line.endswith("\r") else ""
        parts.append(_neutralise_line(line[: len(line) - len(ending)]) + ending)
    return "\n".join(parts)


SEMANTIC_FIELDS = frozenset(
    {
        "type",
        "servicetype",
        "state",
        "status",
        "http2",
        "http2direct",
        "ssl3",
        "tls1",
        "tls11",
        "tls12",
        "tls13",
        "clientauth",
        "enabled",
        "disabled",
        "secure",
        "protocol",
        "protocoltype",
        "feature",
        "mode",
        "actiontype",
        "timestamp",
        "dnsoverhttps",
    }
)
SPECIAL_RESOURCE_FILES = {
    "config/nsrunningconfig": "parsed/runningconfig.txt",
    "config/nssavedconfig": "parsed/savedconfig.txt",
    "config/systemuser": "parsed/systemuser.json",
    "config/authenticationldapaction": "parsed/authenticationldapaction.json",
}
STATUSES = {"OK", "EMPTY", "NOT_SUPPORTED", "RBAC_DENIED", "FAILED", "SKIPPED"}
HASH_RX = re.compile(r"[a-fA-F0-9]{64}")


class Refused(ValueError):
    """A public-safe diagnostic; never contains original data or raw exceptions."""


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("JSON bevat een dubbele sleutel")
        result[key] = value
    return result


def _json(text: str):
    try:
        return json.loads(
            text,
            object_pairs_hook=_json_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Refused("JSON bevat een ongeldige constante")),
        )
    except (ValueError, TypeError) as exc:
        raise Refused("JSON is ongeldig") from exc


def _newline(data: bytes) -> str:
    match = re.search(rb"\r\n|\n|\r", data)
    return match.group().decode("ascii") if match else "\n"


def _encode(value, source: bytes = b"") -> bytes:
    text = json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    return _encode_text(text.replace("\n", _newline(source)), source)


def _encode_text(text: str, source: bytes) -> bytes:
    """Keep each file's UTF-8 BOM; decoding and payload normalization omit it."""
    return (b"\xef\xbb\xbf" if source.startswith(b"\xef\xbb\xbf") else b"") + text.encode("utf-8")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _payload_hash(name: str, data: bytes) -> str:
    # The product reader hashes the two config projections as LF text.
    if name in {"parsed/runningconfig.txt", "parsed/savedconfig.txt"}:
        data = _text(data).replace("\r\n", "\n").encode("utf-8")
    return _hash(data)


def _text(data: bytes) -> str:
    try:
        result = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise Refused("Export bevat een niet-UTF-8-bestand; handmatige beoordeling nodig") from exc
    if "\x00" in result:
        raise Refused("Export bevat binaire inhoud; handmatige beoordeling nodig")
    return result


def _relative(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise Refused("Manifest bevat een onveilig bestandspad")
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in ("..", ".", "") for p in name.split("/")):
        raise Refused("Manifest bevat een onveilig bestandspad")
    return path.as_posix()


def resource_file(resource: str) -> str:
    if not isinstance(resource, str):
        raise Refused("Manifest bevat een ongeldige resource")
    base = resource.split("?", 1)[0]
    if not re.fullmatch(r"(?:config|stat)/[A-Za-z0-9_]+", base):
        raise Refused("Manifest bevat een ongeldige resource")
    # Query arguments may contain a filelocation. They are data, never paths.
    return SPECIAL_RESOURCE_FILES.get(base, f"objects/{base.split('/')[-1]}.json")


def validate_manifest(blobs: dict[str, bytes], *, source_newlines: bool = False) -> dict:
    if MANIFEST not in blobs:
        raise Refused("Exportmanifest ontbreekt")
    manifest = _json(_text(blobs[MANIFEST]))
    if (
        not isinstance(manifest, dict)
        or not isinstance(manifest.get("resources"), dict)
        or not manifest["resources"]
        or not isinstance(manifest.get("files"), dict)
    ):
        raise Refused("Exportmanifest heeft een ongeldige vorm")

    def matches(data, expected):
        return (
            _hash(data) == expected.upper()
            or source_newlines
            and _hash(data.replace(b"\r\n", b"\n")) == expected.upper()
        )

    def check_hash(name, expected):
        name = _relative(name)
        if name in (MANIFEST, "scan-doel.txt"):
            raise Refused("Manifest bevat een cyclische bestandshash")
        if not isinstance(expected, str) or not HASH_RX.fullmatch(expected):
            raise Refused("Manifest bevat een ontbrekende of ongeldige hash")
        valid = name in blobs and (
            _payload_hash(name, blobs[name]) == expected.upper() or source_newlines and matches(blobs[name], expected)
        )
        if not valid:
            raise Refused("Bronbestand ontbreekt of wijkt af van de manifest-hash")

    for resource, entry in manifest["resources"].items():
        name = resource_file(resource)
        if not isinstance(entry, dict) or entry.get("status") not in STATUSES:
            raise Refused("Manifest bevat een ongeldige resourcevermelding")
        expected = entry.get("payloadSha256")
        usable = entry["status"] in {"OK", "EMPTY"}
        # Missing hashes are evidence gaps, not permission to create trust.
        # Validate every claimed hash; transform preserves absent/empty hashes.
        if entry["status"] == "OK" and name not in blobs:
            raise Refused("Bruikbaar bronbestand ontbreekt")
        if expected is not None and expected != "":
            check_hash(name, expected)
        if usable:
            count = entry.get("objectCount")
            if type(count) is not int or count < 0 or (entry["status"] == "EMPTY" and count != 0):
                raise Refused("Manifest bevat een ongeldige rijtelling")
            key = resource.split("?", 1)[0].split("/")[-1]
            if entry.get("propertyName") != key:
                raise Refused("Manifest heeft een afwijkende propertyName")
            if name in blobs and name.endswith(".json"):
                raw = _json(_text(blobs[name]))
                if not isinstance(raw, dict) or (key not in raw and entry["status"] != "EMPTY"):
                    raise Refused("Objectbestand heeft een afwijkende vorm")
                # NITRO omits the resource key entirely for some EMPTY responses.
                rows = raw.get(key, [])
                actual = len(rows) if isinstance(rows, list) else 1 if isinstance(rows, dict) else 0
                if actual != count:
                    raise Refused("Manifesttelling wijkt af van de inhoud")
    for name, expected in manifest["files"].items():
        _relative(name)
        if expected is not None and expected != "":
            check_hash(name, expected)
    if "scan-doel.txt" in blobs:
        lines = _text(blobs["scan-doel.txt"]).splitlines()
        if len(lines) != 2 or not lines[0].strip() or not matches(blobs[MANIFEST], lines[1]):
            raise Refused("Scan-doelstempel hoort niet bij het bronmanifest")
    return manifest


def _linked(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def read_source(source: Path) -> dict[str, bytes]:
    if not source.is_dir() or _linked(source):
        raise Refused("Bron is geen gewone exportmap")
    blobs = {}
    for path in sorted(source.rglob("*")):
        if _linked(path):
            raise Refused("Export bevat een link of doorverwijzing")
        if path.is_dir():
            continue
        if not path.is_file():
            raise Refused("Export bevat een afwijkend bestandstype")
        name = path.relative_to(source).as_posix()
        data = path.read_bytes()
        text = _text(data)
        if name.endswith(".json"):
            _json(text)
        blobs[name] = data
    return blobs


def _rows(blobs: dict[str, bytes], file: str, key: str) -> list[dict]:
    data = blobs.get("objects/" + file)
    if data is None:
        return []
    raw = _json(_text(data))
    if isinstance(raw, dict) and key not in raw:
        manifest = _json(_text(blobs[MANIFEST]))
        if manifest["resources"].get("config/" + key, {}).get("status") == "EMPTY":
            return []
    if not isinstance(raw, dict) or key not in raw:
        raise Refused("Naambron heeft een ongeldige vorm")
    rows = raw[key]
    rows = [rows] if isinstance(rows, dict) else rows
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise Refused("Naambron bevat geen objecten")
    return rows


def _public_host(value: str) -> bool:
    low = value.casefold()
    return any(low == suffix or low.endswith("." + suffix) for suffix in PUBLIC_SUFFIXES)


def _address(value: str):
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def identity_hostnames(blobs: dict[str, bytes]) -> set[str]:
    """Original identity evidence, independent of the replacement table.
    Every hostname-shaped harvest - nshardware/hanode/nshostname JSON and
    the 'set ns hostname' config line - is gathered through the single
    `consider` gate below, so the four-character floor applies uniformly
    and its warning prints at most once per distinct short name per run,
    however many of these sources happen to carry it (the normal shape of
    a real export: nshostname.json and the config agree)."""
    result: set[str] = set()
    warned: set[str] = set()

    def consider(host: str) -> None:
        # Same floor as _is_generic_derived_candidate (line ~352): a name
        # this short cannot be policed as a substring without also matching
        # unrelated technical vocabulary (policylabel, ns_cvpn_v2_url_label)
        # or ordinary prose. Renaming the host on the source is the only
        # fix; --extra-forbidden would instead swap a NetScaler keyword for
        # a customer alias and break the configuration text.
        if len(host) < 4:
            key = host.casefold()
            if key not in warned:
                print("[waarschuwing] hostnaam korter dan vier tekens; niet als substring te bewaken; blijft staan")
                warned.add(key)
            return
        result.add(host)

    for resource in ("nshardware", "hanode", "nshostname"):
        for row in _rows(blobs, resource + ".json", resource):
            for key, value in row.items():
                field = key.casefold()
                is_hostname = field in {"hostname", "host_name"} or (resource == "hanode" and field == "name")
                if is_hostname and isinstance(value, str) and value.strip() and _address(value) is None:
                    consider(value.strip())
    for name in ("parsed/runningconfig.txt", "parsed/savedconfig.txt"):
        if name not in blobs:
            continue
        for line in _text(blobs[name]).splitlines():
            if line.casefold().startswith("set ns hostname "):
                host = line[len("set ns hostname ") :].strip().strip('"')
                if host:
                    consider(host)
    return result


def protected_category(term: str) -> str | None:
    """Only known technical/public terms qualify for an operator diagnostic."""
    low = term.casefold()
    if low in {"root-servers", "root-servers.net"} or low.endswith(".root-servers.net"):
        return "rootserver"
    if low in {"cloud", "cloud.com", "netscaler"} or any(low == d or low.endswith("." + d) for d in VENDOR_SUFFIXES):
        return "leverancier"
    if low in CONFIG_TERMS or low in SEMANTIC_FIELDS or low in KEEP_NAMES:
        return "configparameter"
    if low in PLATFORM_TERMS or any(low == d or low.endswith("." + d) for d in PLATFORM_SUFFIXES):
        return "publiek platform"
    if low in _VENDOR_BUILTIN_NAMES_CF:
        return "ingebouwd"
    return None


def _strip_known_suffix(name: str) -> str | None:
    """The bare stem when a known FILE_SUFFIXES extension is present, else
    None. A sibling filename that keeps the stem but carries a different or
    missing extension is otherwise invisible to both the replacer (name
    boundaries) and the end gate (no known original)."""
    low = name.lower()
    for suffix in FILE_SUFFIXES:
        if low.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return None


# A generic technical vocabulary a DERIVED candidate (a stem or a path
# folder, never the full basename) must not collide with as a substring.
# Only fixed, non-customer words: never a source of a real original.
_GENERIC_DERIVED_VOCABULARY = frozenset(
    literal.casefold()
    for literal in PROTECTED_PUBLIC_SUFFIXES
    | KEEP_NAMES
    | CONFIG_TERMS
    | SEMANTIC_FIELDS
    | CERT_PATH_IGNORED_SEGMENTS
    | VENDOR_CERT_NAMES
)


def _is_generic_derived_candidate(name: str) -> bool:
    """A derived cert candidate (stem or folder - the full basename is
    exempt) is too generic to trust as a customer original when it is
    short, or itself a substring of a fixed technical/public vocabulary
    word (root inside root-servers.net, ssl inside a SEMANTIC_FIELDS
    value, ...). Excluding it only ever excludes generic vocabulary."""
    low = name.casefold()
    if len(name) < 4:
        return True
    return any(low in literal for literal in _GENERIC_DERIVED_VOCABULARY)


def check_extra_lines(lines: list[str]) -> list[str]:
    rejected = False
    for number, line in enumerate(lines, 1):
        term = line.strip()
        category = protected_category(term)
        if category:
            # Escaping prevents control characters or quotes from forging log lines.
            print(f"[fout] extra regel {number}: {json.dumps(term, ensure_ascii=True)} - {category}", file=sys.stderr)
            rejected = True
    if rejected:
        raise Refused("Extra termen raken beschermde categorieen; pas de genoemde regels aan")
    return sorted({line.strip() for line in lines if line.strip()})


def _is_builtin_row(row: dict) -> bool:
    """NITRO marks a vendor-shipped, on-every-appliance object with a
    non-empty 'builtin' list (MODIFIABLE/DELETABLE/IMMUTABLE/PARTITION_ALL,
    ...) on most object types. appfwprofile reuses the same key as a plain
    boolean instead - measured in tests/fixtures/lab-export-vpx-20260826,
    `true` marks exactly the four built-in profiles NetScaler ships on
    every appliance (APPFW_BYPASS/RESET/DROP/BLOCK), `false` the rest - so
    a boolean is honoured too, but only when it is literally True."""
    value = row.get("builtin")
    if isinstance(value, bool):
        return value
    return isinstance(value, list) and len(value) > 0


def builtin_names(blobs: dict[str, bytes]) -> frozenset[str]:
    """The full builtin vocabulary of THIS export: `_VENDOR_BUILTIN_NAMES_CF`
    (the fixed, measured list) plus every non-empty NAME_SOURCES name field
    on a builtin-flagged row (`_is_builtin_row`) that the fixed list does
    not cover. One shared set for three call sites - collect_candidates()'s
    fresh harvest, build_mapping()'s legacy-mapping filter, and the
    extra-literal route below - so an attribute-marked builtin name unknown
    to VENDOR_BUILTIN_NAMES is excluded on every one of those paths, not
    only the row-level skip a fresh harvest already has on its own.
    Cert-/key FILE names are deliberately outside this set (see
    collect_candidates' sslcertkey loop)."""
    return _VENDOR_BUILTIN_NAMES_CF | {
        value.casefold()
        for file, key, field, _ in NAME_SOURCES
        for row in _rows(blobs, file, key)
        if _is_builtin_row(row)
        for value in [row.get(field)]
        if isinstance(value, str) and value
    }


def collect_candidates(
    blobs: dict[str, bytes], extra: list[str], identity: set[str] | None = None
) -> dict[str, tuple[str, str | None]]:
    """Classify originals first; precedence and alias allocation are separate.
    `identity` lets a caller that already computed identity_hostnames(blobs)
    (execute(), for the leak-check identities) pass it through instead of
    triggering a second pass - identity_hostnames() also warns and excludes
    short names, and a second pass on the same blobs would warn twice."""
    candidates: dict[str, tuple[str, str | None]] = {}
    builtins = builtin_names(blobs)
    # VENDOR_BUILTIN_NAMES is measured, not a prefix rule (scripts/README.md):
    # a name with a vendor prefix that is NOT in the list still becomes a
    # normal candidate and gets replaced - safe, but worth a count so an
    # operator sees a possible list gap (a newer firmware/CVPN generation)
    # instead of it passing by silently.
    vendor_prefix_drift = 0
    for file, key, field, family in NAME_SOURCES:
        rows = _rows(blobs, file, key)
        monitor_types = {str(row.get("type", "")).casefold() for row in rows} if key == "lbmonitor" else set()
        for row in rows:
            # A built-in row (regel A) never yields a candidate, in no
            # family - not measured in this schema's own object types, but
            # cheap and future-proof for an export where it is.
            if _is_builtin_row(row):
                continue
            value = row.get(field)
            if value in (None, ""):
                continue
            if not isinstance(value, str):
                raise Refused("Objectnaam heeft een ongeldige vorm")
            if _allowed_alias(value):
                # Measured (18-9-2026): a candidate name in
                # exactly the shape this tool hands out itself - a
                # per-family `FAMILIE-NNN` alias (derived from
                # `NAME_SOURCES` via `_allowed_alias()`, so already general
                # across every family here, not a second, hand-kept list),
                # a `host-NNN.(lab.example|invalid)` alias, or one of the
                # fixed id-aliases - is never a fresh customer original. It
                # is this tool's own OUTPUT: a historical run from before
                # the manifest marker existed (addendum 6) just as much as
                # a fresh one, marker or not. Refuse before any mapping is
                # built, with its own diagnosis - no target directory, the
                # mapping unchanged. Conscious trade-off, documented in
                # scripts/README.md: a genuine first-time original spelled
                # exactly like such an alias is refused too; the operator
                # renames it on the source.
                raise Refused("Objectnaam heeft al de vorm van een pseudoniem van dit gereedschap; hernoem de bron")
            # Generic monitor names also occur as hyphen-delimited words in
            # protocol literals (DNS, TCP, CITRIX-STA-SERVICE, ...).
            generic_monitor = any("-" + value.casefold() + "-" in "-" + kind + "-" for kind in monitor_types)
            # VENDOR_BUILTIN_NAMES (regel B): a fixed, exact-casefold list of
            # NetScaler-shipped names not covered by regel A in this fixture
            # - never printed here, the same silent precedent as KEEP_NAMES,
            # since a real export can carry well over a hundred of them
            # (the built-in CVPN rewrite ruleset).
            if value.casefold() not in KEEP_NAMES and value.casefold() not in builtins and not generic_monitor:
                candidates.setdefault(value, (family, None))
                if value.casefold().startswith(("ns_cvpn_", "ns_default_")):
                    vendor_prefix_drift += 1
    if vendor_prefix_drift:
        # Nameless by design: the names themselves are already safe vendor
        # vocabulary to print, but the point here is the count, not which
        # ones - keeps this one line regardless of how many are found.
        print(
            f"[waarschuwing] {vendor_prefix_drift} niet-gelijste namen met een "
            "leveranciersvoorvoegsel (ns_cvpn_/ns_default_) zijn wel vervangen; "
            "controleer de mapping"
        )
    for row in _rows(blobs, "sslcertkey.json", "sslcertkey"):
        # Regel A does NOT apply here: a builtin certkey row still carries
        # operator-chosen cert/key file names (the certkey NAME itself is
        # already excluded above, via NAME_SOURCES and regel B). Skipping
        # the whole row would leave such a file name unreplaced and
        # invisible to the end gate - the exact fail-open shape this tool
        # must never have.
        for field in ("cert", "key", "linkcertkeyname"):
            value = row.get(field)
            if value in (None, ""):
                continue
            if not isinstance(value, str):
                raise Refused("Certificaatverwijzing heeft een ongeldige vorm")
            # Appliance paths are strings, never local files.
            path = PurePosixPath(value)
            basename = path.name
            if basename in {"", ".", ".."}:
                continue
            # The full basename (extension too) is ALWAYS a candidate, so
            # the boundary-respecting replacer keeps replacing it whole.
            names = [basename]
            # A known extension present also makes the bare stem a
            # candidate: a sibling filename that keeps the stem under a
            # different or missing extension is otherwise invisible to
            # both the replacer and the end gate. A folder component of
            # the path (e.g. a customer name under /nsconfig/ssl/<folder>/)
            # is a candidate too, unless it is a standard NetScaler
            # certificate-storage segment. Both are DERIVED - fragments the
            # script invented from a path, not names an operator chose -
            # so a short or generically technical one is skipped instead:
            # such a fragment is far more likely to collide with unrelated
            # schema text (root inside root-servers.net, ssl inside a
            # protocol value, a hex hash) than to be a real original.
            derived = []
            stem = _strip_known_suffix(basename)
            if stem:
                derived.append(stem)
            parent = path.parent.name
            if parent and parent.casefold() not in CERT_PATH_IGNORED_SEGMENTS:
                derived.append(parent)
            for candidate_name in derived:
                if _is_generic_derived_candidate(candidate_name):
                    # Never name the candidate here: unlike a protected_category
                    # match below, this is only a heuristic (length or a
                    # generic-vocabulary substring), not a positively known
                    # public/technical term.
                    reason = "te kort" if len(candidate_name) < 4 else "raakt technisch vocabulaire"
                    print(f"[waarschuwing] afgeleide certificaatnaam {reason}; niet als kandidaat opgenomen")
                    continue
                names.append(candidate_name)
            for candidate_name in names:
                category = protected_category(candidate_name)
                if category is not None:
                    # Safe to print: a protected term is known technical or
                    # public vocabulary, never customer data (same policy
                    # as check_extra_lines above).
                    print(
                        f"[waarschuwing] certificaatnaam raakt {category}; "
                        f"niet als kandidaat opgenomen: {candidate_name}"
                    )
                    continue
                candidates.setdefault(candidate_name, ("CERT", None))
    texts = {name: _text(data) for name, data in blobs.items()}
    hosts: set[str] = set(identity) if identity is not None else identity_hostnames(blobs)

    def harvest(text):
        for match in HOST_RX.finditer(text):
            host = match.group(0)
            if not host.lower().endswith(FILE_SUFFIXES) and not _public_host(host):
                hosts.add(host)

    for row in _rows(blobs, "server.json", "server"):
        if isinstance(row.get("domain"), str):
            harvest(row["domain"])
    for name in ("parsed/runningconfig.txt", "parsed/savedconfig.txt"):
        for line in texts.get(name, "").splitlines():
            if line.casefold().startswith(tuple(p.casefold() for p in HOST_LINE_PREFIXES)):
                harvest(line)
            # 'set ns hostname' itself, including its four-character floor
            # and de-duplicated warning, is harvested once by
            # identity_hostnames() above (and seeded into `hosts` via
            # `identity`) - nshostname.json/hanode.json normally carry the
            # same value, so re-adding it here unfiltered would silently
            # undo that floor for the config-line copy.
    if "scan-doel.txt" in texts:
        name = texts["scan-doel.txt"].splitlines()[0].strip()
        if name and _address(name) is None:
            # Same four-character floor as identity_hostnames() above and
            # _is_generic_derived_candidate (line ~352): a target name this
            # short cannot be policed as a substring without also matching
            # unrelated technical vocabulary (policylabel, ns_cvpn_v2_url_label)
            # or ordinary prose. Renaming the target on the source is the
            # only fix; --extra-forbidden would instead swap a NetScaler
            # keyword for a customer alias and break the configuration text.
            if len(name) < 4:
                print("[waarschuwing] doelnaam korter dan vier tekens; niet als substring te bewaken; blijft staan")
            else:
                hosts.add(name)
    suffixes = {".".join(host.casefold().split(".")[-2:]) for host in hosts if "." in host}
    # A certificate named after its host embeds the stem in subject/issuer
    # (and similar fields) as <stem>.<domain> - one unbroken dotted token,
    # since "." is never a name-boundary. Harvesting only the stem (an
    # object name or a cert basename/stem, already in `candidates` by this
    # point) leaves it dangling inside that token: unreplaceable, yet still
    # a known original for the boundary-free end gate. Harvesting the WHOLE
    # token here - whenever its first label matches an already-known
    # original - lets the (longest-first) replacer remove it in one piece.
    known_labels = {key.casefold() for key in candidates} | {host.casefold().split(".")[0] for host in hosts}
    for text in texts.values():
        for match in HOST_RX.finditer(text):
            token = match.group(0)
            low = token.casefold()
            if _public_host(token) or low.endswith(FILE_SUFFIXES):
                continue
            suffix_known = low.endswith((".nl", ".local")) or any(low == s or low.endswith("." + s) for s in suffixes)
            first_label_known = token.split(".", 1)[0].casefold() in known_labels
            if suffix_known or first_label_known:
                hosts.add(token)
    for host in sorted(hosts | suffixes):
        candidates[host] = ("host", None)
    for text in texts.values():
        for match in IP_RX.finditer(text):
            ip = _address(match.group(0))
            if ip is not None and any(ip in net for net in PRIVATE_NETS):
                candidates[str(ip)] = ("ip", None)
        for match in MAC_RX.finditer(text):
            value = match.group(0)
            if value.lower() != NEUTRAL_MAC_COLON:
                candidates[value] = ("fixed", NEUTRAL_MAC_COLON)
                candidates[value.replace(":", "")] = ("fixed", NEUTRAL_IDENTITY["host"])
    for row in _rows(blobs, "nshardware.json", "nshardware"):
        for key, neutral in NEUTRAL_IDENTITY.items():
            value = row.get(key)
            if value is None or value == "":
                continue
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise Refused("Apparaatidentiteit heeft een ongeldige vorm")
            if key == "serialno" and any(o.casefold() in str(neutral).casefold() for o in candidates):
                neutral = "SERIAL1"
            if str(value).casefold() != str(neutral).casefold():
                candidates[str(value)] = ("fixed", str(neutral))
    # An IP/hardware/name already classified above must retain its type even
    # when the operator's list also contains it. Extra literals extend the set.
    known = {value.casefold() for value in candidates}
    for value in extra:
        if value.casefold() in builtins:
            # The operator supplied this literal themselves via
            # --extra-forbidden, so echoing it back is the same policy as
            # check_extra_lines above - but that check only knows the fixed
            # VENDOR_BUILTIN_NAMES list, not an attribute-marked builtin name
            # from THIS export, so this is the backstop for it.
            print(
                f"[fout] extra term raakt een ingebouwde naam: {json.dumps(value, ensure_ascii=True)}",
                file=sys.stderr,
            )
            raise Refused("Extra term raakt een ingebouwde naam; pas de genoemde regel aan")
        if value.casefold() not in known:
            candidates[value] = ("TERM", None)
    return candidates


def _allowed_alias(value: str) -> bool:
    fixed = FIXED_ALIASES
    families = "|".join(sorted({entry[3] for entry in NAME_SOURCES} | {"TERM"}))
    ip = _address(value)
    return (
        value in fixed
        or re.fullmatch(rf"(?:{families})-\d{{3,}}", value) is not None
        or re.fullmatch(r"host-\d{3,}\.(?:lab\.example|invalid)", value) is not None
        or (
            ip is not None
            and any(ip in net and ip not in (net.network_address, net.broadcast_address) for net in TESTNETS)
        )
    )


def _validate_mapping_shape(mapping: dict) -> None:
    """Structural checks only: a dict, string original/alias, a non-empty
    original, a syntactically valid alias form. Deliberately no semantic
    checks here (identity exception, KEEP_NAMES, consistency, collisions) -
    those must run only on what SURVIVES build_mapping()'s short-name/
    builtin filter, never on `existing` before that filter runs, or a
    legacy entry the filter would otherwise skip with a warning refuses the
    whole run instead. See validate_mapping() below and build_mapping()."""
    if not isinstance(mapping, dict):
        raise Refused("Bestaande mapping heeft een ongeldige vorm")
    for original, alias in mapping.items():
        if not isinstance(original, str) or not original or not isinstance(alias, str) or not _allowed_alias(alias):
            raise Refused("Bestaande mapping bevat een ongeldige vermelding")


def validate_mapping(mapping: dict, extra: list[str] | None = None) -> None:
    _validate_mapping_shape(mapping)
    aliases: dict[str, str] = {}
    originals: dict[str, str] = {}
    fixed = FIXED_ALIASES
    explicit = {value.casefold() for value in (extra or [])}
    for original, alias in mapping.items():
        low = original.casefold()
        explicit_lab = low in explicit and (low == "lab.example" or low.endswith(".lab.example"))
        if low == alias.casefold() or low in KEEP_NAMES or (_public_host(original) and not explicit_lab):
            raise Refused("Mapping raakt een uitzondering of bevat een identiteitsmapping")
        previous = originals.setdefault(original.casefold(), alias)
        if previous != alias:
            raise Refused("Mapping is niet consistent voor hoofdlettervarianten")
        first = aliases.setdefault(alias.casefold(), original.casefold())
        if first != original.casefold() and alias not in fixed:
            raise Refused("Mapping bevat botsende pseudoniemen")
    matcher = MappingTable(mapping).pattern
    for alias in mapping.values():
        if matcher is not None and matcher.search(alias):
            raise Refused("Pseudoniem bevat nog een origineel")


def build_mapping(
    blobs: dict[str, bytes], extra: list[str], existing: dict, identity: set[str] | None = None
) -> dict[str, str]:
    _validate_mapping_shape(existing)
    candidates = collect_candidates(blobs, extra, identity=identity)
    builtins = builtin_names(blobs)
    mapping: dict[str, str] = {}
    retired_aliases: set[str] = set()
    for original, alias in existing.items():
        # Same four-character floor as identity_hostnames()/collect_candidates
        # (scripts/README.md): a legacy mapping.json entry this short can no
        # longer be policed as a substring either - the families-based end
        # gate has no boundaries, so keeping it would let it flag an
        # unrelated fixed alias that merely contains it (LABSERIAL1, ...) as
        # a false leak. Drop it from the working and rewritten mapping
        # instead of reusing it, and never print the name itself; the
        # operator removes the entry (or renames the source) the same way
        # as for a fresh short name.
        if len(original) < 4:
            print(
                "[waarschuwing] bestaande mapping bevat een naam korter dan "
                "vier tekens; niet als substring te bewaken; overgeslagen"
            )
            retired_aliases.add(alias)
            continue
        # regel B (VENDOR_BUILTIN_NAMES): a legacy mapping entry for a
        # NetScaler-shipped name is dropped the same way as a too-short one
        # (retired alias stays occupied, see below) - unlike that case the
        # name itself is safe to print, vendor vocabulary is public.
        if original.casefold() in _VENDOR_BUILTIN_NAMES_CF:
            print(f"[waarschuwing] bestaande mapping bevat een ingebouwde leveranciersnaam ({original}); overgeslagen")
            retired_aliases.add(alias)
            continue
        # An attribute-marked builtin name (`_is_builtin_row` in THIS
        # export) that VENDOR_BUILTIN_NAMES does not cover: same drop and
        # reserved alias as regel B above, but unlike that fixed public
        # vocabulary an arbitrary attribute-marked name is not known-safe to
        # print - never assume it is.
        if original.casefold() in builtins:
            print("[waarschuwing] bestaande mapping bevat een ingebouwde naam (niet in de vaste lijst); overgeslagen")
            retired_aliases.add(alias)
            continue
        mapping[original] = alias
    # Semantic checks (identity exception, KEEP_NAMES, consistency,
    # collisions) run on what SURVIVED the filter above, never on `existing`
    # itself: a legacy entry the filter above would otherwise skip with a
    # warning must not refuse the whole run before it gets the chance to.
    validate_mapping(mapping, extra)
    all_text = "\n".join(_text(data) for data in blobs.values()).casefold()
    originals = {v.casefold() for v in candidates} | {v.casefold() for v in mapping}
    by_case = {key.casefold(): key for key in mapping}
    # A retired alias is never handed out again in this run, even though its
    # original is gone: reusing it for an unrelated candidate would break
    # alias stability across a delivery for anyone still holding the old one.
    occupied = set(mapping.values()) | retired_aliases
    fixed = FIXED_ALIASES

    def available(alias):
        return (
            alias not in occupied
            and alias.casefold() not in all_text
            and not any(o in alias.casefold() for o in originals)
        )

    pool = (str(ip) for net in TESTNETS for ip in net.hosts())
    counters: dict[str, int] = {}
    # Family order is explicit. IP order is numeric, all other ordering lexical.
    families = [entry[3] for entry in NAME_SOURCES] + ["host", "ip", "fixed", "TERM"]

    def order(item):
        original, (family, _) = item
        value = int(ipaddress.IPv4Address(original)) if family == "ip" else original.casefold()
        return families.index(family), value, original

    for original, (family, neutral) in sorted(candidates.items(), key=order):
        if original.casefold() in by_case:
            alias = mapping[by_case[original.casefold()]]
            if neutral is not None and alias != neutral:
                raise Refused("Mapping wijkt af van de vaste apparaatidentiteit")
            if neutral is None:
                valid = (
                    _address(alias) is not None
                    if family == "ip"
                    else re.fullmatch(r"host-\d{3,}\.(?:lab\.example|invalid)", alias)
                    if family == "host"
                    else re.fullmatch(re.escape(family) + r"-\d{3,}", alias)
                )
                if not valid:
                    raise Refused("Bestaand pseudoniem heeft een verkeerde naamfamilie of gegevenstype")
            if alias.casefold() in all_text and alias not in fixed:
                raise Refused("Bestaand pseudoniem botst met de nieuwe bron")
            continue
        if neutral is not None:
            alias = neutral
        elif family == "ip":
            alias = next((ip for ip in pool if available(ip)), None)
            if alias is None:
                raise Refused("Te weinig vrije TEST-NET-adressen")
        else:
            prefix = "host-" if family == "host" else family + "-"
            suffix = ".lab.example" if family == "host" else ""
            # The reference appliance's hostname is literally LAB. Embedding
            # that original in every alias would defeat the final leak check.
            if suffix and any(o in suffix for o in originals):
                suffix = ".invalid"
            if any(o in prefix.casefold() or (suffix and o in suffix) for o in originals):
                raise Refused("Origineel botst met de verplichte pseudoniemvorm")
            alias = ""
            for _ in range(10000):
                counters[family] = counters.get(family, 0) + 1
                alias = f"{prefix}{counters[family]:03d}{suffix}"
                if available(alias):
                    break
            else:
                raise Refused("Geen vrij pseudoniem beschikbaar")
        mapping[original] = str(alias)
        occupied.add(str(alias))
        by_case[original.casefold()] = original
    validate_mapping(mapping, extra)
    return mapping


class MappingTable(dict):
    """One replacement pass: aliases are never fed into later replacements."""

    def __init__(self, mapping):
        super().__init__(mapping)
        self.by_case = {key.casefold(): value for key, value in mapping.items()}
        names = []
        addresses = []
        parts = []
        for key in sorted(mapping, key=lambda k: (-len(k), k)):
            if _address(key) is not None:
                addresses.append(re.escape(key))
            else:
                names.append(re.escape(key))
        # Check boundaries once per group, not once per original at every byte.
        if names:
            parts.append(r"(?<![A-Za-z0-9_.-])(?:" + "|".join(names) + r")(?![A-Za-z0-9_.-])")
        if addresses:
            parts.append(r"(?<![\d.])(?:" + "|".join(addresses) + r")(?![\d.])")
        self.pattern = re.compile("|".join(parts), re.IGNORECASE) if parts else None


def apply_mapping(text: str, mapping: MappingTable) -> str:
    if mapping.pattern is None:
        return text
    return mapping.pattern.sub(lambda match: mapping.by_case[match.group().casefold()], text)


def _transform_json(value, mapping, protect_keys=False):
    if isinstance(value, str):
        return apply_mapping(value, mapping)
    if type(value) is int and str(value).casefold() in mapping.by_case:
        alias = mapping.by_case[str(value).casefold()]
        if not alias.isdecimal():
            raise Refused("Mapping zou het type van een getal wijzigen")
        return int(alias)
    if isinstance(value, list):
        return [_transform_json(row, mapping, protect_keys) for row in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            new_key = apply_mapping(key, mapping)
            if protect_keys and new_key != key:
                raise Refused("Pseudonimisering zou een JSON-veldnaam wijzigen")
            if new_key in result:
                raise Refused("Pseudonimisering zou JSON-sleutels laten botsen")
            changed = _transform_json(item, mapping, protect_keys)
            if key.casefold() in SEMANTIC_FIELDS and changed != item:
                raise Refused("Pseudonimisering zou een protocol- of statuswaarde wijzigen")
            result[new_key] = changed
        return result
    return value


def transform(blobs: dict[str, bytes], mapping: dict) -> dict[str, bytes]:
    table = MappingTable(mapping)
    for literal in KEEP_NAMES:
        if apply_mapping(literal, table) != literal:
            raise Refused("Pseudonimisering zou een beschermde naam wijzigen")
    for literal in PROTECTED_PUBLIC_SUFFIXES:
        if apply_mapping(literal, table) != literal:
            raise Refused("Pseudonimisering zou een toegestaan leveranciersdomein wijzigen")
    result = {}
    for name, data in blobs.items():
        text = _text(data)
        decoded = json.dumps(_json(text), ensure_ascii=False) if name.endswith(".json") else text
        for match in HOST_RX.finditer(decoded):
            host = match.group()
            lab_alias = host.casefold() == "lab.example" or host.casefold().endswith(".lab.example")
            if _public_host(host) and not lab_alias and apply_mapping(host, table) != host:
                raise Refused("Pseudonimisering zou een toegestane publieke hostnaam wijzigen")
        if name.endswith(".json"):
            value = neutralise_json(_json(text))
            result[name] = _encode(_transform_json(value, table, protect_keys=name.startswith("objects/")), data)
        else:
            neutral = neutralise_config_text(text) if name in CONFIG_TEXT_FILES else text
            result[name] = _encode_text(apply_mapping(neutral, table), data)
    manifest = _json(_text(result[MANIFEST]))
    original = _json(_text(blobs[MANIFEST]))
    if set(manifest["resources"]) != set(original["resources"]) or set(manifest["files"]) != set(original["files"]):
        raise Refused("Pseudonimisering zou de manifeststructuur wijzigen")
    for resource, entry in manifest["resources"].items():
        if entry.get("payloadSha256"):
            file = resource_file(resource)
            entry["payloadSha256"] = _payload_hash(file, result[file])
    for file in manifest["files"]:
        if manifest["files"][file]:
            manifest["files"][file] = _payload_hash(file, result[file])
    # Marks every fresh output as pseudonymised, so execute() can refuse a
    # second pass over it directly on this marker - an invariant of its own,
    # not a coincidental collision with the public-suffix host-alias check
    # (a source without any host alias was previously re-aliased silently
    # on a second pass). Set AFTER the hash loops above so both the
    # manifest's own recomputed hashes and the scan-doel.txt stamp below
    # (computed from these encoded bytes) already reflect it.
    manifest["pseudonymisation"] = {"version": 1}
    result[MANIFEST] = _encode(manifest, blobs[MANIFEST])
    if "scan-doel.txt" in result:
        name = _text(result["scan-doel.txt"]).splitlines()[0]
        newline = _newline(blobs["scan-doel.txt"])
        result["scan-doel.txt"] = _encode_text(
            name + newline + _hash(result[MANIFEST]).lower() + newline, blobs["scan-doel.txt"]
        )
    validate_manifest(result)
    return result


def _decoded_json_parts(value) -> tuple[list[str], list[str]]:
    """Decoded JSON split into (keys, values), both read raw - never
    rebuilt through json.dumps. Re-serializing would re-escape quotes,
    backslashes and control characters, letting an original carrying one
    of those hide inside a decoded string while a scan built from the
    re-encoded text still reports it as clean."""
    if isinstance(value, str):
        return [], [value]
    if isinstance(value, bool) or value is None:
        return [], []
    if isinstance(value, (int, float)):
        return [], [str(value)]
    if isinstance(value, dict):
        keys: list[str] = []
        values: list[str] = []
        for key, item in value.items():
            keys.append(key)
            sub_keys, sub_values = _decoded_json_parts(item)
            keys.extend(sub_keys)
            values.extend(sub_values)
        return keys, values
    if isinstance(value, list):
        keys, values = [], []
        for item in value:
            sub_keys, sub_values = _decoded_json_parts(item)
            keys.extend(sub_keys)
            values.extend(sub_values)
        return keys, values
    return [], []


def _origin_family(alias: str) -> str:
    """The alias prefix is always safe, fixed vocabulary - never an
    original - so it is safe to name in a public diagnostic."""
    if alias in FIXED_ALIASES:
        return "fixed"
    if _address(alias) is not None:
        return "ip"
    return alias.split("-", 1)[0]


def verify(blobs: dict[str, bytes], mapping: dict, original_hostnames=()) -> None:
    """Also inspect decoded JSON: every key/string value, read raw, never
    rebuilt through a re-encoding step that could hide an original. The
    diagnosis names the family of the original (from its alias prefix -
    always safe vocabulary) and, when the hit sits only inside a JSON key
    or a filename rather than any actual value, says so: that is a schema
    collision an operator cannot resolve via --extra-forbidden."""
    families = {value.casefold(): _origin_family(alias) for value, alias in mapping.items()}
    identities = {value.casefold() for value in original_hostnames}
    for index, (name, data) in enumerate(sorted(blobs.items()), 1):
        raw_text = _text(data)
        if name.endswith(".json"):
            keys, values = _decoded_json_parts(_json(raw_text))
            value_text = "\n".join(values).casefold()
        else:
            keys, values = [], []
            value_text = raw_text.casefold()
        text = "\n".join([name, raw_text, *keys, *values]).casefold()
        file = _diagnostic_file(name, index, set(families) | identities)
        # End gates deliberately have NO replacement boundaries. An original
        # inside a longer token is still a leak even when it cannot be replaced.
        # Sorted: two runs with the same leak must name the same family,
        # never depend on the mapping dict's (re-used, hand-editable) order.
        matched = next((original for original in sorted(families) if original in text), None)
        if matched is not None:
            location = "" if matched in value_text else " (in sleutel of bestandsnaam)"
            raise Refused(
                f"Lekcontrole: gemapt origineel achtergebleven; familie {families[matched]}{location}; bestand {file}"
            )
        if any(original in text for original in identities):
            raise Refused(f"Lekcontrole: oorspronkelijke apparaathostnaam achtergebleven; familie host; bestand {file}")
        for match in IP_RX.finditer(text):
            ip = _address(match.group())
            if ip is not None and any(ip in net for net in PRIVATE_NETS):
                raise Refused(f"Lekcontrole: intern IPv4-adres achtergebleven; familie ip; bestand {file}")
        if re.search(r"\.(?:nl|local)\b", text):
            raise Refused(f"Lekcontrole: interne domeinverwijzing achtergebleven; familie host; bestand {file}")
        if name.endswith(".json"):
            decoded = _json(raw_text)
            survived = neutralise_json(decoded) != decoded
        else:
            survived = name in CONFIG_TEXT_FILES and neutralise_config_text(raw_text) != raw_text
        if survived:
            raise Refused(f"Lekcontrole: vrije tekst achtergebleven; bestand {file}")


def _diagnostic_file(name: str, index: int, originals) -> str:
    """Only known schema filenames may be logged; others get an ordinal."""
    known = (
        {"objects/" + row[0] for row in NAME_SOURCES}
        | set(SPECIAL_RESOURCE_FILES.values())
        | {
            MANIFEST,
            "scan-doel.txt",
            "collect-log.txt",
            "objects/nshardware.json",
            "objects/hanode.json",
            "objects/nshostname.json",
        }
    )
    if name in known and not any(value.casefold() in name.casefold() for value in originals):
        return name
    return f"#{index} (naam afgeschermd)"


def _hash_gap_label(name: str, index: int, originals) -> str:
    """warn_missing_hashes may show any manifest-derived name (a files key
    or a resource_file() result: both schema-shaped, never customer
    content) as long as it does not itself contain a known original -
    unlike _diagnostic_file's stricter allowlist for arbitrary blob names
    inside the leak check itself, which stays conservative."""
    if not any(value.casefold() in name.casefold() for value in originals):
        return name
    return f"#{index} (naam afgeschermd)"


def warn_missing_hashes(manifest: dict, blobs: dict[str, bytes], originals) -> None:
    """Report each expected but absent hash without manufacturing evidence."""
    indices = {name: index for index, name in enumerate(sorted(blobs), 1)}

    def warn(name, kind, *, manifest_derived):
        # Only a files-key or a resource_file() result is schema-derived
        # (never customer content) and may use the more permissive label; a
        # blob that merely starts with bindings/ or parsed/ but was never
        # declared in the manifest at all falls back to the conservative
        # allowlist verify() itself uses.
        label = _hash_gap_label if manifest_derived else _diagnostic_file
        file = label(name, indices.get(name, 0), originals)
        print(f"[waarschuwing] {kind} ontbreekt; bestand {file}; dit leesgat blijft in de uitvoer behouden")

    for resource, entry in manifest["resources"].items():
        if entry["status"] in {"OK", "EMPTY"} and not entry.get("payloadSha256"):
            warn(resource_file(resource), "payloadSha256", manifest_derived=True)
    expected_files = set(manifest["files"]) | {name for name in blobs if name.startswith(("bindings/", "parsed/"))}
    for name in sorted(expected_files):
        if not manifest["files"].get(name):
            warn(name, "fileSha256", manifest_derived=name in manifest["files"])


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _in_repo(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def _atomic_file(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=".pseudo-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def execute(source: Path, target: Path, mapping_dir: Path, extra_file: Path | None) -> int:
    # Resolve before containment checks, including junctions and linked worktrees.
    source, target, mapping_dir = (p.resolve() for p in (source, target, mapping_dir))
    if target.exists():
        raise Refused("Doel bestaat al; kies een nieuwe doelmap")
    if any(_inside(a, b) or _inside(b, a) for a, b in ((source, target), (source, mapping_dir), (target, mapping_dir))):
        raise Refused("Bron, doel en mappingmap mogen niet overlappen")
    if _in_repo(mapping_dir):
        raise Refused("Mappingmap moet buiten de repository staan")
    extra = []
    if extra_file is not None:
        extra_file = extra_file.resolve()
        if _in_repo(extra_file) or _inside(extra_file, source) or _inside(extra_file, target):
            raise Refused("Extra verboden literalen moeten buiten repository, bron en doel staan")
        extra = check_extra_lines(_text(extra_file.read_bytes()).splitlines())
    blobs = read_source(source)
    source_manifest = validate_manifest(blobs, source_newlines=True)
    if "pseudonymisation" in source_manifest:
        # Own invariant, checked directly after source validation and
        # before anything else (no target, no mapping read or written): a
        # source WITHOUT this marker (every fixture shipped before this
        # check existed) still relies solely on the alias-collision
        # fallback below, and stays refused by that path instead.
        raise Refused("Bron is al gepseudonimiseerd (marker in manifest); tweede pas is niet toegestaan")
    original_hostnames = identity_hostnames(blobs)
    print("[ok] bronmanifest, hashes en structuur gecontroleerd")
    mapping_dir.mkdir(parents=True, exist_ok=True)
    lock = mapping_dir / ".pseudonymise.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise Refused("Mappingmap is vergrendeld door een andere of onderbroken run") from exc
    os.close(fd)
    stage: Path | None = None
    try:
        mapping_file = mapping_dir / "mapping.json"
        existing = _json(_text(mapping_file.read_bytes())) if mapping_file.exists() else {}
        mapping = build_mapping(blobs, extra, existing, identity=original_hostnames)
        warn_missing_hashes(source_manifest, blobs, set(mapping) | original_hostnames)
        output = transform(blobs, mapping)
        verify(output, mapping, original_hostnames)
        print(f"[ok] {len(mapping)} originelen vervangen; hashes en lekcontrole akkoord")
        target.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".pseudonymise-", dir=target.parent))
        for name, data in output.items():
            file = stage / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        # Verify the bytes that will actually be published, not just memory.
        staged = read_source(stage)
        validate_manifest(staged)
        verify(staged, mapping, original_hostnames)
        _atomic_file(mapping_file, _encode(dict(sorted(mapping.items()))))
        _atomic_file(mapping_dir / "verboden.txt", ("\n".join(sorted(mapping)) + "\n").encode("utf-8"))
        if target.exists():
            raise Refused("Doel is tijdens de run aangemaakt; uitvoer niet gepubliceerd")
        stage.rename(target)
        stage = None
        print("[ok] nieuwe doelmap gepubliceerd; mapping blijft buiten de repository")
        return len(mapping)
    finally:
        # Only the random directory created by this invocation may be removed.
        if stage is not None and stage.parent == target.parent and stage.name.startswith(".pseudonymise-"):
            shutil.rmtree(stage)
        lock.unlink(missing_ok=True)


def execute_free_text(source: Path, target: Path, extra_file: Path | None) -> int:
    """The after-treatment of an export that was pseudonymised before the
    free-text fields were covered: no alias harvest and no mapping
    directory. Free text and EUI-64 link-local addresses are neutralised,
    every literal of the optional extra-terms file becomes a TERM alias,
    the hashes and the scan stamp are recomputed and the result passes the
    same leak check as a full run. Returns the number of changed files."""
    source, target = (p.resolve() for p in (source, target))
    if target.exists():
        raise Refused("Doel bestaat al; kies een nieuwe doelmap")
    if _inside(source, target) or _inside(target, source):
        raise Refused("Bron en doel mogen niet overlappen")
    extra = []
    if extra_file is not None:
        extra_file = extra_file.resolve()
        if _in_repo(extra_file) or _inside(extra_file, source) or _inside(extra_file, target):
            raise Refused("Extra verboden literalen moeten buiten repository, bron en doel staan")
        extra = check_extra_lines(_text(extra_file.read_bytes()).splitlines())
    blobs = read_source(source)
    validate_manifest(blobs, source_newlines=True)
    print("[ok] bronmanifest, hashes en structuur gecontroleerd")
    builtins = builtin_names(blobs)
    if any(value.casefold() in builtins for value in extra):
        raise Refused("Extra term raakt een ingebouwde naam; pas de extra termen aan")
    all_text = "\n".join(_text(data) for data in blobs.values()).casefold()
    mapping: dict[str, str] = {}
    counter = 0
    for value in extra:
        counter += 1
        while f"term-{counter:03d}" in all_text:
            counter += 1
        mapping[value] = f"TERM-{counter:03d}"
    validate_mapping(mapping, extra)
    output = transform(blobs, mapping)
    # The source is already pseudonymised: its device names ARE aliases, so
    # there is no original host identity left to look for.
    verify(output, mapping)
    changed = sum(1 for name, data in output.items() if blobs.get(name) != data)
    print(f"[ok] {changed} bestanden herschreven; {len(mapping)} extra termen vervangen; lekcontrole akkoord")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".pseudonymise-", dir=target.parent))
    try:
        for name, data in output.items():
            file = stage / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        staged = read_source(stage)
        validate_manifest(staged)
        verify(staged, mapping)
        if target.exists():
            raise Refused("Doel is tijdens de run aangemaakt; uitvoer niet gepubliceerd")
        stage.rename(target)
        stage = None
        print("[ok] nieuwe doelmap gepubliceerd")
        return changed
    finally:
        if stage is not None and stage.parent == target.parent and stage.name.startswith(".pseudonymise-"):
            shutil.rmtree(stage)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pseudonimiseer een NSHC-export naar een nieuwe map; mapping blijft buiten de repo."
    )
    parser.add_argument("--source", required=True, type=Path, help="Bestaande exportmap")
    parser.add_argument("--target", required=True, type=Path, help="Nieuwe doelmap (mag nog niet bestaan)")
    parser.add_argument("--mapping", type=Path, help="Mappingmap buiten de repository; hergebruik is toegestaan")
    parser.add_argument("--extra-forbidden", type=Path, help="Bestand buiten de repo met een extra literal per regel")
    parser.add_argument(
        "--free-text-only",
        action="store_true",
        help="Alleen vrije tekst neutraliseren en hashes herrekenen, op een al gepseudonimiseerde export",
    )
    args = parser.parse_args(argv)
    if args.free_text_only:
        if args.mapping is not None:
            parser.error("--free-text-only gebruikt geen --mapping")
        print("[start] nabehandeling vrije tekst van export")
        try:
            execute_free_text(args.source, args.target, args.extra_forbidden)
        except Refused as exc:
            print(f"[fout] {exc}", file=sys.stderr)
            print("[eindstatus] MISLUKT - geen nieuwe doelmap gepubliceerd", file=sys.stderr)
            return 1
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            print("[fout] Bestandsbewerking of gegevensvalidatie mislukt; inhoud niet gelogd", file=sys.stderr)
            print("[eindstatus] MISLUKT - geen nieuwe doelmap gepubliceerd", file=sys.stderr)
            return 1
        print("[eindstatus] GESLAAGD - vrije tekst geneutraliseerd, hashes herrekend, lekcontrole akkoord")
        return 0
    if args.mapping is None:
        parser.error("--mapping is verplicht")
    print("[start] pseudonimisering van export")
    try:
        execute(args.source, args.target, args.mapping, args.extra_forbidden)
    except Refused as exc:
        print(f"[fout] {exc}", file=sys.stderr)
        print("[eindstatus] MISLUKT - geen nieuwe doelmap gepubliceerd", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        print("[fout] Bestandsbewerking of gegevensvalidatie mislukt; inhoud niet gelogd", file=sys.stderr)
        print("[eindstatus] MISLUKT - geen nieuwe doelmap gepubliceerd", file=sys.stderr)
        return 1
    print("[eindstatus] GESLAAGD - geen enkel gemapt origineel meer in het doel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
