"""Running config against saved config: the one comparison, and `config_drift`.

The two real lab exports are the gold standard here. Both carry a running
config that differs from its saved config in exactly three lines, and all
three are artefacts of how the appliance writes the two files, not
configuration: the header line `# Last modified ...` (a different text on each
side) and the closing ` Done` of the running config. The comparison leaves
out every stripped line that starts with `#` or is exactly `Done`; everything
else counts, as a multiset.

`config_drift` is the one tool that shows configuration lines, so most of
this file is about the fences around that: a line only at openheid
`volledig`, a line with a secret never, a command head (never an argument)
at `beperkt`, only counts at `minimaal`, and a cap on length and number.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import date
from pathlib import Path

import pytest
from config_export_harness import (
    COLLECTOR_MARKER_LINES,
    DOH,
    INSERTED,
    LAB,
    NEW_SECRET,
    OLD_SECRET,
    RUNNING_HEADER,
    SAVED_AFTER_CHANGE_HEADER,
    SAVED_HEADER,
    WITHHELD_ONLY_PAIRS,
    config_pair,
    copy_with_running,
    insert_after_line,
)
from conftest import provenance_dir_for, record_collected
from upgrade_fase_harness import _call, _knowledge, _text

from nsmcp import config_drift as drift_module
from nsmcp.answer import stamp_data
from nsmcp.config_drift import comparable_lines, compare_config, comparison_evidence, read_comparison
from nsmcp.disclosure import Disclosure, names_from_export, render
from nsmcp.export import load_export
from nsmcp.ha import DRIFT_LABEL, OFF, ON, UNCONFIRMED, ha_result
from nsmcp.knowledge import Knowledge
from nsmcp.mcp_server import DEFAULT_CHAPTERS, ONBEKEND_DOEL_TEXT, build_server

_KNOWLEDGE = Knowledge(version="drifttest", date="2026-09-24", age_days=0, missing=False)
TODAY = date(2026, 9, 24)

# The body both sides of a synthetic pair share. Synthetic names and
# TEST-NET addresses only.
BASE = [
    "set ns config -IPAddress 192.0.2.2 -netmask 255.255.255.0",
    "add server SRV-001 192.0.2.10",
    "add serviceGroup SG-001 HTTP",
    "bind serviceGroup SG-001 SRV-001 80",
    "add lb vserver LBV-001 HTTP 192.0.2.20 80",
    "bind lb vserver LBV-001 SG-001",
]


def _pair(tmp_path, extra_running=(), extra_saved=()):
    return load_export(
        config_pair(
            tmp_path,
            RUNNING_HEADER + BASE + list(extra_running) + [" Done"],
            SAVED_HEADER + BASE + list(extra_saved),
        )
    )


def _render(export, level, tmp_path):
    answer = stamp_data(drift_module.drift_answer(export, _KNOWLEDGE), export.collected_at, TODAY, export.target_name)
    return render(
        answer,
        level,
        tool="config_drift",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )


# ---------------------------------------------------------------------------
# The shared normalization, through `ha_result` (the reader `ha_stand`, the
# scorecard and pre-flight check 3 all go through).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "state"),
    [(LAB, UNCONFIRMED), (DOH, OFF)],
    ids=["lab-20260826", "lab-doh-synthetic"],
)
def test_the_header_lines_and_done_are_not_drift_on_either_lab_export(fixture, state):
    """On neither export do the header lines or `Done` count: 0 and 0. The
    first export still does not come out `uit`: its headers say it changed
    after the last save, and ten lines per side carry a value the collector
    withheld, so whether that change sits in such a value cannot be compared
    (see the section on the collector's marker below). The second export
    was saved at the moment of its last change."""
    result, gaps = ha_result(load_export(fixture))
    assert gaps == ()
    assert result.drift.state == state, result.drift.evidence
    assert "0 alleen in running, 0 alleen in saved" in result.drift.evidence
    assert (DRIFT_LABEL in result.blockers) is (state == UNCONFIRMED)


def test_a_deliberately_inserted_line_is_drift_on_the_real_export(tmp_path):
    export = load_export(copy_with_running(tmp_path, LAB, insert_after_line(3, INSERTED)))
    result, gaps = ha_result(export)
    assert gaps == ()
    assert result.drift.state == ON
    assert "1 alleen in running, 0 alleen in saved" in result.drift.evidence
    assert DRIFT_LABEL in result.blockers


# ---------------------------------------------------------------------------
# The normalization itself.
# ---------------------------------------------------------------------------


def test_header_lines_done_and_blank_lines_do_not_take_part():
    lines = [
        "#NS14.1 Build 72.57",
        "# Last modified Wed Aug 26 12:22:53 2026",
        "",
        "   ",
        "set ns config -IPAddress 192.0.2.2",
        " Done",
    ]
    assert comparable_lines(lines) == ["set ns config -IPAddress 192.0.2.2"]


def test_done_is_left_out_only_as_the_whole_line():
    """`Done` is the appliance's closing line, matched EXACTLY on the stripped
    line. A configuration line that merely carries the word still counts."""
    lines = ["Done", " Done ", "Done.", "done", "set lb vserver LBV-001 -comment Done"]
    assert comparable_lines(lines) == ["Done.", "done", "set lb vserver LBV-001 -comment Done"]


def test_the_comparison_is_a_multiset_and_ignores_indentation():
    running = ["add server SRV-001 192.0.2.10", "add server SRV-001 192.0.2.10", "  bind lb vserver LBV-001 SG-001"]
    saved = ["add server SRV-001 192.0.2.10", "bind lb vserver LBV-001 SG-001"]
    comparison = compare_config(running, saved)
    assert comparison.only_running == ("add server SRV-001 192.0.2.10",)
    assert comparison.only_saved == ()
    assert comparison.drift is True


def test_the_evidence_names_the_compared_counts_and_what_was_left_out():
    comparison = compare_config(
        ["# Last modified Thu Sep 24 10:12:03 2026", "add server SRV-001 192.0.2.10", "extra", " Done"],
        ["# Last modified by `save config`, Wed Sep 23 12:59:15 2026", "add server SRV-001 192.0.2.10"],
    )
    assert comparison_evidence(comparison) == (
        "parsed/runningconfig.txt 2 regels tegenover parsed/savedconfig.txt 1 regels na weglaten van"
        " kopregels en 'Done'; 1 alleen in running, 0 alleen in saved"
    )


# ---------------------------------------------------------------------------
# The answer at `volledig`: the lines themselves.
# ---------------------------------------------------------------------------


def test_volledig_shows_a_line_only_in_running_with_its_command_head(tmp_path):
    text = _render(_pair(tmp_path, extra_running=[INSERTED]), Disclosure.FULL, tmp_path)
    assert "Vraag: wijkt de draaiende configuratie af van de opgeslagen configuratie" in text
    assert "- config-drift: aan [vastgesteld]" in text
    assert (
        "    bewijs: parsed/runningconfig.txt 7 regels tegenover parsed/savedconfig.txt 6 regels na weglaten"
        " van kopregels en 'Done'; 1 alleen in running, 0 alleen in saved"
    ) in text
    assert f"- alleen in running: {INSERTED} [vastgesteld]\n    bewijs: parsed/runningconfig.txt; niet in" in text
    assert "- commandohoofd alleen in running: set lb vserver (1 regel) [vastgesteld]" in text
    assert "- alleen in saved:" not in text


def test_volledig_shows_a_line_only_in_saved_on_its_own_side(tmp_path):
    text = _render(_pair(tmp_path, extra_saved=["add server SRV-002 192.0.2.11"]), Disclosure.FULL, tmp_path)
    assert "0 alleen in running, 1 alleen in saved" in text
    assert "- alleen in saved: add server SRV-002 192.0.2.11 [vastgesteld]" in text
    assert "    bewijs: parsed/savedconfig.txt; niet in parsed/runningconfig.txt" in text
    assert "- commandohoofd alleen in saved: add server (1 regel) [vastgesteld]" in text
    assert "- alleen in running:" not in text


def test_on_the_real_export_exactly_the_inserted_line_is_shown(tmp_path):
    export = load_export(copy_with_running(tmp_path, LAB, insert_after_line(3, INSERTED)))
    text = _render(export, Disclosure.FULL, tmp_path)
    assert "- config-drift: aan [vastgesteld]" in text
    assert text.count("- alleen in running: ") == 1
    assert f"- alleen in running: {INSERTED} [vastgesteld]" in text
    assert "- alleen in saved: " not in text


@pytest.mark.parametrize(
    ("fixture", "verdict"),
    [(LAB, "onbevestigd [niet vastgesteld]"), (DOH, "uit [vastgesteld]")],
    ids=["lab-20260826", "lab-doh-synthetic"],
)
def test_no_visible_difference_on_a_real_export_shows_no_line(tmp_path, fixture, verdict):
    """Neither lab export differs in a line anyone can see. The first is not
    `uit` (its headers say changed after the last save, and lines whose value
    the collector withheld could carry that change - see further down); the
    second is. Neither shows a line."""
    text = _render(load_export(fixture), Disclosure.FULL, tmp_path)
    assert f"- config-drift: {verdict}" in text
    assert "- alleen in running: " not in text
    assert "- alleen in saved: " not in text
    assert "- commandohoofd alleen in" not in text


# ---------------------------------------------------------------------------
# Below `volledig`.
# ---------------------------------------------------------------------------


def test_beperkt_shows_only_the_command_head_and_a_count(tmp_path):
    comment = "set lb vserver LBV-001 -comment klantnaam-zichtbaar"
    export = _pair(tmp_path, extra_running=[INSERTED, comment])
    text = _render(export, Disclosure.LIMITED, tmp_path)
    assert "- config-drift: aan [vastgesteld]" in text
    assert "- commandohoofd alleen in running: set lb vserver (2 regels) [vastgesteld]" in text
    assert "- alleen in running:" not in text
    for fragment in ("LBV-001", "acceptatietest", "klantnaam-zichtbaar", "-comment"):
        assert fragment not in text


def test_minimaal_shows_only_counts(tmp_path):
    export = _pair(tmp_path, extra_running=[INSERTED])
    text = _render(export, Disclosure.MINIMAL, tmp_path)
    assert "Vraag: config_drift (stand: minimaal)" in text
    # The config-drift finding and the header finding. The lines are gone
    # (volledig only) and the heads are not counted a second time.
    assert "- 2 bevinding(en)" in text
    for fragment in ("set lb vserver", "LBV-001", "acceptatietest", "commandohoofd"):
        assert fragment not in text


# ---------------------------------------------------------------------------
# The secret fence: never a line with a secret, at no level.
# ---------------------------------------------------------------------------

# Per marker a line that carries THAT marker and no other, and a control line
# that differs only there - so each marker is proven on its own, and a later
# edit that drops one from the list fails here by name.
SECRET_MARKER_CASES = {
    "<redacted>": ("set lb monitor MON-01 HTTP -veld <REDACTED>", "set lb monitor MON-01 HTTP -veld WAARDE"),
    "password": ("add lb monitor MON-01 LDAP -password WAARDE-123", "add lb monitor MON-01 LDAP -veld WAARDE-123"),
    "passwd": ("add snmp manager 192.0.2.1 -authPasswd WAARDE-123", "add snmp manager 192.0.2.1 -veld WAARDE-123"),
    "encrypted": ("add ns ip 192.0.2.5 255.255.255.0 -encrypted", "add ns ip 192.0.2.5 255.255.255.0 -veld"),
    "encryptmethod": ("add ns ip 192.0.2.5 -encryptmethod ENCMTHD_3", "add ns ip 192.0.2.5 -veld ENCMTHD_3"),
    "passphrase": ("add authentication dfaAction DFA-01 -passphrase W", "add authentication dfaAction DFA-01 -veld W"),
    "secret": ("add authentication OAuthAction OA-01 -clientSecret W", "add authentication OAuthAction OA-01 -veld W"),
    "privatekey": ("add ipsec profile IPS-01 -privatekey WAARDE", "add ipsec profile IPS-01 -veld WAARDE"),
    "bindpw": ("add authentication ldapAction LDAP-01 -bindpw WAARDE", "add authentication ldapAction LDAP-01 -veld W"),
    "radkey": ("add authentication radiusAction RAD-01 -radKey W", "add authentication radiusAction RAD-01 -veld W"),
    "sharedsecret": ("add authentication x AX-01 -sharedSecret W", "add authentication x AX-01 -veld W"),
    "geredigeerd": ("set lb monitor MON-01 HTTP <geredigeerd>", "set lb monitor MON-01 HTTP <gewijzigd>"),
    "keyvalue": ("add ns encryptionKey EK-01 -keyValue WAARDE", "add ns encryptionKey EK-01 -veld WAARDE"),
    "passcrypt": ("add authentication localPolicy LP-01 -passcrypt W", "add authentication localPolicy LP-01 -veld W"),
    "passplain": ("add ssl certKey CERT-01 -cert c.pem -passplain W", "add ssl certKey CERT-01 -cert c.pem -veld W"),
    "psk": ("add ipsec profile IPS-01 -psk WAARDE", "add ipsec profile IPS-01 -veld WAARDE"),
    "credential": ("add vpn sessionAction SES-01 -ssoCredential PRIMARY", "add vpn sessionAction SES-01 -sso PRIMARY"),
    "community": ("add snmp trap generic 192.0.2.1 -communityName W", "add snmp trap generic 192.0.2.1 -veld W"),
    "apikey": ("add api spec SPEC-01 -apiKey WAARDE", "add api spec SPEC-01 -veld WAARDE"),
    "token": ("add authentication OAuthAction OA-02 -tokenEndpoint https://idp.example/x", "add x OA-02 -veld y"),
    "scriptargs": (
        'add lb monitor MON-02 USER -scriptName s.pl -scriptArgs "user=a;pw=b"',
        "add lb monitor MON-02 USER -scriptName s.pl -veld x",
    ),
    "bearer": (
        'add rewrite action RWA-01 insert_http_header X-Auth "\\"Bearer QUJD\\""',
        'add rewrite action RWA-01 insert_http_header X-Auth "\\"Waarde QUJD\\""',
    ),
    "pass=": (
        'add authentication webAuthAction WA-01 -serverIP 192.0.2.52 -fullReqExpr "\\"user=beheer&pass=W\\""',
        'add authentication webAuthAction WA-01 -serverIP 192.0.2.52 -fullReqExpr "\\"user=beheer&veld=W\\""',
    ),
    "key=": (
        'add responder action RA-01 respondwith "\\"HTTP/1.1 200 OK\\r\\n\\r\\nkey=WAARDE-123\\""',
        'add responder action RA-01 respondwith "\\"HTTP/1.1 200 OK\\r\\n\\r\\nveld=WAARDE-123\\""',
    ),
    "cookie:": (
        'add lb monitor MON-05 HTTP -customHeaders "Cookie: session=WAARDE-123"',
        'add lb monitor MON-05 HTTP -customHeaders "X-Test: session=WAARDE-123"',
    ),
}

# Per shape rule a line whose secret is recognised by its SHAPE, not by a
# word: the credentials in a URL (`scheme://user:password@host`), a
# cookie with a fixed value in the header a rewrite action or an HTTP callout
# inserts - written there without the colon `cookie:` needs - a cookie
# header with blank space (or a quote) before its colon, and the
# Authorization header written out, EXCEPT immediately before "policy",
# "policylabel" or "action" (those name a policy OBJECT, not a header value)
# - an exception that never holds on a line that writes a header in one of
# these ways: a rewrite or responder action, an `*_http_header` action type,
# a monitor's `-customHeaders`, `-send` or `-httpRequest`, a callout's
# `-headers` or `-fullReqExpr` or a webAuth action's `-fullReqExpr` that
# names the Authorization header is withheld whatever word follows it.
SECRET_PATTERN_CASES = (
    (
        "add appflow collector COL-01 -url https://beheer:WAARDE-123@192.0.2.30/in",
        "add appflow collector COL-01 -url https://192.0.2.30/in",
    ),
    (
        'add rewrite action RWA-05 insert_http_header Cookie "\\"session=WAARDE-123\\""',
        'add rewrite action RWA-05 insert_http_header X-Test "\\"session=WAARDE-123\\""',
    ),
    # NetScaler writes a string in double quotes, in single quotes or between
    # q-delimiters (`q{...}`, `q/.../`, ...), and a header name may be quoted
    # itself: the cookie with a fixed value is the same secret in every form.
    (
        "add rewrite action RWA-07 insert_http_header Cookie 'sid=WAARDE-123'",
        "add rewrite action RWA-07 insert_http_header X-Test 'sid=WAARDE-123'",
    ),
    (
        'add rewrite action RWA-08 insert_http_header Cookie q{"sid=WAARDE-123"}',
        'add rewrite action RWA-08 insert_http_header X-Test q{"sid=WAARDE-123"}',
    ),
    (
        "add rewrite action RWA-09 insert_http_header Cookie q/sid=WAARDE-123/",
        "add rewrite action RWA-09 insert_http_header X-Test q/sid=WAARDE-123/",
    ),
    (
        'add rewrite action RWA-10 insert_http_header "Cookie" "\\"sid=WAARDE-123\\""',
        'add rewrite action RWA-10 insert_http_header "X-Test" "\\"sid=WAARDE-123\\""',
    ),
    # A rewrite action that touches the Cookie or Set-Cookie header at all:
    # as the target it replaces or writes next to, or with a value that is
    # an expression rather than a string.
    (
        'add rewrite action RWA-11 replace "HTTP.REQ.HEADER(\\"Cookie\\")" "\\"sid=WAARDE-123\\""',
        'add rewrite action RWA-11 replace "HTTP.REQ.HEADER(\\"X-Test\\")" "\\"sid=WAARDE-123\\""',
    ),
    (
        'set rewrite action RWA-12 -target "HTTP.RES.HEADER(\\"Set-Cookie\\")" -stringBuilderExpr "\\"WAARDE\\""',
        'set rewrite action RWA-12 -target "HTTP.RES.HEADER(\\"X-Test\\")" -stringBuilderExpr "\\"WAARDE\\""',
    ),
    (
        'add lb monitor MON-03 HTTP -customHeaders "Authorization: Basic QUJD"',
        'add lb monitor MON-03 HTTP -customHeaders "X-Test: Basic QUJD"',
    ),
    # Blank space before the colon: the header is the same cookie.
    (
        'add lb monitor MON-08 HTTP -customHeaders "Cookie : session=WAARDE-123"',
        'add lb monitor MON-08 HTTP -customHeaders "X-Test : session=WAARDE-123"',
    ),
    # A rewrite action that writes the Authorization header, even when the
    # word after the header name is one the policy-object exception knows.
    (
        "add rewrite action RWA-13 insert_http_header Authorization policy WAARDE-123",
        "add rewrite action RWA-13 insert_http_header X-Test policy WAARDE-123",
    ),
    # The same exception on a monitor's custom headers and a callout's
    # headers: any line that writes a header naming Authorization.
    (
        'add lb monitor MON-09 HTTP -customHeaders "Authorization policylabel WAARDE-123"',
        'add lb monitor MON-09 HTTP -customHeaders "X-Test policylabel WAARDE-123"',
    ),
    # Per shape at least one case that no other rule withholds (see
    # test_every_filter_rule_has_its_own_case_above): a cookie with a fixed
    # value, the Authorization header written out and a cookie header with
    # blank space before its colon, each outside every command that writes a
    # header - an entry of a string map or a pattern set.
    (
        'bind policy stringmap SM-01 Cookie "sid=WAARDE-123"',
        'bind policy stringmap SM-01 X-Test "sid=WAARDE-123"',
    ),
    (
        'bind policy patset PS-01 "Authorization: Basic WAARDE-123"',
        'bind policy patset PS-01 "X-Test: Basic WAARDE-123"',
    ),
    (
        'bind policy patset PS-02 "Cookie : sid=WAARDE-123"',
        'bind policy patset PS-02 "X-Test : sid=WAARDE-123"',
    ),
    # A rewrite or responder action that writes the Authorization header into
    # a value rather than through a header argument, with a policy-object
    # word after the header name: that word is still the value.
    (
        'add rewrite action RWA-15 replace "HTTP.REQ.HEADER(\\"X-Test\\")" "\\"Authorization policy WAARDE-123\\""',
        'add rewrite action RWA-15 replace "HTTP.REQ.HEADER(\\"X-Test\\")" "\\"X-Test policy WAARDE-123\\""',
    ),
    (
        'add responder action RSA-01 respondwith "\\"HTTP/1.1 200 OK\\r\\nAuthorization policy WAARDE-123\\r\\n\\""',
        'add responder action RSA-01 respondwith "\\"HTTP/1.1 200 OK\\r\\nX-Test policy WAARDE-123\\r\\n\\""',
    ),
    # Per alternative and per optional part of a shape at least one case that
    # nothing else withholds (see
    # test_every_alternative_and_optional_part_of_a_shape_has_its_own_case_above).
    # A cookie with a fixed value after a quoted header name, between
    # q-delimiters, and as the argument of an expression, with and without
    # blank space before the parenthesis.
    (
        'bind policy stringmap SM-03 "Cookie" "sid=WAARDE-123"',
        'bind policy stringmap SM-03 "X-Test" "sid=WAARDE-123"',
    ),
    (
        "bind policy stringmap SM-02 Cookie q{sid=WAARDE-123}",
        "bind policy stringmap SM-02 X-Test q{sid=WAARDE-123}",
    ),
    (
        'add ns assignment NA-01 -variable $v -set Cookie("sid=WAARDE-123")',
        'add ns assignment NA-01 -variable $v -set X-Test("sid=WAARDE-123")',
    ),
    (
        'add ns assignment NA-02 -variable $v -set Cookie  ("sid=WAARDE-123")',
        'add ns assignment NA-02 -variable $v -set X-Test  ("sid=WAARDE-123")',
    ),
    # The obsolete Cookie2 header, a quote and more than one space between a
    # cookie header's name and its colon.
    (
        'bind policy patset PS-03 "Cookie2 : sid=WAARDE-123"',
        'bind policy patset PS-03 "X-Test2 : sid=WAARDE-123"',
    ),
    (
        "bind policy patset PS-04 'Cookie\": sid=WAARDE-123'",
        "bind policy patset PS-04 'X-Test\": sid=WAARDE-123'",
    ),
    (
        'bind policy patset PS-05 "Cookie  : sid=WAARDE-123"',
        'bind policy patset PS-05 "X-Test  : sid=WAARDE-123"',
    ),
    # A responder action that names a cookie, and a `set` of a rewrite action
    # that names Authorization, neither through a header argument.
    (
        'add responder action RSA-05 respondwith "\\"HTTP/1.1 200 OK\\r\\nSet-Cookie\\r\\n: sid=WAARDE-123\\r\\n\\""',
        'add responder action RSA-05 respondwith "\\"HTTP/1.1 200 OK\\r\\nX-Test\\r\\n: sid=WAARDE-123\\r\\n\\""',
    ),
    (
        'set rewrite action RWA-17 -stringBuilderExpr "\\"Authorization policy WAARDE-123\\""',
        'set rewrite action RWA-17 -stringBuilderExpr "\\"X-Test policy WAARDE-123\\""',
    ),
    # Per header-writing argument a line that names a cookie or Authorization
    # in a way no other shape reads: a callout's `-headers` and
    # `-fullReqExpr` and an `*_http_header` action type (here with the verb
    # abbreviated, as the CLI accepts it) before a policy-object word, and a
    # monitor's `-send` and `-httpRequest` with the cookie header's name as
    # the last word before an escaped CRLF.
    (
        'add policy httpCallout HC-05 -fullReqExpr "\\"GET / HTTP/1.1\\r\\nAuthorization policy WAARDE-123\\r\\n\\""',
        'add policy httpCallout HC-05 -fullReqExpr "\\"GET / HTTP/1.1\\r\\nX-Test policy WAARDE-123\\r\\n\\""',
    ),
    (
        "add policy httpCallout HC-03 -headers Proxy-Authorization action WAARDE-123",
        "add policy httpCallout HC-03 -headers X-Test action WAARDE-123",
    ),
    (
        "add rewrite act RWA-16 insert_http_header Authorization policy WAARDE-123",
        "add rewrite act RWA-16 insert_http_header X-Test policy WAARDE-123",
    ),
    (
        'add lb monitor MON-17 HTTP-ECV -send "GET / HTTP/1.1\\r\\nCookie\\r\\n: sid=WAARDE-123\\r\\n" -recv OK',
        'add lb monitor MON-17 HTTP-ECV -send "GET / HTTP/1.1\\r\\nX-Test\\r\\n: sid=WAARDE-123\\r\\n" -recv OK',
    ),
    (
        'add lb monitor MON-18 HTTP -httpRequest "GET / HTTP/1.1\\r\\nCookie\\r\\n: sid=WAARDE-123"',
        'add lb monitor MON-18 HTTP -httpRequest "GET / HTTP/1.1\\r\\nX-Test\\r\\n: sid=WAARDE-123"',
    ),
)

# The narrower side of the same rule: a command that NAMES an authorization
# policy object - never the header value the pattern above exists to
# protect - stays visible. MEASURED on both real lab exports: `add
# authorization policy`/`policylabel` occur on neither, so narrowing the
# pattern costs nothing there for those two shapes. `-defaultAuthorization
# Action` DOES occur - three `add vpn sessionAction` lines per side on the
# vpx export - and this pattern no longer catches it on its own; those real
# lines stay withheld anyway, on `<redacted>`/`credential`
# (`-ssoCredential <REDACTED>` further along the same lines), which is why
# the pinned counts below do not move; see
# test_the_filter_withholds_exactly_the_measured_lines_of_both_lab_exports.
AUTHORIZATION_POLICY_LINES = (
    "add authorization policy AUTHPOL_LOGIN ns_true ALLOW",
    "bind authorization policylabel AUTHLBL_LOGIN -policyName AUTHPOL_LOGIN -priority 100",
    "add vpn sessionAction SES_LOGIN -defaultAuthorizationAction ALLOW",
)


@pytest.mark.parametrize("line", AUTHORIZATION_POLICY_LINES)
def test_an_authorization_policy_object_stays_visible(line):
    """The negative lookahead in `SECRET_PATTERNS` (`authorization(?!\\s*
    (?:policy|policylabel|action)\\b)`) leaves exactly these shapes alone,
    IN ISOLATION: a command that defines or binds an authorization policy
    object, or a parameter that only names one (`-defaultAuthorizationAction`,
    a real `vpn sessionAction` flag, MEASURED on the vpx lab export - there
    it sits on a line that also carries `-ssoCredential`, withheld for that
    unrelated reason instead; see the module comment above `SECRET_PATTERNS`
    in config_drift.py)."""
    assert "authorization" in line.casefold()
    assert not drift_module.is_secret_line(line), line
    assert drift_module.shown_line(line) == line


# Per command rule a line WITHOUT any marker, so the command itself is what
# withholds it; the control is a neighbouring command that is not a rule.
SECRET_COMMAND_CASES = (
    ("set ns encryptionParams -method AES256", "set ns param -timezone GMT"),
    ("add system user beheerder WAARDE-123", "add system group beheerders"),
    ("set system user beheerder -externalAuth DISABLED", "set system parameter -timeout 900"),
    ("set ns rpcNode 192.0.2.2 -srcIP 192.0.2.2", "set ns ip 192.0.2.2 -mgmtAccess ENABLED"),
    ("add aaa user jan", "add aaa group medewerkers"),
    ("set aaa user jan", "set aaa parameter -maxAAAUsers 5"),
    ("add snmp user jan -group G1", "add snmp group G1 authNoPriv"),
    ("set db user jan", "set db dbProfile PROF-01"),
)


@pytest.mark.parametrize("marker", sorted(SECRET_MARKER_CASES))
def test_every_secret_marker_withholds_a_line_on_its_own(marker):
    line, control = SECRET_MARKER_CASES[marker]
    assert marker in line.casefold()
    assert drift_module.is_secret_line(line)
    assert not drift_module.is_secret_line(control), "de controleregel zelf draagt al een kenmerk"
    shown = drift_module.shown_line(line)
    assert shown == f"{drift_module.command_head(line)} {drift_module.SECRET_WITHHELD_TEXT}"


@pytest.mark.parametrize(("line", "control"), SECRET_COMMAND_CASES, ids=[case[0][:22] for case in SECRET_COMMAND_CASES])
def test_every_secret_command_withholds_a_line_without_any_marker(line, control):
    assert not any(marker in line.casefold() for marker in drift_module.SECRET_MARKERS)
    assert drift_module.is_secret_line(line)
    assert not drift_module.is_secret_line(control)
    # The command IS the reason the line is withheld, so its head is too:
    # nothing of the line is repeated, not even the command.
    assert drift_module.command_head(line) == drift_module.SECRET_HEAD_TEXT
    assert drift_module.shown_line(line) == drift_module.SECRET_WITHHELD_TEXT
    assert drift_module.shown_line(control) == control


@pytest.mark.parametrize(("line", "control"), SECRET_PATTERN_CASES)
def test_every_secret_shape_withholds_a_line_without_any_marker(line, control):
    assert not any(marker in line.casefold() for marker in drift_module.SECRET_MARKERS)
    assert drift_module.is_secret_line(line)
    assert not drift_module.is_secret_line(control)
    assert "WAARDE" not in drift_module.shown_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "add lb monitor MON-01 LDAP -pass\x07word WAARDE-123",
        # Built from code points so this source file stays ASCII.
        "add lb monitor MON-01 LDAP -pass" + chr(0x200B) + "word WAARDE-123",
        "add lb monitor MON-01 LDAP -" + "".join(chr(ord(letter) + 0xFEE0) for letter in "password") + " WAARDE-123",
        "add lb monitor MON-01 LDAP -pas" + chr(0x301) + "sword WAARDE-123",
        "add lb monitor MON-01 LDAP -pass" + chr(0x20DD) + "word WAARDE-123",
    ],
    ids=["stuurteken", "nulbreedte", "volle-breedte", "combinerend-accent", "omsluitend-teken"],
)
def test_a_marker_hidden_by_an_invisible_or_wide_character_is_still_a_secret(line):
    """The shown line replaces non-printable characters, so a marker split by
    one would otherwise come out readable; a full-width spelling reads the
    same to a person, and so does a word with a combining mark on one of its
    letters. The filter looks through all of them."""
    assert drift_module.is_secret_line(line)
    assert "WAARDE" not in drift_module.shown_line(line)


@pytest.mark.parametrize(
    "line",
    [
        'add rewrite action RWA-04 insert_http_header X-Api-Key "\\"WAARDE-123\\""',
        "add lb monitor MON-01 LDAP -pass-word WAARDE-123",
        "add ipsec profile IPS-01 -private_key WAARDE-123",
    ],
    ids=["x-api-key", "pass-word", "private_key"],
)
def test_a_marker_split_by_a_hyphen_or_underscore_is_still_a_secret(line):
    """`api-key`, `api_key` and `X-Api-Key` are `apikey` to a person. The
    filter also reads the line with every `-` and `_` left out; none of
    these lines carries a marker as written, so that reading is what
    withholds them."""
    assert not any(marker in line.casefold() for marker in drift_module.SECRET_MARKERS)
    assert drift_module.is_secret_line(line)
    assert "WAARDE" not in drift_module.shown_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "add lb monitor MON-01 LDAP -p" + chr(0x430) + "ssword WAARDE-123",
        "add lb monitor MON-01 LDAP -" + chr(0x1D18) + "assword WAARDE-123",
        "add lb monitor MON-01 LDAP -" + "".join(chr(code) for code in (0x440, 0x430, 0x455, 0x455)) + "word W-123",
        "set lb vserver LBV-001 -comment Stra" + chr(0xDF) + "e",
    ],
    ids=["cyrillische-a", "kleine-hoofdletter-p", "cyrillisch-woorddeel", "ringel-s-zonder-kenmerk"],
)
def test_a_letter_outside_ascii_after_the_fold_withholds_the_line(line):
    """A letter from another script can look exactly like a Latin one (a
    Cyrillic `a` in `-password`); no list of markers can see that. So a line
    that still carries a letter outside ASCII after the fold above is not
    shown - also when it carries no marker at all (the last case): a
    look-alike cannot be told apart from an ordinary letter, and withholding
    a line too many costs only a look at the appliance. Its own note, not
    `SECRET_WITHHELD_TEXT`: none of these lines carries a marker, a shape or
    a credential command - saying "geheim" would be untrue, and an operator
    reading `SECRET_NON_ASCII_TEXT` knows AT ONCE why (a script mismatch, not
    a credential) instead of assuming the wrong kind of secret."""
    assert drift_module.is_secret_line(line)
    assert drift_module.shown_line(line).endswith(drift_module.SECRET_NON_ASCII_TEXT)


def test_an_accented_letter_that_folds_to_ascii_is_still_shown():
    """The fold drops the accent, so an accent alone withholds nothing."""
    line = "set lb vserver LBV-001 -comment caf" + chr(0xE9)
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


# Secrets where NetScaler configuration really carries them: in a header a
# rewrite action or an HTTP callout inserts (written there WITHOUT a colon),
# in the query or the body of a monitor or an authentication request, in a
# cookie, and in two spellings a person reads as a marker. Synthetic values
# only (`QUJD` is base64 for `ABC`).
REALISTIC_SECRET_LINES = {
    "rewrite-authorization": 'add rewrite action RWA-02 insert_http_header Authorization "\\"Basic QUJD\\""',
    "rewrite-proxy-authorization": (
        'add rewrite action RWA-03 insert_http_header Proxy-Authorization "\\"Basic QUJD\\""'
    ),
    "callout-authorization": (
        'add policy httpCallout HC-01 -vServer LBV-001 -returnType TEXT -headers "Authorization(\\"Basic QUJD\\")"'
    ),
    "rewrite-x-api-key": 'add rewrite action RWA-04 insert_http_header X-Api-Key "\\"WAARDE-123\\""',
    "monitor-api_key": 'add lb monitor MON-04 HTTP-ECV -send "GET /health?api_key=WAARDE-123"',
    "webauth-pass": (
        'add authentication webAuthAction WA-01 -serverIP 192.0.2.52 -fullReqExpr "\\"user=beheer&pass=WAARDE-123\\""'
    ),
    "monitor-cookie": 'add lb monitor MON-05 HTTP -customHeaders "Cookie: session=WAARDE-123"',
    "responder-key": 'add responder action RA-01 respondwith "\\"HTTP/1.1 200 OK\\r\\n\\r\\nkey=WAARDE-123\\""',
    "combinerend-accent": "add lb monitor MON-06 LDAP -pas" + chr(0x301) + "sword WAARDE-123",
    "cyrillische-a": "add lb monitor MON-07 LDAP -p" + chr(0x430) + "ssword WAARDE-123",
    "rewrite-cookie": 'add rewrite action RWA-05 insert_http_header Cookie "\\"session=WAARDE-123\\""',
    "callout-cookie": (
        'add policy httpCallout HC-02 -vServer LBV-001 -returnType TEXT -headers "Cookie(\\"session=WAARDE-123\\")"'
    ),
}

# Lines next to them that carry no secret and stay readable at `volledig`.
VISIBLE_NEIGHBOURS = (
    "set lb vserver LBV-001 -comment zichtbaar",
    "add authentication samlAction SAML-01 -samlIdPCertName CERT-IDP -samlRedirectUrl https://idp.example/sso",
    'add rewrite action RWA-06 insert_http_header X-Test "\\"Basic ZICHTBAAR\\""',
    "set lb vserver LBV-002 -persistenceType COOKIEINSERT -cookieName SESSIE",
)


@pytest.mark.parametrize("name", sorted(REALISTIC_SECRET_LINES))
def test_a_realistic_secret_line_is_withheld(name):
    line = REALISTIC_SECRET_LINES[name]
    assert drift_module.is_secret_line(line)
    shown = drift_module.shown_line(line)
    # "cyrillische-a" carries no marker in any reading (the Cyrillic letter
    # never folds to Latin "a"), so its OWN note applies - every other name
    # here is caught by a marker, shape or command instead.
    text = drift_module.SECRET_NON_ASCII_TEXT if name == "cyrillische-a" else drift_module.SECRET_WITHHELD_TEXT
    assert shown == f"{drift_module.command_head(line)} {text}"


@pytest.mark.parametrize("line", VISIBLE_NEIGHBOURS)
def test_a_neighbour_without_a_secret_stays_visible(line):
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


def test_realistic_secret_lines_never_reach_the_answer_through_a_real_export_read(tmp_path):
    """Through the export read, so the product's own credential filter runs
    first: none of these lines is touched by it, and every one is withheld
    here - at every level - while its neighbours stay readable at `volledig`."""
    lines = list(REALISTIC_SECRET_LINES.values())
    export = _pair(tmp_path, extra_running=lines + list(VISIBLE_NEIGHBOURS))
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        text = _render(export, level, tmp_path)
        for fragment in ("WAARDE", "QUJD", "session="):
            assert fragment not in text, (level, fragment)
    full = _render(export, Disclosure.FULL, tmp_path)
    withheld = drift_module.SECRET_WITHHELD_TEXT
    non_ascii = drift_module.SECRET_NON_ASCII_TEXT
    # One of the twelve ("cyrillische-a") carries its own note instead - see
    # test_a_realistic_secret_line_is_withheld.
    assert full.count(f"{withheld} [vastgesteld]") == len(lines) - 1
    assert full.count(f"{non_ascii} [vastgesteld]") == 1
    assert "- alleen in running: set lb vserver LBV-001 -comment zichtbaar [vastgesteld]" in full
    assert "- alleen in running: set lb vserver LBV-002 -persistenceType COOKIEINSERT -cookieName SESSIE" in full
    assert f"{len(lines) + len(VISIBLE_NEIGHBOURS)} alleen in running, 0 alleen in saved" in full


def test_every_filter_rule_has_its_own_case_above(monkeypatch):
    """A rule added to the filter without a case here fails loudly, and so
    does a rule whose cases other rules withhold as well: per shape and per
    command at least one case above is withheld by that rule ALONE, so the
    filter without it shows that line. Dropping a rule fails here by name,
    not only when it happens to be the last one standing; narrowing a shape
    fails in test_every_alternative_and_optional_part_of_a_shape_has_its_own_case_above."""
    assert set(SECRET_MARKER_CASES) == set(drift_module.SECRET_MARKERS)
    unguarded = []
    for attribute, cases in (("SECRET_COMMANDS", SECRET_COMMAND_CASES), ("SECRET_PATTERNS", SECRET_PATTERN_CASES)):
        rules = getattr(drift_module, attribute)
        for index, rule in enumerate(rules):
            assert any(rule.search(line) for line, _ in cases), rule.pattern
            with monkeypatch.context() as patched:
                patched.setattr(drift_module, attribute, rules[:index] + rules[index + 1 :])
                if all(drift_module.is_secret_line(line) for line, _ in cases):
                    unguarded.append(rule.pattern)
    assert not unguarded, "geen geval dat alleen deze regel achterhoudt: " + " | ".join(unguarded)


_LOOKAROUNDS = ("(?=", "(?!", "(?<=", "(?<!")


def _without_alternative(pattern, inside, starts, end):
    """Per alternative of one group that has a bar: the alternative, and the
    pattern without it and one of its bars (the bar after it, or before the
    last one)."""
    if inside or len(starts) < 2:
        return []
    stops = [start - 1 for start in starts[1:]] + [end]
    found = []
    for start, stop in zip(starts, stops, strict=True):
        if stop < end:
            found.append((pattern[start:stop], pattern[:start] + pattern[stop + 1 :]))
        else:
            found.append((pattern[start:stop], pattern[: start - 1] + pattern[stop:]))
    return found


def _narrowings(pattern):
    """Every way to narrow a shape by one part, as (part, what is left): an
    alternative of a group dropped with one of its bars, a part that may be
    absent (an atom with `?` or `*`) dropped, and a part that may repeat
    (`*`) allowed at most once. A lookaround is left alone: the one lookahead
    in the filter is an EXCEPTION, and dropping from it widens the shape. So
    is a part that must be there (`+`, a bare atom): narrowing its count or
    dropping a letter of a word is not what this lists."""
    found = []
    groups = [(False, 0, [0])]  # (inside a lookaround, opened at, start of each alternative)
    atom = None
    position = 0
    while position < len(pattern):
        character = pattern[position]
        if character == "\\":
            atom, position = position, position + 2
            continue
        if character == "[":
            end = position + 1
            while pattern[end] != "]":
                end += 2 if pattern[end] == "\\" else 1
            atom, position = position, end + 1
            continue
        if character == "(":
            inside = groups[-1][0] or pattern.startswith(_LOOKAROUNDS, position)
            prefix = 4 if pattern.startswith(("(?<=", "(?<!"), position) else 3 if pattern[position + 1] == "?" else 1
            groups.append((inside, position, [position + prefix]))
            atom, position = None, position + prefix
            continue
        if character == "|":
            groups[-1][2].append(position + 1)
            atom = None
        elif character == ")":
            inside, opened, starts = groups.pop()
            found.extend(_without_alternative(pattern, inside, starts, position))
            atom = opened
        elif character in "?*+":
            if character != "+" and atom is not None and not groups[-1][0]:
                found.append((pattern[atom : position + 1], pattern[:atom] + pattern[position + 1 :]))
                if character == "*":
                    found.append((pattern[atom : position + 1], pattern[:position] + "?" + pattern[position + 1 :]))
            atom = None
        else:
            atom = position
        position += 1
    inside, _, starts = groups.pop()
    found.extend(_without_alternative(pattern, inside, starts, len(pattern)))
    return found


def test_the_narrowings_of_a_shape_are_every_alternative_and_every_optional_part():
    """The helper above itself, on a pattern with every construct it reads:
    a group with a bar, a nested group, a character class, an escape, `?`
    and `*`, a lookahead with a bar of its own, and a lazy `*?`."""
    assert _narrowings(r"a(?:b|c[\"']?)\s*(?!x|y)(?:d|e)*?f") == [
        (r"[\"']?", r"a(?:b|c)\s*(?!x|y)(?:d|e)*?f"),
        ("b", r"a(?:c[\"']?)\s*(?!x|y)(?:d|e)*?f"),
        (r"c[\"']?", r"a(?:b)\s*(?!x|y)(?:d|e)*?f"),
        (r"\s*", r"a(?:b|c[\"']?)(?!x|y)(?:d|e)*?f"),
        (r"\s*", r"a(?:b|c[\"']?)\s?(?!x|y)(?:d|e)*?f"),
        ("d", r"a(?:b|c[\"']?)\s*(?!x|y)(?:e)*?f"),
        ("e", r"a(?:b|c[\"']?)\s*(?!x|y)(?:d)*?f"),
        ("(?:d|e)*", r"a(?:b|c[\"']?)\s*(?!x|y)?f"),
        ("(?:d|e)*", r"a(?:b|c[\"']?)\s*(?!x|y)(?:d|e)??f"),
    ]


SECRET_SHAPE_NARROWINGS = [
    (index, part, narrowed)
    for index, rule in enumerate(drift_module.SECRET_PATTERNS)
    for part, narrowed in _narrowings(rule.pattern)
]


@pytest.mark.parametrize(
    ("index", "part", "narrowed"),
    SECRET_SHAPE_NARROWINGS,
    ids=[f"{index}-{number}-{part}" for number, (index, part, _) in enumerate(SECRET_SHAPE_NARROWINGS)],
)
def test_every_alternative_and_optional_part_of_a_shape_has_its_own_case_above(monkeypatch, index, part, narrowed):
    """Narrowing a shape by one part - an alternative dropped, a part that
    may be absent dropped, a part that may repeat allowed only once - shows
    at least one case above: every part of every shape is there for a line
    no other part and no other rule withholds, so a narrowing fails here by
    name, not only dropping the whole shape."""
    rules = drift_module.SECRET_PATTERNS
    monkeypatch.setattr(
        drift_module, "SECRET_PATTERNS", (*rules[:index], re.compile(narrowed, rules[index].flags), *rules[index + 1 :])
    )
    shown = [line for line, _ in SECRET_PATTERN_CASES if not drift_module.is_secret_line(line)]
    assert shown, f"geen geval dat zichtbaar wordt zonder {part!r} in {rules[index].pattern!r}"


def test_the_security_statement_names_every_secret_marker():
    """docs/klant/SECURITY.md lists the markers a customer can rely on; a
    marker added in code and not there (or dropped there) fails here."""
    root = Path(__file__).resolve().parent.parent
    text = (root / "docs" / "klant" / "SECURITY.md").read_text(encoding="utf-8").casefold()
    for marker in drift_module.SECRET_MARKERS:
        assert f"`{marker}`" in text, marker


def test_a_secret_line_is_never_shown_at_any_level(tmp_path):
    """Through a real export read, so the product's own credential filter
    (redact.py) runs first - and a secret that filter does not know
    (`-passphrase`) is caught here all the same."""
    lines = [
        "add authentication ldapAction LDAP-01 -serverIP 192.0.2.10 -ldapBindDnPassword WAARDE-123"
        " -encrypted -encryptmethod ENCMTHD_3",
        "add authentication dfaAction DFA-01 -clientID C1 -passphrase WAARDE-456",
        "set ns encryptionParams -method AES256 -keyValue WAARDE-789",
    ]
    export = _pair(tmp_path, extra_running=lines)
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        text = _render(export, level, tmp_path)
        for fragment in ("WAARDE-", "LDAP-01", "DFA-01", "192.0.2.10", "AES256", "ldapBindDnPassword"):
            assert fragment not in text, (level, fragment)
    full = _render(export, Disclosure.FULL, tmp_path)
    withheld = drift_module.SECRET_WITHHELD_TEXT
    assert f"- alleen in running: add authentication ldapAction {withheld} [vastgesteld]" in full
    assert f"- alleen in running: add authentication dfaAction {withheld} [vastgesteld]" in full
    # `set ns encryptionParams` is itself one of the credential commands, so
    # its head is withheld with the line: only the note stands there.
    assert f"- alleen in running: {withheld} [vastgesteld]" in full
    assert "encryptionParams" not in full
    assert "3 alleen in running, 0 alleen in saved" in full


# The shapes an untrusted export can give a secret that the lists above do
# not see on their own: a cookie with a fixed value in NetScaler's other two
# string forms (single quotes, q-delimiters), and a secret in the command
# head itself - text no appliance writes, but an export is data, and the head
# is a projection of the line like the line itself. Synthetic canaries only.
HOSTILE_LEAK_LINES = {
    "cookie-enkele-aanhalingstekens": "add rewrite action RWA-SYNTH insert_http_header Cookie '\"sid=CANARY04\"'",
    "cookie-q-scheidingsteken": 'add rewrite action RWA-SYNTH insert_http_header Cookie q{"sid=CANARY07"}',
    "geheim-in-het-objecttype": "add passwordCANARY05 value",
    "geheim-in-het-derde-woord": "set ns tokenCANARY06 value",
}

# The three lines with a secret the same untrusted export carried next to
# them, which the filter already withheld - they must stay withheld.
HOSTILE_KNOWN_SECRETS = (
    'add rewrite action RWA-SYNTH insert_http_header Authorization "Basic CANARY01"',
    'add rewrite action RWA-SYNTH insert_http_header X-Api-Key "CANARY02"',
    'add lb monitor MON-SYNTH HTTP -customHeaders "Cookie: session=CANARY03"',
)

# And three control lines without a secret that must stay readable at
# `volledig`, each one next to the widened rules: an ordinary comment, a
# single-quoted cookie NAME of cookie persistence, and a q-delimited value in
# a header that is not a cookie.
HOSTILE_VISIBLE_CONTROLS = (
    "set lb vserver LBV-SYNTH -comment gewonecontrole",
    "set lb vserver LBV-SYNTH -persistenceType COOKIEINSERT -cookieName 'SESSIE'",
    'add rewrite action RWA-SYNTH insert_http_header X-Test q{"zichtbaar"}',
)


@pytest.mark.parametrize("name", sorted(HOSTILE_LEAK_LINES))
def test_a_secret_in_a_cookie_form_or_in_the_command_head_is_in_no_projection(name):
    line = HOSTILE_LEAK_LINES[name]
    assert drift_module.is_secret_line(line)
    assert "CANARY" not in drift_module.shown_line(line)
    assert "CANARY" not in drift_module.command_head(line)


@pytest.mark.parametrize("line", HOSTILE_VISIBLE_CONTROLS)
def test_a_control_line_next_to_the_widened_rules_stays_visible(line):
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


# A case that tested a marker word ALSO being a command GROUP name
# ("authorization" being both, "add authorization policy AUTHZ-01 true
# ALLOW" withholding its own head) no longer applies: "authorization" is a
# `SECRET_PATTERNS` shape now, with a lookahead that leaves exactly this
# command visible (see `test_an_authorization_policy_object_stays_visible`
# above), so the line withholds nothing to repeat, and no other marker/
# group pair produces the same coincidence.
@pytest.mark.parametrize(
    ("line", "shown"),
    [
        ("add passwordCANARY05 value", None),
        ("set ns tokenCANARY06 value", None),
        ("add system user beheerder WAARDE-123", None),
        (HOSTILE_LEAK_LINES["cookie-enkele-aanhalingstekens"], "add rewrite action"),
    ],
    ids=["objecttype", "derde-woord", "geheimcommando", "gewoon-hoofd"],
)
def test_a_command_head_that_is_itself_withheld_is_never_repeated(line, shown):
    """The head passes the same fence as the line. A head the fence withholds
    becomes `SECRET_HEAD_TEXT` at `beperkt`, and at `volledig` the line is
    only the note - without a head that would repeat what the fence caught.
    A head the fence lets through stays, in front of the note."""
    if shown is None:
        assert drift_module.command_head(line) == drift_module.SECRET_HEAD_TEXT
        assert drift_module.shown_line(line) == drift_module.SECRET_WITHHELD_TEXT
    else:
        assert drift_module.command_head(line) == shown
        assert drift_module.shown_line(line) == f"{shown} {drift_module.SECRET_WITHHELD_TEXT}"


def test_hostile_lines_never_reach_the_answer_through_a_real_export_read(tmp_path):
    """Through the export read, at every level: no canary anywhere, the known
    secrets stay withheld, the controls stay readable at `volledig`, and at
    `beperkt` the two heads that carried a canary are counted under the one
    generic head."""
    lines = list(HOSTILE_KNOWN_SECRETS) + list(HOSTILE_LEAK_LINES.values()) + list(HOSTILE_VISIBLE_CONTROLS)
    export = _pair(tmp_path, extra_running=lines)
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        text = _render(export, level, tmp_path)
        assert "CANARY" not in text, level
    withheld = drift_module.SECRET_WITHHELD_TEXT
    full = _render(export, Disclosure.FULL, tmp_path)
    assert full.count(f"{withheld} [vastgesteld]") == len(HOSTILE_KNOWN_SECRETS) + len(HOSTILE_LEAK_LINES)
    assert full.count(f"- alleen in running: {withheld} [vastgesteld]") == 2
    for control in HOSTILE_VISIBLE_CONTROLS:
        assert f"- alleen in running: {control} [vastgesteld]" in full
    assert f"{len(lines)} alleen in running, 0 alleen in saved" in full
    limited = _render(export, Disclosure.LIMITED, tmp_path)
    head = drift_module.SECRET_HEAD_TEXT
    assert f"- commandohoofd alleen in running: {head} (2 regels) [vastgesteld]" in limited
    assert "- commandohoofd alleen in running: add rewrite action (5 regels) [vastgesteld]" in limited
    assert "- commandohoofd alleen in running: add lb monitor (1 regel) [vastgesteld]" in limited
    assert "- commandohoofd alleen in running: set lb vserver (2 regels) [vastgesteld]" in limited
    for fragment in ("password", "token", "gewonecontrole", "zichtbaar"):
        assert fragment not in limited


# An invisible character between two words: the fold that drops it reads
# `systemuser`, while a reader sees `system user` - the shown line used to
# print a control character as a space, and a zero-width character is
# nothing at all to the eye. Built from code points so this file stays ASCII.
ZERO_WIDTH_SPACE = chr(0x200B)
INVISIBLE_LEAK_LINES = {
    "nulbreedte-in-geheimcommando": f"add system{ZERO_WIDTH_SPACE}user beheerder CANARY13",
    "stuurteken-in-geheimcommando": "add aaa" + chr(0x01) + "user jan CANARY14",
    "nulbreedte-voor-cookiewaarde": (
        f"add rewrite action RWA-SYNTH insert_http_header Cookie{ZERO_WIDTH_SPACE}'sid=CANARY11'"
    ),
    "woordverbinder-in-geheimcommando": "set system" + chr(0x2060) + "user beheerder CANARY19",
    "blanco-teken-in-geheimcommando": "add system" + chr(0x2800) + "user beheerder CANARY20",
    "stuurteken-en-nulbreedte": "add system" + chr(0x01) + "us" + ZERO_WIDTH_SPACE + "er beheerder CANARY21",
    "nulbreedte-voor-het-commando": ZERO_WIDTH_SPACE + "add system user beheerder CANARY22",
}


@pytest.mark.parametrize("name", sorted(INVISIBLE_LEAK_LINES))
def test_an_invisible_character_between_two_words_never_opens_the_filter(name):
    """The filter reads the line with every invisible character left out AND
    with every one as a space, and the line exactly as it would be shown: a
    word split or joined by a character the eye does not see is caught in
    whichever of those readings carries the secret."""
    line = INVISIBLE_LEAK_LINES[name]
    assert drift_module.is_secret_line(line)
    assert "CANARY" not in drift_module.shown_line(line)
    assert "CANARY" not in drift_module.command_head(line)


def test_invisible_characters_never_reach_the_answer_through_a_real_export_read(tmp_path):
    lines = list(INVISIBLE_LEAK_LINES.values())
    export = _pair(tmp_path, extra_running=lines)
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        text = _render(export, level, tmp_path)
        assert "CANARY" not in text, level
    full = _render(export, Disclosure.FULL, tmp_path)
    assert full.count(f"{drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]") == len(lines)


# A rewrite action whose target is the Cookie or Set-Cookie header writes a
# fixed cookie value just as `insert_http_header Cookie "..."` does - valid
# CLI, not hostile text - and so does one whose value is an expression.
REWRITE_COOKIE_LEAK_LINES = {
    "replace-cookie": 'add rewrite action RWA-SYNTH replace "HTTP.REQ.HEADER(\\"Cookie\\")" "\\"sid=CANARY15\\""',
    "insert-after-cookie": (
        'add rewrite action RWA-SYNTH insert_after "HTTP.REQ.HEADER(\\"Cookie\\")" "\\"; sid=CANARY16\\""'
    ),
    "insert-before-cookie": (
        'add rewrite action RWA-SYNTH insert_before "HTTP.REQ.HEADER(\\"Cookie\\")" "\\"sid=CANARY18; \\""'
    ),
    "replace-set-cookie": (
        'add rewrite action RWA-SYNTH replace "HTTP.RES.HEADER(\\"Set-Cookie\\")" "\\"sid=CANARY17; Secure\\""'
    ),
    "insert-after-set-cookie": (
        'set rewrite action RWA-SYNTH -target "HTTP.RES.HEADER(\\"Set-Cookie\\")"'
        ' -stringBuilderExpr "\\"; sid=CANARY23\\""'
    ),
    "cookie-uit-een-expressie": 'add rewrite action RWA-SYNTH insert_http_header Cookie CLIENT.IP.SRC+"; sid=CANARY24"',
}

# Lines next to them that only READ a cookie, or name one without a value.
REWRITE_COOKIE_VISIBLE_CONTROLS = (
    'add rewrite policy RWP-SYNTH "HTTP.REQ.HEADER(\\"Cookie\\").CONTAINS(\\"sid\\")" RWA-SYNTH',
    'add responder policy RSP-SYNTH "HTTP.REQ.COOKIE.VALUE(\\"sid\\").EQ(\\"x\\")" NOOP',
    "set lb vserver LBV-SYNTH -persistenceType COOKIEINSERT -cookieName SESSIE",
    'add rewrite action RWA-SYNTH insert_http_header X-Test q{"zichtbaar"}',
)


@pytest.mark.parametrize("name", sorted(REWRITE_COOKIE_LEAK_LINES))
def test_a_rewrite_action_on_a_cookie_header_is_withheld(name):
    line = REWRITE_COOKIE_LEAK_LINES[name]
    assert drift_module.is_secret_line(line)
    assert "CANARY" not in drift_module.shown_line(line)
    assert drift_module.command_head(line) in ("add rewrite action", "set rewrite action")


@pytest.mark.parametrize("line", REWRITE_COOKIE_VISIBLE_CONTROLS)
def test_a_line_that_only_reads_a_cookie_stays_visible(line):
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


def test_rewrite_actions_on_a_cookie_header_never_reach_the_answer_through_a_real_export_read(tmp_path):
    lines = list(REWRITE_COOKIE_LEAK_LINES.values())
    export = _pair(tmp_path, extra_running=lines + list(REWRITE_COOKIE_VISIBLE_CONTROLS))
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        text = _render(export, level, tmp_path)
        assert "CANARY" not in text, level
    full = _render(export, Disclosure.FULL, tmp_path)
    assert full.count(f"{drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]") == len(lines)
    for control in REWRITE_COOKIE_VISIBLE_CONTROLS:
        assert f"- alleen in running: {control} [vastgesteld]" in full


# A secret header with blank space before its colon, and the Authorization
# header written by a rewrite action with a policy-object word after it. The
# first two lines below passed the filter before, through the real route at
# `volledig`: `cookie:` needs the colon right after the name, and the
# policy-object exception of the Authorization shape looked only at the word
# after the header name, never at the command that writes the header. The
# last two are their neighbours of the same export, which the filter already
# withheld. A synthetic canary as the value.
SPACED_HEADER_CANARY = "ZX9Q4TESTONLY"
SPACED_HEADER_LINES = {
    "cookie-spatie-voor-dubbele-punt": f'add lb monitor MON-01 HTTP -customHeaders "Cookie : session={SPACED_HEADER_CANARY}"',
    "rewrite-authorization-policy": f"add rewrite action RW-01 insert_http_header Authorization policy {SPACED_HEADER_CANARY}",
    "cookie-dubbele-punt": f'add lb monitor MON-01 HTTP -customHeaders "Cookie: session={SPACED_HEADER_CANARY}"',
    "rewrite-authorization-basic": (
        f'add rewrite action RW-01 insert_http_header Authorization "Basic {SPACED_HEADER_CANARY}"'
    ),
}


@pytest.mark.parametrize("side", ["running", "saved"])
@pytest.mark.parametrize("name", sorted(SPACED_HEADER_LINES))
def test_a_secret_header_line_is_in_no_answer_on_either_side(tmp_path, name, side):
    """Through the export read, `drift_answer` and the disclosure seam, one
    line per export on the side it stands on: the canary is in no answer at
    any level, and at `volledig` the line is there as withheld."""
    line = SPACED_HEADER_LINES[name]
    export = _pair(
        tmp_path,
        extra_running=[line] if side == "running" else [],
        extra_saved=[line] if side == "saved" else [],
    )
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        assert SPACED_HEADER_CANARY not in _render(export, level, tmp_path), level
    label = "alleen in running" if side == "running" else "alleen in saved"
    full = _render(export, Disclosure.FULL, tmp_path)
    assert f"- {label}: {drift_module.command_head(line)} {drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]" in full


# Every header this filter recognises as carrying a secret, with blank space
# or an invisible character between its name and its colon - also a space
# and a colon that only become ASCII after compatibility decomposition. Built
# from code points so this source file stays ASCII.
SECRET_HEADER_NAMES = ("Cookie", "Set-Cookie", "Authorization", "Proxy-Authorization", "X-Api-Key")
BEFORE_THE_COLON = {
    "spatie": " ",
    "drie-spaties": "   ",
    "tab": "\t",
    "harde-spatie": chr(0xA0),
    "smalle-harde-spatie": chr(0x202F),
    "em-spatie": chr(0x2003),
    "ideografische-spatie": chr(0x3000),
    "nulbreedte": chr(0x200B),
    "nulbreedte-en-spatie": chr(0x200B) + " ",
    "woordverbinder-en-spatie": chr(0x2060) + " ",
}
COLONS = {"dubbele-punt": ":", "volle-breedte": chr(0xFF1A), "klein": chr(0xFE55)}
SPACED_HEADER_CASES = {
    f"{header}-{gap}-{colon}": (
        f'add lb monitor MON-10 HTTP -customHeaders "{header}{BEFORE_THE_COLON[gap]}{COLONS[colon]} sid=CANARY-SEP"'
    )
    for header in SECRET_HEADER_NAMES
    for gap in BEFORE_THE_COLON
    for colon in COLONS
}


@pytest.mark.parametrize("name", sorted(SPACED_HEADER_CASES))
def test_a_secret_header_with_a_gap_before_its_colon_is_withheld(name):
    line = SPACED_HEADER_CASES[name]
    assert drift_module.is_secret_line(line), name
    assert "CANARY" not in drift_module.shown_line(line)


# Next to them, lines that carry no secret and stay readable at `volledig`:
# the three authorization policy OBJECT shapes the exception exists for, a
# header that is not a secret with the same blank space before its colon, a
# rewrite action writing an ordinary header with a policy-object word after
# it, and a cookie persistence setting.
SPACED_HEADER_VISIBLE_CONTROLS = (
    *AUTHORIZATION_POLICY_LINES,
    'add lb monitor MON-11 HTTP -customHeaders "X-Test : sid=zichtbaar"',
    "add rewrite action RWA-14 insert_http_header X-Test policy zichtbaar",
    "set lb vserver LBV-SYNTH -persistenceType COOKIEINSERT -cookieName SESSIE",
)


@pytest.mark.parametrize("line", SPACED_HEADER_VISIBLE_CONTROLS)
def test_a_control_next_to_a_secret_header_stays_visible(line):
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


@pytest.mark.parametrize("side", ["running", "saved"])
@pytest.mark.parametrize("header", SECRET_HEADER_NAMES)
def test_secret_headers_with_a_gap_never_reach_the_answer_through_a_real_export_read(tmp_path, header, side):
    """One export per header name, so its thirty lines and the controls stay
    under the cap of forty shown lines per side and every one is counted."""
    lines = [line for name, line in SPACED_HEADER_CASES.items() if name.startswith(f"{header}-")]
    assert len(lines) == len(BEFORE_THE_COLON) * len(COLONS)
    extra = lines + list(SPACED_HEADER_VISIBLE_CONTROLS)
    assert len(extra) <= drift_module.MAX_LINES_PER_SIDE
    export = _pair(
        tmp_path,
        extra_running=extra if side == "running" else [],
        extra_saved=extra if side == "saved" else [],
    )
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        assert "CANARY" not in _render(export, level, tmp_path), level
    label = "alleen in running" if side == "running" else "alleen in saved"
    full = _render(export, Disclosure.FULL, tmp_path)
    assert full.count(f"{drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]") == len(lines)
    for control in SPACED_HEADER_VISIBLE_CONTROLS:
        assert f"- {label}: {control} [vastgesteld]" in full


# A raw HTTP message written out in full carries its headers the way
# `-customHeaders` does: a responder action's `respondwith`, an HTTP-ECV
# monitor's `-send`, an HTTP monitor's `-httpRequest`. The same shapes apply
# there: the Cookie or Set-Cookie header with a colon that only looks like
# one, the Authorization header followed by a word the policy-object
# exception knows, the header name as the last word before an escaped CRLF,
# and a Set-Cookie header put together by concatenation. MEASURED: neither
# lab export carries a responder action, a `-send` or an `-httpRequest` that
# names a cookie or Authorization. Look-alike colons built from code points
# so this source file stays ASCII.
ESCAPED_CRLF = "\\r\\n"
LOOK_ALIKE_COLONS = {
    "verhouding": chr(0x2236),
    "modificatieletter": chr(0xA789),
    "armeens": chr(0x0589),
    "hebreeuws": chr(0x05C3),
    "twee-punten": chr(0x205A),
    "z-notatie": chr(0x2982),
    "mongools": chr(0x1804),
    "bamum": chr(0xA6F4),
}


def _respond(header):
    return (
        f'add responder action RSA-02 respondwith "\\"HTTP/1.1 200 OK{ESCAPED_CRLF}{header}'
        f'{ESCAPED_CRLF}{ESCAPED_CRLF}\\""'
    )


def _send(header):
    return f'add lb monitor MON-15 HTTP-ECV -send "GET / HTTP/1.1{ESCAPED_CRLF}{header}{ESCAPED_CRLF}" -recv OK'


def _http_request(header):
    return f'add lb monitor MON-16 HTTP -httpRequest "GET / HTTP/1.1{ESCAPED_CRLF}{header}"'


RAW_MESSAGE_HEADER_LINES = {
    **{
        f"respondwith-set-cookie-{name}": _respond(f"Set-Cookie{colon} sid={SPACED_HEADER_CANARY}")
        for name, colon in LOOK_ALIKE_COLONS.items()
    },
    **{
        f"send-cookie-{name}": _send(f"Cookie{colon} sid={SPACED_HEADER_CANARY}")
        for name, colon in LOOK_ALIKE_COLONS.items()
    },
    **{
        f"httprequest-cookie-{name}": _http_request(f"Cookie{colon} sid={SPACED_HEADER_CANARY}")
        for name, colon in LOOK_ALIKE_COLONS.items()
    },
    "respondwith-authorization-policy": _respond(f"Authorization policy {SPACED_HEADER_CANARY}"),
    "respondwith-proxy-authorization-action": _respond(f"Proxy-Authorization action {SPACED_HEADER_CANARY}"),
    "send-authorization-policy": _send(f"Authorization policy {SPACED_HEADER_CANARY}"),
    "httprequest-authorization-policylabel": _http_request(f"Authorization policylabel {SPACED_HEADER_CANARY}"),
    "respondwith-set-cookie-crlf-voor-dubbele-punt": _respond(f"Set-Cookie{ESCAPED_CRLF}: sid={SPACED_HEADER_CANARY}"),
    "respondwith-set-cookie-laatste-woord": _respond(f"X-Test: Set-Cookie{ESCAPED_CRLF} sid={SPACED_HEADER_CANARY}"),
    "send-cookie-crlf-voor-dubbele-punt": _send(f"Cookie{ESCAPED_CRLF}: sid={SPACED_HEADER_CANARY}"),
    "respondwith-set-cookie-samengesteld": _respond(f'Set-Cookie\\" + \\": sid={SPACED_HEADER_CANARY}'),
}

# Next to them: the same three arguments without a secret header, and a
# responder POLICY that only reads a cookie.
RAW_MESSAGE_VISIBLE_CONTROLS = (
    _respond("X-Test: zichtbaar"),
    _send("Host: zichtbaar"),
    _http_request("Host: zichtbaar"),
    'add responder policy RSP-02 "HTTP.REQ.COOKIE.CONTAINS(\\"sid\\")" RSA-02',
)


@pytest.mark.parametrize("name", sorted(RAW_MESSAGE_HEADER_LINES))
def test_a_secret_header_in_a_raw_http_message_is_withheld(name):
    line = RAW_MESSAGE_HEADER_LINES[name]
    assert drift_module.is_secret_line(line), name
    assert SPACED_HEADER_CANARY not in drift_module.shown_line(line)


@pytest.mark.parametrize("line", RAW_MESSAGE_VISIBLE_CONTROLS)
def test_a_raw_http_message_without_a_secret_header_stays_visible(line):
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


@pytest.mark.parametrize("side", ["running", "saved"])
def test_secret_headers_in_a_raw_http_message_never_reach_the_answer_through_a_real_export_read(tmp_path, side):
    lines = list(RAW_MESSAGE_HEADER_LINES.values())
    extra = lines + list(RAW_MESSAGE_VISIBLE_CONTROLS)
    assert len(extra) <= drift_module.MAX_LINES_PER_SIDE
    export = _pair(
        tmp_path,
        extra_running=extra if side == "running" else [],
        extra_saved=extra if side == "saved" else [],
    )
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        assert SPACED_HEADER_CANARY not in _render(export, level, tmp_path), level
    label = "alleen in running" if side == "running" else "alleen in saved"
    full = _render(export, Disclosure.FULL, tmp_path)
    assert full.count(f"{drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]") == len(lines)
    for control in RAW_MESSAGE_VISIBLE_CONTROLS:
        assert f"- {label}: {control} [vastgesteld]" in full


# A request written out in full the same way: the `-fullReqExpr` of an HTTP
# callout and of a webAuth action carries its headers as `-send` and
# `-httpRequest` do, so the same shapes apply there. MEASURED: neither lab
# export carries a `-fullReqExpr` at all.
def _callout_request(header):
    return (
        "add policy httpCallout HC-04 -IPAddress 192.0.2.40 -port 80 -returnType TEXT "
        f'-fullReqExpr "\\"GET / HTTP/1.1{ESCAPED_CRLF}{header}{ESCAPED_CRLF}{ESCAPED_CRLF}\\""'
    )


def _webauth_request(header):
    return (
        "add authentication webAuthAction WAA-01 -serverIP 192.0.2.41 -serverPort 80 "
        f'-fullReqExpr "\\"POST / HTTP/1.1{ESCAPED_CRLF}{header}{ESCAPED_CRLF}{ESCAPED_CRLF}\\"" '
        "-scheme http -successRule true"
    )


FULL_REQUEST_HEADER_LINES = {
    **{
        f"callout-cookie-{name}": _callout_request(f"Cookie{colon} sid={SPACED_HEADER_CANARY}")
        for name, colon in LOOK_ALIKE_COLONS.items()
    },
    "callout-authorization-policy": _callout_request(f"Authorization policy {SPACED_HEADER_CANARY}"),
    "callout-proxy-authorization-action": _callout_request(f"Proxy-Authorization action {SPACED_HEADER_CANARY}"),
    "callout-cookie-crlf-voor-dubbele-punt": _callout_request(f"Cookie{ESCAPED_CRLF}: sid={SPACED_HEADER_CANARY}"),
    "callout-cookie-samengesteld": _callout_request(f'Cookie\\" + \\": sid={SPACED_HEADER_CANARY}'),
    "webauth-cookie-verhouding": _webauth_request(f"Cookie{chr(0x2236)} sid={SPACED_HEADER_CANARY}"),
    "webauth-authorization-policylabel": _webauth_request(f"Authorization policylabel {SPACED_HEADER_CANARY}"),
    "webauth-cookie-crlf-voor-dubbele-punt": _webauth_request(f"Cookie{ESCAPED_CRLF}: sid={SPACED_HEADER_CANARY}"),
    "webauth-cookie-samengesteld": _webauth_request(f'Cookie\\" + \\": sid={SPACED_HEADER_CANARY}'),
}

FULL_REQUEST_VISIBLE_CONTROLS = (
    _callout_request("Host: zichtbaar"),
    _webauth_request("Host: zichtbaar"),
)


@pytest.mark.parametrize("name", sorted(FULL_REQUEST_HEADER_LINES))
def test_a_secret_header_in_a_full_request_is_withheld(name):
    line = FULL_REQUEST_HEADER_LINES[name]
    assert drift_module.is_secret_line(line), name
    assert SPACED_HEADER_CANARY not in drift_module.shown_line(line)


@pytest.mark.parametrize("line", FULL_REQUEST_VISIBLE_CONTROLS)
def test_a_full_request_without_a_secret_header_stays_visible(line):
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == line


@pytest.mark.parametrize("side", ["running", "saved"])
def test_secret_headers_in_a_full_request_never_reach_the_answer_through_a_real_export_read(tmp_path, side):
    lines = list(FULL_REQUEST_HEADER_LINES.values())
    extra = lines + list(FULL_REQUEST_VISIBLE_CONTROLS)
    assert len(extra) <= drift_module.MAX_LINES_PER_SIDE
    export = _pair(
        tmp_path,
        extra_running=extra if side == "running" else [],
        extra_saved=extra if side == "saved" else [],
    )
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        assert SPACED_HEADER_CANARY not in _render(export, level, tmp_path), level
    label = "alleen in running" if side == "running" else "alleen in saved"
    full = _render(export, Disclosure.FULL, tmp_path)
    assert full.count(f"{drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]") == len(lines)
    for control in FULL_REQUEST_VISIBLE_CONTROLS:
        assert f"- {label}: {control} [vastgesteld]" in full


# A line break other than LF INSIDE one configuration line: a lone carriage
# return, a vertical tab, a form feed, a file, group or record separator,
# NEL, the Unicode line or paragraph separator. The export read used to cut
# a line there - before its own credential filter and before this one - so
# what followed the character (the value after `-password`, after a cookie
# header's colon) reached the answer at `volledig` as a line of its own. The
# read splits on LF alone: the character stays inside its line, where the
# filter reads it as a space or as nothing. Built from code points so this
# source file stays ASCII.
LINE_BREAKS_INSIDE_A_LINE = {
    "wagenterugloop": chr(0x0D),
    "verticale-tab": chr(0x0B),
    "formulierdoorvoer": chr(0x0C),
    "bestandsscheiding": chr(0x1C),
    "groepsscheiding": chr(0x1D),
    "recordscheiding": chr(0x1E),
    "volgende-regel": chr(0x85),
    "regelscheiding": chr(0x2028),
    "alineascheiding": chr(0x2029),
}


def _lines_with_a_break_inside(gap):
    """Every secret header name with the break before its colon, a cookie
    with the break after its colon, and a password flag with the break
    between the flag and its value."""
    return [
        *(
            f'add lb monitor MON-12 HTTP -customHeaders "{header}{gap}: sid={SPACED_HEADER_CANARY}"'
            for header in SECRET_HEADER_NAMES
        ),
        f'add lb monitor MON-13 HTTP -customHeaders "Cookie:{gap}session={SPACED_HEADER_CANARY}"',
        f"add lb monitor MON-14 LDAP -password{gap}{SPACED_HEADER_CANARY}",
    ]


@pytest.mark.parametrize("side", ["running", "saved"])
@pytest.mark.parametrize("name", sorted(LINE_BREAKS_INSIDE_A_LINE))
def test_a_line_break_inside_a_secret_line_never_reaches_the_answer(tmp_path, name, side):
    """Through the export read, `drift_answer` and the disclosure seam, one
    export per character and side: the canary is in no answer at any level,
    and at `volledig` every line is counted and withheld as ONE line."""
    lines = _lines_with_a_break_inside(LINE_BREAKS_INSIDE_A_LINE[name])
    export = _pair(
        tmp_path,
        extra_running=lines if side == "running" else [],
        extra_saved=lines if side == "saved" else [],
    )
    for level in (Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL):
        assert SPACED_HEADER_CANARY not in _render(export, level, tmp_path), level
    full = _render(export, Disclosure.FULL, tmp_path)
    running, saved = (len(lines), 0) if side == "running" else (0, len(lines))
    assert f"{running} alleen in running, {saved} alleen in saved" in full
    assert full.count(f"{drift_module.SECRET_WITHHELD_TEXT} [vastgesteld]") == len(lines)


@pytest.mark.parametrize(
    ("fixture", "withheld"),
    [(LAB, (11, 11)), (DOH, (8, 8))],
    ids=["lab-20260826", "lab-doh-synthetic"],
)
def test_the_filter_withholds_exactly_the_measured_lines_of_both_lab_exports(fixture, withheld):
    """Counted per side (running, saved) over the compared lines, before the
    fold read invisible characters both ways and before every rewrite action
    on a cookie header counted as a secret: 11 of 330 on the lab export.
    Widening the filter may not cost a line of a real export. The synthetic
    DoH export carries exactly its 8 marker lines per side as secret lines,
    8 of 169."""
    export = load_export(fixture)
    counts = []
    for lines, gap in (export.running_config_lines(), export.saved_config_lines()):
        assert gap is None
        counts.append(sum(drift_module.is_secret_line(line) for line in comparable_lines(lines)))
    assert tuple(counts) == withheld


@pytest.mark.parametrize(
    ("line", "shown", "head"),
    [
        (
            f"set lb vserver LBV-SYNTH -comment ge{ZERO_WIDTH_SPACE}woon",
            "set lb vserver LBV-SYNTH -comment gewoon",
            "set lb vserver",
        ),
        (
            f"set lb v{ZERO_WIDTH_SPACE}server LBV-SYNTH -comment gewoon",
            "set lb vserver LBV-SYNTH -comment gewoon",
            "set lb vserver",
        ),
    ],
    ids=["in-een-waarde", "in-het-commando"],
)
def test_an_invisible_format_character_is_shown_as_nothing(line, shown, head):
    """A zero-width or other format character is shown as what it looks
    like - nothing - never as a space, and the command head is built from
    the line as shown."""
    assert not drift_module.is_secret_line(line)
    assert drift_module.shown_line(line) == shown
    assert drift_module.command_head(line) == head


# ---------------------------------------------------------------------------
# The shape fence: cap per line, cap per side, nothing unprintable.
# ---------------------------------------------------------------------------


def test_at_most_forty_lines_per_side_and_the_rest_counted(tmp_path):
    extra = [f"add server SRV-{index:03d} 192.0.2.{index}" for index in range(100, 145)]
    text = _render(_pair(tmp_path, extra_running=extra), Disclosure.FULL, tmp_path)
    assert text.count("- alleen in running: ") == 41
    assert "- alleen in running: en 5 regels meer [vastgesteld]" in text
    assert "    bewijs: maximaal 40 regels per kant getoond; de telling staat bij config-drift" in text
    assert "SRV-139 " in text and "SRV-140 " not in text
    assert "45 alleen in running, 0 alleen in saved" in text
    assert "- commandohoofd alleen in running: add server (45 regels) [vastgesteld]" in text


def test_one_line_over_the_cap_is_counted_in_the_singular(tmp_path):
    extra = [f"add server SRV-{index:03d} 192.0.2.{index}" for index in range(100, 141)]
    text = _render(_pair(tmp_path, extra_running=extra), Disclosure.FULL, tmp_path)
    assert "- alleen in running: en 1 regel meer [vastgesteld]" in text


def test_at_most_forty_command_heads_per_side(tmp_path):
    extra = [f"set lb type{index} -x 1" for index in range(42)]
    text = _render(_pair(tmp_path, extra_running=extra), Disclosure.LIMITED, tmp_path)
    assert text.count("- commandohoofd alleen in running: ") == 41
    assert "- commandohoofd alleen in running: en 2 commandohoofden meer [vastgesteld]" in text
    assert "    bewijs: maximaal 40 commandohoofden per kant getoond" in text


def test_a_long_line_is_cut_at_two_hundred_characters_and_says_so(tmp_path):
    line = "add policy expression EXP-001 " + "A" * 250
    text = _render(_pair(tmp_path, extra_running=[line]), Disclosure.FULL, tmp_path)
    assert f"- alleen in running: {line[:200]} [...] (regel afgekapt op 200 tekens) [vastgesteld]" in text
    assert line[:201] not in text


def test_a_non_printable_character_never_reaches_the_answer(tmp_path):
    line = "set lb vserver LBV-001 -comment a\x1b[31mb\x07"
    text = _render(_pair(tmp_path, extra_running=[line]), Disclosure.FULL, tmp_path)
    assert "\x1b" not in text and "\x07" not in text
    assert "- alleen in running: set lb vserver LBV-001 -comment a [31mb  [vastgesteld]" in text


# ---------------------------------------------------------------------------
# A read gap is `onbevestigd`, never "geen drift".
# ---------------------------------------------------------------------------


def test_a_saved_config_that_does_not_match_its_hash_is_onbevestigd(tmp_path):
    export = _pair(tmp_path, extra_running=[INSERTED])
    (export.directory / "parsed" / "savedconfig.txt").write_text("gewijzigd\n", encoding="utf-8")
    text = _render(load_export(export.directory), Disclosure.FULL, tmp_path)
    assert "- config-drift: onbevestigd [niet vastgesteld]" in text
    assert "NIET VASTGESTELD (geen stille aanname):" in text
    assert "- parsed/savedconfig.txt: parsed/savedconfig.txt komt niet overeen met het manifest" in text
    assert "config-drift: uit" not in text
    assert "alleen in running" not in text
    assert INSERTED not in text


def test_a_missing_saved_config_is_onbevestigd(tmp_path):
    export_dir = _pair(tmp_path).directory
    manifest_path = export_dir / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["resources"]["config/nssavedconfig"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    text = _render(load_export(export_dir), Disclosure.FULL, tmp_path)
    assert "- config-drift: onbevestigd [niet vastgesteld]" in text
    assert "- config/nssavedconfig: resource staat niet in het manifest van deze export" in text


# ---------------------------------------------------------------------------
# The header moments: evidence, never the verdict.
# ---------------------------------------------------------------------------


def test_on_the_real_export_the_headers_and_the_withheld_values_leave_the_verdict_open(tmp_path):
    """The headers say "changed after the last save"; what is left of the
    content after the header lines compares equal, but ten lines per side
    carry a value the collector already withheld on the jumphost. Whether
    the change sits in one of those values the export cannot say, so the
    answer used to call the content equal as an established fact and now
    says it is not established - without a line and without a read gap."""
    text = _render(load_export(LAB), Disclosure.FULL, tmp_path)
    assert (
        "- config-drift: onbevestigd [niet vastgesteld]\n"
        "    bewijs: parsed/runningconfig.txt 330 regels tegenover parsed/savedconfig.txt 330 regels na weglaten"
        " van kopregels en 'Done'; 0 alleen in running, 0 alleen in saved; 10 regels per kant met een waarde"
        " die de verzamelaar al achterhield, niet te vergelijken\n"
        "    reden: 10 regels per kant dragen een waarde die de verzamelaar al achterhield en die niet te"
        " vergelijken is; de kopregels melden een wijziging na de laatste opslag, en of die in zo'n waarde"
        " zit, is uit deze export niet vast te stellen\n"
    ) in text
    assert (
        "- kopregels: laatste wijziging Wed Aug 26 12:22:53 2026, laatste opslag Thu Aug 20 13:19:38 2026"
        " (tijd van de appliance) [vastgesteld]\n"
        "    bewijs: regel 2 van parsed/runningconfig.txt en van parsed/savedconfig.txt; bewijs, geen oordeel:"
        " het oordeel rust op de inhoud"
    ) in text
    assert "config-drift: uit" not in text
    assert "de inhoud is gelijk" not in text
    assert "kopregels tegenover inhoud" not in text
    assert "NIET VASTGESTELD (geen stille aanname):" not in text


def test_on_the_doh_export_the_headers_carry_uit_and_the_withheld_values_are_counted(tmp_path):
    """Saved at the moment of the last change: the headers carry `uit`, and
    the evidence says how many lines could not be compared."""
    text = _render(load_export(DOH), Disclosure.FULL, tmp_path)
    assert (
        "- config-drift: uit [vastgesteld]\n"
        "    bewijs: parsed/runningconfig.txt 169 regels tegenover parsed/savedconfig.txt 169 regels na"
        " weglaten van kopregels en 'Done'; 0 alleen in running, 0 alleen in saved; 8 regels per kant met"
        " een waarde die de verzamelaar al achterhield, niet te vergelijken\n"
    ) in text


def test_a_synthetic_pair_without_any_marker_line_pins_the_full_contradiction_block(tmp_path):
    """The one export that used to pin the full "headers against content"
    block (label, outcome and evidence sentence together) was the first lab
    export - and that export now carries lines the collector withheld, so
    its answer is `onbevestigd`, not the contradiction. A synthetic pair
    with the same later-running header, equal content and not a single
    marker line is the one case left where `undecided` is false and the
    contradiction fires, so this is where the exact form of its evidence
    sentence stays pinned."""
    text = _render(_pair(tmp_path), Disclosure.FULL, tmp_path)
    assert (
        "- kopregels tegenover inhoud: de kopregels melden een wijziging na de laatste opslag, maar de inhoud"
        " is gelijk [vastgesteld]\n"
        "    bewijs: laatste wijziging Thu Sep 24 10:12:03 2026 is later dan laatste opslag Wed Sep 23"
        " 12:59:15 2026; parsed/runningconfig.txt 6 regels tegenover parsed/savedconfig.txt 6 regels na"
        " weglaten van kopregels en 'Done'; 0 alleen in running, 0 alleen in saved"
    ) in text
    assert "- config-drift: uit [vastgesteld]" in text
    assert "onbevestigd" not in text


def test_equal_headers_on_the_doh_export_raise_no_contradiction(tmp_path):
    text = _render(load_export(DOH), Disclosure.FULL, tmp_path)
    assert (
        "- kopregels: laatste wijziging Sun Sep 6 12:00:00 2026, laatste opslag Sun Sep 6 12:00:00 2026"
        " (tijd van de appliance) [vastgesteld]"
    ) in text
    assert "kopregels tegenover inhoud" not in text


def test_real_drift_with_a_later_change_is_no_contradiction(tmp_path):
    text = _render(_pair(tmp_path, extra_running=[INSERTED]), Disclosure.FULL, tmp_path)
    assert (
        "- kopregels: laatste wijziging Thu Sep 24 10:12:03 2026, laatste opslag Wed Sep 23 12:59:15 2026"
        " (tijd van de appliance) [vastgesteld]"
    ) in text
    assert "kopregels tegenover inhoud" not in text


@pytest.mark.parametrize(
    "header",
    [
        "# Last modified GISTEREN-NOG",
        "# Last modified Mon Sep 24 10:12:03 2026",  # 24 September 2026 is a Thursday
        "# Last modified Thu Sep 24 10:12:03 2026 GISTEREN-NOG",
        "# Last modified by `save config`, Thu Sep 24 10:12:03 2026",  # the saved form on the running side
    ],
)
def test_a_header_of_an_unknown_shape_is_not_established_and_never_echoed(tmp_path, header):
    export = load_export(
        config_pair(tmp_path, [RUNNING_HEADER[0], header, *BASE, " Done"], SAVED_HEADER + BASE, name="kop")
    )
    text = _render(export, Disclosure.FULL, tmp_path)
    assert "- config-drift: uit [vastgesteld]" in text
    assert (
        "- kopregels: niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: regel 2 van parsed/runningconfig.txt en van parsed/savedconfig.txt; bewijs, geen oordeel:"
        " het oordeel rust op de inhoud\n"
        "    reden: regel 2 van parsed/runningconfig.txt draagt geen tijdstempel in de vorm die deze versie kent"
    ) in text
    assert "GISTEREN" not in text
    assert "Mon Sep 24" not in text


# ---------------------------------------------------------------------------
# A difference that sits only in the part the credential filter withholds.
# The export read cuts that part away for every reader, so the compared lines
# are equal while the files are not: a changed bind password that was not
# saved. That is drift, counted, and its content is in no answer.
# ---------------------------------------------------------------------------

WITHHELD_ONLY_EVIDENCE = (
    "parsed/runningconfig.txt 7 regels tegenover parsed/savedconfig.txt 7 regels na weglaten van"
    " kopregels en 'Done'; 1 alleen in running, 1 alleen in saved, waarvan 1 per kant alleen in een"
    " achtergehouden deel"
)
WITHHELD_ONLY_FINDING = (
    "- verschil in achtergehouden deel: 1 regel per kant verschilt alleen in een deel dat een geheim"
    " kan dragen; dat deel wordt in geen stand getoond [vastgesteld]\n"
    "    bewijs: running en saved vergeleken met en zonder dat deel; alleen een telling, nooit de inhoud"
)


def _withheld_only_pair(tmp_path, name, swapped):
    running_line, saved_line = WITHHELD_ONLY_PAIRS[name]
    if swapped:
        running_line, saved_line = saved_line, running_line
    export = _pair(tmp_path, extra_running=[running_line], extra_saved=[saved_line])
    # PREMISE: the two lines really are equal once the credential filter of
    # the export read has cut them, and really differ in the files - so the
    # answer below is about a difference ONLY in the withheld part.
    running, running_gap = export.running_config_lines()
    saved, saved_gap = export.saved_config_lines()
    assert (running_gap, saved_gap) == (None, None)
    assert comparable_lines(running) == comparable_lines(saved)
    assert running_line != saved_line
    return export


def _assert_no_secret(text):
    for value in (OLD_SECRET, NEW_SECRET):
        assert value not in text


@pytest.mark.parametrize("swapped", [False, True], ids=["oud-in-running", "oud-in-saved"])
@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_a_difference_only_in_the_withheld_part_is_drift_at_volledig(tmp_path, name, swapped):
    text = _render(_withheld_only_pair(tmp_path, name, swapped), Disclosure.FULL, tmp_path)
    assert f"- config-drift: aan [vastgesteld]\n    bewijs: {WITHHELD_ONLY_EVIDENCE}\n" in text
    assert WITHHELD_ONLY_FINDING in text
    # The headers say "changed after the last save", and the content agrees.
    assert "kopregels tegenover inhoud" not in text
    assert "de inhoud is gelijk" not in text
    # No line is listed: the part that differs is withheld, at every level.
    assert "- alleen in running:" not in text
    assert "- alleen in saved:" not in text
    _assert_no_secret(text)


@pytest.mark.parametrize("swapped", [False, True], ids=["oud-in-running", "oud-in-saved"])
@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_a_difference_only_in_the_withheld_part_is_drift_at_beperkt(tmp_path, name, swapped):
    text = _render(_withheld_only_pair(tmp_path, name, swapped), Disclosure.LIMITED, tmp_path)
    assert f"- config-drift: aan [vastgesteld]\n    bewijs: {WITHHELD_ONLY_EVIDENCE}\n" in text
    assert WITHHELD_ONLY_FINDING in text
    assert "de inhoud is gelijk" not in text
    _assert_no_secret(text)


@pytest.mark.parametrize("swapped", [False, True], ids=["oud-in-running", "oud-in-saved"])
@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_a_difference_only_in_the_withheld_part_counts_at_minimaal_as_a_visible_one_does(tmp_path, name, swapped):
    """At `minimaal` only counts remain. A difference in the withheld part
    must count exactly as a visible one-line difference counts - the drift
    finding and the header finding - not as "equal content" with the
    header contradiction on top."""
    text = _render(_withheld_only_pair(tmp_path, name, swapped), Disclosure.MINIMAL, tmp_path)
    control = _pair(
        tmp_path / "controle",
        extra_running=["set lb vserver LBV-001 -comment een"],
        extra_saved=["set lb vserver LBV-001 -comment twee"],
    )
    assert text == _render(control, Disclosure.MINIMAL, tmp_path)
    assert "- 2 bevinding(en)" in text
    _assert_no_secret(text)


@pytest.mark.parametrize("swapped", [False, True], ids=["oud-in-running", "oud-in-saved"])
@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_a_difference_only_in_the_withheld_part_is_config_drift_in_ha_stand(tmp_path, name, swapped):
    result, gaps = ha_result(_withheld_only_pair(tmp_path, name, swapped))
    # A synthetic pair carries no HA objects; those dimensions have their own
    # read gaps. None of them is about the two config texts.
    assert not [gap for gap in gaps if gap.source.startswith("parsed/")]
    assert result.drift.state == ON
    assert result.drift.evidence == WITHHELD_ONLY_EVIDENCE
    assert DRIFT_LABEL in result.blockers
    _assert_no_secret(repr(result))


@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_an_equal_withheld_part_on_both_sides_is_still_no_drift(tmp_path, name):
    """The control: the same credential on both sides is equal content, and
    the header contradiction still stands - counting the withheld part may
    not turn every line with a credential into drift."""
    line, _ = WITHHELD_ONLY_PAIRS[name]
    export = _pair(tmp_path, extra_running=[line], extra_saved=[line])
    text = _render(export, Disclosure.FULL, tmp_path)
    assert "- config-drift: uit [vastgesteld]" in text
    assert "; 0 alleen in running, 0 alleen in saved\n" in text
    assert "achtergehouden deel" not in text
    assert "de inhoud is gelijk [vastgesteld]" in text
    result, _gaps = ha_result(export)
    assert result.drift.state == OFF
    _assert_no_secret(text)


def test_a_withheld_and_a_visible_difference_are_counted_together(tmp_path):
    user_old, user_new = WITHHELD_ONLY_PAIRS["system-user"]
    same = f"add system user SYSU-02 {OLD_SECRET} -encrypted -encryptmethod ENCMTHD_3"
    export = _pair(
        tmp_path,
        extra_running=[user_old, same, "set lb vserver LBV-001 -comment een"],
        extra_saved=[user_new, same, "set lb vserver LBV-001 -comment twee"],
    )
    text = _render(export, Disclosure.FULL, tmp_path)
    assert "- config-drift: aan [vastgesteld]" in text
    assert "; 2 alleen in running, 2 alleen in saved, waarvan 1 per kant alleen in een achtergehouden deel\n" in text
    assert "- alleen in running: set lb vserver LBV-001 -comment een [vastgesteld]" in text
    assert "- alleen in saved: set lb vserver LBV-001 -comment twee [vastgesteld]" in text
    assert text.count("- alleen in running: ") == 1
    assert text.count("- alleen in saved: ") == 1
    assert WITHHELD_ONLY_FINDING in text
    _assert_no_secret(text)


def test_the_withheld_part_is_compared_as_a_multiset(tmp_path):
    """Two lines that are equal after the cut, twice on each side: one pair
    is equal in the files too, the other is not - one line per side."""
    line_old, line_new = WITHHELD_ONLY_PAIRS["ldap-bind-password"]
    comparison, gaps = read_comparison(
        _pair(tmp_path, extra_running=[line_old, line_old], extra_saved=[line_old, line_new])
    )
    assert gaps == ()
    assert (comparison.only_running, comparison.only_saved, comparison.withheld_only) == ((), (), 1)
    assert comparison.drift is True


@pytest.mark.parametrize(("fixture", "marked"), [(LAB, 10), (DOH, 8)], ids=["lab-20260826", "lab-doh-synthetic"])
def test_neither_lab_export_differs_in_a_withheld_part(fixture, marked):
    """Zero on both lab exports - BY CONSTRUCTION, not as a measurement: the
    collector already wrote its marker in place of every credential value,
    on both sides, so there is no value left in these files for the keyed
    count to compare. This says nothing about whether NetScaler writes an
    encrypted value identically into the running and the saved config; that
    is not measured in this repository (docs/klant/OPENSTAANDE-METINGEN.md),
    and until an export that carries the values exists, a false `aan` from
    a value encrypted anew on save is not ruled out. What these exports do
    show: every marked line is counted as not comparable instead."""
    comparison, gaps = read_comparison(load_export(fixture))
    assert gaps == ()
    assert (comparison.withheld_only, comparison.not_comparable) == (0, marked)
    assert "achtergehouden" not in comparison_evidence(comparison)


def test_a_withheld_count_that_cannot_be_read_is_onbevestigd_never_uit(tmp_path, monkeypatch):
    """The count is a second read of the same two files. When that read
    fails - the export was replaced in between - the verdict is not
    established; it never falls back to the comparison without it."""
    from nsmcp.answer import ReadGap

    export = _withheld_only_pair(tmp_path, "system-user", False)
    gap = ReadGap(source="parsed/savedconfig.txt", reason="de export is vervangen; stel de vraag opnieuw")
    monkeypatch.setattr(export, "withheld_only_difference", lambda _comparable: (None, gap))
    text = _render(export, Disclosure.FULL, tmp_path)
    assert "- config-drift: onbevestigd [niet vastgesteld]" in text
    assert "- config-drift: uit" not in text
    result, gaps = ha_result(export)
    assert result.drift.state == UNCONFIRMED
    assert gap in gaps


# ---------------------------------------------------------------------------
# A value the collector already withheld. The released collector writes its
# marker in place of a credential value on the jumphost, in the running and
# in the saved config alike, so a password changed and not saved stands in
# the export as two EQUAL lines: no count can see it. Such lines are counted
# as not comparable - a number, never a line - and when the headers do not
# say the last save came at or after the last change, the verdict is not
# established: `uit` would claim what the export does not carry.
# ---------------------------------------------------------------------------

NOT_COMPARABLE_EVIDENCE = (
    "parsed/runningconfig.txt 7 regels tegenover parsed/savedconfig.txt 7 regels na weglaten van"
    " kopregels en 'Done'; 0 alleen in running, 0 alleen in saved; 1 regel per kant met een waarde die"
    " de verzamelaar al achterhield, niet te vergelijken"
)
UNDECIDED_REASON = (
    "1 regel per kant draagt een waarde die de verzamelaar al achterhield en die niet te vergelijken is;"
    " de kopregels melden een wijziging na de laatste opslag, en of die in zo'n waarde zit, is uit deze"
    " export niet vast te stellen"
)


def _collector_pair(tmp_path, name, saved_header=SAVED_HEADER):
    """The line of `name` on both sides, as the collector writes it; the
    running header says the configuration changed after the saved one's
    moment unless `saved_header` says otherwise."""
    line = COLLECTOR_MARKER_LINES[name]
    return load_export(
        config_pair(tmp_path, RUNNING_HEADER + BASE + [line, " Done"], saved_header + BASE + [line], name="markering")
    )


@pytest.mark.parametrize("level", [Disclosure.FULL, Disclosure.LIMITED], ids=["volledig", "beperkt"])
@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_a_value_the_collector_withheld_is_onbevestigd_when_the_headers_say_changed_after_save(tmp_path, name, level):
    text = _render(_collector_pair(tmp_path, name), level, tmp_path)
    assert (
        "- config-drift: onbevestigd [niet vastgesteld]\n"
        f"    bewijs: {NOT_COMPARABLE_EVIDENCE}\n"
        f"    reden: {UNDECIDED_REASON}\n"
    ) in text
    assert "config-drift: uit" not in text
    assert "de inhoud is gelijk" not in text
    assert "kopregels tegenover inhoud" not in text
    # Nothing of the line, at any level, and no read gap: both files were read.
    assert "- alleen in running:" not in text and "- alleen in saved:" not in text
    assert "SYSU-01" not in text and "MON-01" not in text and "192.0.2.6" not in text
    assert "NIET VASTGESTELD (geen stille aanname):" not in text


@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_a_value_the_collector_withheld_leaves_minimaal_without_an_established_answer(tmp_path, name):
    text = _render(_collector_pair(tmp_path, name), Disclosure.MINIMAL, tmp_path)
    assert "- actie nodig: niet vast te stellen uit dit antwoord" in text
    assert "- 0 leesgat(en) (niet vastgesteld, geen stille aanname)" in text


@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_a_value_the_collector_withheld_makes_config_drift_onbevestigd_in_ha_stand(tmp_path, name):
    result, gaps = ha_result(_collector_pair(tmp_path, name))
    assert not [gap for gap in gaps if gap.source.startswith("parsed/")]
    assert result.drift.state == UNCONFIRMED
    assert result.drift.evidence == NOT_COMPARABLE_EVIDENCE
    assert result.drift.reason == UNDECIDED_REASON
    # `onbevestigd` is never the safe state, so it holds up the change.
    assert DRIFT_LABEL in result.blockers


@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_a_value_the_collector_withheld_stays_uit_when_the_headers_say_saved_after_the_change(tmp_path, name):
    """The appliance itself says nothing changed after the last save, so the
    marker cannot hide an unsaved change: `uit`, with the count noted."""
    export = _collector_pair(tmp_path, name, saved_header=SAVED_AFTER_CHANGE_HEADER)
    text = _render(export, Disclosure.FULL, tmp_path)
    assert f"- config-drift: uit [vastgesteld]\n    bewijs: {NOT_COMPARABLE_EVIDENCE}\n" in text
    assert "onbevestigd" not in text
    result, _gaps = ha_result(export)
    assert result.drift.state == OFF
    assert result.drift.evidence == NOT_COMPARABLE_EVIDENCE


def test_a_value_the_collector_withheld_is_onbevestigd_when_the_headers_cannot_be_read(tmp_path):
    """Headers of an unknown shape carry no statement about the order of
    change and save, so they cannot carry `uit` either: fail closed."""
    line = COLLECTOR_MARKER_LINES["system-user"]
    export = load_export(
        config_pair(
            tmp_path,
            [RUNNING_HEADER[0], "# Last modified GISTEREN-NOG", *BASE, line, " Done"],
            SAVED_HEADER + BASE + [line],
            name="kop",
        )
    )
    text = _render(export, Disclosure.FULL, tmp_path)
    assert (
        "- config-drift: onbevestigd [niet vastgesteld]\n"
        f"    bewijs: {NOT_COMPARABLE_EVIDENCE}\n"
        "    reden: 1 regel per kant draagt een waarde die de verzamelaar al achterhield en die niet te"
        " vergelijken is; de kopregels dragen geen leesbaar tijdstempel, dus of er na de laatste opslag iets"
        " in zo'n waarde is gewijzigd, is uit deze export niet vast te stellen\n"
    ) in text
    assert "GISTEREN-NOG" not in text


def test_a_visible_difference_next_to_a_withheld_value_is_still_aan(tmp_path):
    line = COLLECTOR_MARKER_LINES["rpcnode-password"]
    export = _pair(tmp_path, extra_running=[line, INSERTED], extra_saved=[line])
    text = _render(export, Disclosure.FULL, tmp_path)
    assert (
        "- config-drift: aan [vastgesteld]\n"
        "    bewijs: parsed/runningconfig.txt 8 regels tegenover parsed/savedconfig.txt 7 regels na weglaten van"
        " kopregels en 'Done'; 1 alleen in running, 0 alleen in saved; 1 regel per kant met een waarde die de"
        " verzamelaar al achterhield, niet te vergelijken\n"
    ) in text
    assert f"- alleen in running: {INSERTED} [vastgesteld]" in text


def test_a_withheld_value_on_one_side_only_is_a_visible_difference(tmp_path):
    """A line with the marker that stands on one side only differs in what
    every reader sees; it is not a line that could not be compared."""
    export = _pair(tmp_path, extra_running=[COLLECTOR_MARKER_LINES["monitor-password"]])
    comparison, gaps = read_comparison(export)
    assert gaps == ()
    assert (len(comparison.only_running), len(comparison.only_saved), comparison.not_comparable) == (1, 0, 0)
    assert "niet te vergelijken" not in comparison_evidence(comparison)
    assert "- config-drift: aan [vastgesteld]" in _render(export, Disclosure.FULL, tmp_path)


# ---------------------------------------------------------------------------
# The command head.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "head"),
    [
        ("set lb vserver LBV-001 -comment x", "set lb vserver"),
        ("add server SRV-001 192.0.2.10", "add server"),
        ("bind serviceGroup SG-001 SRV-001 80", "bind serviceGroup"),
        ("add ssl certKey CERT-001 -cert a.pem", "add ssl certKey"),
        ("set HA node -haStatus STAYPRIMARY", "set HA node"),
        ("add route 0.0.0.0 0.0.0.0 192.0.2.1", "add route"),
        ("set interface 0/1 -haMonitor OFF", "set interface"),
        ("set service nshttpd-gui-127.0.0.1-80 -maxClient 0", "set service"),
        ("add lb LBV-001 x", "add lb"),
        ("add lb vserver", "add lb vserver"),
        ("SET LB VSERVER LBV-001", "set LB VSERVER"),
        ('add "LBV 001" x', "add"),
        ("add", "add"),
        ("frobnicate lb vserver", "(commando niet herkend)"),
        ('"add" lb vserver', "(commando niet herkend)"),
        ("add passwordX value", "(commandohoofd met een geheim; niet getoond)"),
        ("set aaa user jan", "(commandohoofd met een geheim; niet getoond)"),
    ],
)
def test_the_command_head_never_carries_an_argument(line, head):
    assert drift_module.command_head(line) == head


# ---------------------------------------------------------------------------
# The tool: its own chapter, always registered, `doel` checked and never
# echoed.
# ---------------------------------------------------------------------------

LAB_02 = {
    "naam": "lab-02",
    "adres": "192.0.2.2",
    "credentialTarget": "GJK/Test/lab-02/nitro-read",
    "certificaat": "keten",
}


def _server(tmp_path, *, chapters=DEFAULT_CHAPTERS, doelen=None):
    export_dir = copy_with_running(tmp_path, LAB, lambda text: text)
    # The lab export as this server's own scan of `lab`: the provenance
    # record `status_ververs` would have left, outside the export.
    record_collected(export_dir, "lab")
    targets_path = None
    if doelen is not None:
        targets_path = tmp_path / "doelen.json"
        targets_path.write_text(json.dumps({"doelen": doelen}), encoding="utf-8")
    return build_server(
        export_dir,
        _knowledge(tmp_path),
        targets_path=targets_path,
        chapters=chapters,
        pseudonym_table_path=tmp_path / "tabel.json",
        provenance_dir=provenance_dir_for(export_dir),
    )


def test_config_drift_is_the_tool_of_its_own_chapter_and_needs_no_configuration(tmp_path):
    assert "config" in DEFAULT_CHAPTERS
    server = _server(tmp_path, chapters=frozenset({"config"}))
    assert {tool.name for tool in asyncio.run(server.list_tools())} == {"config_drift"}


def test_config_drift_answers_without_a_doel(tmp_path):
    r = _call(_server(tmp_path), "config_drift", {})
    assert not r.isError, _text(r)
    # The verdict on this export (see
    # test_on_the_real_export_the_headers_and_the_withheld_values_leave_the_verdict_open).
    assert "- config-drift: onbevestigd [niet vastgesteld]" in _text(r)
    assert "doel: lab, herkomst: verzameld door deze server op " in _text(r)


LAB_DOEL = {
    "naam": "lab",
    "adres": "192.0.2.1",
    "credentialTarget": "GJK/Test/lab/nitro-read",
    "certificaat": "keten",
}


def test_config_drift_answers_for_the_doel_the_export_describes(tmp_path):
    r = _call(_server(tmp_path, doelen=[LAB_DOEL, LAB_02]), "config_drift", {"doel": "lab"})
    assert not r.isError, _text(r)
    assert "- config-drift: onbevestigd [niet vastgesteld]" in _text(r)


def test_config_drift_refuses_a_configured_doel_the_export_does_not_describe(tmp_path):
    """The server holds ONE export, of `lab`. A configured `lab-02` is a
    real target, but this export says nothing about it: the answer would
    describe the wrong appliance, so the call is refused with the advice to
    refresh first."""
    r = _call(_server(tmp_path, doelen=[LAB_DOEL, LAB_02]), "config_drift", {"doel": "lab-02"})
    assert r.isError
    assert ("de export van deze server beschrijft een ander doel (lab); ververs eerst met status_ververs") in _text(r)


@pytest.mark.parametrize("doelen", [None, [LAB_02]], ids=["geen-doelen", "een-doel"])
def test_an_unknown_doel_is_refused_without_repeating_it(tmp_path, doelen):
    r = _call(_server(tmp_path, doelen=doelen), "config_drift", {"doel": "geheim-doel-x"})
    assert r.isError
    assert ONBEKEND_DOEL_TEXT in _text(r)
    assert "geheim-doel-x" not in _text(r)
