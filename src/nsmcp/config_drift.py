"""Running config against saved config: the ONE comparison, and the answer
`config_drift` gives about it.

Three readers ask the same question - does the running configuration differ
from the saved one - and they must not answer it three ways: `ha.py` (the
`config-drift` dimension of `ha_stand`, and through it the scorecard's
GJK-L1-HA-004), `preflight.py` (check 4, when the export carries no
`config/nsconfig`) and this module's own tool. So the comparison lives here,
once, and the other two call it.

WHAT IS LEFT OUT, MEASURED. On two real lab exports
(tests/fixtures/lab-export-vpx-20260826, 333 against 332 lines, and a second
workbench export that is not in this repository) a plain multiset comparison
reported "2 alleen in running, 1 alleen in saved", and the three lines were
never configuration:

- line 2 of the running config, `# Last modified <tijd>`;
- line 2 of the saved config, "# Last modified by `save config`, <tijd>" -
  a different TEXT, even when both carry the same moment (the second export);
- the closing ` Done` the appliance writes under the running config only.

So a stripped line that starts with `#`, or that is exactly `Done`, does not
take part. Everything else does, as a multiset - a line that occurs twice in
running and once in saved is one line only in running - and, as before, a
difference in blank lines or indentation alone is not drift. The CVE readers
deliberately stay on the raw lines: their evidence counts every line of the
file ("in 333 regels") and that is a different statement.

The lines this module compares have already passed `export.py`'s credential
filter (`redact.py`): a credential-carrying line is compared in its redacted
form on both sides. That alone would call two lines equal that differ only in
the part the filter cut away - a password changed on the appliance and not
saved - so the export also COUNTS those lines (`Export.withheld_only_difference`,
a number per side, never a line or a value), and that count is drift like any
other difference: it takes part in the verdict, in the only-in counts of the
evidence (`, waarvan N per kant alleen in een achtergehouden deel`) and in a
finding of its own, at every level, with nothing of the withheld part in it.

That count only sees a value the export carries. The released collector
already writes a fixed marker in place of a credential value on the
jumphost, in the running and the saved config alike (measured on two lab
exports, ten and thirteen lines per side), and then a password changed and not saved is
two EQUAL lines in the export - no count can see it. The export counts those
lines too, as not comparable (a number per side), and the comparison does
not call their content equal: with such lines and headers that do not say
"saved at or after the last change", the verdict is `onbevestigd` with that
count as its reason (`Comparison.undecided`), in all three readers alike.

THE ANSWER SHOWS LINES, AND THAT IS A DELIBERATE EXCEPTION. Every other tool
of this product reports counts and never a configuration line, because a
line can carry a credential (design 3.6, unit 8) and a name that sits in no
name family. `config_drift` is the one tool that shows the lines themselves,
because "which lines would a save keep" is the question an operator has
before saving. The exception is fenced four ways, each at its own seam:

1. OPENHEID. A line finding carries `Finding.only_in_full=True`, so the
   disclosure seam drops it at 'beperkt' and 'minimaal' before anything is
   masked or counted. Below 'volledig' what remains is, per side, the
   COMMAND HEAD of those lines (at most three words, never an argument) with
   a count - and at 'minimaal' only the seam's own counts. This module does
   not know the disclosure level (the layer rule, docs/ARCHITECTURE.md); it
   only states, per finding, what may be said where.
2. SECRETS. A line with any of the markers in `SECRET_MARKERS`, of one of
   the shapes in `SECRET_PATTERNS`, or of one of the commands in
   `SECRET_COMMANDS` - as written, as it would be shown, as a person reads
   it (an invisible character both left out and read as a space), or
   without `-` and `_` - or with a letter outside ASCII after that fold, is NEVER
   shown, at no level: only its command head and a note (`SECRET_WITHHELD_TEXT`
   for a marker/shape/command, `SECRET_NON_ASCII_TEXT` for the letter-outside-
   ASCII rule alone - `_secret_reason`/`is_secret_line`), and the head only
   when it passes this same fence itself - otherwise the note stands alone at
   'volledig' and the head is `SECRET_HEAD_TEXT` at 'beperkt'. This list is broader than
   `redact.py`'s closed set on purpose - that filter must keep a line
   usable for the CVE rules, this one only decides whether a line may be
   READ, and here withholding one line too many costs nothing but a look at
   the appliance. Matching is a plain case-insensitive substring test on the
   whole line, blind to quoting, for the same reason.
3. SHAPE. Every shown line has its format characters (zero-width and the
   like) left out and its other non-printable characters replaced by a
   space, and is cut at `MAX_LINE_CHARS`, visibly; at most `MAX_LINES_PER_SIDE` lines per
   side are shown, with the rest counted.
4. HEADS. A command head is built from a closed verb list and a closed list
   of command groups, and every word in it must have the shape of a command
   word. A token that could be an object name never gets into a head. The
   object type is checked for its shape only, so the finished head passes
   the fence of point 2 as well: a head that would carry a marker, or that
   is one of the credential commands, is never shown.

The two header timestamps (line 2 of each file) are EVIDENCE, never the
verdict: the verdict rests on the content. When the headers say "changed
after the last save" while the content compares equal, the answer says so in
a finding of its own instead of letting either side silently win. The one
place the headers weigh in is the paragraph above: where lines could not be
compared, only headers that say "saved at or after the last change" let the
answer stay `uit`; otherwise it is `onbevestigd` - measured on
tests/fixtures/lab-export-vpx-20260826, whose headers say changed after the
last save and whose ten marked lines per side could carry it. A timestamp is the
appliance's own clock without a time zone: it is only ever compared with the
other one, never with the clock of this server, and it is re-rendered from
the parsed value, never echoed.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from nsmcp.answer import Answer, Certainty, Finding, ReadGap
from nsmcp.export import RUNNING_CONFIG_FILE, SAVED_CONFIG_FILE

# The two shapes of a line that is not configuration. Named once, so the
# evidence sentence below and the filter cannot say different things.
HEADER_MARK = "#"
TRAILER = "Done"

# What the evidence says was left out. Product copy, pinned in
# tests/test_product_surface.py - like every other Dutch text of this module.
LEFT_OUT_TEXT = "na weglaten van kopregels en 'Done'"

QUESTION = "wijkt de draaiende configuratie af van de opgeslagen configuratie"

ONLY_RUNNING_LABEL = "alleen in running"
ONLY_SAVED_LABEL = "alleen in saved"
HEAD_RUNNING_LABEL = "commandohoofd alleen in running"
HEAD_SAVED_LABEL = "commandohoofd alleen in saved"
HEADERS_LABEL = "kopregels"
HEADERS_AGAINST_CONTENT_LABEL = "kopregels tegenover inhoud"

SECRET_WITHHELD_TEXT = "(regel met een geheim of een geredigeerde waarde; niet getoond)"
SECRET_NON_ASCII_TEXT = "(regel met letters buiten ASCII; niet getoond)"
SECRET_HEAD_TEXT = "(commandohoofd met een geheim; niet getoond)"
UNKNOWN_HEAD_TEXT = "(commando niet herkend)"
APPLIANCE_TIME_TEXT = "(tijd van de appliance)"
HEADERS_EVIDENCE_TEXT = (
    f"regel 2 van {RUNNING_CONFIG_FILE} en van {SAVED_CONFIG_FILE}; bewijs, geen oordeel: het oordeel rust op de inhoud"
)
HEADERS_UNREADABLE_TEXT = "draagt geen tijdstempel in de vorm die deze versie kent"
HEADERS_AGAINST_CONTENT_TEXT = "de kopregels melden een wijziging na de laatste opslag, maar de inhoud is gelijk"
WITHHELD_ONLY_LABEL = "verschil in achtergehouden deel"
WITHHELD_ONLY_EVIDENCE_SUFFIX = ", waarvan {n} per kant alleen in een achtergehouden deel"
WITHHELD_ONLY_EVIDENCE_TEXT = "running en saved vergeleken met en zonder dat deel; alleen een telling, nooit de inhoud"
# The lines whose value the collector itself already withheld (its marker on
# both sides, `export.COLLECTOR_REDACTION_MARKER`): a count in the evidence,
# and - when the headers do not carry `uit` - the reason the verdict is not
# established (`undecided_reason`).
NOT_COMPARABLE_EVIDENCE_SUFFIX = "; {n} per kant met een waarde die de verzamelaar al achterhield, niet te vergelijken"
UNDECIDED_TEXT = "{n} per kant {verb} een waarde die de verzamelaar al achterhield en die niet te vergelijken is"
UNDECIDED_CHANGED_TEXT = (
    "de kopregels melden een wijziging na de laatste opslag, en of die in zo'n waarde zit, is uit deze"
    " export niet vast te stellen"
)
UNDECIDED_UNREADABLE_TEXT = (
    "de kopregels dragen geen leesbaar tijdstempel, dus of er na de laatste opslag iets in zo'n waarde is"
    " gewijzigd, is uit deze export niet vast te stellen"
)
HEADS_EVIDENCE_TEXT = "het commandohoofd van regels die alleen in {bron} staan; argumenten en namen weggelaten"
LINE_EVIDENCE_TEXT = "{bron}; niet in {ander}"
MORE_LINES_EVIDENCE_TEXT = "maximaal {n} regels per kant getoond; de telling staat bij config-drift"
MORE_HEADS_EVIDENCE_TEXT = "maximaal {n} commandohoofden per kant getoond"

# The fence of point 3 above.
MAX_LINE_CHARS = 200
MAX_LINES_PER_SIDE = 40
LINE_CUT_NOTE = " [...] (regel afgekapt op 200 tekens)"

# The fence of point 2 above. Case-insensitive SUBSTRINGS of the whole line.
# The first eleven are the design's own list; the rest widen it, each for a
# credential carrier this product has seen named:
#   - "geredigeerd": `redact.REDACTION_NOTE`, the product's own mark on a
#     line `export.py` already cut;
#   - "keyvalue", "passcrypt", "psk": flag names of `redact.py`'s class 1
#     that no word above covers;
#   - "passplain": the plain-text passphrase of `add ssl certKey`;
#   - "credential": `-ssoCredential` and its kin;
#   - "community": an SNMP community string, a password by another name;
#   - "apikey", "token": keys and tokens of API and OAuth objects;
#   - "scriptargs": the free-form arguments of a scripted monitor, the usual
#     place a monitor's credentials travel under a name of their own;
#   - "bearer": an HTTP bearer token written out literally in a monitor, a
#     rewrite action, an HTTP callout or a policy expression. "authorization"
#     itself moved to `SECRET_PATTERNS` below - a bare marker also withheld
#     `add authorization policy`/`bind authorization policylabel`, which name
#     a policy OBJECT, never a header value;
#   - "pass=", "key=": a password or a key in the query or the body of a
#     monitor, an authentication request or a responder text;
#   - "cookie:": a session cookie in a monitor's custom headers.
# "api-key", "api_key" and "X-Api-Key" need no marker of their own: the
# filter also reads a line without `-` and `_` (see `is_secret_line`), and
# then "apikey" catches them.
# "sharedsecret" is already covered by "secret"; it stays because the design
# names it, and a later narrowing of "secret" must not quietly drop it.
SECRET_MARKERS: tuple[str, ...] = (
    "<redacted>",
    "password",
    "passwd",
    "encrypted",
    "encryptmethod",
    "passphrase",
    "secret",
    "privatekey",
    "bindpw",
    "radkey",
    "sharedsecret",
    "geredigeerd",
    "keyvalue",
    "passcrypt",
    "passplain",
    "psk",
    "credential",
    "community",
    "apikey",
    "token",
    "scriptargs",
    "bearer",
    "pass=",
    "key=",
    "cookie:",
)

# Secrets recognised by their SHAPE rather than by a word: the credentials of
# a URL (`scheme://user:password@host`), wherever a line carries one; a
# cookie with a fixed value in the header a rewrite action
# (`insert_http_header Cookie "..."`) or an HTTP callout
# (`-headers "Cookie(...)"`) inserts - in each of the three forms NetScaler
# writes a string in (double quotes, single quotes, and a `q` followed by a
# delimiter: `q{...}`, `q/.../`, ...), and with the header name quoted itself
# (`"Cookie" "..."`). And EVERY rewrite or responder action that mentions a
# cookie: a rewrite action's target can be the Cookie or Set-Cookie header
# (`replace`, `insert_after`, `insert_before` on `HTTP.REQ.HEADER("Cookie")`),
# and its value can be an expression instead of a string - a fixed cookie
# value either way; a responder action writes a whole HTTP response
# (`respondwith "...Set-Cookie..."`), its headers included, in any spelling
# the appliance passes on as text. Not the bare word elsewhere: `cookie` also
# names cookie persistence (`COOKIEINSERT`, `-cookieName`) and a policy that
# only reads the header (`HEADER("Cookie")`, `HTTP.REQ.COOKIE`), and those
# lines carry no secret. Measured: neither real lab export carries a rewrite
# or responder action that mentions a cookie.
#
# The Authorization/Proxy-Authorization header written out literally - a bare
# "authorization" marker also withheld a line that only NAMES the header, and
# on both real lab exports that cost exactly the lines that mention it: a
# built-in cache policy and header allow-lists, never a value. MEASURED:
# `add authorization policy`/`policylabel` occur on neither real lab export,
# so this negative lookahead costs nothing there for those two shapes.
# `-defaultAuthorizationAction` DOES occur - three `add vpn sessionAction`
# lines per side on the vpx export - and this lookahead no longer catches
# them; they stay withheld anyway, on `<redacted>`/`credential`
# (`-ssoCredential <REDACTED>` further along the same lines), which is why
# the pinned counts (11/11, 18/18) do not move. Widens what stays visible
# the day a line carries `-defaultAuthorizationAction` and no OTHER marker -
# a policy OBJECT NAME, never a header value, so nothing this filter exists
# to protect.
#
# The lookahead is about the word after the header name only, so it may never
# decide on a line that WRITES a header: there the word after the name is the
# header VALUE (`insert_http_header Authorization policy <value>` passed the
# lookahead and showed its value at `volledig`). So, next to it, two shapes
# that look at the command instead: every rewrite or responder action that
# mentions Authorization (the mirror of the cookie rule above), and every
# header-writing argument - an `*_http_header` action type, a monitor's
# `-customHeaders`, the raw request of an HTTP-ECV monitor's `-send` or an
# HTTP monitor's `-httpRequest`, a callout's `-headers`, the raw request of
# an HTTP callout's or a webAuth action's `-fullReqExpr` - that names
# Authorization or a cookie, whatever follows. In a raw request or response
# that also covers a header the appliance would not send as one (a colon
# replaced by a look-alike, the name as the last word before an escaped
# CRLF, a header put together by concatenation): its value would still
# stand in the answer. `add authorization policy`, `bind authorization
# policylabel` and `-defaultAuthorizationAction` write no header and stay
# visible. MEASURED: on the doh lab export the only lines these two shapes
# match are two `insert_http_header Access-Control-Allow-Headers "...
# authorization ..."` rewrite actions per side, already withheld by the
# lookahead shape; on the vpx export they match nothing. Neither export
# carries a responder action, a `-send` or an `-httpRequest` that names a
# cookie or Authorization (per side: eight responder actions and 47
# `-send`/`-httpRequest` lines on the doh export, one and none on the vpx
# export), and neither carries a `-fullReqExpr` at all.
#
# And a cookie header with blank space - or a quote - between its name and
# its colon (`"Cookie : session=..."`): the marker `cookie:` needs the colon
# right after the name, so the space let the value through at `volledig`.
# The shape runs on every reading `_secret_reason` makes, so an invisible
# character in the gap is left out or read as a space, and a space or colon
# outside ASCII that compatibility-decomposes to one (a no-break or
# ideographic space, a full-width colon) is caught as well. `Set-Cookie2`, the
# obsolete cookie header, is the same secret. The Authorization and
# Proxy-Authorization headers need no such shape: blank space and a colon
# after the name already pass the lookahead above. MEASURED: neither lab
# export carries `cookie` before a colon.
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"://[^\s/@\"']*:[^\s/@\"']*@"),
    re.compile(r"cookie[\"']?(?:\s+(?:[\"']|q[^\w\s])|\s*\()", re.IGNORECASE),
    re.compile(r"^(?:add|set)\s+(?:rewrite|responder)\s+action\b.*cookie", re.IGNORECASE),
    re.compile(r"authorization(?!\s*(?:policy|policylabel|action)\b)", re.IGNORECASE),
    re.compile(r"cookie2?[\"']?\s*:", re.IGNORECASE),
    re.compile(r"^(?:add|set)\s+(?:rewrite|responder)\s+action\b.*authorization", re.IGNORECASE),
    re.compile(
        r"(?:_http_header|-customheaders|-send|-httprequest|-fullreqexpr|-headers)\b.*(?:authorization|cookie)",
        re.IGNORECASE,
    ),
)

# Commands whose purpose is to carry a credential, withheld whatever their
# flags say - on some the secret rides a POSITIONAL argument that no marker
# could name. The first five are the design's own; the others are the same
# kind of object (a user with a password) under another group.
SECRET_COMMANDS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^set\s+ns\s+encryptionparams\b", re.IGNORECASE),
    re.compile(r"^add\s+system\s+user\b", re.IGNORECASE),
    re.compile(r"^set\s+system\s+user\b", re.IGNORECASE),
    re.compile(r"^set\s+ns\s+rpcnode\b", re.IGNORECASE),
    re.compile(r"^add\s+aaa\s+user\b", re.IGNORECASE),
    re.compile(r"^set\s+aaa\s+user\b", re.IGNORECASE),
    re.compile(r"^(?:add|set)\s+snmp\s+user\b", re.IGNORECASE),
    re.compile(r"^(?:add|set)\s+db\s+user\b", re.IGNORECASE),
)

# The fence of point 4 above. A head is the verb, and then either the object
# type (`add server`, `bind serviceGroup`) or the command group plus the
# object type (`set lb vserver`, `add ssl certKey`). Both lists are CLOSED:
# a verb outside `_VERBS` gives `UNKNOWN_HEAD_TEXT`, and a second word
# outside `_GROUPS` ends the head after two words - so an object name,
# which in NetScaler's grammar always comes after the object type, can
# never be the third word.
_VERBS = frozenset(
    {
        "add",
        "apply",
        "bind",
        "clear",
        "create",
        "disable",
        "enable",
        "import",
        "link",
        "rename",
        "reset",
        "rm",
        "set",
        "sync",
        "unbind",
        "unlink",
        "unset",
        "update",
    }
)
_GROUPS = frozenset(
    {
        "aaa",
        "analytics",
        "api",
        "appflow",
        "appfw",
        "appqoe",
        "audit",
        "authentication",
        "authorization",
        "autoscale",
        "bot",
        "cache",
        "cloud",
        "cluster",
        "cmp",
        "contentinspection",
        "cr",
        "cs",
        "db",
        "dns",
        "dos",
        "dps",
        "feo",
        "filter",
        "gslb",
        "ha",
        "ica",
        "ipsec",
        "lb",
        "lsn",
        "ns",
        "ntp",
        "policy",
        "pq",
        "protocol",
        "qos",
        "rdp",
        "reputation",
        "responder",
        "rewrite",
        "rise",
        "sc",
        "smpp",
        "snmp",
        "spillover",
        "ssl",
        "stream",
        "subscriber",
        "system",
        "tm",
        "transform",
        "tunnel",
        "urlfiltering",
        "videooptimization",
        "vpn",
    }
)
# A command word: a letter, then letters and digits. No hyphen, underscore,
# dot, slash or quote - the characters object names, addresses and
# interface numbers are made of.
_COMMAND_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]{0,39}")

# Line 2 of each file. The moment is parsed field by field and re-rendered
# from the parsed value, so nothing of the supplied line is ever echoed.
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MOMENT = (
    r"(?P<weekday>[A-Z][a-z]{2}) (?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2})"
    r" (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) (?P<year>\d{4})"
)
_CHANGE_HEADER = re.compile(rf"#\s*Last modified {_MOMENT}")
_SAVE_HEADER = re.compile(rf"#\s*Last modified by `save config`, {_MOMENT}")


def comparable_lines(lines) -> list[str]:
    """The stripped lines that take part in the comparison, in file order.

    Left out: an empty line, a line that starts with `#` (the header lines),
    and a line that is exactly `Done` (the appliance's closing line). The
    test is on the STRIPPED line, so the leading space of ` Done` does not
    let it through; `Done` is matched exactly, so a configuration line that
    merely contains the word still counts.
    """
    kept: list[str] = []
    for line in lines:
        stripped = str(line).strip()
        if not stripped or stripped.startswith(HEADER_MARK) or stripped == TRAILER:
            continue
        kept.append(stripped)
    return kept


def _only_in(lines: list[str], other: list[str]) -> tuple[str, ...]:
    """The lines of `lines` that `other` does not also carry, as a multiset
    difference, in the order they stand in `lines`."""
    remaining = Counter(other)
    only: list[str] = []
    for line in lines:
        if remaining[line] > 0:
            remaining[line] -= 1
        else:
            only.append(line)
    return tuple(only)


def _moment(lines, pattern: re.Pattern[str]) -> datetime | None:
    """The moment on line 2, or None when line 2 does not have exactly the
    shape this version knows - including a weekday that does not belong to
    the date, which no appliance writes."""
    if len(lines) < 2:
        return None
    match = pattern.fullmatch(str(lines[1]).strip())
    if match is None or match["weekday"] not in _WEEKDAYS or match["month"] not in _MONTHS:
        return None
    try:
        moment = datetime(
            int(match["year"]),
            _MONTHS.index(match["month"]) + 1,
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
        )
    except ValueError:
        return None
    if _WEEKDAYS[moment.weekday()] != match["weekday"]:
        return None
    return moment


def moment_text(moment: datetime) -> str:
    """A header moment in the appliance's own notation, built from the
    parsed value (so `Sun Sep  6` comes back as `Sun Sep 6`)."""
    return (
        f"{_WEEKDAYS[moment.weekday()]} {_MONTHS[moment.month - 1]} {moment.day}"
        f" {moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} {moment.year}"
    )


@dataclass(frozen=True)
class Comparison:
    """What the comparison established, and nothing it did not.

    `running_count` and `saved_count` are the numbers of lines that TOOK PART
    (after leaving out the header lines and `Done`), so the evidence never
    prints a raw line count next to only-in counts that were computed on
    something else. `last_change` and `last_save` are the two header moments,
    or None where line 2 did not have the known shape.

    `only_running` and `only_saved` are the lines that differ in what the
    credential filter left of them - the lines `volledig` may show.
    `withheld_only` is the number of lines PER SIDE that are equal in that
    form and differ only in the part the filter cut away
    (`Export.withheld_only_difference`); those lines are never held here, so
    they can never be shown. Both kinds are drift, and both count in
    `running_only_count`/`saved_only_count`.

    `not_comparable` is the number of lines PER SIDE that are equal in the
    files and carry the collector's marker in place of a value
    (`Export.withheld_only_difference`): the collector withheld the value
    on the jumphost, on both sides, so a password changed and not saved
    looks exactly like an unchanged one. Such lines are neither drift nor
    equal content; `undecided` says when they decide the verdict.
    """

    running_count: int
    saved_count: int
    only_running: tuple[str, ...]
    only_saved: tuple[str, ...]
    last_change: datetime | None = None
    last_save: datetime | None = None
    withheld_only: int = 0
    not_comparable: int = 0

    @property
    def running_only_count(self) -> int:
        return len(self.only_running) + self.withheld_only

    @property
    def saved_only_count(self) -> int:
        return len(self.only_saved) + self.withheld_only

    @property
    def drift(self) -> bool:
        return bool(self.only_running or self.only_saved or self.withheld_only)

    @property
    def saved_after_change(self) -> bool:
        """Do the two headers say the last save came at or after the last
        change? False when either header could not be read: an unread header
        says nothing about the order of the two."""
        return self.last_change is not None and self.last_save is not None and self.last_save >= self.last_change

    @property
    def undecided(self) -> bool:
        """No difference found, and yet `uit` is not established: lines whose
        value the collector withheld could hide one, and the headers do not
        say that nothing changed after the last save - they say it did, or
        they cannot be read. With the headers saying "saved at or after the
        last change", the appliance itself carries `uit`, and those lines
        are only counted in the evidence."""
        return not self.drift and self.not_comparable > 0 and not self.saved_after_change


def compare_config(running, saved, *, withheld_only: int = 0, not_comparable: int = 0) -> Comparison:
    """Compares two config texts, given as lines, the one way this product does.

    `withheld_only` is the export's count of lines that differ only in the
    part its credential filter cut away, and `not_comparable` its count of
    equal lines whose value the collector had already withheld
    (`Export.withheld_only_difference`); the lines given here are the cut
    ones, so this function can see neither itself."""
    running = list(running)
    saved = list(saved)
    left = comparable_lines(running)
    right = comparable_lines(saved)
    return Comparison(
        running_count=len(left),
        saved_count=len(right),
        only_running=_only_in(left, right),
        only_saved=_only_in(right, left),
        last_change=_moment(running, _CHANGE_HEADER),
        last_save=_moment(saved, _SAVE_HEADER),
        withheld_only=withheld_only,
        not_comparable=not_comparable,
    )


def comparison_evidence(comparison: Comparison) -> str:
    """The one evidence sentence for a comparison, shared by every reader.
    The parts about the withheld difference and about the lines that could
    not be compared are only there when there are such lines, so the
    sentence of every comparison without them reads as it always did."""
    evidence = (
        f"{RUNNING_CONFIG_FILE} {comparison.running_count} regels tegenover"
        f" {SAVED_CONFIG_FILE} {comparison.saved_count} regels {LEFT_OUT_TEXT};"
        f" {comparison.running_only_count} alleen in running, {comparison.saved_only_count} alleen in saved"
    )
    if comparison.withheld_only:
        evidence += WITHHELD_ONLY_EVIDENCE_SUFFIX.format(n=comparison.withheld_only)
    if comparison.not_comparable:
        evidence += NOT_COMPARABLE_EVIDENCE_SUFFIX.format(n=_lines_text(comparison.not_comparable))
    return evidence


def undecided_reason(comparison: Comparison) -> str:
    """Why `uit` is not established on an `undecided` comparison - the one
    sentence `config_drift`, `ha_stand` and pre-flight check 4 give. A
    count and the headers' order, never a line or a value."""
    count = comparison.not_comparable
    lines = UNDECIDED_TEXT.format(n=_lines_text(count), verb="draagt" if count == 1 else "dragen")
    readable = comparison.last_change is not None and comparison.last_save is not None
    return f"{lines}; {UNDECIDED_CHANGED_TEXT if readable else UNDECIDED_UNREADABLE_TEXT}"


def read_comparison(export) -> tuple[Comparison | None, tuple[ReadGap, ...]]:
    """The comparison of this export's two config texts, or the read gaps
    that stood in its way.

    Both texts are hash-verified by `export.py`; a text that could not be
    read, or whose hash does not match, is a read gap here - never an empty
    list that would compare as "no drift". The same holds for the count of
    lines that differ only in the withheld part: it is a second read of the
    same two files, and a gap there (the export replaced in between) is a
    read gap too, never a comparison without that count.
    """
    running, running_gap = export.running_config_lines()
    saved, saved_gap = export.saved_config_lines()
    gaps = tuple(gap for gap in (running_gap, saved_gap) if gap is not None)
    if gaps:
        return None, gaps
    counts, withheld_gap = export.withheld_only_difference(comparable_lines)
    if withheld_gap is not None:
        return None, (withheld_gap,)
    return (
        compare_config(running, saved, withheld_only=counts.differing, not_comparable=counts.not_comparable),
        (),
    )


# ---------------------------------------------------------------------------
# The fences around a shown line.
# ---------------------------------------------------------------------------


def _shown_form(text: str) -> str:
    """The characters of a line as `volledig` shows them, before the length
    cut: a format character (Unicode category Cf - a zero-width space, a word
    joiner, a soft hyphen) is invisible, so it is shown as what it looks
    like: nothing. Every other non-printable character becomes a space. The
    command head is built from this form too."""
    return "".join(
        "" if unicodedata.category(character) == "Cf" else (character if character.isprintable() else " ")
        for character in text
    )


def _visible(character: str) -> bool:
    """A character a reader sees as itself: printable ASCII, or a letter or
    digit of any script (the last rule of `is_secret_line` withholds such a
    letter anyway). Anything else - a non-printable or format character, a
    blank or another symbol outside ASCII - is at most a gap to the eye."""
    return (character.isascii() and character.isprintable()) or character.isalnum()


def _readable_forms(text: str) -> tuple[str, str]:
    """The line as a person reads it, twice. Compatibility-decomposed
    (full-width letters become ASCII, an accented letter becomes the letter
    plus a combining mark) and every mark (Unicode category M) left out;
    then every character that is not `_visible` once left OUT (`pass`,
    zero-width space, `word` reads `password`) and once read as a SPACE
    (`system`, zero-width space, `user` reads `system user`). Which of the
    two a reader sees depends on the character and on the screen, so the
    filter reads both."""
    letters = [
        character
        for character in unicodedata.normalize("NFKD", text)
        if not unicodedata.category(character).startswith("M")
    ]
    left_out = "".join(character for character in letters if _visible(character))
    as_space = "".join(character if _visible(character) else " " for character in letters)
    return left_out, as_space


def _secret_reason(line: str) -> str | None:
    """Why `is_secret_line()` withholds this line, or None when it does not:
    `SECRET_WITHHELD_TEXT` for a marker, a shape or a credential command
    (`shown_line()`'s ordinary note), `SECRET_NON_ASCII_TEXT` for the one
    rule below that carries no list. Split out of `is_secret_line()` itself
    so the two callers - the boolean check and the text `shown_line()`
    picks - can never read a different reason than the one that actually
    withheld the line.

    Looked at in every form a reader could see: as written; exactly as
    `shown_line` would show it (`_shown_form`); as a person reads it with
    every invisible character left out and with every one read as a space
    (`_readable_forms`: a password spelled in full-width letters, with a
    combining accent on a letter, or with an invisible character inside or
    between its words); and those two readings without `-` and `_`
    (`api-key` and `X-Api-Key` read as `apikey`). A marker, a shape or a
    credential command in any one of them withholds the line.

    Then one rule without a list: a line that still carries a letter
    outside ASCII after that fold is withheld too. A letter from another
    script can look exactly like a Latin one (a Cyrillic `a` in
    `-password`), and no marker list can see that; telling a look-alike from
    an ordinary letter would take a table of every such letter, and one
    missing entry would be a secret shown. So the rule also withholds a line
    with, say, a German sharp s in a comment - measured on both real lab
    exports, not one line carries such a letter. Its own note: nothing in
    `SECRET_WITHHELD_TEXT` (a marker or a "geredigeerde waarde") is true of
    such a line, and an operator reading the note should not go looking for
    a credential that is not there.
    """
    text = str(line).strip()
    left_out, as_space = _readable_forms(text)
    readings = (left_out, as_space)
    compact = tuple(reading.replace("-", "").replace("_", "") for reading in readings)
    for form in (text, _shown_form(text), *readings, *compact):
        form = form.strip()
        folded = form.casefold()
        if any(marker in folded for marker in SECRET_MARKERS):
            return SECRET_WITHHELD_TEXT
        if any(pattern.search(form) for pattern in SECRET_PATTERNS + SECRET_COMMANDS):
            return SECRET_WITHHELD_TEXT
    if any(character.isalpha() and not character.isascii() for character in left_out):
        return SECRET_NON_ASCII_TEXT
    return None


def is_secret_line(line: str) -> bool:
    """May this line never be shown? Errs on the side of yes. See
    `_secret_reason()` for the rules; this is only whether one of them
    fired."""
    return _secret_reason(line) is not None


def _raw_head(line: str) -> str:
    """The head as the grammar of point 4 builds it, before the secret fence."""
    tokens = str(line).split()
    if not tokens or tokens[0].casefold() not in _VERBS:
        return UNKNOWN_HEAD_TEXT
    head = [tokens[0].casefold()]
    if len(tokens) < 2 or not _COMMAND_WORD.fullmatch(tokens[1]):
        return head[0]
    head.append(tokens[1])
    if tokens[1].casefold() in _GROUPS and len(tokens) >= 3 and _COMMAND_WORD.fullmatch(tokens[2]):
        head.append(tokens[2])
    return " ".join(head)


def command_head(line: str) -> str:
    """The command head of a configuration line: at most three words, never
    an argument. See point 4 of the module docstring for why a name cannot
    get in.

    The head is a projection of the line, so it passes the secret fence of
    point 2 itself. The second and third word are only checked for the SHAPE
    of a command word, and an export is data: a line such as `add
    passwordX value` has a head that carries the secret the fence caught in
    the line. A head the fence withholds - that one, or a head that is one
    of `SECRET_COMMANDS` - is `SECRET_HEAD_TEXT`, never the words. The head
    is built from the line as it is shown (`_shown_form`), so an invisible
    character inside a word neither splits nor hides it."""
    head = _raw_head(_shown_form(str(line)))
    return SECRET_HEAD_TEXT if is_secret_line(head) else head


def shown_line(line: str) -> str:
    """What `volledig` shows of a line: the secret fence first, then the
    shown form (`_shown_form`: a format character left out, every other
    non-printable character replaced by a space), then the length cut.

    A withheld line keeps its command head in front of the note only when
    the head itself passed the fence; otherwise the note stands alone, so
    nothing of the line is repeated. The note itself is `_secret_reason()`'s
    - `SECRET_NON_ASCII_TEXT` for the one rule that carries no marker, shape
    or command, `SECRET_WITHHELD_TEXT` for every other reason - never mixed
    with the head's OWN note: a head can never itself trigger the ASCII rule
    (`command_head()`'s words are built only from `_VERBS`/`_GROUPS`/
    `_COMMAND_WORD`, all ASCII by construction), so `SECRET_HEAD_TEXT` always
    means a marker, a shape or a command."""
    reason = _secret_reason(line)
    if reason is not None:
        head = command_head(line)
        return reason if head == SECRET_HEAD_TEXT else f"{head} {reason}"
    text = _shown_form(str(line))
    if len(text) > MAX_LINE_CHARS:
        return text[:MAX_LINE_CHARS] + LINE_CUT_NOTE
    return text


def _lines_text(count: int) -> str:
    return "1 regel" if count == 1 else f"{count} regels"


def more_lines_text(count: int) -> str:
    return f"en {_lines_text(count)} meer"


def more_heads_text(count: int) -> str:
    return "en 1 commandohoofd meer" if count == 1 else f"en {count} commandohoofden meer"


def withheld_only_text(count: int) -> str:
    """The outcome of the withheld-difference finding: a count per side, and
    that what differs is shown nowhere."""
    verb = "verschilt" if count == 1 else "verschillen"
    return (
        f"{_lines_text(count)} per kant {verb} alleen in een deel dat een geheim kan dragen;"
        " dat deel wordt in geen stand getoond"
    )


def _withheld_only_findings(comparison: Comparison) -> list[Finding]:
    """The lines that differ only in the part the credential filter cut
    away - their COUNT, at every level; there is no line to show, and no
    command head either (the export hands out the number and nothing else).

    `counted_at_minimal=False`: like the command heads, this summarizes drift
    the config-drift finding already counts, so 'minimaal' counts a withheld
    difference exactly as it counts a visible one.
    """
    if not comparison.withheld_only:
        return []
    return [
        Finding(
            subject=WITHHELD_ONLY_LABEL,
            outcome=withheld_only_text(comparison.withheld_only),
            certainty=Certainty.ESTABLISHED,
            evidence=WITHHELD_ONLY_EVIDENCE_TEXT,
            subject_is_name=False,
            counted_at_minimal=False,
        )
    ]


def _line_findings(lines: tuple[str, ...], label: str, source: str, other: str) -> list[Finding]:
    """The lines themselves - `volledig` only, by construction."""
    findings = [
        Finding(
            subject=label,
            outcome=shown_line(line),
            certainty=Certainty.ESTABLISHED,
            evidence=LINE_EVIDENCE_TEXT.format(bron=source, ander=other),
            subject_is_name=False,
            only_in_full=True,
        )
        for line in lines[:MAX_LINES_PER_SIDE]
    ]
    if len(lines) > MAX_LINES_PER_SIDE:
        findings.append(
            Finding(
                subject=label,
                outcome=more_lines_text(len(lines) - MAX_LINES_PER_SIDE),
                certainty=Certainty.ESTABLISHED,
                evidence=MORE_LINES_EVIDENCE_TEXT.format(n=MAX_LINES_PER_SIDE),
                subject_is_name=False,
                only_in_full=True,
            )
        )
    return findings


def _head_findings(lines: tuple[str, ...], label: str, source: str) -> list[Finding]:
    """Per command head, how many lines carry it - at every level.

    `counted_at_minimal=False`: these SUMMARIZE the drift the config-drift
    finding already counts, so 'minimaal' does not count them a second time.
    """
    counts = Counter(command_head(line) for line in lines)
    heads = list(counts)  # first-appearance order: Counter keeps insertion order
    findings = [
        Finding(
            subject=label,
            outcome=f"{head} ({_lines_text(counts[head])})",
            certainty=Certainty.ESTABLISHED,
            evidence=HEADS_EVIDENCE_TEXT.format(bron=source),
            subject_is_name=False,
            counted_at_minimal=False,
        )
        for head in heads[:MAX_LINES_PER_SIDE]
    ]
    if len(heads) > MAX_LINES_PER_SIDE:
        findings.append(
            Finding(
                subject=label,
                outcome=more_heads_text(len(heads) - MAX_LINES_PER_SIDE),
                certainty=Certainty.ESTABLISHED,
                evidence=MORE_HEADS_EVIDENCE_TEXT.format(n=MAX_LINES_PER_SIDE),
                subject_is_name=False,
                counted_at_minimal=False,
            )
        )
    return findings


def _header_findings(comparison: Comparison) -> list[Finding]:
    """The two header moments as evidence, and the one contradiction worth a
    finding of its own."""
    change, save = comparison.last_change, comparison.last_save
    if change is None or save is None:
        unreadable = [
            source for source, moment in ((RUNNING_CONFIG_FILE, change), (SAVED_CONFIG_FILE, save)) if moment is None
        ]
        return [
            Finding(
                subject=HEADERS_LABEL,
                outcome="niet vastgesteld",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=HEADERS_EVIDENCE_TEXT,
                reason="; ".join(f"regel 2 van {source} {HEADERS_UNREADABLE_TEXT}" for source in unreadable),
                subject_is_name=False,
            )
        ]
    findings = [
        Finding(
            subject=HEADERS_LABEL,
            outcome=(
                f"laatste wijziging {moment_text(change)}, laatste opslag {moment_text(save)} {APPLIANCE_TIME_TEXT}"
            ),
            certainty=Certainty.ESTABLISHED,
            evidence=HEADERS_EVIDENCE_TEXT,
            subject_is_name=False,
        )
    ]
    # Not when the comparison is `undecided`: lines the collector withheld
    # could carry the change the headers report, so "de inhoud is gelijk"
    # would be a statement nobody measured - the drift finding says why.
    if change > save and not comparison.drift and not comparison.undecided:
        findings.append(
            Finding(
                subject=HEADERS_AGAINST_CONTENT_LABEL,
                outcome=HEADERS_AGAINST_CONTENT_TEXT,
                certainty=Certainty.ESTABLISHED,
                evidence=(
                    f"laatste wijziging {moment_text(change)} is later dan laatste opslag {moment_text(save)};"
                    f" {comparison_evidence(comparison)}"
                ),
                subject_is_name=False,
            )
        )
    return findings


def drift_answer(export, knowledge) -> Answer:
    """The answer of `config_drift`: the verdict on the content, the lines
    (`volledig` only), the command heads, and the header moments as evidence.
    """
    # ha.py imports this module for the comparison, so the vocabulary travels
    # the other way at call time: one set of state words for `config-drift`,
    # whether `ha_stand` or `config_drift` says it.
    from nsmcp.ha import DRIFT_LABEL, OFF, ON, UNCONFIRMED

    comparison, gaps = read_comparison(export)
    if comparison is None:
        return Answer(
            question=QUESTION,
            findings=[
                Finding(
                    subject=DRIFT_LABEL,
                    outcome=UNCONFIRMED,
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{RUNNING_CONFIG_FILE} en {SAVED_CONFIG_FILE}",
                    reason="; ".join(gap.reason for gap in gaps),
                    subject_is_name=False,
                )
            ],
            read_gaps=list(gaps),
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )
    if comparison.undecided:
        verdict = Finding(
            subject=DRIFT_LABEL,
            outcome=UNCONFIRMED,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=comparison_evidence(comparison),
            reason=undecided_reason(comparison),
            subject_is_name=False,
        )
    else:
        verdict = Finding(
            subject=DRIFT_LABEL,
            outcome=ON if comparison.drift else OFF,
            certainty=Certainty.ESTABLISHED,
            evidence=comparison_evidence(comparison),
            subject_is_name=False,
        )
    findings = [verdict]
    findings += _withheld_only_findings(comparison)
    findings += _line_findings(comparison.only_running, ONLY_RUNNING_LABEL, RUNNING_CONFIG_FILE, SAVED_CONFIG_FILE)
    findings += _line_findings(comparison.only_saved, ONLY_SAVED_LABEL, SAVED_CONFIG_FILE, RUNNING_CONFIG_FILE)
    findings += _head_findings(comparison.only_running, HEAD_RUNNING_LABEL, RUNNING_CONFIG_FILE)
    findings += _head_findings(comparison.only_saved, HEAD_SAVED_LABEL, SAVED_CONFIG_FILE)
    findings += _header_findings(comparison)
    return Answer(
        question=QUESTION,
        findings=findings,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
