"""The ONE place a running-config line loses what it must never carry.

Why in the product and not in a scanner. The NetScaler credential format -
`-password <blob> -encrypted`, `-keyValue <blob>` - is NOT recognised by
detect-secrets or by GitHub secret scanning (measured). A
scanner therefore cannot be the protection; the protection has to sit on the
path itself, which is why this module is imported by `export.py` and applied
before any caller ever sees a line.

Why the line stays instead of disappearing. A5 (hidden rules) and B3
(pre-flight) grep over the running config and report a verdict WITH a line
number as evidence. Dropping a line would shift every number after it and
would make a read gap out of something that was read perfectly well. The head
of the line - the command and the object it names - survives, so a rule can
still see the shape; everything inside a CLOSED set of known credential
carriers is replaced by one visible note.

THE REAL CONTRACT (read this before trusting a
new evidence path to this module). Three classes are closed, nothing more:

1. NAMED PARAMETERS (`_CREDENTIAL_PARAMETER_FLAGS`): any line carrying one of
   a fixed set of flag names - -password, -passcrypt, -radKey,
   -tacacsSecret, -ldapBindDnPassword, -kcdPassword, -authPasswd,
   -privPasswd, -clientSecret, -psk, -keyValue, -secondaryPassword - as a
   REAL TOKEN loses everything from that flag onward, whatever command
   carries it. "Real token" means: at a token start AND outside every quoted
   run (see QUOTING below).
2. THE ENCRYPTED BACKSTOP: any line carrying BOTH -encrypted AND
   -encryptmethod loses everything from its first flag onward, whatever the
   command is and whatever the secret-bearing flag is called. Every
   encrypted blob NetScaler writes to ns.conf carries this pair, so a
   parameter name this module has never heard of is still caught here - the
   LAST line of defence named in the module's own docstring history. Because
   it is the last line of defence, its DETECTION deliberately does not care
   about quoting (a line carrying that pair anywhere is treated as an
   encrypted blob); only its CUT is quote-safe.
3. NAMED COMMANDS, cut back to a fixed TOKEN HEAD on the strength of the
   command itself. Three different jobs share this class, and the rule table
   says per entry which one it is doing:
     a. the credential rides a POSITIONAL argument, so no flag name could
        ever mark it and class 1 can never reach it: `(add|set) system
        user`, `add snmp community`.
     b. the head this rule keeps is SHORTER than the one class 1 would
        leave, so the rule still removes text class 1 would have kept:
        `set ns encryptionParams`.
     c. belt and braces over class 1: `set ns rpcNode`, `(add|set) aaa
        user`, `(add|set) lb monitor ... -password/-radKey`. On every
        secret-bearing shape this suite exercises, class 1 already produces
        the identical output, so deleting one of these three leaves the
        suite green (measured). They are kept anyway -
        a command whose whole purpose is to carry a credential should not
        depend on one flag name being spelled the way this module expects.

A line outside all three classes comes back BYTE-IDENTICAL. This is a filter
on a closed set of known credential carriers, not a guess about content - and
closed is NOT the same as complete: a command this module has never seen,
whose secret rides neither a listed parameter name nor the
-encrypted/-encryptmethod pair, passes through UNFILTERED (see
`test_a_single_unnamed_flag_without_the_full_encrypted_pair_is_not_caught`
in tests/test_redact.py for the concrete boundary this leaves open).

QUOTING, and why every path in this module reads it - the two directions
of one mistake. A NetScaler name, expression or
probe string carrying spaces stands between double quotes, and the flag
NAMES this module looks for occur inside such strings on perfectly ordinary
lines: `add responder policy p "HTTP.REQ.URL.CONTAINS(\\"/reset -password\\")"
a`, `add lb monitor m HTTP -httpRequest "GET /reset-password HTTP/1.0"`.
Two separate defects came out of not reading that:
  - MATCHING a flag name inside a quoted run truncated a responder policy,
    a rewrite policy and a health-check monitor - lines carrying no secret
    at all - down to their first few tokens.
  - CUTTING at a raw offset inside a quoted run left an UNBALANCED quote
    behind. `cve.py::_tokens` reads an unclosed quote as unreadable and
    `_reduce_config` counts such a line as a read gap, so the filter
    manufactured a read gap on a line this product read perfectly well.
So there is now exactly one tokenisation here (`_token_spans`), it reads
quotes and backslash escapes the same way `cve.py::_tokens` does, and every
match test and every cut point in this module goes through it. A cut never
lands inside a quoted run; a line whose quoting never closes is treated
fail-closed (matched quote-blind, and cut back to before the run that never
closes, so the head this module returns is balanced even when its input was
not).

An earlier version of this module used an allowlist of COMMAND HEADS
instead of classes 1 and 2 above; independent review replaced it, because
that allowlist let the whole authentication-action family through
(ldapAction, radiusAction, tacacsAction, OAuthAction, kcdAccount, snmp
user's auth/priv passwords, db user, ipsec profile, ssl certKey's
passphrase) - a NetScaler secret is marked by its PARAMETER NAME, not by
which command happens to carry it, and a list of commands can never be as
complete as a list of the handful of parameter names NetScaler actually
uses for a secret.

Nothing here is configurable, in either direction: an allowlist on a
credential filter is a way to turn it off.
"""

from __future__ import annotations

import re

# Dutch, because it can end up in an answer an operator reads. Product copy.
REDACTION_NOTE = "<geredigeerd: deze regel kan een credential dragen>"

# The extra condition on the `lb monitor` rule of class 3: this command only
# carries a credential when one of these flags is on it. `(?<!\S)` anchors
# the flag to a token START, and `_flag_position` additionally requires it to
# sit OUTSIDE every quoted run - without both, `-httpRequest "GET
# /reset-password HTTP/1.0"` and `-send "check-radKey-status"` truncated an
# ordinary health-check monitor to five tokens. Every
# other pattern in this module already carried the token-start anchor; this
# one did not, and an earlier version extended it to a second flag name without noticing.
# On a line whose quoting CLOSES, `_flag_position` is the stronger of the two
# guards and subsumes this anchor entirely; the anchor is what is left when
# the quoting cannot be read at all, and that is the only place a test can
# see it work on its own (tests/test_redact.py, the fail-closed group).
_MONITOR_CREDENTIAL_FLAG = re.compile(r"(?<!\S)-(?:password|radKey)\b", re.IGNORECASE)

# CLASS 3 of the module docstring: named commands cut back to a fixed token
# head. Each entry is (command-head pattern, number of leading tokens that
# survive, flag that must ALSO be present as a real token - or None when the
# command alone is enough). See `_token_head` for how a "token" is counted,
# quotes and all.
#
# The first five are the design's own (3.6 unit 8). `add snmp community`
# is a later addition: the community string itself is the
# credential, and it is written with no flag name at all.
#
# `(add|set) system user`: both the create form (`add`) and the update form
# (`set`) put the password directly after the username with no flag name at
# all, and neither carries `-encryptmethod` on its own, so the class-2
# backstop cannot reach either shape. An earlier version shipped only `add
# system user`, with no test behind it anywhere in the suite; a later
# change deleted the untested rule instead of writing the missing
# test, which silently reopened this exact leak - confirmed live by a
# direct probe: `add system user beheerder <secret> -encrypted` came
# back byte-identical, secret intact, and `-encrypted -encryptmethod
# ENCMTHD_3` still leaked because the backstop's cut point (the first FLAG
# token) sits AFTER the positional password on this shape. This
# restores coverage as ONE rule symmetric with `set`, keeping only 4 tokens
# (command, `system`, `user`, `<name>`) - the password is always the 5th
# token on both forms, so it can never sit inside the kept head. Deleting an
# untested rule is not a fix for "no test"; the fix is the test (see
# tests/test_redact.py).
#
# Positional-hazard audit: every rule below keeps fewer
# tokens than the position of any secret its shape can carry, named PER
# RULE rather than assumed. The letter after each rule is the job it does in
# class 3 (a = positional-only, b = narrower head than class 1, c = belt and
# braces over class 1); see the module docstring.
#   - `set ns rpcNode` (c): secret (if positional at all) cannot start
#     before token 5; keep=4 stops at the IP address (token 4).
#   - `(add|set) system user` (a): password is always token 5 (right after
#     the username); keep=4 stops at the username (token 4).
#   - `(add|set) aaa user` (c): password rides `-password` at token 5+;
#     keep=4 stops at the username (token 4), before the flag ever appears.
#   - `set ns encryptionParams` (b): this object has no name token at all,
#     so every flag - and therefore every secret - starts at token 4; keep=3
#     stops at `encryptionParams` itself (token 3), one token earlier than
#     the cut class 1 would make at `-keyValue`.
#   - `(add|set) lb monitor ... -password/-radKey` (c): token 5 is always
#     the monitor TYPE (an enum, e.g. `LDAP`, `RADIUS`), never a secret; the
#     password/radKey flag cannot appear before token 6; keep=5 stops at
#     the type (token 5).
#   - `add snmp community` (a): the community string itself is the
#     credential and sits at token 4 with no flag in front of it; keep=3
#     stops at `community` (token 3), one token before the secret.
_CREDENTIAL_LINE_RULES: tuple[tuple[re.Pattern[str], int, re.Pattern[str] | None], ...] = (
    (re.compile(r"^\s*set\s+ns\s+rpcNode\b", re.IGNORECASE), 4, None),
    (re.compile(r"^\s*(?:add|set)\s+system\s+user\b", re.IGNORECASE), 4, None),
    (re.compile(r"^\s*(?:add|set)\s+aaa\s+user\b", re.IGNORECASE), 4, None),
    (re.compile(r"^\s*set\s+ns\s+encryptionParams\b", re.IGNORECASE), 3, None),
    (
        re.compile(r"^\s*(?:add|set)\s+lb\s+monitor\b", re.IGNORECASE),
        5,
        _MONITOR_CREDENTIAL_FLAG,
    ),
    (re.compile(r"^\s*add\s+snmp\s+community\b", re.IGNORECASE), 3, None),
)

# CLASS 1 of the module docstring: the credential rides one of these NAMED
# PARAMETERS, on whatever command carries it. `(?<!\S)` anchors each flag to
# a token START (not preceded by a non-space character), so this cannot fire
# on the flag name appearing mid-word inside something else;
# `_flag_position` adds the second half of that guarantee by refusing a
# match that sits inside a quoted run.
_CREDENTIAL_PARAMETER_FLAGS = re.compile(
    r"(?<!\S)-(?:"
    r"password|passcrypt|radKey|tacacsSecret|ldapBindDnPassword|kcdPassword|"
    r"authPasswd|privPasswd|clientSecret|psk|keyValue|secondaryPassword"
    r")\b",
    re.IGNORECASE,
)

# CLASS 2 of the module docstring: the universal suffix. Every encrypted blob
# NetScaler ever writes to ns.conf is followed by `-encrypted -encryptmethod
# ENCMTHD_n`. Two separate patterns rather than one `.*` between them: the
# two flags need not be adjacent, and a single combined pattern would
# silently assume an order this module has never measured on every command.
# These two are searched QUOTE-BLIND on purpose: this is the last line of
# defence, so a line carrying that pair anywhere at all is treated as an
# encrypted blob. Only the cut it then makes is quote-safe.
_ENCRYPTED_FLAG = re.compile(r"(?<!\S)-encrypted\b", re.IGNORECASE)
_ENCRYPTMETHOD_FLAG = re.compile(r"(?<!\S)-encryptmethod\b", re.IGNORECASE)

# Where the encrypted backstop cuts when it fires: the first FLAG-shaped
# token in the line, whatever its name. NetScaler CLI syntax always puts
# positional arguments (the command, the object type, the object name)
# before every flag, so this still leaves the command and the object name in
# the head - it just cannot know, for a parameter name outside class 1,
# which one flag among possibly several carries the secret, so it drops all
# of them rather than guess which is safe to keep.
_ANY_FLAG_TOKEN = re.compile(r"(?<!\S)-\S+")


def _token_spans(text: str) -> tuple[tuple[tuple[int, int], ...], bool]:
    """Every token of `text` as a (start, end) slice of the ORIGINAL string,
    plus whether the line's quoting CLOSED.

    Read exactly the way `cve.py::_tokens` reads a running-config line: a
    double quote toggles quoting, a backslash escapes a quote or a backslash
    INSIDE a quoted run (the real export's policy expressions are written
    that way), and only whitespace OUTSIDE quotes ends a token. So
    `"jan de vries"` is ONE token, and so is
    `"HTTP.REQ.URL.CONTAINS(\\"/reset -password\\")"`.

    Spans are offsets into `text`, never re-joined pieces: everything this
    module returns is therefore a true PREFIX of the original line, so
    indentation and internal spacing survive exactly as written.

    The second value is False when a quote never closes. Callers treat that
    line fail-closed: it is matched quote-blind (so a secret behind the
    unclosed quote is still caught) and cut back to before the run that
    never closes (so the head handed back is balanced even though the input
    was not).
    """
    spans: list[tuple[int, int]] = []
    quoted = False
    start = -1
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if quoted and char == "\\" and index + 1 < length and text[index + 1] in '"\\':
            index += 2
            continue
        if char == '"':
            quoted = not quoted
            if start < 0:
                start = index
            index += 1
            continue
        if not quoted and char.isspace():
            if start >= 0:
                spans.append((start, index))
                start = -1
            index += 1
            continue
        if start < 0:
            start = index
        index += 1
    if start >= 0:
        spans.append((start, length))
    return tuple(spans), not quoted


def _usable_spans(spans: tuple[tuple[int, int], ...], closed: bool) -> tuple[tuple[int, int], ...]:
    """The spans a cut may end on. When the quoting never closed, the LAST
    span is the run that opened the quote and swallowed the rest of the line
    (no whitespace outside quotes can follow it, so there is exactly one such
    span); ending a cut there would hand back the unbalanced quote. Dropping
    it redacts MORE, never less.
    """
    return spans if closed else spans[:-1]


def _token_head(text: str, spans: tuple[tuple[int, int], ...], closed: bool, keep: int) -> str:
    """The leading slice of `text` covering its first `keep` tokens, taken as
    a literal PREFIX of `text` - never a re-join of `text.split()`.

    Counting raw whitespace-tokens instead (an earlier version of this
    function did exactly that) cuts a quoted, space-carrying object name in
    half and leaves an unbalanced quote in the output.
    """
    usable = _usable_spans(spans, closed)
    if not usable:
        return ""
    return text[: usable[min(keep, len(usable)) - 1][1]]


def _safe_cut(spans: tuple[tuple[int, int], ...], closed: bool, position: int) -> int:
    """The largest offset at or before `position` that ends a whole token.

    This is the quote-safe replacement for a raw `text[:position]`.
    A cut here can never land inside a quoted run: either
    `position` already starts a token, in which case this returns the end of
    the token before it, or `position` sits inside a token, in which case
    that whole token is cut away with the rest.
    """
    cut = 0
    for start, end in _usable_spans(spans, closed):
        if start >= position or end > position:
            break
        cut = end
    return cut


def _flag_position(
    text: str,
    starts: frozenset[int],
    closed: bool,
    pattern: re.Pattern[str],
) -> int | None:
    """Offset of the first match of `pattern` that is a REAL flag token: at a
    token start AND outside every quoted run.

    A flag name inside a quoted string is a piece of text, not a parameter -
    `-httpRequest "GET /reset-password HTTP/1.0"` configures a health check,
    it does not carry a RADIUS key. On a line whose
    quoting never closes this cannot be decided, so every match counts:
    fail-closed, the same direction `_usable_spans` fails.
    """
    for match in pattern.finditer(text):
        if not closed or match.start() in starts:
            return match.start()
    return None


def _with_note(head: str) -> str:
    """Appends `REDACTION_NOTE` to `head`, or returns the bare note when
    `head` carries nothing worth keeping. Only the TRAILING side is
    stripped, so a leading indent that is genuinely part of the original
    line's head survives - the cut already stopped exactly at the end of the
    kept content, so any trailing whitespace here is only the separator
    before whatever was cut away.
    """
    head = head.rstrip()
    return f"{head} {REDACTION_NOTE}" if head.strip() else REDACTION_NOTE


def redact_config_line(line: str) -> str:
    """Returns `line` with everything that could carry a credential replaced.

    A line outside all three classes named in this module's docstring comes
    back byte-identical: this is a filter on a closed set of known
    credential carriers, not a guess about content - and it is closed, not
    complete. See the module docstring for exactly what is and is not
    covered.
    """
    text = str(line)
    spans, closed = _token_spans(text)
    starts = frozenset(start for start, _ in spans)
    for pattern, keep, required_flag in _CREDENTIAL_LINE_RULES:
        if pattern.search(text) is None:
            continue
        if required_flag is not None and _flag_position(text, starts, closed, required_flag) is None:
            continue
        return _with_note(_token_head(text, spans, closed, keep))
    parameter_position = _flag_position(text, starts, closed, _CREDENTIAL_PARAMETER_FLAGS)
    if parameter_position is not None:
        return _with_note(text[: _safe_cut(spans, closed, parameter_position)])
    if _ENCRYPTED_FLAG.search(text) and _ENCRYPTMETHOD_FLAG.search(text):
        flag_position = _flag_position(text, starts, closed, _ANY_FLAG_TOKEN)
        if flag_position is None:
            return _with_note("")
        return _with_note(text[: _safe_cut(spans, closed, flag_position)])
    return text


def redact_config_lines(lines: list[str]) -> list[str]:
    """The same, per line, with the line COUNT and the order untouched."""
    return [redact_config_line(line) for line in lines]
