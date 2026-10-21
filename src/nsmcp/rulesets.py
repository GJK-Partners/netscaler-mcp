"""The versioned rule sets this product judges by - and their anchor.

Requirement 6 of the parity definition (design 1.3): the same versioned rule
set as the healthcheck, and that version stands in the answer. This module is
this product's side of that. The healthcheck's side sits vendored in
`tests/rulesets/`, with the SHA-256 anchors below, and
`tests/test_parity_nshc.py` compares the two.

WHY A PYTHON CONSTANT AND NOT A JSON FILE: a `.py` travels in every wheel
without a package-data line in `pyproject.toml` (which belongs to another
stream), and a constant cannot be edited on a customer machine without the
parity test noticing on the next run. The content is byte-for-byte the
`rules` object of `nshc-ssl-baseline.json` 2026.08; the test proves that
rather than the comment claiming it.

WHAT IS NOT HERE: the CVE baseline and the IP-reputation baseline. This
version judges CVEs from the knowledge package (`cve.py`) and does not judge
IP reputation at all. Both are vendored anyway, with their anchor, so a
version bump on either side is still caught by the parity test - a rule set
that silently moves while nobody reads it is exactly what requirement 6
exists to prevent.

WHY THERE IS A SHAPE GATE IN HERE AT ALL. A rule set is JSON ON DISK whose
strings go straight into answer text through `ruleset_line`, and the
healthcheck ships an override path for exactly that file ("Bij te werken
zonder rebuild via AppData-override", in the notes of
`nshc-ssl-baseline.json`). So on a customer machine a rule set field has the
same standing as a field out of a supplied export: it reaches the model
unless something stops it. The disclosure seam does not stop it - a rule set
name is not an entity name - so the stop is here, at the one seam where a
rule set field becomes answer text. Both `Ruleset` constants below
(`HIDDEN_RULES` joined `SSL_BASELINE`) are hand-written Python, so neither can
fail the gate today; the gate exists so that the first consumer to build one
from a file cannot be the hole.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nsmcp.export import shape_of


@dataclass(frozen=True)
class Ruleset:
    name: str
    version: str
    date: str
    rules: dict = field(default_factory=dict)


# SHA-256 of the vendored copies in tests/rulesets/, measured 2026-09-06
# against GJK NetScaler Healthcheck 1.0.1. Changing a vendored file without
# changing its anchor here fails the parity test - which is the point.
VENDORED_ANCHORS = {
    "nshc-ssl-baseline": "66a9b3786231e9757f6bb0c16be00c239fba1937148b14399be6c7a3ad1b72fd",
    "nshc-cve-baseline": "ff56f0a6c0113e48744eaba0c0a21f62db33e570714d63991377820ee3a97013",
    # Het vrije-tekst "source"-veld droeg de lab-
    # hostnaam - labdata in een datafile, geen
    # vendorregel (de vendor-provenance zelf, "Lab-bevestigd tegen live
    # NetScaler NS14.1 iprep.log", blijft ongewijzigd). Vervangen door
    # dezelfde alias als elders in de fixture (TERM-001); anker herrekend
    # over de nieuwe bytes. Dit is de ENIGE afwijking van de werkkopie van GJK
    # NetScaler Healthcheck 1.0.1: de pariteitstest vergelijkt dit bestand
    # daarom buiten het source-veld om, tot de werkkopie zelf de hostnaam
    # laat vallen en het bestand weer byte-gelijk gevendord kan worden.
    "nshc-iprep-baseline": "3f5ecdf5ab32de0eb991d48c555fb2b7f1947dad73a72b065eaf8cb5aed1a233",
    # Read out of NSHC's hidden-rule PowerShell catalog on 2026-09-06 (29
    # rules, 16 high, 13 medium - the extractor's own tripwire line), plus
    # the TLS-letter $order literal from Invoke-NshcSslGrade.ps1
    # (gradeLetters, 6 letters). Not a byte-for-byte
    # vendor copy like the three above (NSHC keeps this catalog in
    # PowerShell, not JSON); tests/rulesets/extract_nshc_hidden_rules.py
    # is the generator, committed so this re-runs the
    # IDENTICAL code against the NSHC working copy and compares. Anchor
    # updated when gradeLetters
    # was added and the provenance fields became required CLI arguments -
    # the rules/statuses content is byte-identical to the earlier
    # fixture, only the source/notes text and the new gradeLetters field
    # changed.
    "nshc-hidden-rules": "c72a58e023e8fb47eb4295de98d8961ed132e35b1dadc90a9de46c281f9119b4",
}

SSL_BASELINE = Ruleset(
    name="nshc-ssl-baseline",
    version="2026.08",
    date="2026-08-12",
    rules={
        "approvedTlsVersions": ["TLS1.2", "TLS1.3"],
        "deprecatedTlsVersions": ["SSLv2", "SSLv3", "TLS1.0", "TLS1.1"],
        "approvedCiphers": [
            "TLS1.3-AES256-GCM-SHA384",
            "TLS1.3-AES128-GCM-SHA256",
            "TLS1.3-CHACHA20-POLY1305-SHA256",
            "TLS1.2-ECDHE-RSA-AES256-GCM-SHA384",
            "TLS1.2-ECDHE-RSA-AES128-GCM-SHA256",
            "TLS1.2-ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS1.2-ECDHE-ECDSA-AES128-GCM-SHA256",
        ],
        "weakCipherPatterns": [
            "(?i)-CBC-",
            "(?i)3DES",
            "(?i)-DES-",
            "(?i)RC4",
            "(?i)-MD5",
            "(?i)-SHA$",
            "(?i)EXPORT",
            "(?i)NULL",
            "(?i)-ADH-",
            "(?i)anon",
        ],
        "approvedEccCurves": ["X25519", "P_256", "P_384", "P_521"],
        "forbiddenEccCurves": ["P_224"],
        "hstsMinAge": 31536000,
        "defaultCipherGroupNames": ["DEFAULT", "DEFAULT_BACKEND"],
        "weights": {"protocol": 30, "keyExchange": 30, "cipher": 40},
        "gradeThresholds": {"Aplus": 95, "A": 80, "B": 65, "C": 50, "Fbelow": 50},
        "certGate": {"expiredCapsTo": "T", "weakKeyCapsTo": "C", "minRsaBits": 2048},
    },
)

# The hidden-rules catalogue IS a ruleset too - it is
# vendored exactly like the three above (SHA-anchored in VENDORED_ANCHORS as
# "nshc-hidden-rules"), parity-gated by tests/test_parity_nshc.py, and the
# vendored file itself carries a version and a date. Before this it had no
# `Ruleset` object at all: `hidden_rules.py` never imported this module, so
# `beveiliging_verstopte_regels` printed no regelset line while
# `beveiliging_tls_baseline` (reading the SAME kind of vendored source) did -
# a direct Global Constraint breach ("de regelsetversie staat in elk
# antwoord dat uit een regelset volgt"). `rules` is deliberately empty: the
# catalogue's own content lives in `hidden_rules.CATALOG` (a list of `Rule`
# objects, not a `dict`), so this `Ruleset` carries only what `ruleset_line`
# actually prints - name, version, date - byte-identical to
# tests/rulesets/nshc-hidden-rules.json's own `rulesetName`/`rulesetVersion`/
# `rulesetDate` (measured 2026-09-06).
IPREP_BASELINE = Ruleset(
    name="nshc-iprep-baseline",
    version="2026.07.1",
    date="2026-07-24",
    rules={
        "patternsConfirmed": True,
        "staleAfterMinutes": 1440,
        "iprepExpressionPattern": r"(?i)(IPREP_IS_MALICIOUS|SRC\.IPREP|\.IPREP_|CLIENT\.IP\.SRC\.IPREP|ipreputation)",
    },
)

HIDDEN_RULES = Ruleset(
    name="nshc-hidden-rules",
    version="1.0.1",
    date="2026-09-06",
)


# The longest a rule set name, version or date may be before it is refused
# unread. Measured on the three vendored files: the longest of the nine
# fields is 19 characters (`nshc-iprep-baseline`), so this cap is wide enough
# for a name three times that and still far too narrow for a sentence.
RULESET_FIELD_MAX_LEN = 64

# The three shapes, one per field that `ruleset_line` prints. Deliberately
# THREE patterns and not `answer.repeatable_token`: that gate is the one for
# NITRO enumerations and states, and it starts at `[A-Z]`. A rule set name is
# lower case with hyphens, a version is digits and dots, and a date is an ISO
# date - none of the three would pass it, so reusing it would mean widening
# the gate that `impact`, `dienst` and `overzicht` share. Three narrow
# patterns here are tighter than one widened pattern there.
#
# Each pattern is a POSITIVE test on the shape, never a sanitization of what
# is dangerous, for the reason spelled out in `coverage._resource_key`.
_RULESET_FIELDS = (
    ("naam", re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"), "een regelsetnaam"),
    ("versie", re.compile(r"[0-9]+(?:\.[0-9A-Za-z]+){0,3}"), "een regelsetversie"),
    ("datum", re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}"), "een ISO-datum"),
)


def _ruleset_field(value, pattern: re.Pattern[str], shape_name: str) -> tuple[str | None, str]:
    """The text when this rule set field may be REPEATED in an answer, and
    what it is INSTEAD when it may not.

    Same idiom, on purpose, as `coverage._resource_key` and
    `coverage._binding_file_name`: one gate, and the caller picks the value
    when it passed and the SHAPE when it did not. `shape_of` alone would not
    do - it calls any text "leeg of alleen witruimte", which a hostile value
    is precisely not - so a value that IS text but has the wrong shape gets
    the "heeft niet de vorm van ..." wording instead, exactly as
    `coverage._resource_key` does one layer over.

    The refusal depends on nothing but the value's own shape, so it observes
    nothing about the machine this runs on.
    """
    if not isinstance(value, str) or not value.strip():
        return None, f"is {shape_of(value)}"
    text = value.strip()
    if len(text) > RULESET_FIELD_MAX_LEN or pattern.fullmatch(text) is None:
        return None, f"heeft niet de vorm van {shape_name}"
    return text, ""


def ruleset_line(ruleset: Ruleset) -> str:
    """The sentence that puts the rule set version IN the answer.

    Requirement 6 is not "the version is known somewhere", it is "the version
    stands in the answer". One formatter, so every verdict that follows from a
    rule set says it the same way and a test can pin one sentence instead of
    five spellings.

    Every one of the three fields passes the shape gate BEFORE any of them is
    printed. When all three pass, the sentence is the established one. When
    one does not, the sentence says NIET VASTGESTELD and the refused field is
    named by its SHAPE - it does not vanish, and it does not take the usable
    fields with it, so an operator can still see which field broke. There is
    no branch in which a field that failed the gate is echoed, and no default
    that lands on a version this product did not read: an absent date is a
    read gap, not a dash.
    """
    gated = [
        (label, _ruleset_field(value, pattern, shape_name))
        # `strict=True` so that a fourth entry in `_RULESET_FIELDS` cannot
        # silently be dropped here: an ungated field is exactly the hole this
        # function exists to close, and zip's default would close it quietly.
        for (label, pattern, shape_name), value in zip(
            _RULESET_FIELDS, (ruleset.name, ruleset.version, ruleset.date), strict=True
        )
    ]
    if all(text is not None for _, (text, _) in gated):
        name, version, date = (text for _, (text, _) in gated)
        return f"Regelset {name} {version} ({date})."
    parts = "; ".join(f"{label} {text if text is not None else shape}" for label, (text, shape) in gated)
    return f"Regelset NIET VASTGESTELD: {parts}."
