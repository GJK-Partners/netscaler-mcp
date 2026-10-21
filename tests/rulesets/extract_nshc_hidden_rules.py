"""Extract NSHC's hidden-rule catalog and SSL-grade letter order (PowerShell)
into the JSON fixture this directory vendors them as.

This script commits the extraction here, not only in a planning document,
so it can be re-run against the NSHC working copy and the result compared -
a hash anchor whose generator exists only inside a plan cannot be
reproduced reliably.

Reads THREE NSHC files:
- `backend/hiddenrules/NshcHiddenRules.ps1` -> the 29 hidden-rule entries
  (id, severity, requires, first why-sentence) and the five-status set NSHC's
  evaluator can emit.
- `backend/readonly/Invoke-NshcSslGrade.ps1` -> the `$order` literal that
  fixes the TLS letter vocabulary (`gradeLetters`). A later fix: the parity gate used to compare this
  product's `LETTERS` constant against a literal tuple typed in the test
  file itself, so a change on NSHC's side would never be seen. Vendoring it
  here, through the same extractor mechanism as the hidden-rule catalog,
  closes that.
- `backend/readonly/Invoke-NshcSecurityScorecard.ps1` -> the four
  `GJK-L1-HA-*` controls (id, title, severity, and the applicability a
  STANDALONE appliance lands on). This
  product's four HA dimensions claimed to be equal to NSHC in id,
  severity and word while naming those ids only in docstrings, so no
  test could measure the claim. Vendored into this SAME file rather than
  a fourth JSON, for the same reason `gradeLetters` is: one anchored
  file stays covered by every directory-wide gate.

Usage (from the repo root):

    ./.venv/Scripts/python.exe tests/rulesets/extract_nshc_hidden_rules.py \
        --nshc-root <path to the NSHC working copy> \
        --nshc-version 1.0.2 --read-at 2026-09-07

`--nshc-root` may be left off when the NSHC_ROOT environment variable is
set, or when a released NSHC copy is unpacked next to this checkout (see
`DEFAULT_NSHC_ROOT` below). It is deliberately NOT a path written into
this file: this script is committed precisely so another machine, or a
build runner, can re-run the identical extraction.

`--nshc-version` and `--read-at` are REQUIRED, with no defaults: they used
to be literals in `build_fixture()`
(`rulesetVersion "1.0.1"`, `rulesetDate "2026-09-06"`, `readAt "2026-09-06"`),
so a legitimate re-run against a later NSHC release would silently emit a
fixture still claiming it was read from NSHC 1.0.1 on 2026-09-06. Making them
required arguments means a regeneration cannot inherit a stale stamp by doing
nothing; `--read-at` is not derived from the clock either, so a given
invocation's output stays byte-reproducible.

Prints "<rule count> <high count> <medium count>" as its first line - the
tripwire this extraction relies on: if this is not "29 16 13", NSHC's catalog has
moved since 2026-09-06. STOP and report; do not adjust the numbers to fit.
Prints the extracted `gradeLetters` as its second line, for the same reason.
Writes nshc-hidden-rules.json next to itself, ASCII-encoded
(json.dumps(..., ensure_ascii=True)) so the fixture round-trips through git
and any encoding byte for byte while still decoding back to the exact
Dutch characters NSHC wrote.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_HIDDEN_RULES_RELATIVE = Path("backend/hiddenrules/NshcHiddenRules.ps1")
_SSL_GRADE_RELATIVE = Path("backend/readonly/Invoke-NshcSslGrade.ps1")
_SCORECARD_RELATIVE = Path("backend/readonly/Invoke-NshcSecurityScorecard.ps1")

# WHERE the NSHC working copy sits is the CALLER's business, never this
# file's. A module constant naming one contributor's
# drive letter describes that one machine and nothing about the product,
# and it makes the one thing this script exists for - re-running the
# IDENTICAL extraction on another machine or on a build runner - impossible
# without editing the script. The root comes from --nshc-root, falling back
# to the NSHC_ROOT environment variable, falling back to the DOCUMENTED
# default below: a sibling of the repository root, which is where a
# released NSHC copy is unpacked next to this checkout.
NSHC_ROOT_ENV = "NSHC_ROOT"
DEFAULT_NSHC_ROOT = Path(__file__).resolve().parents[2].parent / "nshc-vrijgegeven-v1.0.1"


def nshc_sources(nshc_root: Path) -> tuple[Path, Path, Path]:
    """The three NSHC files this extractor reads, under `nshc_root`."""
    return (
        nshc_root / _HIDDEN_RULES_RELATIVE,
        nshc_root / _SSL_GRADE_RELATIVE,
        nshc_root / _SCORECARD_RELATIVE,
    )


OUTPUT = Path(__file__).resolve().parent / "nshc-hidden-rules.json"

# A chain of two or more single-letter "X." groups back to back ("i.p.v.",
# "n.v.t.", "e.d.") is a Dutch abbreviation, not a sentence end - even though
# its last period is followed by a space, the one shape the naive
# `re.split(r"(?<=[.!?]) ", why)` splitter cannot tell apart from a real
# sentence break. MEASURED on the whole catalog (2026-09-06): only
# NSHC-HR-LB-001's whyItMatters carries one ("i.p.v."), and the naive
# splitter breaks there, producing the half sentence "... i.p.v.".
_ABBREVIATION_CHAIN = re.compile(r"(?:^|\s)(?:[A-Za-z]\.){2,}$")


def split_into_sentences(text: str) -> list[str]:
    """Sentence-split `text`, abbreviation-aware.

    Same idea as the test-side splitter - break after a `.`/`!`/`?` that is
    followed by a space - except a candidate break is swallowed (merged back
    into the sentence being built) when the text ending at that point ends
    in an abbreviation chain (see `_ABBREVIATION_CHAIN`). Returns at least
    one sentence for any non-empty input.
    """
    parts = re.split(r"(?<=[.!?]) ", text)
    sentences: list[str] = []
    buffer = ""
    for part in parts:
        buffer = f"{buffer} {part}" if buffer else part
        if _ABBREVIATION_CHAIN.search(buffer):
            continue
        sentences.append(buffer)
        buffer = ""
    if buffer:
        sentences.append(buffer)
    return sentences


def extract_rules(text: str) -> list[dict]:
    """The 29 hidden-rule entries of NshcHiddenRules.ps1, id-sorted.

    The catalog is a PowerShell array literal, not JSON, so this reads it as
    text rather than parsing PowerShell.
    """
    rules = []
    for block in text.split("\n        @{\n            id = '")[1:]:
        rule_id = block.split("'", 1)[0]
        severity = re.search(r"\n            severity = '(\w+)'", block).group(1)
        requires = re.search(r"\n            requires = @\((.*?)\)\n", block, re.S).group(1)
        why = re.search(r"\n            whyItMatters = '(.*?)'\n", block, re.S).group(1)
        why = why.replace("''", "'")
        rules.append(
            {
                "id": rule_id,
                "severity": severity,
                "requires": [r.strip().strip("'") for r in requires.split(",") if r.strip()],
                "whyFirstSentence": split_into_sentences(why)[0],
            }
        )
    return sorted(rules, key=lambda r: r["id"])


# The status literals Invoke-NshcHiddenRules can assign to `$base.status`
# (the one field this fixture's "statuses" list mirrors). Matches the
# `status = 'PASS'` initializer and every `$base.status = '...'` reassignment
# in the file - MEASURED 2026-09-06: 8 assignment sites, 5 distinct values,
# the same set the module docstring names ("Statusset: PASS | FINDING |
# NOT_ASSESSABLE | SKIPPED | ERROR").
_STATUS_ASSIGNMENT = re.compile(r"status\s*=\s*'([A-Z_]+)'")


def extract_statuses(text: str) -> list[str]:
    return sorted(set(_STATUS_ASSIGNMENT.findall(text)))


# The TLS letter vocabulary Get-NshcSslGrade can produce, read from the
# `$order` array literal in Invoke-NshcSslGrade.ps1 - the same list the cert
# gate uses to compare letters by strictness (`$order.IndexOf(...)`).
# MEASURED 2026-09-06: exactly one such assignment in the file, at line 381:
# `$order = @('A+', 'A', 'B', 'C', 'F', 'T')`.
_GRADE_ORDER = re.compile(r"\$order\s*=\s*@\(([^)]*)\)")


def extract_grade_letters(text: str) -> list[str]:
    matches = _GRADE_ORDER.findall(text)
    assert len(matches) == 1, (
        f"verwacht precies 1 '$order = @(...)' literal in {_SSL_GRADE_RELATIVE}, {len(matches)} gevonden"
    )
    letters = re.findall(r"'([^']*)'", matches[0])
    assert letters, f"geen letters gevonden in $order-literal: {matches[0]!r}"
    return letters


_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """No defaults, on purpose: a version or
    a read date this script assumes on its own is exactly how a legitimate
    regeneration against a later NSHC release ends up stamping a false
    provenance. The caller states, every run, which NSHC version and which
    date this extraction reads - not derived from the clock (that would make
    the output depend on WHEN it happens to run, breaking byte-
    reproducibility for a given invocation) and not defaulted (that would
    make a stale stamp the path of least resistance).
    """
    parser = argparse.ArgumentParser(
        description=(
            "Extract NSHC's hidden-rule catalog and SSL-grade letter order into tests/rulesets/nshc-hidden-rules.json."
        )
    )
    parser.add_argument(
        "--nshc-root",
        default=None,
        help=(
            "Path to the NSHC working copy to read. Falls back to the"
            f" {NSHC_ROOT_ENV} environment variable, and then to"
            f" {DEFAULT_NSHC_ROOT} - a released NSHC copy unpacked next to"
            " this checkout. Never a path baked into this file: the point"
            " of committing this extractor is that another machine can"
            " re-run the identical code."
        ),
    )
    parser.add_argument(
        "--nshc-version",
        required=True,
        help=(
            "NSHC product version this checkout is, e.g. 1.0.2. Stamped"
            " verbatim into rulesetVersion and into the source sentence. No"
            " default, so a run against a newer NSHC cannot silently keep"
            " the previous version's stamp."
        ),
    )
    parser.add_argument(
        "--read-at",
        required=True,
        help=(
            "ISO date (YYYY-MM-DD) this extraction happens. Stamped into"
            " both rulesetDate and readAt. No default and not read from the"
            " clock, so the output stays reproducible for a given"
            " invocation."
        ),
    )
    args = parser.parse_args(argv)
    if not _ISO_DATE.fullmatch(args.read_at):
        parser.error(f"--read-at must be an ISO date (YYYY-MM-DD), got {args.read_at!r}")
    chosen = args.nshc_root or os.environ.get(NSHC_ROOT_ENV) or DEFAULT_NSHC_ROOT
    args.nshc_root = Path(chosen).expanduser()
    if not args.nshc_root.is_dir():
        parser.error(
            f"NSHC working copy not found at {args.nshc_root}; pass --nshc-root"
            f" or set the {NSHC_ROOT_ENV} environment variable"
        )
    return args


# NSHC's four HA controls, READ from the scorecard rather
# than typed into a test. The parity row for these four asks for id,
# severity and word; without a vendored counterpart that gate can only
# compare this product against itself.
#
# Three separate reads, because they answer three separate questions:
#   _HA_META      - the id and title of each control;
#   _HA_BRANCH    - every verdict branch, for the severity and the
#                   naReason a STANDALONE appliance lands on;
#   _NA_SWITCH    - what Resolve-ControlVerdict turns that naReason into.
# The last one is read rather than assumed for the same reason the grade
# letters are: a mapping typed into this file could not notice NSHC
# changing it.
_HA_META = re.compile(r"(ha00\d)\s*=\s*@\{\s*id='([^']*)';\s*title='([^']*)'\s*\}")
# The REST OF THE LINE, not a brace-balanced body: `severity=` and `naReason=`
# always sit on the opening line of the assignment, while the `evidence=`
# below them contains PowerShell sub-expressions with their own braces - a
# `[^}]*` body stops at the first of those and finds nothing.
# The REST OF THE LINE, not a brace-balanced body: `severity=` and
# `naReason=` always sit on the OPENING line of the assignment, while the
# `evidence=` under them carries PowerShell sub-expressions with braces of
# their own - a body pattern that stops at the first closing brace finds
# nothing at all there.
_HA_BRANCH = re.compile(r"\$(ha00\d)\s*=\s*\[ordered\]@\{([^\r\n]*)")
_NA_SWITCH = re.compile(r"'(\w+)'\s*\{\s*return \[ordered\]@\{[^}]*Applicability='([^']*)'")


def extract_ha_controls(text: str) -> list[dict]:
    """The four GJK-L1-HA controls, as NSHC declares and resolves them."""
    meta = {key: (control_id, title) for key, control_id, title in _HA_META.findall(text)}
    assert len(meta) == 4, f"verwacht 4 haMeta-regels, {len(meta)} gevonden"
    applicability = dict(_NA_SWITCH.findall(text))
    assert applicability.get("scope") == "NotApplicable", applicability
    severities: dict[str, set[str]] = {}
    standalone: dict[str, str] = {}
    for key, body in _HA_BRANCH.findall(text):
        flat = " ".join(body.split())
        severity = re.search(r"severity='([^']*)'", flat)
        na_reason = re.search(r"naReason='([^']*)'", flat)
        if severity:
            severities.setdefault(key, set()).add(severity.group(1).lower())
        if na_reason and na_reason.group(1) == "scope":
            # The standalone branch is the ONLY one that reaches 'scope'
            # (measured on every branch of Get-NshcHaVerdict).
            standalone[key] = "scope"
    controls = []
    for key in sorted(meta):
        control_id, title = meta[key]
        found = severities.get(key, set())
        # One severity per control across EVERY branch - measured, and
        # asserted rather than assumed: if NSHC ever varies it, this stops
        # instead of silently picking one.
        assert len(found) == 1, f"{control_id}: {sorted(found)}"
        reason = standalone.get(key)
        controls.append(
            {
                "id": control_id,
                "title": title,
                "severity": found.pop(),
                "standaloneNaReason": reason,
                "standaloneApplicability": applicability[reason] if reason else None,
            }
        )
    return controls


def build_fixture(
    rules: list[dict],
    statuses: list[str],
    grade_letters: list[str],
    ha_controls: list[dict],
    *,
    nshc_version: str,
    read_at: str,
) -> dict:
    """Assemble the fixture. `nshc_version` and `read_at` are the two
    honestly-unavoidable literals (nothing in either source file states its
    own NSHC product version or today's date - the SSL-grade module's own
    header says as much: "Productversie: backend/capabilities.json
    (appVersion) - dit bestand draagt geen eigen versienummer"). Everything
    else derivable from the source paths - the file-path portion of
    `source` - is built from `_HIDDEN_RULES_RELATIVE`/`_SSL_GRADE_RELATIVE`
    themselves rather than typed again as a second literal, so it cannot
    drift from the paths this script actually reads.
    """
    source = (
        f"GJK NetScaler Healthcheck {nshc_version}"
        f" {_HIDDEN_RULES_RELATIVE.as_posix()} (rules, statuses)"
        f" + {_SSL_GRADE_RELATIVE.as_posix()} (gradeLetters)"
        f" + {_SCORECARD_RELATIVE.as_posix()} (haControls)"
    )
    return {
        "schemaVersion": "1.0",
        "rulesetName": "nshc-hidden-rules",
        "rulesetVersion": nshc_version,
        "rulesetDate": read_at,
        "source": source,
        "readAt": read_at,
        "notes": (
            "Generated readout of two PowerShell files, not a byte-for-byte"
            " vendor copy like the other files in this directory - see"
            " extract_nshc_hidden_rules.py in this same directory. rules and"
            " statuses come from backend/hiddenrules/NshcHiddenRules.ps1;"
            " gradeLetters comes from the $order literal in"
            " backend/readonly/Invoke-NshcSslGrade.ps1 (fix round 1,"
            " task-8-review.md finding I-1 - the parity gate used to compare"
            " this product's TLS-letter constant against a literal typed in"
            " the test file, never reading NSHC at all). haControls comes from"
            " $haMeta, the verdict branches of Get-NshcHaVerdict and the"
            " naReason switch of Resolve-ControlVerdict in"
            " backend/readonly/Invoke-NshcSecurityScorecard.ps1 (merge-review"
            " I-2: the four HA controls were named only in docstrings, so the"
            " parity claim -equal in id, severity and word- could not be measured"
            " against NSHC at all). Regenerate with"
            " './.venv/Scripts/python.exe"
            " tests/rulesets/extract_nshc_hidden_rules.py --nshc-version"
            " <version> --read-at <YYYY-MM-DD>' against the NSHC working"
            " copy and update the anchor in src/nsmcp/rulesets.py in the"
            " same commit - both arguments are required with no default"
            " (fix round 1, finding I-2), so a regeneration cannot silently"
            " keep stamping a stale version or date. Written with LF line"
            " endings only (no os.linesep) so the anchor holds regardless of"
            " which platform regenerates it - unlike the other files in this"
            " directory, this one is not a byte-for-byte copy of an NSHC"
            " file, so there is no CRLF original to preserve."
        ),
        "statuses": statuses,
        "gradeLetters": grade_letters,
        "haControls": ha_controls,
        "rules": rules,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    hidden_rules_source, ssl_grade_source, scorecard_source = nshc_sources(args.nshc_root)
    text = hidden_rules_source.read_text(encoding="utf-8-sig", errors="replace")
    grade_text = ssl_grade_source.read_text(encoding="utf-8-sig", errors="replace")
    scorecard_text = scorecard_source.read_text(encoding="utf-8-sig", errors="replace")
    rules = extract_rules(text)
    statuses = extract_statuses(text)
    grade_letters = extract_grade_letters(grade_text)
    ha_controls = extract_ha_controls(scorecard_text)
    high = sum(1 for r in rules if r["severity"] == "high")
    medium = sum(1 for r in rules if r["severity"] == "medium")
    print(f"{len(rules)} {high} {medium}")
    print(f"gradeLetters: {' '.join(grade_letters)}")
    # Third tripwire, same discipline as the two above: if this line stops
    # reading "GJK-L1-HA-001=high GJK-L1-HA-002=medium GJK-L1-HA-003=high GJK-L1-HA-004=medium",
    # NSHC's HA controls moved. STOP and report; do not adjust to fit.
    print("haControls: " + " ".join(f"{c['id']}={c['severity']}" for c in ha_controls))
    fixture = build_fixture(
        rules,
        statuses,
        grade_letters,
        ha_controls,
        nshc_version=args.nshc_version,
        read_at=args.read_at,
    )
    # write_bytes, not write_text: write_text's default newline handling
    # translates "\n" to os.linesep, which would make this file's bytes (and
    # therefore its SHA-256 anchor) depend on the platform that regenerates
    # it. Encode explicitly instead, LF only, on every platform.
    payload = (json.dumps(fixture, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    OUTPUT.write_bytes(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
