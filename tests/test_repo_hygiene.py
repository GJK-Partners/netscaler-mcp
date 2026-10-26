"""A reference a cloner cannot follow is a dead end.

Measured: 14 tracked files pointed at a workflow planning-notes folder that
is gitignored and never ships to a clone, another 15 lines pointed at an
archive-notes folder, and 3 more at a design-spec folder - all three leave
the public tree entirely. The code said "see the report" and the report
did not exist for anyone who cloned. That undermines exactly the evidence
culture this product sells.

The same holds for a reviewer's name and a contributor's local working
path: neither tells a future contributor anything once the actual finding
is written out in the surrounding line, and a personal path only ever
describes one machine, never the product.

Widened after a first sweep still let five of these slip through: a
folder needle that required a trailing slash missed a line naming the
folder without one, a mixed-case reviewer-name needle missed an
all-lowercase spelling, and a citation to a dead per-round write-up file
was not covered at all when the reviewer's name did not appear next to
it. The folder needles below now match with or without a trailing
slash, the reviewer-name check is case-insensitive, and a dedicated
check covers that citation pattern on its own.

This guard also scans its OWN file (tests/, not only src/). A name that
would identify the development environment - a local directory, a folder
that never ships, a tool or model name, the working name - is therefore not
in this file at all: it comes from the needle list outside the tracked tree
(tests/private_needles.py), and a guard without its needles skips with that
reason. The generic patterns that remain (a ticket word, a review word) are
assembled from parts, so this file does not match itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from private_needles import needles_or_skip, private_needles

ROOT = Path(__file__).resolve().parent.parent
SOURCES = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "tests").rglob("*.py"))


def _hits(needle: str, *, ignore_case: bool = False) -> list[str]:
    found = []
    target = needle.lower() if ignore_case else needle
    for path in SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            haystack = line.lower() if ignore_case else line
            if target in haystack:
                found.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    return found


def test_no_source_or_test_points_at_a_path_that_does_not_ship():
    # The folders come from the needle list outside the tree (see the module
    # docstring). No trailing slash required: a line naming the folder
    # without one is just as dead a reference.
    for needle in needles_or_skip("map"):
        assert _hits(needle) == [], needle


def test_no_tool_or_model_name_survives_in_the_code():
    # The name of a tool or a model used while building says nothing to a
    # contributor; what was FOUND does. Case-insensitive: an all-lowercase
    # spelling defeated an exact-case check once.
    for name in needles_or_skip("naam"):
        assert _hits(name, ignore_case=True) == [], name


def test_no_review_round_citation_with_a_commit_id_survives_in_the_code():
    """A citation shape combining the Dutch word for a review round with a
    short commit hash (optionally a hash..hash range) is the same dead end
    as the reviewer's name above, just carrying a hash instead of a name: a
    future contributor cannot look up a commit message this repository's
    own history no longer has meaning for outside it. A later sweep
    measured 16 of these still standing after the reviewer-name sweep above
    widened - the name was gone, the round-plus-hash citation next to it was
    not. Built split, same self-blindness reason as every guard above: the
    round word and the digit pattern must not sit contiguous in this file's
    own source line either.
    """
    import re

    round_word = "keu" + "ring"
    pattern = re.compile(rf"\b{round_word}\b.*[0-9a-f]{{7}}")
    offenders = []
    for path in SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == []


def test_no_loose_internal_task_number_survives_in_the_code():
    """The ticket-prefix guard further down catches an internal task number
    used as a TEST NAME prefix. That same later sweep measured the same number
    surviving in well over a hundred places as a loose citation inside an
    ordinary comment or docstring instead - the name-prefix form was gone,
    the free-floating pointer to the same ticket was not. Built split, same
    self-blindness reason as every guard above.
    """
    import re

    ticket_word = "TASK"
    pattern = re.compile(rf"\b{ticket_word} ?\d+")
    offenders = []
    for path in SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == []


def test_no_dead_report_citation_survives_in_the_code():
    # Same dead end as the folder references above, just shaped as a
    # filename instead of a path: a per-round write-up lives under the
    # gitignored planning-notes folder and never ships to a clone, whether
    # or not the reviewer's name happens to sit next to it. Built split,
    # same reason as above.
    report_citation = "-report" + ".md"
    assert _hits(report_citation) == [], report_citation


def _tracked_text_files() -> list[tuple[str, str]]:
    """(relative path, text) for every tracked file that reads as UTF-8
    text; a file that does not is binary and skipped."""
    import subprocess

    listing = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    files = []
    for rel in listing.decode("utf-8").split("\0"):
        if not rel:
            continue
        try:
            files.append((rel, (ROOT / rel).read_text(encoding="utf-8")))
        except UnicodeDecodeError:
            continue
    return files


def _local_path_offenders(files: list[tuple[str, str]], tails: tuple[str, ...]) -> list[str]:
    """Every line of `files` - (relative path, text) pairs - that names a
    contributor's local working path: C:\\<one contributor's own dir>, in
    any capitalisation, with one to four separators between the drive and
    the directory - a backslash, a forward slash, or a backslash escaped
    once (JSON, a Python string) or twice. Measured before: a plain
    case-sensitive substring with exactly one separator, so a lower-case or
    a JSON-escaped spelling in a `.json` or `.md` file slipped through.
    The directory names (`tails`) come from the caller - for the real tree
    from the needle list outside it."""
    import re

    if not tails:
        return []
    drive = "C" + ":"
    pattern = re.compile(
        re.escape(drive) + r"[\\/]{1,4}(?:" + "|".join(re.escape(tail) for tail in tails) + ")",
        re.IGNORECASE,
    )
    return [
        f"{rel}:{number}: {line.strip()}"
        for rel, text in files
        for number, line in enumerate(text.splitlines(), 1)
        if pattern.search(line)
    ]


def test_no_local_working_path_survives_in_the_code():
    # A path on one contributor's own machine describes that machine, never
    # the product. The path needles run over EVERY tracked text file, not
    # only `*.py`: measured, a fixture's README named the local path of the
    # export it was copied from, and a scan of Python files alone could not
    # see it. The directory names come from the needle list outside the tree.
    tracked = _tracked_text_files()
    assert len(tracked) > 100, len(tracked)
    assert _local_path_offenders(tracked, needles_or_skip("pad")) == []


def test_no_doubled_backslash_user_path_survives_in_the_code():
    # Doubled backslashes in actual paths (JSON-escaped paths in code), not
    # in raw strings, docstrings or simulated OS output. The one directory
    # name in this tracked pattern is the generic `Users`; the names of the
    # maintainers' own directories join it from the needle list, when present.
    import re

    tails = ("Users", *private_needles("pad"))
    double_backslash_pattern = re.compile(r"C:\\\\(?:" + "|".join(re.escape(tail) for tail in tails) + ")")
    offenders = []
    for path in SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # Skip docstrings and raw string literals
            if (
                '"""' in line
                or "'''" in line
                or 'r"' in line
                or "r'" in line
                or "# `%SystemRoot%" in line
                or "# This is a test file" in line
                or "At C:\\\\" in line
            ):
                continue
            if double_backslash_pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == [], offenders


_ASCII_TREES = ("src/", "scripts/", "tests/")


def _non_ascii_offenders(root: Path, rel_paths: list[str]) -> list[str]:
    """Every line in `rel_paths` that carries a byte outside ASCII, read as
    bytes: a file in another encoding cannot hide its characters from a
    UTF-8 reading this way."""
    offenders = []
    for rel in rel_paths:
        for number, line in enumerate((root / rel).read_bytes().splitlines(), 1):
            if any(byte > 0x7F for byte in line):
                offenders.append(f"{rel}:{number}: {line.decode('utf-8', 'replace').strip()}")
    return offenders


def test_code_tests_and_scripts_are_ascii():
    """CONTRIBUTING's rule for code, tests and scripts: Windows PowerShell
    5.1 reads a script without a byte order mark in the ANSI code page, so
    a non-ASCII character there changes meaning on a host. Measured before
    this test existed: three section signs in a module docstring, an
    accented letter in scripts/README, and accented letters in comments,
    docstrings and test data of eight test files - the test data now
    written as escapes (the same string at run time, and a digit from
    another script is visible as what it is). No exception is needed. The
    Dutch customer documents under docs/klant/ may carry accents; they are
    not in these three trees."""
    import subprocess

    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", *_ASCII_TREES], cwd=ROOT, capture_output=True, check=True
    ).stdout
    tracked = [rel for rel in listing.decode("utf-8").split("\0") if rel]
    assert len(tracked) > 100, len(tracked)
    assert _non_ascii_offenders(ROOT, tracked) == []


def test_the_ascii_guard_catches_a_character_in_any_encoding(tmp_path):
    (tmp_path / "a.py").write_text("x = 1  # v\u00f3\u00f3r\n", encoding="utf-8")
    (tmp_path / "b.ps1").write_bytes("# \u00e9\n".encode("cp1252"))
    (tmp_path / "c.md").write_text("gewoon ASCII\n", encoding="utf-8")
    offenders = _non_ascii_offenders(tmp_path, ["a.py", "b.ps1", "c.md"])
    assert [offender.split(":", 2)[:2] for offender in offenders] == [["a.py", "1"], ["b.ps1", "1"]]


def _public_security_contact() -> str:
    """The address SECURITY.md publishes for reports: a deliberate
    publication, read from that file rather than typed here."""
    import re

    match = re.search(r"\*\*([^*\s@]+@[^*\s]+)\*\*", (ROOT / "SECURITY.md").read_text(encoding="utf-8"))
    assert match, "SECURITY.md noemt geen meldadres"
    return match.group(1).lower()


def _local_identity_offenders(files: list[tuple[str, str]], values: list[str], published: list[str]) -> list[str]:
    """`path:line` for every line that carries one of `values`, in any case,
    once the `published` addresses are taken out of it. Only the place is
    reported, never the value: the value is what must not travel."""
    needles = [value.lower() for value in values if len(value) >= 4]
    offenders = []
    for rel, text in files:
        for number, line in enumerate(text.splitlines(), 1):
            lowered = line.lower()
            for address in published:
                lowered = lowered.replace(address, "")
            if any(needle in lowered for needle in needles):
                offenders.append(f"{rel}:{number}")
    return offenders


def test_no_tracked_file_carries_the_name_of_this_machine_or_its_account():
    """Measured by a publication scan: a test used the real machine name
    and account name of a development machine as a test value. No literal
    can guard that without being the leak itself, so this reads the names
    of the machine the suite runs on (COMPUTERNAME, USERNAME) and holds
    every tracked text file to not carrying them, in any case. A name
    shorter than 4 characters is skipped (too many ordinary words contain
    it); on a machine whose account name is an ordinary word that still
    occurs in the tree, this test says so - rename the account in the
    fixture, not the check. One exception: the report address SECURITY.md
    publishes on purpose, which may contain the maintainer's name."""
    import os

    values = [os.environ.get("COMPUTERNAME", ""), os.environ.get("USERNAME", "")]
    if not any(len(value) >= 4 for value in values):
        pytest.skip("geen machine- of accountnaam van 4 tekens of meer in de omgeving")
    offenders = _local_identity_offenders(_tracked_text_files(), values, [_public_security_contact()])
    assert offenders == [], f"de machine- of accountnaam van deze machine staat in: {offenders}"


def test_the_local_identity_guard_names_the_place_and_never_the_value():
    files = [
        ("a.md", "gemeten op WERKPLEK-99\\Beheer\n"),
        ("b.md", "meld het aan meldpunt.beheer@voorbeeld.invalid\n"),
        ("c.md", "niets bijzonders\n"),
    ]
    published = ["meldpunt.beheer@voorbeeld.invalid"]
    offenders = _local_identity_offenders(files, ["werkplek-99", "beheer", "abc"], published)
    assert offenders == ["a.md:1"]
    assert not any("werkplek" in offender.lower() or "beheer" in offender.lower() for offender in offenders)
    # A name shorter than four characters is no needle: "abc" would match anywhere.
    assert _local_identity_offenders([("d.md", "abc\n")], ["abc"], []) == []


def test_no_test_name_carries_an_internal_task_or_review_prefix():
    """A prefix that names an internal ticket (a task number plus a letter) points at a ticket system a visitor cannot
    look up. The TAIL of these names is already excellent; only the
    prefix goes.

    A prefix that names a tool comes from the needle list outside the
    tree (see the module docstring).
    """
    import re

    prefixes = ["TASK", "FINDING", *(re.escape(name.upper()) for name in private_needles("naam"))]
    pattern = re.compile(rf"^def (test_({'|'.join(prefixes)})[0-9A-Z]*_)")
    offenders = []
    for path in sorted((ROOT / "tests").rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = pattern.match(line)
            if match:
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {match.group(1)}")
    assert offenders == []


def test_the_public_tree_carries_no_internal_build_material():
    """This step removes the research and archaeology material; the plans and the
    design stayed in the tree afterward, until a later step removed them too
    (design par. 2.9, decision 6-9). Codepoort 1
    point 6 has two halves for exactly this reason: G2 measures the first
    half here, G4 the second. This test only asserts those two removals -
    the guard for the plans-and-specs subtree lives elsewhere in this file,
    once its own removal made asserting its absence safe to add."""
    for directory in needles_or_skip("map"):
        if directory.startswith("docs/"):
            assert not (ROOT / directory).exists(), directory


def test_no_tracked_file_points_at_the_removed_plans_specs_or_roadmap_tree():
    """The release removes the plans-and-specs subtree and the roadmap subtree
    (test_the_public_tree_carries_no_internal_build_material above explains
    why they stayed in the tree until now) from the public tree entirely.
    After that removal, no tracked file may still point at either one, or a
    clone follows a path that no longer exists - and no tracked file may
    still name the build tooling itself either, the same reason a reviewer's
    name above says nothing to a future contributor.

    Scoped to `git ls-files`, not the `SOURCES` list above (src/ and tests/
    only): a stray reference living in docs/ or a fixture README would slip
    past a scan limited to source and test files, exactly the blind spot
    the module docstring's widening story already describes for other
    needles. The folders and the tool names come from the needle list
    outside the tree (see the module docstring); a tool name is matched as
    a whole word, so it cannot fire inside an unrelated longer word.
    """
    import re
    import subprocess

    folders = needles_or_skip("map")
    names = private_needles("naam")
    patterns = [re.compile(re.escape(folder.lower())) for folder in folders]
    patterns += [re.compile(rf"(?<![a-z0-9]){re.escape(name.lower())}(?![a-z0-9])") for name in names]

    listing = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    tracked = [line for line in listing.splitlines() if line]

    offenders = []
    for rel_path in tracked:
        try:
            text = (ROOT / rel_path).read_text(encoding="utf-8").lower()
        except UnicodeDecodeError:
            continue
        for pattern in patterns:
            if pattern.search(text):
                offenders.append(f"{rel_path}: {pattern.pattern}")
    assert offenders == []


def test_no_tracked_file_name_carries_the_working_name():
    """The name-neutrality guard in tests/test_product_surface.py watches the
    CONTENT of src/ and tests/. A file NAME is just as visible in a public
    repository. The search term is assembled here rather than typed, so this
    file cannot make itself falsely green.

    Two plan file names in the plans and specs directory originally carried
    the working name; a later cleanup renamed them. The files that originally
    included the working name in their paths were renamed to remove it:
    2026-09-02-demo-minimum (with working name suffix) became demo-minimum
    only, and 2026-09-02-hoofdstukken-handelen-en-kennis (with working name
    prefix) was removed from that prefix. No file name in the tracked tree
    contains the working name substring anymore.
    """
    import subprocess

    listing = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    offenders = [
        line for line in listing.splitlines() for term in needles_or_skip("werknaam") if term.lower() in line.lower()
    ]
    assert offenders == []


def test_no_working_name_survives_in_the_customer_facing_docs():
    """The working name is not a G7 (brand clearance) problem for `src/`
    and `tests/` alone (see test_name_neutrality_no_product_name_in_code
    in tests/test_product_surface.py) - it is exactly as unfinished a name in
    the two documents a customer actually reads. A later review measured
    it standing six times across docs/klant/HANDLEIDING.md and
    docs/klant/BEVEILIGING-EN-DATASTROMEN.md, right next to the neutral
    wording ("dit product" in Dutch, "netscaler-mcp" in README) those same
    documents already use everywhere else.

    This guard stays scoped to those two documents and README, not all of
    docs/: the internal plans-and-specs and roadmap material that once lived
    elsewhere under docs/ was never customer-facing, and this same
    workstream's own later task removes it from the tree entirely - a guard
    over all of docs/ would fail a gate that is not this test's to close.
    The working name comes from the needle list outside the tree.
    """
    names = [name.lower() for name in needles_or_skip("werknaam")]
    targets = sorted((ROOT / "docs" / "klant").rglob("*.md")) + [ROOT / "README.md"]
    offenders = []
    for path in targets:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(name in line.lower() for name in names):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == []


def test_no_working_name_survives_in_any_file_of_the_shipped_tree():
    """The content guards above read `*.py` under src/ and tests/
    (test_name_neutrality_no_product_name_in_code) and the customer
    documents under docs/klant/ plus README. A fixture's own read-me, a
    PowerShell script or a developer document under docs/ fell outside all
    of them - measured: a fixture read-me named the working name in its
    opening sentence. This guard reads EVERY file under src/, tests/
    (fixtures included), scripts/ and docs/, plus the documents at the
    root, whatever the extension. Case-insensitive and on the bare
    substring, so a compound that merely contains the name is caught too.
    The working name comes from the needle list outside the tree."""
    names = [name.lower() for name in needles_or_skip("werknaam")]
    files = [
        path
        for folder in ("src", "tests", "scripts", "docs")
        for path in sorted((ROOT / folder).rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    ] + sorted(ROOT.glob("*.md"))
    offenders = []
    for path in files:
        text = path.read_bytes().decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), 1):
            if any(name in line.lower() for name in names):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []


def _branch_name_offenders(listing: str, term: str, exact_exception: str) -> list[str]:
    """Every `git branch -r` line that carries `term`, except the ONE ref
    that matches `exact_exception` byte for byte after stripping. An EXACT
    match, not a substring check: a first version compared with `in`, so a
    suffixed variant of the excepted branch (say, the same name with `-v2`
    appended) matched the substring test and slipped through uncaught -
    measured directly: that variant passed, while an unrelated branch
    carrying the working name still failed. `line.strip() != exact_exception`
    closes that gap; a name that only EXTENDS the excepted one is no longer
    read as "the same branch"."""
    return [line.strip() for line in listing.splitlines() if term in line.lower() and line.strip() != exact_exception]


def test_no_remote_branch_name_carries_the_working_name():
    """The name-neutrality guard (tests/test_product_surface.py) watches file
    CONTENT; test_no_tracked_file_name_carries_the_working_name above watches
    file NAMES; test_no_working_name_survives_in_the_customer_facing_docs
    watches the customer-facing docs. A branch name is visible to anyone who
    lists the remotes and is covered by none of those three - this closes
    that fourth axis.

    Measured: one remote branch is already fully merged into the release
    branch and carries the working name; its removal is its own
    branch-cleanup step, tracked separately, so it is named here as a single
    deliberate, EXACT exception (see `_branch_name_offenders`) rather than
    silently widening this guard's blind spot - any OTHER branch carrying
    the name, including one that only extends this one's name, still fails
    this test (proven in
    test_the_branch_name_guard_still_catches_a_suffixed_variant_of_the_exception
    below, against a synthetic listing rather than a real ref). The working
    name comes from the needle list outside the tree.

    On a shallow checkout (a CI runner with the default fetch-depth) `git
    branch -r` sees at most the checked-out ref, not the full remote list
    this guard means to cover - it still passes there, just proves little;
    it bites on a full local clone.
    """
    import subprocess

    listing = subprocess.run(["git", "branch", "-r"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for term in needles_or_skip("werknaam"):
        pending_cleanup = "origin/feat/" + term.lower() + "-2-0-demo-minimum"
        assert _branch_name_offenders(listing, term.lower(), pending_cleanup) == []


def test_the_branch_name_guard_still_catches_a_suffixed_variant_of_the_exception():
    """Mutation proof for the exact-match repair above, against a SYNTHETIC
    listing so this test never has to create or remove a real ref. A branch
    whose name only extends the excepted one (`-v2` appended) is not the
    excepted branch and must still fail; an unrelated branch carrying the
    working name must fail regardless. The excepted branch itself, and a
    branch without the working name at all, must both pass. A synthetic
    name stands in for the working name."""
    term = "werkmerk"
    pending_cleanup = "origin/feat/" + term + "-2-0-demo-minimum"
    listing = "\n".join(
        [
            "  " + pending_cleanup,
            "  origin/feat/" + term + "-2-0-demo-minimum-v2",
            "  origin/ws9/" + term + "-probe",
            "  origin/master",
        ]
    )
    offenders = _branch_name_offenders(listing, term, pending_cleanup)
    assert offenders == [
        "origin/feat/" + term + "-2-0-demo-minimum-v2",
        "origin/ws9/" + term + "-probe",
    ]


BINDING_TEST_NAMES = (
    # design 3.6 unit 1
    "test_the_powershell_starter_uses_the_absolute_system_path",
    "test_a_missing_powershell_fails_closed",
    "test_both_call_sites_use_the_same_starter_and_the_same_encoding",
    "test_the_timeout_label_names_the_same_absolute_path",
    # design 3.6 unit 2
    "test_a_forged_object_file_is_refused_against_the_manifest_hash",
    "test_a_source_without_a_payload_hash_is_a_read_gap",
    # design 3.6 unit 3 and 4
    "test_an_object_file_above_the_byte_cap_becomes_a_read_gap",
    "test_a_free_text_field_above_the_cap_is_truncated_and_says_so",
    "test_a_capped_read_never_produces_a_verdict",
    "test_a_deeply_nested_object_file_becomes_a_read_gap_with_a_named_reason",
    "test_a_deeply_nested_knowledge_package_is_refused_with_a_reason",
    # design 3.6 unit 5
    "test_a_code_is_burned_after_five_failed_attempts",
    "test_five_wrong_guesses_burn_the_pending_proposal_not_only_a_matching_code",
    "test_the_burn_notice_reaches_the_channel_and_carries_no_code",
    # design 3.6 unit 6
    "test_every_write_action_writes_one_structured_stderr_line",
    "test_the_action_log_never_carries_the_code",
    "test_the_action_log_marks_the_client_name_as_self_declared",
    # design 3.6 unit 7
    "test_the_server_runs_on_stdio_and_the_spy_records_the_argument",
    # design 3.6 unit 8
    "test_a_credential_bearing_config_line_never_reaches_an_answer",
    # design 3.6 unit 9
    "test_a_knowledge_package_without_a_cve_key_is_refused",
    "test_the_scrub_masks_targets_taken_from_the_handelen_section",
    "test_a_tool_without_its_configuration_is_not_registered",
    "test_an_empty_chapter_list_is_a_startup_error",
    "test_the_window_presenter_declares_its_ctypes_signature",
    "test_a_long_argument_value_is_capped_in_the_window",
    "test_running_the_module_directly_exits_with_the_run_code",
    # design par. 2.7, item 2 - the evidence gate G1 asks for
    "test_the_window_text_names_the_screen_sharing_risk",
)


def test_the_local_path_guard_catches_every_spelling_in_a_file_that_is_not_python(tmp_path):
    """The guard's own scanner (`_local_path_offenders`), on a JSON file: a
    local working path written plainly, JSON-escaped (doubled backslashes)
    and with forward slashes, in other capitalisations, is caught line by
    line; a neutral path on the same drive is not. Measured before: the
    scan over every tracked file compared case-sensitively with exactly one
    separator, and only `*.py` was searched for doubled backslashes - so
    every line below slipped through in a `.json` or `.md` file. Built
    split, same reason as the guard itself."""
    drive = "c" + ":"
    plain = drive + "\\" + "werkmap-a" + "\\nsmcp\\export"
    escaped = drive.upper() + "\\\\" + "WERKMAP-A" + "\\\\nsmcp\\\\export"
    forward = drive + "/" + "werkmap-b" + "/werk"
    neutral = drive.upper() + "\\\\" + "Product" + "\\\\netscaler-mcp\\\\export"
    bestand = tmp_path / "voorbeeld.json"
    bestand.write_text(
        "\n".join(
            (
                "{",
                f'  "exportmap": "{escaped}",',
                f'  "notitie": "{plain}",',
                f'  "werk": "{forward}",',
                f'  "neutraal": "{neutral}"',
                "}",
            )
        ),
        encoding="utf-8",
    )
    offenders = _local_path_offenders(
        [("voorbeeld.json", bestand.read_text(encoding="utf-8"))], ("Werkmap-A", "Werkmap-B")
    )
    assert [offender.split(":", 2)[1] for offender in offenders] == ["2", "3", "4"], offenders


def test_hygiene_guard_catches_doubled_backslash_in_temp_file(tmp_path):
    """RED test: verify the guard actually catches doubled backslashes.
    Creates a temp file with a C:\\ pattern to prove the regex works."""
    temp_test_file = tmp_path / "test_temp_hygiene.py"
    temp_test_file.write_text("# This is a test file with a path: C:\\\\Users\\\\test", encoding="utf-8")

    import re

    pattern = re.compile(r"C:[/\\]")
    content = temp_test_file.read_text(encoding="utf-8")

    # This should find the match
    matches = list(pattern.finditer(content))
    assert len(matches) > 0, "Pattern should match C:\\ in the file"


def _workflow_label_pattern():
    """The same group of needles this label-cleanup sweep was measured
    against - built split, same self-blindness reason as every guard above:
    the words below must not sit contiguous in this file's own source, or
    the guard would trip on itself. Deliberately narrower than that sweep's
    OWN measurement command: that command's finding-code alternation
    (`[ABCHIM]-?[0-9]{1,2}`) also matches a hex SSH fingerprint octet and a
    fixture slug like `c1-cipher-source` or `a14-lab` - real, unrelated
    content, not a workflow label - so it is not part of this permanent
    guard. Everything below it, by contrast, had zero legitimate hits
    anywhere in the swept tree.

    Widened by the later hygiene fix-round (see `_finding_label_pattern()`'s
    own docstring for the sibling widening): `task N`/`taak N` required a
    literal space, so an identifier-shaped ticket prefix glued straight onto
    a number, underscore or not, went unseen - measured standing in nine
    test names this same fix-round renamed. That first attempt at a fix
    (making the separator optional, `[_ ]?`) still used `\b` on the outside,
    and `\b` is not a boundary between two word characters - an underscore
    and the letters around it both count as one - so the ticket prefix
    embedded inside a longer identifier, on either side of the digits,
    still slipped through untouched;
    a re-review measured the claim false against exactly the two test
    names above and five ticket-prefixed module constants this same
    fix-round left in place (62 call sites total, in `tests/test_cve.py`
    and `tests/test_disclosure.py`). Replaced
    with lookarounds that check the SURROUNDING CHARACTER instead of a
    word-boundary: not preceded by a letter, not followed by one - an
    underscore, a digit, the start/end of the line, or a space all still
    count as "outside", but another letter does not. The five constants
    were renamed to their behaviour instead of narrowing this guard to fit
    around them.
    """
    import re

    task_en = "task"
    task_nl = "taak"
    ws_word = "ws"
    review_round = "review" + "ronde"
    fix_round = "fix" + "ronde"
    progress_file = "-progress" + ".md"
    brief_file = "-brief" + ".md"
    batch_word = "batch"

    return re.compile(
        rf"(?<![A-Za-z]){task_en}[_ ]?[0-9]+(?![A-Za-z])"
        rf"|(?<![A-Za-z]){task_nl}[_ ]?[0-9]+(?![A-Za-z])"
        rf"|{re.escape(progress_file)}"
        rf"|{re.escape(brief_file)}"
        rf"|\b{ws_word}(2a|2b|3a|3b|1|2|3|4)\b"
        rf"|\b{review_round}\b"
        rf"|\b{fix_round}\b"
        rf"|\b{batch_word} [ab]\b",
        re.IGNORECASE,
    )


def test_no_workflow_or_task_label_survives_in_the_public_tree():
    """Measured before this sweep (git grep, the same pattern below, over
    `src tests scripts docs README.md CHANGELOG.md CONTRIBUTING.md
    SECURITY.md`): 753 hits naming an internal workstream, a numbered
    build task, a numbered review or fix round, or a working-file name for
    one of those - meaningless to a reader outside the team that wrote
    them, none of it product behaviour. RED on this test's own
    introduction before the sweep; GREEN after every hit was rewritten to
    the actual content/reason it stood for, or the sentence removed where
    no content survived the label (never a new fact invented to replace
    one).

    Two exceptions, both deliberate:

    - This test file itself: every needle above must be assembled from
      parts to describe itself, so a plain substring scan of its own source
      would trip on the needles it defines. The same reason every other
      Built-split guard above excepts itself.
    - The two historical ledger files below (see the `LEESMIJ.md` in the
      same directory, itself NOT excepted and scanned like any other
      tracked file): GENUINE, pseudonymised evidence from a real lab
      upgrade run, not prose this sweep authored. One row's
      `snapshotverwijzing` field carries a hypervisor snapshot label an
      operator typed in AT THE TIME, during that real run - editing it
      would not remove a meaningless internal reference, it would falsify
      what the historical record actually says. `test_runner_ledger_evidence.py`
      already states the repo's own principle for this directory:
      "Historical evidence is never rewritten (LEESMIJ.md)". No other
      exception was needed: CHANGELOG.md already carried zero hits of this
      pattern, so it needs none either.
    """
    import subprocess

    pattern = _workflow_label_pattern()
    self_path = "tests/test_repo_hygiene.py"
    # Exactly the two historical evidence files, not the whole directory -
    # a directory-prefix exception would also silently cover LEESMIJ.md (it
    # has zero hits today, see above, so nothing hides there right now) and
    # any FUTURE file dropped in this same directory, which this sweep never
    # measured and has no reason to except.
    historical_evidence = {
        "tests/fixtures/runner-ledger-lab-02-20260908/run-R1-poort-dicht-vrije-ruimte.jsonl",
        "tests/fixtures/runner-ledger-lab-02-20260908/run-geslaagd-R0-R6.jsonl",
    }

    listing = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "src",
            "tests",
            "scripts",
            "docs",
            "README.md",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    tracked = [line for line in listing.splitlines() if line and line != self_path and line not in historical_evidence]

    offenders = []
    for rel_path in tracked:
        text = (ROOT / rel_path).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{rel_path}:{number}: {line.strip()}")
    assert offenders == []


def test_the_workflow_label_guard_still_catches_a_lowercase_hit(tmp_path):
    """RED-proof for the guard above, against a SYNTHETIC file so this test
    never depends on the swept tree staying dirty. Case-insensitive: an
    all-lowercase spelling must still match, the same reason the
    reviewer-name guard above is case-insensitive. Built split, same
    self-blindness reason as every guard above: the probe text below must
    not spell a real hit out contiguously in this file's own source line
    either, or this file would fail its own guard above."""
    pattern = _workflow_label_pattern()
    probe_text = "fixed in ws" + "3b, " + "task" + " 6, " + "review" + "ron" + "de 2."
    probe = tmp_path / "probe.py"
    probe.write_text(f'"""{probe_text}"""\n', encoding="utf-8")
    hits = [line for line in probe.read_text(encoding="utf-8").splitlines() if pattern.search(line)]
    assert hits, "the guard must still catch a lowercase workflow label"


@pytest.mark.parametrize(
    "probe_text",
    [
        "def test_at_volledig_the_candidate_line_of_" + "task" + "_23_is_unchanged():",
        "def test_INTEGRATION_" + "TASK" + "46_the_global_default():",
        "_" + "TASK" + "48_VERSIE = 'NetScaler NS14.1'",
    ],
)
def test_the_workflow_label_guard_catches_a_ticket_prefix_glued_inside_an_identifier(probe_text, tmp_path):
    """RE-PROOF for the exact gap a re-review measured: `\\b` is not a
    boundary between an underscore and a letter, so a ticket prefix fused
    onto the REST of an identifier - a test name, a module constant -
    passed through the space-only, then the space-or-underscore, version of
    this guard untouched. The three probes are the two test names and one
    of the five constants that gap let slip, reproduced synthetically so
    this test does not depend on those identifiers still existing (they
    were renamed to their behaviour once this gap was fixed) to prove the
    RED case. Built split, same self-blindness reason as every guard
    above."""
    pattern = _workflow_label_pattern()
    probe = tmp_path / "probe.py"
    probe.write_text(f"{probe_text}\n", encoding="utf-8")
    hits = [line for line in probe.read_text(encoding="utf-8").splitlines() if pattern.search(line)]
    assert hits, f"the guard must catch a ticket prefix glued inside an identifier: {probe_text!r}"


def test_every_binding_test_name_from_the_design_exists():
    """The design says the test names in chapter 3 are BINDING: a plan may
    rename one, but then the new name belongs in the design. Until it is there,
    the suite carries the name the design carries - so a gate can be measured
    by name instead of by reading.

    This only checks that the name EXISTS. What it proves is the business of
    the test itself.

    `test_both_call_sites_use_the_same_starter_and_the_same_encoding` is the
    design's own name (3.6 unit 1). An earlier version of this suite was built
    on an earlier spec draft
    ("drie, niet twee") and carried `test_all_three_call_sites...` here and
    in tests/test_powershell.py; a first attempt at THIS guard already hit
    the matching failure mode once - it carried the pre-rename
    `test_both_call_sites...` name while the test itself was still
    `test_all_three_call_sites...`, so it matched neither name correctly
    and never went red for either. A guard that copies the wrong name
    proves nothing for that name.

    A later review (in the merge to feat/release-1-0): the target branch
    carries the REVISED spec (da96cc1: "twee echte aanroepplekken" -
    collect.py:121 and handelen.py:227, both through `start_powershell`;
    `handelen.py`'s `cmd=list(process.args)` labels a re-raised
    `TimeoutExpired`, not a third starter) while the earlier test and this list
    still named the pre-revision test. Renamed both to the spec's name so
    the merged tree carries one name, not two, for the same unit."""
    body = "\n".join(path.read_text(encoding="utf-8") for path in sorted((ROOT / "tests").rglob("*.py")))
    missing = [name for name in BINDING_TEST_NAMES if f"def {name}(" not in body]
    assert missing == []


def _finding_label_pattern():
    """A different, older label shape than the workflow-label sweep above:
    not a task/ws/round pointer, but a numbered finding CITATION carried
    inside a comment or docstring next to the reason it once justified -
    "review N, Important/Critical/Minor" and a hyphenated internal ticket
    id directly followed by the word for a review ("task-<id> review").
    Measured (the same pattern below, over `src tests scripts docs`): 80
    hits across twelve files - chain.py, expiry.py, export.py, impact.py,
    mgmt_plane.py, answer.py and their test files - all pre-existing from
    before this guard, none introduced by it. Every hit was rewritten to
    the behaviour it stood for, or the citation removed where nothing but
    the label itself remained; a test NAME that happens to carry the same
    kind of round marker (`test_review4_important1_...`,
    `test_A8_1_...`) is not a comment or a docstring and is out of this
    guard's scope - identical to how the binding-test-name guard above
    treats a design-given name as fixed.

    Case does not matter (the same citation with a lowercase severity word
    is still a match), and
    a third form joins the two: the short parenthesised label of a single
    finding, a letter and a number after the word for a review ("(<word>
    M4)"), as it survived in rewritten commit messages.

    Widened by a later, separate sweep (a hygiene task, not a code review)
    for three more shapes measured standing in comments/docstrings across
    `src tests scripts` after a much larger cleanup of a model name next to
    a review round next to a numbered finding, all in one citation: three
    of the four AI model names on their own,
    standalone word - the fourth already has its own
    case-insensitive guard above,
    `test_no_internal_review_process_name_survives_in_the_code`, so it is
    not repeated here; the English "review round N" citation (the
    one-word Dutch compound of the review word or the fix word glued to
    the round word already has its own guard, `_workflow_label_pattern`
    above - this is the SPACED, English form that
    guard does not cover); and a bare "finding N:" citation,
    colon-suffixed to match the one shape actually measured in this tree
    and to leave ordinary prose ("finding a bug", "finding 12 vservers")
    alone.

    That sweep measured four hits of the new shapes, all four inside an
    `assert` message string (`assert cond, "reason naming the citation"`) -
    executable code, not a comment or a docstring, and therefore outside
    what this cleanup was permitted to touch (see the sibling sweep's own
    report: "assert-message strings ... must NEVER touch, even if they
    carry label-like text"). Rather than loosen this guard's own rule
    forbidding a whole-file exception here, or accept a permanently RED
    guard, the four are named by EXACT file and line number in
    `test_no_finding_review_citation_survives_in_the_public_tree`'s
    `KNOWN_ASSERT_MESSAGE_EXCEPTIONS` below - so any new label anywhere
    else, including a new line in one of those same four files, still
    fails, exactly as narrow as the historical-ledger exception two guards
    up.

    Widened a second time, by an independent review of the first widening:
    86 more hits across 42 files survived the first pass, in shapes this
    pattern did not yet know:
    - the SPACED Dutch round-plus-severity form (the round word, a number,
      a comma, the word for critical or important, another number) -
      `_workflow_label_pattern` above only ever knew the compound form of
      the round word glued to "fix"/"review", one word, no space;
    - the bare English round-plus-number citation, hyphenated, without the
      word for a review in front of it - REQUIRING the hyphen (not also
      accepting a bare space, unlike every other form above) on purpose:
      ordinary prose about rounding a number ("we round 2 decimals",
      "round 1.5 up") only ever uses a space, never a hyphen, so this one
      form stays discriminating without a hyphen-only real hit ever going
      unswept - none did, measured. The fix word directly in front of the
      round word (space OR hyphen, exactly like the review-word form
      above) still needs its own, separate branch: an actual measured hit
      (the fix word, a space, then the round word and a number, inside the
      SAME dict/JSON value already excepted below) would otherwise stop
      matching anything at all the moment the bare form went hyphen-only,
      which is precisely the kind of silent narrowing this guard exists to
      prevent;
    - the two-word "review"-plus-"fix" phrase itself, and a bare
      "review"-plus-a-letter-plus-a-digit citation with no parentheses
      around it (the parenthesised form was already covered);
    - a finding citation with a lettered sub-id - the digit-only form did
      not allow the trailing letter.
    A ticket prefix glued straight onto its number, no space at all, is the
    same gap in `_workflow_label_pattern` above, widened there instead,
    since that is the guard the space-separated form already lived in.

    Built split, same self-blindness reason as every guard above: the word
    for a review and the severity words must not sit contiguous in this
    file's own source line either.
    """
    import re

    review_word = "re" + "view"
    severity_word = "(Important|Critical|Minor)"
    task_word = "task"
    finding_word = "find" + "ing"
    # Tool and model names come from the needle list outside the tree; a
    # name that never matches stands in when the list is absent.
    model_names = "|".join(re.escape(name) for name in private_needles("naam")) or "(?!)"
    round_word_nl = "ronde"
    fix_word_nl = "fix"
    severity_word_nl = "(kritiek|belangrijk)"

    return re.compile(
        rf"\b{review_word} [0-9]+, {severity_word}"
        rf"|\b{task_word}-[0-9a-z-]+ {review_word}"
        rf"|\({review_word} [a-z][0-9]+\)"
        rf"|\b({model_names})\b"
        rf"|\b{review_word}[ -]round[ -][0-9]+\b"
        rf"|\b{fix_word_nl}[ -]round[ -][0-9]+\b"
        rf"|\b{finding_word}[ -][0-9]+[a-z]?\s*:"
        rf"|\b{fix_word_nl}[ -]?{round_word_nl}[ -][0-9]+\b"
        rf"|\b{round_word_nl}[ -][0-9]+\b"
        rf"|\b{severity_word_nl}[ -][0-9]+\b"
        rf"|\bround-[0-9]+\b"
        rf"|\b{review_word}[ -]fix\b"
        rf"|\b{review_word} [A-Za-z][0-9]+\b",
        re.IGNORECASE,
    )


# Exact (path, line number) pairs the widened `_finding_label_pattern()`
# still matches, and the only ones this guard accepts: each is an `assert`
# message STRING, executable code the cleanup that widened this guard was
# not permitted to touch (see `_finding_label_pattern()`'s own docstring).
# Line-exact, not file-exact like the historical-ledger exception above: a
# NEW hit anywhere else in these same four files - a second line, a fresh
# comment, a renamed test - still fails this guard. Re-measure and update
# this set (never just delete a line from it) if one of these four lines
# ever moves or is legitimately rewritten.
KNOWN_ASSERT_MESSAGE_EXCEPTIONS = frozenset(
    {
        ("tests/test_hidden_rules.py", 938),
        ("tests/test_hidden_rules.py", 949),
        ("tests/test_hidden_rules.py", 1026),
        ("tests/test_health.py", 67),
    }
)

# Exact (path, line number) pairs from the SECOND widening (see
# `_finding_label_pattern()`'s own docstring, "widened a second time"): each
# is a `"notes"` DICT/JSON value carrying the fixture's own generation
# history verbatim - `tests/rulesets/extract_nshc_hidden_rules.py`'s
# `return {...}` and the matching value in the `nshc-hidden-rules.json` it
# generates. Both are data literals, not a comment or a docstring, and are
# the SAME text by construction (the script writes the json field verbatim)
# - outside what this cleanup was permitted to touch for the same reason as
# `KNOWN_ASSERT_MESSAGE_EXCEPTIONS` above: dict/data literal values must
# never be touched, even when they carry label-like text.
KNOWN_DATA_LITERAL_EXCEPTIONS = frozenset(
    {
        ("tests/rulesets/extract_nshc_hidden_rules.py", 351),
        ("tests/rulesets/extract_nshc_hidden_rules.py", 366),
        ("tests/rulesets/nshc-hidden-rules.json", 8),
    }
)


def test_no_finding_review_citation_survives_in_the_public_tree():
    """RED on this test's own introduction (measured: 80 hits, see
    `_finding_label_pattern()`); GREEN once every hit was swept. One
    exception, the same reason every Built-split guard above excepts
    itself: this test file must assemble the pattern from parts to
    describe itself, so a plain scan of its own source would trip on the
    needles it defines.

    Widened later (see `_finding_label_pattern()`'s own docstring) for
    model names, the English "review round N" form and a bare "finding N:"
    citation - RED against the pre-widening tree on four lines, each an
    `assert` message string this cleanup could not touch (three in
    `tests/test_hidden_rules.py`, one in `tests/test_health.py`); GREEN
    again once those four were named exactly, by file AND line, in
    `KNOWN_ASSERT_MESSAGE_EXCEPTIONS` above. Every other hit the widened
    pattern found (an ordinary comment in `tests/test_runner_script.py`,
    unrelated to the four exceptions) was swept like any other.

    Widened a second time (see `_finding_label_pattern()`'s own docstring):
    RED again on three MORE lines, this time dict/JSON values rather than
    assert messages - named in `KNOWN_DATA_LITERAL_EXCEPTIONS` above,
    checked separately from the assert-message set.
    """
    import subprocess

    pattern = _finding_label_pattern()
    self_path = "tests/test_repo_hygiene.py"
    known_exceptions = KNOWN_ASSERT_MESSAGE_EXCEPTIONS | KNOWN_DATA_LITERAL_EXCEPTIONS

    # Scope: src, tests, scripts - and docs/, which already sat in this scan
    # and carries none of the three forms (measured, case-insensitive: 0).
    # CHANGELOG.md and README.md at the root stay OUTSIDE this guard: they,
    # like parts of the tree, still carry older round and finding labels in
    # other shapes (about 300 lines); sweeping those is a separate cleanup,
    # not something this guard pretends to have done.
    listing = subprocess.run(
        ["git", "ls-files", "--", "src", "tests", "scripts", "docs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    tracked = [line for line in listing.splitlines() if line and line != self_path]

    offenders = []
    for rel_path in tracked:
        text = (ROOT / rel_path).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line) and (rel_path, number) not in known_exceptions:
                offenders.append(f"{rel_path}:{number}: {line.strip()}")
    assert offenders == []


def test_the_known_assert_message_exceptions_still_carry_the_citation():
    """The exception set above is a NARROW allowance, not a blind spot: each
    of the four exact lines must still be there and must still be the
    reason it was excepted, or the exception is stale and hides nothing.
    If a line moves, gets rewritten, or disappears, this fails LOUD instead
    of the sweep above silently staying green for the wrong reason.

    The `assert` keyword itself is checked within the two lines ABOVE the
    excepted one, not only on it: a message string wrapped in parentheses
    (`assert cond, (\\n    "text"\\n)`) puts the citation on its own
    continuation line, one line below the `assert` that owns it - exactly
    the shape `tests/test_hidden_rules.py:1026` has."""
    pattern = _finding_label_pattern()
    for rel_path, number in sorted(KNOWN_ASSERT_MESSAGE_EXCEPTIONS):
        lines = (ROOT / rel_path).read_text(encoding="utf-8").splitlines()
        line = lines[number - 1]
        assert pattern.search(line), f"{rel_path}:{number} no longer carries the excepted citation: {line!r}"
        nearby = lines[max(0, number - 3) : number]
        assert any(candidate.lstrip().startswith("assert") for candidate in nearby), (
            f"{rel_path}:{number} is no longer part of an assert statement: {line!r}"
        )


def test_the_known_data_literal_exceptions_still_carry_the_citation():
    """The same narrow-allowance discipline as the assert-message exceptions
    above, for the dict/JSON pair instead: each exact line must still be
    there, still carry the citation, and still sit inside the SAME quoted
    string value both files are documented to share verbatim - not a
    comment that drifted next to it by accident."""
    pattern = _finding_label_pattern()
    for rel_path, number in sorted(KNOWN_DATA_LITERAL_EXCEPTIONS):
        lines = (ROOT / rel_path).read_text(encoding="utf-8").splitlines()
        line = lines[number - 1]
        assert pattern.search(line), f"{rel_path}:{number} no longer carries the excepted citation: {line!r}"
        assert '"' in line, f"{rel_path}:{number} is no longer inside a quoted string value: {line!r}"


def test_the_finding_review_citation_guard_still_catches_a_hit(tmp_path):
    """RED-proof for the guard above, against a SYNTHETIC file so this test
    never depends on the swept tree staying dirty. Built split, same
    self-blindness reason as every guard above: the probe text below must
    not spell a real hit out contiguously in this file's own source line
    either."""
    pattern = _finding_label_pattern()
    probe_text = "re" + "view 2, Im" + "portant 3, and " + "task" + "-2b-9 re" + "view besides"
    probe = tmp_path / "probe.py"
    probe.write_text(f'"""{probe_text}"""\n', encoding="utf-8")
    hits = [line for line in probe.read_text(encoding="utf-8").splitlines() if pattern.search(line)]
    assert hits, "the guard must still catch a finding-review citation"


@pytest.mark.parametrize(
    "probe_text",
    [
        "# " + "Re" + "view 1, Im" + "portant 3: the reason",
        "# " + "re" + "view 2, im" + "portant 1: the reason",
        "# " + "RE" + "VIEW 4, MI" + "NOR 2",
        "# rewritten to behaviour (" + "re" + "view M" + "4)",
        "# rewritten to behaviour (" + "Re" + "view m" + "5)",
        "# " + "Ta" + "sk-2b-2 Re" + "view: the reason",
        # Widened forms (see _finding_label_pattern()'s own docstring):
        "# fixed after the second " + "re" + "view rou" + "nd 2",
        "# measured by a reader, " + "fin" + "ding 3: the reason",
        "# " + "re" + "view rou" + "nd 2: the answer changed",
        "# " + "Re" + "VIEW ROU" + "ND 11: renamed the field",
        "# " + "fin" + "ding 7: the value leaked",
        "# " + "Fin" + "ding 12: masked now",
        # Second-widening forms (see _finding_label_pattern()'s own
        # docstring, "widened a second time"):
        "# " + "RON" + "DE 3, KRI" + "TIEK 1: the soak window",
        "# " + "ron" + "de 3, be" + "langrijk 2: a truncated char",
        "# " + "FIX RON" + "DE 2: the old comment",
        "# this was the " + "round" + "-2 code path",
        "# " + "pre-round" + "-3 broken behavior",
        "# " + "RE" + "VIEW FIX (whole-branch, Important)",
        "# " + "re" + "view fix for the same defect",
        "# " + "Re" + "view B2. optional_field is for",
        "# " + "Fin" + "ding 2b: masked now",
        "# " + "fin" + "ding 12b: the value leaked",
    ],
)
def test_the_finding_review_citation_guard_ignores_case_and_catches_the_short_label(probe_text):
    """Each form on its own, in any case: the numbered citation with its
    severity, the short parenthesised label, and the ticket id followed by
    the word for a review. Built split, same self-blindness reason as above.

    Probes 7-12 are the first widening: the English
    review-word-plus-round-plus-number citation and a colon-suffixed
    finding-plus-number citation (the model-name branch has its own test
    below, on the needle list outside the tree). Probes 13-21 are the
    second widening: the spaced Dutch round form, the bare
    English round-plus-number form, the review word directly followed by
    the word for a repair, a bare review-word-plus-letter-plus-digit
    citation with no parentheses, and a finding citation with a lettered
    sub-id."""
    assert _finding_label_pattern().search(probe_text), probe_text


def test_the_finding_review_citation_guard_catches_a_model_name_as_a_word():
    """The model-name branch of `_finding_label_pattern()`, on the names
    of the needle list outside the tree: each one caught as a standalone
    word in any case, never inside a longer word."""
    pattern = _finding_label_pattern()
    for name in needles_or_skip("naam"):
        assert pattern.search(f"# a {name.capitalize()} pass caught this"), name
        assert not pattern.search(f"# x{name}y"), name


@pytest.mark.parametrize(
    "plain_text",
    [
        "# a review of the chain found nothing",
        "# the review step comes after the build (see the policy)",
        "# reviewed in 2 rounds, important to keep",
        # Widened forms must still leave ordinary prose alone:
        "# " + "finding" + " a bug takes time",
        "# " + "finding" + " 12 vservers in this export",
        "# a round trip " + "re" + "view before merging",
        # Second-widening forms must still leave ordinary prose alone:
        "# een " + "ron" + "de tafel zonder nummer",
        "# a " + "round" + "-robin DNS setup",
        "# the " + "re" + "view fixed nothing here",
        "# de " + "kri" + "tiek was mild, geen probleem",
        "# we " + "round" + " 2 decimals here",
        "# " + "round" + " 1.5 up to the nearest int",
    ],
)
def test_the_finding_review_citation_guard_leaves_ordinary_text_alone(plain_text):
    """The guard stays discriminating: the word on its own, or next to a
    number that is not a citation, is ordinary prose. "finding 12 vservers"
    has no colon, so the widened bare-finding form does not fire on it.
    The last two probes are ordinary prose ABOUT rounding a number, spaced
    rather than hyphenated - a re-review measured this as a latent risk
    for the bare round-plus-number form, since fixed by requiring the
    hyphen (see `_finding_label_pattern()`'s own docstring).

    The three new model names are the one deliberate exception to "stays
    discriminating" in this guard: they are ALSO ordinary English words (a
    creative work, a poem form, a Japanese verse form) and this guard
    accepts that a legitimate use of one would also fail it - the same
    trade this file's
    own reviewer-name guard above already makes for its own two names.
    Nothing in this product's own domain language uses any of the three,
    so the measured risk is zero today; a future false hit is a one-line
    exception in `KNOWN_ASSERT_MESSAGE_EXCEPTIONS`-style, not a reason to
    narrow the pattern back to nothing."""
    assert not _finding_label_pattern().search(plain_text), plain_text


# ---------------------------------------------------------------------------
# uv.lock is the one source; both requirements files are exports of it.
# Measured before: a dependency fix raised pyjwt in requirements-dev.txt only,
# so `uv sync --frozen` would have installed the version with the known
# vulnerability while CI audited the other file; and requirements-build.txt
# was kept by hand, outside the lock.
#
# Since 1.1 each export carries an EXPLICIT selection. In uv, extras and
# dependency groups are different selections (`--all-extras` takes no group
# along), so the dev export names the group it leaves out and the build
# export names the one group it takes. Each export is compared with the
# closure of exactly its own selection, computed here from uv.lock - per
# normalised name on version, markers and the FULL hash set - never with
# "every package in the lock". `--frozen` only says the lock was not
# rewritten during the export; it does not prove the lock still describes
# pyproject.toml, so that agreement is a test of its own.
#
# A Dependabot pull request changes uv.lock but not the exports: it fails
# here, visibly, until the two commands below have been run again.
# ---------------------------------------------------------------------------

UV_VERSION = "0.12.13"
EXPORT_DEV = "uv export --frozen --all-extras --no-group build --no-emit-project -o requirements-dev.txt"
EXPORT_BUILD = "uv export --frozen --only-group build --no-emit-project -o requirements-build.txt"
_EXPORTS = {"requirements-dev.txt": EXPORT_DEV, "requirements-build.txt": EXPORT_BUILD}


def _normalised(name: str) -> str:
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


def _conjunction(marker: str | None) -> frozenset[str]:
    """A marker as a set of atoms joined by `and`. A shape this test does
    not compute (an `or`, parentheses) fails it: fail-closed, never a
    comparison that silently matches."""
    if not marker:
        return frozenset()
    assert " or " not in marker and "(" not in marker, f"marker niet in een vorm die deze toets uitrekent: {marker}"
    return frozenset(atom.strip() for atom in marker.split(" and "))


def _minimal(conjunctions: set[frozenset[str]]) -> frozenset[frozenset[str]]:
    """OR over paths, AND along a path; a path implied by a weaker one drops
    out, and an unconditional path makes the package unconditional."""
    if frozenset() in conjunctions:
        return frozenset({frozenset()})
    return frozenset(c for c in conjunctions if not any(other < c for other in conjunctions))


def _lock_packages(lock: dict) -> dict[str, dict]:
    packages: dict[str, dict] = {}
    for package in lock["package"]:
        name = _normalised(package["name"])
        # Two versions of one name (a fork in the resolution) would need a
        # choice this test does not make for itself.
        assert name not in packages, f"uv.lock draagt {name} meer dan eens"
        packages[name] = package
    return packages


def _lock_root(lock: dict, pyproject: dict) -> dict:
    return _lock_packages(lock)[_normalised(pyproject["project"]["name"])]


def _selection_roots(root: dict, export: str) -> list[dict]:
    """The direct entries of one export's selection, read from the project's
    own entry in uv.lock. The dev export: the project's dependencies plus
    every extra, never a group. The build export: only the group `build`."""
    groups = root.get("dev-dependencies", {})
    # uv takes the group `dev` along by default; with `build` as the only
    # group, `--no-group build` leaves no group at all. Another group means
    # this selection has to be thought through again.
    assert set(groups) == {"build"}, sorted(groups)
    if export == "requirements-dev.txt":
        entries = list(root.get("dependencies", []))
        for extra in sorted(root.get("optional-dependencies", {})):
            entries += root["optional-dependencies"][extra]
        return entries
    assert export == "requirements-build.txt", export
    return list(groups["build"])


def _selected_closure(lock: dict, pyproject: dict, export: str) -> dict[str, dict]:
    """name -> {version, markers, hashes} for the transitive closure of one
    export's selection: markers as the minimal OR of AND-paths, hashes as
    the full set the lock records (sdist and every wheel)."""
    packages = _lock_packages(lock)
    root_name = _normalised(pyproject["project"]["name"])
    paths: dict[str, set[frozenset[str]]] = {}
    seen: set[tuple] = set()
    stack = [
        (_normalised(e["name"]), _conjunction(e.get("marker")), tuple(sorted(e.get("extra", []))))
        for e in _selection_roots(packages[root_name], export)
    ]
    while stack:
        name, conjunction, extras = stack.pop()
        if (name, conjunction, extras) in seen:
            continue
        seen.add((name, conjunction, extras))
        assert name != root_name, "de selectie bereikt het project zelf"
        paths.setdefault(name, set()).add(conjunction)
        package = packages[name]
        children = list(package.get("dependencies", []))
        for extra in extras:
            children += package["optional-dependencies"][extra]
        for child in children:
            stack.append(
                (
                    _normalised(child["name"]),
                    conjunction | _conjunction(child.get("marker")),
                    tuple(sorted(child.get("extra", []))),
                )
            )
    closure = {}
    for name, conjunctions in paths.items():
        package = packages[name]
        hashes = [w["hash"] for w in package.get("wheels", [])]
        if "sdist" in package:
            hashes.append(package["sdist"]["hash"])
        assert all(h.startswith("sha256:") for h in hashes), name
        closure[name] = {
            "version": package["version"],
            "markers": _minimal(conjunctions),
            "hashes": frozenset(h.removeprefix("sha256:") for h in hashes),
        }
    return closure


def _parse_export(text: str) -> dict[str, dict]:
    """name -> {version, markers, hashes} from an exported file. Anything
    that is not a comment, a `name==version` line or a hash line fails: an
    index URL, an editable line or a loose requirement has no place here."""
    import re

    pins: dict[str, dict] = {}
    name = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        start = re.match(r"^([A-Za-z0-9_.\-]+)==([^ ;\\]+)(?: ; (.+?))? \\$", line)
        if start:
            name = _normalised(start.group(1))
            assert name not in pins, f"{name} staat twee keer in de export"
            marker = start.group(3)
            if marker:
                assert "(" not in marker, f"marker niet in een vorm die deze toets uitrekent: {marker}"
                markers = frozenset(_conjunction(part) for part in marker.split(" or "))
            else:
                markers = frozenset({frozenset()})
            pins[name] = {"version": start.group(2), "markers": markers, "hashes": []}
            continue
        found = re.match(r"^    --hash=sha256:([0-9a-f]{64})(?: \\)?$", line)
        assert found and name is not None, f"regel die geen vereiste en geen hash is: {line!r}"
        pins[name]["hashes"].append(found.group(1))
    for name, pin in pins.items():
        assert len(pin["hashes"]) == len(set(pin["hashes"])), f"dubbele hash bij {name}"
        pin["hashes"] = frozenset(pin["hashes"])
    return pins


def _export_differences(text: str, lock: dict, pyproject: dict, export: str) -> dict[str, dict]:
    exported = _parse_export(text)
    closure = _selected_closure(lock, pyproject, export)
    differences = {}
    for name in sorted(exported.keys() | closure.keys()):
        got, want = exported.get(name), closure.get(name)
        if got is None or want is None:
            differences[name] = {"export": got is not None, "uv.lock-selectie": want is not None}
            continue
        for field in ("version", "markers", "hashes"):
            if got[field] != want[field]:
                differences.setdefault(name, {})[field] = {"export": got[field], "uv.lock-selectie": want[field]}
    return differences


def _toml(name: str) -> dict:
    import tomllib

    return tomllib.loads((ROOT / name).read_text(encoding="utf-8"))


def _requirement_key(name, specifier, marker, extras) -> tuple:
    from packaging.markers import Marker
    from packaging.specifiers import SpecifierSet

    return (
        _normalised(name),
        str(SpecifierSet(specifier or "")),
        str(Marker(marker)) if marker else "",
        tuple(sorted(_normalised(e) for e in extras or ())),
    )


def _pyproject_lock_differences(pyproject: dict, lock: dict) -> list[str]:
    """The lock records the project's own input (requires-dist, the extras
    it provides, the groups, requires-python); each must be what
    pyproject.toml says now."""
    from packaging.requirements import Requirement

    project = pyproject["project"]
    root = _lock_root(lock, pyproject)
    metadata = root.get("metadata", {})
    differences = []

    def from_pyproject(text: str, extra: str | None) -> tuple:
        requirement = Requirement(text)
        if extra is None:
            marker = str(requirement.marker) if requirement.marker else None
        else:
            # An extra's own marker would be AND-ed by uv; not computed here.
            assert requirement.marker is None, f"marker in extra niet uitgerekend: {text}"
            marker = f"extra == '{extra}'"
        return _requirement_key(requirement.name, str(requirement.specifier), marker, requirement.extras)

    want_dist = sorted(
        [from_pyproject(text, None) for text in project.get("dependencies", [])]
        + [
            from_pyproject(text, extra)
            for extra, texts in project.get("optional-dependencies", {}).items()
            for text in texts
        ]
    )
    got_dist = sorted(
        _requirement_key(e["name"], e.get("specifier"), e.get("marker"), e.get("extras"))
        for e in metadata.get("requires-dist", [])
    )
    if want_dist != got_dist:
        differences.append(f"requires-dist: pyproject {want_dist} != uv.lock {got_dist}")
    want_extras = sorted(_normalised(e) for e in project.get("optional-dependencies", {}))
    got_extras = sorted(_normalised(e) for e in metadata.get("provides-extras", []))
    if want_extras != got_extras:
        differences.append(f"extras: pyproject {want_extras} != uv.lock {got_extras}")
    want_groups = {}
    for group, texts in pyproject.get("dependency-groups", {}).items():
        assert all(isinstance(t, str) for t in texts), f"include-group niet uitgerekend: {group}"
        want_groups[_normalised(group)] = sorted(from_pyproject(t, None) for t in texts)
    got_groups = {
        _normalised(group): sorted(
            _requirement_key(e["name"], e.get("specifier"), e.get("marker"), e.get("extras")) for e in entries
        )
        for group, entries in metadata.get("requires-dev", {}).items()
    }
    if want_groups != got_groups:
        differences.append(f"dependency-groups: pyproject {want_groups} != uv.lock {got_groups}")
    if project.get("requires-python") != lock.get("requires-python"):
        differences.append(
            f"requires-python: pyproject {project.get('requires-python')} != uv.lock {lock.get('requires-python')}"
        )
    if project.get("version") != root.get("version"):
        differences.append(f"version: pyproject {project.get('version')} != uv.lock {root.get('version')}")
    return differences


@pytest.mark.parametrize("export", sorted(_EXPORTS))
def test_each_export_is_exactly_the_closure_of_its_selection_in_uv_lock(export):
    text = (ROOT / export).read_text(encoding="utf-8")
    assert _parse_export(text), f"{export} draagt geen enkele naam==versie"
    differences = _export_differences(text, _toml("uv.lock"), _toml("pyproject.toml"), export)
    assert differences == {}, differences


@pytest.mark.parametrize("export", sorted(_EXPORTS))
def test_each_export_names_the_command_that_made_it(export):
    header = (ROOT / export).read_text(encoding="utf-8").splitlines()[:3]
    assert f"#    {_EXPORTS[export]}" in header, header


def test_the_two_exports_select_differently_and_share_no_version_or_hash_drift():
    dev = _parse_export((ROOT / "requirements-dev.txt").read_text(encoding="utf-8"))
    build = _parse_export((ROOT / "requirements-build.txt").read_text(encoding="utf-8"))
    # The build export is the group `build`: pip, setuptools, wheel and what
    # they ask for (packaging, for wheel). setuptools and wheel are in no
    # other selection, so the dev export never carries them.
    assert set(build) == {"pip", "setuptools", "wheel", "packaging"}, sorted(build)
    assert "setuptools" not in dev and "wheel" not in dev, sorted(dev)
    # pip-audit asks for pip: the dev export carries it too.
    assert "pip" in dev
    for name in build.keys() & dev.keys():
        assert build[name]["version"] == dev[name]["version"], name
        assert build[name]["hashes"] == dev[name]["hashes"], name


def test_uv_lock_records_what_pyproject_says():
    differences = _pyproject_lock_differences(_toml("pyproject.toml"), _toml("uv.lock"))
    assert differences == [], differences


def test_the_build_group_pins_the_toolchain_exactly():
    groups = _toml("pyproject.toml")["dependency-groups"]
    assert set(groups) == {"build"}, sorted(groups)
    names = {}
    for text in groups["build"]:
        name, _, version = text.partition("==")
        names[_normalised(name)] = version
    assert set(names) == {"pip", "setuptools", "wheel"}, names
    assert all(names.values()), names
    # PEP 639 in pyproject.toml: setuptools 77 or newer.
    assert int(names["setuptools"].split(".")[0]) >= 77, names


def test_the_export_commands_and_the_uv_version_are_in_contributing_and_the_pr_template():
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    template = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
    for command in (EXPORT_DEV, EXPORT_BUILD):
        assert command in contributing, command
        assert command in template, command
    assert f"uv {UV_VERSION}" in contributing


def _dependabot_offences(text: str) -> list[str]:
    """The Python block uses the uv ecosystem (the lock is the source), weekly,
    with the limit of five and the deliberate `mcp` exclusion; the
    github-actions block stays; no pip block remains."""
    import re

    blocks = re.split(r"\n(?=  - package-ecosystem: )", text)
    by_ecosystem = {}
    for block in blocks[1:]:
        name = re.match(r'  - package-ecosystem: "([^"]+)"', block).group(1)
        by_ecosystem[name] = block
    offences = []
    if set(by_ecosystem) != {"uv", "github-actions"}:
        offences.append(f"ecosystemen: {sorted(by_ecosystem)}")
    uv = by_ecosystem.get("uv", "")
    for needed in ('directory: "/"', 'interval: "weekly"', "open-pull-requests-limit: 5", '- dependency-name: "mcp"'):
        if needed not in uv:
            offences.append(f"uv-blok mist {needed}")
    if "mcp 2.0.0 moves/removes" not in uv:
        offences.append("uv-blok mist het commentaar bij de mcp-uitzondering")
    if 'interval: "weekly"' not in by_ecosystem.get("github-actions", ""):
        offences.append("github-actions-blok niet wekelijks")
    return offences


def test_dependabot_updates_the_uv_lock_and_the_actions():
    text = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert _dependabot_offences(text) == []
    # Negative proof: the 1.0.x pip block is refused.
    old = text.replace('package-ecosystem: "uv"', 'package-ecosystem: "pip"')
    assert _dependabot_offences(old)


def _first_line_with(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines()) if needle in line)


def _replace_hash(text: str, old_index: int, new: str) -> str:
    import re

    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", text)
    return text.replace(hashes[old_index], new, 1)


def test_the_export_comparison_fails_on_a_removed_a_replaced_or_an_extra_entry():
    """Negative proof: the comparison above is not a comparison that can only
    pass."""
    lock, pyproject = _toml("uv.lock"), _toml("pyproject.toml")
    for export in sorted(_EXPORTS):
        text = (ROOT / export).read_text(encoding="utf-8")
        assert _export_differences(text, lock, pyproject, export) == {}, export
        lines = text.splitlines(keepends=True)
        # A removed hash line (the first hash of the first package that
        # carries more than one, so the file stays well-formed).
        first = _first_line_with(text, "--hash=sha256:")
        second = lines[first + 1]
        assert "--hash=sha256:" in second, export
        removed = "".join(lines[:first] + lines[first + 1 :])
        assert _export_differences(removed, lock, pyproject, export), f"{export}: verwijderde hash niet gezien"
        # A replaced hash.
        replaced = _replace_hash(text, 0, "0" * 64)
        assert _export_differences(replaced, lock, pyproject, export), f"{export}: vervangen hash niet gezien"
        # An extra package.
        extra = text + "notinlock==1.0 \\\n    --hash=sha256:" + "1" * 64 + "\n"
        assert _export_differences(extra, lock, pyproject, export), f"{export}: extra pakket niet gezien"
        # A changed version.
        changed = text.replace("==", "==9", 1)
        assert _export_differences(changed, lock, pyproject, export), f"{export}: andere versie niet gezien"


def test_the_marker_comparison_fails_on_a_dropped_marker():
    lock, pyproject = _toml("uv.lock"), _toml("pyproject.toml")
    text = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert " ; sys_platform == 'win32'" in text
    dropped = text.replace(" ; sys_platform == 'win32'", "", 1)
    assert _export_differences(dropped, lock, pyproject, "requirements-dev.txt")


def test_the_pyproject_lock_comparison_fails_when_pyproject_moves():
    import copy

    lock, pyproject = _toml("uv.lock"), _toml("pyproject.toml")
    assert _pyproject_lock_differences(pyproject, lock) == []
    moved = copy.deepcopy(pyproject)
    moved["project"]["dependencies"].append("requests>=2")
    assert _pyproject_lock_differences(moved, lock)
    moved = copy.deepcopy(pyproject)
    moved["project"]["optional-dependencies"]["dev"][0] += ",<99"
    assert _pyproject_lock_differences(moved, lock)
    moved = copy.deepcopy(pyproject)
    moved["dependency-groups"]["build"].append("tomli==2.0.0")
    assert _pyproject_lock_differences(moved, lock)
    moved = copy.deepcopy(pyproject)
    moved["project"]["version"] = "0.0.1"
    assert _pyproject_lock_differences(moved, lock)


# ---------------------------------------------------------------------------
# The CI chain around --require-hashes. Measured on a CI log: pip was upgraded
# unpinned before the hash-locked install, `pip install -e . --no-deps` built
# in an isolated environment that fetched setuptools from the index without a
# hash, the three actions ran from mutable tags, and Posh-SSH came from the
# gallery with a version pin but nothing on its content. Each of these tests
# holds one link of that chain.
# ---------------------------------------------------------------------------

_CI = ROOT / ".github" / "workflows" / "ci.yml"
_BUILD_FILES = ("requirements-build.txt", "requirements-dev.txt")
_EDITABLE_INSTALL = "python -m pip install -e . --no-deps --no-build-isolation"


def _pip_install_lines(text: str) -> list[str]:
    """Every `pip install` command in `text`, from `python -m pip` on, in order."""
    import re

    lines = []
    for line in text.splitlines():
        match = re.search(r"-m pip install .*$", line)
        if match:
            lines.append("python " + match.group(0).strip())
    return lines


def _hash_locked(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    """name -> (version, hashes) for every requirement in a hash-locked file."""
    import re

    pins: dict[str, tuple[str, tuple[str, ...]]] = {}
    name = None
    for line in path.read_text(encoding="utf-8").splitlines():
        start = re.match(r"^([A-Za-z0-9_.\-]+)==([^ ;\\]+)", line)
        if start:
            name = start.group(1).lower().replace("_", "-")
            pins[name] = (start.group(2), ())
            continue
        found = re.match(r"^\s+--hash=sha256:([0-9a-f]{64})", line)
        if found and name is not None:
            version, hashes = pins[name]
            pins[name] = (version, (*hashes, found.group(1)))
        elif line.strip() and not line.lstrip().startswith("#") and not line.startswith(" "):
            name = None
    return pins


def test_every_action_in_ci_is_pinned_to_a_full_commit_sha_with_its_tag():
    """A tag can be moved; a commit id cannot. The tag stays readable as a
    comment behind it, so an update proposal shows which release it is."""
    import re

    uses = [line.strip() for line in _CI.read_text(encoding="utf-8").splitlines() if "uses:" in line]
    assert len(uses) >= 3, uses
    form = re.compile(r"^(- )?uses: [A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$")
    loose = [line for line in uses if not form.match(line)]
    assert loose == [], f"niet op een volledige commit-SHA met tag als commentaar: {loose}"


RELEASE_BRANCH = "feat/release-1-1"


def _push_branches(text: str) -> list[str]:
    """The branch list of `on.push`, read from the workflow text."""
    import json
    import re

    on = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    push = on.split("\n  push:\n", 1)[1]
    match = re.search(r"^    branches: (\[.*\])$", push, re.MULTILINE)
    assert match, "on.push.branches niet als lijst op een regel"
    return json.loads(match.group(1))


def test_ci_runs_on_a_push_to_the_release_branch():
    """1.0.x started a push run on feat/release-1-0 and `v*` tags only; the
    1.1 release branch is named explicitly, so its green run exists."""
    text = _CI.read_text(encoding="utf-8")
    branches = _push_branches(text)
    assert RELEASE_BRANCH in branches, branches
    assert 'tags: ["v*"]' in text.split("\npermissions:", 1)[0]
    # Negative proof: the 1.0.x trigger does not carry the branch.
    assert RELEASE_BRANCH not in _push_branches(text.replace(f', "{RELEASE_BRANCH}"', ""))


def test_checkout_does_not_persist_credentials():
    """The job pushes nothing, so the token stays out of .git/config
    (checkout keeps it in a separate file since v6, but still keeps it).
    The workflow starts on no `pull_request_target` or `workflow_run`, the
    two triggers that run fork code with a write token."""
    text = _CI.read_text(encoding="utf-8")
    step = text.split("uses: actions/checkout@", 1)[1].split("\n      - ", 1)[0]
    assert "\n        with:\n          persist-credentials: false" in step, step
    on = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert "pull_request_target" not in on and "workflow_run" not in on


def test_the_sbom_upload_keeps_its_archive_and_its_name():
    """upload-artifact v7 can upload a single file unzipped (`archive:
    false`), and then ignores `name`. The default (`true`) keeps the
    artifact name `sbom-<python-version>` the release step looks for."""
    text = _CI.read_text(encoding="utf-8")
    step = text.split("uses: actions/upload-artifact@", 1)[1].split("\n      - ", 1)[0]
    assert "archive:" not in step, step
    assert "name: sbom-${{ matrix.python-version }}" in step
    assert "path: sbom-${{ matrix.python-version }}.cdx.json" in step


def test_the_install_lines_in_contributing_are_the_install_lines_of_ci():
    """CONTRIBUTING says its install lines mirror CI: the same commands, in the
    same order, both ways - CI cannot add an install line the document does
    not show, and the document cannot promise one CI does not run."""
    contributing = _pip_install_lines((ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8"))
    ci = _pip_install_lines(_CI.read_text(encoding="utf-8"))
    assert contributing, "CONTRIBUTING.md noemt geen enkele pip install"
    assert contributing == ci, {"CONTRIBUTING.md": contributing, "ci.yml": ci}


def test_ci_installs_nothing_outside_a_hash_locked_file():
    """The build toolchain comes first and from its own hash-locked file,
    pip included; the project itself is installed without dependencies and
    without an isolated build environment, so no build requirement is
    fetched from the index behind the hash check."""
    lines = _pip_install_lines(_CI.read_text(encoding="utf-8"))
    assert lines == [
        "python -m pip install --require-hashes -r requirements-build.txt",
        "python -m pip install --require-hashes -r requirements-dev.txt",
        _EDITABLE_INSTALL,
    ], lines
    for name in _BUILD_FILES:
        assert (ROOT / name).is_file(), name


def test_ci_audits_every_hash_locked_file():
    """What CI installs from a hash-locked file, it also audits: setuptools
    and wheel appear only in requirements-build.txt."""
    audit = [line for line in _CI.read_text(encoding="utf-8").splitlines() if "-m pip_audit" in line]
    assert len(audit) == 1, audit
    for name in _BUILD_FILES:
        assert f"-r {name}" in audit[0], (name, audit[0])


def test_the_build_requirements_are_exact_and_carry_the_wheel_and_the_sdist_hash():
    """requirements-build.txt is the export of the group `build` (1.0.x kept
    it by hand, with exactly two hashes per package). Re-judged for the
    export: the count is no longer the rule - the export carries every hash
    the lock records, which the closure test above holds. What stays is
    that a build package can be installed from either form: each carries
    the sdist hash and at least one wheel hash of its locked release, and
    setuptools is 77 or newer (PEP 639 in pyproject.toml). The second
    install changes nothing the first one laid down: a package in both
    files has the same version and hashes (held above)."""
    build = _hash_locked(ROOT / "requirements-build.txt")
    packages = _lock_packages(_toml("uv.lock"))
    assert set(build) == {"pip", "setuptools", "wheel", "packaging"}, sorted(build)
    for name, (version, hashes) in build.items():
        package = packages[name]
        assert version == package["version"], (name, version)
        assert package["sdist"]["hash"].removeprefix("sha256:") in hashes, (name, "sdist")
        wheels = {w["hash"].removeprefix("sha256:") for w in package["wheels"]}
        assert wheels and wheels <= set(hashes), (name, "wheel")
    major = int(build["setuptools"][0].split(".")[0])
    assert major >= 77, build["setuptools"]


def test_ci_checks_the_content_of_posh_ssh_after_installing_it():
    """The pin in the transport checks the version; CI also checks the
    content, with the same script an operator can run, after the install
    and in the same step."""
    text = _CI.read_text(encoding="utf-8")
    install = text.index("Install-Module -Name Posh-SSH")
    check = text.index("scripts\\Get-GjkPoshSshManifest.ps1")
    assert install < check, "de manifestcontrole hoort NA Install-Module"
    assert (ROOT / "scripts" / "Get-GjkPoshSshManifest.ps1").is_file()


# ---------------------------------------------------------------------------
# 1.0.2: the needle guards run in CI on push and tag runs
# ---------------------------------------------------------------------------
#
# Without a needle list the hygiene guards skip, and in CI they skipped every
# time. The list comes from the repository secret NSMCP_PRIVATE_NEEDLES; a
# fork pull request has no access to it and keeps skipping, visibly.


def _ci_step(name: str) -> str:
    text = _CI.read_text(encoding="utf-8")
    start = text.index(f"- name: {name}")
    end = text.find("\n      - ", start + 1)
    return text[start : end if end != -1 else len(text)]


def test_h3_ci_writes_the_needle_secret_to_a_temporary_file_on_push_runs_only():
    step = _ci_step("Private hygiene needles")
    assert "if: github.event_name == 'push'" in step
    # The secret reaches the script through the environment, never inline in
    # the script text, and is never printed.
    assert "${{ secrets.NSMCP_PRIVATE_NEEDLES }}" in step
    run = step.split("run: |", 1)[1]
    assert "secrets." not in run
    assert "RUNNER_TEMP" in run and "GITHUB_ENV" in run
    assert "NSMCP_PRIVATE_NEEDLES=" in run
    for printer in ("Write-Host $env:NEEDLES", "echo $env:NEEDLES", "Write-Output $env:NEEDLES"):
        assert printer not in run
    # Before the suites that read it.
    text = _CI.read_text(encoding="utf-8")
    assert text.index("- name: Private hygiene needles") < text.index("- name: Full suite")


def test_h3_the_suites_in_ci_name_the_reason_of_every_skip():
    for name in ("The three invariants, by name", "Full suite"):
        # The command line itself, not a comment in the step.
        command = _ci_step(name).split("run: ", 1)[1].splitlines()[0]
        assert command.startswith("python -m pytest") and command.split()[-1] == "-rs", (name, command)


def test_h3_contributing_says_a_maintainer_runs_the_hygiene_suite_with_the_list():
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "NSMCP_PRIVATE_NEEDLES" in text
    assert "maintainer" in text.lower()
