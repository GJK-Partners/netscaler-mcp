"""Claims in the documentation that the code has to keep.

A document is not tested by reading it. These claims were measured wrong
(security 3, 4, 13 and the README contradiction) and are pinned here so a
later edit cannot quietly restore them. No count is given here on purpose -
it rotted once already (thirteen claims, seventeen tests) - count the
`test_` functions in this file for the real number.

These assertions are canaries against silent deletion of a section, not proof
that the section says something true: "payloadSha256" in text also passes on
a sentence saying there is no such check."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """Body of the section starting at the literal line `heading` (e.g.
    "## Vertrouwensmodel en scope"), up to the next top-level "## " heading
    or end of file. A test scoped to the section cannot pass on text that
    lives anywhere else in the document."""
    start = text.index(heading)
    body_start = start + len(heading)
    tail = text[body_start:]
    next_heading = re.search(r"\n## ", tail)
    end = body_start + (next_heading.start() if next_heading else len(tail))
    return text[start:end]


def _bullet(text: str, marker: str) -> str:
    """Body of the bullet item starting at the literal text `marker`, up to
    the next top-level bullet ("- **" at the start of a line) or end of
    file."""
    start = text.index(marker)
    after_marker = start + len(marker)
    tail = text[after_marker:]
    next_bullet = re.search(r"\n- \*\*", tail)
    end = after_marker + (next_bullet.start() if next_bullet else len(tail))
    return text[start:end]


def test_the_customer_security_document_carries_a_trust_model():
    text = _read("docs/klant/SECURITY.md")
    section = _section(text, "## Vertrouwensmodel en scope")
    for trusted in ("export", "kennispakket", "configuratiebestand", "verzamelscript", "schrijfscript"):
        assert trusted in section
    # Gate G1(b) (spec 2.7 noot bij 17, security 4). The trust
    # model must say, with these words, that the export is a SEMI-trusted
    # input, that an object name carrying an instruction reaches the answer
    # AS TEXT and never AS a command, and that the model may not read that
    # text as authority. Measured absent (0 hits for all four) before this.
    for phrase in ("semi", "als tekst", "niet als opdracht", "gezag"):
        assert phrase in section, phrase


def test_the_window_text_names_the_screen_sharing_risk():
    """Design par. 2.7, item 2: the sentence the FILE channel already carries -
    a channel is exactly as closed as the machine it comes out on - now stands
    at the window too, with the four situations named rather than implied. This
    test is the evidence gate G1 asks for on that item, so it checks the four
    by name instead of checking that the paragraph exists."""
    text = _read("docs/klant/SECURITY.md")
    assert "precies zo gesloten als de machine waarop het uitkomt" in text
    for situation in ("schermdeling", "RMM", "tweede lokale gebruiker", "RDP-shadowsessie"):
        assert situation in text, situation


def test_prompt_injection_is_named_as_a_risk():
    assert "prompt-injectie" in _read("docs/klant/SECURITY.md")


def test_the_readme_no_longer_claims_the_write_script_reaches_only_a_known_appliance():
    text = _read("README.md")
    normalized = " ".join(text.split())
    assert "only the appliance the operator configured or targeted" not in normalized


def test_the_data_flow_document_describes_the_hash_check_that_really_exists():
    text = _read("docs/klant/BEVEILIGING-EN-DATASTROMEN.md")
    assert "payloadSha256" in text or "hash per bron" in text


def test_the_root_security_file_works_without_opening_another_document():
    text = _read("SECURITY.md")
    assert "kevin.borger@gjk-partners.nl" in text
    assert "90 days" in text
    assert "Safe harbor" in text
    assert "Supported versions" in text
    assert "Out of scope" in text
    assert "private vulnerability reporting" in text.lower()


def test_the_contribution_path_exists_and_names_the_gates():
    text = _read("CONTRIBUTING.md")
    for gate in ("pytest", "ruff", "test_no_network.py", "test_product_surface.py"):
        assert gate in text


def test_every_community_file_is_present():
    for name in (
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "CHANGELOG.md",
        ".github/CODEOWNERS",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/bug_report.md",
        ".github/ISSUE_TEMPLATE/feature_request.md",
    ):
        assert (ROOT / name).is_file(), name


def test_the_glossary_translates_the_verdict_vocabulary():
    text = _read("docs/GLOSSARY.md")
    for word in ("GERAAKT", "NIET GERAAKT", "NIET VASTGESTELD", "[vastgesteld]", "bewijs", "reden", "Kennisbasis"):
        assert word in text


def test_the_readme_links_the_glossary_and_states_the_platform():
    text = _read("README.md")
    assert "docs/GLOSSARY.md" in text
    assert "## Platform" in text
    assert "ctypes.windll" in text or "Windows-only" in text


def test_the_glossary_does_not_join_a_bulletin_id_to_a_cve_id():
    """cve.py builds a per-CVE finding's subject as the bare CVE id
    (`identity = str(cve["id"])`, cve.py:2705-2771); the bulletin id is
    the subject of a separate finding (cve.py:2894). The product never
    joins the two with " / " in one subject. An earlier draft of the
    annotated example did (CTX696604 / CVE-2026-8452, review finding
    F3); this guards against that shape reappearing, case and internal
    spacing included (ctx696604 / CVE-..., CTX 696604 / CVE-...)."""
    text = _read("docs/GLOSSARY.md")
    assert not re.search(r"(?i)[a-z]{2,}\s*[0-9]+\s*/\s*cve-", text)


def test_the_architecture_document_names_the_three_invariants_and_their_guards():
    text = _read("docs/ARCHITECTURE.md")
    for guard in ("tests/test_no_network.py", "tests/test_answer.py", "tests/test_handelen_zonder_code.py"):
        assert guard in text
    for topic in ("layer rule", "disclosure", "Where to add"):
        assert topic in text


def test_the_architecture_document_describes_the_cs_route_as_the_code_does():
    """`chain._cs_chain` makes the WHOLE content-switching route "niet
    vastgesteld" when a policy cannot be resolved, and does not follow the
    standard load balancer further. The paragraph once said the opposite
    (the standard load balancer and the chain beyond it "unaffected");
    pinned to the paragraph itself so that claim cannot come back."""
    text = _read("docs/ARCHITECTURE.md")
    start = text.index("**The content-switching step.**")
    paragraph = " ".join(text[start : text.index("\n\n", start)].split())
    assert 'makes the whole route "niet vastgesteld"' in paragraph
    assert "the standard load balancer is not followed further" in paragraph
    assert "unaffected" not in paragraph


def test_the_four_tests_the_architecture_document_names_by_signature_exist():
    """The invariant table in docs/ARCHITECTURE.md cites four test
    functions by exact name. Checking for the guard file names and
    words like "disclosure" (see the test above) is a canary that
    survives almost any rewrite - it does not notice a rename or
    deletion of the named function itself. This pins each cited name
    to the file it is claimed to live in, so a rename breaks the doc
    claim instead of quietly rotting it.
    """
    cited = (
        ("tests/test_no_network.py", "def test_the_reading_tools_open_no_socket_through_a_real_session"),
        ("tests/test_no_network.py", "def test_the_reading_tools_on_the_REAL_export_open_no_socket"),
        ("tests/test_no_network.py", "def test_the_guard_really_trips"),
        ("tests/test_answer.py", "def test_finding_requires_evidence"),
    )
    for relative, signature in cited:
        assert signature in _read(relative), (relative, signature)


def test_no_public_document_still_names_the_internal_version():
    """C6: pyproject, the tag and the README all say 1.0.0. Design par. 1.4 is
    blunter: publicly there is no 2.0 - that number is the INTERNAL state of
    the product. A customer document that still carries it makes two version
    stories out of one release."""
    for relative in (
        "README.md",
        "docs/klant/SECURITY.md",
        "docs/klant/HANDLEIDING.md",
        "docs/klant/BEVEILIGING-EN-DATASTROMEN.md",
        # Added with the document itself (merge round): a guard that lists
        # files by hand covers a NEW customer document only when someone
        # remembers to add it, which is exactly how such a list rots.
        "docs/klant/OPENSTAANDE-METINGEN.md",
    ):
        assert "2.0.0" not in _read(relative), relative


def test_the_data_flow_document_carries_the_public_version():
    assert "1.0.1" in _read("docs/klant/BEVEILIGING-EN-DATASTROMEN.md")


def test_the_security_policy_promises_the_window_the_gate_asks_for():
    """Gate G1 names it: five working days to a first SUBSTANTIVE response,
    ninety days to publication. An acknowledgement inside five days and a
    verdict inside ten is a different promise, and the gate is the one that
    counts."""
    text = _read("SECURITY.md")
    assert "first substantive response" in text
    assert "within 5 working days" in text
    assert "within 10 working days" not in text
    assert "90 days" in text


def test_the_attempt_counter_is_documented_where_the_operator_reads():
    """Security 10 (`confirm.MAX_ATTEMPTS`, CHANGELOG line 61) is built and
    tested, but was measured absent from every document an
    operator actually opens: docs/klant/SECURITY.md, docs/klant/HANDLEIDING.md
    and README.md described the code's life as "ten minutes, used once"
    without the five-failed-attempts limit or the channel notice that fires
    when it burns a proposal - the one place the operator SEES that notice
    and has to know what it means. The trust model additionally needs the
    accepted consequence spelled out: an AI client driving the calls can
    burn a proposal this way, on purpose or by guessing wrong."""
    security = _section(_read("docs/klant/SECURITY.md"), "## Vertrouwensmodel en scope")
    assert "vijf foute" in security.lower()
    assert "verbrand" in security or "verbrandt" in security
    assert "AI-client" in security or "AI-assistent" in security

    handleiding = _read("docs/klant/HANDLEIDING.md")
    assert "vijf foute" in handleiding.lower()
    assert "verbrand" in handleiding or "verbrandt" in handleiding

    readme_writing = _section(_read("README.md"), "## What it does not do")
    assert "five wrong guesses" in readme_writing.lower()


def test_the_chain_documentation_says_what_the_chain_does_not_follow():
    """`dienst_keten` gives a contentswitching- and a Gateway-vserver the
    verdict "niet vastgesteld" by design (chain.NOT_FOLLOWED). A reader who
    only knows "niet vastgesteld = bindingsbestand niet te lezen" would look
    for a read problem that is not there, so both documents say it."""
    handleiding = _bullet(_read("docs/klant/HANDLEIDING.md"), "- **dienst**")
    assert "contentswitching" in handleiding
    assert "Gateway" in handleiding
    assert "samenvattingsregel" in handleiding
    readme = _read("README.md")
    row = [line for line in readme.splitlines() if line.startswith("| `dienst_keten(dienst, doel)`")][0]
    assert "summary line" in row
    assert "contentswitching" in row


def test_the_certificate_documentation_names_the_management_services():
    """`certificaat_wat_breekt_er` reads the SSL services on a certificate and
    `certificaat_wat_moet_ik_doen` refuses a proposal on the appliance's own
    management traffic. An operator reading "geen wijzigingsvoorstel" must be
    able to find why in the documents they open."""
    handleiding = " ".join(_bullet(_read("docs/klant/HANDLEIDING.md"), "- **certificaat**").split())
    assert "beheerverkeer van de appliance zelf" in handleiding
    assert "SSL-diensten" in handleiding
    readme = _read("README.md")
    prefix = "| `certificaat_wat_moet_ik_doen(certnaam, doel)`"
    row = [line for line in readme.splitlines() if line.startswith(prefix)][0]
    assert "management traffic" in row


def test_the_certificate_documentation_names_the_use_outside_the_bindings():
    """`certificaat_wat_breekt_er` names the SAML actions, SAML IdP profiles
    and SSL servicegroups that use a certificate, and says "niet
    vastgesteld" for a source the export does not carry; the advice leaves
    those uses to the operator. The documents say so, and the page of open
    measurements names what is still NOT followed."""
    handleiding = " ".join(_read("docs/klant/HANDLEIDING.md").split())
    bullet = " ".join(_bullet(_read("docs/klant/HANDLEIDING.md"), "- **certificaat**").split())
    assert "SAML-actie" in bullet and "SSL-servicegroup" in bullet
    for phrase in (
        "gebruikt als signing-certificaat door SAML-actie X",
        "gebruikt als SP-certificaat door IdP-profiel Y",
        "gebonden aan SSL-servicegroup Z (CA: ja)",
        "niet vastgesteld: bron ... niet in de export",
        "`certificaat_vervangen` wisselt alleen de binding op een virtuele server om",
        # The fourth source, and what it establishes on an appliance without SSL servicegroups.
        "`config/sslservicegroup`",
        "Een appliance zonder SSL-servicegroups is daarmee vastgesteld",
        # All three states `rapport_dekking` can print for these sources.
        "gelezen, niet in de export, of niet bruikbaar gelezen",
        # The effect on check 5 of `status_update_preflight`.
        "Toets 5 (certificaathorizon) telt een certificaat alleen als vrij",
        # The proposal of the replacement tool itself.
        "dit certificaat is ook elders in gebruik: ...; die gebruiken raakt deze vervanging niet, neem ze zelf mee",
        '"gebruik buiten de binding niet vastgesteld"',
        "ook als de export een ander doel beschrijft dan de handeling",
    ):
        assert phrase in handleiding, phrase
    readme = _read("README.md")
    row = [line for line in readme.splitlines() if line.startswith("| `certificaat_wat_breekt_er(certnaam, doel)`")][0]
    assert "SAML action" in row and "SSL servicegroup" in row
    metingen = " ".join(
        _section(_read("docs/klant/OPENSTAANDE-METINGEN.md"), "## Certificaatgebruik dat niet gevolgd wordt").split()
    )
    for phrase in ("OAuth", "certificaten in monitors", "client-cert-CA-ketens buiten de binding"):
        assert phrase in metingen, phrase


def test_the_coverage_documentation_names_both_collector_gaps():
    """On a real export `rapport_dekking` keeps two binding files with a gap
    after reading both shapes: lbmonitor (parent source without a hash) and
    sslcipher (parent source not collected). Both are collector facts, and
    the page that lists what this product does not establish says so."""
    metingen = _section(
        _read("docs/klant/OPENSTAANDE-METINGEN.md"), "## Twee bindingsbestanden zijn niet te kruiscontroleren"
    )
    assert "lbmonitor_binding.by-parent.json" in metingen
    assert "sslcipher_binding.by-parent.json" in metingen
    assert "config/sslcipher" in metingen
    handleiding = " ".join(_read("docs/klant/HANDLEIDING.md").split())
    assert '"2 van de 11 bindingsbestanden dragen een gat"' in handleiding


def test_the_glossary_example_shows_only_lines_the_product_really_writes():
    """An annotated example is a promise about output. This one claimed the
    product does not judge FIPS builds (it does - cve.py carries its own
    FIPS/NDcPP branch) and put a NIET BEOORDEELD section in a CVE answer, which
    never carries one. Design par. 2.8 states the honest boundary instead: the
    FIPS branch is proven on synthetic fixtures only, and stays that way in 1.0."""
    text = _read("docs/GLOSSARY.md")
    assert "beoordeelt geen FIPS-builds" not in text
    assert "GSLB-vservers" in text
    assert "synthetic fixtures" in text


def test_the_provenance_trust_boundary_is_documented_where_the_operator_reads():
    """The startup check keeps the provenance map out of the export map by
    comparing paths; it does not look at who may write where. Whoever can
    write the directory ABOVE the provenance map can rename or replace it,
    so a provenance map beside the export map, under a parent the supplier
    can write, is no independent boundary - the server starts all the same.
    That is an operator duty, and it has to be written where the operator
    reads: the trust model and the files-on-disk section. Not only the
    directory right above: whoever can rename any directory higher up can
    replace the whole branch, so the text names the whole chain."""
    security = " ".join(_section(_read("docs/klant/SECURITY.md"), "## Vertrouwensmodel en scope").split())
    assert "vergelijkt paden, geen rechten" in security
    assert "hele keten van bovenliggende mappen" in security
    assert "geen onafhankelijke vertrouwensgrens" in security
    assert "aanbevolen indeling" in security

    files_on_disk = " ".join(_section(_read("docs/klant/HANDLEIDING.md"), "## Bestanden op schijf").split())
    assert "niet naar rechten" in files_on_disk
    assert "**Beheermappen**" in files_on_disk
    assert "hele keten van bovenliggende mappen" in files_on_disk
    assert "**Exportmap**" in files_on_disk


EXPORT_MAP_INSIDE_A_MAP_TEXT = (
    "De omgekeerde richting, de exportmap binnen een beheermap, weigert de server alleen voor de "
    "ledgermap, de herkomstmap en de firmwaremap; de map van het configuratiebestand en de map van de "
    "scripts mogen de exportmap wel bevatten, en dat toetst de server niet."
)
EXPORT_MAP_INSIDE_SAFE_TEXT = (
    "Dat is alleen veilig als de aanleverende partij in die bovenmap zelf niet kan schrijven, alleen "
    "in de exportmap; de aanbevolen indeling houdt de exportmap er apart van."
)


def test_the_documents_say_which_maps_may_hold_the_export_map_and_when_that_is_safe():
    """The start check refuses an export map INSIDE the ledger map, the
    provenance map and the firmware map, and deliberately not inside the
    map of the configuration file or of the scripts
    (`start._check_export_boundaries`): the configuration example in the
    manual puts the export under the map of its scripts. The code, its
    tests and the changelog said so; the customer documents listed only the
    enforced set, next to a recommended layout that keeps the export map
    out of every administrative map - so a reader could not tell whether
    the example is refused, allowed or unsafe. The trust model and "Bestanden
    op schijf" now say both halves in so many words, and when the allowed
    half is safe."""
    security = " ".join(_section(_read("docs/klant/SECURITY.md"), "## Vertrouwensmodel en scope").split())
    files_on_disk = " ".join(_section(_read("docs/klant/HANDLEIDING.md"), "## Bestanden op schijf").split())
    for naam, tekst in (("SECURITY.md", security), ("HANDLEIDING.md", files_on_disk)):
        assert EXPORT_MAP_INSIDE_A_MAP_TEXT in tekst, naam
        assert EXPORT_MAP_INSIDE_SAFE_TEXT in tekst, naam


def test_the_trust_model_says_which_knowledge_refusal_quotes_the_identity():
    """The refusal for an identity outside its form names the field and the
    form, not the value; a copy of an identity already seen, differing only
    in case or white space, is refused by the duplicate check first, and
    that reason does quote the spelling (escaped). The trust model may not
    promise that no reason ever repeats the value."""
    row = next(line for line in _read("docs/klant/SECURITY.md").splitlines() if line.startswith("| het kennispakket |"))
    assert "zonder de waarde te herhalen" not in row
    assert "niet de waarde" in row
    assert "dubbelcontrole" in row


def _block_with(text: str, needle: str) -> str:
    """The one paragraph or top-level bullet of `text` that carries
    `needle`, with its white space collapsed - so a claim is pinned to the
    passage that makes it, not to a word that happens to occur elsewhere."""
    blocks = [block for block in re.split(r"\n\s*\n|\n(?=- )", text) if needle in block]
    assert len(blocks) == 1, (needle, len(blocks))
    return " ".join(blocks[0].split())


def test_the_powershell_module_path_is_named_as_an_administrative_map():
    """The transport loads exactly "Posh-SSH 3.2.7" - a VERSION pin. Which
    files answer to that version is decided by whoever may write the module
    path of the account the server runs under; the pin checks neither
    content nor origin. So that path is an administrative map, and the
    trust model says so next to the other administrative maps, the manual
    where Posh-SSH is required, and scripts/README where the transport's
    requirements are listed.

    Each of the three passages also names the module map in the account's
    OWN profile (the CurrentUser scope, `Documents\\WindowsPowerShell\\Modules`):
    it comes first in `PSModulePath`, so it is searched first, the account
    itself can write it, and folder redirection can put it in a
    synchronised documents folder. Naming only the machine-wide maps left
    out the one map that is loaded first."""
    # SR-6 (1.0.2): the transport checks the content too now; the three
    # passages say so, and that origin is still not checked.
    security = _block_with(_section(_read("docs/klant/SECURITY.md"), "## Vertrouwensmodel en scope"), "PSModulePath")
    assert "toetst het SSH-transport" in security and "ook de inhoud" in security
    vereist = _block_with(_read("docs/klant/HANDLEIDING.md"), "**Vereist: Posh-SSH")
    assert "PSModulePath" in vereist and "ook de" in vereist and "geen herkomst" in vereist
    scripts = _block_with(_section(_read("scripts/README.md"), "## Vereisten"), "PSModulePath")
    assert "ook de inhoud" in scripts and "geen" in scripts and "herkomst" in scripts
    for naam, passage in (("SECURITY.md", security), ("HANDLEIDING.md", vereist), ("scripts/README.md", scripts)):
        assert "Documents\\WindowsPowerShell\\Modules" in passage, naam
        assert "CurrentUser" in passage, naam
        assert "als eerste doorzocht" in passage, naam
        assert "gesynchroniseerde" in passage, naam


_POSH_SSH_VERSION_IN_TEXT = re.compile(r"(?:Posh-SSH|-RequiredVersion)\s+(\d+\.\d+\.\d+)")


def _changelog_current_part(text: str) -> str:
    """ "Unreleased" and the current release line: every "## [" section from
    the top down to and including the newest section whose version ends in
    ".0" (the minor release that introduced the line). A maintenance release
    (1.0.1) only says what it changed; the claims of the line stay in the
    1.0.0 section. Older lines may name an older pin as history."""
    heads = list(re.finditer(r"^## \[([^\]]+)\]", text, flags=re.MULTILINE))
    for index, head in enumerate(heads):
        if re.fullmatch(r"\d+\.\d+\.0", head.group(1)):
            return (
                text[heads[0].start() : heads[index + 1].start()]
                if index + 1 < len(heads)
                else text[heads[0].start() :]
            )
    return text[heads[0].start() :]


def test_every_document_names_the_posh_ssh_version_the_transport_pins_and_no_other():
    """The version lives in one place, `$vereist` in the transport. Four
    documents tell an operator which version to install; each must name that
    version (as "Posh-SSH <versie>" or "-RequiredVersion <versie>") and none
    may name another - in the changelog only "Unreleased" and the current
    release line count, older lines are history."""
    from conftest import posh_ssh_pin

    versie = posh_ssh_pin()
    documenten = {
        "docs/klant/HANDLEIDING.md": _read("docs/klant/HANDLEIDING.md"),
        "scripts/README.md": _read("scripts/README.md"),
        "docs/klant/SECURITY.md": _read("docs/klant/SECURITY.md"),
        "CHANGELOG.md": _changelog_current_part(_read("CHANGELOG.md")),
    }
    for naam, tekst in documenten.items():
        genoemd = set(_POSH_SSH_VERSION_IN_TEXT.findall(" ".join(tekst.split())))
        assert versie in genoemd, f"{naam} noemt Posh-SSH {versie} niet"
        assert genoemd == {versie}, f"{naam} noemt een andere Posh-SSH-versie: {sorted(genoemd - {versie})}"


def test_the_manual_states_the_soak_minimum_the_start_check_applies():
    """The manual said `soak_uren` "mag alleen groter zijn dan 24", while the
    start check refuses only a value BELOW the minimum (`<`), so 24 itself
    starts - as the side-by-side configuration in tests/test_start.py
    shows, which carries exactly 24 - and the start error itself says
    "minimaal". The manual now says the same, from the one constant."""
    from nsmcp.upgrade_plan import MINIMUM_SOAK_HOURS

    tekst = " ".join(_read("docs/klant/HANDLEIDING.md").split())
    assert f"`soak_uren` is minimaal {MINIMUM_SOAK_HOURS}" in tekst
    assert "`soak_uren` mag alleen groter" not in tekst


def test_a_final_version_carries_the_production_stable_classifier():
    """`version` 1.0.0 with "Development Status :: 4 - Beta" told an index
    the release was not final. A version without a pre-release or dev
    suffix, at 1.0 or higher, carries "5 - Production/Stable" and no other
    development status."""
    import tomllib

    project = tomllib.loads(_read("pyproject.toml"))["project"]
    status = [c for c in project["classifiers"] if c.startswith("Development Status ::")]
    final = re.fullmatch(r"(\d+)\.\d+\.\d+", project["version"])
    assert final and int(final.group(1)) >= 1, project["version"]
    assert status == ["Development Status :: 5 - Production/Stable"], status


ONE_ADDRESS_PER_APPLIANCE_TEXT = (
    "Een appliance staat met precies een adres in het doelenbestand; staan twee doelen op hetzelfde "
    "adres, dan weigert de server te starten"
)
ADDRESS_AS_TEXT = "zonder naamresolutie"


def test_the_documents_say_one_appliance_stands_in_the_targets_file_with_one_address():
    """The open-phase refusal, the hold of an undecided start and the phase
    runner's own check hold a target by its NAME. Two names with another
    first label for one address got past all three (measured); the start
    now refuses a targets file in which two targets share an address
    (`start._require_one_target_per_address`). The trust model says so
    where it promises one writer at a time, the manual where it describes
    the targets file - both with the limit that the address is compared as
    text, never resolved."""
    security = _block_with(
        _section(_read("docs/klant/SECURITY.md"), "## Wat dit product wel en niet doet"), "**Er schrijft er hooguit"
    )
    handleiding = _read("docs/klant/HANDLEIDING.md")
    doelenbestand = " ".join(
        handleiding[handleiding.index("### Het doelenbestand") : handleiding.index("### De hoofdstukken")].split()
    )
    for naam, tekst in (("SECURITY.md", security), ("HANDLEIDING.md", doelenbestand)):
        assert ONE_ADDRESS_PER_APPLIANCE_TEXT in tekst, naam
        assert ADDRESS_AS_TEXT in tekst, naam


def test_the_hold_of_an_undecided_start_is_described_per_target_name_not_per_appliance():
    """The register of undecided starts is keyed on the target NAME as the
    open-phase refusal compares it (capitalisation and the domain part of
    an FQDN aside). The trust model and the changelog said "the appliance,
    not the spelling of its name" - more than the code does: a name with
    another first label is another target to the register. What makes that
    one address in practice is the start check on the targets file; the
    documents now say exactly that."""
    security = _block_with(
        _section(_read("docs/klant/SECURITY.md"), "## Wat dit product wel en niet doet"), "**Het startvenster"
    )
    assert "Het doel is daarbij de appliance" not in security
    assert "Het doel is daarbij de doelnaam zoals de weigering voor een openstaande fase hem vergelijkt" in security
    assert "Een naam met een ander eerste deel is een ander doel" in security
    changelog = " ".join(_changelog_current_part(_read("CHANGELOG.md")).split())
    assert "per appliance, not per spelling" not in changelog
    assert "per target name and per server process" in changelog


def test_the_doh_measurement_says_its_export_is_not_in_the_repository():
    """The DNS over HTTPS measurement of 6-9-2026 was made on a workbench
    export that carried a real configuration. That export is not in this
    repository; the shape lives on in a SYNTHETIC fixture written by
    scripts/make_doh_fixture.py. The document must say exactly that, name
    the synthetic fixture and the renamed gate test, and carry no workbench
    label and no path of the withdrawn fixture."""
    section = _section(_read("docs/klant/OPENSTAANDE-METINGEN.md"), "## Openstaande meting: A15a")
    assert "tests/fixtures/lab-export-vpx-doh-synthetic/" in section
    assert "scripts/make_doh_fixture.py" in section
    assert "test_the_doh_shape_against_the_synthetic_doh_export" in section
    assert "staat niet in deze repository" in section
    assert not re.search(r"werkbank\s+`[A-Z]+-\d+`", section), "een werkbanklabel hoort er niet in"
    assert not re.search(r"lab-export-vpx-doh-\d{8}", section), "het pad van de ingetrokken fixture hoort er niet in"
    for gone in ("against_a_real_doh_export", "gepseudonimiseerd"):
        assert gone not in section, gone


def _pip_lines(text: str) -> list[str]:
    """Every `pip install` command in `text`, from `-m pip` on, in order."""
    return ["python " + match.group(0).strip() for match in re.finditer(r"-m pip install [^\r\n`]*", text)]


def test_the_readme_quickstart_installs_through_the_hash_locked_route():
    """The release claims hash-locked runtime and build dependencies. That
    claim has to hold for the route the README offers an end user first,
    not only for CI and CONTRIBUTING: the quickstart carries exactly the
    three install lines of CI, in the same order, and no bare editable
    install that would resolve every dependency unpinned."""
    section = _section(_read("README.md"), "## Try it in five minutes")
    ci = _pip_lines(_read(".github/workflows/ci.yml"))
    assert _pip_lines(section) == ci, {"README": _pip_lines(section), "ci.yml": ci}
    assert "--require-hashes" in section


def test_the_readme_names_no_unlocked_install_anywhere():
    """README once said "`pip install -e .` installs the `netscaler-mcp`
    command" in its running section. Every pip line in the README is one of
    the locked lines of CI."""
    ci = set(_pip_lines(_read(".github/workflows/ci.yml")))
    readme = _read("README.md")
    assert "`pip install -e .`" not in readme
    assert set(_pip_lines(readme)) <= ci, set(_pip_lines(readme)) - ci


def test_a_release_tag_gets_its_own_ci_run_and_the_release_notes_name_it():
    """A tag run is the run that belongs to a release: CI runs on a push of a
    `v*` tag next to the release branch, CONTRIBUTING says so, and the
    release-notes template asks for the URL of exactly that run."""
    ci = _read(".github/workflows/ci.yml")
    on_block = ci.split("\non:", 1)[1].split("\npermissions:", 1)[0]
    assert re.search(r'^\s+tags: \["v\*"\]$', on_block, re.MULTILINE), on_block
    assert re.search(r'^\s+branches: \["feat/release-1-0"\]$', on_block, re.MULTILINE), on_block
    release = _section(_read("CONTRIBUTING.md"), "## Release")
    assert "`v*`" in release and ".github/release-notes-template.md" in release
    template = _read(".github/release-notes-template.md")
    assert "https://github.com/" in template and "/actions/runs/" in template
    assert "tag" in template.lower()


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_sso_reference_presenter_is_not_described_as_identifying_the_approver():
    """The reference `sso` presenter (scripts/sso_presenter_windows.py) asks
    the token of its own process who is signed in: that is the account the
    server session runs under, whoever clicks OK - and any process in that
    session can read the box and press OK. The documents must say exactly
    that, say when the channel means something, and repeat the window
    warning for it; the old claim that it identifies the approving person
    is gone from both."""
    readme = _flat(_read("README.md"))
    security = _flat(_read("docs/klant/SECURITY.md"))
    assert "can identify the approving person" not in readme
    assert "De soort `sso` kan het wel" not in security
    assert "sign-in account of the server's session" in readme
    assert "not a verified approver" in readme
    assert "different account or session" in readme
    assert "aanmeldaccount van de serversessie" in security
    assert "geen geverifieerde goedkeurder" in security
    assert "ander account of in een andere sessie" in security
    # The hard condition of the window channel is repeated for `sso`.
    condition = _flat(_section(_read("README.md"), "#### The window channel's hard condition"))
    assert "`sso`" in condition


def test_the_report_button_is_named_with_its_condition_and_email_is_an_equal_route():
    """The private-reporting button exists only while the repository is
    public and the setting is on; a reporter who follows the policy and
    finds no button must not end up at a public issue. The policy names
    the button with that condition and the email address as an equal
    route, never the button as the preferred one."""
    section = _flat(_section(_read("SECURITY.md"), "## Reporting a vulnerability"))
    assert "preferred route" not in section
    assert "equal" in section and "kevin.borger@gjk-partners.nl" in section
    assert "only works while this repository is public" in section


def test_the_changelog_says_why_1_0_0_was_withdrawn_and_keeps_the_dependency_text():
    """1.0.1 replaces a withdrawn 1.0.0. Its section says so first, names the
    fixture swap, and keeps the dependency maintenance it already carried;
    the 1.0.0 section stays as history."""
    text = _read("CHANGELOG.md")
    start = text.index("## [1.0.1] - 2026-10-21")
    section = " ".join(text[start : text.index("## [1.0.0]")].split())
    assert (
        "1.0.0 (tagged 2026-09-30) was published on 2026-10-21 and withdrawn the same day: a test fixture"
        " derived from a real export carried free text that pseudonymisation does not cover."
    ) in section
    assert "replaces that fixture with a synthetic one" in section
    assert "should discard that clone and take 1.0.1" in section
    assert "`mcp` 1.29.0 -> 1.30.0" in section
    assert section.index("withdrawn the same day") < section.index("dependency audit")
    assert "## [1.0.0] - 2026-09-30" in text


# --- Documentation Minors of the public test (1.0.2) ------------------------


def test_the_readme_carries_no_source_line_numbers_that_rot():
    """The Platform section named `mcp_server.py:89`, `disclosure.py:42` and
    `:466`/`:480`; measured a release later, every one of them pointed at
    another line."""
    readme = _read("README.md")
    assert re.findall(r"\b[a-z_]+\.py:\d+", readme) == []
    assert re.findall(r"`:\d+`", readme) == []


def test_the_english_readme_does_not_end_in_a_dutch_internal_chapter():
    readme = _read("README.md")
    assert "## Integratiegrens" not in readme
    assert "externe review" not in readme
    assert "under 40 lines" not in readme


def test_the_readme_explains_the_unknown_tool_error_of_an_unregistered_writing_tool():
    readme = _read("README.md")
    assert "Unknown tool: <name>" in readme and "handelen" in readme
