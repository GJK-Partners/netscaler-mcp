"""The three words a piece of reading advice may carry about itself."""

from nsmcp.advice import ADVICE_CAN, ADVICE_MANUAL, ADVICE_NOT_ALLOWED, ADVICE_WORDS, advice_label
from nsmcp.handelen import Allowlist

ALLOWLIST = Allowlist(
    per_target={
        "lab": {
            "certificaat_vervangen": {
                "dienst": ("lb_vs_portaal_443",),
                "nieuwcert": ("portaal-2027",),
            },
            "onderhoud_backup_maken": True,
        }
    }
)


def test_an_item_with_no_tool_at_all_is_a_manual_action():
    assert advice_label(None, {}, target="lab", allowlist=ALLOWLIST) == ADVICE_MANUAL


def test_an_allowed_object_gets_the_can_word():
    label = advice_label(
        "certificaat_vervangen",
        {"dienst": "lb_vs_portaal_443", "nieuwcert": "portaal-2027"},
        target="lab",
        allowlist=ALLOWLIST,
    )
    assert label == ADVICE_CAN


def test_an_object_outside_the_allowlist_gets_the_not_allowed_word():
    label = advice_label(
        "certificaat_vervangen",
        {"dienst": "lb_vs_iets_anders", "nieuwcert": "portaal-2027"},
        target="lab",
        allowlist=ALLOWLIST,
    )
    assert label == ADVICE_NOT_ALLOWED


def test_an_objectless_action_follows_the_on_off_switch():
    assert advice_label("onderhoud_backup_maken", {}, target="lab", allowlist=ALLOWLIST) == ADVICE_CAN
    switched_off = Allowlist(per_target={"lab": {"onderhoud_backup_maken": False}})
    assert advice_label("onderhoud_backup_maken", {}, target="lab", allowlist=switched_off) == ADVICE_NOT_ALLOWED


def test_without_a_configured_allowlist_the_label_fails_closed():
    """Geen allowlist betekent niet 'alles mag'."""
    assert advice_label("certificaat_vervangen", {}, target=None, allowlist=None) == ADVICE_NOT_ALLOWED
    assert (
        advice_label("certificaat_vervangen", {}, target="lab", allowlist=Allowlist(per_target={}))
        == ADVICE_NOT_ALLOWED
    )


def test_an_unknown_target_fails_closed_too():
    """Fail-closed op de derde vorm van 'geen doel': een doelnaam die de
    allowlist niet kent. Zonder deze test blijft een mutatie die alleen op
    `target=None` zou controleren groen, terwijl een onbekend doel dan het
    can-woord zou krijgen.
    """
    assert (
        advice_label(
            "certificaat_vervangen",
            {"dienst": "lb_vs_portaal_443", "nieuwcert": "portaal-2027"},
            target="ander_doel",
            allowlist=ALLOWLIST,
        )
        == ADVICE_NOT_ALLOWED
    )


def test_an_unknown_tool_fails_closed_instead_of_raising():
    """Een label mag nooit de leestool laten crashen: een gereedschapsnaam
    die dit product niet kent is 'niet in de allowlist', geen ActionError
    die door de leeskant heen slaat.
    """
    assert advice_label("bestaat_niet", {}, target="lab", allowlist=ALLOWLIST) == ADVICE_NOT_ALLOWED


def test_the_reading_advice_labels_every_item_with_one_of_three_words():
    for tool, args in (
        (None, {}),
        ("certificaat_vervangen", {"dienst": "lb_vs_portaal_443", "nieuwcert": "portaal-2027"}),
        ("certificaat_vervangen", {"dienst": "onbekend", "nieuwcert": "portaal-2027"}),
        ("onderhoud_backup_maken", {}),
    ):
        assert advice_label(tool, args, target="lab", allowlist=ALLOWLIST) in ADVICE_WORDS


# ---------------------------------------------------------------------------
# Een waarde die de LEESKANT nog niet kent.
#
# Een leesadvies dat zegt "zet het nieuwe certificaat klaar" kent de naam van
# dat nieuwe certificaat niet: de beheerder heeft hem nog niet gekozen. Het
# label mag dan niet doen alsof het die naam beoordeelt. `None` als waarde
# betekent daarom: deze waarde weet de leeskant nog niet - en de eerlijke
# vraag wordt: heeft de beheerder voor dit argument op dit doel UBERHAUPT
# iets toegestaan?
# ---------------------------------------------------------------------------


def test_a_value_the_reading_side_does_not_know_asks_whether_anything_is_approved():
    """`nieuwcert=None`: de allowlist staat er een waarde voor toe, dus de
    beheerder heeft hier schrijfruimte gegeven en het can-woord is eerlijk -
    ook al noemt het advies de uiteindelijke naam niet.
    """
    assert (
        advice_label(
            "certificaat_vervangen",
            {"dienst": "lb_vs_portaal_443", "nieuwcert": None},
            target="lab",
            allowlist=ALLOWLIST,
        )
        == ADVICE_CAN
    )


def test_an_unknown_value_fails_closed_when_the_allowlist_approves_nothing_for_it():
    """Tegenproef: hetzelfde doel, hetzelfde gereedschap, maar voor
    `nieuwcert` staat geen enkele waarde op de lijst. Dan is er geen
    schrijfruimte en blijft het label fail-closed.
    """
    nothing_approved = Allowlist(
        per_target={
            "lab": {
                "certificaat_vervangen": {"dienst": ("lb_vs_portaal_443",), "nieuwcert": ()},
            }
        }
    )
    assert (
        advice_label(
            "certificaat_vervangen",
            {"dienst": "lb_vs_portaal_443", "nieuwcert": None},
            target="lab",
            allowlist=nothing_approved,
        )
        == ADVICE_NOT_ALLOWED
    )


def test_a_known_value_next_to_an_unknown_one_is_still_judged_exactly():
    """`None` verzwakt alleen het argument dat de leeskant niet kent. Een
    argument met een echte waarde - hier de virtuele server - wordt gewoon
    tegen de allowlist gelegd.
    """
    assert (
        advice_label(
            "certificaat_vervangen",
            {"dienst": "lb_vs_iets_anders", "nieuwcert": None},
            target="lab",
            allowlist=ALLOWLIST,
        )
        == ADVICE_NOT_ALLOWED
    )


def test_an_unknown_value_still_runs_through_the_denylist_and_the_grammar():
    """Er is EEN beslispad: `validate()`. De ingevulde vervangwaarde gaat
    daar net zo goed doorheen, dus een allowlist die alleen een naam van de
    ingebouwde denylist toestaat levert nooit het can-woord op.
    """
    denied_only = Allowlist(
        per_target={
            "lab": {
                "certificaat_vervangen": {
                    "dienst": ("lb_vs_portaal_443",),
                    "nieuwcert": ("nshttps-127.0.0.1-443",),
                },
            }
        }
    )
    assert (
        advice_label(
            "certificaat_vervangen",
            {"dienst": "lb_vs_portaal_443", "nieuwcert": None},
            target="lab",
            allowlist=denied_only,
        )
        == ADVICE_NOT_ALLOWED
    )


def test_an_unknown_value_on_an_unknown_target_fails_closed():
    """`None` mag geen sluiproute om de doelcontrole heen zijn."""
    assert (
        advice_label(
            "certificaat_vervangen",
            {"dienst": "lb_vs_portaal_443", "nieuwcert": None},
            target="ander_doel",
            allowlist=ALLOWLIST,
        )
        == ADVICE_NOT_ALLOWED
    )
