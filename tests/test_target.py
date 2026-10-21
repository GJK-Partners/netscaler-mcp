import json
from pathlib import Path

import pytest

from nsmcp.target import CertAgreement, Target, TargetError, load_targets


def write(tmp_path: Path, content) -> Path:
    path = tmp_path / "doelen.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def test_target_with_chain_agreement_is_valid():
    target = Target(
        name="lab",
        address="10.0.0.10",
        credential_target="gjk/netscaler/lab/readonly",
        agreement=CertAgreement.CHAIN,
    )
    assert target.fingerprint is None


def test_fingerprint_agreement_without_fingerprint_cannot_exist():
    with pytest.raises(ValueError):
        Target(
            name="lab",
            address="10.0.0.10",
            credential_target="t",
            agreement=CertAgreement.FINGERPRINT,
            fingerprint=None,
        )


def test_chain_agreement_with_fingerprint_cannot_exist():
    """Two agreements at once makes it unclear which one applied - exactly the
    ambiguity the rule must remove."""
    with pytest.raises(ValueError):
        Target(
            name="lab",
            address="10.0.0.10",
            credential_target="t",
            agreement=CertAgreement.CHAIN,
            fingerprint="AA:BB",
        )


def test_agreement_with_wrong_type_is_refused():
    """agreement used to be the only type gate __post_init__ lacked: a string
    that happens to look like an enum value (or any other non-Enum) simply
    built a Target, and read as 'not FINGERPRINT' in every 'is' comparison
    - a silent fallback to chain validation on an object this design must
    not let exist."""
    for value in ("vingerafdruk", None):
        with pytest.raises(ValueError):
            Target(
                name="lab",
                address="1.2.3.4",
                credential_target="t",
                agreement=value,
            )


def test_agreement_as_string_with_fingerprint_gives_valueerror_not_attributeerror():
    """This used to crash with AttributeError ('str' object has no attribute
    'value') because the error message in the chain branch asks for
    self.agreement.value before the type is ever checked. load_targets()
    only catches ValueError - so an AttributeError escaped the TargetError
    contract."""
    with pytest.raises(ValueError):
        Target(
            name="lab",
            address="1.2.3.4",
            credential_target="t",
            agreement="keten",
            fingerprint="AA:BB",
        )


def test_empty_fields_are_refused():
    for field in ("name", "address", "credential_target"):
        fields = {
            "name": "lab",
            "address": "10.0.0.10",
            "credential_target": "t",
            "agreement": CertAgreement.CHAIN,
        }
        fields[field] = "   "
        with pytest.raises(ValueError):
            Target(**fields)


def test_fingerprint_is_normalized():
    """Copying from a certificate dialog yields spaces and lowercase letters.
    That must not mismatch what the collect script returns."""
    target = Target(
        name="lab",
        address="10.0.0.10",
        credential_target="t",
        agreement=CertAgreement.FINGERPRINT,
        fingerprint="aa bb:cc dd",
    )
    assert target.fingerprint == "AABBCCDD"


def test_fingerprint_that_normalizes_to_empty_does_not_survive_the_guard():
    """':' and variants are non-empty before normalization but empty after it.
    If the guard tests the raw value, a Target arises with
    agreement=FINGERPRINT and fingerprint=='' - exactly the state the guard
    must make impossible."""
    for junk in (":", ":::", ": :", "-", "- -"):
        with pytest.raises(ValueError):
            Target(
                name="lab",
                address="10.0.0.10",
                credential_target="t",
                agreement=CertAgreement.FINGERPRINT,
                fingerprint=junk,
            )


def test_load_targets_refuses_fingerprint_that_normalizes_to_empty(tmp_path):
    """The same normalizes-to-empty bypass, but through the file - so a
    fingerprint of ':' does not end up as a valid target on the collect
    command line."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "acc",
                    "adres": "10.0.0.11",
                    "credentialTarget": "t",
                    "certificaat": "vingerafdruk",
                    "vingerafdruk": ":",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_fingerprint_is_also_stripped_of_dashes():
    """Thumbprints are also shown with dashes, depending on the tool."""
    target = Target(
        name="lab",
        address="10.0.0.10",
        credential_target="t",
        agreement=CertAgreement.FINGERPRINT,
        fingerprint="aa-bb:cc dd",
    )
    assert target.fingerprint == "AABBCCDD"


def test_fingerprint_with_wrong_type_is_refused():
    """str(x) is a conversion, not a type gate - name/address/credential_target
    already had that gate, but the fingerprint IS the pin that ends up on
    the collect script's command line. An int, bool, list or dict must not
    silently become 'valid' text there."""
    for value in (12345, True, ["AA", "BB"], {"x": "; whoami"}):
        with pytest.raises(ValueError):
            Target(
                name="lab",
                address="10.0.0.10",
                credential_target="t",
                agreement=CertAgreement.FINGERPRINT,
                fingerprint=value,
            )


def test_fingerprint_with_wrong_type_is_also_refused_under_chain():
    """The type gate in _normalize_fingerprint() runs before the agreement
    branch, so a wrong type under CHAIN gives the same type message as
    under FINGERPRINT ('vingerafdruk moet tekst zijn') and not the
    chain-specific 'staat geen vingerafdruk toe' message. Both fail closed;
    this pins which of the two the code actually gives."""
    with pytest.raises(ValueError, match="vingerafdruk moet tekst zijn"):
        Target(
            name="lab",
            address="10.0.0.10",
            credential_target="t",
            agreement=CertAgreement.CHAIN,
            fingerprint=12345,
        )


def test_chain_agreement_with_non_empty_text_as_fingerprint_is_refused():
    """Fail-closed, not silently dropped: a fingerprint field with a real
    (non-null) text value means something, even when that value happens to
    normalize to nothing. Silently dropping it is exactly the silent
    fallback this design forbids. This does not cover the case where the
    field is explicitly null - that is a separate, accepted route, see
    test_chain_agreement_with_explicit_null_fingerprint_is_valid below."""
    for junk in (":", ":::", ": :", "-", "- -"):
        with pytest.raises(ValueError):
            Target(
                name="lab",
                address="10.0.0.10",
                credential_target="t",
                agreement=CertAgreement.CHAIN,
                fingerprint=junk,
            )


def test_chain_agreement_with_explicit_null_fingerprint_is_valid():
    """Unlike a filled-in (even if normalizing-to-empty) text: a fingerprint
    field that is explicitly None/null equals no field at all - that must
    simply stay valid under CHAIN. Pinned so this is a deliberate, tested
    outcome and not an accidentally accepted side effect."""
    target = Target(
        name="lab",
        address="10.0.0.10",
        credential_target="t",
        agreement=CertAgreement.CHAIN,
        fingerprint=None,
    )
    assert target.fingerprint is None


def test_load_targets_refuses_chain_target_with_fingerprint_field(tmp_path):
    """The same refusal, but through the file - so a chain target with a
    (normalizing-to-empty) fingerprint field does not silently end up as a
    valid target for the collect path."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "vingerafdruk": ":",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_load_targets_accepts_explicit_null_fingerprint_under_chain(tmp_path):
    """The same accepted outcome as with Target() above, but through the file:
    {"certificaat": "keten", "vingerafdruk": null} loads and yields
    fingerprint=None - pinned deliberately, so it does not remain an
    accidental side effect."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "vingerafdruk": None,
                }
            ]
        },
    )
    targets = load_targets(path)
    assert targets["x"].fingerprint is None


def test_load_targets_reads_a_file(tmp_path):
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "lab",
                    "adres": "10.0.0.10",
                    "credentialTarget": "gjk/netscaler/lab/readonly",
                    "certificaat": "keten",
                },
                {
                    "naam": "acc",
                    "adres": "10.0.0.11",
                    "credentialTarget": "gjk/netscaler/acc/readonly",
                    "certificaat": "vingerafdruk",
                    "vingerafdruk": "aa:bb:cc",
                },
            ]
        },
    )
    targets = load_targets(path)
    assert set(targets) == {"lab", "acc"}
    assert targets["lab"].agreement is CertAgreement.CHAIN
    assert targets["acc"].fingerprint == "AABBCC"


def test_missing_file_yields_no_targets_and_no_error(tmp_path):
    """Without a targets file the server simply runs on a supplied export.
    That is the service profile and it must keep working."""
    assert load_targets(tmp_path / "bestaat-niet.json") == {}


def test_unknown_certificate_agreement_is_refused(tmp_path):
    """A typo must not become a silent fallback to a weaker agreement."""
    path = write(
        tmp_path,
        {"doelen": [{"naam": "x", "adres": "1.2.3.4", "credentialTarget": "t", "certificaat": "overslaan"}]},
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_a_password_in_the_configuration_is_refused(tmp_path):
    """Only the credential target name belongs here. Whoever puts down a
    password anyway must notice before the file lands in some backup."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "wachtwoord": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_broken_json_gives_a_clear_error(tmp_path):
    path = tmp_path / "doelen.json"
    path.write_text("{ dit is geen json", encoding="utf-8")
    with pytest.raises(TargetError):
        load_targets(path)


def test_forbidden_key_is_recognized_case_insensitively(tmp_path):
    """The key list is deliberately lowercase; 'Password' is exactly what
    someone types in an otherwise camelCase file and must not slip through
    on casing."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "Password": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_forbidden_key_one_level_deeper_is_also_detected(tmp_path):
    """A secret one level deeper leaks just as much as a secret at the top of
    a target entry."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "credentials": {"password": "geheim"},
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_forbidden_key_outside_the_targets_list_is_also_detected(tmp_path):
    """A secret next to 'doelen' instead of inside it is no less of a leak."""
    path = write(
        tmp_path,
        {
            "apiKey": "geheim",
            "doelen": [{"naam": "x", "adres": "1.2.3.4", "credentialTarget": "t", "certificaat": "keten"}],
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_forbidden_key_at_great_depth_gives_no_recursionerror(tmp_path):
    """The search function (_forbidden_keys) walks with its own stack and must
    not recurse into a RecursionError while doing it - that would escape the
    TargetError contract, the same defect class as the broken-JSON case,
    introduced by the fix itself. The secret planted at depth must also really
    be found - a depth limit that silently stops earlier must not get away
    with it here, so this tests one outcome (found) instead of 'no crash'.

    Depth used to be 2000, on the premise that json.dumps/json.loads handle
    that "without trouble" on every supported Python. Measured true on CPython
    3.12.10 (survives past 2997 in this venv), but false on CPython 3.11 (also
    in the CI matrix): there, this test's own write() helper raises
    RecursionError from json.dumps() before load_targets() ever runs.
    target.py has no MAX_JSON_DEPTH ceiling of its own (it does not import
    nsmcp.limits), so 300 is chosen only to stay deep enough to be a real
    stress test of the iterative search while comfortably under every
    supported CPython's json RecursionError zone."""
    depth = 300
    nested: dict = {"password": "geheim"}
    for _ in range(depth):
        nested = {"laag": nested}
    path = write(
        tmp_path,
        {
            "doelen": [{"naam": "x", "adres": "1.2.3.4", "credentialTarget": "t", "certificaat": "keten"}],
            "genest": nested,
        },
    )
    with pytest.raises(TargetError, match="password"):
        load_targets(path)


def test_clientsecret_is_recognized_as_a_forbidden_key(tmp_path):
    """Stem matching, not exact match: 'apisecret' was already on the old
    list, but 'clientSecret' - a far more common key name - was not."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "clientSecret": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_accesstoken_is_recognized_as_a_forbidden_key(tmp_path):
    """'accessToken' is a more common key name than the exact 'token' the old
    list already covered."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "accessToken": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_api_key_with_underscore_is_recognized_as_a_forbidden_key(tmp_path):
    """'apikey' without an underscore was already on the old list, but
    'api_key' - just as common - was not."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "api_key": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_api_key_with_hyphen_is_recognized_as_a_forbidden_key(tmp_path):
    """'api_key' (underscore) was already on the list, but 'api-key' (hyphen)
    was not - an equally common spelling."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "api-key": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_x_api_key_header_name_is_recognized_as_a_forbidden_key(tmp_path):
    """'x-api-key' is the common HTTP header name for an API key and must be
    recognized just like 'apiKey' itself."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "x-api-key": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_passphrase_is_recognized_as_a_forbidden_key(tmp_path):
    """'passphrase' covers certificate/key passwords that do not fall under
    'password' but are just as sensitive."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "t",
                    "certificaat": "keten",
                    "passphrase": "geheim",
                }
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_credentialtarget_stays_allowed_despite_stem_matching(tmp_path):
    """Regression test: the stem matching must not give a false positive on
    the ONLY key that belongs here. 'credentialTarget' contains none of the
    forbidden stems - an error here breaks every valid configuration."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {
                    "naam": "x",
                    "adres": "1.2.3.4",
                    "credentialTarget": "gjk/netscaler/lab/readonly",
                    "certificaat": "keten",
                }
            ]
        },
    )
    targets = load_targets(path)
    assert targets["x"].credential_target == "gjk/netscaler/lab/readonly"


def test_credential_target_null_is_refused(tmp_path):
    """JSON null must not silently become the text 'None' - that ends up
    literally on the collect script's command line."""
    path = write(
        tmp_path,
        {"doelen": [{"naam": "x", "adres": "1.2.3.4", "credentialTarget": None, "certificaat": "keten"}]},
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_address_as_number_is_refused(tmp_path):
    """str(10) == '10' looks valid but is not an address someone filled in -
    it is a number that happens to be expressible as text."""
    path = write(
        tmp_path,
        {"doelen": [{"naam": "x", "adres": 10, "credentialTarget": "t", "certificaat": "keten"}]},
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_name_as_list_is_refused(tmp_path):
    path = write(
        tmp_path,
        {"doelen": [{"naam": ["a", "b"], "adres": "1.2.3.4", "credentialTarget": "t", "certificaat": "keten"}]},
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_top_level_list_gives_target_error_not_a_raw_traceback(tmp_path):
    """Forgetting the {'doelen': ...} wrapper must not leak an AttributeError
    - that is not a Dutch error message."""
    path = tmp_path / "doelen.json"
    path.write_text(json.dumps([{"naam": "lab"}]), encoding="utf-8")
    with pytest.raises(TargetError):
        load_targets(path)


def test_targets_as_object_gives_target_error_not_a_raw_traceback(tmp_path):
    path = write(tmp_path, {"doelen": {"lab": {"naam": "lab"}}})
    with pytest.raises(TargetError):
        load_targets(path)


def test_targets_as_number_gives_target_error_not_a_raw_traceback(tmp_path):
    path = write(tmp_path, {"doelen": 5})
    with pytest.raises(TargetError):
        load_targets(path)


def test_targets_list_with_text_gives_target_error_not_a_raw_traceback(tmp_path):
    path = write(tmp_path, {"doelen": ["lab"]})
    with pytest.raises(TargetError):
        load_targets(path)


def test_missing_doelen_key_is_refused(tmp_path):
    """A typo in the key name ('targets' instead of 'doelen') must not
    silently mean 'scan nothing' - that is a configuration error."""
    path = write(
        tmp_path,
        {"targets": [{"naam": "x", "adres": "1.2.3.4", "credentialTarget": "t", "certificaat": "keten"}]},
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_explicitly_empty_targets_list_stays_valid(tmp_path):
    """A deliberately empty list differs from a missing key: this is a valid
    configuration that yields zero targets."""
    path = write(tmp_path, {"doelen": []})
    assert load_targets(path) == {}


def test_path_to_a_directory_gives_target_error_not_a_raw_traceback(tmp_path):
    """path.exists() is also true for a directory; read_text() then blows up
    on IsADirectoryError - which, like every other read error, must become
    a TargetError."""
    with pytest.raises(TargetError):
        load_targets(tmp_path)


def test_duplicate_key_in_a_target_is_refused(tmp_path):
    """The same gap as in start.py's load_config() - this loader feeds the
    same server, so the same hook belongs here too. 'naam' occurs twice
    inside ONE target object here (nested level, inside the 'doelen'
    list); without the hook json.loads() would silently let the last one
    ('ns02') win."""
    path = tmp_path / "doelen.json"
    path.write_text(
        '{"doelen": [{"naam": "ns01", "naam": "ns02", "adres": "10.0.0.1", '
        '"credentialTarget": "t", "certificaat": "keten"}]}',
        encoding="utf-8",
    )
    with pytest.raises(TargetError, match="naam.*dubbel"):
        load_targets(path)


def test_duplicate_name_is_refused(tmp_path):
    """Two targets with the same name leaves ambiguous which address and
    which agreement belong to that name."""
    path = write(
        tmp_path,
        {
            "doelen": [
                {"naam": "lab", "adres": "1.2.3.4", "credentialTarget": "t1", "certificaat": "keten"},
                {"naam": "lab", "adres": "5.6.7.8", "credentialTarget": "t2", "certificaat": "keten"},
            ]
        },
    )
    with pytest.raises(TargetError):
        load_targets(path)


def test_name_is_stored_trimmed():
    """The duplicate-name check compares the stored name - so it must really
    be stored trimmed, not merely tested trimmed."""
    target = Target(
        name=" lab ",
        address="10.0.0.10",
        credential_target="t",
        agreement=CertAgreement.CHAIN,
    )
    assert target.name == "lab"
