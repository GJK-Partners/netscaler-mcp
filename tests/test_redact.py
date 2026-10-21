"""The one door where a running-config line loses what it must never carry.

Why this exists and why it cannot be a scanner. The NetScaler credential
format is not recognised by detect-secrets or by GitHub secret scanning
(measured), so a line like `set ns rpcNode 10.0.0.1
-password <blob> -encrypted` would travel unnoticed. A5 (hidden rules) and B3
(pre-flight) both grep over the running config and report a verdict WITH a
line number; without this filter the line TEXT could ride along as evidence
into an answer, a report or a log line.

Every fixture line here is synthetic. A real credential never enters a test.

An earlier version of this filter - an
allowlist of COMMAND HEADS - let the whole authentication-action family
through unredacted, redacted a line that carries no credential
at all, and shipped two code paths with no test behind them at
all. The tests below that are new for that hardening pass are
grouped and say so.
"""

from __future__ import annotations

from nsmcp.redact import REDACTION_NOTE, redact_config_line, redact_config_lines

SECRET = "AAAAsecretpayloadAAAA"
SECRET2 = "BBBBsecretpayloadBBBB"


def test_an_ordinary_line_is_returned_untouched():
    line = "add lb vserver web HTTP 10.0.0.9 80 -persistenceType COOKIEINSERT"
    assert redact_config_line(line) == line


def test_the_rpc_node_password_never_survives():
    out = redact_config_line(f"set ns rpcNode 10.0.0.1 -password {SECRET} -encrypted")
    assert SECRET not in out
    assert out == f"set ns rpcNode 10.0.0.1 {REDACTION_NOTE}"


def test_a_system_user_line_keeps_the_name_and_loses_the_rest():
    out = redact_config_line(f"set system user beheerder {SECRET} -encrypted")
    assert out == f"set system user beheerder {REDACTION_NOTE}"


# ---------------------------------------------------------------------------
# Regression. An earlier fix deleted the untested `add system
# user` rule instead of testing it, which silently reopened the exact leak
# the rule existed to close: a direct probe of the shipped filter
# found the secret intact on all three `add system user` shapes below. The
# rule is restored, merged with `set` into one pattern, and this time every
# shape it covers has its own test.
# ---------------------------------------------------------------------------


def test_an_add_system_user_line_keeps_the_name_and_loses_the_rest():
    """The plain create form, symmetric with the `set` test above: the
    password is positional (no flag name at all), so only the class-3 rule
    on the command itself can catch it."""
    out = redact_config_line(f"add system user beheerder {SECRET}")
    assert SECRET not in out
    assert out == f"add system user beheerder {REDACTION_NOTE}"


def test_an_add_system_user_line_with_encrypted_flag_is_redacted():
    """The controller's first leak: with the rule missing, a bare
    `-encrypted` (no `-encryptmethod`) is outside class 1 (no named
    parameter flag at all) and outside class 2 (the backstop needs BOTH
    flags), so the line came back completely unchanged, secret intact."""
    out = redact_config_line(f"add system user beheerder {SECRET} -encrypted")
    assert SECRET not in out
    assert out == f"add system user beheerder {REDACTION_NOTE}"


def test_an_add_system_user_line_with_encryptmethod_does_not_leak_in_the_kept_head():
    """The controller's third leak, and the sharpest one: with the rule
    missing, the `-encrypted`/`-encryptmethod` backstop DID fire, but its
    cut point is the first FLAG-shaped token - which sits AFTER the
    positional password on this shape - so the backstop kept 'add system
    user beheerder <secret>' in its own head and the secret survived
    anyway. The restored class-3 rule is checked first and cuts at the
    username (token 4), before the password (token 5) is ever reached."""
    out = redact_config_line(f"add system user beheerder {SECRET} -encrypted -encryptmethod ENCMTHD_3")
    assert SECRET not in out
    assert out == f"add system user beheerder {REDACTION_NOTE}"


def test_an_aaa_user_line_is_redacted():
    """The original version of this test only asserted the secret's
    ABSENCE, which would also pass for a function that returned an empty
    string or dropped the line outright. Assert the full expected output,
    like its neighbours."""
    out = redact_config_line(f"add aaa user gast -password {SECRET}")
    assert out == f"add aaa user gast {REDACTION_NOTE}"


def test_the_encryption_parameters_line_keeps_nothing_but_its_head():
    out = redact_config_line(f"set ns encryptionParams -method AES256 -keyValue {SECRET}")
    assert out == f"set ns encryptionParams {REDACTION_NOTE}"


def test_a_monitor_line_is_only_redacted_when_it_carries_a_password():
    plain = "add lb monitor mon_http HTTP -respCode 200"
    assert redact_config_line(plain) == plain
    out = redact_config_line(f"add lb monitor mon_ldap LDAP -password {SECRET}")
    assert out == f"add lb monitor mon_ldap LDAP {REDACTION_NOTE}"


def test_the_redaction_says_what_it_did_and_never_pretends_the_line_was_absent():
    """A silently dropped line would be a read gap this product never named.
    The line stays, its head stays, and the note says why the tail is gone."""
    out = redact_config_line(f"set ns rpcNode 10.0.0.1 -password {SECRET}")
    assert "geredigeerd" in out
    assert out.startswith("set ns rpcNode")


def test_the_list_form_keeps_the_line_numbering_intact():
    """A rule reports a LINE NUMBER as evidence. Dropping a line would shift
    every number after it."""
    lines = [
        "#NS14.1 Build 72.57",
        f"set ns rpcNode 10.0.0.1 -password {SECRET}",
        "add lb vserver web HTTP 10.0.0.9 80",
    ]
    out = redact_config_lines(lines)
    assert len(out) == 3
    assert out[0] == lines[0]
    assert out[2] == lines[2]
    assert SECRET not in "\n".join(out)


# ---------------------------------------------------------------------------
# `-ssoCredential` on `vpn sessionAction` is the
# documented enum PRIMARY | SECONDARY - which credential SET to use for
# single sign-on, not a secret itself (verified against the vendor CLI
# reference for `vpn sessionAction`: "specifies whether to use the primary or
# secondary authentication credentials for single sign-on"; possible values
# PRIMARY, SECONDARY). The original rule that redacted this line was added
# because the collector's OWN keyword-based masker had blanked it in the real
# fixture - but that same masker also blanks `-lastpwdchangetimestamp` (a
# timestamp, fixture line 7) and `-isPasswdIntSet` (a boolean, fixture line
# 77), so the masker proves its own crudeness, not this shape's danger. The
# original rule also truncated real Gateway lines from ~16-20 parameters down
# to four tokens, discarding -clientlessVpnMode, -icaProxy, -splitTunnel,
# -transparentInterception, -wihome and -SSO - attributes CVE rules narrow
# on - while telling the operator an ordinary session policy "kan een
# credential dragen", which is false. The rule and both of its tests are
# removed; a plain `vpn sessionAction` line, `-ssoCredential` included, is
# simply an ordinary line under `test_an_ordinary_line_is_returned_untouched`
# now.
# ---------------------------------------------------------------------------


def test_a_vpn_session_action_line_with_sso_credential_is_no_longer_touched():
    line = (
        "add vpn sessionAction NSG_SES_PRO_VPN -sessTimeout 65535 -SSO ON "
        '-ssoCredential PRIMARY -icaProxy OFF -wihome "https://host-003.lab.example/x"'
    )
    assert redact_config_line(line) == line


# ---------------------------------------------------------------------------
# The original filter was an allowlist of COMMAND HEADS;
# on NetScaler the secret is marked by the PARAMETER NAME and by a universal
# suffix (every encrypted blob is followed by `-encrypted -encryptmethod
# ENCMTHD_n`), so an allowlist of commands could never be complete - it
# missed the entire authentication-action family. One test per shape was
# probed. Every secret value below is synthetic.
# ---------------------------------------------------------------------------


def test_ldap_action_bind_dn_password_is_redacted():
    line = (
        f"add authentication ldapAction ldap1 -serverIP 10.0.0.5 "
        f"-ldapBindDnPassword {SECRET} -encrypted -encryptmethod ENCMTHD_4"
    )
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication ldapAction ldap1 -serverIP 10.0.0.5 {REDACTION_NOTE}"


def test_ldap_params_bind_dn_password_is_redacted():
    out = redact_config_line(f"set aaa ldapParams -ldapBindDnPassword {SECRET} -encrypted")
    assert SECRET not in out
    assert out == f"set aaa ldapParams {REDACTION_NOTE}"


def test_radius_action_radkey_is_redacted():
    line = f"add authentication radiusAction rad1 -radKey {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication radiusAction rad1 {REDACTION_NOTE}"


def test_radius_params_radkey_is_redacted():
    out = redact_config_line(f"set aaa radiusParams -radKey {SECRET} -encrypted")
    assert SECRET not in out
    assert out == f"set aaa radiusParams {REDACTION_NOTE}"


def test_certkey_passcrypt_is_redacted_but_the_filenames_before_it_survive():
    line = f"add ssl certKey mycert -cert x.crt -key x.key -passcrypt {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add ssl certKey mycert -cert x.crt -key x.key {REDACTION_NOTE}"


def test_tacacs_action_secret_is_redacted():
    line = f"add authentication tacacsAction tac1 -tacacsSecret {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication tacacsAction tac1 {REDACTION_NOTE}"


def test_snmp_user_auth_and_priv_passwords_are_both_redacted_by_one_cut():
    """Two secret-bearing flags on one line. The filter cuts at the FIRST
    one and drops everything after it, so the second (-privPasswd) never
    needs its own match to be gone too."""
    line = f"add snmp user snmpuser1 -authType SHA -authPasswd {SECRET} -privType AES -privPasswd {SECRET2} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert SECRET2 not in out
    assert out == f"add snmp user snmpuser1 -authType SHA {REDACTION_NOTE}"


def test_kcd_account_password_is_redacted():
    line = f"add aaa kcdAccount kcd1 -kcdPassword {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add aaa kcdAccount kcd1 {REDACTION_NOTE}"


def test_a_monitor_line_using_set_and_radkey_is_redacted():
    """Two defects closed in one test: the `set` form of this rule
    had no test at all, and the rule fired only on `-password`, missing
    `-radKey` - exactly the form the real bundled fixture uses for its
    RADIUS-style monitors (lines 78-79 use `set` and `-password`; this shape
    substitutes `-radKey` to prove the fix, not just the pre-existing half)."""
    line = f"set lb monitor mon_radius RADIUS -radKey {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"set lb monitor mon_radius RADIUS {REDACTION_NOTE}"


def test_snmp_community_string_is_redacted():
    """The community string itself IS the credential; it carries no flag
    name at all, so this needed its own rule rather than the parameter-name
    one."""
    out = redact_config_line(f"add snmp community {SECRET} ALL")
    assert SECRET not in out
    assert out == f"add snmp community {REDACTION_NOTE}"


def test_oauth_action_client_secret_is_redacted():
    line = f"add authentication OAuthAction oauth1 -clientSecret {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication OAuthAction oauth1 {REDACTION_NOTE}"


def test_db_user_password_is_redacted():
    line = f"add db user dbuser1 -password {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add db user dbuser1 {REDACTION_NOTE}"


def test_ipsec_profile_psk_is_redacted():
    out = redact_config_line(f"add ipsec profile ips1 -psk {SECRET}")
    assert SECRET not in out
    assert out == f"add ipsec profile ips1 {REDACTION_NOTE}"


def test_aaa_user_set_form_is_redacted():
    """The original rule anchored on `add` only; a `set aaa user` line
    with the same `-password` flag came back byte-identical, secret intact."""
    out = redact_config_line(f"set aaa user gast -password {SECRET}")
    assert SECRET not in out
    assert out == f"set aaa user gast {REDACTION_NOTE}"


def test_the_encrypted_backstop_catches_a_parameter_name_outside_the_list():
    """The LAST line of defence: a command and a parameter name this module
    has never named at all, but the universal `-encrypted -encryptmethod`
    pair still marks it as a stored secret."""
    line = f"add authentication samlAction sam1 -someFutureSecretKey {SECRET} -encrypted -encryptmethod ENCMTHD_4"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication samlAction sam1 {REDACTION_NOTE}"


def test_a_single_unnamed_flag_without_the_full_encrypted_pair_is_not_caught():
    """The documented boundary of the closed set (module docstring): a
    parameter name outside class 1, on a line that carries only ONE of
    -encrypted / -encryptmethod, is outside class 2 too and passes through
    unfiltered. Not a defect - the module's contract is a closed set, not a
    guess about content - but a real gap this test keeps visible rather than
    silent."""
    line = f"add authentication samlAction sam1 -someFutureSecretKey {SECRET} -encrypted"
    assert redact_config_line(line) == line


# ---------------------------------------------------------------------------
# `_token_head` used to re-join `text.split()`, which
# both normalises whitespace (a redacted line was no longer a PREFIX of the
# original) and cuts a quoted, space-carrying object name in half, leaving an
# unbalanced quote behind. `cve.py::_tokens` reads that unbalanced quote as
# UNREADABLE and `_reduce_config` counts it - so the bug could manufacture a
# read gap on a line this product actually read perfectly. See
# tests/test_cve.py::test_redaction_of_a_quoted_name_never_manufactures_a_read_gap
# for the integration-level proof.
# ---------------------------------------------------------------------------


def test_a_quoted_object_name_with_spaces_survives_redaction_intact():
    line = f'add aaa user "jan de vries" -password {SECRET}'
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f'add aaa user "jan de vries" {REDACTION_NOTE}'
    # The quote is BALANCED - an even number, never a dangling open quote.
    assert out.count('"') % 2 == 0


# ---------------------------------------------------------------------------
# Stripping `re.IGNORECASE` from every pattern left the
# suite green; nothing exercised a mixed-case or unusually-indented line.
# ---------------------------------------------------------------------------


def test_the_parameter_name_rule_is_case_insensitive():
    line = f"ADD AUTHENTICATION RADIUSACTION RAD1 -RADKEY {SECRET} -ENCRYPTED"
    out = redact_config_line(line)
    assert SECRET not in out
    assert REDACTION_NOTE in out
    assert out.startswith("ADD AUTHENTICATION RADIUSACTION RAD1")


def test_a_tab_indented_line_is_still_redacted():
    line = f"\tset ns rpcNode 10.0.0.1 -password {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"\tset ns rpcNode 10.0.0.1 {REDACTION_NOTE}"


# ---------------------------------------------------------------------------
# The OTHER direction of the same mistake: this filter was broadened until
# nothing leaked; a later pass then
# probed what the broadened filter DESTROYS on lines carrying no secret, and
# found two defects on the paths that broadening had introduced or widened.
#
#   THE QUOTE-UNBALANCED CUT - the class-1 and class-2 cuts used a raw
#        `text[:match.start()]`, which
#        lands inside a quoted run and leaves an UNBALANCED quote behind.
#        `cve.py::_tokens` reads that as unreadable and `_reduce_config`
#        counts it, so the filter manufactured a read gap on a line this
#        product read perfectly (the same defect reopened on the two newest cut
#        paths). Measured before the fix: the responder policy below came back
#        as `... CONTAINS(\"/reset <note>` - one dangling quote, the whole
#        responder definition gone.
#   THE ANCHOR-LESS SUBSTRING MATCH - the `lb monitor` rule matched
#        `-password` / `-radKey` as bare
#        SUBSTRINGS, without the token-start anchor every class-1 flag
#        carries, so an ordinary health-check monitor lost its probe
#        definition to `/reset-password` inside a quoted -httpRequest.
#
# Every line in this group carries NO credential. The assertion is therefore
# byte-identity plus balanced quoting, not absence of a secret.
# ---------------------------------------------------------------------------


def _quoting_closes(text: str) -> bool:
    """Whether `text` leaves a quote open, read the way `cve.py::_tokens`
    reads a running-config line: a double quote toggles quoting, and inside a
    quoted run a backslash escapes a quote or a backslash. A plain
    `count('"') % 2` cannot answer this on the real export's policy
    expressions, which are full of escaped quotes."""
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if quoted and char == "\\" and index + 1 < len(text) and text[index + 1] in '"\\':
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        index += 1
    return not quoted


def test_a_responder_policy_naming_a_password_flag_in_its_expression_is_untouched():
    """The quote-unbalanced cut's headline shape: `-password` sits INSIDE the quoted expression, so
    the line carries no credential at all. Before the fix the class-1 cut
    landed between the two quotes."""
    line = 'add responder policy pol_block_pwreset "HTTP.REQ.URL.PATH.CONTAINS(\\"/reset -password\\")" act_drop'
    out = redact_config_line(line)
    assert out == line
    assert _quoting_closes(out)


def test_a_rewrite_policy_naming_psk_in_its_expression_is_untouched():
    """The same defect on a second class-1 flag name, to show it was not one
    unlucky word: `-psk` inside a rewrite policy expression."""
    line = 'add rewrite policy pol_pwreset "HTTP.REQ.URL.CONTAINS(\\"/portal -psk-reset\\")" act_rewrite'
    out = redact_config_line(line)
    assert out == line
    assert _quoting_closes(out)


def test_a_health_check_monitor_naming_a_password_url_keeps_its_probe():
    """The anchor-less substring match, first shape: `-password` matched inside `/reset-password` because
    the monitor rule carried no token-start anchor. An ordinary HTTP monitor
    lost -respCode, -httpRequest and -recv - everything that says what it
    actually probes."""
    line = 'add lb monitor mon_authcheck HTTP -respCode 200 -httpRequest "GET /reset-password HTTP/1.0" -recv "OK"'
    out = redact_config_line(line)
    assert out == line
    assert _quoting_closes(out)


def test_a_health_check_monitor_naming_radkey_inside_a_send_string_keeps_its_probe():
    """The anchor-less substring match, second shape: `-radKey` matched inside `check-radKey-status`. An
    earlier fix added `-radKey` to this rule without auditing the anchor the rule never
    had."""
    line = 'set lb monitor mon_custom TCP-ECV -send "check-radKey-status" -recv "OK" -interval 5'
    out = redact_config_line(line)
    assert out == line
    assert _quoting_closes(out)


def test_a_monitor_send_string_with_a_flag_shaped_word_keeps_its_probe():
    """The anchor alone is not enough here: in `"check -radKey status"` the
    word IS at a whitespace-token start, and only reading the quoting keeps
    this monitor whole."""
    line = 'set lb monitor mon_probe TCP-ECV -send "check -radKey status" -recv "OK" -interval 5'
    out = redact_config_line(line)
    assert out == line
    assert _quoting_closes(out)


def test_a_quoted_object_name_carrying_a_flag_name_is_not_a_flag():
    """A quoted NAME, not an expression - the third place the unanchored,
    unquoted match fired. Leading indentation survives too, because every cut
    is a true prefix of the original line."""
    line = '    add service "svc -keyValue demo" 10.0.0.9 SSL 443 -gslb NONE'
    out = redact_config_line(line)
    assert out == line
    assert _quoting_closes(out)


# ---------------------------------------------------------------------------
# The same quote-safety, now on lines that DO carry a
# secret. The cut must still happen; what it may not do is end inside a
# quoted run.
# ---------------------------------------------------------------------------


def test_a_class_one_cut_after_a_quoted_name_leaves_the_quote_balanced():
    """The class-1 path: a quoted, space-carrying object name sits before the
    secret-bearing flag. The cut lands at the flag, so the whole quoted name
    survives and the quoting closes."""
    line = f'add ssl certKey "my cert" -cert x.crt -passcrypt {SECRET} -encrypted'
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f'add ssl certKey "my cert" -cert x.crt {REDACTION_NOTE}'
    assert _quoting_closes(out)


def test_the_encrypted_backstop_never_cuts_inside_a_quoted_run():
    """The class-2 path: the FIRST flag-shaped token of this line sits inside
    the quoted name (`-x`), so before the fix the backstop cut there and left
    `add authentication samlAction "sam` behind. The cut point is now the
    first REAL flag token, and the quoted name survives whole."""
    line = (
        f'add authentication samlAction "sam -x one" -someFutureSecretKey {SECRET} -encrypted -encryptmethod ENCMTHD_4'
    )
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f'add authentication samlAction "sam -x one" {REDACTION_NOTE}'
    assert _quoting_closes(out)


def test_a_line_whose_quoting_never_closes_is_redacted_and_handed_back_balanced():
    """Fail-closed, both ways at once. The quoting of this line cannot be
    read, so the flag name behind the open quote is matched anyway (the
    secret must not survive), and the head is cut back to before the run that
    never closes (so this module does not hand on an unbalanced quote it was
    given)."""
    line = f'add aaa kcdAccount kcd1 -note "unterminated -kcdPassword {SECRET}'
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add aaa kcdAccount kcd1 -note {REDACTION_NOTE}"
    assert _quoting_closes(out)


# ---------------------------------------------------------------------------
# Class-1 flags with no test behind them. Deleting
# `-secondaryPassword` from the flag list, or `-keyValue` from it, left the
# suite green: `-keyValue` was only ever exercised on `set ns
# encryptionParams`, where the class-3 rule fires first and the flag list is
# never consulted. Class 1 is command-agnostic BY DESIGN (module docstring:
# "on whatever command carries it"), so what these two tests pin is the FLAG
# NAME; the command each rides here is arbitrary and the pairing is
# synthetic, exactly like every secret value in this file.
# ---------------------------------------------------------------------------


def test_the_secondary_password_flag_is_redacted():
    line = f"add authentication ldapAction ldap2 -secondaryPassword {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication ldapAction ldap2 {REDACTION_NOTE}"


def test_the_key_value_flag_is_redacted_off_the_encryption_parameters_command():
    line = f"add authentication samlAction sam2 -keyValue {SECRET} -encrypted"
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication samlAction sam2 {REDACTION_NOTE}"


# ---------------------------------------------------------------------------
# `re.IGNORECASE` on the class-3 COMMAND-HEAD patterns
# had no test behind it either: stripping it from all six left the suite
# green. Three of the six can be pinned, and are pinned below. The other
# three - `set ns rpcNode`, `(add|set) aaa user` and `(add|set) lb monitor
# ... -password/-radKey` - are belt and braces over class 1 (module
# docstring, class 3c): on every secret-bearing shape they can fire on, the
# class-1 flag list produces the IDENTICAL output, so no assertion about a
# redacted line can tell which of the two rules did the work, and their
# case-insensitivity is not independently observable. That redundancy is
# deliberate defence in depth, and this comment is the record of it rather
# than a test that would only pretend to check it.
# ---------------------------------------------------------------------------


def test_an_uppercase_system_user_line_is_redacted():
    """Only the class-3 rule can reach this shape: the password is
    positional, `-ENCRYPTED` is not a class-1 flag, and the class-2 backstop
    needs `-encryptmethod` as well. Without IGNORECASE on the command head
    the line comes back untouched, secret intact."""
    out = redact_config_line(f"ADD SYSTEM USER BEHEERDER {SECRET} -ENCRYPTED")
    assert SECRET not in out
    assert out == f"ADD SYSTEM USER BEHEERDER {REDACTION_NOTE}"


def test_an_uppercase_encryption_parameters_line_keeps_nothing_but_its_head():
    """Here class 1 would still catch `-KEYVALUE`, but it would cut one token
    later and leave `-METHOD AES256` standing. The class-3 head is what this
    asserts, so losing IGNORECASE on the command head changes the output."""
    out = redact_config_line(f"SET NS ENCRYPTIONPARAMS -METHOD AES256 -KEYVALUE {SECRET}")
    assert SECRET not in out
    assert out == f"SET NS ENCRYPTIONPARAMS {REDACTION_NOTE}"


def test_an_uppercase_snmp_community_line_is_redacted():
    """The community string carries no flag name at all, so class 1 and class
    2 can never reach it: without IGNORECASE on the command head this
    cleartext credential comes back in full."""
    out = redact_config_line(f"ADD SNMP COMMUNITY {SECRET} ALL")
    assert SECRET not in out
    assert out == f"ADD SNMP COMMUNITY {REDACTION_NOTE}"


# ---------------------------------------------------------------------------
# The fail-closed path - and the only place three of this fix's own
# guarantees are observable at all. On a line whose quoting CLOSES,
# `_flag_position` already refuses every match that is not a real token, so
# it subsumes the `(?<!\S)` anchors and makes every cut point a token start
# by itself. Take the quoting away and the three fall apart separately:
# mutation-tested, each of the three tests below is the only one in this file
# that turns red for its mutation.
# ---------------------------------------------------------------------------


def test_an_unreadable_monitor_line_still_needs_the_flag_to_start_a_token():
    """The token-start anchor on the monitor flag, on its own. This line's
    quoting never closes, so every match counts (fail-closed) - and
    `-password` here is the tail of `/reset-password`, which is not a flag
    under any reading. The line carries no credential and stays whole."""
    line = 'set lb monitor mon_x TCP-ECV -send "unterminated /reset-password probe'
    assert redact_config_line(line) == line


def test_the_backstop_cut_never_ends_inside_a_run_that_never_closes():
    """The quote-safe cut, on its own. The FIRST flag-shaped token of this
    line (`-x`) sits inside a quoted run that never closes, so a raw
    `text[:position]` would hand back `add authentication samlAction "sam` -
    a dangling quote `cve.py` reads as a read gap. The cut falls back to the
    last token that ends outside the run."""
    line = (
        f'add authentication samlAction "sam -x one -someFutureSecretKey {SECRET} -encrypted -encryptmethod ENCMTHD_4'
    )
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"add authentication samlAction {REDACTION_NOTE}"
    assert _quoting_closes(out)


def test_a_class_three_head_never_reaches_into_a_run_that_never_closes():
    """The head counter, on its own, and the sharpest of the three: this
    line's fourth token is the quoted run that never closes, and it carries
    the secret. A head of four tokens would therefore hand back the whole
    line. The head stops at the last token that ends outside the run."""
    line = f'set ns rpcNode "10.0.0.1 -password {SECRET}'
    out = redact_config_line(line)
    assert SECRET not in out
    assert out == f"set ns rpcNode {REDACTION_NOTE}"
    assert _quoting_closes(out)
