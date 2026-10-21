# netscaler-mcp

Ask your NetScaler what expires, what breaks then, and what to do - with
evidence attached, and an honest "not established".

## What this is

An MCP server that answers management questions about a Citrix NetScaler. It
is not a monitoring tool: monitoring says *that* a certificate expires. This
product says what falls over when it does, what to do about it, and what it
could not establish.

The answers are computed by code, not reasoned by a language model. That
makes them reproducible and cheap: the same question on the same data gives
the same answer, and a question costs hundreds of tokens, not hundreds of
thousands. The model only does language.

## Try it in five minutes

This repository ships a **real NetScaler export** - written by the released
NSHC 1.0 collector against GJK's own lab VPX on 2026-08-26, with credentials
redacted. You can get a real answer out of this product without an appliance,
without a network connection and without an API key.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-build.txt
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps --no-build-isolation
.\.venv\Scripts\python.exe examples\minimal_client.py
```

The three install lines are the install lines of CI, in the same order. Both
requirements files are hash-locked (`requirements-dev.txt` is an export of
`uv.lock`, `requirements-build.txt` pins pip, setuptools and wheel), so the
install fails closed on a mismatch instead of resolving something else, and
`--no-build-isolation` keeps the build toolchain inside that hash check.

The last line prints the tool list and then a full `status_overzicht` answer computed
from [`tests/fixtures/lab-export-vpx-20260826/`](tests/fixtures/lab-export-vpx-20260826/)
(see its own README for provenance) - nothing else: startup is silent by
default, and `NSMCP_DEBUG=1` before the command restores the request-level log
lines (and any third-party warning) if you are diagnosing a problem.

The client is under 40 lines, docstring included: [`examples/minimal_client.py`](examples/minimal_client.py).
It uses [`config.example.json`](config.example.json), which points at the
shipped export and at [`kennis.example.json`](kennis.example.json), and pins that
package with `kennispin` (the output of `python -m nsmcp.knowledge --digest
kennis.example.json`). Change the example package and the server refuses it until
the pin is updated.

**About that knowledge package.** `kennis.example.json` deliberately carries no
CVE base. The real knowledge package (CVE base, cipher baseline, expiry rules)
travels separately and is not in this repository. With the example package
`status_cve_controle` reports zero bulletins, and any answer that names the
knowledge package's version carries `VOORBEELD - dit pakket bevat geen echte
CVE-basis`, so the absence is visible in the answer itself rather than
looking like good news.

To answer in Dutch through your own MCP client, point it at
`netscaler-mcp <path-to-config.json>`; a full walkthrough is in
[docs/klant/HANDLEIDING.md](docs/klant/HANDLEIDING.md).

## What it does not do

### Writing happens only with a human in the loop

#### The two-step confirmation

Seven tools can change
  an appliance (stage a certificate, replace a certificate, disable a
  service-group member, enable it again, make a backup, run one phase
  of a firmware upgrade, or save the running configuration). None of them
  acts on a first call: the first call returns a proposal and delivers a
  six-character confirmation code to the operator through the configured
  channel, outside the tool result. The code lives ten minutes and works
  once. Only a second call carrying that code acts; right before it acts, the product runs a fresh preview
  and binds the code to the target the write script reports at that
  moment, so a target that has changed since the proposal is refused and
  burns the code. Five wrong guesses against the same proposal burn it the
  same way, and the channel shows a notice with no code in it - an AI
  client driving the calls can burn a proposal this way, by design or by
  guessing wrong; nothing changes, the caller just asks again. The write
  script itself reads the changed object back from the appliance and
  reports it; the product treats a non-zero exit
  code, a missing action-id or target marker, a time limit or an error as
  failure and relays the script's end status verbatim - it never inspects
  that end status itself, and never composes a "read back" claim of its
  own. The one exception is `config_opslaan`: its script prints the raw
  `show ns config` answer it read right after `save ns config`, and the
  product itself judges that read-back - fail-closed, on the measured field
  shapes - because the script judges nothing. The proposal reads nothing off the appliance: the target label in it
  comes from the action plus its arguments, which the write script works out
  before it connects. So a proposal states what would change and against
  which target, not what the current state of that object is.

#### Reversibility and who does the writing

Three of the
  seven are reversible through their counterpart (`dienst_lid_uitschakelen`
  <-> `dienst_lid_inschakelen`; a replaced certificate can be replaced back
  with `certificaat_vervangen`); the other four have no inverse in this
  product - saving the configuration (`config_opslaan`) cannot be undone,
  the previous saved configuration survives only in a backup made beforehand with
  `onderhoud_backup_maken`, which `config_opslaan` does not check - removing a staged certificate (`certificaat_klaarzetten`) is a
  separate administrative step, a backup (`onderhoud_backup_maken`) is
  itself the rollback point, not a change to undo - and it never leaves the
  appliance: carrying it off-box is not something this product does - and
  an upgrade phase (`onderhoud_upgrade_fase`) has no counterpart phase: its
  undo path is that backup or a hypervisor snapshot (see below). The
  writing itself is
  done by the reviewed PowerShell write tool of the demo lab for five of
  the seven, by the upgrade runner for the sixth, and by a small SSH script
  next to that runner for the seventh, each started as a separate process -
  this product does not carry a NITRO write client.

#### The allowlist

The allowed object list comes from CONFIGURATION, not code: the
  `handelen.toegestaan` section says, per target name per tool, which values
  are allowed (a list per argument, or `true`/`false` for a tool that forms
  its own object), and the product validates that section at STARTUP - a
  wrong shape, an unknown tool or argument, or a missing value refuses the
  start immediately, instead of surfacing mid-proposal. For this demo lab the
  configuration is set today so that: `certificaat_klaarzetten` takes only
  a `certnaam` and accepts only the certificate `gjk-zaakportaal-2027`; it
  names no service. `certificaat_vervangen` accepts only the service
  `lb_vs_gjk_zaakportaal_443` with `gjk-zaakportaal-2027` - or, as a
  rollback target, `gjk-zaakportaal-2026` - as `nieuwcert`.
  `dienst_lid_uitschakelen`/`dienst_lid_inschakelen` only accept the
  service group `gjkdemo_sg_proefdienst` with member `gjkdemo_web01` or
  `gjkdemo_web02`, always on port `3389`: that port is fixed in this
  product as `MEMBER_PORT` and is not an argument.

#### The built-in denylist

Next to that
  CONFIGURABLE allowlist this product carries a BUILT-IN denylist that
  lives in code and stands apart from it: names starting with `nshttps-`
  or `nsrpcs-`, and the certificates `ns-server-certificate` and
  `ns-sftrust-certificate`, are always refused, even if an allowlist would
  release them - the appliance's own management services and
  certificates. That denylist is checked before the allowlist at TWO
  points: at startup (a configuration that puts a denylist name in
  `toegestaan` is refused) and at every call (the validation step checks
  the denylist before the allowlist) - so an allowlist rule can never
  release a denylist name, in either place. See `handelen.toegestaan` in
  the configuration, and `MEMBER_PORT`, `DENIED_PREFIXES`, `DENIED_NAMES`
  and `validate()` in `src/nsmcp/handelen.py`, plus the configuration
  validation at startup (`_allowlist()` in `src/nsmcp/start.py`). An
  operator pointing `handelen` at their own appliance without adapting the
  configuration gets four name-bound tools that refuse every object by
  name - the example values above are this demo lab's configuration, not
  theirs.

#### Writing tools under the disclosure switch

Without a `handelen` section in the configuration the seven tools do not
  exist at all, and they exist at `openheid: volledig` and `openheid:
  beperkt`: everything a writing tool says - a proposal, an outcome, a
  refusal and also a failure - passes through the same disclosure seam as
  a reading answer, and a refusal names nothing more than what the caller
  itself supplied. In `beperkt` the caller hands in a pseudonym and gets a
  pseudonym back. At `openheid: minimaal` the seven do not exist: that
  level summarises an answer down to counts, which cannot carry a
  proposal, so `handelen` combined with `minimaal` is refused at startup
  rather than half-shielded. Everything the write script prints that ends
  up in an answer - the proposal lines, the read-back block, the end
  status, the target label and the raw output on the failure path - is
  masked for the known values of every configured target and capped at
  ten lines, with a visible note saying how many lines were dropped.
  `tests/test_handelen_zonder_code.py` measures through a real MCP session
  that without a valid code every run is a `-WatIs` preview.

### This product does not move firmware or restart anything outside one runner phase

A firmware
  rollback restores the build, not the configuration, so the backup or the
  hypervisor snapshot is the only real undo path for an upgrade - never
  the old firmware alone. `tests/test_firmware_boundary.py` derives this
  from the real tool register instead of a flag: it fails the day any
  write tool other than the upgrade runner (`onderhoud_upgrade_fase`)
  builds an argument that names firmware, a reboot or `installns`, or any
  other registered tool's description does. A backup made on
  the appliance is not an off-box backup; downloading it is a separate
  step this product does not do.

### The confirmation code does not reach the model

#### Why the confirmation code moved out of the tool result

It used to travel in
  the tool result, and three headless practice runs against a lab measured
  what that costs: the model read the code in the proposal and called the
  second step itself, in the same turn, without the human ever seeing the
  proposal. So the code now leaves through a channel the model cannot read
  - `handelen.codekanaal`: a window on the machine where the server runs
  (`{"soort": "venster"}`), or, for practising and automation, a file the
  operator names (`{"soort": "bestand", "pad": "<absolute path>"}`). The
  channel is deliberately a plug-in point - the configuration always names a
  `soort`, and one function (`code_channel.presenter_for`) turns that into a
  presenter. The reference `sso` presenter records the sign-in account of the
  server's session in the action register: the account the server runs under,
  whoever clicks OK - not a verified approver. That identity only means
  something when the MCP host runs under a different account or session than
  the administrator; approval outside the session (a push or MFA prompt) is
  not part of this release. The proposal in the chat keeps
  the target, intended change and undo instructions. At `volledig` it also
  includes script plan lines; at `beperkt` these are suppressed in the chat,
  so the model never reads them below full disclosure. The operator's own
  proposal - the `proposal_text` the file and SSO channels present - carries
  those plan lines at every disclosure level, masked the same way a refusal
  is, never suppressed: a human confirming a physical action must see what
  the script itself said it would do. The window channel shows no proposal
  text at all, on any disclosure level - only tool, target label, allowlist
  section and arguments, above the code. The chat says only
  that the code was shown to the operator. The second step therefore needs
  a code a human read and typed.

#### The window channel's hard condition

**The window channel holds under one hard
  condition: the AI client must have no screen or UI access to the desktop
  of the machine where the server runs.** The code is put on that desktop;
  "the model cannot read it" is a statement about the environment, not
  something this product can enforce - an assistant with screenshots,
  computer-use or browser tools on that same desktop simply reads the box.
  In Claude Desktop: switch computer-use and the browser tools OFF in the
  project that uses this server, or run the server on a machine where the
  assistant has no screen. The box closes itself after the code expires (on
  Windows versions that can; without that, it stays until someone clicks it
  away), so no dead code is left on a screen. Fail-closed on a DIRECTLY MEASURED
  failure: no Windows, an unwritable path, or a box that returns 0 or throws
  within the 0.5 s measurement makes the product spend the code it had just
  issued and refuse the proposal, and a `handelen` section without
  `codekanaal` refuses to start. That measurement has a boundary, stated in
  full in docs/klant/SECURITY.md: a session without a visible desktop can
  leave the box hanging, and the product then reports the code as shown to
  nobody - nobody being the model as well, so the action simply cannot be
  confirmed.
  The file channel is only as closed as the file: an assistant with file
  tools on the same machine can read it, so that form is for practising,
  never for a live session.
  The same condition holds for the `sso` channel: its reference presenter
  shows its box in the session of the server as well, and any process in
  that session can read the box and press OK.

### No telemetry

The server sends no usage data. Traffic of configured
  collector and write scripts is outside the server's socket measurement.

## The thirty-four tools

A fully configured server offers 34 tools: 27 reading and 7 writing tools,
across nine chapters. All `onderhoud_` tools require an `onderhoud` section;
the writing tools also require `handelen` and a code channel. The phase tool
and `config_opslaan` require an allowlist grant, and `config_opslaan` also
requires an `onderhoud` section. `status_ververs` requires a scan configuration.
Without those configurations, 23 reading tools remain. The writing tools are
available with disclosure `volledig` and `beperkt`, never `minimaal`.

Every reading tool that answers out of the export takes an optional `doel` -
all of them except `status_ververs`, `status_doelen`, `kennis_uitleg`,
`rapport_vergelijk`, `onderhoud_upgrade_stand` and `rapport_na_upgrade`. This
server holds one export, so a given `doel` must be a configured target AND the
target that export describes: an unknown one is refused without repeating it,
and another configured target is refused with the advice to refresh first with
`status_ververs` (the refusal names the export's own target only at
`volledig`). The export must also be one this server collected for that
target itself: without its own provenance record for exactly this manifest
(see "Configuration" below) a given `doel` is refused with "doel niet
vastgesteld: de export is niet door deze server voor dit doel verzameld". At `beperkt` the pseudonym `status_doelen` shows for a target is a
valid `doel` - for these tools, for `onderhoud_upgrade_stand` and
`rapport_na_upgrade`, and for the writing tools - and an unknown pseudonym gets
the same refusal as an unknown name. Without `doel` every tool answers exactly
as before, with one exception: `rapport_na_upgrade` checks, with or without `doel`, that the
export describes the target whose ledger it reads, and answers "niet vastgesteld" when it
does not.

### certificaat

| Tool | Answer |
|---|---|
| `certificaat_wat_verloopt_er(horizon_dagen, doel)` | which certificates expire within the horizon (default 90 days), with evidence and read gaps; the days count from today: the age of the export is taken off the appliance's count at the scan, and an unreadable export date gives "niet vastgesteld" |
| `certificaat_wat_breekt_er(certnaam, doel)` | which virtual servers fail if this certificate expires, also through the certificates it issues; the SSL services on the certificate are read from the certificate-side binding file, and a management service of the appliance itself (`nshttps-`, `nsrpcs-`) is named as the appliance's own management traffic; the use outside those bindings is named with object and role - a SAML action (IdP or signing certificate), a SAML IdP profile (IdP or SP certificate) and an SSL servicegroup (with its CA flag); a source of those that the export does not carry is reported as not established, never as "no use" |
| `certificaat_wat_moet_ik_doen(certnaam, doel)` | the change, the rollback and the read-back check - only when the impact is established; a certificate that carries management traffic of the appliance itself gets no proposal (the built-in denylist), an SSL service gets its own manual step, and a use by a SAML object or an SSL servicegroup gets a manual step with the warning that `certificaat_vervangen` only rebinds a virtual server |
| `certificaat_klaarzetten(certnaam, bevestiging)` | writing tool: stages a replacement certificate on the appliance without binding it |
| `certificaat_vervangen(dienst, nieuwcert, bevestiging)` | writing tool: swaps the certificate bound to a service; the write script reads the new binding back and the product relays that outcome verbatim; the proposal names every other use of the certificate it takes off (object and role), which this replacement does not touch, or says that use is not established |

### status

| Tool | Answer |
|---|---|
| `status_ververs(doelnaam)` | rescans a configured target; takes minutes - one of the two reading tools that reach the appliance, via the collector script as a separate process |
| `status_overzicht(doel)` | an overview of the NetScaler: build, HA state, number of virtual servers and how old the data is |
| `status_cve_controle(doel)` | tests the NetScaler's build against the known security bulletins in the knowledge package |
| `status_namen(doel)` | which names this NetScaler knows, per family: load-balancing, content-switching and Gateway vservers, service groups, services and certificates |
| `status_doelen()` | which targets this server knows, from the targets file and the allowlist: per target its name, its address, how old the export of that target is (there is one export per server, so the other targets have none), the last maintenance run in the ledger with its last line in this product's own words, which writing tools the allowlist grants there - and which of those this server does not offer - and whether an SSH host key is pinned (yes/no). Never a credential-target name, a fingerprint or an allowlisted object name. At `beperkt` names and addresses are pseudonyms, at `minimaal` only counts remain; without any target it says so in one sentence |
| `status_gezondheid(doel)` | what stood DOWN at the moment of the scan: counts and names per family, with storing and coverage kept strictly apart; a snapshot from the export with a data age, not monitoring |
| `status_update_advies(doel)` | which build belongs on this NetScaler: the current build, the floor from the knowledge package and the vendor's offered build, side by side with their provenance and age |
| `status_update_preflight(doel)` | nine checks that can stop an upgrade within 14.1 - licence, classic markers, HA state, drift between running and saved, certificate horizon, build and branch, form factor, free space on `/var` and the rollback path. The heading is only conclusive when all nine say `geen blokkade`; free space is read live in a separate process - over SSH (`df -k /var`, pinned host key) when `onderhoud` is configured and the target carries a pinned SSH host key, otherwise through the collector script like a scan - and a failed route is a read gap, never a second attempt through the other one. The drift check reads the two timestamps of `config/nsconfig` when the export carries it; the released collector does not, and then the check compares the running and the saved config themselves, with the same counts as `config_drift`. This is not a vendor pre-check |

### dienst

| Tool | Answer |
|---|---|
| `dienst_status(dienst, doel)` | the state of a service (virtual server) and of every member of its bound service group, as the appliance reports it |
| `dienst_keten(dienst, doel)` | the chain of a service, from VIP to backend: entry point, backend group and members, with per chain whether it is complete, where the gap sits, or that it could not be established; leave the argument empty for every chain, and the answer opens with a summary line (chains per verdict). A loadbalancing-vserver is followed to its servicegroups, services and members, in both binding shapes the collector writes. A contentswitching-vserver is followed to its standard load balancer and its policies (each resolved to its target load balancer, directly from the binding row when present, otherwise through cspolicy/csaction) and from there the same loadbalancing chain; a policy that cannot be resolved (cspolicy/csaction absent, unreadable, or a reference inside them that leads nowhere) makes the WHOLE route `niet vastgesteld` with the reason, showing only the standard load balancer and the policy names themselves - never a guessed target, and the standard load balancer is not followed further either in that case. A Gateway-vserver is `niet vastgesteld` with the reason (this version does not follow the Gateway session chain) |
| `dienst_lid_uitschakelen(dienst, lid, bevestiging)` | writing tool: takes a member out of a service group (`dienst` is the service group here, not the virtual server); the write script reads back and the product relays that outcome verbatim |
| `dienst_lid_inschakelen(dienst, lid, bevestiging)` | writing tool: puts an earlier-disabled member back into the service group (`dienst` is the service group here, not the virtual server); the write script reads back and the product relays that outcome verbatim |

### kennis

| Tool | Answer |
|---|---|
| `kennis_uitleg(begrip)` | explains a NetScaler term from GJK's knowledge package, or says it is not in there |

### rapport

| Tool | Answer |
|---|---|
| `rapport_na_upgrade(doel, run)` | reads the ledger and export after an upgrade; requires maintenance configuration |
| `rapport_dekking(doel)` | how complete this answer is: per source whether it was read, which sources failed, were refused or are missing, and whether the cross-check on the bindings succeeded - for binding files in both shapes the collector writes; a file whose parent source has no hash or is not collected is counted with its reason |
| `rapport_vergelijk(mapA, mapB, modus)` | compares two export directories in one of four modes: HA-parity, drift, run-diff or pre/post. Configuration, state and coverage differences stay in three strictly separated blocks; which side is "good" is a human judgement this answer does not make |
| `rapport_wat_is_er_veranderd(doel)` | what changed since the previous scan of this target: the same comparison as `rapport_vergelijk` in `run-diff` mode, with both directories chosen automatically. No kept previous export means "nothing to compare with", never "no differences" |

### ha

| Tool | Answer |
|---|---|
| `ha_stand(doel)` | the HA situation before a change: role distribution, propagation and sync, forced node state and the difference between the running and the saved config - each `aan`, `uit` or `onbevestigd`, and `niet van toepassing` on the two pair dimensions when the export carries no HA pair. The config difference compares content: the header lines and the closing `Done` do not count. It proves no working failover and says nothing about the partner's configuration |

### config

| Tool | Answer |
|---|---|
| `config_drift(doel)` | which lines stand only in the running and which only in the saved configuration, from the export; the header lines and the closing `Done` do not count. The lines themselves appear only at disclosure `volledig` (at most 40 per side, 200 characters each), and a line carrying a recognised secret or a redacted value never - only its command head, and not even that when the head itself is withheld. At `beperkt` only command heads with a count, at `minimaal` only counts. A line that differs only in the part the export withholds as a possible secret (a changed password that was not saved) counts as drift, at every level as a number only - never the line, its head or the value - when the export carries that value. The released collector already replaces such values with `<REDACTED>` on both sides; such a line cannot be compared, and when the header lines say the configuration changed after the last save (or cannot be read) the answer is `onbevestigd` instead of `uit`, with the number of such lines as the reason. The two header timestamps stand next to it as evidence, never as the verdict. `doel` is optional and, when given, must be a configured target and the target the export describes |
| `config_opslaan(bevestiging, doel)` | writing tool: has the NetScaler save its running configuration (`save ns config`) over SSH with the pinned host key, after a live role check - it refuses on a node that is secondary, because a save there does not propagate - and then reads `show ns config` back: the server, not the script, judges that the last save is not older than the last change. A failed read-back is a failed action with a spent code. The first call returns a proposal WITHOUT a code; the proposal also shows the drift counts of the export (and `onbevestigd` where `config_drift` says so) and that the role is decided at execution. Never execute a proposal yourself. Supply `doel` when more than one NetScaler is configured. It has no inverse: the previous saved configuration survives only in a backup made beforehand with `onderhoud_backup_maken`, which this tool does not check |

### beveiliging

| Tool | Answer |
|---|---|
| `beveiliging_verstopte_regels(doel)` | the 29 hidden rules no alarm fires on: per rule whether it is hit, on which objects, and why it goes unnoticed. Reads configuration fields; proves no behaviour |
| `beveiliging_tls_baseline(doel)` | a TLS grade per virtual server (A+ through T) with the deciding characteristics, plus the spread across the appliance and the ruleset version used. Protocol and ciphers come from the bound SSL profile when there is one. A configuration weighing, not a live scan |
| `beveiliging_beheervlak(doel)` | whether the management plane of this appliance is open: exposure on data-plane addresses, cleartext transport, the default management certificate on production traffic and RBAC hardening. Each of the four is PASS, FAIL or NIET BEOORDEELD. A network ACL in front of the management address is invisible to this answer |
| `beveiliging_headers(doel)` | whether the six HTTP security headers are configured: rewrite headers require an effective RESPONSE binding; HSTS counts only when a vserver binds a FrontEnd SSL profile with `hsts=ENABLED` (named per vserver); an own profile nobody binds is "defined, not bound", an unbound built-in profile does not count, and an unread binding is "niet beoordeeld" |
| `beveiliging_scorekaart(doel)` | Level-1 controls with outcome-dependent severity; X of Y assessed (18 or 19), five controls excluded and seven fixed out-of-scope subjects |

### onderhoud

| Tool | Answer |
|---|---|
| `onderhoud_backup_maken(bevestiging, doel)` | writing tool: has the NetScaler make a full backup itself and reads it back into the backup collection; the name is formed here, in UTC. The first call returns a proposal WITHOUT a code - the confirmation code goes to the operator, not to the caller. Never execute a proposal yourself: wait for the operator to hand over the code and call this tool again with it. Supply `doel` when more than one NetScaler is configured. Use this before working on the NetScaler |
| `onderhoud_upgrade_plan(doel)` | the plan for an upgrade within 14.1: the seven phases, the HA order (secondary first), the soak window, the rollback path per phase and the gate each phase must clear, plus the current build (`config/nsversion` in the export), the target build (the one bundle in `onderhoud.firmwaremap`), the security floor of the appliance's own branch from the knowledge package, and R0's verdict between the two with the bulletins that stay open below the floor. Reading only - it changes nothing |
| `onderhoud_upgrade_fase(fase, run, bevestiging, doel)` | writing tool: starts one confirmed phase through the runner; the ledger supplies its outcome. Phase arguments: `snapshotverwijzing` and `doelbuild_geaccepteerd` (R0 only), `drift_geaccepteerd` and `oude_buildbomen_opruimen` (R1 only), `standalone_geaccepteerd`. R0 checks the target build against the current build and the security floor: it opens on evidence at or above the floor and above the current build, below the floor, without a known floor or current build, or for a target build not higher than the current build only on `doelbuild_geaccepteerd=true` as a human decision (the evidence names the pinned knowledge package and warns, without closing, when it is more than 30 days old), and never in another release line than the current build or across branches. A floor or current build without the runner's form (a FIPS train) does not travel to the runner, and neither does the acceptance: R0 closes there, and a call that carries the acceptance anyway is refused before a code exists. R1 to R6 refuse a bundle other than the one R0 of the same run started with. R1 reads `show ns config` itself: its drift gate opens on evidence (nothing changed since the last save, for instance after `config_opslaan` on the primary) or on `drift_geaccepteerd=true` as a human decision. Every proposal ends with the target build and the floor with R0's verdict |
| `onderhoud_upgrade_stand(doel, run)` | reads the phase gates and freshness from the ledger |

For the seven writing tools, `bevestiging` is the code delivered to the
operator for that proposal - see "What it does not do" above and, for the customer-facing
walkthrough, [docs/klant/HANDLEIDING.md](docs/klant/HANDLEIDING.md).

## Security

See [SECURITY.md](SECURITY.md) (English pointer) and
[docs/klant/SECURITY.md](docs/klant/SECURITY.md) (the Dutch security
statement: vulnerability reporting, the socket guarantee and its measured
boundary, front-door defenses, known target values in error messages).

### Twenty-five of the twenty-seven reading tools never open a socket

The guard
  calls those twenty-five reading tools with real input over real MCP sessions,
  including the tools that require maintenance configuration. There are exactly
  two exceptions: `status_ververs` rescans a target and `status_update_preflight`
  reads free space live. Both start a separate child process (the collector
  script, or for free space with `onderhoud` and a pinned SSH host key the small
  SSH read script); the server process itself opens no socket. The same guard
  covers every one of those process boundaries.

## Development

For offline NSHC export pseudonymisation, run `python scripts/pseudonymise_export.py --source <export-directory> --target <new-directory> --mapping <directory-outside-repos> [--extra-forbidden <file-outside-repos>]`; keep mappings private, curate any diagnosed protected terms, and verify unchanged verdicts before publication. Source LF/CRLF line endings, per-file UTF-8 BOMs and missing hashes are retained; configuration hashes follow the reader's BOM-free LF normalization. The final gate refuses original substrings, including longer tokens; see scripts/README.md for certificate basenames, safe diagnostics and mandatory manual subject/issuer checks.

```powershell
./.venv/Scripts/python.exe -m pytest
```

`tests/test_product_surface.py` is the permanent parity guard
for the Dutch product surface (tool names, parameters, description first
lines, config keys, enum values, on-disk artifact names, key answer
texts).

## The product surface is Dutch (by design)

Tool names, tool parameters, answer texts, error messages and configuration
keys are Dutch: the customers and their AI assistants are Dutch. The code -
identifiers, docstrings, comments, tests - is English. A parity test
(`tests/test_product_surface.py`) pins the Dutch surface so a refactor
cannot silently change it. The Dutch customer documentation lives in
[docs/klant/](docs/klant/), starting with
[docs/klant/HANDLEIDING.md](docs/klant/HANDLEIDING.md).

If you do not read Dutch, start with
[docs/GLOSSARY.md](docs/GLOSSARY.md): one page with the verdict
vocabulary, the certainty markers, the footer lines and one fully
annotated answer.

## A read gap is an outcome

When something cannot be established, the answer says so - with the reason.
This is the fail-closed model, in code rather than in a promise:

- an unreadable source becomes a **read gap** (`NIET VASTGESTELD`), never
  "no impact"; an empty list because a read failed is distinct from an
  empty list because nothing was there;
- a finding carries its own certainty (`vastgesteld` / `niet vastgesteld`)
  and its evidence; a finding without evidence cannot be constructed;
- while a read gap is open, `certificaat_wat_moet_ik_doen` proposes no change;
- a dimension this version deliberately does not assess is named as such
  in the answer instead of silently missing;
- every substantive answer carries the age of the knowledge package (`Kennisbasis van
  ...`); an assessing answer also carries the age of the data
  (`Gegevens van ..., doel: ..., herkomst: ...`) - `kennis_uitleg` reads no export, so its
  answer carries the knowledge age alone; a missing or unreadable
  timestamp is reported with its reason, never invented. When `kennis_uitleg`
  refuses an unusable package, it reports that refusal and reason without an
  age line; no knowledge from that package is used.

## Self-scanning (phase 2)

Besides a supplied export, the server can scan a configured target itself,
through the NSHC collector script as a separate process.

- A target is an address, the target name of a credential in Windows
  Credential Manager, and a certificate agreement (`keten`: the management
  certificate validates against the trust chain, or `vingerafdruk`: the
  fingerprint is pinned in the configuration - no third form and no
  interactive escape). The credential value itself never appears in any
  configuration file.
- A targets file (or main configuration) containing a known secret-like
  key name (`password`, `secret`, `token`, `apiKey`, ...) is refused
  before anything is scanned. This is a key-name check, not a value check.
- A scan lands in a fresh directory and is swapped in only after
  verification, behind a commit gate: a failed or cancelled scan leaves
  the previous export in place. Cancellation is honored up to the commit
  boundary; a cancellation that lands after it lets the swap complete and
  the answer says so explicitly.
- There is one export directory per server; a second scan is refused while
  one is running (a lock file next to the export directory, refusal names
  the path and pid).

## Running / configuration

The locked install of "Try it in five minutes" above installs the
`netscaler-mcp` command. It takes exactly
one argument, the path to a JSON configuration file; a bad configuration
prints a Dutch `Fout: ...` line on stderr and exits with code 1 - the
server does not start.

```powershell
netscaler-mcp "C:\pad\naar\config.json"
```

Configuration keys (Dutch, verbatim):

| Key | Required | Meaning |
|---|---|---|
| `profiel` | yes | `"online"`, `"afgeschermd"` or `"dienst"` |
| `exportmap` | yes | directory with the NSHC export (`objects/`, `bindings/`, `export-manifest.json`). A relative path in any path key counts from the directory of the configuration file, not from the working directory; a network path (UNC, also `\\?\UNC\`), a device path other than a local drive, a colon after the drive letter (an alternate data stream), a drive- or root-relative path and a component ending in a dot or space are refused at start |
| `kennispad` | yes | path to the knowledge package |
| `doelen` | no | path to a targets file, enabling self-scanning |
| `verzamelscript` | no | path to the NSHC collector script |
| `hoofdstukken` | no | list of active chapters (`certificaat`, `status`, `dienst`, `kennis`, `rapport`, `ha`, `beveiliging`, `onderhoud`, `config`); all nine when absent |
| `handelen` | no | object with `schrijfscript`, `fixturemap`, `codekanaal` and `toegestaan`; without it the seven writing tools do not exist at all (see "What it does not do" above) |
| `handelen.codekanaal` | yes, inside `handelen` | object naming a `soort`: `{"soort": "venster"}` or `{"soort": "bestand", "pad": "<absolute path>"}` - where the confirmation code is shown to the operator. An unknown `soort` is refused with the kinds this version has; the file path must be absolute, must not be a directory and may not sit inside a directory the product itself reads |
| `openheid` | no | `"volledig"` (default), `"beperkt"` or `"minimaal"` - see below |
| `kennispin` | no | `{"versie": "<package version>", "digest": "<sha256>"}` - the knowledge package the operator approved. A package that differs in version or content is refused; without the field the package loads, but every floor and CVE verdict says `[niet vastgesteld]` (reason: `kennispakket niet gepind in de configuratie`). `python -m nsmcp.knowledge --digest <kennispad>` prints the block |

```json
{
  "profiel": "afgeschermd",
  "exportmap": "C:\\GJK\\netscaler-mcp\\export",
  "kennispad": "C:\\GJK\\netscaler-mcp\\kennis.json",
  "kennispin": {"versie": "2026.09", "digest": "<uitvoer van python -m nsmcp.knowledge --digest>"},
  "doelen": "C:\\GJK\\netscaler-mcp\\doelen.json",
  "verzamelscript": "C:\\GJK\\netscaler-mcp\\verzamel.ps1"
}
```

The digest is the sha256 of the package's canonical JSON content (sorted
keys, no whitespace, ASCII escapes, UTF-8), so line endings and indentation
do not count. Whoever can write the knowledge path can change the knowledge;
the pin, kept in the configuration, is what makes such a change visible. After
a knowledge refresh, compute the new digest and update the pin, or the server
refuses the new package.

`status_ververs` records every export it collects - target, manifest sha256,
moment, export map - outside the export map: in `<onderhoud.ledgermap>/herkomst/`
when `onderhoud` is configured, otherwise in a `herkomst` directory next to the
configuration file. The server does not start when that directory lies inside the
export map, or the export map inside it. A reading tool given a `doel`, the upgrade phases and the
export-based lines of a writing proposal need the newest record for that target
to carry the export's manifest hash; an export this server did not collect for
that target is refused ("doel niet vastgesteld: de export is niet door deze
server voor dit doel verzameld"). `scan-doel.txt` inside the export proves only
that the name and the manifest belong together, not who wrote them. Every data
age line ends with `herkomst: verzameld door deze server op <tijd>` or
`herkomst: niet vastgesteld (aangeleverde export)`.

The `dienst` profile answers exclusively on a supplied export: configuring
`doelen`/`verzamelscript` there is refused, not silently ignored.
`afgeschermd` and `online` accept both and behave identically today
(`online` is reserved for a future task: fetching knowledge itself). An
unknown profile, an unknown disclosure level, or half a scan configuration
(only one of `doelen`/`verzamelscript`) refuses to start - never a silent
fallback.

Scanning sends management traffic exclusively to the addresses the operator
configures in the targets file. Five of the seven writing tools reach an
appliance too, through the demo lab's own write script
(`handelen.schrijfscript`) - not to an address this product's own
configuration carries, since `handelen` names no target; which appliance
that script reaches is the script's own concern, outside this product. The
sixth, `onderhoud_upgrade_fase`, starts its own runner against the address
of the target named in the call - the same targets file scanning uses (see
docs/ARCHITECTURE.md). The seventh, `config_opslaan`, starts its own small
SSH script next to that runner, against the same target address, with the
same pinned host key and transport. One read goes live outside a scan:
the pre-flight's free space on `/var` (`status_update_preflight`), over
SSH through `Invoke-GjkLiveMeting.ps1` against the same target address
when `onderhoud` is configured and the target carries a pinned host key,
otherwise through the collector script like a scan. Beyond scanning, that free-space read and
writing, the product opens no other traffic. Whether that traffic stays inside the
customer network is not a guarantee this
product enforces: it follows from the addresses the operator picks and from
the customer's own outbound network (egress) policy - that is the
enforcement layer, not this code. There is deliberately no homegrown
address filter (CIDR or allowlist check) on top: without a reliable local
DNS/proxy picture such a filter is itself bypassable (an address that looks
"internal" can still resolve outward), so it would add false certainty
instead of a real boundary - a claim the product cannot keep is a claim it
should not make.

Operator steps, a full configuration walkthrough and an MCP client example
are in [docs/klant/HANDLEIDING.md](docs/klant/HANDLEIDING.md).

## The disclosure switch

The optional `openheid` key controls how much the answer itself reveals to
the model reading along - computed in code at the envelope boundary, never
performed by the model (the model is precisely the thing being shielded
against). Three levels:

| Level | What the model sees |
|---|---|
| `volledig` (default) | real names, days, bindings, evidence |
| `beperkt` | pseudonyms (`object-01`, ...) with real counts, days, severity and actions |
| `minimaal` | aggregates only: counts, worst remaining term, a typed action line - no names and no pseudonyms |

`beperkt` keeps its pseudonym table in a local file
(`openheid-vertaaltabel.json`) beside the configuration file, or in
`onderhoud.ledgermap` when that is configured - never in or beside the
export map, which whoever supplies an export may write: a configuration in
the directory around the export map is refused at start at `beperkt`. That
file is the customer-held decode key: it is itself sensitive, it never leaves
the operator, and a broken or suspicious table (a value with a control
character included) is refused visibly - never silently repaired or
overwritten. A lock next to it that cannot be opened is a refusal with its
reason, not a generic error. The table carries no integrity pin: it grows
with every new name, so a pin in the configuration cannot follow it. Age/origin stamps and the visibility of read gaps survive
every level; in `minimaal` the count of read gaps remains.

The seven writing tools sit UNDER this switch, not outside it. Everything
they say - a proposal, an outcome, a refusal and also a failure - passes
through the same filter as a reading answer, and a refusal names nothing
more than what the caller itself supplied. In `beperkt` the caller hands in
a pseudonym, the server resolves it through the pseudonym table to the real
name for the allowlist check and the write script, and hands the pseudonym
back; the operator sees the real name in the code channel and on the
`[TARGET]` label, because a human must see what they are confirming.

At `openheid: minimaal` the seven do not exist - not because anything would
leak there, that level says less. It cannot CARRY a proposal: `minimaal`
summarises an answer down to counts, so the proposal lines, its arguments
and the instruction to call again with the confirmation code would all
disappear, while that code is shown to the operator all the same. A
configuration combining `handelen` with `minimaal` is refused at startup,
and a caller building the server as a library gets the seven tools
unregistered plus the reason on stderr. The reading tools are unaffected in
all three settings, with one exception in the same spirit: a failed scan's
raw collector output (masked only for the target's known address,
credential-target name and fingerprint) reaches the `status_ververs` answer
only at `volledig`. Below that the answer keeps the exit code and the phase
diagnosis and says the script output is withheld on this setting.

`config_drift` is the one reading tool that shows configuration lines, and
only at `volledig`: a configuration line carries names that sit in no name
family, so below `volledig` the answer keeps only each line's command head
(`set lb vserver`) with a count, and at `minimaal` only counts. A line
carrying a recognised secret or a redacted value is never shown, on any
level - only its command head and a note that it was withheld, and not even
the head when the head itself would give the secret away (`add system user`).
Recognised means one of the markers and shapes listed in
docs/klant/SECURITY.md: the filter works on known markers, not on meaning,
so a secret in a parameter that carries none of them would show at
`volledig`.

## The knowledge base is not in this repo

This repository is the shell. The curated knowledge - CVE base, firmware
floors, cipher baselines, assessment rules - is delivered separately as a
subscription artifact (a JSON package carrying `datum` and `versie`) and is
maintained by GJK Partners. The shell works without it, but knows little; a
missing or aged knowledge package is a visible fact in every answer, not a
silent degradation.

## Platform

This product is Windows-only today, end to end - reading included. The
table below says why per part.

| part | platform | why |
|---|---|---|
| the reading tools (an answer from a supplied export) | Windows | `nsmcp.mcp_server` imports `nsmcp.disclosure` at module scope (`mcp_server.py:89`), and `nsmcp.disclosure` does an unconditional top-level `import msvcrt` (`disclosure.py:42`) - stdlib on Windows only, absent on Linux and macOS. Importing the server fails with `ModuleNotFoundError` before any tool runs |
| self-scanning (`status_ververs`) | Windows | it starts the NSHC collector through Windows PowerShell |
| five of the seven writing tools | Windows | they start the reviewed write script through Windows PowerShell (the sixth, `onderhoud_upgrade_fase`, starts its own runner and the seventh, `config_opslaan`, its own SSH script - see docs/ARCHITECTURE.md) |
| the confirmation window (`codekanaal: venster`) | Windows | `ctypes.windll` and a user32 message box. `ctypes` itself imports on any platform; only touching `.windll` fails, so in isolation this channel refuses gracefully at start, with a message that points at the file channel (`code_channel.py:254-256` and `:288-293`) - unreached today, though: `mcp_server.py` imports `nsmcp.disclosure` (line 89) before `nsmcp.code_channel` (line 93), so on another platform the `msvcrt` import failure fires first and this refusal never runs through the product's shipped entry point |

**Why the reading half is not the exception it looks like.** `msvcrt` is
unlike `ctypes` or `subprocess`: it does not exist at all outside Windows,
so the bare `import msvcrt` fails immediately, rather than only when a
Windows-only member is touched. `nsmcp/disclosure.py` uses it for real
cross-process file locking around the pseudonym table (`msvcrt.locking` in
`_ProcessLock`, `disclosure.py:466` and `:480`). So a Linux or macOS user
gets nothing today: the failure is `ModuleNotFoundError` at import time,
before any question is asked - not a first-use refusal like the
confirmation window's.

**What is proven and what is not.** CI runs the full suite on
`windows-latest`, on Python 3.11 and 3.12. There is no CI job for any other
platform, and this README does not claim one exists.

The distribution classifiers say `Operating System :: Microsoft :: Windows`
and deliberately do not say `OS Independent`.

## License

Apache License 2.0 - see [LICENSE](LICENSE).

The curated knowledge base is not covered by it: it is maintained and
delivered separately by GJK Partners.

## Integratiegrens

Het volledige register bevat 34 gereedschappen: 27 lezende en 7 schrijvende,
in negen hoofdstukken. Alle namen die beginnen met `onderhoud_` worden alleen
aangemeld wanneer `onderhoud` is geconfigureerd; hun bestaande schrijf- en
allowlistpoorten blijven daarnaast gelden. De enige netwerkuitzonderingen
voor leestools zijn `status_ververs` en `status_update_preflight`.

Het actielogboek op stderr bevat per voorstel en per uitvoerpoging een
gestructureerde regel met tien velden. `voorstel` is dezelfde letter als in
het codekanaal en wordt voor het inwisselen gelezen. `bevestiger` komt uit
het kanaal voor die specifieke code, of is null. De code zelf staat nooit
in het logboek. Een gestart runnerproces krijgt `uitkomst: gestart`; dat is
geen geslaagde fase. Het faseoordeel komt uit het ledger.

De twaalf bevindingen uit de externe review zijn in deze integratie verwerkt
(14-9-2026), met drie bewuste afwijkingen van de aangedragen patches: een MCP-host
binnen een Windows Job Object wordt niet geweigerd maar gemeten (zie "Gemeten: de
faserunner en het Job Object van de host" in OPENSTAANDE-METINGEN.md); de vendorbanner
wordt herkend op zijn gemeten eerste zin, niet op een exacte tweede zin; en de
volledigheidseis aan `show ha node` geldt alleen op het pad dat met
`standalone_geaccepteerd` opent. Historische ledgergegevens zijn niet herschreven.
