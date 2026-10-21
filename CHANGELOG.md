# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.0.2] - 2026-10-21

1.0.2 closes what a newcomer's test of the public release and an independent
security review of it measured. One line per finding; the behaviour an
operator notices first is listed under "Changed".

### Changed
- Relative paths in the configuration count from the directory of the
  configuration file, not from the working directory of the process that
  starts the server; a missing export map names the resolved path and that
  directory. `config.example.json` now starts from any working directory and
  from a client configuration without `cwd`.
- A configuration file on a network path or a network drive, or a configured
  path that leads to one through a link, no longer starts the server; keep the
  configuration and the paths it names on a local disk.
- At `openheid: beperkt` the pseudonym table and its lock live beside the
  configuration file (or in `onderhoud.ledgermap`), never beside the export;
  a configuration in the directory around the export map is refused at start.
- On the shipped lab export, `beveiliging_headers` reports HSTS as
  "niet beoordeeld" and `beveiliging_beheervlak` the certificate dimension as
  "NIET BEOORDEELD" (both were a false PASS/"aanwezig en gebonden"), and every
  expiry count is the count of today.

### Fixed
- Certificate expiry counts from today: `daystoexpiration` is the count at the
  scan, and the expiry list and check 5 of `status_update_preflight` now take
  the age of the export off it ("gerekend vanaf vandaag, export van N dagen
  oud"); an unreadable export date gives "niet vastgesteld", never the raw field.
- HSTS is "aanwezig en gebonden" only when a vserver binds a FrontEnd profile
  with `hsts=ENABLED`, with the vserver names; an own profile nobody binds is
  "wel gedefinieerd, niet gebonden", an unbound built-in profile does not count,
  and a gap in the binding read is "niet beoordeeld". A test keeps the headers
  answer and the TLS baseline from contradicting each other.
- Check 8 of `status_update_preflight` no longer claims a live read that did not
  happen: "niet gelezen: <reden>" without a route - also when the process could
  not start (on the collector route "het verzamelscript is niet gestart:
  <reden>": a script that differs from its pin, no PowerShell, no temporary
  directory) -,
  "live gelezen via <route>, geen bruikbare waarde" for a read that ran without
  a number, and the measurement only when there is one.
- Check 3 of `status_update_preflight` names the HA states in words instead of
  printing internal objects.
- `beveiliging_beheervlak` gives no certificate PASS while the certificate
  bindings of a vserver are missing from the export; the gap stands under
  NIET VASTGESTELD, here and in the scorecard.
- `initialize` reports the product version in `serverInfo.version`, not the
  version of the mcp library.

### Added
- `heeft_saml_action_of_idp`: the condition "SAML SP or IdP" as one OR
  composite of `heeft_saml_action` and `is_saml_idp`, with the evidence of both
  halves, accepted in the knowledge package.
- `scriptpin` (file name -> sha256, printed by `python -m nsmcp.powershell
  --pin`, also for a whole directory): with it, a PowerShell script is started
  only when its bytes and those of every other script (`.ps1`, `.psm1`) in the
  same directory match their pins, right before the start; an unpinned script
  there refuses the start, because PowerShell can read a sibling by name (the
  SSH scripts dot-source their transport). Without it nothing is checked, as
  before. `uitvoeringsbeleid` chooses the
  execution policy (`Bypass` by default, `AllSigned`, `RemoteSigned`).
- The SSH transport checks the content of Posh-SSH 3.2.7 against the measured
  manifest before it loads, not only the version; a deviation stops with
  `[FOUT]` and exit code 3.

### Security
- Every field of every answer goes through one character filter: control,
  format, line- and paragraph-separator characters (ESC, bidi overrides,
  zero-width characters) become a visible "?". `status_namen` names a name
  over 128 characters or with such a character by its position; everywhere
  else an object name the export knows, and a name or term the caller passes,
  is cut at 128 characters with a note, in every field of every reading tool
  (`rapport_dekking` and `certificaat_wat_breekt_er` carried a name of 5000
  characters whole).
- At `openheid: minimaal` the severity line comes from typed fields of the
  expiry list, never from outcome text, so an object name cannot steer it.
- The failure answer of `status_ververs` filters the collector's lines, cuts a
  long line, counts the lines it leaves out and ends with the product's own
  knowledge and data lines.
- Every path in the configuration refuses a network or device path (UNC, also
  `\\?\UNC\`), a colon after the drive letter (an alternate data stream), a
  drive- or root-relative path and a component ending in a dot or a space. The
  same refusals hold for the configuration file itself and for where a path
  leads: links and junctions are followed without opening their target, and a
  configuration on a share, a link to a share or a stream, or a network drive
  letter is refused at start.
- A lock beside the pseudonym table that cannot be opened is a refusal with
  its reason, and a table value with a control character is refused.
- A configuration file, targets file or pseudonym table nested deeper than the
  JSON parser can follow is refused with a reason instead of a traceback.

### CI
- On push runs the hygiene guards get their list from the repository secret
  `NSMCP_PRIVATE_NEEDLES` (written to a temporary file, never printed; a push
  without the secret fails); pull requests run without it, and both suites
  print every skip with its reason (`-rs`).

### Documentation
- The manual has an install chapter from GitHub and names
  `config.example.json`, the lab export and the full path to the command; the
  README Platform section names modules instead of line numbers that had
  moved, the English README no longer ends in a Dutch internal chapter, and it
  explains the "Unknown tool" error of an unregistered writing tool.
- `docs/klant/BEVEILIGING-EN-DATASTROMEN.md` has a chapter on `scriptpin`,
  `uitvoeringsbeleid` and the path rules; `docs/klant/SECURITY.md` names where
  the pseudonym table lives and its start and lock refusals; the manual says
  HSTS is read through an SSL profile only, not set directly on a vserver.

## [1.0.1] - 2026-10-21

1.0.0 (tagged 2026-09-30) was published on 2026-10-21 and withdrawn the same
day: a test fixture derived from a real export carried free text that
pseudonymisation does not cover. 1.0.1 replaces that fixture with a synthetic
one, cleans the tree of development traces, aligns the documentation with what
the release proves, and carries the dependency maintenance below. Anyone who
cloned 1.0.0 in those hours should discard that clone and take 1.0.1; the
withdrawn fixture is not part of any later tree.

### Changed (fixtures and test tooling)
- The DNS over HTTPS fixture is synthetic now:
  `tests/fixtures/lab-export-vpx-doh-synthetic/`, written deterministically by
  `scripts/make_doh_fixture.py` (invented names, TEST-NET addresses,
  `lab.example` host names, no free text from any real export). Its manifest
  hashes come from `nsmcp.export.payload_digest` and
  `nsmcp.export.config_text_digest`, the functions the readers compare
  against. The gate test is `test_the_doh_shape_against_the_synthetic_doh_export`;
  `docs/klant/OPENSTAANDE-METINGEN.md` (A15a) says the measurement export is
  not in the repository.
- `scripts/pseudonymise_export.py` neutralises free text by field (comment,
  monitor send/receive strings, store name, rewrite string-builder
  expressions, a time zone with a place name, NT domain, the path of a
  Gateway home URL) and EUI-64 link-local IPv6 addresses, and refuses output
  in which such a field survived. `--free-text-only` after-treats an export
  pseudonymised before that; the alias family for extra terms is `TERM`.
  `tests/fixtures/lab-export-vpx-20260826/` went through it once; every CVE
  verdict pinned on that export is unchanged.
- The hygiene guards read the names they search for (local directories,
  folders that never ship, tool and model names, the working name) from a
  needle list outside the tracked tree (`tests/private_needles.py`); without
  it those guards skip with that reason.

### Changed (product surface)
- The advice label of a step this product can perform reads
  `dit product kan dit uitvoeren`; it carried an internal working name.

### Documentation
- README: the quickstart installs through the same three hash-locked lines
  as CI and CONTRIBUTING.
- CI also runs on a pushed `v*` tag; the release notes
  (`.github/release-notes-template.md`) name the URL of that tag run.
- README and `docs/klant/SECURITY.md`: the reference `sso` presenter records
  the sign-in account of the server's session, not a verified approver; it
  only means something when the MCP host runs under another account or
  session than the administrator, and the window warning holds for `sso` too.
- SECURITY.md: the private-reporting button works only while the repository
  is public with the setting on; email is an equal route.

### Dependencies

The dependency audit of the first public CI run on the
1.0.0 tree reported seven advisories in four locked distributions, all
published after 2026-09-30. None of them is reachable through this product
(the server speaks stdio, not the stateful Streamable HTTP transport the mcp
advisory concerns; the product never parses a JWT, never streams an HTTP
response and never opens a TLS connection from Python), so this is a
hygiene change, not a security fix of the product itself.

- `mcp` 1.29.0 -> 1.30.0 (CVE-2026-59951, stateful Streamable HTTP sessions
  without idle timeout or cap). Still the 1.x maintenance line;
  `mcp.server.fastmcp` is unchanged.
- Locked transitive distributions: `pyjwt` 2.14.0 -> 2.15.1
  (PYSEC-2026-4141, PYSEC-2026-4183), `urllib3` 2.7.0 -> 2.8.0
  (PYSEC-2026-4175, -4176, -4177), `certifi` 2026.7.22 -> 2026.10.19
  (PYSEC-2026-4320, compromised emSign intermediates).
- `uv.lock` and `requirements-dev.txt` re-exported; `requirements-build.txt`
  unchanged (pip and packaging kept their versions).

## [1.0.0] - 2026-09-30

The public 1.0.0: the release candidate of 2026-09-05 plus the hardening rounds below
(five red/blue rounds and a second acceptance test on a lab appliance).

### Documented limits (from the final red-team pass)

- The duplicate-address check in the targets file compares text: an IPv4 address in another
  notation (leading zero, decimal, hexadecimal) counts as a different address, while the transport
  reads it as a normal one. Use plain dotted-decimal addresses. `docs/klant/SECURITY.md`,
  `docs/klant/HANDLEIDING.md`.
- The Posh-SSH content manifest covers ordinary files under the module directory; it does not see
  what lies behind a directory junction or in alternate data streams. `scripts/README.md`,
  `docs/klant/SECURITY.md`.

### Changed

- The open-phase refusal ("er staat nog een fase open op dit doel; ...") now leaves through the
  same openness seam as the undecided start next to it, not as a bare string: an answer with the
  question (`voorstel` or `uitvoering` and the tool), one finding for the tool carrying the same
  sentence as before, and the ledger fact as evidence ("ledger van dit doel: regel fase_gestart
  voor fase X zonder sluitregel, gestart om ..."). The run is not echoed. Both places that refuse
  on an open phase - the confirmed phase and every other writing tool - do this. `mcp_server`;
  `tests/test_product_surface.py`, `tests/test_handelen_zonder_code.py`.
- While a confirmed phase call still waits for its `fase_gestart` row, the undecided-start refusal
  and `onderhoud_upgrade_stand` now say so: "... de server wacht nog op zijn regel fase_gestart
  (tot <moment>)", with "het wachten op de regel fase_gestart loopt tot <moment>" as evidence.
  Measured with two client sessions on one server: another caller and the stand read "het wachten
  op zijn regel fase_gestart brak af" [vastgesteld] for a wait that was still running, and seconds
  later the same call answered FASE GESTART. "brak af" is kept for a wait that was cancelled or
  raised, including a cancellation while the runner is being launched. The hold itself is
  unchanged. `mcp_server._act`, `upgrade.UndecidedStart.waiting_until`; `docs/klant/SECURITY.md`,
  `docs/klant/HANDLEIDING.md`; `tests/test_upgrade_start_window.py`, `tests/test_product_surface.py`.
- Posh-SSH now has to be exactly 3.2.7, not "3.2.7 or higher within the major version": a host
  that already has a different 3.x version installed now fails closed (exit code 3) on every
  phase, the configuration-save script and the live-measurement preflight, where it used to load
  and continue. Install (or reinstall) the pinned version with `Install-Module -Name Posh-SSH
  -RequiredVersion 3.2.7 -Scope AllUsers`. `scripts/GjkUpgrade-Ssh.ps1`;
  `docs/klant/HANDLEIDING.md`.

### Security

- A confirmed phase whose runner writes no `fase_gestart` within the 20-second wait now keeps its
  target blocked. A slow runner used to leave an empty ledger behind the "telt niet als gestart"
  answer, and a new proposal plus confirmation for the same phase and run started a second runner
  against the same appliance - and read the first runner's row as its own start (measured offline:
  two `fase_gestart` rows R1 with different action ids). The server now holds such a start in a
  register of its own, per target name and per server process, with the target name in the
  spelling the open-phase refusal compares targets on: a second configured name that differs only
  in capitalisation or in the domain part of an FQDN is held too (measured before the register
  followed that rule: inside the window a backup on such a name was proposed and run). A name with
  another first label is another target, to the register as to that refusal; that two targets do
  not share an address is the start check on the targets file (next entry), which compares the
  address as text. Every
  writing tool on that target, proposal and confirmed call alike, refuses with "op dit doel is de
  start van fase X (run Y) nog onbeslist ..." until the row lands (the ordinary open-phase
  refusal then takes over) or the phase's time limit, counted from the runner's launch, passes
  (the refusal then lifts with an `onbesliste start` line in the answer that goes through). The
  same holds when the wait itself breaks off, and when the call is cancelled while the runner is
  still being launched: the target is held from the moment the start is requested (a cancellation
  during the launch used to leave a runner behind and no hold), and only a launch that provably
  started no process takes the hold back. The timeout answer says until when the target stays
  blocked, and
  `onderhoud_upgrade_stand` shows an undecided start as a finding of its own. Behind it, `python
  -m nsmcp.upgrade_measure` action `start` - the one writer of `fase_gestart` - refuses with exit
  code 2 when the ledger directory already carries an open phase for that target within its time
  limit (any run), so a second runner excludes itself once the first has written its row; a
  retry after a closing row or past the time limit is not affected. `mcp_server._act`,
  `upgrade.UndecidedStarts` (keyed on `upgrade_gate._normalised_target()`),
  `upgrade_measure._start`; `docs/klant/SECURITY.md`,
  `docs/klant/HANDLEIDING.md`, `scripts/README.md`; `tests/test_upgrade_start_window.py`,
  `tests/test_upgrade_measure.py`, `tests/test_product_surface.py`.
- A targets file in which two targets carry the same address no longer starts. Everything that
  keeps a second writer off an appliance - the open-phase refusal, the hold of an undecided start
  and the phase runner's own check - holds a target by its name. Measured: a second configured
  name with another first label for the same address (`doos-b` next to `netscaler-02`, one
  address) proposed and really ran a backup while a phase start on the other name was undecided,
  and again once that phase was open. The start now refuses with a reason that names both
  targets and the field ("hebben hetzelfde adres"), for every target in the file. The address is
  compared as text - case and whitespace aside - and never resolved, so one appliance under a
  host name and under its IP address is not caught; the documents say so. The alias names in the
  start-window tests now carry addresses of their own. `start._require_one_target_per_address`;
  `docs/klant/SECURITY.md`, `docs/klant/HANDLEIDING.md`; `tests/test_start.py`,
  `tests/test_docs_claims.py`, `tests/test_upgrade_start_window.py`.
- Nothing the server reads, runs or writes may lie in the export map any more - the one map a
  supplying party may write. Only the provenance map and the code file were held against it: an
  action register, firmware map, collect script, knowledge file, target file, runner, write script
  or fixture map inside the export map started without a word, and a script there is code run by
  whoever supplies the export. The server now refuses to start when the configuration file,
  `kennispad`, `doelen`, `verzamelscript`, `handelen.schrijfscript`, `handelen.fixturemap`,
  `onderhoud.runner`, `onderhoud.ledgermap`, `onderhoud.firmwaremap` or `onderhoud.actieregister`
  lies in the export map, or the export map in the ledger map or the firmware map, and names the
  field ("<veld> ligt in de exportmap ..." / "de exportmap ligt in <veld> ..."); a path it cannot
  compare is refused too. The map of the configuration file and of the scripts may still hold the
  export map: that is the layout of the configuration example in the manual. The trust model and
  "Bestanden op schijf" say so in so many words - which maps the reverse check covers, which it
  does not, and that the allowed layout is safe only while the supplying party cannot write that
  parent map. `start.py`;
  `docs/klant/SECURITY.md`, `docs/klant/HANDLEIDING.md`; `tests/test_start.py`,
  `tests/test_docs_claims.py`.
- The code file and the sso presenter of `handelen.codekanaal` may no longer sit in a map the
  maintenance half reads or writes: the ledger map (with the provenance map in it), the provenance
  map next to the configuration, the action register's map, the firmware map and the runner's own
  map. Measured before: `pad` = `<ledgermap>\herkomst\herkomst.jsonl` or the action register itself
  started, and every proposal then overwrote the provenance record or the register. `start.py`;
  `tests/test_start.py`.
- CI no longer fetches anything outside a hash check, and pins what it runs. The build toolchain
  (pip 26.2.1, setuptools 84.0.0, wheel 0.48.0, and packaging, which wheel needs) comes from a new
  hash-locked `requirements-build.txt` with the wheel and the sdist hash of each, installed first
  with the pip setup-python provides; the unpinned `pip install --upgrade pip` is gone; the project
  is installed with `--no-build-isolation`, so setuptools is no longer fetched from the index into
  an isolated build environment without a hash; and the dependency audit covers the new file. The
  three actions run from the full commit id of the newest release within their major version
  (checkout v4.4.0, setup-python v5.6.0, upload-artifact v4.6.2), the tag as a comment. After
  installing Posh-SSH 3.2.7, CI checks its content with the new
  `scripts/Get-GjkPoshSshManifest.ps1`: a sha256 manifest over every module file except
  `PSGetModuleInfo.xml`, compared with the value measured over that version from the PowerShell
  Gallery; the full list is printed and a difference fails the job. An operator can run the same
  script. CONTRIBUTING.md shows the same three install lines as CI and names the unattested SBOM
  as an open choice. `.github/workflows/ci.yml`, `requirements-build.txt`, `CONTRIBUTING.md`,
  `docs/klant/SECURITY.md`, `docs/klant/HANDLEIDING.md`, `scripts/README.md`;
  `tests/test_repo_hygiene.py`, `tests/test_posh_ssh_manifest_script.py`.
- The documents now name the PowerShell module path of the account the server runs under
  (`PSModulePath`, in particular `%ProgramFiles%\WindowsPowerShell\Modules` and `$PSHOME\Modules`)
  as an administrative map: the Posh-SSH pin checks the version, not the content or origin of the
  module, so whoever may write there chooses what loads as 3.2.7. They name the module map in
  that account's own profile as well (the CurrentUser scope, `Documents\WindowsPowerShell\Modules`):
  it is searched first, the account itself can write it, and folder redirection can place it in a
  synchronised documents folder. `docs/klant/SECURITY.md`,
  `docs/klant/HANDLEIDING.md`, `scripts/README.md`; `tests/test_docs_claims.py`.
- The phase runner refuses a control character (CR, LF, tab, 0-31 and 127) in every text
  parameter and every forbidden address, not only in `-Doel` and `-Adres`: `-Actieid` is printed in
  the `[ACTIEID]` line the code binds to, `-Run` in a log line and every ledger row, `-Bevestiger`
  and `-Snapshotverwijzing` in ledger rows, and a line break in any of them split that line. Same
  `[FOUT]`/`[GEWEIGERD]` lines and exit code 1, before any label, transport or ledger row, without
  repeating the value. `scripts/Invoke-GjkUpgradeFase.ps1`, `scripts/README.md`;
  `tests/test_runner_script.py`.
- The phase runner no longer passes a firmware bundle name it found through a wildcard into a
  remote shell unchecked. Without a branch in `-Doelbuild` it chose the bundle with
  `build-*-<build>_nc_64.tgz`, and a file named, for example, `build-x';reboot;echo
  '-72.57_nc_64.tgz` became a second command on the appliance in R1 and R2 (measured with the fake
  transport). Every candidate must now have the bundle form `build-<tak>-<build>_nc_64.tgz`
  (ASCII digits and dots, case-sensitive); R1, R2, R3 and R5 check this before the transport
  loads, also on `-WatIs`, and again where the bundle is chosen. A refusal exits with the new
  exit code 4 and never repeats the name. The server always passes a branch-qualified
  `-Doelbuild` and was not affected. `scripts/Invoke-GjkUpgradeFase.ps1`, `scripts/README.md`;
  `tests/test_runner_script.py`.
- R0's floor gate no longer opens on evidence for a target build that is not higher than the
  current build. A reinstall of the running build, or a downgrade within the line at or above the
  floor, now closes with "doelbuild niet hoger dan de huidige build (herinstallatie of downgrade):
  menselijke acceptatie vereist; zet doelbuild_geaccepteerd=true als dat bewust is" and opens as a
  human when that switch is set; the plan and every phase proposal name that verdict beforehand.
  Below the floor the floor's own reason stays the closing one. `upgrade.floor_gate`,
  `upgrade_plan.floor_verdict_finding`; `tests/test_upgrade.py`, `tests/test_upgrade_plan.py`.
- R0's evidence names the pinned knowledge package the floor came from ("kennispakket <versie> van
  <datum>") and warns when that package is more than 30 days older than the day R0 runs, without
  changing the outcome: an old package can name a floor below the vendor's current one. The server
  hands version and date to the runner with the floor (`-VloerPakket`, `-VloerPakketDatum`, R0
  only, form-checked on both sides); a direct runner call without them says "kennispakket niet
  meegegeven". `upgrade.floor_gate`, `upgrade.runner_package`, `handelen.build_upgrade_arguments`;
  `tests/test_upgrade.py`, `tests/test_upgrade_fase.py`, `tests/test_runner_script.py`.
- A target name or address with a control character is refused. Both travel into the write
  scripts as `-Doel` and `-Adres` and are printed in the `[TARGET]` line the confirmation code
  binds to; a line break in either printed a forged `[ACTIEID]` line ahead of the real one
  (measured with `-WatIs`). The server does not start with such a target (every name and address
  in the targets file must be printable), and the phase runner and the save script refuse such a
  value themselves with exit code 1, before any label or transport. `start.py`,
  `scripts/Invoke-GjkUpgradeFase.ps1`, `scripts/Invoke-GjkConfigOpslaan.ps1`;
  `tests/test_start.py`, `tests/test_runner_script.py`, `tests/test_config_opslaan_script.py`.
- The SSH transport loads exactly Posh-SSH 3.2.7, the version its host-key pin was measured
  against. It imported the module by name, so the first or highest installed version won, and a
  module of any version that was already loaded went through (measured with a fake 9.9.9). It now
  imports with `-RequiredVersion 3.2.7` and stops with exit code 3 when that version is missing or
  another one is loaded. The requirement in the manual and in `scripts/README.md` changes from
  "3.2.7 or higher within the major version" to exactly 3.2.7. `scripts/GjkUpgrade-Ssh.ps1`;
  `tests/test_runner_script.py`.
- docs/klant/SECURITY.md names two boundaries it left implicit: the action register is plain JSONL
  without a signature, so whoever can write it can open R0's backup gate, and whoever can write
  `onderhoud.firmwaremap` chooses both the bundle and the vendor value R1 checks it against. Both
  belong in a directory only the administrator can write. The docstring of
  `upgrade.backup_register_gate` says the same.

- `config_drift` no longer shows two header lines at openheid `volledig` that carry a secret, on
  the running or the saved side. Measured before: a monitor's custom header `Cookie : session=...`
  (blank space before the colon, which the `cookie:` marker does not see) and `add rewrite action
  ... insert_http_header Authorization policy <value>` (the policy-object exception of the
  Authorization shape looked only at the word after the header name) reached the answer with
  their value. Three shapes are added to the secret filter: a cookie header with blank space, an
  invisible character or a quote before its colon, on every reading of the line (a no-break or
  ideographic space and a full-width colon included); every rewrite action that mentions
  Authorization; and every header-writing argument (an `..._http_header` action, `-customHeaders`,
  `-headers`) that names Authorization or a cookie. `add authorization policy`, `bind
  authorization policylabel` and `-defaultAuthorizationAction` stay visible, and the withheld
  counts on both lab exports stay 11/11 and 18/18. The claim in the documents and in the tool
  description now reads "a recognised secret": the filter works on known markers and shapes, as
  docs/klant/SECURITY.md already said further on. `config_drift.SECRET_PATTERNS`;
  `tests/test_config_drift.py`.
- `config_drift` no longer shows the rest of a configuration line after a line break other than
  LF. Measured before: the export read split the running and the saved config on every line break
  Python knows - a lone CR, VT, FF, the file, group and record separators, NEL, U+2028, U+2029 -
  so `-password<U+2028><value>` reached the credential filter and the secret filter as two lines
  and the value was shown at openheid `volledig` as a line of its own, as was a cookie header with
  such a character before or after its colon. Every reader of the two configs now gets lines split
  on LF alone (CRLF read as LF); such a character stays inside its line, where the filter reads it
  as a space or as nothing. Neither lab export carries one: its line counts and the withheld
  11/11 and 18/18 stay the same. `export.Export._config_text_lines`; `tests/test_export.py`,
  `tests/test_config_drift.py`.
- `config_drift` withholds a secret header in a raw HTTP message as well: a responder action that
  names a cookie or Authorization, and a monitor's `-send` or `-httpRequest` and an HTTP
  callout's or a webAuth action's `-fullReqExpr` that does, are withheld like a rewrite action and
  `-customHeaders` already were. Measured before: a Set-Cookie or Cookie header with a look-alike
  colon, `Authorization policy <value>`, a header name as the last word before an escaped CRLF
  and a Set-Cookie header put together by concatenation reached the answer at `volledig`. Neither
  lab export carries such a line; the withheld counts stay 11/11 and 18/18. Every shape of the
  filter, and every alternative and optional part of one, now has a test case nothing else
  withholds, so dropping a shape, or narrowing it by dropping an alternative or an optional part
  or by allowing a repeated part only once, fails a test. `config_drift.SECRET_PATTERNS`;
  `tests/test_config_drift.py`.
- `rapport_vergelijk` and `rapport_wat_is_er_veranderd` no longer show a compared reference name
  at openheid `beperkt`. Measured before: a csvserver's `targetlbvserver` and a certificate's
  `linkcertkeyname` that named an object absent from the export reached both answers verbatim,
  because no name family knew such a name. The two fields are named in `compare.REFERENCE_FIELDS`
  and harvested by `compare.names_in_compare_sources()`, the seventeenth family of
  `disclosure.names_from_export()`; every other compared field carries a value, not a name, and a
  test fails on a new compared field - configuration or state - that is in neither list. On the
  fixture exports the family
  adds no name. `tests/test_compare.py`.
- The knowledge loader refuses a package that contradicts itself or counts twice: a branch whose
  fix-build lies below its own affected bound (`getroffen "< 73.37"` next to `fix "66.00"`; a
  fix-build at or above the bound stays valid), an affected range or fix-build it cannot compare,
  a bulletin listed twice, and a CVE identity in more than one bulletin or twice in one. Measured
  before: such packages turned 6 hit / 3 not hit into 0 / 9 or 7 / 4, and lowered the floor from
  73.37 to 66.00, all established. The verdict now parses the affected range with the loader's own
  pattern. `knowledge.load_knowledge()`; `tests/test_knowledge_integrity.py`.
- New optional configuration field `kennispin` (`{"versie": ..., "digest": ...}`): the knowledge
  package the operator approved, fingerprinted as the sha256 of its canonical JSON content, so line
  endings and indentation do not count. A package that differs in version or content is refused,
  with a reason that names the differing half and never the expected digest. Without the field
  the package loads, but every CVE verdict, floor, offered build and update verdict carries
  `[niet vastgesteld]` with the reason `kennispakket niet gepind in de configuratie`, and so does
  the extra step after the upgrade in `rapport_na_upgrade` (measured before: an outstanding step
  read as `NIET GERAAKT [vastgesteld]` once only its value in the package was changed); the floor of
  the upgrade plan and of R0's floor gate is then not established (R0 closes unless the target
  build is accepted), pre-flight check 6 is not assessed, and the scorecard counts no CVE verdict.
  `build_server()` takes `knowledge_pin` and defaults to no pin. `python -m nsmcp.knowledge
  --digest <pad>` prints the block, and pins no package the server would refuse.
  `tests/test_knowledge_integrity.py`, `tests/test_rapport_na_upgrade.py`. After a knowledge
  refresh the pin must be updated (docs/klant/AUTOMATISERING.md, step 5). `config.example.json`
  pins `kennis.example.json`; `tests/test_examples.py` ties the pin to that package.
- `status_ververs` records every export it collects - target, manifest sha256, UTC moment and
  export map - in `herkomst/herkomst.jsonl` outside the export map: under `onderhoud.ledgermap`, or
  next to the configuration file without `onderhoud`; the server does not start when that map
  lies inside the export map or the export map inside it. A reading tool given a `doel`,
  `rapport_na_upgrade`, the upgrade phases, and the drift and certificate-use lines of the writing
  proposals now need the newest record for that target to carry the export's manifest hash;
  otherwise "doel niet vastgesteld: de export is niet door deze server voor dit doel verzameld".
  Measured before: an export of target B relabelled as target A with a recomputed hash answered
  as A's established build. Every data age line now ends with `herkomst: verzameld door deze
  server op <tijd>` or `herkomst: niet vastgesteld (aangeleverde export)`. `build_server()` takes
  `provenance_dir` and defaults to none, which records and proves nothing. The record carries the
  manifest hash the scan computed in its own work map (`SwapGate.manifest_hash`), not a second
  reading of the export map: an export put in its place right after the swap is not recorded, and
  the scan answer says so.
  `tests/test_export_provenance.py`.
- The startup check that keeps the provenance map and the export map apart, and the one that
  keeps the file code channel out of every directory the product reads, now compare every
  spelling of one location. Measured before: a provenance map inside the export map, written
  with the Windows extended prefix (`\\?\C:\...`), was accepted as lying beside it, because
  `Path.resolve()` keeps that spelling. The extended and device prefix is peeled down to the
  drive or share it names and the result is compared case-folded; where no text rule maps a
  spelling back (`\\?\UNC\localhost\C$\...`, `\\localhost\C$\...`), the directory is compared by
  volume and file number with every existing directory above the inner path. A map beside the
  export map stays accepted in every spelling. The path as written counts as well as the
  resolved one: a map or code file written through a link that lies in the export map and points
  out of it is refused, since the server uses the path as written. A path the check cannot
  compare, such as one with a NUL character, stops the start instead of counting as lying
  outside. `start._lies_within`;
  `tests/test_export_provenance.py::test_a_provenance_map_inside_the_export_map_is_refused_in_every_spelling`,
  `tests/test_export_provenance.py::test_a_provenance_map_through_a_link_inside_the_export_map_is_refused`,
  `tests/test_start.py::test_a_code_file_inside_a_directory_the_product_reads_is_refused_in_every_spelling`,
  `tests/test_start.py::test_a_code_file_path_that_cannot_be_compared_is_refused`.
- The knowledge loader holds bulletin and CVE identities to their ASCII form: `CTX` followed by
  digits, and `CVE-`, four digits, a hyphen and four or more digits. Measured before: a second
  copy of a CVE with its hyphens replaced by the Unicode hyphen (U+2010) passed the loader of an
  unpinned package as another identity. Any other spelling - another hyphen or dash, non-ASCII
  digits, a space, lower case - refuses the package with a reason that names the field and the
  form, not the value. A copy of an identity listed earlier that differs only in case or in the
  white space around it is refused by the duplicate check first; that reason quotes the spelling,
  with control characters escaped. `knowledge._identity_problem`;
  `tests/test_knowledge_integrity.py::test_a_cve_id_spelled_with_a_unicode_hyphen_is_refused`.
- docs/klant/SECURITY.md and HANDLEIDING.md ("Bestanden op schijf") state the trust boundary the
  startup check cannot see: it compares paths, not rights. The configuration directory and the
  ledger map with the provenance map in it must be writable only by the operator and the
  scanning account, and in the whole chain of directories above them no one else may rename,
  delete or replace a directory; a provenance map beside the export map under a parent the
  supplier can write is no independent boundary. The recommended layout
  keeps the export map apart from those directories.
- An sso delivery refused because the answer does not mirror the section and fingerprint now
  leaves one fixed line on the server's stderr, `[codekanaal] sso-presenter-protocol-oud`, without
  the code or the section; the caller still reads only the channel-failure text.
  `code_channel.MirrorRefused`;
  `tests/test_handelen_zonder_code.py::test_a_presenter_that_ignores_the_section_leaves_one_fixed_marker_on_stderr_and_no_secret`.
- The sso channel refuses a presenter answer that is not exactly one line on stdout, before it is
  parsed; it used to read the first line and accept a delivery whatever followed.
  `tests/test_code_channel.py::test_a_presenter_answer_of_more_than_one_line_delivers_no_code`.
- A confirmation code is now also bound to the allowlist section (`doel`) it was proposed for,
  not only to the tool, the arguments and the label the write script reports. Two sections that
  allow the same action get the same label from the script; a code proposed for one of them is
  refused and burnt under the other, nothing runs and no register row is written.
  `section` is a required keyword of `confirm.ConfirmationStore.issue()`/`redeem()`, so a caller
  that leaves it out fails instead of issuing a code bound to no section;
  `tests/test_handelen_zonder_code.py::test_a_code_proposed_for_one_target_is_refused_and_burnt_under_another`,
  `::test_an_object_tool_code_for_one_target_is_refused_and_burnt_under_another`,
  `::test_a_config_opslaan_code_for_one_target_is_refused_and_burnt_under_another` and
  `tests/test_confirm.py::test_the_section_is_a_required_keyword_of_issue_and_redeem`.
- The backup read-back counts only a positive line: `[OK]` directly followed by the collection
  phrase. A line that names the object behind `[FOUT]` or `[WAARSCHUWING]`, or says `ontbreekt`
  or `niet gevonden` (in any case or spacing), no longer counts as found, also at exit code 0. A
  `[FOUT]` line that names the object fails the whole read-back, also next to an `[OK]` line; a
  `[WAARSCHUWING]` line next to an `[OK]` line does not, since the write script prints that pair
  when the create call returned an error but the object is there. `backup.readback_ok()`;
  `tests/test_backup.py::test_a_negative_readback_line_naming_the_object_is_a_failure`,
  `::test_a_positive_line_that_carries_a_negative_word_is_a_failure`,
  `::test_a_warning_next_to_a_positive_line_still_passes` and
  `::test_a_failure_line_naming_the_object_fails_the_read_back_next_to_a_positive_line`.
- `rapport_na_upgrade` now checks the target whose ledger it reads (the given `doel`, or the one
  configured target when `doel` is left out) against the target the export describes: the ledger
  was the chosen target's, but the CVE verdict and the extra step came from the one export, which
  could describe another target. An export of another target, or one that does not record its
  target, is refused and no report is built, with or without `doel`. `mcp_server._export_is_van()`;
  `tests/test_rapport_na_upgrade.py::test_the_report_refuses_an_export_of_another_target` and
  `::test_the_report_without_doel_refuses_an_export_of_another_or_unknown_target`.
- The `sso` code channel now sends every action argument (each argument the tool was called
  with, except `doel` and `bevestiging`) in a field `argumenten`: the same sorted lines the window
  and the file channel show under `wat:`, each value capped at 120 characters. For a phase that
  includes the snapshot reference and the acceptance switches, which the request did not carry
  before. The allowlist section (`doel`) the code is also bound to is not among these lines; it
  travels in a field of its own, `sectie` (next entry). The
  reference presenter requires the field and shows the lines above the code, apart from the
  proposal text, so its 1000-character cut no longer hides them. A presenter must show every
  line; one from before this version ignores the field, and its answer no longer counts as a
  delivery (see the entry on the mirrored section below). The request's
  `vingerafdruk` covers the tool, the arguments, the shown target label and the section. The
  snapshot reference stays a human promise the server does not check beyond "not empty", and a
  reference over 120 characters is shown cut; SECURITY.md says so.
  `code_channel._argument_lines()`, `scripts/sso_presenter_windows.py`;
  `tests/test_code_channel.py::test_the_sso_request_shows_every_phase_argument_the_code_is_bound_to`
  and `tests/test_sso_presenter_context.py::test_every_argument_line_is_shown_apart_from_the_bounded_proposal`.
- Every code channel now shows the allowlist section (`doel`) the code is bound to. The write
  script forms its target label from its own facts, so two sections that allow the same action
  get the same label, and a proposal under one of them read exactly like a proposal under the
  other in every channel. The window and the file show `sectie: <name>` on a line of its own
  directly under `doel:`, also when the name reads like the label. The `sso` request carries it
  in a required field `sectie`, checked like `doel` before the presenter starts (not empty,
  printable, at most 256 characters, never cut), and its `vingerafdruk` covers the section: two
  sections with the same label and the same arguments give two different fingerprints. The
  reference presenter shows `sectie` directly under `doel` and refuses a request without it; a
  presenter from before this version ignores the field, and its answer no longer counts as a
  delivery (next entry), so update presenter and server together. The presenter contract gains a
  seventh positional argument, `section`; a
  presenter that does not accept it fails closed like any other channel failure.
  `code_channel._message()`, `SsoCodeChannel.__call__`, `mcp_server._present()`,
  `scripts/sso_presenter_windows.py`;
  `tests/test_code_channel.py::test_every_channel_shows_the_section_so_two_sections_with_one_label_differ`,
  `::test_the_sso_request_names_the_section_and_binds_it_in_its_fingerprint`,
  `::test_the_sso_channel_refuses_an_unusable_section_before_starting_the_presenter`,
  `tests/test_sso_presenter_context.py::test_the_window_shows_the_section_on_its_own_line_under_the_target`
  and `tests/test_handelen_zonder_code.py::test_two_sections_with_one_label_reach_the_operator_as_two_different_proposals`.
- The `sso` channel accepts a delivery only when the presenter's answer mirrors the `sectie` and
  the `vingerafdruk` it sent, exactly. A presenter from before the `sectie` field ignored that
  field, showed the code without the section and still answered `afgeleverd: true`, and the
  channel accepted that on `afgeleverd` alone. Such an answer is now no delivery: the channel
  fails closed with "de presenter spiegelt sectie en vingerafdruk niet terug: verouderde of
  onbekende presenter", the proposal is refused with the usual channel-failure text, and the code
  that presenter showed is spent, so it cannot be redeemed. The same holds for a mirror of
  another request's section or fingerprint, or one that differs in case or spacing. The reference
  presenter mirrors both fields after OK only. No protocol version field and no fallback to the
  old answer. The mirror proves the presenter read the section, not what it displayed; that
  guarantee holds for the shipped reference presenter or a presenter you have reviewed.
  `code_channel.SSO_ANSWER_MIRROR_FIELDS`, `SsoCodeChannel.__call__`,
  `scripts/sso_presenter_windows.py`;
  `tests/test_code_channel.py::test_a_presenter_that_ignores_the_section_delivers_no_code`,
  `::test_a_presenter_that_mirrors_another_section_or_fingerprint_delivers_no_code`,
  `::test_the_reference_presenter_delivers_under_each_of_two_sections_with_one_label`,
  `tests/test_sso_presenter_windows.py::test_ok_mirrors_the_received_section_and_fingerprint_exactly`,
  `::test_answer_mirror_fields_match_the_sso_channels_own_check` and
  `tests/test_handelen_zonder_code.py::test_a_presenter_that_ignores_the_section_leaves_no_redeemable_code`.
- Forbidden target addresses for the firmware upgrade route (`onderhoud_upgrade_fase`) come from
  the configuration (`handelen.verboden_adressen`), not from code. The runner's static name guard
  is unchanged; address forms are supplied by the caller at run time and never committed to this
  repository.
- docs/klant/SECURITY.md no longer promises more than the header rule of the `config_drift`
  secret filter covers. "Whatever word or character follows the header name" holds while the
  header name itself stands in the line whole; a header name put together from pieces of text
  (`"Set-Coo" + "kie: ..."`, also in the response a responder action writes) is now named in the
  boundary next to a look-alike marker and a look-alike colon, where it already belonged. The
  filter is unchanged.

### Fixed

- A test of the sso presenter used the real machine name and account name of a development machine
  as its test value, and test data and a comment elsewhere carried the same account name. They are
  synthetic now. A new guard reads the name of the machine the suite runs on and its account name
  from the environment (no literal can guard this without being the leak) and holds every tracked
  text file to not carrying either, in any case; it reports only the path and line, never the
  value. Names shorter than four characters are skipped, and the report address SECURITY.md
  publishes on purpose is the one exception. `tests/test_repo_hygiene.py`.
- Three things slipped past the hygiene guards, because each guard looked at part of the tree
  only. The name of the supplier's internal knowledge system stood in seven places outside
  `docs/klant/` (project metadata, three modules, the SSH transport, scripts/README), each citing a
  lab lesson by it; the lesson's slug stays, the name is gone. A fixture README named the local
  path of the export it was copied from. And code, tests and scripts carried non-ASCII characters
  against the contributing rule: three section signs in `disclosure.py`, an accented letter in
  scripts/README, and accents in comments, docstrings and test data of eight test files (test data
  now written as escapes, the same string at run time). The knowledge-system guard and the
  local-path guard now scan every tracked file - the local-path guard in any capitalisation and
  with one to four separators, so a JSON-escaped path is caught outside `*.py` too, with a test
  that it still catches each spelling - and a new test holds every tracked file under
  `src/`, `scripts/` and `tests/` to ASCII; CONTRIBUTING says the rule covers code, tests and
  scripts, while the Dutch customer documents may carry accents. `tests/test_product_surface.py`,
  `tests/test_repo_hygiene.py`.
- Two claims now say what is true. The manual said `soak_uren` "mag alleen groter zijn dan 24",
  while the start check accepts 24 itself and its own error says "minimaal"; it now says "is
  minimaal 24". And `pyproject.toml` carried "Development Status :: 4 - Beta" next to version
  1.0.0; it now says "5 - Production/Stable". A third, CONTRIBUTING's "the first two lines mirror
  what CI does" while CI had three, is covered by the install-line entry under Security.
  `docs/klant/HANDLEIDING.md`, `pyproject.toml`; `tests/test_docs_claims.py`.
- An `exportmap` the server cannot compare (a NUL character, for one) is now refused over the
  export map itself: "exportmap is geen pad dat de server kan vergelijken (bijvoorbeeld een
  NUL-teken)". The refusal used to name `handelen.codekanaal.pad`, because the code-file check was
  the first to compare against the export map. `start._require_comparable_export_dir`;
  `tests/test_start.py`.
- The server's firmware bundle form now ends at the real end of the name (`\Z`), not before a
  trailing line break (`$`), the same rule the phase runner's own bundle check (`\z`) keeps. A
  Windows file name cannot carry a line break, so this is consistency, not a reachable hole.
  `handelen._FIRMWARE_BUNDLE_RE`; `tests/test_handelen.py`.
- After the confirmation code was redeemed, a phase runner that could not be started now gets an
  honest answer: the action did not start, the code is spent, and the kind of failure. Before, a
  missing Windows PowerShell surfaced as the generic "unexpected error" text, and a process or log
  file that did not open was reported through the configuration handler, with the raw exception
  text and its local paths as an established finding. `mcp_server` (`onderhoud_upgrade_fase`);
  `tests/test_upgrade_fase.py`.
- The manual no longer says that an export differing only in its header lines stays `uit` "only
  if the header lines report a save at or after the change": without lines in which the collector
  replaced a value, it is `uit` whatever the headers say; the headers count only next to such
  lines.
- A test pins the promise that the key behind the keyed digest of the withheld part is drawn per
  call: both sides of one call share it, two calls never do, and the digest of the same line
  differs between calls. `tests/test_export.py`.
- The docstring of the writing path says `beperkt` where it said `volledig` for the level at which
  a caller types pseudonyms, and names that a real decision point would have to judge the
  translated name.
- A line that differs between the running and the saved config only in the part the export
  withholds as a possible secret now counts as drift, when the export carries that value (see
  the next entry for an export that does not). Measured before: `add system user` with
  another password, an LDAP action with another `-ldapBindDnPassword`, `set ns rpcNode` with
  another `-password` and an LDAP monitor with another `-password` - a password changed and not
  saved - gave `config-drift: uit` and "de inhoud is gelijk" as established in `config_drift`,
  `uit` in `ha_stand` and `geen blokkade` in pre-flight check 4, because the comparison ran on
  the redacted lines only. The export now counts, from the lines before redaction, how many lines
  per side are equal after it and different before it, and hands out that number and nothing
  else (a keyed digest per line under a key that lives for one call; no line, no value, nothing
  kept). The count is part of the only-in counts of the one evidence sentence (", waarvan N per
  kant alleen in een achtergehouden deel"), a finding "verschil in achtergehouden deel" at every
  openheid, counted at `minimaal` as a visible difference is, and in check 4 an attention point
  that says `config_drift` counts these lines and does not show them. Both lab exports count
  zero - by construction, since the collector already replaced every such value with its marker;
  whether NetScaler writes an encrypted value identically into running and saved is not measured
  (docs/klant/OPENSTAANDE-METINGEN.md). The withheld 11/11 and 18/18 stay the same lines.
  `Export.withheld_only_difference`, `config_drift.read_comparison`; `tests/test_config_drift.py`,
  `tests/test_export.py`, `tests/test_preflight.py`.
- An export on which the collector already replaced a credential value with `<REDACTED>` no
  longer reads as "no drift, the content is equal" while its header lines say the configuration
  changed after the last save. The released collector writes that marker on the jumphost in the
  running and the saved config alike, so a password changed and not saved is two equal lines in
  the export. Measured before, on the three shapes the lab exports carry (system user, rpcNode,
  monitor password) and on the first lab export as shipped: `config-drift: uit` and "de inhoud is
  gelijk" as established, `uit` in `ha_stand`, `geen blokkade` in pre-flight check 4. The export
  now counts those lines in the same read (a number per side); with such lines and header lines
  that say changed after the last save, or that cannot be read, `config_drift` and `ha_stand` say
  `onbevestigd` with that number as the reason, check 4 is `niet beoordeeld` with it, the
  `config_opslaan` proposal adds "maar config-drift is onbevestigd" to its counts, and
  GJK-L1-HA-004 is NIET BEOORDEELD with the two config texts as its source (not `config/hanode`).
  With header lines that say saved at or after the last change the answer stays `uit` and the
  evidence notes the number. The first lab export changes from `uit` to `onbevestigd`; the second
  stays `uit`. `Export.withheld_only_difference`, `config_drift.Comparison.undecided`;
  `tests/test_config_drift.py`, `tests/test_export.py`, `tests/test_preflight.py`,
  `tests/test_handelen_zonder_code.py`, `tests/test_scorecard.py`.
- The file code channel marks its file `verbruikt` only while the file still shows the code that
  was just redeemed. With several proposals outstanding, redeeming an older code used to
  overwrite the file although it showed a newer code that was still valid, which then stayed
  redeemable but out of view. The comparison folds case and spacing the way the confirmation
  store does, and the read, the comparison and the rewrite hold one lock with the proposal
  writes, so a proposal written meanwhile is not wiped either. `FileCodeChannel.spent()`;
  `tests/test_code_channel.py::test_spending_an_older_code_leaves_the_newer_code_in_the_file`,
  `::test_the_file_is_marked_spent_however_the_code_was_typed`,
  `::test_a_proposal_written_while_a_code_is_spent_is_not_wiped` and
  `tests/test_handelen_zonder_code.py::test_redeeming_an_older_proposal_leaves_the_newer_code_in_the_file`.
- The code file path (`handelen.codekanaal.pad`, also the presenter of the `sso` kind) written
  through a volume GUID (`\\?\Volume{...}\...`) reaches the check whether it lies in a directory
  the product reads or writes on Python 3.11 as well. Measured on the 3.11 CI runner: pathlib there
  reads that spelling as not absolute, so the start refused it as `moet een absoluut pad zijn`
  where 3.12 checked its place. A path behind the extended or device prefix now counts as absolute
  whatever pathlib answers; every other spelling keeps pathlib's rule of a drive and a root, so a
  root without a drive (`\codes\code.txt`) stays refused. `start._is_absolute_path()`;
  `tests/test_start.py::test_the_absolute_check_reads_every_windows_spelling`,
  `::test_a_prefixed_path_is_absolute_whatever_pathlib_says` and
  `::test_a_volume_guid_code_path_reaches_the_containment_check_whatever_pathlib_says`.

## [1.0.0-rc.1] - 2026-09-05

First public release. The version number restarts at 1.0.0: everything before
this was internal.

### After the first acceptance test on a lab appliance

Changes made before this release was tagged. Each line names the code path or
the test that carries it.

#### Added

- `config_drift` (reading, new chapter `config`): which lines differ between
  the running and the saved configuration. Lines only at `openheid: volledig`,
  always through the credential filter and a cap; at `beperkt` only the
  command head and a count, at `minimaal` only counts. `src/nsmcp/config_drift.py`;
  `tests/test_config_drift.py::test_beperkt_shows_only_the_command_head_and_a_count`
  and `::test_minimaal_shows_only_counts`.
- `config_opslaan` (writing, chapter `config`): has the NetScaler save its
  running configuration over SSH through `scripts/Invoke-GjkConfigOpslaan.ps1`,
  next to the phase runner and on its transport, after a role check - never
  on a secondary - and judges the raw read-back. `handelen.perform_save()`,
  `backup.save_readback_ok()`;
  `tests/test_config_opslaan_script.py::test_on_a_secondary_the_script_refuses_without_saving`
  and `::test_on_the_primary_it_saves_and_prints_the_raw_readback_for_the_server`.
- `status_doelen` (reading, chapter `status`, always registered): per
  configured target the address, the export age, the last maintenance run, the
  writing tools granted there and whether a host key is pinned - never a
  credential target or a fingerprint. `src/nsmcp/doelen.py`;
  `tests/test_status_doelen.py::test_no_credential_target_or_fingerprint_in_any_answer`.
- An optional `doel` on every export-backed reading tool. It is a check, not a
  switch: an unknown target is refused without repeating it, and a configured
  target the export does not describe is refused with "de export van deze
  server beschrijft een ander doel; ververs eerst met status_ververs". At
  `beperkt` the pseudonym `status_doelen` showed is a valid `doel`.
  `mcp_server._load_for()`;
  `tests/test_status_doelen.py::test_every_export_backed_reading_tool_checks_its_doel_against_the_export`
  and `::test_at_beperkt_a_pseudonym_from_status_doelen_is_a_valid_doel`.

The register now holds 34 tools: 27 reading and 7 writing, in nine chapters
(`tests/test_no_network.py::test_the_documents_that_enumerate_the_tools_match_measured_reality`).

#### Changed

- The drift "2 only in running, 1 only in saved" on an unchanged appliance was
  an artefact: the `# Last modified` header lines and the closing `Done` no
  longer count, in `ha_stand`, pre-flight check 4 and `config_drift` alike.
  `tests/test_config_drift.py::test_the_header_lines_and_done_are_not_drift_on_either_lab_export`.
- Pre-flight check 4 compares the content of running and saved when the export
  carries no `config/nsconfig`, with the same counts as `config_drift`.
  `tests/test_preflight.py::test_check_four_compares_the_content_when_the_export_carries_no_nsconfig`
  and `::test_check_four_on_content_is_an_attention_point_with_the_same_counts_as_config_drift`.
- Pre-flight check 8 reads the free space on `/var` over SSH
  (`scripts/Invoke-GjkLiveMeting.ps1`) when `onderhoud` is configured and the
  target has a pinned host key, otherwise through the collector.
  `tests/test_preflight.py::test_the_evidence_of_check_eight_names_the_route_of_the_live_read`,
  `tests/test_live_meting_script.py::test_the_free_space_is_measured_through_the_transport_and_read_by_the_server`.
- `dienst_keten`, the certificate side of `certificaat_wat_verloopt_er`, the
  service users of a certificate in impact and advice, and the members in
  `status_gezondheid` read binding files in the list AND the aggregate shape
  through one reader, `Export.binding_rows()`; `rapport_dekking` cross-checks
  both shapes. `tests/test_binding_rows.py::test_the_aggregate_form_returns_each_requested_child_under_its_own_key`,
  `tests/test_chain.py::test_an_aggregate_lb_chain_is_read_to_its_members`,
  `tests/test_expiry.py::test_the_cert_side_aggregate_file_is_read_on_the_doh_export`,
  `tests/test_impact.py::test_the_service_bindings_of_a_certificate_are_read_and_named`,
  `tests/test_health.py::test_the_members_of_the_aggregate_member_file_are_read`,
  `tests/test_coverage.py::test_the_doh_export_has_two_binding_gaps_and_both_are_collector_facts`.
- R0 checks the target build - the one bundle in `onderhoud.firmwaremap` -
  against the security floor of the appliance's own branch from the knowledge
  package. It opens on evidence at or above the floor; below the floor, or
  without a known floor, only on `doelbuild_geaccepteerd=true` as a human
  decision; never across branches, measured against the appliance's current
  build from the export (unknown current build: closed unless accepted). A
  floor without the runner's form (a FIPS
  train) does not reach the runner, and the acceptance does not either.
  `upgrade.floor_gate()`;
  `tests/test_upgrade.py::test_a_target_build_below_the_floor_opens_as_a_human_decision_when_accepted`,
  `::test_no_floor_is_not_a_branch_difference_and_opens_as_a_human_decision_when_accepted`,
  `::test_a_branch_difference_closes_even_when_accepted`,
  `tests/test_upgrade_fase.py::test_an_acceptance_never_travels_past_a_known_floor_the_runner_cannot_see`.
- `onderhoud_upgrade_plan` and every phase proposal name the target build, the
  floor and R0's verdict beforehand. With zero or more than one bundle the
  reason names the local firmware directory only at `volledig`.
  `tests/test_upgrade_plan.py::test_the_plan_names_the_target_build_the_floor_and_the_verdict_below_the_floor`,
  `::test_at_beperkt_the_plan_says_what_the_firmware_directory_holds_without_its_path`,
  `tests/test_upgrade_fase.py::test_every_phase_proposal_ends_with_the_target_build_and_the_floor`.
- R1 to R6 install only the bundle R0 of the same run started with; another
  bundle is refused before the runner starts. `upgrade.run_binding_refusal()`;
  `tests/test_upgrade_fase.py::test_a_bundle_swapped_after_r0_is_refused_at_the_next_proposal_before_any_code`.
- R1 reads `show ns config` itself: its drift gate opens on evidence (nothing
  changed since the last save) or on `drift_geaccepteerd=true` as a human
  decision. `tests/test_upgrade.py::test_the_drift_gate_opens_on_evidence_when_nothing_changed_since_the_last_save`,
  `::test_a_human_acceptance_opens_the_drift_gate_with_the_measured_state_as_evidence`,
  `tests/test_runner_script.py::test_r1_opens_the_drift_gate_on_evidence_after_a_save`.
- Forbidden addresses reach the phase runner as one comma-separated argument,
  and the runner binds no parameter by position: a second address used to
  bind to `-Snapshotverwijzing`.
  `tests/test_runner_script.py::test_two_forbidden_addresses_in_one_argument_are_both_refused`
  and `::test_a_second_loose_forbidden_address_is_refused_not_bound_to_another_parameter`.

### Certificate use outside the bindings, and the content-switching step in dienst_keten

- The certificate tools name a certificate's use outside the SSL-vserver
  bindings: as the IdP or signing certificate of a SAML action, as the IdP
  or SP certificate of a SAML IdP profile, and as the certificate bound to
  an SSL servicegroup (with its CA role). `certificaat_wat_breekt_er` and
  `certificaat_wat_moet_ik_doen` name each use by object and role and add it
  as a step the operator must take by hand - this product has no writing
  tool for these objects. `src/nsmcp/cert_usage.py`;
  `tests/test_cert_usage.py::test_the_saml_uses_of_a_certificate_are_named_with_object_and_role`,
  `::test_the_signing_certificate_of_a_saml_action_is_named_next_to_its_virtual_server`,
  `::test_the_sp_certificate_of_an_idp_profile_is_named` and
  `::test_a_servicegroup_binding_names_the_servicegroup_and_the_ca_flag`.
- `certificaat_wat_verloopt_er` counts a certificate with only a use outside
  the bindings as in use (`gebonden`), never `los`.
  `tests/test_cert_usage.py::test_a_certificate_used_only_outside_the_bindings_is_gebonden_not_los`
  and `::test_the_expiry_list_names_the_use_outside_the_bindings`.
- `certificaat_vervangen`'s proposal names every use of the certificate it
  takes off the vserver outside that one binding (another vserver, an SSL
  service, a SAML object, an SSL servicegroup), with object and role, since
  the replacement only touches the vserver binding. When that use cannot be
  established - a source not in the export or not read, an export of another
  target or without a recorded target, or a write by this server since the
  scan - the proposal says "gebruik buiten de binding niet vastgesteld" with
  the reason. `src/nsmcp/mcp_server.py::_vervangen_voorstel_findings` and
  `src/nsmcp/action.py::replacement_findings`;
  `tests/test_cert_usage.py::test_the_proposal_names_the_old_certificates_other_uses`,
  `::test_the_proposal_says_niet_vastgesteld_when_a_source_is_not_in_the_export`,
  `::test_the_proposal_never_states_a_use_read_from_the_export_of_another_target`,
  `::test_after_a_write_without_a_new_scan_the_proposal_does_not_state_the_old_binding`
  and `tests/test_cert_usage_openness.py::test_the_replacement_proposal_names_no_real_name_at_beperkt`.
- These uses read four new export sources (collector 1.1.0):
  `config/authenticationsamlaction`, `config/authenticationsamlidpprofile`,
  `config/sslservicegroup` and `sslservicegroup_sslcertkey_binding.by-parent.json`.
  `rapport_dekking` gives each of the three uses its own line (SAML actions,
  SAML IdP profiles, SSL servicegroups) in one of three states: `gelezen`,
  `niet in de export`, or `niet bruikbaar gelezen` (a read gap); and the SAML-action,
  IdP-profile and servicegroup names join the pseudonym families at
  `beperkt`/`minimaal`. `src/nsmcp/disclosure.py::names_from_export`
  (sixteenth family);
  `tests/test_cert_usage.py::test_the_coverage_report_shows_the_three_sources_as_read`
  and `::test_the_coverage_report_shows_the_three_sources_as_absent_on_an_older_export`;
  `tests/test_cert_usage_openness.py::test_no_real_fixture_name_reaches_a_limited_or_minimal_certificate_answer`.
- A source missing from the export manifest reads "niet vastgesteld: bron
  ... niet in de export", never "geen gebruik"; a source present but
  unreadable, or a row with an unreadable identity field, is a read gap with
  its own reason - never a silent "no use" verdict.
  `tests/test_cert_usage.py::test_an_export_without_the_sources_says_niet_vastgesteld_never_no_use`,
  `::test_a_source_the_manifest_carries_but_could_not_read_is_a_read_gap` and
  `::test_a_saml_action_without_a_name_that_uses_the_certificate_is_a_read_gap`.
- `dienst_keten` follows a content-switching vserver to its standard load
  balancer (`csvserver_lbvserver_binding`) and to every load balancer its
  policies point at, resolved through the policy's own `targetlbvserver` or,
  failing that, through `cspolicy.action` -> `csaction.targetlbvserver`, and
  from there the existing load-balancing chain. A route is complete when
  every branch ends in members, a gap when a branch has no backend, and
  "niet vastgesteld" with a reason when a policy cannot be resolved:
  `cspolicy`/`csaction` not in the export or not readable, a reference inside
  them that leads nowhere, or an action whose target is not a load-balancing
  vserver. The whole route is then "niet vastgesteld": only the standard load
  balancer and the policy names show, and the standard load balancer is not
  followed further. `src/nsmcp/chain.py::_cs_chain`;
  `tests/test_chain.py::test_a_cs_route_follows_its_default_lb_to_a_complete_chain`,
  `::test_a_cs_route_resolves_a_policy_through_cspolicy_and_csaction`,
  `::test_a_cs_route_without_cspolicy_or_csaction_in_the_export_is_not_established`,
  `::test_a_policy_without_a_readable_action_in_cspolicy_is_not_established`,
  `::test_a_csaction_target_that_is_not_a_loadbalancing_vserver_says_so`
  and `::test_a_cs_route_to_an_unknown_lb_name_is_a_gap`.
- A content-switching vserver with no standard load balancer and no policy,
  whose own binding document carries another nested kind (a GSLB vserver, a
  VPN vserver, or a kind this version has no rule for), is "niet vastgesteld"
  with that kind named, never "gat in de keten": the kind is the route, and
  this version does not follow it. Next to a followed route, such a kind
  makes the whole route "niet vastgesteld" as well, with the kind named - the
  same answer an action with a target that is not a load-balancing vserver
  gets; a policy binding (responder, rewrite and the like) leaves the verdict
  alone. `src/nsmcp/chain.py::_cs_chain`;
  `tests/test_chain.py::test_a_cs_entry_routing_only_through_an_unread_kind_is_not_a_gap`,
  `::test_a_followed_cs_route_next_to_an_unread_routing_kind_is_not_established`
  and `::test_a_followed_cs_route_next_to_a_policy_binding_keeps_its_verdict`.
- `rapport_dekking` names `config/cspolicy` and `config/csaction` as "niet in
  de export" when a content-switching route of the export asks for them (a
  policy without its own target) and the manifest does not carry them, and
  the verdict is then never "volledig" - the same sources `dienst_keten`
  reports as "niet vastgesteld". A key the export boundary refused is "niet
  bruikbaar gelezen" instead. A source no route asks for costs no coverage.
  `src/nsmcp/chain.py::route_source_gaps`;
  `tests/test_coverage.py::test_a_policy_source_a_cs_route_asks_for_is_named_when_it_is_not_in_the_export`,
  `::test_a_policy_source_whose_key_was_refused_is_not_usably_read_not_absent`
  and `::test_a_policy_source_no_cs_route_asks_for_costs_no_coverage`.

### The three invariants

Each is enforced in code, guarded by a named test, and proven by a mutation:
switch the enforcement off and that test fails.

- **A reading tool never opens a socket.** Guarded by `tests/test_no_network.py`.
  Mutation proof: adding `socket.socket()` in the guarded path fails
  `test_the_reading_tools_open_no_socket_through_a_real_session` and
  `test_the_reading_tools_on_the_REAL_export_open_no_socket`. Two documented
  exceptions reach the appliance through their own child process instead:
  `status_ververs` and `status_update_preflight`.
- **Nothing is `[vastgesteld]` without a successful read.** Guarded by
  `tests/test_answer.py`. Mutation proof: removing the `raise` in
  `Finding.__post_init__` fails `test_finding_requires_evidence`.
- **The confirmation code never reaches the model.** Guarded by
  `tests/test_handelen_zonder_code.py`. Mutation proof (measured by putting
  the code into the `bevestigingscode` finding's outcome text): seven tests
  in that file turn red (measured), among them
  `test_the_proposal_carries_no_code_at_all`,
  `test_the_marker_never_reaches_the_model_together_with_a_code` and
  `test_a_proposal_at_openheid_beperkt_carries_the_code_line_and_every_argument`.

### Added

- Continuous integration on Windows (Python 3.11 and 3.12): the full suite,
  `ruff`, `pip-audit`, a CycloneDX SBOM per Python version as a workflow
  artifact, and a separate step that runs the three invariant files by name.
- A lock file with hashes, and Dependabot on pip and github-actions.
- A runnable five-minute path: `config.example.json`, `kennis.example.json`,
  a 20-line MCP client in `examples/`, and the real lab export in
  `tests/fixtures/` with its own README.
- `docs/ARCHITECTURE.md` and `docs/GLOSSARY.md`.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and pull request templates.
- A trust model and scope statement in `SECURITY.md` and
  `docs/klant/SECURITY.md`, including what counts as a vulnerability and what
  does not.
- A structured stderr log line per write action - time, self-declared client
  name, tool, arguments, target, action id and outcome. Never the confirmation
  code.
- All nine chapters, measured against the registered tools: `certificaat`
  (`certificaat_wat_verloopt_er`, `certificaat_wat_breekt_er`,
  `certificaat_wat_moet_ik_doen` reading; `certificaat_klaarzetten`,
  `certificaat_vervangen` writing), `status` (`status_ververs`,
  `status_overzicht`, `status_cve_controle`, `status_namen`,
  `status_doelen`, `status_gezondheid`, `status_update_advies`,
  `status_update_preflight`),
  `dienst` (`dienst_status`, `dienst_keten` reading;
  `dienst_lid_uitschakelen`, `dienst_lid_inschakelen` writing), `kennis`
  (`kennis_uitleg`), `rapport` (`rapport_dekking`, `rapport_vergelijk`,
  `rapport_wat_is_er_veranderd`, `rapport_na_upgrade`), `ha` (`ha_stand`),
  `beveiliging` (`beveiliging_verstopte_regels`, `beveiliging_tls_baseline`,
  `beveiliging_beheervlak`, `beveiliging_headers`, `beveiliging_scorekaart`),
  `onderhoud` (`onderhoud_upgrade_plan`, `onderhoud_upgrade_stand`
  reading; `onderhoud_backup_maken`, `onderhoud_upgrade_fase` writing) and
  `config` (`config_drift` reading; `config_opslaan` writing) - 34 tools in
  total, 27 reading and 7 writing. See the tool table in `README.md` for what
  each answers.
- All seven writing tools behind the same proposal-then-confirmation-code
  flow, never returning the code itself.
- A `doel` argument on the seven writing tools and on `rapport_na_upgrade` and
  `onderhoud_upgrade_stand`, for a configuration with more than one target,
  and an optional `doel` on every export-backed reading tool (see above);
  `status_ververs` keeps its own `doelnaam`.
- Outstanding measurements against a real appliance export, tracked with
  their status in `docs/klant/OPENSTAANDE-METINGEN.md`.

### Changed

- The allowlist for writing tools now lives in the configuration file
  instead of in code: `handelen` gained a required field `toegestaan`
  (`src/nsmcp/start.py`, `_HANDELEN_FIELDS`). Absent, `false` and an empty
  list (`[]`) all mean the same thing - not allowed - for a given target and
  tool (`src/nsmcp/handelen.py`, `Allowlist`).
  **Migration:** a configuration file from before this version does not have
  `codekanaal` or `toegestaan` yet (`codekanaal` is new in this version as
  well), and the product refuses to start with a `Fout: handelen mist
  veld: ...` line that names every missing field. Measured for such a file
  (both fields missing):
  `Fout: handelen mist veld: codekanaal, toegestaan; codekanaal zegt WAAR de
  bevestigingscode heen gaat - hij staat niet meer in het antwoord van het
  gereedschap, want dat leest het model mee. Kies {"soort": "venster"} (een
  venster op deze machine) of {"soort": "bestand", "pad": "<absoluut pad>"}
  om te oefenen; de allowlist komt sinds 1.0 uit de configuratie en niet meer
  uit de code. Zet 'toegestaan' in de handelen-sectie: per doelnaam per
  handeling de toegestane waarden, of true/false voor een handeling die haar
  object zelf vormt. Een lege sectie ({}) is geldig en betekent: niets
  toegestaan`. With only `toegestaan` missing (an already-migrated
  `codekanaal` in place) it reads the shorter:
  `Fout: handelen mist veld: toegestaan; de allowlist komt sinds 1.0 uit de
  configuratie en niet meer uit de code. Zet 'toegestaan' in de
  handelen-sectie: per doelnaam per handeling de toegestane waarden, of
  true/false voor een handeling die haar object zelf vormt. Een lege sectie
  ({}) is geldig en betekent: niets toegestaan`. Add both keys before
  upgrading; an empty `toegestaan` (`{}`) is valid and means nothing is
  allowed. See `docs/klant/HANDLEIDING.md` for the full grammar.

### Security

- PowerShell is started from its absolute path under `%SystemRoot%`, with an
  existence check and fail-closed behaviour, on both the reading and the
  writing path. Measured before this: a file named `powershell.exe` in the
  working directory was executed instead.
- Object files are verified against the `payloadSha256` in the export manifest.
  Measured before this: a forged object file came out as `[vastgesteld]`.
- Input ceilings on size, object count, line count, nesting depth and free text
  fields; `RecursionError`, `MemoryError` and `ValueError` become read gaps
  with a named reason instead of a masked error.
- The confirmation code is burned after five failed attempts, and the operator
  is told through the channel that carried it.
- A knowledge package without a `cve` key is refused instead of loading as
  valid and empty.
- The transport is pinned to stdio and the test spy records the argument.

### Fixed

- A configuration with a nonexistent `exportmap` or `kennispad` now prints a
  Dutch `Fout: ...` line and exits with code 1, as the README always promised.
- An answer with no findings, no read gaps and nothing unassessed now says so
  instead of rendering an empty body.
- `status_ververs` is no longer offered without a targets file and a collector
  script; `hoofdstukken: []` is refused instead of starting a silent server
  with no tools.
- The masking of write-script output now also derives its target values from
  the action context, so a configuration without a targets file is masked too.
