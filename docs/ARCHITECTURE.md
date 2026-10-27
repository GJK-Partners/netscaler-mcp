# Architecture

English, because this is code documentation. The product surface it describes
is Dutch - see [GLOSSARY.md](GLOSSARY.md).

## The shape

```
MCP client (stdio)
      |
      v
mcp_server.build_server()          34 tools, Dutch names and descriptions
                                    (without scan, maintenance or write
                                    configuration 23 remain - see README.md)
      |
      v
disclosure.render()                THE seam: decides what a name may look like
      |
      v
expiry / impact / action / cve / dienst / overzicht      the analysis modules
      |
      v
export.Export                      the manifest is the truth about the data
      |
      v
disk
```

Four side branches, all separate processes:

- **collect** - `status_ververs` starts the NSHC collector through
  `powershell.start_powershell()`. The server itself opens no socket; the child
  process does the network work. `status_update_preflight` reads the free
  space on `/var` live the same way: over SSH through
  `scripts/Invoke-GjkLiveMeting.ps1` when `onderhoud` is configured and the
  target has a pinned host key, otherwise through the collector.
- **handelen + confirm + code_channel** - the writing path. A proposal comes
  back without a code; the code goes to the operator through one of three
  channels - `venster` (a MessageBox on the server's own screen), `bestand`
  (a file the operator names, for practising and automation) or `sso` (a
  separate process that, unlike the other two, can say WHO took delivery);
  a second call with that code acts. Five writing tools start the reviewed
  write script (`handelen.perform()`).
- **config_opslaan** - the writing route over SSH (`handelen.perform_save()`).
  It starts `scripts/Invoke-GjkConfigOpslaan.ps1`, its own script next to
  the phase runner, on the runner's transport (`scripts/GjkUpgrade-Ssh.ps1`:
  pinned host key, credential from Windows Credential Manager). The script
  judges nothing: `python -m nsmcp.upgrade_measure` decides the role before
  `save ns config`, and the server judges the raw `show ns config`
  read-back (`backup.save_readback_ok`).
- **onderhoud_upgrade_fase** - one phase of a firmware upgrade. The runner
  (`scripts/Invoke-GjkUpgradeFase.ps1`) starts detached and is never waited
  on to completion; it judges nothing about the appliance itself, only what
  the ledger says afterwards (see "The phase runner and the ledger" below).

## The chapters

Every tool the server can register sits under one of nine chapters:
`status`, `certificaat`, `dienst`, `kennis`, `beveiliging`, `rapport`, `ha`,
`onderhoud`, `config`. `build_server()` only registers a tool whose chapter is
switched on. A deployment may narrow the surface with the `hoofdstukken`
config key; the key must not be an empty list (a silent zero-tool server
would look like a running product, not a mistake anyone would notice).
Leaving the key out switches on all nine.

## Targets and the one export

A server has ONE export directory; `status_ververs` writes every target into
it, and the export records which target it describes. `status_doelen`
(`doelen.py`) lists the configured targets - the union of the targets file
and the allowlist sections - with address, export age, last maintenance run
and the NAMES of the writing tools granted there; never a credential target
or a fingerprint. Every export-backed reading tool takes an optional `doel`.
It is a check, not a switch: `mcp_server._load_for()` refuses an unknown
target without repeating it, and refuses a configured target that is not the
one the export describes - or any target when the export does not record
which one it describes. Empty means the behaviour without `doel`. One
resolver, `_resolve_doel()`, serves the reading tools, the ledger-reading
tools and the writing path; at 'beperkt' it also accepts the pseudonym
`status_doelen` showed, and an unknown pseudonym gets the same refusal as an
unknown name.

## Reading the export

**Bindings.** A binding file comes in two shapes: a list, or an aggregate per
parent object. `Export.binding_rows()` is the one reader for both; it returns
the rows per parent, or a read gap with a named reason for any shape it does
not know. `dienst_keten`, the certificate side of
`certificaat_wat_verloopt_er`, the service users in impact and advice, and
the members in `status_gezondheid` all read through it; `rapport_dekking`
cross-checks the parents of both shapes through `Export.binding_parents()`,
which refuses what the reader refuses.

**Certificate use outside the bindings.** `cert_usage.py` reads four sources
the collector added at version 1.1.0: `config/authenticationsamlaction`,
`config/authenticationsamlidpprofile`, `config/sslservicegroup` and its
binding file `sslservicegroup_sslcertkey_binding.by-parent.json` (the parent
list for that binding file comes from `config/sslservicegroup` itself, the
same pattern `config/sslvserver` already sets for the vserver binding). A
source missing from the manifest is "niet vastgesteld", never "geen
gebruik"; the certificate tools and `certificaat_vervangen`'s warning read
through this one module.

**The content-switching step.** `dienst_keten` follows a content-switching
vserver to its standard load balancer and to every load balancer its
policies name, resolving a policy without its own `targetlbvserver` through
`cspolicy.action` -> `csaction.targetlbvserver`. A policy that cannot be
resolved (`cspolicy`/`csaction` not readable, a reference that leads
nowhere, or a target that is not a loadbalancing-vserver) makes the whole
route "niet vastgesteld": only the standard load balancer and the policy
names are shown, and the standard load balancer is not followed further.
A vserver whose document carries another nested kind that can route (a
GSLB or VPN vserver, or a kind without a rule here) is "niet vastgesteld"
with that kind named - never "gat in de keten" without another route, and
never "keten compleet" next to one; a policy binding (responder, rewrite
and the like) leaves the verdict alone.

**Drift.** Running against saved configuration is compared once, in
`config_drift.py`; `ha_stand`, pre-flight check 4 (when the export carries no
`config/nsconfig`) and `config_drift` itself all call that comparison. Lines
that start with `#` (the "Last modified" header lines) and the closing `Done`
of the running configuration are left out, so an unchanged appliance shows
no drift. The lines compared are the redacted ones; the export also counts
the lines that differ only in the redacted part, and the equal lines whose
value the collector already replaced with its `<REDACTED>` marker
(`Export.withheld_only_difference`, two numbers and nothing else). The first
count is drift too; the second makes the verdict `onbevestigd` instead of
`uit` when the header lines do not say the last save came at or after the
last change (`Comparison.undecided`). `config_drift` is the one tool that shows configuration lines:
only at 'volledig', always through the credential filter and a cap.

## The three invariants

These are not preferences. Each one is enforced in code, guarded by a named
test, and has a mutation proof: switch the enforcement off and that test fails.

| # | invariant | where it is enforced | where it is guarded | mutation proof |
|---|---|---|---|---|
| 1 | Twenty-five of the twenty-seven reading tools never open a socket | the Export- and Knowledge-backed paths construct no connection | `tests/test_no_network.py` - among them `test_the_reading_tools_open_no_socket_through_a_real_session` and `test_the_reading_tools_on_the_REAL_export_open_no_socket`, plus `test_the_guard_really_trips` as the counter-proof | injecting `socket.socket()` at the top of `disclosure.render()` - the render path the `Export`-backed tools call; `kennis_uitleg` never calls `render()` - fails 2 tests (measured) |
| 2 | Nothing is `[vastgesteld]` without a successful read | `Finding.__post_init__` refuses a finding without evidence; `Answer.is_complete()` refuses completeness across a read gap | `tests/test_answer.py`, plus `tests/test_action.py` and `tests/test_cve.py` for the ways it shows up in an answer | removing the `raise` in `Finding.__post_init__` fails `test_finding_requires_evidence` |
| 3 | The confirmation code never reaches the model | `mcp_server._act()` composes a proposal without the code; the code goes only to `code_presenter` | `tests/test_handelen_zonder_code.py` | putting the code back in the proposal text fails 3 tests |

Invariant 1's documented exceptions: `status_ververs` and
`status_update_preflight` - the two documented exceptions - and the seven
writing tools each reach outside this process through their own child
process (see "The shape" above), and
Python's own event loop self-pipe on Windows (ProactorEventLoop),
described in the module docstring of `tests/test_no_network.py`. None
of this is hidden.

## The phase runner and the ledger

An upgrade phase starts a child process the way `collect` does, but
detached: `onderhoud_upgrade_fase` starts `scripts/Invoke-GjkUpgradeFase.ps1`
and returns without waiting for it. That runner talks to the appliance over
SSH for every phase after R0, and calls `python -m nsmcp.upgrade_gate` once
per phase with everything it measured; that process turns the measurement
into one ledger line and nothing else.

**The ledger is the truth**, not a log line and not the runner's own exit
code. `read_ledger()` is the only reader; `onderhoud_upgrade_stand` and
`rapport_na_upgrade` build every verdict they report from what it returns,
never from anything the runner printed. `append_line()` is the only writer,
append-only and fsynced before the next action begins. A ledger line a
later call reads back is untrusted input like any other file this product
reads: bounded, never assumed well-formed.

**The target build and the floor.** The target build is the one bundle in
`onderhoud.firmwaremap` (`handelen.firmware_target_build()`); the floor is
the highest fix build of the appliance's own branch in the knowledge package
(`update_advice.export_floor()`, the same route as `status_update_advies`).
The server computes both at the proposal and again at the execution and
hands them to the runner for R0, together with the version and date of the
pinned knowledge package the floor came from; `upgrade.floor_gate()` judges
them. It opens on evidence at or above the floor and above the current
build, as a human decision below the floor, without a known floor, or for
a target build not higher than the current build (a reinstall or a
downgrade within the line) when `doelbuild_geaccepteerd=true`, and never
across branches: the branch is compared against the appliance's current
build from the export, and an unknown current build closes the gate unless
the operator accepts explicitly. The evidence names the package and warns,
without closing, when it is more than 30 days old. A floor without the runner's form (a FIPS train) does
not travel, and the acceptance stays behind with it. `onderhoud_upgrade_plan`
and every phase proposal show the target build, the floor and this verdict
beforehand.

**The run binding.** R0's `fase_gestart` line records the target build it
started with. R1 to R6 of the same run refuse a bundle that differs from it
(`upgrade.run_binding_refusal()`): at the proposal when the difference is
readable, and at the execution also when R0's value is absent or
unreadable - before the runner starts.

## The layer rule

**The analysis modules do not know `Disclosure` exists.** `expiry`, `impact`,
`action`, `cve`, `dienst` and `overzicht` compute an answer with real object
names in it. Only `disclosure.py` knows which disclosure level is in force, and
it is the last thing an answer passes through before it leaves the server.

Why it is worth a rule: a decision on a seam cannot be forgotten by the next
module. Put a name-shielding rule inside an analysis module and the next
analysis module has to remember it too - and one day will not.

The practical consequence: no analysis module imports `disclosure` or
decides a disclosure level. It still must decide, per finding, whether
the subject is a real object name (`Finding.subject_is_name`, answer.py
- default `True`, fail-closed) and whether the finding may only appear
at 'volledig' (`Finding.only_in_full`, answer.py - default `False`).
Get `subject_is_name` wrong and the seam masks your own product
vocabulary and writes it into the operator's pseudonym table. If you
add a NAME to an answer, make sure the disclosure layer can find it
(see `names_from_export` and its siblings).

## Where the Dutch text comes from

Every user-visible sentence is composed in code, never by the model. The tool
names, tool descriptions, answer texts and error messages are pinned byte for
byte in `tests/test_product_surface.py`. That file is the guard on the product
surface: a refactor may rename anything internal, but a customer's client must
see exactly the same words.

## Reading the design citations

Comments and docstrings cite the design by numbered section (`design 2.1.1`,
`ontwerp 3.5`, `spec 2.6`). Those numbers point at the internal design
document of 5 September 2026, which the maintainers keep outside the public
tree; the sections above (invariants, chapters, phase runner, layer rule)
summarise what the code relies on from it. A citation records where a rule
came from - the rule itself is always stated, and tested, where it is used.

## Where to add things

| you want to add | open | and also |
|---|---|---|
| a CVE rule | `src/nsmcp/cve.py` - the declarative rule shapes and the predicate table | a fixture that proves BOTH the affected and the not-affected verdict, and a read-gap fixture for the source it needs |
| a tool | `src/nsmcp/mcp_server.py` - `build_server()` registers every tool under a chapter gate | its Dutch description in `tests/test_product_surface.py`, and its entry in the no-socket guard |
| a confirmation channel | `src/nsmcp/code_channel.py` - `presenter_for()` is the one place that turns a `soort` into a presenter | one branch there, one presenter, one row in `start._CHANNEL_FIELDS`. `_act()` never changes |
| an export source | `src/nsmcp/export.py` | the resource in the collector's manifest, and a read-gap fixture for the case where it cannot be read |

## What the manifest is for

`export-manifest.json` is not an index, it is the trust anchor. Per resource it
carries a status and a `payloadSha256`; per binding file a hash under `files`.
Every read verifies the file it is about to use against that manifest, and
re-checks that the manifest itself has not changed underneath (a scan can swap
the export directory mid-read). A source with no hash is a read gap: no hash is
no trust.

Since 1.1 the PLACE of a file is part of that trust, not only its bytes. A hash
that matches says nothing about where the bytes came from: a junction inside
the export, beside the pseudonym table or in the place of a ledger file led a
read to a place the start check would have refused, and a matching hash in the
manifest then accepted it. So every file the product opens - Python and
PowerShell alike - is opened in exactly one place: `nsmcp.localpath` (and its
PowerShell twin `Open-GjkLokaalBestand` in `scripts/GjkUpgrade-LokaalPad.ps1`,
the same walk, kinds and fixed sentences). It opens every component itself with
`NtCreateFile`, relative to a directory handle it holds, as itself
(`FILE_OPEN_REPARSE_POINT`), and refuses every reparse point inside the approved
directory, the directory itself included; containment is structural (the root
is walked on its own text, everything below it relative to the held root
handle), never a comparison of resolved path strings. A held directory is
shared for reading and writing but not for deletion, so it cannot be renamed or
replaced while a file below it is in use; a directory is listed on its held
handle (`NtQueryDirectoryFile`), never by name. `tests/test_read_inventory.py`
checks this mechanically, within what its patterns see: in `src/nsmcp` an AST
walk over the file operations and the metadata questions and listings by name
(`open`, `read_text`, `exists`, `glob`, `iterdir`, `stat`, `mkdir`, ...), in
`scripts/*.ps1` a case-insensitive search over the code (the file cmdlets,
`Get-ChildItem`, `Test-Path`, `Resolve-Path`, `Get-Item`, `New-Item`,
`Copy-Item`, the `[System.IO.*]` and `[IO.*]` file, stream and path types,
`GetTempFileName`, redirections to a file). Every finding outside the walk is
pinned with its reason or fails the test. A pattern the search does not know
(an alias such as `gci`, a .NET call through a variable) is not covered by it;
an audit hook in the route and session tests catches any open by path of the
Python side at run time. What the walk does not prove: the access
rights on those directories (who may write there), and which bytes PowerShell
finally executes for a pinned script.
