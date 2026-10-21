# a14-export - measured, not planned

This fixture captures the four resources this branch's collector actually delivers
(`config/nstcpprofile`, `config/systembackup`, `config/nsconfig`,
`stat/system`). It is deliberately NOT the four resources the design
originally asked for - a change request (2026-09-07) reconciled the design
against what the collector branch actually shipped, once that branch had
moved further than the design knew. In short: the design wanted `config/systemfile` with
`filelocation` on `/var/nsinstall` as the fourth resource; the collector
branch that actually shipped delivered `stat/system` instead, and the
`/var/nsinstall` read still does not exist anywhere. This fixture follows
what was delivered, not what was planned.

## Provenance

Every object file in `objects/` is copied from the real export measured on
2026-09-07, with the address substitution documented below in "Address
pseudonymised by hand"; field names and field types are preserved. The
source was the collector's four-resource export of the lab appliance
(`export-lab-02-vierbronnen-20260906`), kept outside this repository.

- `nsversion.json` - the one real object (build `NetScaler NS14.1: Build
  72.57.nc, ...`).
- `nstcpprofile.json` - ALL 13 real rows, unedited. Every row carries
  `timestamp: "DISABLED"`; there is NOT ONE row with `"ENABLED"` anywhere in
  the measured export. `builtin` is a JSON list (`["MODIFIABLE"]`) on every
  row, also unedited.
- `systembackup.json` - all 7 real rows. `size` is a JSON number,
  `uselocaltimezone` a JSON boolean - not text, on the real appliance.
- `nsconfig.json` - the one real object, including `configchanged` (JSON
  boolean) and `currentsytemtime` - that spelling is the collector's own
  field name, not a typo introduced here.
- `system.json` (`stat/system`) - the one real object, including the
  hardware-dependent fields (voltages, temperatures, fan speeds) that read
  `0`/`0.0` on this appliance.
- `lbvserver.json` - a trimmed subset (5 of the real 103 rows), kept only to
  ground the change request's association note: `LAB-LBV-005` and two more
  real rows carry `tcpprofilename: "nstcp_default_tcp_lan"`, a name that
  really does appear in `nstcpprofile.json` above (with `timestamp:
  "DISABLED"`). No code on this branch reads this file today.
- `parsed/runningconfig.txt` - a TRIMMED excerpt (5 lines, not the real
  1703), but the lines preserve the measured configuration apart from that
  address substitution. This is not decorative: without
  a running config at all, the LINE half of `heeft_tcp_timestamp_profiel`'s
  `_Sources` cannot be read (`config/nsrunningconfig` would be
  `NIET_IN_MANIFEST`), and a disjunction with one unreadable side comes out
  `niet vastgesteld` regardless of what the object side says (`_combine`,
  `src/nsmcp/cve.py`). The one `set ns tcpProfile` line in the real 1703-line
  file is included for exactly that reason - it is the only such line that
  exists, and it does NOT carry `-timestamp`, so it establishes the LINE
  source as absent too, the same way the real file does.

`export-manifest.json` and `scan-doel.txt` are built by hand to match: eight
resources, seven `OK` (six object resources plus `config/nsrunningconfig`)
and one `NOT_SUPPORTED`
(`config/systemfile?args=filename:iprep.log,filelocation:%2Fvar%2Flog` -
present in the manifest, unusable, exactly as measured; this is NOT the
`/var/nsinstall` read).

## What is intentionally NOT in this fixture

**No row anywhere in this fixture has `nstcpprofile.timestamp == "ENABLED"`.**
That is not an oversight - it is what the real export looks like. A fixture
that invented a positive value here would no longer be "measured", it would
be "measured, except for the one row that matters most" - and no reader
should have to guess which value in a checked-in fixture is real and which
one somebody added to make a test pass.

The positive path (an OBJECT row with `timestamp: "ENABLED"`, evaluated with
no contradicting running-config line) is tested separately, with an inline
synthetic export built in the test itself:
`tests/test_cve.py::test_object_only_tcp_timestamp_enabled_is_established_present`.
That test's docstring says so, and this file is the other half of the same
claim: real bytes prove the negative path works, a labeled synthetic proves
the positive path works, and neither on its own would have proven both.

There is also no `config/systemfile` entry for `/var/nsinstall` in this
fixture, for the same reason: it does not exist in the measured export, and
inventing it here would misrepresent what this product can actually rely on today.

## Address pseudonymised by hand

This fixture's manifest is hand-built to match a trimmed export (see
"Provenance" above), not written by the real collector - `scripts/
pseudonymise_export.py` refused it (`Manifest bevat een ongeldige
rijtelling`) rather than run against a shape it cannot trust. The one lab-
range address this fixture carried (`objects/nsconfig.json`,
`objects/systembackup.json`, `parsed/runningconfig.txt` - ten lines in
total) has therefore been replaced BY HAND with a TEST-NET-3 address
(`203.0.113.11`, RFC 5737), the same substitution the tool would have made.
`export-manifest.json`'s three affected `payloadSha256` values and its
`files` entry were recomputed over the edited bytes (object files: raw
bytes; `parsed/runningconfig.txt`: LF-normalised text, matching `nsmcp.
export`'s own hash sources); `scan-doel.txt`'s manifest hash was recomputed
to match. Every other value in this fixture (field names, field types, all
other values, the trimmed row counts) is unchanged from what "Provenance"
above describes; the three edited files were rewritten with LF line endings
when the address was replaced, and their hashes cover those bytes.

Later (2026-10-21), by hand for the same reason: the `timezone` of
`objects/nsconfig.json` carried a place name and now reads
`CoordinatedUniversalTime`; its `payloadSha256` and the manifest hash in
`scan-doel.txt` were recomputed with `nsmcp.export.payload_digest` over the
edited bytes.
