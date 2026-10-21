# lab-export-vpx-20260826

An export from a real appliance, not synthetic JSON. The current tree
carries it pseudonymised (see "Pseudonymisation" below). It is the
measuring stick of this repository: the engine runs against these files in
`tests/test_lab_export_parity.py`, and the CVE verdicts computed from them are
pinned byte for byte.

## Where it came from

- Written by the released **NSHC 1.0 collector** on **2026-08-26**, over a
  read-only NITRO session.
- Source: a Citrix NetScaler **VPX in GJK Partners' own lab**. No customer
  data, no production system.
- Firmware at the time of the scan: 14.1, build 72.57.nc.

## What is in it

| directory | content |
|---|---|
| `objects/` | one JSON file per NITRO resource, named after its `propertyName` |
| `bindings/` | by-parent binding documents |
| `parsed/` | the text projections: running config, saved config, system users |
| `export-manifest.json` | per resource a status and a `payloadSha256`; per binding file a hash under `files` |
| `collect-log.txt` | what the collector did, including which fields it redacted |

58 resources, 49 object files, 7 hashed binding files and 2 hashed parsed dumps.

## What has been removed

The collector redacts credential-bearing fields before writing. Measured in
this export: `parsed/runningconfig.txt` and `parsed/savedconfig.txt` both
contain ten lines where a password, encryption key or SSO credential value is
redacted, replaced with the literal `<REDACTED>` marker. Separately, the `password` field was removed from the `lbmonitor`
object before it was written - which is why that one resource carries an
empty `payloadSha256` in the manifest and is not read as an object source (no
hash, no trust).

**Note for anyone adding a fixture.** `detect-secrets` and GitHub secret
scanning do NOT recognise the NetScaler credential format
(`-password <blob> -encrypted -encryptmethod ENCMTHD_4`). Check by hand for
`set system user`, `set ns encryptionParams`, `add aaa user`, `set ns rpcNode`
and `set lb monitor ... -password` before a scanner, never after.

## Pseudonymisation

The current tree contains a pseudonymised export from a real appliance:
`scripts/pseudonymise_export.py` replaced private IP addresses, the
hostname, serial number, `encodedserialno`, `hostid`, `netscaleruuid`, the
MAC address and operator-named objects (certificates, policies, vservers,
monitors, ...) with generated aliases. Historical commits still require a
separate history-cleanup pass before publication - this README does not
claim otherwise. NetScaler's own built-in/default objects (for
example the appliance's stock management certificate, the built-in
`NOREWRITE` rewrite action, the default SSL profiles and monitors) are never
candidates and keep their real, vendor-published names - that vocabulary is
public and this product's own logic compares against it directly. The
mapping and the extra forbidden-terms list used for that run are kept
outside this repository, never committed. The pseudonymisation changes
operator-chosen names and addresses only - the judgements this fixture
proves (expired, bound, CVE) are unchanged.

**Manually checked, as the tool's own README requires** (`scripts/README.md`,
"Offline pseudonimisering van een export" - subject/issuer are not a harvest
source, so the tool cannot cover them on its own): the built-in management
certificate's `subject`/`issuer`/`servername`/`servicename` fields
(`objects/sslcertkey.json`) carried the lab hostname in its Common Name.
That token has been added to the forbidden-terms list for this fixture and
now carries the same alias as everywhere else it appears.

**After-treatment of free text (2026-10-21).** The alias run did not cover
text an operator typed. `scripts/pseudonymise_export.py --free-text-only`
was run over this fixture once, with one extra term (the alias the earlier
run gave the lab hostname, from a family the tool has since renamed): the
`send`/`recv` strings of one stock monitor without a builtin attribute, the
StoreFront path and the NT domain of two Gateway session actions, the time
zone (in `objects/nsparam.json` and both config texts) and the EUI-64
link-local address of the management interface (it spelled out the
interface's MAC address) are neutral now, and the certificate Common Name
carries `TERM-001`. The manifest hashes, the scan stamp and the
`pseudonymisation` marker were written by the tool. Every CVE verdict
pinned in `tests/test_lab_export_parity.py` is unchanged.

## May I extend it?

Yes, but not by editing these files: the manifest hashes are verified on every
read, and the CVE verdicts are pinned. Add a new fixture directory instead, and
state in its own README where it came from and what was removed.
