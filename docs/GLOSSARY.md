# Glossary - reading a Dutch answer

The product surface of this server is Dutch by design: the customers and
their AI assistants are Dutch. The code is English. This page is the
bridge: it does not translate the product, it tells you how to read one
answer.

## The verdict vocabulary

| Dutch | English | what it means |
|---|---|---|
| `GERAAKT` | affected | the rule applies to this appliance, computed from a source that was read |
| `NIET GERAAKT` | not affected | the rule was evaluated and does not apply |
| `NIET VASTGESTELD` | **not established** | a source could not be read. This is a READ GAP, never "no problem". Treat it as unknown, not as safe |
| `NIET BEOORDEELD IN DEZE VERSIE` | deliberately out of scope | this version does not look at this dimension at all. Nothing went wrong; it simply is not assessed |

The difference between the last two is the whole point of this product.
"Not established" means a lookup failed. "Not assessed" means we never
promised to look.

## Certainty markers

| Dutch | English |
|---|---|
| `[vastgesteld]` | established from a source that was actually read |
| `[niet vastgesteld]` | the source could not be read; the reason follows |
| `bewijs:` | evidence - which source, which field, which value |
| `reden:` | reason - why something could not be established |

## The footer of every answer

| Dutch | English |
|---|---|
| `Kennisbasis van <date>, <n> dagen oud.` | age of the knowledge package |
| `Kennisbasis: ONBEKEND - er is geen kennispakket geladen.` | no knowledge package at all - so no CVE verdict is possible |
| `Gegevens van <date>, <n> dagen oud, doel: <name>, herkomst: <provenance>.` | age of the export, which target it names, and where it came from |
| `Gegevens: ONBEKEND - <reason>; doel: <name>, herkomst: <provenance>.` | the export carries no usable timestamp |
| `doel: niet vastgelegd` | the export was supplied rather than scanned, so no target is recorded |
| `herkomst: verzameld door deze server op <date> <time> UTC` | this server's own record says it collected exactly this export for that target |
| `herkomst: niet vastgesteld (aangeleverde export)` | no record of this server carries this export: the target name, if any, comes from the export itself |
| `kennispakket niet gepind in de configuratie` | the configuration carries no `kennispin`, so no floor or CVE verdict is established |

## The two knowledge package lines

| Dutch | English | what it means |
|---|---|---|
| `minimaleEngine` | minimum engine | a top-level field of the package: the lowest engine version (MAJOR.MINOR.PATCH, at least `1.1.0`) that may load it |
| bestaande lijn | existing line | packages WITHOUT `minimaleEngine`; they load on 1.0.x and on 1.1 (also with `naconfiguratieVerplicht`). The line for customers still on 1.0.x |
| nieuwe lijn | new line | packages WITH `minimaleEngine` >= `1.1.0`; every 1.0.x engine refuses them as an unknown field. Released only after every customer runs at least that engine |
| `kennispakket vraagt engine <x> of nieuwer; deze engine is <y>; werk eerst de engine bij` | the package needs a newer engine | update the engine first; nothing in the package is used |
| `kennispakket: <pad> moet <type> zijn` | wrong type at a path | the package is refused as a whole; the value is never repeated |
| `kennispakket: <pad> bevat onbekend veld; ...` | unknown field at a path | this engine refuses a field it does not know instead of ignoring it |
| `regressiematrix geweigerd: <reden>` | regression matrix refused | the matrix did not run: wrong package digest, an engine not in `engines`, incomplete coverage, or any other reason the line names (the package version, a package this engine does not load, an engine whose commit cannot be established, the shape of the matrix, a case that does not fit the package) |

`kennis_uitleg` reads no export, so its answer carries the `Kennisbasis`
line only, never the `Gegevens` line - the export/data age does not apply
to a tool that looks nothing up on the appliance.

An answer that says "no known vulnerabilities" with a knowledge base four
months old does not lie, but it does mislead. That is why the age is in
every substantive answer and never optional. If `kennis_uitleg` refuses an
unusable package, it returns the refusal and reason without an age line;
it does not use knowledge from that package.

## An annotated answer

The lines below are real output: `cve_check()` against the NetScaler
export shipped in this repository
([`tests/fixtures/lab-export-vpx-20260826/`](tests/fixtures/lab-export-vpx-20260826/)),
judged against a real vendor bulletin (`tests/test_cve.py`,
`test_the_real_export_against_the_real_bulletins`). Nothing here
is invented for the page.

```
Vraag: raakt een bekende CVE deze build          <- the question, echoed
                                                     back verbatim

- CVE-2026-10816: GERAAKT - de build is kwetsbaar en de voorwaarde altijd
  is aanwezig [vastgesteld]
    bewijs: buildlaag: build 14.1-72.57 < fix-build 72.61; voorwaardelaag:
            voorwaarde geldt onvoorwaardelijk
                                                 <- verdict, certainty, and
                                                     the exact source it
                                                     rests on

- CVE-2026-10817: NIET VASTGESTELD - de voorwaarde
  heeft_tcp_timestamp_profiel is niet vast te stellen [niet vastgesteld]
    reden: buildlaag: build 14.1-72.57 < fix-build 72.61; voorwaardelaag:
           config/nstcpprofile: resource staat niet in het manifest van
           deze export OF parsed/runningconfig.txt: 0 regels 'add ns
           tcpProfile ... -timestamp ENABLED' in 333 regels OF
           parsed/runningconfig.txt: 0 regels 'set ns tcpProfile ...
           -timestamp ENABLED' in 333 regels
                                                 <- a read gap. NOT "you
                                                     are safe" - it is
                                                     unknown

NIET VASTGESTELD (geen stille aanname):          <- every read gap
- config/nstcpprofile: resource staat niet in het manifest van deze export

Kennisbasis van 2026-09-02, 0 dagen oud.        <- how old the rules are
Gegevens: ONBEKEND - dit antwoord is niet gestempeld;
doel: niet vastgelegd.                          <- how old the data is
```

### "NIET BEOORDEELD IN DEZE VERSIE"

A third section exists next to the verdicts and the read gaps, and it
appears only where the product really has a blind spot it chose. It is
not a read gap: a read gap is something that could have been read and
was not, this is something that is deliberately out of range.
`status_overzicht` writes exactly one such line today:

```
NIET BEOORDEELD IN DEZE VERSIE (bewust buiten bereik, geen aanname):
- GSLB-vservers: deze versie leest alleen config/lbvserver,
  config/csvserver, config/vpnvserver en config/authenticationvserver;
  config/gslbvserver wordt niet gelezen en dus ook niet meegeteld
```

A CVE answer carries no such section: every CVE statement is either
GERAAKT, NIET GERAAKT or NIET VASTGESTELD, and the last of those always
names the source that could not be read.

**On FIPS, since it is the question people ask.** This version does
judge a FIPS/NDcPP build: the vendor writes its own train marker into
the version string, and the CVE rules follow that marker onto the FIPS
branch. What is missing is a box: there is no FIPS appliance in either
lab, so that branch is proven on synthetic fixtures only, and it stays
that way in 1.0.

## Configuration keys

The configuration keys are Dutch too. The full table is in the README
under "Running / configuration"; the thirty-four tool names are in "The
thirty-four tools".
