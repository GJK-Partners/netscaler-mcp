# Openstaande metingen

## Openstaande meting: A15a (DNS over HTTPS) en A15b (FIPS) - de acceptatiepoort van cve.py

Twee takken van `cve.py` rusten vandaag op synthetische fixtures en
vendordocumentatie, niet op een meting aan een echte appliance -
`tests/test_cve.py` bewaakt dat zichtbaar met een luide skip (`pytest -rs`
toont de reden), nooit met een stille groene suite.

**A15a - DNS over HTTPS (1.0-must, GESLOTEN).** `dnsOverHttps` is
CONFIGURATIE en dus op een werkbank te maken - en dat is gebeurd: op
6-9-2026 is op een werkbank een export met `-dnsOverHttps ENABLED`
verzameld en is de DoH-vorm van `cve.py` daarop gemeten. Die export
staat niet in deze repository en komt er ook niet in: een echte export draagt
configuratie die niet aan ons is om te publiceren, en het schoningsgereedschap
dekt vrije tekst (commentaarvelden, monitorteksten, herschrijfpaden) niet.

De vorm is vastgelegd in een SYNTHETISCHE fixture,
`tests/fixtures/lab-export-vpx-doh-synthetic/`, geschreven door
`scripts/make_doh_fixture.py`: elke naam, elk adres en elke waarde daarin is
verzonnen, in de bestandsvorm die de verzamelaar schrijft (manifest met
hashes, objects/, bindings/, parsed/). De poorttest
`tests/test_cve.py::test_the_doh_shape_against_the_synthetic_doh_export`
slaagt tegen die fixture.

Wat de fixture draagt en de suite via de bestaande, gecureerde bulletinset
en zonder een tweede detector vastpint: de vier vormen die de voorwaarde
`heeft_lb_oracle_of_dns` kent - een SSL-lbvserver en een SSL-csvserver met
`-dnsOverHttps ENABLED` op de add-regel, de `set lb vserver`- en
`set cs vserver`-vorm die het achteraf aanzet, en een DNS-profiel met
`-recursiveResolution ENABLED` - plus twee klassieke DNS-proxy's
(servicetype DNS en DNS_TCP) en een negatieve controle (SSL met
`dnsoverhttps=DISABLED`) die in geen enkele bewijsregel voorkomt.
CVE-2026-8655 komt daardoor GERAAKT uit. De meting van 6-9-2026 bracht ook
een los defect aan het licht dat geen synthetische test raakte:
HTTP-ECV-monitorregels met een `q/.../`-vorm waren onleesbaar voor de
tokeniser; dat is gerepareerd, en de synthetische fixture draagt die vorm
zodat de suite het blijft bewaken.

**A15b - FIPS (blijvende grens van 1.0, geen tijdelijke).** Een
FIPS-versietekst is HARDWARE, en die doos staat in geen van beide labs.
De FIPS-tak blijft daarom in 1.0 uitsluitend op synthetische fixtures
beproefd (`tests/test_cve.py::test_the_fips_branch_against_a_real_fips_export`,
skipt zolang `tests/fixtures/fips-export/` leeg is). Dit is geen "nog niet
gemeten" dat binnenkort volgt: er is geen FIPS-appliance gepland in enig
lab, en dit document formuleert het daarom als een blijvende grens van
1.0, niet als een tijdelijke slag om de arm.

Bewijs bij de release-notes: per mutatieproef welke poort is uitgezet, welke test daardoor omviel,
en dat de wijziging is teruggedraaid. Een mutatieproef die alleen op een Windows-werkbank draait,
bewijst niets op de bouwmachine waar de vrijgave op leunt - vandaar dat elke poort in
`src/nsmcp/upgrade.py` staat en niet in de PowerShell-kant van de runner.

## Gemeten: de bouwpoort van het lokale pad (1.1, 26-10-2026)

Voordat het lokale pad (`nsmcp.localpath` en de PowerShell-tweeling `Open-GjkLokaalBestand`) gebouwd
werd, is op Windows met een prototype gemeten of de vijf eigenschappen waar het op rust, echt gelden.
Uitkomst:

- (a) **Bewezen.** Een vastgehouden map (geopend zonder verwijderdeling) kan door een ander proces niet
  hernoemd, verwijderd of vervangen worden, ook niet met de POSIX-verwijderroute; na het vrijgeven
  wel. Bedoelde bijwerking: de hele keten vanaf de volumewortel is tijdens een bewerking vastgehouden.
- (b) **Bewezen.** Een junction of symbolische link die onder een vastgehouden ouder wordt ingewisseld,
  wordt als zichzelf geopend en geweigerd; zonder `FILE_OPEN_REPARSE_POINT` wordt hij wel gevolgd
  (positieve controle). Een vastgehouden map die in het venster leeggemaakt wordt, kan een mount point
  krijgen; de relatieve open eronder geeft `0xC0000280` en volgt niets (daarom staat die status als
  `koppeling` in de tabel).
- (c) **Gemeten, met een verplichte ontwerpwijziging.** Andere schrijvers in een vastgehouden map
  (nieuw bestand, append op een ander bestand, vervangen, hernoemen, submap, verwijderen) worden niet
  geblokkeerd; schrijvers op HETZELFDE bestand wel als dat alleen leesdeling heeft. Daarom kiest het
  product de deelmodus per bestandsklasse: ledger en runnerlog met schrijfdeling, bundel, sidecar,
  sleutel en exportbestanden alleen met leesdeling. Mappen met alleen leesdeling is gemeten en
  verworpen (het blokkeert vervangen, hernoemen en submappen van een ander proces).
- (d) **Bewezen**, met de afwijkingen die in het ontwerp verwerkt zijn: het type wordt na de tag
  getoetst, `0xC0000280` en `0xC0000281` zijn `koppeling`, `STATUS_OBJECT_PATH_NOT_FOUND` komt in de
  wandeling niet voor, `STATUS_DELETE_PENDING` alleen bij de klassieke verwijderroute, en de
  spellingstap (geen dubbele punt in een onderdeel) is een harde eis: zonder die stap maakt een
  relatieve open op `naam:stroom` een alternatieve gegevensstroom aan.
- (e) **Bewezen.** Een symbolische link of mount point naar een UNC-pad (als voorouder en als blad) en
  een `subst`-station worden geweigerd zonder open van het doel en zonder nieuwe SMB-verbinding
  (seamteller en TCP-tabel, met een positieve controle die een naieve open wel ziet); een echte
  netwerkletter wordt geweigerd met nul `NtCreateFile` en alleen `GetDriveTypeW`. In een verhoogde run
  door een tweede hand toonde een ETW-trace van de SMB-client- en SMB-serverprovider de wandeling op
  rustniveau (gelijk aan het venster zonder activiteit), tegenover honderden events en een
  serverzijdig open bestand voor de controle. Een pakketopname met `pktmon` bleek op loopback blind en
  is als waarnemer verworpen.

## Openstaande meting: de netwerkproef van het lokale pad (1.1, B.5)

**Release-blokkerend.** De bouwpoortmeting hierboven (e) is op het prototype gedaan. Op de
productcode is de verhoogde meting een vaste stap van de eindcontrole voor de release: dezelfde
ETW-trace van de SMB-client- en SMB-serverprovider per venster (rust, wandeling, controle die het
bestand openhoudt, wandeling, rust) op `localpath.read_local_bytes` tegen een echte netwerkletter,
verhoogd, door een tweede hand; de controle moet in hetzelfde venster zichtbaar uitslaan, anders telt
de meting niet. De uitkomst komt in dit document. Zonder die meting gaat 1.1 niet uit. De
suiteproef hieronder blijft voor de suite een benoemde skip zonder verhoogde rechten.

**Open.** De proef vraagt een pakketopname (`pktmon`) en daarvoor verhoogde rechten: een symbolische
link op de plek van een voorouder naar het documentatieadres `\\192.0.2.10\x`, de lezing via
`nsmcp.localpath`, en tijdens de lezing nul pakketten naar dat adres op poort 445 en 139. De test
`tests/test_localpath_windows.py::test_the_network_provider_sees_no_packet` doet precies dat, maar
draait alleen met `NSMCP_NETWERKPROEF=1` in een verhoogde sessie; zonder dat is hij een benoemde skip
met deze reden. Wat er zonder opname wel bewezen is: de seamteller van `localpath` (geen enkele
open op de share, het doel van de koppeling komt niet voorbij de spellingstap) en de duur (onder
100 ms, waar een echt netwerkcontact met dat adres 21 s kost, gemeten in de rode review van deel 2
van B) - voor de wandeling zelf (`tests/test_localpath_windows.py`) en voor elke plek die een
bestaan, een mapinhoud of een nieuwe map vraagt (`tests/test_metadata_no_network.py`). Een
seamteller telt geen pakketten; de opname blijft daarom open tot ze gedraaid is.

## Mutatieproeven van de runner

| # | poort | uitgezet in | test die omviel | status |
|---|---|---|---|---|
| 10 | schijfruimte R1 (`disk_gate`) | `if int(free_mb) < drempel:` vervangen door `if False:` | `test_free_space_below_the_vendor_floor_closes_the_gate` | uitgevoerd, teruggedraaid |
| 11 | soakvenster (`soak_gate`) | `if now < einde:` (binnen `soak_gate`, niet `soak_state`) vervangen door `if False:` | `test_the_soak_window_cannot_be_shortened_by_a_tool` | uitgevoerd, teruggedraaid |
| 12 | vendor-precheck (`precheck_gate`) | `if global_status_ruw.lower() == "failed" or gezakt:` vervangen door `if False:` (poort altijd `open`, alsof de exitcode telt) | `test_the_vendor_precheck_gate_ignores_the_exit_code` | uitgevoerd, teruggedraaid |
| 13 | primary-node (`secondary_gate`) | Een latere fix: `secondary_gate` beoordeelt sindsdien alleen het blok van de LOKALE node (`Node ID: 0`) uit `show ha node`, niet de hele tekst - de eerdere vorm zocht `"secondary"` over de VOLLEDIGE uitvoer en opende de poort op de PEER's regel terwijl deze fase op de PRIMARY draaide. Herhaalde mutatie op de huidige regel `if staat == "secondary":` vervangen door `if True:` (poort altijd `open`) | `test_a_phase_on_the_primary_node_of_a_real_ha_pair_is_refused_despite_the_peers_secondary_line` (een ECHTE two-node `show ha node`-fixture; de eerdere single-node fixture van deze proef kon de fout niet vangen en blijft daarnaast bestaan als `test_a_phase_on_the_primary_node_is_refused`) | uitgevoerd, teruggedraaid |
| 9 | hostsleutelcontrole | `start._require_upgrade_hostkeys()`: `if doel is None or not doel.ssh_hostsleutel_vingerafdruk:` vervangen door `if False:` (de startcontrole op `ssh_hostsleutel_vingerafdruk` altijd overslaan) | `test_the_runner_refuses_an_unknown_host_key` | uitgevoerd, teruggedraaid |
| 8 | identiteitsvereiste | `mcp_server._act()`: `if bevestiger is None:` vervangen door `if False:` (de weigering bij een niet-identificerend codekanaal altijd overslaan) | `test_the_runner_refuses_a_channel_that_cannot_identify_the_confirmer` | uitgevoerd, teruggedraaid |
| 14 | startdiagnose: werkmap (1.1) | `mcp_server`: de takken `RunnerWorkdirUnusable` en `RunnerLogUnopenable` van de losgekoppelde start afgebeeld op `RUNNER_NIET_GESTART_PROCES` (alles op PROCES) | `test_unusable_workdir_is_named_as_such` | uitgevoerd 26-10-2026, teruggedraaid |
| 15 | startdiagnose: scriptpin (1.1) | `mcp_server`: de tak `except ScriptPinMismatch` rond `upgrade_command` weggehaald (de fout valt dan in de tak `PowerShellMissing`) | `test_script_pin_mismatch_is_not_reported_as_missing_powershell` | uitgevoerd 26-10-2026, teruggedraaid |
| 16 | startdiagnose: doel bezet na `Popen` (1.1) | `handelen.start_detached`: een fout van de Job Object-meting na een geslaagde `Popen` afgebeeld als `RunnerProcessNotStarted` | `test_failure_after_popen_keeps_the_target_reserved` | uitgevoerd 26-10-2026, teruggedraaid |
| 17 | startdiagnose: controle vooraf (1.1) | `mcp_server`: in de `-WatIs`-tak van `onderhoud_upgrade_fase` de afbeelding op type weggehaald (`detail` alleen nog de klassenaam) | `test_a_preview_that_cannot_start_on_the_proposal_names_why`, `test_a_preview_that_cannot_start_on_the_confirmed_call_names_why` | uitgevoerd 26-10-2026, teruggedraaid |
| 18 | startdiagnose: onbesliste start (1.1) | `mcp_server`: bij een `ActionError` van onbekende soort weer het kader "De handeling is niet gestart: de faserunner kon niet gestart worden", als vastgesteld | `test_an_unknown_action_error_says_the_start_is_undecided_and_keeps_the_target_held` | uitgevoerd 26-10-2026, teruggedraaid |
| 19 | startdiagnose: schrijftools (1.1) | `handelen.default_runner`: de startfout weer als `ActionError` met de tekst van de fout (het PowerShell-pad erin) | `test_a_write_tool_whose_script_cannot_start_shows_no_powershell_path` | uitgevoerd 26-10-2026, teruggedraaid |
| 20 | startdiagnose: pinzin per route (1.1) | `mcp_server`: op het schrijfpad weer de pinzin van de faserunner (`_not_started_sentence(exc)` zonder `scriptpin=`) | `test_a_write_tool_whose_script_differs_from_its_pin_names_its_own_script`, `test_a_save_preview_whose_script_differs_from_its_pin_names_the_script_of_this_action`, `test_a_save_script_that_cannot_start_after_the_redeem_says_nothing_started` | uitgevoerd 26-10-2026, teruggedraaid |
| 21 | startdiagnose: onbekende startfout (1.1) | `handelen._not_started`: de tak `OSError` weg, elke andere fout weer als `RunnerProcessNotStarted` | `test_an_unrecognised_start_failure_is_never_labelled_as_a_process_that_did_not_start` | uitgevoerd 26-10-2026, teruggedraaid |
| 22 | kennispakket: de engine die het pakket vraagt (1.1) | `knowledge._minimum_engine_problem`: `if wanted > engine:` vervangen door `if False:` | `test_package_requiring_newer_engine_is_refused` | uitgevoerd 26-10-2026, teruggedraaid |
| 23 | kennispakket: CVE-regel strikt op sleutels (1.1) | `knowledge._structure_problem`: voor `cve[].cves[]` weer alleen op ontbrekende velden getoetst (de sleutelcontrole overgeslagen, een onbekende sleutel overgeslagen) | `test_unknown_cve_field_is_refused` | uitgevoerd 26-10-2026, teruggedraaid |
| 24 | kennispakket: ondergrens `minimaleEngine` 1.1.0 (1.1) | `knowledge._minimum_engine_problem`: `if floor is None or wanted < floor:` vervangen door `if False:` | `test_minimum_engine_below_1_1_0_is_refused` (alle vijf waarden; het pakket bleef wel geweigerd, door de introductieregel van `minimaleEngine` zelf, maar niet met de vaste zin) | uitgevoerd 26-10-2026, teruggedraaid |
| 25 | kennispakket: typecontrole `extraStapNaUpgrade` (1.1) | `knowledge._structure_problem`: de typecontrole overgeslagen voor het pad `cve[].extraStapNaUpgrade` | `test_extra_step_object_is_refused` | uitgevoerd 26-10-2026, teruggedraaid |
| 26 | kennispakket: introductieregel `FIELD_INTRODUCED` (1.1) | `knowledge._introduction_problem`: `if declared is None or since is None or declared < since:` vervangen door `if False:` | `test_field_newer_than_declared_minimum_is_refused` | uitgevoerd 26-10-2026, teruggedraaid |
| 27 | regressiematrix: digestbinding (1.1) | `knowledge_regression.run_regression`: `if canonical_digest(document) != raw_matrix["pakketdigest"]:` vervangen door `if False:` | `test_regression_matrix_refuses_a_digest_or_engine_mismatch_before_any_case` (een geval draaide) | uitgevoerd 26-10-2026, teruggedraaid |
| 28 | regressiematrix: enginebinding (1.1) | `knowledge_regression.run_regression`: `if (engine.version, engine.commit) not in pinned:` vervangen door `if False:` | `test_regression_matrix_refuses_a_digest_or_engine_mismatch_before_any_case` (een geval draaide) | uitgevoerd 26-10-2026, teruggedraaid |
| 29 | regressiematrix: verplichte dekking (1.1) | `knowledge_regression.run_regression`: `if missing:` vervangen door `if False:` | `test_regression_matrix_requires_full_coverage` | uitgevoerd 26-10-2026, teruggedraaid |
| 30 | regressiematrix: predicaatseam fail-closed (1.1) | `cve._evaluate_condition`: de seam alleen voor opgelegde namen; een niet opgelegde voorwaarde valt door naar de echte evaluatie | `test_the_seam_refuses_a_condition_the_case_does_not_state` | uitgevoerd 26-10-2026, teruggedraaid |
| 31 | regressiematrix: engine-identiteit uit een gewijzigde checkout (1.1) | `knowledge_regression.engine_identity`: `if status.strip():` vervangen door `if False:` | `test_an_editable_checkout_counts_only_when_its_code_is_its_commit` | uitgevoerd 26-10-2026, teruggedraaid |
| 32 | kennispakket: weigerzin zonder predicaattekst (1.1) | `knowledge._condition_problem`: de predicaattekst weer in de zin (`{condition!r}`) | `test_an_existing_refusal_route_names_the_place_not_the_content[predicaat-tekst]` | uitgevoerd 26-10-2026, teruggedraaid |
| 33 | kennispakket: weigerzin zonder takkennamen (1.1) | `knowledge.knowledge_from_document`: de takken die maar in een van `getroffen`/`fix` staan weer in de zin (`!r`) | `test_an_existing_refusal_route_names_the_place_not_the_content[tak-alleen-fix]` | uitgevoerd 26-10-2026, teruggedraaid |
| 34 | oude-lijnharnas: enginebinding gelijk aan de runner (1.1) | `tools/regressie-1.0.x/harnas.py`, `run_matrix`: `if tuple(identity) not in pinned:` vervangen door `if False:` | `test_the_harness_applies_the_same_matrix_rules_as_the_runner` (de vorige vorm van deze test bleef groen) | uitgevoerd 26-10-2026, teruggedraaid |
| 35 | oude-lijnharnas: drempelregel van de dekking (1.1) | `tools/regressie-1.0.x/harnas.py`, `_applies_below`: `threshold < fix` vervangen door `threshold <= fix` | `test_the_harness_applies_the_same_matrix_rules_as_the_runner` (de vorige vorm van deze test bleef groen) | uitgevoerd 26-10-2026, teruggedraaid |
| 36 | kennispakket: bulletin zonder tak (1.1) | `knowledge.knowledge_from_document`: `if not entry[field_name]:` vervangen door `if False:` | `test_a_bulletin_without_branches_is_refused` | uitgevoerd 26-10-2026, teruggedraaid |
| 37 | kennispakket: bulletin zonder CVE (1.1) | `knowledge.knowledge_from_document`: `if not entry["cves"]:` vervangen door `if False:` | `test_a_bulletin_without_cves_is_refused` | uitgevoerd 26-10-2026, teruggedraaid |
| 38 | kennispakket: lengtegrens van een id (1.1) | `knowledge._BULLETIN_ID`: `CTX[0-9]{1,12}` vervangen door `CTX[0-9]+` | `test_an_identifier_is_at_most_as_long_as_its_grammar_allows` | uitgevoerd 26-10-2026, teruggedraaid |
| 39 | regressiematrix: dekking eist een tak per bulletin (1.1) | `knowledge_regression._missing_coverage` en, apart, `tools/regressie-1.0.x/harnas.py` `missing_coverage`: `if not bulletin["getroffen"]:` vervangen door `if False:` | `test_the_coverage_asks_a_branch_of_every_bulletin_in_runner_and_harness` (beide mutaties) | uitgevoerd 26-10-2026, teruggedraaid |
| 40 | lokaal pad: geen herparseerpunt binnen de wortel (1.1) | `localpath._walk_windows`: `if inside:` vervangen door `if False:` (een junction binnen de wortel wordt dan gevolgd zoals boven de wortel) | `test_junction_inside_the_root_is_a_link_and_nothing_below_it_is_opened` | uitgevoerd 26-10-2026, teruggedraaid |
| 41 | lokaal pad: de wandeling per onderdeel (1.1) | `localpath._walk_windows`: de mappen tot de ouder van het blad in een open op het volledige pad (`\Device\HarddiskVolumeN\...`, zonder ouderhandle) in plaats van per onderdeel | `test_ancestor_swap_never_opens_outside_the_root` (het bestand buiten de wortel werd gelezen) | uitgevoerd 26-10-2026, teruggedraaid |
| 42 | lokaal pad: koppeling als zichzelf openen (1.1) | `localpath._walk_windows`: `FILE_OPEN_REPARSE_POINT` weggehaald bij de tussenmappen | `test_ancestor_swap_never_opens_outside_the_root` (het bestand buiten de wortel werd gelezen) | uitgevoerd 26-10-2026, teruggedraaid |
| 43 | lokaal pad: spellingstap voor een stroom (1.1) | `localpath.check_spelling` (`if ":" in rest:`) en `localpath._components` (`if ":" in part:`) beide vervangen door `if False:` | `test_an_alternate_data_stream_is_refused_before_any_open` (de naam met stroom bereikte `NtCreateFile`) | uitgevoerd 26-10-2026, teruggedraaid |
| 44 | lokaal pad: tag voor het type (1.1) | `localpath._leaf_open`: bij lezen weer `FILE_NON_DIRECTORY_FILE` op de open van het blad | `test_a_junction_in_the_place_of_a_file_is_a_link_not_a_wrong_type` (`geen_gewoon_bestand` in plaats van `koppeling`) | uitgevoerd 26-10-2026, teruggedraaid |
| 45 | lokaal pad: vastgehouden map zonder verwijderdeling (1.1) | `localpath.DIR_SHARE` met `FILE_SHARE_DELETE` erbij | `test_a_held_ancestor_cannot_be_renamed_or_deleted_during_a_read` (de vastgehouden map liet zich hernoemen) | uitgevoerd 26-10-2026, teruggedraaid |
| 46 | lokaal pad: deelmodus van het blad per bestandsklasse (1.1) | `localpath._leaf_open`: het blad altijd met `FILE_SHARE_WRITE`, ook zonder `shared_writers` | `test_a_running_append_blocks_a_reader_that_does_not_share_writing` | uitgevoerd 26-10-2026, teruggedraaid |
| 47 | lokaal pad: netwerkstation in de volumestap (1.1) | `localpath._volume_target`: `if drive_type == DRIVE_REMOTE:` vervangen door `if False:` | `test_a_network_drive_letter_is_refused_without_any_open` (`apparaatpad` in plaats van `netwerkstation`) | uitgevoerd 26-10-2026, teruggedraaid |
| 48 | lokaal pad: de wortel op haar eigen tekst (1.1) | `localpath._within` terug naar de vorm van de eerste bouw: de padtekst met `upper()` tegen de worteltekst vergeleken EN de wandeling over de onderdelen van de padtekst | `test_a_case_folding_sibling_of_the_root_is_outside_it` (alle drie: ligatuur, ringel-s, lange s; het zusje van de wortel werd gelezen) | uitgevoerd 26-10-2026, teruggedraaid |
| 49 | lokaal pad: tussenmappen alleen met traverseerrecht (1.1) | `localpath.DIR_ACCESS` weer met `FILE_LIST_DIRECTORY` | `test_an_ancestor_with_only_the_traverse_right_is_walked_and_still_held` (`onleesbaar` op de map zonder lijstrecht) | uitgevoerd 26-10-2026, teruggedraaid |
| 50 | lokaal pad: 0xC0000281 is een koppeling (1.1) | `localpath._LINKISH` zonder `STATUS_DIRECTORY_IS_A_REPARSE_POINT` | `test_every_status_has_one_kind_and_an_unknown_one_is_unreadable[3221226113-koppeling]` | uitgevoerd 26-10-2026, teruggedraaid |
| 51 | lokaal pad: geen schrijfroute buiten Windows (1.1) | `localpath._require_windows_for_writing`: `if not isinstance(_native, _Native):` vervangen door `if False:` | `test_the_write_routes_refuse_off_windows_before_anything_opens` | uitgevoerd 26-10-2026, teruggedraaid |
| 52 | lokaal pad: ordinale wortelvergelijking alleen (1.1) | `localpath._within`: alleen de vergelijking weer met `upper()` (de wandeling blijft op de worteltekst) | `test_a_case_folding_sibling_of_the_root_is_outside_it` (alle drie: `onleesbaar` in plaats van `buiten_wortel`; de wandeling opende de wortel op haar eigen tekst en vond daar het bestand niet, het zusje bleef ongeopend) | uitgevoerd 26-10-2026, teruggedraaid |
| 53 | lezer export: de exportmap als wortel (1.1) | `export._read_export_file`: `root=_root_text(directory)` vervangen door `root=None` (een koppeling in de export wordt dan gevolgd) | `test_export_a_junction_inside_the_export_is_a_read_gap_of_its_kind` (het object van buiten de export, met een passende hash in het manifest, kwam als resultaat terug) | uitgevoerd 26-10-2026, teruggedraaid |
| 54 | lezer ledger: append via de wandeling (1.1) | `upgrade.append_line`: de append via `open_local_for_append` terug naar `open(pad, "ab")` op naam | `test_ledger_an_append_on_a_link_writes_no_line` (geen `PathRefused`; de runtime-controle meldde bovendien `upgrade.py:append_line` als open op naam) | uitgevoerd 26-10-2026, teruggedraaid |
| 55 | lezer kennispakket (1.1) | `knowledge.read_package_document`: de lezing via `read_configured` vervangen door `Path(path).read_bytes()` | `test_knowledge_a_cloud_placeholder_on_the_way_is_absent_with_its_kind` (het pakket laadde door de cloud-plaatshouder heen; de runtime-controle meldde de open op naam) | uitgevoerd 26-10-2026, teruggedraaid |
| 56 | lezer codekanaal: `spent()` (1.1) | `code_channel.FileCodeChannel.spent`: de lezing via `read_local` vervangen door `Path(path).read_bytes()` | `test_1_1_a_code_file_that_became_a_link_keeps_the_handling_rereads_nothing_and_the_code_is_spent` (geen soort in het serverlog; de runtime-controle meldde de open op naam) | uitgevoerd 26-10-2026, teruggedraaid |
| 57 | lezer configuratiebestand (1.1) | `start.load_config`: de lezing via `read_configured` vervangen door `Path(path).read_bytes()` | `test_config_a_cloud_placeholder_after_the_start_check_is_a_config_error_of_its_kind` (geen `ConfigError`; de runtime-controle meldde de open op naam) | uitgevoerd 26-10-2026, teruggedraaid |
| 58 | statische inventaris (1.1) | in `src/nsmcp/export.py` een functie met `Path(p).read_text()` toegevoegd | `test_every_python_file_operation_is_in_localpath_or_a_pinned_exception` (meldde precies `export.py:_mutant: Path(p).read_text`) | uitgevoerd 26-10-2026, teruggedraaid |
| 59 | runtime-controle (audit-hook) (1.1) | `export.load_export`: voor de wandeling ook `read_bytes()` van het manifest op naam | `test_the_reading_tools_open_no_socket_through_a_real_session` (de fixture `open_audit` faalde op `export.py:load_export opende ...export-manifest.json`) | uitgevoerd 26-10-2026, teruggedraaid |
| 60 | lezer herkomst (1.1) | `export._provenance_records`: `root=root` vervangen door `root=None` | `test_provenance_a_swapped_provenance_map_is_no_record_and_its_file_is_never_opened` (het herkomstrecord van buiten de herkomstmap telde) | uitgevoerd 26-10-2026, teruggedraaid |
| 61 | lezer bewaarde exports: volumewortel van de eigen tekst (1.1) | `export.plain_path` en `retention._read_kept` beide zonder wortel (`root=None`) | `test_kept_an_ancestor_of_the_exports_that_is_a_link_refuses_every_kept_export` (de bewaarde export achter een gekoppelde voorouder telde). Eerst gemeten met `test_kept_a_kept_export_swapped_for_a_link_mid_walk_...`: die bleef groen, omdat de bestaande `resolve().parent`-controle van `_owned_manifest` de wissel van de bewaarde map zelf ook vangt; de voorouderproef is de proef die alleen deze laag draagt | uitgevoerd 26-10-2026, teruggedraaid |
| 62 | lezer collector: de werkexportmap als wortel (1.1) | `collect._work_read`: `root=root` vervangen door `root=None` | `test_collector_a_work_map_swapped_mid_walk_fails_the_scan_and_is_never_read` (DID NOT RAISE `CollectError`: het manifest van buiten werd gelezen) | uitgevoerd 26-10-2026, teruggedraaid |
| 63 | lezer vertaaltabel: de map van de tabel als wortel (1.1) | `disclosure._load_table`: `root=root` vervangen door `root=None` | `test_table_a_link_in_the_place_of_the_table_is_refused_and_never_overwritten` (`geen_gewoon_bestand` in plaats van `koppeling`: de junction werd gevolgd). Eerst gemeten met de mapwissel `test_table_a_table_directory_swapped_mid_walk_...`: die bleef groen, omdat het slot de map van de tabel vasthoudt (zonder verwijderdeling) en de wandeling van het slot de wissel al weigert voordat de tabel gelezen wordt | uitgevoerd 26-10-2026, teruggedraaid |
| 64 | lezer ledger: de ledgermap als wortel (1.1) | `upgrade.read_ledger`: `root=localpath.parent_text(tekst)` vervangen door `root=None` | `test_ledger_a_ledger_map_swapped_mid_walk_is_unreadable_and_never_read` (DID NOT RAISE `LedgerUnreadable`) | uitgevoerd 26-10-2026, teruggedraaid |
| 65 | lezer firmwarebundel (Python) (1.1) | `handelen.firmware_target_build`: `root=root` vervangen door `root=None` | `test_firmware_a_firmware_map_swapped_mid_walk_never_opens_the_bundle_outside` (DID NOT RAISE: de bundel van buiten werd geopend) | uitgevoerd 26-10-2026, teruggedraaid |
| 66 | lezer scriptpin (1.1) | `powershell.file_sha256`: `root=localpath.parent_text(text)` vervangen door `root=None` | `test_scriptpin_a_script_directory_swapped_mid_walk_starts_no_process` (DID NOT RAISE: het script van buiten werd gehasht en paste op de pin) | uitgevoerd 26-10-2026, teruggedraaid |
| 67 | lezer runnerlog (1.1) | `handelen.start_detached`: het logbestand zonder wortel (`root=None`) | `test_runner_log_a_ledger_map_swapped_mid_walk_starts_nothing` (de start ging door tot na `Popen`) | uitgevoerd 26-10-2026, teruggedraaid |
| 68 | vaste zinnen per soort (1.1, B.4) | `localpath.REASONS["buiten_wortel"]` ingekort | `test_1_1_the_refusal_sentence_of_every_kind_is_pinned` | uitgevoerd 26-10-2026, teruggedraaid |
| 69 | inventaris: metadata op naam (1.1) | `coverage._object_file_present`: de wandeling vervangen door `(export.directory / "objects" / ...).exists()` | `test_every_python_file_operation_is_in_localpath_or_a_pinned_exception` (meldde precies `coverage.py:_object_file_present: ... .exists`) | uitgevoerd 27-10-2026, teruggedraaid |
| 70 | ledgermap opsommen op de vastgehouden handle (1.1) | `upgrade_gate._rows_for_target`: `list_local` vervangen door `Path(...).glob("*.jsonl")` | `tests/test_metadata_no_network.py::test_the_ledger_map_listing` (21,06 s: een echt netwerkcontact met het documentatieadres) | uitgevoerd 27-10-2026, teruggedraaid |
| 71 | lokaal pad: hardlink binnen de wortel (1.1, B.2 stap 6) | `localpath._walk_windows`: `if links > 1:` vervangen door `if False:` | `test_a_hardlink_inside_the_root_is_refused` (DID NOT RAISE: het bestand van buiten werd via de tweede naam gelezen) | uitgevoerd 27-10-2026, teruggedraaid |
| 72 | tabelslot sluit een tweede proces uit (1.1) | `disclosure._ProcessLock`: het slotbestand met `shared_writers=True` (mutatie R2 van de rode review van deel 2, die tegen de vorige test groen bleef) | `test_table_the_lock_keeps_another_process_out_and_lets_it_in_once_free` (het tweede proces schreef in het vastgehouden slot) | uitgevoerd 27-10-2026, teruggedraaid |
| 73 | mapflush via een heropening van de vastgehouden map (1.1) | `LocalHandle.flush_directory`: terug naar `FlushFileBuffers` op de vastgehouden ouder met alleen traverseerrecht | `test_the_directory_flush_uses_the_held_parent_and_opens_nothing_by_name` (`False`: er werd niets geflusht) | uitgevoerd 27-10-2026, teruggedraaid |
| 74 | bewaking: plafond voor de lezing (1.1) | `export._read_export_file`: `cap_for` van de map genegeerd (alleen het algemene plafond) | `test_watch_target_file_ceiling_holds_before_the_read` (2 `ReadFile` op een doelbestand boven de 1 KiB) | uitgevoerd 27-10-2026, teruggedraaid |
| 75 | herkomstmap aanmaken op de wandeling (1.1) | `export.record_provenance`: `mkdir_local` terug naar `provenance_dir.mkdir(parents=True, exist_ok=True)` | `test_the_provenance_map_and_the_export_identity` (geen weigering van zijn soort; de duur bleef kort omdat de redirector het documentatieadres van mutatie 70 nog als onbereikbaar in zijn cache had) | uitgevoerd 27-10-2026, teruggedraaid |
| 76 | bestaand blad dat niet als zichzelf te openen is (1.1) | `localpath._existing_leaf`: weer `FileExistsError` als de heropening faalt | `test_an_existing_leaf_that_cannot_be_opened_as_itself_is_unreadable_not_already_there` | uitgevoerd 27-10-2026, teruggedraaid |
| 85 | scriptpin: een koppeling met een scriptnaam naast de runner (1.1) | `powershell.check_script_pins`: een weigering van de wandeling op een naam naast de runner weer `continue` (stil overslaan, zoals de eerste herstelronde deed) | `test_h1_a_script_link_beside_the_runner_refuses_the_start` (DID NOT RAISE: de start ging door met een gelinkt script naast de runner) | uitgevoerd 27-10-2026, teruggedraaid |
| 86 | vrije ruimte op de vastgehouden handle (1.1) | `retention.free_mb`: weer `shutil.disk_usage` op de naam | `tests/test_metadata_no_network.py::test_the_free_space_of_the_map_around_the_export` (21,05 s: een echt netwerkcontact) | uitgevoerd 27-10-2026, teruggedraaid |
| 87 | scanslot verwijderen op de handle (1.1) | `collect._remove_lock`: weer `lock.unlink(missing_ok=True)` | `test_removing_a_tree_and_the_scan_lock` (21,06 s). De eerste uitvoering bleef groen: de redirector had het documentatieadres na mutatie 86 als onbereikbaar in zijn cache, zodat de aanroep op naam snel terugkwam; sindsdien krijgt elke test een eigen documentatieadres | uitgevoerd 27-10-2026, teruggedraaid |
| 88 | startmelding bij een andere herkomstidentiteit (1.1) | `start.build_server_from_config`: de melding uit (`if False:`) | `test_h1_a_start_names_provenance_of_another_export_identity` | uitgevoerd 27-10-2026, teruggedraaid |
| 89 | verwijderen: een koppeling als zichzelf (1.1) | `localpath._delete_below`: een koppeling behandeld als een gewone map (de toets `not is_link` weg) | `test_rmtree_local_deletes_a_tree_and_a_link_inside_as_itself_never_its_target` BLEEF GROEN: de koppeling is met `FILE_OPEN_REPARSE_POINT` als zichzelf geopend en levert bij het opsommen geen namen van haar doel op; de laag die het doel beschermt is die open-optie (rij 90), niet deze toets | uitgevoerd 27-10-2026, teruggedraaid |
| 90 | verwijderen opent als zichzelf (1.1) | `localpath._delete_below`: de open zonder `FILE_OPEN_REPARSE_POINT` (een koppeling wordt dan gevolgd) | `test_rmtree_local_deletes_a_tree_and_a_link_inside_as_itself_never_its_target` (de verwijdering volgde de koppeling en brak af) | uitgevoerd 27-10-2026, teruggedraaid |
| 91 | PowerShell-wandeling: elk onderdeel als zichzelf (1.1) | `GjkUpgrade-LokaalPad.ps1`, `Wandeling.Loop`: `FILE_OPEN_REPARSE_POINT` weg bij de tussenmappen | `test_ancestor_swap_never_opens_outside_the_root` (PowerShell; geen weigering: de junction voor `C` werd gevolgd en het bestand buiten de wortel gelezen) | uitgevoerd 27-10-2026, teruggedraaid |
| 92 | PowerShell-wandeling: geen open op het volledige pad (1.1) | `Wandeling.Loop`: de wandeling per onderdeel vervangen door een open van het hele pad onder de volumewortel (de wissel loopt eerst) | `test_ancestor_swap_never_opens_outside_the_root` (PowerShell; geen weigering, het bestand buiten de wortel gelezen) | uitgevoerd 27-10-2026, teruggedraaid |
| 93 | PowerShell-wandeling: de bundel vastgehouden (1.1, race d) | `Wandeling.Loop`: het blad altijd met `FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE` | `test_race_d_the_bundle_cannot_be_swapped_between_the_local_hash_and_the_upload` (hernoemen, overschrijven en verwijderen van de bundel tussen hash en upload gelukt) | uitgevoerd 27-10-2026, teruggedraaid |
| 94 | upload alleen vanaf een vastgehouden stroom (1.1) | `GjkUpgrade-Ssh.ps1`, `Copy-GjkFile`: de controle op een open `GjkLokaalPad.LokaalStroom` vervangen door `if ($false)` | `test_the_real_copy_refuses_a_source_that_is_not_a_held_local_file` (een tekst kwam voorbij de controle en een credential werd gevraagd) | uitgevoerd 27-10-2026, teruggedraaid |
| 95 | firmware-hash ook tegen de lokale hash (1.1) | `upgrade.hash_gate`: de vergelijking doos tegen lokale hash vervangen door `if False:` | `test_the_hash_gate_binds_the_box_to_the_locally_hashed_bundle_too` (`open` in plaats van `dicht`) | uitgevoerd 27-10-2026, teruggedraaid |
| 96 | runner: de firmwaremap als wortel (1.1) | `Invoke-GjkUpgradeFase.ps1`, `_GjkOpenLokaal`: `-Wortel` vervangen door `-ZonderWortel` | `test_a_bundle_that_is_a_junction_is_refused_with_exit_4_before_the_session[R1]` (de junction op de plek van de bundel werd gevolgd; de weigering noemde een map in plaats van een koppeling) | uitgevoerd 27-10-2026, teruggedraaid |
| 97 | runner: stderr van de bruggen door een pijp (1.1) | `_GjkAanroepPython`: terug naar een tijdelijk bestand op naam onder `Stop` | `test_the_stderr_of_a_bridge_reaches_the_fout_line_through_a_pipe_not_a_file` (de stderr-regel werd een afbrekende fout; exitcode 1 in plaats van 2) | uitgevoerd 27-10-2026, teruggedraaid |
| 98 | runner: de bundel vastgehouden tot na de upload (1.1, race d) | STAP 3b: de stroom direct na hash en sidecar gesloten | `test_race_d_the_bundle_cannot_be_swapped_between_the_local_hash_and_the_upload` (de firmwaremap kon tussen hash en upload hernoemd worden) | uitgevoerd 27-10-2026, teruggedraaid |
| 99 | runner: de firmwaremap opsommen op de vastgehouden handle (1.1) | `Invoke-GjkUpgradeFase.ps1`, `_GjkBundelKandidaten`: terug naar `Get-ChildItem` op naam | `test_a_firmware_map_below_a_link_to_a_share_is_refused_before_any_listing[run]` (geen weigering: de opsomming op naam volgde de koppeling naar de share, vond niets, en de fase startte en opende een sessie) | uitgevoerd 27-10-2026, teruggedraaid |
| 100 | PowerShell-wandeling: hardlink binnen de wortel (1.1) | `GjkUpgrade-LokaalPad.ps1`, `Wandeling.Loop`: de toets op meer dan een naam vervangen door `if (false)` | `test_a_hardlink_inside_the_root_is_refused_and_read_without_a_root` (het bestand van buiten de wortel werd gelezen) | uitgevoerd 27-10-2026, teruggedraaid |
| 101 | opslagscript: stderr van de brug door een pijp (1.1) | `Invoke-GjkConfigOpslaan.ps1`, `_GjkAanroepPython`: terug naar een tijdelijk bestand op naam onder `Stop` | `test_a_warning_of_the_judging_half_on_stderr_does_not_block_the_save` (een waarschuwing van de brug: "onverwachte fout", niets opgeslagen, exitcode 3) | uitgevoerd 27-10-2026, teruggedraaid |
| 102 | PowerShell-inventaris hoofdletterongevoelig (1.1) | `tests/test_read_inventory.py`: `_I = re.IGNORECASE` vervangen door `0` | `test_the_powershell_scanner_skips_comments_and_counts_the_operations` (`get-content` en `[io.file]::` niet geteld) | uitgevoerd 27-10-2026, teruggedraaid |
| 103 | PowerShell: opsommen alleen op de vastgehouden handle (1.1) | `Get-GjkLokaleNamen`: `Wandeling.Namen` vervangen door `Get-ChildItem` op naam | `test_listing_below_a_link_to_a_share_never_contacts_the_network` (geen weigering: de opsomming op naam liep via de koppeling naar de share) | uitgevoerd 27-10-2026, teruggedraaid |
| 104 | volumeserienummer op de vastgehouden volumehandle (1.1, C) | `_Native.query_volume_serial`: het serienummer op de verkeerde plek van de structuur gelezen (`raw[12:16]` i.p.v. `raw[8:12]`) | `test_the_volume_serial_is_read_on_the_held_volume_root_and_opens_nothing` (wijkt af van `GetVolumeInformationW`) | uitgevoerd 27-10-2026, teruggedraaid |
| 105 | genormaliseerde mapnaam op de vastgehouden handle (1.1, C) | `LocalHandle.directory_name`: de padtekst van de wandeling teruggeven i.p.v. de genormaliseerde naam | `test_the_directory_name_is_the_same_for_a_short_name_and_another_case` (korte naam en hoofdletters gaven drie verschillende teksten) | uitgevoerd 27-10-2026, teruggedraaid |
| 106 | `create_local` exclusief (1.1, C, R2) | `_leaf_open(mode="create")`: `FILE_CREATE` vervangen door `FILE_OPEN_IF` | `test_create_local_is_exclusive_and_names_a_link_in_its_place` en `test_create_local_opens_relative_to_the_held_parent_with_create_and_no_follow` | uitgevoerd 27-10-2026, teruggedraaid |
| 107 | `rename_local` zonder vervangen (1.1, C, R2) | `rename_local`: `set_rename(..., replace=False)` vervangen door `replace=True` | `test_rename_local_renames_by_handle_and_never_replaces` en `test_rename_local_renames_by_handle_in_the_held_parent_without_replace` | uitgevoerd 27-10-2026, teruggedraaid |
| 108 | rij-MAC vertaaltabel (1.1, C) | `tablekey.verify_doc`: de MAC-vergelijking per rij `if False:` | `test_swapped_names_are_refused` | uitgevoerd 27-10-2026, teruggedraaid |
| 109 | keten vertaaltabel (1.1, C) | `tablekey.verify_doc`: de rijnummertoets `if False:` | `test_reordered_rows_are_refused` | uitgevoerd 27-10-2026, teruggedraaid |
| 110 | kop vertaaltabel (1.1, C) | `tablekey.verify_doc`: de kop-MAC-vergelijking `if False:` | `test_truncated_table_with_hand_made_head_is_refused` | uitgevoerd 27-10-2026, teruggedraaid |
| 111 | watermerk (1.1, C, laadregel 8) | `tablekey.load`: `if watermark(doc, anchor):` vervangen door `if False:` (watermerk niet gelezen) | `test_rollback_to_an_older_valid_table_is_refused` | uitgevoerd 27-10-2026, teruggedraaid |
| 112 | anker-id-vergelijking (1.1, C, S-5) | `tablekey.load`: `_identity` weg en de sleutel met id en generatie uit het BESTAND geopend | `test_restored_previous_generation_with_its_key_is_refused` (soort `keten` i.p.v. `afgedankt`) | uitgevoerd 27-10-2026, teruggedraaid |
| 113 | berekend slot (1.1, C, S-5) | `tablekey._identity`: de slotvergelijking weg | `test_tables_swapped_between_two_places_are_refused` (soort `tabelid` i.p.v. `slot`) | uitgevoerd 27-10-2026, teruggedraaid |
| 114 | bestaand anker is nooit een eerste start (1.1, C) | `tablekey.load`: "geen bestanden = eerste start" ook met een anker | `test_existing_anchor_with_missing_files_is_never_a_first_start` | uitgevoerd 27-10-2026, teruggedraaid |
| 115 | controle van het ankerrecord (1.1, C) | `tablekey.parse_anchor`: de `controle`-vergelijking weg | `test_a_torn_or_edited_anchor_record_is_unreadable[controle-klopt-niet]` | uitgevoerd 27-10-2026, teruggedraaid |
| 116 | herlezen onder het slot voor een ankerschrijving (1.1, C) | `tablekey.write_anchor`: `if current != expected_raw:` vervangen door `if False:` | `test_a_delayed_anchor_writer_never_moves_the_anchor_back`. Eerste meting: bleef groen, omdat de monotonietoets de lagere schrijver ook ving; de test is aangescherpt met een vertraagde schrijver op DEZELFDE hoogte (een verloren update), die alleen het herlezen ziet - daarna viel hij | uitgevoerd 27-10-2026, teruggedraaid |
| 117 | binding bij inwisseling (1.1, C.3) | `ConfirmationStore.redeem`: de bindingvergelijking `if False:` | `test_code_redemption_rechecks_table_binding` (het script startte onder generatie 2) | uitgevoerd 27-10-2026, teruggedraaid |
| 118 | tabelpoort voor `validate()`/`issue()` (1.1, C.3) | `mcp_server` schrijfpad: `verify_table(...)` vervangen door `pass` | `test_manipulated_table_refuses_write_before_a_code_is_issued` (er werd een code uitgegeven) | uitgevoerd 27-10-2026, teruggedraaid |
| 119 | backup teruggelezen voor vervanging (1.1, C.4) | `tablekey._backup`: de SHA-256-vergelijking van de teruggelezen backup weg | `test_a_backup_that_does_not_read_back_byte_equal_stops_before_the_anchor` | uitgevoerd 27-10-2026, teruggedraaid |
| 120 | `--gecontroleerd` vereist (1.1, C.4) | `tablekey.migrate`: `if not confirmed:` vervangen door `if False:` | `test_the_cli_without_the_flag_changes_nothing` | uitgevoerd 27-10-2026, teruggedraaid |
| 121 | vorm 1 naast een anker nooit opnieuw gemigreerd (1.1, C.2 m0, revisie 3) | `tablekey.migrate`: m0 weigert alleen nog bij een geldige vorm 2 en loopt bij een vorm-1-terugschrijving door naar de migratie | `test_a_1_0_x_rewrite_next_to_an_anchor_is_never_migrated_again` (er verscheen een nieuwe backup; de ankerschrijving werd daarna nog door de herleescontrole geweigerd) | uitgevoerd 27-10-2026, teruggedraaid |
| 122 | sleutelbestand bij de start op de plek waar het uitkomt (1.1, C.5) | `start`: de `_refuse_where_it_leads` van het sleutelbestand weg | `test_c_the_table_and_its_key_file_are_refused_where_they_lead_at_beperkt[...sleutel...]` | uitgevoerd 27-10-2026, teruggedraaid |
| 123 | pseudoniem in de rij-MAC (1.1, C, herstelronde 1) | `tablekey.row_mac`: het pseudoniem uit het MAC-bericht gehaald | `test_swapped_pseudonyms_are_refused` (twee rijen met verwisseld pseudoniem werden geaccepteerd) | uitgevoerd 27-10-2026, teruggedraaid |
| 124 | rij-MAC in de schrijfbinding (1.1, C.3, herstelronde 1) | `mcp_server._binding_key`: de MAC uit de bindingsleutel | `test_the_write_binding_carries_the_row_mac` | uitgevoerd 27-10-2026, teruggedraaid |
| 125 | aanmaakfout met vaste zin (1.1, C, herstelronde 1) | `tablekey._create`: de `OSError`-vertaling naar `FileFailed` weg | `test_a_create_that_fails_is_a_file_failure_with_its_class_only` en `test_a_file_failure_reaches_the_cli_as_a_fixed_sentence_without_traceback` | uitgevoerd 27-10-2026, teruggedraaid |
| 126 | opgeslagen bestandsnaam in het slot (1.1, C, herstelronde 1) | `tablekey.place_of`: de geconfigureerde naam i.p.v. `leaf_name` | `test_the_slot_takes_the_stored_file_name_so_an_8_3_file_name_gives_the_same_slot` (sinds de herkeuring: `test_an_8_3_file_name_of_the_table_is_refused_and_another_case_is_the_same_place`) | uitgevoerd 27-10-2026, teruggedraaid |
| 127 | mapopsomming op de vastgehouden handle (1.1, C, herstelronde 1) | `tablekey.directory_names`: `os.listdir` op de padtekst i.p.v. de handle | `test_the_directory_listing_is_read_on_the_held_handle` | uitgevoerd 27-10-2026, teruggedraaid |
| 128 | `localpath.leaf_name` op de handle (1.1, C, R2, herstelronde 1) | de laatste component van de padtekst teruggeven i.p.v. de genormaliseerde naam | `test_leaf_name_is_the_stored_long_name_and_none_when_missing` | uitgevoerd 27-10-2026, teruggedraaid |
| 129 | reset-hervatting eindigt (1.1, C, herstelronde 1) | `tablekey._finish_reset`: weer stoppen ("draai de reset opnieuw") i.p.v. de onvoltooide tabel aan de kant zetten | `test_a_reset_resumption_whose_new_table_no_longer_verifies_still_ends` | uitgevoerd 27-10-2026, teruggedraaid |
| 130 | label van afgedankte bestanden (1.1, C, herstelronde 1) | `tablekey._finish_reset`: label weer uit het (onleesbare) anker, dus 0 | `test_a_reset_without_a_readable_anchor_discards_and_never_deletes` | uitgevoerd 27-10-2026, teruggedraaid |
| 131 | vormregel "nieuw id nooit al afgedankt" (1.1, C, herstelronde 1) | `tablekey._anchor_shape_ok`: de toets `nieuw.tabelId in afgedankt` weg | `test_a_torn_or_edited_anchor_record_is_unreadable[nieuw-id-al-afgedankt]` | uitgevoerd 27-10-2026, teruggedraaid |
| 132 | 8.3-bestandsnaam van de tabel geweigerd (1.1, C, herkeuring M-2) | `tablekey.place_of`: de toets op een andere spelling van de bestandsnaam weg | `test_an_8_3_file_name_of_the_table_is_refused_and_another_case_is_the_same_place` en `test_an_8_3_file_name_is_refused_with_its_own_sentence_and_nothing_is_written` (zonder toets: hetzelfde slot, dan `sleutel_ontbreekt`) | uitgevoerd 27-10-2026, teruggedraaid |
| 133 | classic: geen `ns_true`-catchall (1.1, A.5.1) | `classic.classify`: elke `add`-regel met `ns_true`/`ns_false` als verwijderd behandeld (gebonden: verzameling 1) | `test_classic_ns_true_in_audit_is_deprecated_not_blocking` | uitgevoerd 27-10-2026, teruggedraaid |
| 134 | classic: klasse Filter (1.1, A.5.1) | `classic._FAMILIES`: de sleutel van `add filter policy` onbruikbaar gemaakt (klasse uit de tabel) | `test_classic_classification_filter_policy_bound_blocks` | uitgevoerd 27-10-2026, teruggedraaid |
| 135 | classic: onbeslist is geen groen in overstapmodus (1.1, A.5.1) | `preflight._check_2_classic_transition`: `if classification.undecided:` vervangen door `if False:` | `test_classic_undecided_is_not_assessed_in_transition_mode` | uitgevoerd 27-10-2026, teruggedraaid |
| 136 | classic: named expression volgt de gebruikende feature (1.1, A.5.1) | `classic.classify`: de tak voor gebruikers uit verzameling 1/2 vervangen door `elif False:` | `test_classic_named_expression_inherits_the_using_feature` | uitgevoerd 27-10-2026, teruggedraaid |
| 137 | toets 2 binnen 14.1 byte-gelijk (1.1, sectie 2 regel 5) | `preflight.preflight_checks`: `_check_2_classic_markers` vervangen door `_check_2_classic_transition` | `test_the_three_read_tools_are_byte_identical_to_1_0_3` (5 van de 10 exportfixtures vielen om) | uitgevoerd 27-10-2026, teruggedraaid |
| 138 | classic: `ns_adv_*` is geen classic-bewijs (1.1, A.5.1) | `classic._bare_form`: de uitzondering voor `ns_adv_` vervangen door `if False:` | `test_classic_an_advanced_builtin_name_is_not_proof_of_classic` | uitgevoerd 27-10-2026, teruggedraaid |
| 139 | classic: onbekende familie blijft onbeslist (1.1, A.5.1) | `classic.classify`: een classic regel van een onbekende familie gebonden in verzameling 1 gezet | `test_classic_a_family_the_spec_names_no_class_for_stays_undecided` | uitgevoerd 27-10-2026, teruggedraaid |
| 140 | classic overstap: ook de opgeslagen configuratie (1.1, A.5.1, besluit R1) | `preflight._check_2_classic_transition`: de opgeslagen configuratie niet gelezen (`saved, saved_gap = [], None`) | `test_classic_transition_reads_the_saved_config_too` | uitgevoerd 27-10-2026, teruggedraaid |
| 141 | classic overstap: opgeslagen configuratie ontbreekt (1.1, besluit R1) | `preflight._check_2_classic_transition`: `if saved_absent:` vervangen door `if False:` | `test_classic_transition_without_saved_config_is_not_assessed_with_the_fixed_reason` | uitgevoerd 27-10-2026, teruggedraaid |
| 142 | classic overstap: ongebonden verwijderd blokkeert (1.1, besluit R2) | `classic.Classification.removed` geeft alleen verzameling 1 | `test_classic_transition_blocks_on_an_unbound_removed_feature` | uitgevoerd 27-10-2026, teruggedraaid |
| 143 | classic: `SYS.EVAL_CLASSIC_EXPR` onbeslist (1.1, besluit R3) | `classic._bare_form` en `classic._rest_form`: de herkenning van `SYS.EVAL_CLASSIC_EXPR` uitgezet | `test_classic_table_2_rest_forms_block_with_their_row` (3 gevallen, geen bevinding; na besluit R3b hernoemd) | uitgevoerd 27-10-2026, teruggedraaid |
| 144 | classic: ingebouwde classic-policy alleen op een bindregel (1.1, besluit R3) | `classic._rest_form`: de `ns_`-naamtoets vervangen door `if False and ...` | `test_classic_builtin_classic_policy_only_on_a_bind_line_blocks` (6 gevallen; na besluit R3b hernoemd) | uitgevoerd 27-10-2026, teruggedraaid |
| 145 | classic: patclass onbeslist (1.1, besluit R3) | `classic._rest_form`: de patclass-tak vervangen door `if False and ...` | `test_classic_table_2_rest_forms_block_with_their_row` (geval rij 10; na besluit R3b hernoemd) | uitgevoerd 27-10-2026, teruggedraaid |
| 146 | classic: onleesbare bindregel bewijst geen ongebonden (1.1, review M-1) | `classic.classify`: `unreadable_bind` uit de voorwaarde | `test_classic_an_unreadable_bind_line_keeps_a_removed_feature_removed` (na besluit R3c hernoemd: nu verzameling 2) | uitgevoerd 27-10-2026, teruggedraaid |
| 147 | classic: LB-regel zonder bindregel is onbeslist (1.1, review M-2) | `classic.classify`: `family.rule_flag_only` uit de voorwaarde | `test_classic_a_classic_lb_rule_without_a_bind_line_is_removed` (na besluit R3c hernoemd: nu verzameling 2) | uitgevoerd 27-10-2026, teruggedraaid |
| 148 | classic: client-security-kop bewijst geen vorm (1.1, review M-3) | `classic._bare_form`: de `CLIENT.OS`/`APPLICATION`/`SYSTEM`-toets weg | `test_classic_client_security_expression_is_classic` (3 gevallen; na besluit R3b hernoemd: de kop is nu classic, tabel 3 rij 18) | uitgevoerd 27-10-2026, teruggedraaid |
| 149 | classic: blokkerende named expression noemt de rij van de gebruiker (1.1, review M-4) | `classic.classify`: bron terug naar tabel 3 rij 1 | `test_classic_named_expression_in_set_1_cites_the_users_row` | uitgevoerd 27-10-2026, teruggedraaid |
| 150 | classic overstap: regelnummers heel afgekapt (1.1, review I-d) | `preflight._bounded_numbers`: afkappen op de tekenlimiet | `test_the_bounded_line_list_never_cuts_a_number` | uitgevoerd 27-10-2026, teruggedraaid |
| 151 | classic: vormen met een eigen rij in tabel 2 blokkeren (1.1, besluit R3b) | `classic.classify`: de restvormen terug naar verzameling 4 | `test_classic_table_2_rest_forms_block_with_their_row` en `test_classic_builtin_classic_policy_only_on_a_bind_line_blocks` (17 gevallen) | uitgevoerd 27-10-2026, teruggedraaid |
| 152 | classic: tabel-1-familie Priority Queuing (1.1, besluit R3b) | `classic._FAMILIES`: de sleutel van `add pq policy` onbruikbaar gemaakt | `test_classic_table_1_families_block_with_their_row` (geval pq) | uitgevoerd 27-10-2026, teruggedraaid |
| 153 | classic: `Q.`/`S.`-voorvoegsel (1.1, besluit R3b, tabel 2 rij 2) | `classic._rest_form`: de voorvoegseltoets vervangen door `if False and ...` | `test_classic_table_2_rest_forms_block_with_their_row` (3 gevallen rij 2) | uitgevoerd 27-10-2026, teruggedraaid |
| 154 | classic: client-security-kop is classic (1.1, besluit R3b, tabel 3 rij 18) | `classic._bare_form`: de kop terug naar onbeslist | `test_classic_client_security_expression_is_classic` (3 gevallen) | uitgevoerd 27-10-2026, teruggedraaid |
| 155 | classic: tabel-3-rij buiten de spec-klassen is deprecated (1.1, besluit R3b) | `classic._FAMILIES`: de sleutel van `add tunnel trafficPolicy` onbruikbaar gemaakt | `test_classic_table_3_families_without_a_spec_class_are_deprecated_with_their_row` (geval tunnel) | uitgevoerd 27-10-2026, teruggedraaid |
| 156 | classic: ingebouwde policy alleen uit de allowlist (1.1, herkeuring H-1) | `classic._rest_form`: de allowlist `ns_cmp_*`/`ns_nocmp_*` vervangen door elke `ns_`-naam | `test_classic_vendor_objects_with_an_ns_name_that_are_no_classic_policy_are_no_finding` | uitgevoerd 27-10-2026, teruggedraaid |
| 157 | classic: ingebouwde policy alleen op een policyplaats (1.1, herkeuring H-1) | `classic._rest_form`: alle tokens van de bindregel als policyplaats | `test_classic_vendor_objects_with_an_ns_name_that_are_no_classic_policy_are_no_finding` | uitgevoerd 27-10-2026, teruggedraaid |
| 158 | classic: leesbaar commando van een verwijderde feature blijft verwijderd (1.1, besluit R3c) | `classic.classify`: onzekere binding terug naar verzameling 4 | `test_classic_an_unreadable_bind_line_keeps_a_removed_feature_removed` en `test_classic_a_classic_lb_rule_without_a_bind_line_is_removed` | uitgevoerd 27-10-2026, teruggedraaid |
| 159 | classic: HTMLInjection met tabel 1 rij 7 (1.1, herkeuring H-3) | `classic._rest_form`: de HTMLInjection-tak vervangen door `if False:` | `test_classic_filter_and_html_injection_commands_block` (4 gevallen) | uitgevoerd 27-10-2026, teruggedraaid |
| 160 | classic: elk Filter-commando blokkeert (1.1, herkeuring H-3) | `classic._rest_form`: de Filter-tak vervangen door `if False and ...` | `test_classic_filter_and_html_injection_commands_block` (5 gevallen) | uitgevoerd 27-10-2026, teruggedraaid |
| 161 | classic: vermoedelijke SPDY-parameter onbeslist (1.1, herkeuring H-3) | `classic._rest_form`: de `-spdy`-toets vervangen door `if False:` | `test_classic_candidate_parameters_of_rows_without_a_known_form_are_undecided` (geval rij 5) | uitgevoerd 27-10-2026, teruggedraaid |
| 162 | classic overstap: niet onderzochte rijen benoemd (1.1, herkeuring H-3/H-5) | `preflight._check_2_classic_transition`: de zin `NOT_EXAMINED_ROWS` uit de evidence | `test_classic_transition_names_the_rows_it_does_not_examine` | uitgevoerd 27-10-2026, teruggedraaid |
| 163 | classic: literals zijn geen vorm (1.1, herkeuring H-4) | `classic._strip_literals` geeft de tekst ongewijzigd terug | `test_classic_literals_and_comments_are_no_form` (5 gevallen) | uitgevoerd 27-10-2026, teruggedraaid |
| 164 | classic: `-comment` is geen vorm (1.1, herkeuring H-4) | `classic._scan_text`: de waarde van `-comment` niet overgeslagen | `test_classic_literals_and_comments_are_no_form` (geval comment) | uitgevoerd 27-10-2026, teruggedraaid |
| 165 | classic: client-security-kop in een verwijderde familie onbeslist (1.1, herkeuring H-6) | `classic.classify`: de kop overal classic | `test_classic_client_security_head_in_a_removed_family_is_undecided` | uitgevoerd 27-10-2026, teruggedraaid |
| 166 | classic: een zelf onleesbare regel blijft onbeslist (1.1, besluit R3c) | `classic.classify`: de afwaardering van een onleesbare regel vervangen door `if False:` | `test_classic_an_unreadable_line_with_a_rest_form_stays_undecided` en `test_classic_an_unreadable_policy_line_itself_stays_undecided` | uitgevoerd 27-10-2026, teruggedraaid |

Voor elk van de vier uitgevoerde proeven (10-13): de bewuste regel is met een enkel woord uitgezet
(`if False:` of `if True:`), de genoemde test viel om op precies de reden die de poort bewijst, en
de wijziging is meteen teruggedraaid - de werkkopie was daarna weer schoon en de volledige
testsuite stond weer op groen voor er iets werd vastgelegd.

**Telkens opnieuw uitgevoerd wanneer de poorten veranderden.** De vier proeven zijn na elke
wijziging aan de poorten herhaald tegen de gewijzigde code: `disk_gate` (aangenomen bundelgrootte
in plaats van een stille nul), `precheck_gate` (begrensd bewijs), `soak_gate` (parseerbare
UTC-tijden, en het venster dat op de nieuwste begintijd bindt in plaats van op de volgorde van de
ledgerbestanden). De uitgezette expressie van de vendor-precheck heet daardoor anders dan
de eerste keer; de vier testnamen in de tabel hierboven zijn onveranderd en blijven de proef. Alle vier vielen elke
keer om op precies de reden die de poort bewijst, en elke wijziging is meteen teruggedraaid - de
volledige testsuite stond daarna weer groen voor er iets werd vastgelegd.

De twee proeven bij het gereedschap `onderhoud_upgrade_fase` (8 en 9 in de tabel hierboven): elke uitgezette regel bracht
precies de genoemde test om, en beide wijzigingen zijn meteen teruggedraaid - de werkkopie was
daarna weer schoon en de volledige testsuite stond weer op groen voor er iets werd vastgelegd.

De drie proeven van de startdiagnose (14-16, versie 1.1): elke mutatie is in de werkkopie
aangebracht, de genoemde test is alleen gedraaid en viel om op zijn eigen bewering (14: de zin over
de werkmap ontbrak; 15: de zin over de scriptpin ontbrak; 16: het antwoord noemde "het proces kon
niet worden gestart" terwijl er een kindproces bestond), en het bestand is daarna byte voor byte
teruggezet - `git status` was weer schoon.

De tien proeven van het kennispakket en de regressiematrix (22-31, versie 1.1): elke mutatie is in
de werkkopie aangebracht, alleen de genoemde test is gedraaid en viel om, en het bestand is daarna
byte voor byte teruggezet (sha256 voor en na gelijk) - `git status` was weer schoon.

De vier proeven 32-35 en de vijf mutaties van 36-39 (versie 1.1) op dezelfde manier. 34 en 35 zijn eerst op de vorige vorm van
de pariteitstest gedraaid: daar overleefden beide (de test gaf het harnas een vaste, gepinde
identiteit en kende alleen de synthetische matrix). Op de huidige vorm vallen beide, 34 op een
geval met een engine die niet in `engines` staat, 35 op een pakket met de `vanaf`-drempel op de
fix-build.

De acht proeven van het lokale pad (40-47, versie 1.1) op dezelfde manier: elke mutatie is in
`src/nsmcp/localpath.py` aangebracht, alleen de genoemde test is gedraaid en viel om op zijn eigen
bewering, en het bestand is daarna byte voor byte teruggezet (sha256 voor en na gelijk). 41 is de
kernproef (de wandeling vervangen door een open op het volledige pad): de
wissel van de voorouder `C` door een junction naar een map buiten de wortel gaf toen de inhoud van
het bestand buiten de wortel. 40 is de mutatie op de moduleproef; de proef per lezer (een junction
binnen de exportmap wordt een leesgat) komt met het aansluiten van de lezers.

De vijf proeven 48-52 (versie 1.1) op dezelfde manier. 48 en 52 samen tonen de twee lagen van de
wortelcontainment: met beide uit (48) werd een zusje van de wortel met een ligatuur, een ringel-s of
een lange s als "binnen" gelezen; met alleen de vergelijking uit (52) opende de wandeling nog steeds
de wortel op haar eigen tekst en bleef het zusje ongeopend.

De acht proeven 91-98 (versie 1.1, de PowerShell-route van het lokale pad) op dezelfde manier: elke
mutatie in de werkkopie, alleen de genoemde test gedraaid, het bestand daarna byte voor byte
teruggezet (sha256 voor en na gelijk, `git status` ongewijzigd). 93 en 98 samen tonen de greep van
race (d): met een blad dat verwijderdeling toestaat (93) lukten hernoemen, overschrijven en
verwijderen van de bundel, maar het hernoemen van de firmwaremap bleef geweigerd, omdat de keten van
mappen nog vastgehouden werd; met de stroom gesloten voor de upload (98) lukte het hernoemen van de
firmwaremap (de pogingen op de bundel faalden daarna alleen omdat het pad niet meer bestond).

De vijf proeven 99-103 (versie 1.1) op dezelfde manier. 99 en 103 samen tonen dat de firmwaremap nooit
meer op naam opgesomd wordt: met een opsomming op naam (in de runner, of in `Get-GjkLokaleNamen` zelf)
volgde de opsomming een koppeling naar een share voordat er iets weigerde.

## Gemeten: het oude-lijnharnas op de tags v1.0.1, v1.0.2 en v1.0.3 (26-10-2026)

`tools/regressie-1.0.x/opzetten.py` heeft elke tag in een eigen omgeving geinstalleerd: een kloon op
de volledige commit van de tag (teruggelezen), de hash-gelockte `requirements-build.txt` en
`requirements-dev.txt` van die tag, dan de tag zelf. Gemeten:

- v1.0.1, v1.0.2 en v1.0.3 weigeren een pakket met `minimaleEngine` op topniveau, met een passende
  canonieke pin, als `kennispakket bevat onbekend veld: 'minimaleEngine'`;
- alle drie eindigen `python -m nsmcp.knowledge --regressie` met exitcode 2 (hun gebruiksregel);
- de synthetische matrix van `tests/fixtures/kennis-regressie/` (19 gevallen) klopt op engine
  v1.0.3, met dezelfde digest- en enginebinding als op 1.1; een verkeerde digest, een matrix zonder
  de v1.0.3-commit, een ontbrekend geval en een verkeerd verwacht oordeel geven elk exitcode 1, de
  eerste drie voordat er een geval draait.

Grens, blijvend: de predicaatseam bewijst de regelkeuze en de samenvoeging, niet dat een
exportpredicaat de echte vorm van een appliance herkent; dat blijft het werk van de predicaattests
op echte exportfixtures (de openstaande A15a/A15b hierboven).

## Gemeten: de faserunner is eind-tot-eind tegen een appliance gedraaid (8-9-2026)

De volledige route R0 tot en met R6 is op 8-9-2026 achter elkaar gedraaid tegen een standalone
VPX-labappliance, van 14.1 build 66.59 naar 72.57, langs het echte productpad
(`onderhoud_backup_maken`, `status_ververs`, `onderhoud_upgrade_fase` per fase,
`onderhoud_upgrade_stand`). Het ledger van die run staat gepseudonimiseerd in de repo
(`tests/fixtures/runner-ledger-lab-02-20260908/`) en wordt door `tests/test_runner_ledger_evidence.py`
bewaakt. Gemeten, per fase: de upload van de bundel (1,1 GB) ruim 8 minuten, waarna de sha256 OP de
doos gelijk was aan de vendorwaarde; `installns --pre_check` beslist op `global_status` (hier
`warning`, nul gezakte checks) en niet op de exitcode; `installns -Y -n` meldt `END_TIME` (op stderr);
de reboot gaf SSH-authenticatie terug na 110 seconden met de hostsleutel opnieuw gepind; R5 las de
doelbuild exact terug en berekende het anker; R6 opende het soakvenster en een volgende fase werd
geweigerd met de vroegste eindtijd erin. De aannames die hieronder eerder als onbewezen stonden
(`sha256 -q` op de doos, de `df`-parse, het pre-check-pad, `END_TIME`, de reboot-terugkeer) zijn
daarmee gemeten - en een deel bleek anders dan aangenomen: de appliance zet een waarschuwingsblok voor
elke shell-uitvoer, `installns` schrijft zijn tijdmarkers naar stderr, het precheck-bestand draagt dat
blok plus een afsluitregel rond de JSON, een standalone appliance meldt zich als Primary, en
buildbomen liggen genest onder `/var/nsinstall/<tak>/`. Al die vondsten zitten in de code.

**Wat deze run NIET bewijst, en dat hoort erbij:**

- **een HA-paar**: de labappliance is standalone; de secondary-eerst-volgorde en de failover-poort
  (`doel is secondary` met een peer) zijn alleen op fixtures bewezen. Op standalone geldt de
  expliciete menselijke acceptatie `standalone_geaccepteerd` (downtime);
- **`extraStapNaUpgrade`**: `http2smallwndtimeout` bestaat niet onder 72.61, dus die controle blijft op
  fixtures bewezen;
- **SDX, chassis-instances en FIPS**;
- **het menselijke bevestigingspad**: deze run bevestigde elke fase met een bestandsrelay in plaats van
  een mens aan de sso-presenter (de bevestiger heet in het ledger dan ook `labproef-driver
  (bestandsrelay, geen mens)`); de acceptatietest van de eigenaar met de Windows-presenter is het
  bewijs van dat pad.

**Wat een hertest vraagt, gemeten:** een fase die `poort dicht` of `mislukt` sluit, kan niet in
dezelfde run opnieuw; een hertest is een nieuwe run, en de doelbuildboom van de vorige poging moet
eerst van `/var/nsinstall` (anders sluit R1 terecht op de schijfruimtepoort).

## Openstaande meting: `rapport_na_upgrade` blok 1

`rapport_na_upgrade` draagt vandaag drie van de vier ontworpen blokken: het CVE-oordeel op de
nieuwe build (blok 2), de extra stap na de upgrade als eigen controle (blok 3), en blok 4 (het
genormaliseerde configuratie-anker) - alle drie uitsluitend uit bronnen die al op deze branch
bestaan (`cve.cve_check`, het kennispakket, het ledger). De acht familietellingen die ook bij
blok 4 horen, blijven vandaag `niet vastgesteld` - zie de eigen sectie daarover hieronder.

**Blok 1 - de dekkingsuitspraak van beide exports (voor en na) naast elkaar - is bewust niet
gebouwd.** `compare.py` en `retention.py` bestaan inmiddels wel: `compare.compare_answer()` kent
een modus `pre/post` die twee exports van hetzelfde doel rond een wijziging vergelijkt, en
`retention.newest_kept(export_dir)` levert de vorige bewaarde export van diezelfde exportmap.
Beide zijn daarmee in principe geschikt voor blok 1 - maar `after_upgrade.py` roept geen van
beide aan: `report_after_upgrade()` neemt `before` wel aan, gooit het meteen weg (`del before`)
en levert in plaats daarvan de vaste `NotAssessed`-melding hieronder. Het aansluiten van blok 1
is dus geen nieuwe motor bouwen, maar de bestaande `compare_answer()`/`newest_kept()` vanuit
`after_upgrade.py` aanroepen.

Er komt geen tweede vergelijkingsmotor en geen tweede manier om de vorige export te vinden - dat
was precies het probleem dat een gescheiden `compare.py`/`retention.py` voorkomt. Zolang blok 1
ontbreekt, noemt het antwoord dat expliciet als `NIET BEOORDEELD IN DEZE VERSIE` (`nsmcp.
after_upgrade.BLOCK_ONE_SUBJECT`/`BLOCK_ONE_REASON`) - nooit een stille leegte die leest als
"niets aan de hand", en nooit een `GERAAKT`/`NIET GERAAKT` op dekking die dit product niet las.

## Openstaande meting: de acht familietellingen van R5

Blok 4 van `rapport_na_upgrade` zet acht familietellingen van vóór en na de upgrade naast elkaar:
`lbvserver`, `csvserver`, `vpnvserver`, `authenticationvserver`, `service`, `servicegroup`,
`sslcertkey` en `lbmonitor`. **Die vergelijking blijft vandaag `niet vastgesteld`**, en het
antwoord zegt er per regel bij waarom: R5 schrijft geen `familietellingen`-poort in zijn
sluitregel. R0 doet dat wel, uit de export.

**Waarom dat niet even is bij te bouwen.** R0 telt objecten uit de export — de NITRO-telling per
resource. R5 leest niet uit een export maar live over SSH, en het enige dat die fase in handen
heeft is de draaiende configuratie (`show ns runningConfig`). Tellen uit die configuratie is een
ándere telling dan tellen uit de export. Gemeten op de labexport
(`tests/fixtures/lab-export-vpx-20260826`):

| familie | objecten in de export | `add`-regels in de configuratie |
|---|---|---|
| `lbmonitor` | 31 | 0 |
| `sslcertkey` | 4 | 3 |
| de overige zes | gelijk | gelijk |

Ingebouwde monitors en het ingebouwde servercertificaat bestaan wél als NITRO-object, maar staan
niet als `add`-regel in de configuratie. Een R5 die uit de configuratie telt, zou dus permanent
`verschillend` melden op twee van de acht families, zonder dat er iets veranderd is. Erger: een
telling uit de configuratie kan "nul geconfigureerd" niet onderscheiden van "verkeerd geteld", en
zou bij een fout stilletjes op `gelijk: R0=0, R5=0` uitkomen. Dat is precies het soort
schijnzekerheid dat dit product nergens accepteert.

**Wat er nodig is om het wél te leveren.** Een tweede export, verzameld ná de upgrade, en R5 die
zijn familietellingen daaruit haalt zoals R0 dat doet — dezelfde meting aan beide kanten. Dat is
een uitbreiding van de route (een verzamelstap tussen R4 en R5), geen regel code die er nu bij
kan. Tot die tijd staan de acht regels er wél, elk met de reden erbij; ze springen vanzelf aan
zodra R5 de poort schrijft.

## Openstaande meting: de twee ankers komen uit verschillende bronnen

Hetzelfde blok 4 vergelijkt het genormaliseerde configuratie-anker van R0 met dat van R5. Die twee
hashes worden over verschillende teksten berekend:

- **R0** hasht de draaiende configuratie **uit de export** (`parsed/runningconfig.txt`).
- **R5** hasht de draaiende configuratie **live**, over SSH (`show ns runningConfig`).

De verzamelaar redigeert credentialvelden op de jumphost vóór hij de export wegschrijft
(`collect-log.txt`: "geredigeerd op de jumphost"); de live lezing van R5 is niet geredigeerd. Het
anker sluit regels met `set ns encryptionParams`, `set ns rpcNode` of `-encrypted` uit en telt ze
apart — maar niet elke geredigeerde regel draagt een van die drie markeringen. Gemeten op de
labexport: drie regels `add vpn sessionAction ... -ssoCredential <REDACTED>` blijven staan en gaan
dus mee in de hash.

**Gevolg.** Op een appliance met zulke regels is `verschillend` het permanente antwoord, ook als er
niets aan de configuratie veranderd is. Het antwoord noemt daarom bij elk anker zijn eigen bron en
zet er bij een verschil een reden bij die dit uitlegt. Een `verschillend` is een aanleiding om te
kijken, geen vaststelling dat de configuratie gewijzigd is.

**Wat er nodig is om het wél waterdicht te maken.** Beide kanten uit dezelfde soort bron laten
komen — dezelfde tweede export als hierboven, of een redactie die aan beide kanten identiek
gebeurt. Zolang dat er niet is, blijft dit een gerichte aanwijzing en geen bewijs.

## Openstaande meting: een gewijzigd wachtwoord tussen running en saved

`config_drift`, `ha_stand` en pre-flight toets 4 tellen een regel die tussen de draaiende en de
opgeslagen configuratie alleen verschilt in het deel dat een geheim kan dragen, als drift - maar
alleen als de export die waarde draagt. De uitgebrachte verzamelaar vervangt zulke waarden op de
jumphost aan beide kanten door `<REDACTED>` (gemeten: tien regels per kant op de eerste labexport,
dertien op de tweede); een gewijzigd wachtwoord dat niet is opgeslagen, staat dan als twee gelijke
regels in de export. Het product telt die regels als "niet te vergelijken" en zegt `onbevestigd`
zolang de kopregels een wijziging na de laatste opslag melden of onleesbaar zijn.

**Wat niet gemeten is.** Of NetScaler een versleutelde waarde in de draaiende en de opgeslagen
configuratie gelijk schrijft. Op een export die de waarden wél draagt, zou een waarde die bij
opslaan opnieuw versleuteld wordt als drift tellen terwijl er niets gewijzigd is. De labexports
kunnen dat niet laten zien: daar draagt elke zulke regel het merkteken, dus de telling is er per
constructie nul. Evenmin gedraaid: de vormen (system user, LDAP-bindwachtwoord, RPC-wachtwoord,
monitorwachtwoord) tegen een appliance met een echt gewijzigd, niet opgeslagen wachtwoord;
`-ldapBindDnPassword` komt in geen van beide labexports voor. Evenmin gemeten: of een wijziging van
uitsluitend een wachtwoord op de appliance zelf de kopregel `Last modified` van de draaiende
configuratie verzet (en `Last Config Changed Time` in de teruglezing van `config_opslaan`). De
uitkomst `uit` op een export met zulke gemarkeerde regels leunt op die aanname - alleen wanneer de
kopregels een wijziging na de laatste opslag melden, telt het antwoord `onbevestigd` in plaats van
`uit`; verzet een ongeopslagen wachtwoordwijziging die kopregel niet, dan blijft het antwoord `uit`
terwijl de wijziging wel bestaat.

**Wat er nodig is.** Een export die de waarden draagt (of een vingerafdruk per scan in plaats van
het vaste merkteken), van een appliance waarop een wachtwoord gewijzigd en niet opgeslagen is, en
van dezelfde appliance na opslaan. Om de premisse hierboven zelf te meten: een export van vlak vóór
en van vlak ná het wijzigen van uitsluitend een wachtwoord, zonder tussentijds op te slaan, om vast
te stellen of de kopregel van de draaiende configuratie dat wijzigingsmoment verzet.

## Openstaande meting: de vloerpoort van R0 en de runbinding op een appliance

R0 draagt de poort `doelbuild op of boven de vloer, of bewust geaccepteerd`, en R1 tot en met R6
weigeren een bundel die afwijkt van die waarmee R0 van dezelfde run startte. **Beide zijn vandaag
alleen offline bewezen**: met eenheidstests op de poort en de weigering, en met de faserunner
tegen een nep-transport (de runner geeft de huidige build en de vloer door, de poort staat in
`terugrolpunt_vast` en in de sluitregel, een afwijkende vorm weigert bij de binding). Geen van
beide is op een appliance gedraaid; R0 raakt de appliance ook niet aan, maar de keten server -
runner - ledger is op het lab nog niet met een echte vloer en een echte huidige build doorlopen.

**Wat de meting moet laten zien.** Op het lab met doelbuild 14.1-72.57 en vloer 14.1-73.32
(CTX696939): een R0 zonder acceptatie sluit met de vloerpoort dicht en noemt doelbuild, vloer,
bulletin en de huidige build uit de export; dezelfde R0 met `doelbuild_geaccepteerd=true` opent
die poort als menselijke beslissing; `onderhoud_upgrade_plan` en het R0-voorstel noemen vooraf de
huidige build en `ONDER de vloer` met CTX696604 en CTX696939 als open bulletins. Daarna een
bundelwissel in `onderhoud.firmwaremap` na een gesloten R0: het voorstel van R1 weigert met "de
doelbuild van deze run (R0) wijkt af van de bundel in onderhoud.firmwaremap; start een nieuwe
run", zonder code.

**Wat het niet dekt.** Een FIPS/NDcPP-doos: de vloer van een FIPS-trein heeft niet de vorm die de
runner aanneemt, gaat dus niet mee, en `doelbuild_geaccepteerd=true` gaat dan ook niet mee; R0
sluit daar op "geen vloer" (het plan zegt dat erbij). Dat is fail-closed, maar niet op een echte
FIPS-appliance gemeten. Evenmin gemeten: een tak zonder bekende vloer, waar R0 alleen met
`doelbuild_geaccepteerd=true` opent als menselijke beslissing. Ook de releaselijntoets is
alleen offline bewezen: een doelbuild in een andere releaselijn dan de huidige build sluit R0,
ook met acceptatie en ook zonder vloer, en een export zonder leesbare build laat R0 alleen met
acceptatie open, met "huidige build niet bekend" in het bewijs. Een echte bundel van een andere
releaselijn is op het lab niet aangeboden.

## Aanvullende meetgrenzen uit de publieke basis

**netscaler-mcp** · wat dit product bewust nog niet vaststelt

Dit product zegt liever "niet vastgesteld" dan iets aannemelijks. Deze pagina noemt waar dat
vandaag gebeurt en wat er nodig is om die gaten te sluiten. U kunt ze in een antwoord tegenkomen;
het zijn geen storingen. Hoe u een antwoord leest, staat in
[HANDLEIDING.md](HANDLEIDING.md); wat het product met uw gegevens doet, in
[BEVEILIGING-EN-DATASTROMEN.md](BEVEILIGING-EN-DATASTROMEN.md).

## Een bron zonder hash wordt niet gelezen

Het verzamelscript hoort bij elke bron een SHA-256 van het opgehaalde bestand in het manifest te
schrijven. Dit product vergelijkt die hash met het bestand op schijf voordat het er iets uit
leest. Klopt de hash niet, dan wordt de bron niet vertrouwd. **Staat er geen hash, dan wordt de
bron evenmin vertrouwd** — geen hash is geen vertrouwen. Er is geen tussenweg waarin een bestand
"waarschijnlijk wel goed" is.

Dat heeft een zichtbaar gevolg. In de export waarop dit product is gemeten, meldt het manifest
voor de bron `config/lbmonitor` status OK en 31 objecten, maar liet het verzamelscript de hash
leeg. Het gevolg:

- `rapport_dekking` telt die bron als **MISLUKT**, niet als gelezen bron, en noemt de reden erbij;
- `beveiliging_verstopte_regels` zet de twee regels die deze bron nodig hebben op
  **niet beoordeeld**, in plaats van ze stilzwijgend als "niet geraakt" af te vinken.

Beide gereedschappen zeggen daarmee hetzelfde over dezelfde bron. Dat is de bedoeling: twee
antwoorden die elkaar tegenspreken zijn erger dan een antwoord dat iets niet weet.

**Wat het sluit:** een verzamelscript dat ook voor deze bron een hash schrijft. Dit is werk aan de
verzamelkant, niet aan de leeskant. Zodra die hash er is, valt deze bron niet langer op de
hashpoort; het objectbestand zelf staat al op schijf.

## Twee bindingsbestanden zijn niet te kruiscontroleren

`rapport_dekking` legt de parentlijst van elk bindingsbestand naast de objectbron van die parents.
Dat gebeurt voor beide vormen die het verzamelscript schrijft (een platte lijst per parent, en een
document per parent met een lijst per soort binding). Op de gemeten export met elf
bindingsbestanden blijven er daarna **twee** over met een gat, en geen van beide is een vorm die dit
product niet kan lezen:

- `lbmonitor_binding.by-parent.json`: de objectbron `config/lbmonitor` heeft geen hash (zie
  hierboven), dus de parentlijst is niet te kruiscontroleren;
- `sslcipher_binding.by-parent.json`: het verzamelscript haalt de objectbron `config/sslcipher`
  niet op, dus die staat niet in het manifest en er is niets om tegen te kruiscontroleren.

Het antwoord meldt dan "2 van de 11 bindingsbestanden dragen een gat", met bij elk bestand deze
reden. Dat is eerlijk: de bindingen zelf zijn gelezen, alleen de volledigheid van de parentlijst is
niet te bewijzen.

**Wat het sluit:** een verzamelscript dat `config/lbmonitor` met een hash wegschrijft en
`config/sslcipher` ophaalt. Ook dit is werk aan de verzamelkant.

## De ciphergroep wordt niet uitgeklapt

`beveiliging_tls_baseline` geeft per virtuele server een cijfer volgens dezelfde regelset als de
healthcheck waar dit product zich aan spiegelt. Verwijst de cipherbinding alleen naar een
**groepsnaam** (bijvoorbeeld `DEFAULT`), dan levert de export de leden van die groep niet mee: het
bestand waarin ze zouden staan ontbreekt.

Staat er op de virtuele server geen SSL-profiel, dan rekent de healthcheck in dat geval met de
groepsnaam zelf. Dit product doet dat ook, want een ander cijfer voor dezelfde configuratie maakt
het vergelijk tussen beide onbruikbaar. Draagt de virtuele server wél een SSL-profiel en ontbreekt
de expansie van de gebonden groep, dan wordt er niet met de groepsnaam gerekend — maar het gevolg
voor uw antwoord is hetzelfde als hieronder.

Wat dit product er in beide gevallen bij zegt: het cijfer draagt **niet vastgesteld** in plaats
van vastgesteld. Op de bewijsregel staat `ciphergroep niet uitgeklapt; letter volgens de
NSHC-regel`, in de kenmerken staat `ciphergroep niet uitgesplitst`, en onder de kop
`NIET VASTGESTELD (geen stille aanname):` staat de reden nog een keer voluit. Bij het cijfer staat
dus welke regelset en welke versie het volgt, en waar het op steunt en waar niet.

Wie de leden van een groep niet kent, weet niet of er een zwakke cipher tussen zit: het cijfer kan
in werkelijkheid lager uitvallen dan de letter die er staat.

**Wat het sluit:** een export die de leden van een gebonden ciphergroep meelevert. Dat is opnieuw
werk aan de verzamelkant.

## Een enkele appliance zonder partner

Staat er maar één HA-node in de export, dan zijn er twee standen in `ha_stand` die niets te
beschrijven hebben: de rolverdeling en de propagatie naar een partner. Die staan dan op
`niet van toepassing` — niet op `uit`, want er is geen rolverdeling die uit staat. Ze houden ook
geen wijziging tegen. De geforceerde stand en het verschil tussen de running en de saved config
worden zonder partner gewoon beoordeeld.

## Certificaatgebruik dat niet gevolgd wordt

De certificaattools volgen een certificaat naar de virtuele servers en SSL-diensten waaraan het
gebonden is, naar de certificaten die het uitgeeft, en naar drie gebruikers buiten die bindingen:
SAML-acties (IdP- en signing-certificaat), SAML-IdP-profielen (IdP- en SP-certificaat) en
SSL-servicegroups (met de CA-vlag). Een van die drie bronnen die niet in de export staat, geeft
"niet vastgesteld: bron ... niet in de export" en nooit "geen gebruik".

Wat deze versie **niet** volgt:

- **OAuth en OpenID Connect**: een certificaatverwijzing in een OAuth-actie of -profiel wordt niet
  gelezen;
- **certificaten in monitors**: een monitor die met een eigen certificaat of SSL-profiel naar de
  backend kijkt, wordt niet als gebruiker van dat certificaat gezien;
- **client-cert-CA-ketens buiten de binding**: een CA-certificaat dat alleen via een SSL-profiel,
  een CRL- of OCSP-instelling of een ketenlink een rol speelt, en niet via een binding met een
  virtuele server, een SSL-dienst of een SSL-servicegroup.

Noemt het bindingsbestand van de certificaatkant voor een certificaat een soort binding die deze
versie niet leest, dan zegt het antwoord dat met die soort erbij, en staat dat certificaat op
"onbekend" in plaats van "los".

De parentlijst van het servicegroupbestand wordt gekruiscontroleerd tegen `config/sslservicegroup`,
de objectbron die het bestand zelf als parentbron noemt. Is die bron niet bruikbaar gelezen, dan is
de kruiscontrole niet te maken: dat is een leesgat, en dan komt er geen wijzigingsvoorstel. Een
appliance zonder SSL-servicegroups is vastgesteld zodra `config/sslservicegroup` gelezen en leeg is.

Op een export zonder deze bronnen staat een certificaat zonder vastgesteld gebruik op "onbekend" in
plaats van "los". Dat raakt ook toets 5 van `status_update_preflight`: verloopt zo'n certificaat
binnen dertig dagen, dan is die toets "niet beoordeeld". Een nieuwe scan met verzamelscript 1.1.0
lost dat op.

**Wat het sluit:** een verzamelscript dat die bronnen ophaalt, en leesregels in dit product die ze
volgen. Tot die tijd noemt `certificaat_wat_moet_ik_doen` alleen de gebruikers die het kent; kijk
bij een certificaat met een van de bovenstaande rollen zelf na waar het nog meer in gebruik is.

## Wat dit product niet bewijst

Dit is geen live scan. Wat de appliance in een echte TLS-handshake aanbiedt — de volgorde van de
certificaatketen, OCSP-stapling in de praktijk — volgt niet uit een configuratie. Het TLS-antwoord
zegt dat zelf, onder de kop `NIET BEOORDEELD IN DEZE VERSIE (bewust buiten bereik, geen aanname):`.
Een HA-antwoord bewijst evenmin een werkende failover: het leest de standen, het schakelt niets om,
en het zegt ook dat op dezelfde manier.

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
geen geslaagde fase. Het faseoordeel komt uit het ledger. Sinds 1.1 draagt een
regel waarbij een kindproces niet startte, of waarbij dat onbeslist is, een
elfde veld, `oorzaak`: de soort fout (de klassenaam), nooit de tekst ervan.

De twaalf bevindingen uit de externe review zijn in deze integratie verwerkt
(14-9-2026), met drie bewuste afwijkingen van de aangedragen patches: een MCP-host
binnen een Windows Job Object wordt niet geweigerd maar gemeten (zie "Gemeten: de
faserunner en het Job Object van de host" in OPENSTAANDE-METINGEN.md); de vendorbanner
wordt herkend op zijn gemeten eerste zin, niet op een exacte tweede zin; en de
volledigheidseis aan `show ha node` geldt alleen op het pad dat met
`standalone_geaccepteerd` opent. Historische ledgergegevens zijn niet herschreven.

## Gemeten: de faserunner en het Job Object van de host (14-9-2026)

Gemeten op het werkstation, niet beredeneerd: elke MCP-server die de desktopclient start,
draait binnen een Windows Job Object (`IsProcessInJob` op alle zes draaiende productservers:
waar). Een Job Object kan zijn leden beëindigen zodra zijn laatste handle sluit.
`onderhoud_upgrade_fase` vraagt daarom eerst om losmaking uit dat Job Object
(`CREATE_BREAKAWAY_FROM_JOB`, alleen toegestaan als het Job Object dat toelaat), meet daarna
waar de faserunner terecht is gekomen, en meldt dat als regel `faserunner:` in het antwoord —
een van drie vaste zinnen: `losgekoppeld`, `host-gebonden` of `niet beoordeeld`. Een host
binnen een Job Object wordt dus niet geweigerd: dat zou precies de host weigeren waarvoor dit
product gebouwd is.

Niet gemeten: of een host-gebonden faserunner het afsluiten van de host daadwerkelijk
overleeft, en of het Job Object van de desktopclient losmaking toestaat. Het antwoord zegt
welke van de standen de start kreeg; de acceptatietest van de eigenaar meet voor het eerst op
een echte desktopclient welke dat is.


## Scorekaart: ontbrekende licentie- en protocolmetingen (14-9-2026)

De gemeten EXPRESS-export draagt geen `daystoexpiration` in `config/nslicense`.
ANNA-LIC-001 blijft daarom NIET BEOORDEELD/Hoog, bewust afwijkend van de
NSHC-default PASS/Info. Een gemeten verloopdatum sluit dit leesgat. Ontbrekende
featurelicentievelden blijven eveneens onbekend; alleen expliciet false bewijst
niet-gelicentieerd.

Het SSLv2-veld ontbreekt op de profielgedragen vservers van deze build. L1-010
behoudt dit als leesgat; een veilige stand is zonder aanvullende meting niet bewezen.

## De Gateway-keten blijft open

`dienst_keten` volgt de stap van contentswitching naar loadbalancing (standaard
load balancer en beleid, elk beleid via `cspolicy`/`csaction` naar zijn doel, en van daar de
bestaande loadbalancing-keten). De Gateway-keten volgt deze versie nog steeds niet: een
Gateway-vserver hangt niet aan een servicegroup, en de sessiepolicy-keten die er wel toe leidt
vraagt om prioriteitsgedrag dat zonder bewijs uit een testomgeving niet sluitend te bepalen is
(zie het antwoord zelf, onder `NIET BEOORDEELD IN DEZE VERSIE`). Dit blijft een bewuste grens
van deze versie, geen toevallig leesgat.

Kan een beleid niet worden opgelost — `cspolicy` of `csaction` staan niet, of niet leesbaar, in
de export (GEWEIGERD, MISLUKT, of gewoon geen vermelding in het manifest), of een verwijzing
daarin (een beleid zonder actie, een actie zonder doel) wijst nergens naartoe — dan is de HELE
route "niet vastgesteld" met de reden erbij, en toont het antwoord alleen de standaard load
balancer en de beleidsnamen zelf — nooit een gegokt doel; de standaard load balancer wordt in
dat geval ook niet verder gevolgd. De uitgebrachte verzamelaar leest `cspolicy`/`csaction` al
mee (beide labexports dragen ze); "niet in de export" is dus in de praktijk eerder een
leesprobleem of een niet-oplosbare verwijzing dan een oudere collectorversie.

Een contentswitching-vserver die geen standaard load balancer en geen beleid draagt, maar wel
een andere binding (een GSLB-vserver, een VPN-vserver of een soort die deze versie niet kent),
routeert via die binding. Die route volgt deze versie niet: de vserver is dan "niet
vastgesteld" en de reden noemt de bindingssoort, nooit "gat in de keten". Draagt de vserver
zo'n binding naast een standaard load balancer of beleid, dan is de hele route evengoed "niet
vastgesteld" met de bindingssoort in de reden - hetzelfde antwoord als voor een csaction met
een doel dat geen loadbalancing-vserver is. Een beleidsbinding (responder, rewrite en
soortgelijk beleid) stuurt niet naar een andere vserver en laat het oordeel staan. Geen van
beide labexports draagt zo'n routerende binding; dit gedrag is alleen op synthetische exports
gemeten.
