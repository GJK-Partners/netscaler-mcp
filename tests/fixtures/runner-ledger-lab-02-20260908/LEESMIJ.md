# Ledgerbewijs van de echte upgraderoute op het lab (8-9-2026)

Twee ledgers van dit product, geschreven door de faserunner op een
standalone VPX-labappliance (14.1 build 66.59 naar 72.57), gepseudonimiseerd.

- `run-geslaagd-R0-R6.jsonl`: de volledige zeven-fasenroute, elke fase gesloten met
  `geslaagd`; R6 opent het soakvenster. Duur R0 tot R6: circa 14 minuten, waarvan de
  upload van de bundel (1,1 GB) ruim 8 minuten en de reboot 110 seconden.
- `run-R1-poort-dicht-vrije-ruimte.jsonl`: een eerdere run waarin R1 VOOR het uploaden
  dichtging op de schijfruimtepoort (de buildboom van een vorige poging stond nog op
  /var): nul neveneffecten, precies wat de voorpoort belooft.

Pseudoniemen: doel en hostnaam `netscaler-02`, beheeradres `192.0.2.11` (TEST-NET-1),
firmwaremap `C:\firmware`. Er staat geen serienummer, hostid, uuid of MAC in; de
bevestigingscodes staan er per ontwerp niet in. De bevestiger is het label van de
mechanische labproef (`labproef-driver (bestandsrelay, geen mens)`): het menselijke
bevestigingspad wordt apart aangetoond in de acceptatietest van de eigenaar.

Bekend gat in dit bewijs (niet herschreven): de R3-poort `installatie voltooid (END_TIME)`
bewaarde in deze run de STAART van de installns-uitvoer als bewijs, en die staart bevat de
END_TIME-regel zelf niet (die stond op stderr, voor de staart). De poort oordeelde wel op de
volledige tekst. Sinds de integratie op de releasetak bewaart de runner het beslissende
fragment zelf (`gemeten markerfragment: END_TIME ...`); nieuwe runs dragen dat wel.
