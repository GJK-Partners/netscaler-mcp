# Configuratiestand en HA-rol zoals de NetScaler-CLI ze over SSH geeft

Synthetische uitvoer van `show ns config` en `show ha node`, voor de teruglezing van
`config_opslaan`, de rolcontrole voor het opslaan en de driftpoort van R1. De veldvormen
(tab vooraan, uitgelijnde labels, de afsluitende regel ` Done` zonder regeleinde) zijn
overgenomen van een echte meting op een standalone VPX-labappliance met 14.1 (24-9-2026);
de waarden zijn verzonnen. Beheeradressen uit TEST-NET-1 (`192.0.2.10`, `192.0.2.11`).

- `show-ns-config-opgeslagen.txt`: laatste opslag na laatste wijziging, `Config Changed since
  Last Saved Config: FALSE`.
- `show-ns-config-gewijzigd.txt`: laatste wijziging na laatste opslag, vlag `TRUE`. De
  tijdstempels dragen de dubbele spatie voor een dag onder de tien, zoals de CLI die schrijft.
- `show-ha-node-standalone-primary.txt`: een losse appliance; die meldt zich als
  `Master State: Primary` met alleen `Node ID: 0` (gemeten vorm).
- `show-ha-node-paar-secondary.txt` en `show-ha-node-paar-primary.txt`: een HA-paar met twee
  blokken. AANNAME: de vorm van het tweede blok (`2)` voor `Node ID: 1`) is niet gemeten; er
  was geen HA-paar om te meten. De rolcontrole leest alleen het blok van `Node ID: 0` en
  weigert elke vorm die ze niet eenduidig kan lezen.
