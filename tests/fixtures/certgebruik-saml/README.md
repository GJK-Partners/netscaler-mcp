# certgebruik-saml

Kleine synthetische export (geen echte appliance, geen echte namen of adressen) voor het
certificaatgebruik buiten de bindingen met virtuele servers. Zelfde vorm als een export van de
verzamelaar 1.1.0: manifest met hash per bestand, `objects/` en `bindings/*.by-parent.json`.

| Certificaat | Gebruik in deze export |
|---|---|
| CERT-VS | gebonden aan LBV-WEB-01 en signing-certificaat van SAML-ACTIE-01 |
| CERT-IDP | IdP-certificaat van SAML-ACTIE-01, SAML-ACTIE-02 en IdP-profiel SAML-IDP-01 |
| CERT-SP | SP-certificaat van IdP-profiel SAML-IDP-01 |
| CERT-SG | gebonden aan SSL-servicegroup SG-BACKEND-01 (CA: nee) |
| CERT-SG-CA | gebonden aan SSL-servicegroup SG-BACKEND-01 (CA: ja) |
| CERT-LOS | in deze export aan niets gekoppeld |

SAML-ACTIE-02 draagt een leeg `samlsigningcertname`: niet gezet, geen gebruik en geen leesgat.
SG-LEEG-01 is een SSL-servicegroup zonder certificaatbinding (outcome EMPTY).

Na een wijziging van een bestand hier: de hash in `export-manifest.json` opnieuw zetten.
