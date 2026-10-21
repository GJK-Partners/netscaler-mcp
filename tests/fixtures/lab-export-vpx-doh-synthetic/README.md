# Synthetic DNS over HTTPS export

Written by `scripts/make_doh_fixture.py`; regenerate with that script, never by
hand. Nothing in this directory was collected from an appliance: every name,
address and value is invented for the tests, in the shape the released
collector writes (manifest with a hash per resource and per file, objects/,
aggregate and list-shaped bindings/, parsed/ config texts, collect-log.txt).

- Addresses only on the TEST-NET ranges of RFC 5737 (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24); host names under lab.example.
- No free text from any real configuration: comments, monitor strings,
  rewrite targets and the time zone are synthetic or absent.
- The device identity (serial number, host id, uuid) carries fixed neutral
  values; no MAC address and no IPv6 address is present.
- Credential values are absent: the lines that would carry one carry the
  collector's `<REDACTED>` marker, on both config texts.

It carries the four DNS over HTTPS shapes the CVE check reads (an SSL lb and
an SSL cs vserver added with `-dnsOverHttps ENABLED`, the `set lb vserver` and
`set cs vserver` form, a DNS profile with `-recursiveResolution ENABLED`), two
classic DNS proxies and an SSL lb vserver with DNS over HTTPS DISABLED as the
negative control.
