# classic - synthetic running-config fragments

Synthetic, hand-written for the classic classification (`src/nsmcp/classic.py`,
spec 1.1 A.5.1). No line comes from an appliance or a customer export: every
name is invented (`CSP_OUD`, `AUTH_POL_OUD`, ...), every address is in the
documentation range 192.0.2.0/24, and the LDAP base is `dc=voorbeeld,dc=test`.

These are fragments of a running configuration, not exports: the classifier
reads lines, and a full export directory here would join the set of export
fixtures whose read-tool text is pinned byte for byte against 1.0.3.

The file name says which set of A.5.1 the fragment is meant to prove:

| file | expected |
|---|---|
| `verzameling-1-filter-gebonden.conf` | the bound `add filter policy` in set 1, the action it names in set 2 (no bind line names it) |
| `verzameling-1-cs-ns-true-gebonden.conf` | `ns_true` in a bound classic CS policy: set 1 |
| `verzameling-1-cmp-ns-true-gebonden.conf` | `ns_true` in a bound classic compression policy: set 1 |
| `verzameling-2-cs-url-ongebonden.conf` | `add cs policy -url` without a binding: set 2 |
| `verzameling-3-audit-ns-true-gebonden.conf` | `ns_true` in a classic audit syslog policy bound to the system: set 3, never blocking |
| `verzameling-3-gateway-gebonden.conf` | classic LDAP authentication policy and its `bind vpn vserver`: set 3 |
| `named-expressions.conf` | a classic named expression used by an audit policy (3), an unused one (4), one used by a bound CS policy (1) |
| `verzameling-4-onbekende-familie.conf` | a policy line of a family the classifier does not know: set 4 |
| `advanced-geen-classic.conf` | advanced expressions only: no finding at all |
