# pseudonymised-historical-no-marker

What it is: the historical output of `scripts/pseudonymise_export.py` pseudonymising the synthetic minimal export `_minimal_export_without_hostname` builds in `tests/test_pseudonymise_export.py` - no manifest marker, alias `LBV-001` for `Synthetic-Gateway`. Entirely synthetic, no lab or customer data.
Made with: the tool exactly as it stood before the manifest marker existed (a commit that is not part of the public history) - run once, locally.
Why recorded: so the "historical output, no marker" regression test no longer depends on git history (a shallow CI checkout, or a history rewrite, leaves that commit unreachable).
