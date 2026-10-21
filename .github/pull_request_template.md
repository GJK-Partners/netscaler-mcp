## What this changes

<!-- One or two sentences. What was wrong, or what is new. -->

## What was measured

<!-- The command you ran and what it printed. "It works" is not a measurement. -->

## Checklist

- [ ] `python -m pytest -q` is green
- [ ] `python -m ruff check src tests` is green
- [ ] A failing test came first, and it fails without this change
- [ ] Did you change a Dutch user-visible sentence? Then
      `tests/test_product_surface.py` is updated in this same commit, and the
      commit message says why
- [ ] None of the three invariants moved (no socket in a reading tool, nothing
      established without evidence, the confirmation code never in a tool
      result)
- [ ] Everything added is ASCII
