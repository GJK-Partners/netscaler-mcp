from nsmcp.permissions import Refusal, ToolError, allow_all


def test_the_decision_point_currently_lets_everything_through():
    assert allow_all("claude", "certificaat_wat_verloopt_er", {"horizon_dagen": 90}) is None
    assert allow_all(None, "status_ververs", {"doelnaam": "lab"}) is None


def test_refusal_is_a_tool_error_and_stays_readable():
    """This test checks the real, shipped property: `Refusal` is a
    `ToolError` subclass (so mask_error() in mcp_server.py passes the text
    through unchanged instead of replacing it with the generic
    "onverwachte fout" message), and the refusal text itself survives
    creating the exception.

    The guarantee that a refused tool really does not run is NOT a property
    of this class - that is an interplay of permissions.py and
    mcp_server.py's `_guarded()`. That coverage therefore lives in
    tests/test_mcp_server.py::test_a_refusal_stops_the_tool_before_it_runs,
    which checks a real side effect (the `ran` list, filled by `run()`)
    through the real server - not here."""
    assert issubclass(Refusal, ToolError)
    refusal = Refusal("dit gereedschap is niet toegestaan voor deze client")
    assert str(refusal) == "dit gereedschap is niet toegestaan voor deze client"
