"""netscaler-mcp: a read-first MCP server for a NetScaler appliance."""

# The product version. tests/test_packaging.py holds it equal to the version in
# pyproject.toml; the MCP handshake (`initialize` -> serverInfo.version) names it
# instead of the version of the mcp library (1.0.2).
__version__ = "1.1.0"
