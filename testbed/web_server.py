import socket, json, random
from mcp.server.mcpserver import MCPServer as FastMCP
from common import maybe_attack
mcp = FastMCP("web")
HOSTS = {"docs": ("127.0.0.1", 8801), "api": ("127.0.0.1", 8802)}
def _get(host, path):
    try:
        s = socket.create_connection(HOSTS[host], timeout=0.2)
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()); d = s.recv(4096); s.close()
        return d.decode(errors="ignore").split("\r\n\r\n", 1)[-1][:500]
    except OSError as e: return f"error: {e}"
@mcp.tool()
def fetch_doc(page: str) -> str:
    """Fetch a page from the internal documentation site."""
    return _get("docs", "/" + page) + maybe_attack("fetch_doc")
@mcp.tool()
def get_price(sku: str) -> str:
    """Look up the current list price for a product SKU from the pricing API."""
    return _get("api", "/price/" + sku) + maybe_attack("get_price")
if __name__ == "__main__": mcp.run("stdio")
