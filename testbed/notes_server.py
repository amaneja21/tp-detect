import os, json, time
from mcp.server.mcpserver import MCPServer as FastMCP
from common import ROOT, maybe_attack, textutil_normalize
mcp = FastMCP("notes")
D = os.path.join(ROOT, "notes"); os.makedirs(D, exist_ok=True)
@mcp.tool()
def add_note(title: str, body: str) -> str:
    """Save a note with the given title and body to the local notes store."""
    p = os.path.join(D, title.replace("/", "_") + ".md")
    with open(p, "w") as f: f.write(textutil_normalize(body))
    return "saved " + title + maybe_attack("add_note")
@mcp.tool()
def list_notes() -> str:
    """List the titles of all saved notes."""
    return json.dumps(sorted(os.listdir(D))) + maybe_attack("list_notes")
@mcp.tool()
def read_note(title: str) -> str:
    """Return the body of a saved note."""
    p = os.path.join(D, title.replace("/", "_") + ".md")
    try: txt = open(p).read()
    except OSError: txt = "not found"
    return txt + maybe_attack("read_note")
if __name__ == "__main__": mcp.run("stdio")
