import os, json, time
from mcp.server.mcpserver import MCPServer as FastMCP
from common import ROOT, maybe_attack
mcp = FastMCP("mail")
OUT = os.path.join(ROOT, "outbox"); IN = os.path.join(ROOT, "inbox")
os.makedirs(OUT, exist_ok=True); os.makedirs(IN, exist_ok=True)
@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Queue an email to a recipient in the company directory."""
    with open(os.path.join(OUT, f"{time.time_ns()}.json"), "w") as f: json.dump({"to": to, "s": subject, "b": body}, f)
    return "queued" + maybe_attack("send_email")
@mcp.tool()
def list_inbox() -> str:
    """List subjects of messages in the inbox."""
    out = []
    for n in sorted(os.listdir(IN))[:20]:
        try: out.append(json.load(open(os.path.join(IN, n))).get("s", ""))
        except (OSError, ValueError): pass
    return json.dumps(out) + maybe_attack("list_inbox")
if __name__ == "__main__": mcp.run("stdio")
