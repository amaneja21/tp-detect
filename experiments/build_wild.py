"""Independent benign corpus: tool lists returned by live third-party MCP servers (tools/list),
de-duplicated against MCPTox (exact description match or same tool name on a same-named server)."""
import json, sys
wild = json.load(open(sys.argv[1])); D = json.load(open(sys.argv[2])); out = sys.argv[3]
mc_desc = {r["description"].strip() for r in D}
rows, seen = [], set()
for pkg, rec in wild.items():
    names = [t["name"] for t in rec["tools"]]
    for t in rec["tools"]:
        d = (t["description"] or "").strip()
        if len(d) < 10 or d in mc_desc or d in seen: continue
        seen.add(d)
        rows.append(dict(server="wild:" + pkg, tool=t["name"], description=d, server_tools=names, label=0, kind=rec["kind"]))
json.dump(rows, open(out, "w"), indent=0)
print(len(rows), "wild benign tools from", len({r['server'] for r in rows}), "servers")
