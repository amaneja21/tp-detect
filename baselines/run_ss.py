import json, sys
from skillspector.nodes.analyzers import mcp_tool_poisoning as m
items = json.load(open(sys.argv[1])); out = []
for it in items:
    d = it["description"]; n = it["tool"]
    f = []
    try:
        f += m._check_tp1(d, "description")
        f += m._check_tp2(d, "description", False)
        f += m._check_tp2(n, "name", True)
        f += m._check_tp3([{"name": "description", "description": d}])
    except Exception as e:
        f = []
    out.append(sorted({x.rule_id for x in f}))
json.dump(out, open(sys.argv[2], "w"))
print(sum(1 for o in out if o), "flagged of", len(out))
