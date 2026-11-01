import json, sys
from guardbench.analysis.metadata_analyzer import analyze_tool
from guardbench.domain.schemas import ToolDefinitionData
items = json.load(open(sys.argv[1])); out = []
for it in items:
    tool = ToolDefinitionData(name=it["tool"][:256] or "t", description=it["description"], input_schema=it.get("schema") or {"type": "object"})
    sib = [ToolDefinitionData(name=n[:256]) for n in it.get("server_tools", []) if n and n != it["tool"]]
    try: f = analyze_tool(tool, server_name="s", sibling_tools=sib)
    except Exception as e: f = []
    out.append(sorted({str(x.severity.value if hasattr(x.severity, "value") else x.severity) for x in f}))
json.dump(out, open(sys.argv[2], "w"))
