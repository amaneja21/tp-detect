import json, ast, glob, importlib, pkgutil
out = []
import guardbench.mcp_lab.servers as S
for m in pkgutil.iter_modules(S.__path__):
    mod = importlib.import_module(f"guardbench.mcp_lab.servers.{m.name}")
    for name, obj in vars(mod).items():
        if isinstance(obj, type) and getattr(obj, "tool_definitions", None) and obj.__module__ == mod.__name__:
            try: fx = obj()
            except Exception: continue
            tools = fx.tool_definitions(); names = [t.name for t in tools]
            pois = set(getattr(obj, "poisoned_tools", frozenset()))
            for t in tools:
                out.append(dict(src="guardbench", server=m.name, tool=t.name, description=t.description or "", server_tools=names,
                                label=int(t.name in pois), schema=t.input_schema))
for f in glob.glob("MCPSecBench/code/*.py"):
    tree = ast.parse(open(f).read())
    fns = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any("tool" in ast.unparse(d) for d in n.decorator_list)]
    names = [n.name for n in fns]
    for n in fns:
        out.append(dict(src="mcpsecbench", server=f.split("/")[-1], tool=n.name, description=ast.get_docstring(n) or "", server_tools=names, label=None))
json.dump(out, open("/tmp/tp_corpus_raw.json", "w"), indent=1)
for o in out: print(o["src"], o["server"], o["tool"], o["label"], "|", (o["description"] or "")[:150].replace("\n", " "))
