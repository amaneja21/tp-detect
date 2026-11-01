"""Build the description-level dataset from the public MCPTox benchmark.
Benign: clean tool descriptions of the 45 real MCP servers.
Malicious: unique poisoned tool descriptions (all paradigms / enhancement settings),
with per-model attack-success labels from MCPTox's published agent responses."""
import json, re, sys, collections
src = sys.argv[1]; out = sys.argv[2]
r = json.load(open(f"{src}/response_all.json"))
pure = json.load(open(f"{src}/pure_tool.json"))
meta = {}
for d in pure:
    for k, v in d.items():
        meta[(v['server_name'], v['tool_name'])] = v

BLOCK = re.compile(r"Tool:\s*(\S+)\s*\nDescription:(.*?)(?:\nArguments:(.*?))?(?=\n\s*\n\s*Tool:|\Z)", re.S)
def parse_tools(text):
    tools = []
    for m in BLOCK.finditer(text):
        name, desc, args = m.group(1), m.group(2).strip(), (m.group(3) or "").strip()
        argn = [a.split(':')[0].strip('- ').strip() for a in args.splitlines() if a.strip().startswith('-')]
        tools.append({"name": name, "description": desc, "args": argn})
    return tools

rows = []
for sname, s in r['servers'].items():
    prompt = s['clean_system_promot']
    body = prompt.split("access to these tools:", 1)[-1]
    body = body.split("\n\nChoose the appropriate tool")[0]
    tools = parse_tools(body)
    names = set(s['tool_names'])
    tools = [t for t in tools if t['name'] in names]
    for t in tools:
        rows.append(dict(server=sname, tool=t['name'], description=t['description'], args=t['args'],
                         label=0, paradigm=None, risk=None, success_any=None, success_rate=None, server_tools=sorted(names)))
    seen = {}
    for mi in s['malicious_instance']:
        for d in mi['datas']:
            pt = d.get('poisoned_tool') or mi.get('poisoned_tool')
            if not pt: continue
            ts = parse_tools(pt.replace("\\n", "\n").strip())
            if not ts: continue
            t = ts[0]
            key = t['description']
            labs = d.get('label') or {}
            succ = [v == 'Success' for v in labs.values() if v not in (None, 'None')]
            e = seen.setdefault(key, dict(server=sname, tool=t['name'], description=key, args=t['args'], label=1,
                                          n_eval=0, n_succ=0, server_tools=sorted(names)))
            e['n_eval'] += len(succ); e['n_succ'] += sum(succ)
            m = meta.get((sname, t['name']))
            if m: e['paradigm'] = m['paradigm']; e['risk'] = m['security risk']
    for e in seen.values():
        e['success_any'] = e['n_succ'] > 0
        e['success_rate'] = e['n_succ'] / e['n_eval'] if e['n_eval'] else None
        rows.append(e)
json.dump(rows, open(out, 'w'), indent=0)
c = collections.Counter(x['label'] for x in rows)
print("rows", len(rows), c, "servers", len({x['server'] for x in rows}))
mal = [x for x in rows if x['label']]
print("paradigm", collections.Counter(x.get('paradigm') for x in mal))
print("success_any", sum(1 for x in mal if x['success_any']), "of", len(mal))
print("benign per server min/max", min(collections.Counter(x['server'] for x in rows if not x['label']).values()), max(collections.Counter(x['server'] for x in rows if not x['label']).values()))
