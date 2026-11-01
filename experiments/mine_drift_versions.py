"""Real benign description updates from consecutive released versions of live MCP servers
(tools/list of each version), combined with the git-history pairs from the reference servers."""
import json, sys, collections
from packaging.version import Version, InvalidVersion
V = json.load(open(sys.argv[1])); git = json.load(open(sys.argv[2])); out = sys.argv[3]
by = collections.defaultdict(list)
for k, v in V.items():
    if v["ok"] and v["tools"]: by[v["pkg"]].append(v)
def key(v):
    try: return Version(v["ver"])
    except InvalidVersion: return Version("0")
pairs = []
for pkg, vs in by.items():
    vs.sort(key=key)
    for a, b in zip(vs, vs[1:]):
        da = {t["name"]: t["description"] for t in a["tools"]}; db = {t["name"]: t["description"] for t in b["tools"]}
        names = sorted(db)
        for n in names:
            if n in da and da[n] and db[n] and da[n].strip() != db[n].strip():
                pairs.append(dict(server="pkg:" + pkg, tool=n, old=da[n], new=db[n], from_ver=a["ver"], to_ver=b["ver"], server_tools=names, source="releases"))
uniq = {(p["server"], p["tool"], p["old"], p["new"]): p for p in pairs}
for p in git: p.setdefault("source", "git")
allp = list(uniq.values()) + git
json.dump(allp, open(out, "w"), indent=0)
print("release pairs", len(uniq), "from", len({p['server'] for p in uniq.values()}), "packages; git pairs", len(git), "total", len(allp))
