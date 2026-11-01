"""Mine real benign tool-description updates from the git history of
modelcontextprotocol/servers (every commit touching a server source file)."""
import subprocess, re, json, sys, collections
repo = sys.argv[1]; out = sys.argv[2]
def git(*a): return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True).stdout
STR = r'(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`)'
CAT = rf'({STR}(?:\s*\+\s*{STR})*)'
P1 = re.compile(rf'name:\s*["\']([\w-]+)["\']\s*,\s*(?:title:\s*{STR}\s*,\s*)?description:\s*{CAT}', re.S)
P3 = re.compile(rf'\.tool\(\s*["\']([\w-]+)["\']\s*,\s*{CAT}', re.S)
P2 = re.compile(rf'registerTool\(\s*["\']([\w-]+)["\']\s*,\s*\{{[^{{}}]*?description:\s*{CAT}', re.S)
def lit(s):
    parts = re.findall(STR, s)
    return "".join(p[1:-1] for p in parts).replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'")
files = [l for l in git("log", "--all", "--name-only", "--pretty=format:").splitlines()
         if l.startswith("src/") and l.endswith((".ts",".js")) and "__tests__" not in l and ".test." not in l]
files = sorted(set(files))
hist = collections.defaultdict(list)   # (server, tool) -> [(date, commit, desc)]
for f in files:
    server = f.split("/")[1]
    log = git("log", "--all", "--pretty=format:%H %ct", "--", f).splitlines()
    for line in reversed(log):
        h, ts = line.split()
        src = git("show", f"{h}:{f}")
        if not src: continue
        for m in list(P1.finditer(src)) + list(P2.finditer(src)) + list(P3.finditer(src)):
            d = lit(m.group(2)).strip()
            if len(d) < 15: continue
            hist[(server, m.group(1))].append((int(ts), h, d))
pairs = []
for (srv, tool), seq in hist.items():
    seq.sort()
    prev = None
    for ts, h, d in seq:
        if prev is not None and d != prev:
            pairs.append(dict(server=srv, tool=tool, old=prev, new=d, commit=h, ts=ts))
        prev = d
# dedupe identical (old,new)
uniq = {(p["server"], p["tool"], p["old"], p["new"]): p for p in pairs}
pairs = list(uniq.values())
tools_by_server = collections.defaultdict(set)
for (s, t) in hist: tools_by_server[s].add(t)
for p in pairs: p["server_tools"] = sorted(tools_by_server[p["server"]])
json.dump(pairs, open(out, "w"), indent=0)
print("tools tracked", len(hist), "benign update pairs", len(pairs), "servers", len({p['server'] for p in pairs}))
