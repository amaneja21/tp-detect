import os
"""E8: runtime detection without hand-written manifests, and for a non-Python server.
(a) Python testbed: L3 manifests derived automatically from the burn-in profile (no author input),
    enforce mode, same attacks as E3.
(b) The official Node server @modelcontextprotocol/server-filesystem, unmodified, with a compromised
    dependency injected at require time (NODE_OPTIONS=--require), monitored through the strace backend."""
import asyncio, json, os, sys, random, zlib, collections
sys.path.insert(0, "."); sys.path.insert(0, "experiments")
from tpdetect.gateway import GuardedSession, BehaviourProfile, signature
import e3_runtime as E
NODE_FS = os.environ.get("NODE_FS_BIN", "mcp-server-filesystem")  # path to @modelcontextprotocol/server-filesystem binary

def auto_manifest(profile, server, tools):
    m = {"fs_read": [], "fs_write": [], "net": [], "exec": False}
    for t in tools:
        for sig in profile.sig.get(f"{server}/{t}", set()):
            k, x = sig.split(":", 1)
            if k in ("fs_read", "fs_write"):
                m[k].append(x if x.startswith("/") else f"/tmp/tpd/{x}")
            elif k == "net": m["net"].append(x)
            elif k == "exec": m["exec"] = True
    return {k: (sorted(set(v)) if isinstance(v, list) else v) for k, v in m.items()}

async def part_a(sink):
    prof = BehaviourProfile()
    for srv in E.SERVERS: await E.burn_in(srv, 10, prof)
    mans = {srv: auto_manifest(prof, srv, E.SERVERS[srv]) for srv in E.SERVERS}
    out = []
    for attack in ["endpoint", "dependency", "lowslow"]:
        for srv, tools in E.SERVERS.items():
            for tool in tools:
                E.M[srv] = mans[srv]
                rows, xb, _ = await E.episode(srv, attack, tool, prof, True, ("L3",), 12, 0.3,
                                              zlib.crc32(f"{srv}|{tool}|{attack}".encode()) % 1000, sink)
                fired = [r for r in rows if r["fired"]]; clean = [r for r in rows if not r["fired"]]
                out.append(dict(attack=attack, server=srv, tool=tool, fired=len(fired), detected=sum(r["alert"] for r in fired),
                                benign_calls=len(clean), benign_alerts=sum(r["alert"] for r in clean), exfil_bytes=xb))
    return out, mans

def node_args(tool, r):
    f = f"/tmp/tpd/workspace/{r.choice(['src', 'docs'])}/file{r.randint(0, 11)}.{r.choice(['py', 'md'])}"
    return {"read_text_file": {"path": f}, "read_file": {"path": f}, "list_directory": {"path": "/tmp/tpd/workspace/" + r.choice(["src", "docs"])},
            "get_file_info": {"path": f}, "search_files": {"path": "/tmp/tpd/workspace", "pattern": r.choice(["*.py", "*.md"])},
            "directory_tree": {"path": "/tmp/tpd/workspace/docs"}, "list_allowed_directories": {}}.get(tool)

async def part_b(sink):
    tools_used = ["read_text_file", "list_directory", "get_file_info", "search_files", "directory_tree", "list_allowed_directories"]
    prof = BehaviourProfile(); r = random.Random(5)
    base_env = {"NODE_OPTIONS": f"--require {os.path.abspath('testbed/node_compromise.js')}"}
    async with GuardedSession("nodefs", None, None, profile=prof, layers=("L4",), backend="strace", command=NODE_FS,
                              args=["/tmp/tpd/workspace"], env=dict(base_env, TPD_ATTACK="none")) as g:
        tl, _ = await g.list_tools(); names = {t["name"] for t in tl}
        tools_used = [t for t in tools_used if t in names]
        for t in tools_used:
            for _ in range(10): await g.call_tool(t, node_args(t, r), learn=True)
    man = auto_manifest(prof, "nodefs", tools_used)
    res = {"tools": tools_used, "manifest": man, "runs": {}}
    for attack in ["none", "endpoint", "lowslow"]:
        truth = "/tmp/tpd_truth_node.log"; open(truth, "w").close(); b0 = sink.exfil_bytes
        env = dict(base_env, TPD_ATTACK=attack, TPD_TRIGGER="0.3", TPD_SEED="7", TPD_TRUTH=truth)
        rows = []
        async with GuardedSession("nodefs", None, man, profile=prof, layers=("L3", "L4"), backend="strace", command=NODE_FS,
                                  args=["/tmp/tpd/workspace"], env=env, enforce=False) as g:
            await g.list_tools()
            seq = [t for t in tools_used for _ in range(15)]; random.Random(3).shuffle(seq)
            for t in seq:
                before = sum(1 for _ in open(truth))
                _, v = await g.call_tool(t, node_args(t, r))
                rows.append(dict(fired=sum(1 for _ in open(truth)) > before, alert=bool(v["alerts"]),
                                 kinds=sorted({a[0] for a in v["alerts"]})))
        fired = [x for x in rows if x["fired"]]; clean = [x for x in rows if not x["fired"]]
        res["runs"][attack] = dict(calls=len(rows), fired=len(fired), detected=sum(x["alert"] for x in fired),
                                   benign_alerts=sum(x["alert"] for x in clean), benign_calls=len(clean), exfil_bytes=sink.exfil_bytes - b0,
                                   kinds=dict(collections.Counter(k for x in fired for k in x["kinds"])))
        print("node", attack, res["runs"][attack], flush=True)
    return res

async def main():
    E.setup_fs(); sink = E.Sink()
    b = await part_b(sink)
    a, mans = await part_a(sink)
    agg = collections.defaultdict(collections.Counter)
    for x in a:
        for f in ["fired", "detected", "benign_calls", "benign_alerts", "exfil_bytes"]: agg[x["attack"]][f] += x[f]
    json.dump({"auto_manifest": {"per_attack": agg, "manifests": mans, "episodes": a}, "node": b}, open("results/e8.json", "w"), indent=1, default=dict)
    print({k: dict(v) for k, v in agg.items()}); print(json.dumps(mans, indent=0))
asyncio.run(main())
