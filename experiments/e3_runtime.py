"""E3: runtime attacks executed for real through the TP-Detect gateway.
Five Python MCP servers (13 tools) run under the audit-hook sandbox. Attack variants change
nothing visible to static checks (same descriptions, same tool code): a compromised backend
(endpoint), a poisoned helper dependency, a low-and-slow credential read, and response
poisoning. Ground truth = trigger log written by the attack shim. Attacker sink = TCP :9999."""
import zlib, asyncio, json, os, sys, random, socket, threading, time, shutil, collections, itertools
sys.path.insert(0, ".")
from tpdetect.gateway import GuardedSession, BehaviourProfile
from tpdetect.reputation import ReputationStore
from tpdetect.l2 import LearnedL2, L2Scorer
_D = json.load(open("data/mcptox_desc.json")) + json.load(open("data/wild_benign.json"))
SCORER = L2Scorer(LearnedL2().fit(_D))

TB = os.path.abspath("testbed"); M = json.load(open(f"{TB}/manifests.json"))
SERVERS = {"notes": ["add_note", "list_notes", "read_note"], "files": ["read_file", "search_files", "file_stats"],
           "web": ["fetch_doc", "get_price"], "calc": ["add", "describe", "convert"], "mail": ["send_email", "list_inbox"]}
ROOT = "/tmp/tpd"
rng = random.Random(42)

def setup_fs():
    shutil.rmtree(ROOT, ignore_errors=True)
    for d in ["home/.ssh", "home/.aws", "workspace/src", "workspace/docs", "notes", "inbox", "outbox"]:
        os.makedirs(f"{ROOT}/{d}", exist_ok=True)
    open(f"{ROOT}/home/.ssh/id_rsa", "w").write("-----BEGIN KEY----- canary")
    open(f"{ROOT}/home/.aws/credentials", "w").write("aws_secret_access_key=canary")
    open(f"{ROOT}/home/.env", "w").write("API_TOKEN=canary")
    for i in range(12):
        open(f"{ROOT}/workspace/{'src' if i % 2 else 'docs'}/file{i}.{'py' if i % 2 else 'md'}", "w").write("line\n" * (i + 3))
    for i in range(5): json.dump({"s": f"subject {i}", "b": "hi"}, open(f"{ROOT}/inbox/{i}.json", "w"))

def args_for(tool, r):
    w = ["alpha", "beta", "gamma", "delta", "omega", "plan", "todo"]
    return {"add_note": {"title": r.choice(w) + str(r.randint(0, 9)), "body": "text " * r.randint(1, 20)},
            "list_notes": {}, "read_note": {"title": r.choice(w) + str(r.randint(0, 9))},
            "read_file": {"path": f"{r.choice(['src', 'docs'])}/file{r.randint(0, 11)}.{r.choice(['py', 'md'])}"},
            "search_files": {"pattern": r.choice(["*.py", "*.md", "file1*", "*"])},
            "file_stats": {"path": f"src/file{r.randrange(1, 12, 2)}.py"},
            "fetch_doc": {"page": r.choice(["intro", "api", "faq", "install"])}, "get_price": {"sku": f"SKU-{r.randint(100, 999)}"},
            "add": {"a": r.random() * 100, "b": r.random() * 100}, "describe": {"values": [r.random() for _ in range(r.randint(2, 9))]},
            "convert": {"value": r.random() * 50, "unit": r.choice(["km", "mi", "kg", "lb", "C", "F"])},
            "send_email": {"to": r.choice(["ana@corp.example", "li@corp.example"]), "subject": "s", "body": "b"},
            "list_inbox": {}}[tool]

class Sink:
    """Tiny TCP servers: two benign HTTP endpoints and the attacker's exfiltration sink."""
    def __init__(self):
        self.exfil_bytes = 0; self.socks = []
        for port, kind in [(8801, "http"), (8802, "http"), (9999, "sink")]:
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(64)
            self.socks.append(s); threading.Thread(target=self.loop, args=(s, kind), daemon=True).start()
    def loop(self, s, kind):
        while True:
            try: c, _ = s.accept()
            except OSError: return
            try:
                c.settimeout(0.2); d = c.recv(4096)
                if kind == "sink": self.exfil_bytes += len(d)
                else: c.sendall(b"HTTP/1.0 200 OK\r\n\r\n{\"ok\": true, \"page\": \"content\"}")
            except OSError: pass
            finally: c.close()

async def burn_in(server, B, profile):
    async with GuardedSession(server, f"{TB}/{server}_server.py", M[server], profile=profile, enforce=False) as g:
        await g.list_tools()
        for tool in SERVERS[server]:
            for _ in range(B): await g.call_tool(tool, args_for(tool, rng), learn=True)

async def episode(server, attack, target, profile, enforce, layers, calls_per_tool, trigger, seed, sink):
    truth = f"/tmp/tpd_truth_{os.getpid()}.log"
    open(truth, "w").close()
    env = {"TPD_SERVER": server, "TPD_ATTACK": attack, "TPD_TRIGGER": str(trigger), "TPD_TARGET_TOOL": target, "TPD_SEED": str(seed), "TPD_TRUTH": truth}
    rows = []
    b0 = sink.exfil_bytes
    async with GuardedSession(server, f"{TB}/{server}_server.py", M[server], profile=profile, enforce=enforce,
                              layers=layers, reputation=None, env=env, scorer=SCORER) as g:
        await g.list_tools()
        seq = [t for t in SERVERS[server] for _ in range(calls_per_tool)]; random.Random(seed).shuffle(seq)
        for tool in seq:
            before = sum(1 for _ in open(truth))
            _, v = await g.call_tool(tool, args_for(tool, rng))
            fired = sum(1 for _ in open(truth)) > before
            rows.append(dict(tool=tool, fired=fired, alert=bool(v["alerts"]), hard=v["hard"], blocked=v["blocked"],
                             kinds=sorted({a[0] for a in v["alerts"]})))
        timing = list(g.timing)
    return rows, sink.exfil_bytes - b0, timing

async def main():
    setup_fs(); sink = Sink()
    out = {"burnin": {}, "attacks": [], "clean": []}
    LAYER_SETS = {"L3 only": ("L3",), "L4 only": ("L4",), "L2-resp only": ("L2",), "L2+L3+L4": ("L2", "L3", "L4")}
    # burn-in sensitivity: false alerts on clean traffic vs burn-in length
    for B in [1, 2, 5, 10]:
        prof = BehaviourProfile(); fa = 0; n = 0
        for srv in SERVERS: await burn_in(srv, B, prof)
        for srv in SERVERS:
            rows, _, _ = await episode(srv, "none", "*", prof, False, ("L2", "L3", "L4"), 15, 0.0, 100 + B, sink)
            fa += sum(r["alert"] for r in rows); n += len(rows)
        out["burnin"][B] = dict(false_alert_rate=fa / n, calls=n)
        print("burn-in", B, fa / n, flush=True)
    prof = BehaviourProfile()
    for srv in SERVERS: await burn_in(srv, 10, prof)
    for srv in SERVERS:  # clean traffic, all layers, enforcement on
        rows, xb, tm = await episode(srv, "none", "*", prof, True, ("L2", "L3", "L4"), 30, 0.0, 7, sink)
        out["clean"].append(dict(server=srv, calls=len(rows), alerts=sum(r["alert"] for r in rows), blocked=sum(r["blocked"] for r in rows)))
    for attack in ["endpoint", "dependency", "lowslow", "output"]:
        for srv, tools in SERVERS.items():
            for tool in tools:
                for lname, layers in LAYER_SETS.items():
                    for enforce in ([False, True] if lname == "L2+L3+L4" else [False]):
                        rows, xb, tm = await episode(srv, attack, tool, prof, enforce, layers, 12, 0.3, zlib.crc32(f"{srv}|{tool}|{attack}".encode()) % 1000, sink)
                        fired = [r for r in rows if r["fired"]]; clean = [r for r in rows if not r["fired"]]
                        out["attacks"].append(dict(attack=attack, server=srv, tool=tool, layers=lname, enforce=enforce,
                            fired=len(fired), detected=sum(r["alert"] for r in fired), blocked=sum(r["blocked"] for r in fired),
                            benign_calls=len(clean), benign_alerts=sum(r["alert"] for r in clean), exfil_bytes=xb))
        print("done", attack, flush=True)
    json.dump(out, open("results/e3.json", "w"), indent=1)

async def main_inmanifest():
    setup_fs(); sink = Sink(); out = []
    prof = BehaviourProfile()
    for srv in SERVERS: await burn_in(srv, 10, prof)
    for srv in ["mail", "notes", "web", "files"]:
        for tool in SERVERS[srv]:
            for enforce in [False, True]:
                rows, xb, tm = await episode(srv, "inmanifest", tool, prof, enforce, ("L2", "L3", "L4"), 12, 0.3, zlib.crc32(f"{srv}|{tool}".encode()) % 1000, sink)
                fired = [r for r in rows if r["fired"]]
                out.append(dict(server=srv, tool=tool, enforce=enforce, fired=len(fired), detected=sum(r["alert"] for r in fired),
                                kinds=sorted({k for r in fired for k in r["kinds"]})))
    json.dump(out, open("results/e3_inmanifest.json", "w"), indent=1)
    print(sum(o["fired"] for o in out), sum(o["detected"] for o in out), {(o["server"], o["tool"]): o["kinds"] for o in out if o["detected"]})

if __name__ == "__main__":
    asyncio.run(main_inmanifest() if "--inmanifest" in sys.argv else main())
