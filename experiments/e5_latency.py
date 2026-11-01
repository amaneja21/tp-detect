"""E5: end-to-end latency overhead of TP-Detect on real MCP stdio calls."""
import asyncio, json, sys, time, os, random, numpy as np, threading, socket
sys.path.insert(0, ".")
from tpdetect.gateway import GuardedSession, BehaviourProfile
from tpdetect.reputation import ReputationStore
from tpdetect.l2 import LearnedL2, L2Scorer
sys.path.insert(0, "experiments")
from e3_runtime import args_for, setup_fs, Sink, TB, M
D = json.load(open("data/mcptox_desc.json")) + json.load(open("data/wild_benign.json"))
scorer = L2Scorer(LearnedL2().fit(D))
TOOLS = {"calc": "describe", "notes": "add_note", "web": "fetch_doc", "files": "search_files"}
N = 300

async def measure(server, tool, config):
    r = random.Random(1); lat = []
    sandbox = config != "raw"
    layers = ("L1", "L2", "L3", "L4", "L5") if config == "full" else ()
    prof = BehaviourProfile()
    async with GuardedSession(server, f"{TB}/{server}_server.py", M[server], scorer=scorer, layers=layers,
                              reputation=ReputationStore() if config == "full" else None, profile=prof,
                              enforce=(config == "full"), sandbox=sandbox) as g:
        t0 = time.perf_counter(); await g.list_tools(); tl = time.perf_counter() - t0
        for _ in range(10): await g.call_tool(tool, args_for(tool, r), learn=True)
        for _ in range(N):
            a = args_for(tool, r); t0 = time.perf_counter()
            if config == "full": await g.call_tool(tool, a)
            else: await g.s.call_tool(tool, a)
            lat.append((time.perf_counter() - t0) * 1000)
    return np.array(lat), tl * 1000

async def main():
    setup_fs(); Sink(); out = {}
    for server, tool in TOOLS.items():
        for config in ["raw", "sandbox", "full"]:
            lat, tl = await measure(server, tool, config)
            out[f"{server}/{config}"] = dict(p50=float(np.percentile(lat, 50)), p90=float(np.percentile(lat, 90)),
                                             p99=float(np.percentile(lat, 99)), mean=float(lat.mean()), list_tools_ms=tl, n=N)
            print(server, config, {k: round(v, 2) for k, v in out[f"{server}/{config}"].items()}, flush=True)
    # per-component cost of L2 scoring (one description / one response)
    recs = [D[i] for i in range(0, len(D), 7)]
    t0 = time.perf_counter()
    for rc in recs: scorer(rc)
    out["l2_score_ms_per_item"] = (time.perf_counter() - t0) * 1000 / len(recs)
    json.dump(out, open("results/e5.json", "w"), indent=1)
    print(out["l2_score_ms_per_item"])
asyncio.run(main())
