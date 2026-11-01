"""E9: live fleet run of the actual ReputationStore. N agents, each with its own gateway and its own
server process (files server, 3 tools), no manifest (L3 off: soft L4 evidence only), short burn-in.
One tool is compromised (low-and-slow credential read, trigger rho). Policies differ only in whether
agents share one ReputationStore (fleet) or each keep their own (isolated)."""
import asyncio, json, os, sys, random, collections
from contextlib import AsyncExitStack
sys.path.insert(0, "."); sys.path.insert(0, "experiments")
from tpdetect.gateway import GuardedSession, BehaviourProfile
from tpdetect.reputation import ReputationStore
import e3_runtime as E

async def run(N, policy, rho, rounds, B, seed):
    prof = BehaviourProfile()
    async with GuardedSession("files", f"{E.TB}/files_server.py", E.M["files"], profile=prof, layers=()) as g:
        await g.list_tools()
        for t in E.SERVERS["files"]:
            for _ in range(B): await g.call_tool(t, E.args_for(t, E.rng), learn=True)
    shared = ReputationStore(eps=0.01, k=3.0, delta=1e-3)
    truth = f"/tmp/tpd_truth_fleet.log"; open(truth, "w").close()
    exposure = 0; first_q = None; false_q = set(); calls = 0; benign_alerts = 0; trig_alerts = 0
    async with AsyncExitStack() as st:
        agents = []
        for a in range(N):
            rep = shared if policy == "fleet" else ReputationStore(eps=0.01, k=3.0, delta=1e-3)
            g = await st.enter_async_context(GuardedSession("files", f"{E.TB}/files_server.py", None, profile=prof,
                       layers=("L4", "L5"), reputation=rep, sandbox=True, enforce=False,
                       env={"TPD_SERVER": "files", "TPD_ATTACK": "lowslow", "TPD_TARGET_TOOL": "read_file",
                            "TPD_TRIGGER": str(rho), "TPD_SEED": str(seed * 100 + a), "TPD_TRUTH": truth}))
            await g.list_tools(); agents.append((g, rep))
        r = random.Random(seed)
        for rd in range(rounds):
            for a, (g, rep) in enumerate(agents):
                t = r.choice(E.SERVERS["files"])
                before = sum(1 for _ in open(truth))
                _, v = await g.call_tool(t, E.args_for(t, r)); calls += 1
                fired = sum(1 for _ in open(truth)) > before
                if fired: exposure += 1; trig_alerts += bool(v["alerts"])
                elif not v["blocked"]: benign_alerts += bool(v["alerts"])
                for q in rep.quarantined:
                    if q.endswith("/read_file"):
                        if first_q is None: first_q = rd
                    else: false_q.add((id(rep), q))
    return dict(N=N, policy=policy, rho=rho, rounds=rounds, calls=calls, exposure=exposure, first_quarantine_round=first_q,
                false_quarantines=len(false_q), benign_alerts=benign_alerts, triggered_alerts=trig_alerts)

async def main():
    E.setup_fs(); E.Sink(); out = []
    for N in [5, 20]:
        for policy in ["isolated", "fleet"]:
            res = await run(N, policy, rho=0.2, rounds=60, B=10, seed=11)
            out.append(res); print(res, flush=True)
    json.dump(out, open("results/e9.json", "w"), indent=1)
asyncio.run(main())
