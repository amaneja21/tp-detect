"""E4: fleet-wide reputation (Layer 5) vs. isolated detection, trace-driven simulation.
Setting: no capability manifest is available (common in practice), so runtime evidence is
soft: an L4 novelty alert that also fires on benign calls at rate eps (measured in E3 for short
burn-in). One tool out of T is compromised with a low trigger rate rho (low-and-slow).
Policies, all using the same Beta quarantine rule (ReputationStore semantics):
  per-session : evidence kept per (agent, tool) and reset every S calls (session-scoped tools)
  per-agent   : evidence kept per (agent, tool) for the whole horizon
  fleet       : evidence pooled per tool across all agents (TP-Detect L5)
Metrics: malicious executions before quarantine (fleet total), rounds until quarantine,
and benign tools wrongly quarantined."""
import json, sys, numpy as np
from scipy.stats import beta as Beta
sys.path.insert(0, ".")

def threshold_table(eps, k, delta, prior_n, nmax):
    a0, b0 = eps * prior_n, (1 - eps) * prior_n
    tab = np.full(nmax + 1, np.iinfo(np.int32).max)
    a = 0
    for n in range(nmax + 1):
        while a <= n and 1 - Beta.cdf(min(0.999, k * eps), a0 + a, b0 + n - a) < 1 - delta: a += 1
        if a <= n: tab[n] = a
    return tab

def simulate(N, policy, eps, rho, d=1.0, T=50, H=2000, S=50, k=3.0, delta=1e-3, prior_n=20, min_obs=5, seed=0, tab=None):
    rng = np.random.default_rng(seed)
    c = 0
    shape = (T,) if policy == "fleet" else (N, T)
    A = np.zeros(shape, np.int32); n = np.zeros(shape, np.int32)
    quar = np.zeros(shape, bool)
    exposure = 0; t_q = None; falseq = set()
    for r in range(H):
        if policy == "per-session" and r % S == 0 and r > 0:
            A[:] = 0; n[:] = 0; quar[:] = False
        tools = rng.integers(0, T, N)
        idx = (tools,) if policy == "fleet" else (np.arange(N), tools)
        blocked = quar[idx]
        trig = (tools == c) & (rng.random(N) < rho) & ~blocked
        exposure += int(trig.sum())
        alert = np.where(trig, rng.random(N) < d, rng.random(N) < eps) & ~blocked
        if policy == "fleet":
            np.add.at(A, tools[~blocked], alert[~blocked].astype(np.int32)); np.add.at(n, tools[~blocked], 1)
        else:
            m = ~blocked; A[np.arange(N)[m], tools[m]] += alert[m]; n[np.arange(N)[m], tools[m]] += 1
        nn = np.minimum(n, len(tab) - 1)
        newq = (n >= min_obs) & (A >= tab[nn]) & ~quar
        if newq.any():
            quar |= newq
            if policy == "fleet":
                for t in np.where(newq)[0]:
                    if t == c and t_q is None: t_q = r
                    if t != c: falseq.add(int(t))
            else:
                for a_, t in zip(*np.where(newq)):
                    if t == c and t_q is None: t_q = r
                    if t != c: falseq.add((int(a_), int(t)))
    calls = N * H
    return dict(exposure=exposure, rounds_to_quarantine=t_q, false_quarantines=len(falseq),
                false_q_per_100k_calls=len(falseq) / calls * 1e5, calls=calls)

if __name__ == "__main__":
    out = []
    H = 2000
    for eps in [0.01, 0.03]:
        tab = threshold_table(eps, 3.0, 1e-3, 20, 20000)
        for rho in [0.01, 0.03, 0.1]:
            for N in [1, 10, 50, 100, 400]:
                for pol in ["per-session", "per-agent", "fleet"]:
                    reps = [simulate(N, pol, eps, rho, H=H, seed=s, tab=tab) for s in range(5)]
                    ex = [x["exposure"] for x in reps]; tq = [x["rounds_to_quarantine"] if x["rounds_to_quarantine"] is not None else H for x in reps]
                    out.append(dict(eps=eps, rho=rho, N=N, policy=pol, exposure_mean=float(np.mean(ex)), exposure_sd=float(np.std(ex)),
                                    rounds_to_q_median=float(np.median(tq)), quarantined_runs=sum(x["rounds_to_quarantine"] is not None for x in reps),
                                    false_q_mean=float(np.mean([x["false_quarantines"] for x in reps])),
                                    false_q_per_100k=float(np.mean([x["false_q_per_100k_calls"] for x in reps]))))
                    print(out[-1], flush=True)
    json.dump(out, open("results/e4.json", "w"), indent=1)
