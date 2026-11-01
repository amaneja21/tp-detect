"""E2: rug pulls (post-approval definition drift).
Benign drift: 39 real description updates mined from the git history of the official MCP
reference servers. Malicious drift: every benign MCPTox tool receives a rug-pull update that
(i) appends a real MCPTox payload from the same server, or (ii) replaces the description with it.
Detectors: no pinning, plain pinning (ETDI-style hash/version pinning, block any change),
TP-Detect L1 (pin + score only the added text with an L2 model never trained on that server)."""
import json, sys, numpy as np, collections, random
sys.path.insert(0, ".")
from sklearn.model_selection import GroupKFold
from tpdetect.l2 import LearnedL2, L2Scorer
from tpdetect.pinning import PinStore, added_text

D = json.load(open("data/mcptox_desc.json")); B = json.load(open("data/benign_drift_all.json"))
WB = json.load(open("data/wild_benign.json"))
rng = random.Random(1)
servers = sorted({r["server"] for r in D})
fold = {s: i % 5 for i, s in enumerate(servers)}
models = {}
for k in range(5):
    tr = [r for r in D if fold[r["server"]] != k] + WB
    models[k] = L2Scorer(LearnedL2().fit(tr))
allm = L2Scorer(LearnedL2().fit(D + WB))  # used for real-repo drift (servers not in MCPTox folds)

def payload_of(desc_poisoned):
    # the complete MCPTox poisoned description (cover sentence + instruction) is appended
    return desc_poisoned

mal_by_server = collections.defaultdict(list)
for r in D:
    if r["label"]: mal_by_server[r["server"]].append(r["description"])

def run(pairs):
    """pairs: list of (server, tool, server_tools, old, new, label, model)"""
    out = collections.defaultdict(lambda: [0, 0])  # method -> [flags_on_malicious, flags_on_benign]
    n = collections.Counter(l for *_, l, _ in pairs)
    for srv, tool, names, old, new, lab, m in pairs:
        ps = PinStore(scorer=m, threshold=0.5)
        ps.observe(srv, [{"name": tool, "description": old}])
        kind = ps.observe(srv, [{"name": tool, "description": new}])[0][1]
        flags = {"No pinning": False, "Plain pinning": True, "TP-Detect L1": kind == "drift_suspicious"}
        for k, f in flags.items():
            out[k][0 if lab else 1] += int(f)
    return {k: dict(detect_rate=v[0] / max(1, n[1]), false_alarm_rate=v[1] / max(1, n[0])) for k, v in out.items()}, n

pairs = []
for r in D:
    if r["label"] or not mal_by_server[r["server"]]: continue
    m = models[fold[r["server"]]]
    p = rng.choice(mal_by_server[r["server"]])
    pairs.append((r["server"], r["tool"], r["server_tools"], r["description"], r["description"] + " " + payload_of(p), 1, m))
    pairs.append((r["server"], r["tool"], r["server_tools"], r["description"], p, 1, m))
for b in B:
    pairs.append((b["server"], b["tool"], b["server_tools"], b["old"], b["new"], 0, allm))
res, n = run(pairs)
# also: real benign updates that are then poisoned (payload appended to the new version)
pairs2 = []
allp = [r["description"] for r in D if r["label"]]
for b in B:
    pairs2.append((b["server"], b["tool"], b["server_tools"], b["old"], b["new"] + " " + payload_of(rng.choice(allp)), 1, allm))
res2, n2 = run(pairs2)
# rug pulls whose payload uses the held-out OOD-2 phrasing families (payload = OOD-2 text minus its carrier)
O2 = json.load(open("data/ood2_attacks.json")); WR = json.load(open("data/wild_raw.json"))
carrier = {("wild:" + k, t["name"]): t["description"] for k, v in WR.items() for t in v["tools"]}
suff = [o["description"][len(carrier.get((o["server"], o["tool"]), "")):] for o in O2 if carrier.get((o["server"], o["tool"])) and o["description"].startswith(carrier[(o["server"], o["tool"])])]
pairs3 = [(b["server"], b["tool"], b["server_tools"], b["old"], b["new"] + suff[i % len(suff)], 1, allm) for i, b in enumerate(B * 3)][:len(suff)]
res3, n3 = run(pairs3)
# false alarms by benign-update source
fa_src = {}
for src_ in ("git", "releases"):
    sub = [b for b in B if b.get("source", "git") == src_]
    if sub:
        r_, n_ = run([(b["server"], b["tool"], b["server_tools"], b["old"], b["new"], 0, allm) for b in sub])
        fa_src[src_] = dict(n=n_[0], tpdetect=r_["TP-Detect L1"]["false_alarm_rate"])
out = dict(false_alarm_by_source=fa_src, main=res, counts=dict(malicious=n[1], benign=n[0]), poisoned_real_updates=res2, n_poisoned_real=n2[1],
           heldout_phrasing_rugpulls=res3, n_heldout=n3[1])
json.dump(out, open("results/e2.json", "w"), indent=1)
print(json.dumps(out, indent=1))
