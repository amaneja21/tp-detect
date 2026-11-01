"""E1 (final): description-level detection under one protocol.
Pool = MCPTox (353 benign + 1338 poisoned, 45 servers) + live third-party benign tools.
5-fold GroupKFold by server. Learned models see only training-fold servers.
OOD-1 (dev, used during v2 design) and OOD-2 (fresh, written after v2 was frozen) are scored by
the fold model whose held-out servers include the carrier's server."""
import json, sys, hashlib, numpy as np, collections
sys.path.insert(0, ".")
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from tpdetect.models import TextLR
from tpdetect.descriptor import rule_features, rule_score, RULE_NAMES
from tpdetect.descriptor_v2 import v2_features, v2_score, V2_NAMES

D = json.load(open("data/mcptox_desc.json")); W = json.load(open("data/wild_benign.json"))
O1 = json.load(open("data/ood_attacks.json")); O2 = json.load(open("data/ood2_attacks.json"))
for r in D: r["src"] = "mcptox"
for r in W: r["src"] = "wild"
P = D + W; y = np.array([r["label"] for r in P]); g = np.array([r["server"] for r in P])
SEEN = set(json.load(open("data/seen_in_design_sha256.json"))["sha256"])
unseen = np.array([r["src"] == "mcptox" and r["label"] == 1 and hashlib.sha256(r["description"].encode()).hexdigest() not in SEEN for r in P])

def pattern(recs):
    out = []
    for r in recs:
        f = dict(zip(RULE_NAMES, rule_features(r["description"], r["tool"], r["server_tools"])))
        out.append(1.0 if (f["R2_override"] or f["R5_conceal"] or f["R8_hidden"] or f["R6_sensitive"] > 0) else 0.0)
    return np.array(out)

class L2:
    """TP-Detect Layer 2: v2 harm-directed features + TF-IDF text, logistic regression."""
    def __init__(self, scale=4.0): self.t = TextLR(); self.s = scale; self.m = LogisticRegression(C=2.0, max_iter=4000, class_weight="balanced")
    def X(self, recs, fit=False):
        Xt = self.t._X([r["description"] for r in recs], fit)
        F = np.vstack([v2_features(r["description"], r["tool"], r["server_tools"]) for r in recs]) * self.s
        return hstack([Xt, csr_matrix(F)]).tocsr()
    def fit(self, recs): self.m.fit(self.X(recs, True), [r["label"] for r in recs]); return self
    def predict(self, recs): return self.m.predict_proba(self.X(recs))[:, 1]

class TLR:
    def __init__(self): self.m = TextLR()
    def fit(self, recs): self.m.fit([r["description"] for r in recs], [r["label"] for r in recs]); return self
    def predict(self, recs): return self.m.predict_proba([r["description"] for r in recs])

class V2LR:
    def __init__(self): self.m = LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced")
    def F(self, recs): return np.vstack([v2_features(r["description"], r["tool"], r["server_tools"]) for r in recs])
    def fit(self, recs): self.m.fit(self.F(recs), [r["label"] for r in recs]); return self
    def predict(self, recs): return self.m.predict_proba(self.F(recs))[:, 1]

hand = lambda f: (lambda recs: np.array([f(r["description"], r["tool"], r["server_tools"]) for r in recs]))
METHODS = {  # name -> (kind, factory_or_fn, training data)
 "Pattern scanner (MCP-Scan-style)": ("fixed", pattern, None),
 "v1 surface rules (hand)":          ("fixed", hand(rule_score), None),
 "v2 harm-directed rules (hand)":    ("fixed", hand(v2_score), None),
 "Text-LR [MCPTox]":                 ("learn", TLR, "mcptox"),
 "Text-LR [MCPTox+wild]":            ("learn", TLR, "both"),
 "v2-LR [MCPTox+wild]":              ("learn", V2LR, "both"),
 "TP-Detect L2 [MCPTox+wild]":       ("learn", L2, "both"),
}
gkf = GroupKFold(n_splits=5)
folds = list(gkf.split(P, y, g))
server_fold = {}
for k, (_, te) in enumerate(folds):
    for i in te: server_fold[g[i]] = k

def summarize(s, idx_mask):
    return float((s[idx_mask] >= 0.5).mean()) if idx_mask.any() else float("nan")

res = {"counts": dict(mcptox_benign=int(sum(1 for r in D if not r["label"])), mcptox_poisoned=int(sum(r["label"] for r in D)),
                      mcptox_servers=len({r["server"] for r in D}), wild_benign=len(W), wild_servers=len({r["server"] for r in W}),
                      ood1=len(O1), ood2=len(O2), successful_attacks=int(sum(1 for r in D if r.get("success_any"))), unseen_in_design=int(unseen.sum()))}
src = np.array([r["src"] for r in P]); succ = np.array([bool(r.get("success_any")) for r in P])
par = np.array([r.get("paradigm") or "" for r in P])
SAVED = {}
METHODS["TP-Detect L2 ensemble (v2 rules OR learned)"] = ("ens", ["v2 harm-directed rules (hand)", "TP-Detect L2 [MCPTox+wild]"], None)
for name, (kind, M, train_on) in METHODS.items():
    s = np.zeros(len(P)); models = {}
    if kind == "ens":
        s = np.max([SAVED[n][0] for n in M], 0); s1 = np.max([SAVED[n][1] for n in M], 0); s2 = np.max([SAVED[n][2] for n in M], 0)
    elif kind == "fixed":
        s = M(P); s1 = M(O1); s2 = M(O2)
    else:
        for k, (tr, te) in enumerate(folds):
            trr = [P[i] for i in tr if train_on == "both" or P[i]["src"] == "mcptox"]
            models[k] = M().fit(trr); s[te] = models[k].predict([P[i] for i in te])
        def ood_scores(O):
            out = np.zeros(len(O))
            for k in models:
                idx = [i for i, r in enumerate(O) if server_fold.get(r["server"], -1) == k or (r["server"] not in server_fold and k == 0)]
                if idx: out[idx] = models[k].predict([O[i] for i in idx])
            return out
        s1 = ood_scores(O1); s2 = ood_scores(O2)
    SAVED[name] = (s, s1, s2)
    np.savez(f"results/e1_scores_{len(SAVED)}.npz", s=s, s1=s1, s2=s2, name=name)
    mal = (y == 1); mb = (src == "mcptox") & (y == 0); wb = (src == "wild")
    m = dict(mcptox_recall=summarize(s, mal), mcptox_fpr=summarize(s, mb), wild_fpr=summarize(s, wb),
             recall_successful=summarize(s, mal & succ),
             recall_T1=summarize(s, mal & (par == "Template-1")), recall_T2=summarize(s, mal & (par == "Template-2")),
             recall_T3=summarize(s, mal & (par == "Template-3")),
             auroc_mcptox=float(roc_auc_score(y[src == "mcptox"], s[src == "mcptox"])),
             ood1_recall=float((s1 >= 0.5).mean()), ood2_recall=float((s2 >= 0.5).mean()),
             recall_unseen_in_design=float((s[unseen] >= 0.5).mean()))
    # precision/F1 on the pooled benign+poisoned set
    tp = ((s >= 0.5) & (y == 1)).sum(); fp = ((s >= 0.5) & (y == 0)).sum(); fn = ((s < 0.5) & (y == 1)).sum()
    m["pooled_precision"] = float(tp / max(1, tp + fp)); m["pooled_f1"] = float(2 * tp / max(1, 2 * tp + fp + fn))
    # bootstrap over servers (pooled set) for wild FPR and MCPTox recall
    rng = np.random.default_rng(0); servers = sorted(set(g)); br, bw = [], []
    for _ in range(1000):
        pick = rng.choice(servers, len(servers)); idx = np.concatenate([np.where(g == sv)[0] for sv in pick])
        yy, ss, sr = y[idx], s[idx], src[idx]
        if (yy == 1).any(): br.append(((ss >= .5) & (yy == 1)).sum() / (yy == 1).sum())
        if (sr == "wild").any(): bw.append(((ss >= .5) & (sr == "wild")).sum() / (sr == "wild").sum())
    m["mcptox_recall_ci"] = [float(np.percentile(br, 2.5)), float(np.percentile(br, 97.5))]
    m["wild_fpr_ci"] = [float(np.percentile(bw, 2.5)), float(np.percentile(bw, 97.5))]
    for tag, O, so in [("ood1", O1, s1), ("ood2", O2, s2)]:
        bs = collections.defaultdict(list)
        for r, x in zip(O, so): bs[r["style"]].append(x >= 0.5)
        m[f"{tag}_by_style"] = {k: float(np.mean(v)) for k, v in bs.items()}
    res[name] = m
    print(f"{name:36s} MCPTox R={m['mcptox_recall']:.3f} FPR={m['mcptox_fpr']:.3f} | wild FPR={m['wild_fpr']:.3f} | succ R={m['recall_successful']:.3f} | OOD1={m['ood1_recall']:.3f} OOD2={m['ood2_recall']:.3f} | F1={m['pooled_f1']:.3f}")
json.dump(res, open("results/e1_final.json", "w"), indent=1)
print(json.dumps({k: v.get("ood2_by_style") for k, v in res.items() if k != "counts"}, indent=0))
