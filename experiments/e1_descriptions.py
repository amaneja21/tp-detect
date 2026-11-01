"""E1: description-level poisoning detection.
Protocols: (a) leave-server-out 5-fold on MCPTox, (b) leave-paradigm-out, (c) false positives on
an independent corpus of live third-party MCP servers, (d) OOD attack styles, (e) recall on attacks
that actually succeeded against >=1 LLM agent in MCPTox's published runs."""
import json, sys, numpy as np, collections
sys.path.insert(0, ".")
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support
from tpdetect.models import TextLR, RulesLR, Combined
from tpdetect.descriptor import rule_features, rule_score, RULE_NAMES

D = json.load(open("data/mcptox_desc.json"))
W = json.load(open("data/wild_benign.json"))
O = json.load(open("data/ood_attacks.json"))
y = np.array([r["label"] for r in D]); g = np.array([r["server"] for r in D])

def pattern_baseline(recs):
    """Keyword/pattern scanner in the style of public MCP scanners: flags override tags,
    concealment phrases, hidden characters, or sensitive-file references."""
    out = []
    for r in recs:
        f = dict(zip(RULE_NAMES, rule_features(r["description"], r["tool"], r["server_tools"])))
        out.append(1.0 if (f["R2_override"] or f["R5_conceal"] or f["R8_hidden"] or f["R6_sensitive"] > 0) else 0.0)
    return np.array(out)

METHODS = {
 "Pattern scanner": ("rule", pattern_baseline),
 "Rules (hand-weighted)": ("rule", lambda recs: np.array([rule_score(r["description"], r["tool"], r["server_tools"]) for r in recs])),
 "Text-LR": ("text", TextLR),
 "Rules-LR": ("recs", RulesLR),
 "TP-Detect L2 (combined)": ("recs", Combined),
}
def fit_predict(kind, M, tr, te):
    if kind == "rule": return M(te)
    if kind == "text":
        m = M().fit([r["description"] for r in tr], [r["label"] for r in tr]); return m.predict_proba([r["description"] for r in te])
    m = M().fit(tr, [r["label"] for r in tr]); return m.predict_proba(te)

def metrics(yt, s, th=0.5):
    p, r, f, _ = precision_recall_fscore_support(yt, s >= th, average="binary", zero_division=0)
    fpr = float(((s >= th) & (yt == 0)).sum() / max(1, (yt == 0).sum()))
    auc = roc_auc_score(yt, s) if len(set(yt)) > 1 else float("nan")
    return dict(precision=p, recall=r, f1=f, fpr=fpr, auroc=auc)

res = {}
# (a) leave-server-out
gkf = GroupKFold(n_splits=5)
for name, (kind, M) in METHODS.items():
    s = np.zeros(len(D))
    for tr, te in gkf.split(D, y, g):
        s[te] = fit_predict(kind, M, [D[i] for i in tr], [D[i] for i in te])
    m = metrics(y, s)
    succ = np.array([bool(r.get("success_any")) for r in D])
    m["recall_on_successful_attacks"] = float((s[(y == 1) & succ] >= 0.5).mean())
    # bootstrap CI over servers for F1 and FPR
    servers = sorted(set(g)); rng = np.random.default_rng(0); bf, bp = [], []
    for _ in range(1000):
        pick = rng.choice(servers, len(servers)); idx = np.concatenate([np.where(g == sv)[0] for sv in pick])
        mm = metrics(y[idx], s[idx]); bf.append(mm["f1"]); bp.append(mm["fpr"])
    m["f1_ci"] = [float(np.percentile(bf, 2.5)), float(np.percentile(bf, 97.5))]
    m["fpr_ci"] = [float(np.percentile(bp, 2.5)), float(np.percentile(bp, 97.5))]
    per_par = {}
    for p in ["Template-1", "Template-2", "Template-3"]:
        idx = np.array([r.get("paradigm") == p for r in D]); per_par[p] = float((s[idx] >= 0.5).mean())
    m["recall_by_paradigm"] = per_par
    per_risk = collections.defaultdict(list)
    for r, sc in zip(D, s):
        if r["label"]: per_risk[r.get("risk") or "Other"].append(sc >= 0.5)
    m["recall_by_risk"] = {k: float(np.mean(v)) for k, v in per_risk.items()}
    res.setdefault("leave_server_out", {})[name] = m
    np.save(f"results/e1_scores_{name.split()[0]}.npy", s)
    print("LSO", name, {k: (round(v, 3) if isinstance(v, float) else v) for k, v in m.items() if k not in ("recall_by_risk",)})

# (b) leave-paradigm-out (also servers held out)
for name, (kind, M) in METHODS.items():
    out = {}
    for p in ["Template-1", "Template-2", "Template-3"]:
        scores, labels = [], []
        for tr, te in gkf.split(D, y, g):
            trr = [D[i] for i in tr if not (D[i]["label"] and D[i].get("paradigm") == p)]
            ter = [D[i] for i in te if (not D[i]["label"]) or D[i].get("paradigm") == p]
            scores.append(fit_predict(kind, M, trr, ter)); labels += [r["label"] for r in ter]
        s = np.concatenate(scores); out[p] = metrics(np.array(labels), s)
    res.setdefault("leave_paradigm_out", {})[name] = out
    print("LPO", name, {p: (round(v["recall"], 3), round(v["fpr"], 3)) for p, v in out.items()})

# (c)(d) train on all MCPTox, test on wild benign (FP) and OOD attacks (recall)
for name, (kind, M) in METHODS.items():
    sw = fit_predict(kind, M, D, W); so = fit_predict(kind, M, D, O)
    by_style = collections.defaultdict(list)
    for r, sc in zip(O, so): by_style[r["style"]].append(sc >= 0.5)
    res.setdefault("transfer", {})[name] = dict(wild_fpr=float((sw >= 0.5).mean()), wild_n=len(W),
        ood_recall=float((so >= 0.5).mean()), ood_n=len(O), ood_by_style={k: float(np.mean(v)) for k, v in by_style.items()},
        flagged_wild=[(W[i]["server"], W[i]["tool"], round(float(sw[i]), 3)) for i in np.argsort(-sw)[:8] if sw[i] >= 0.5])
    print("XFER", name, "wildFPR", round(float((sw >= 0.5).mean()), 3), "OOD recall", round(float((so >= 0.5).mean()), 3),
          {k: round(float(np.mean(v)), 2) for k, v in by_style.items()})

# rule weights learned on all data (interpretability)
rl = RulesLR().fit(D, y)
res["rules_lr_weights"] = dict(zip(RULE_NAMES, map(float, rl.m.coef_[0])))
res["counts"] = dict(mcptox_benign=int((y == 0).sum()), mcptox_poisoned=int(y.sum()), servers=len(set(g)),
                     successful_attacks=int(sum(1 for r in D if r.get("success_any"))), wild_benign=len(W), ood=len(O))
json.dump(res, open("results/e1.json", "w"), indent=1, default=float)
