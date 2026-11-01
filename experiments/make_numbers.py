"""Emit numbers.tex: every quantitative claim in the paper is a macro computed here.
Output path: $NUMBERS_OUT, default results/numbers.tex."""
import os
OUT = os.environ.get("NUMBERS_OUT", "results/numbers.tex")
import json, collections
e1 = json.load(open("results/e1_final.json")); e2 = json.load(open("results/e2.json"))
e3 = json.load(open("results/e3.json")); e3b = json.load(open("results/e3_inmanifest.json"))
e4 = json.load(open("results/e4.json")); e5 = json.load(open("results/e5.json"))
wild = json.load(open("data/wild_raw.json")); drift = json.load(open("data/benign_drift_all.json"))
L = []
def m(name, val): L.append(f"\\newcommand{{\\{name}}}{{{val}}}")
pct = lambda x, d=1: f"{100*x:.{d}f}\\%"
c = e1["counts"]
m("nMcpBenign", c["mcptox_benign"]); m("nMcpPoison", c["mcptox_poisoned"]); m("nMcpServers", c["mcptox_servers"])
m("nMcpSucc", c["successful_attacks"]); m("nWild", c["wild_benign"]); m("nWildServers", c["wild_servers"])
m("nOODone", c["ood1"]); m("nOODtwo", c["ood2"])
m("nWildAttempted", len(wild)); m("nWildPy", sum(1 for v in wild.values() if v["tools"] and v["kind"] == "py"))
m("nWildNpm", sum(1 for v in wild.values() if v["tools"] and v["kind"] == "npm"))
keys = {"Pat": "Pattern scanner (MCP-Scan-style)", "Vone": "v1 surface rules (hand)", "Vtwo": "v2 harm-directed rules (hand)",
        "TlrM": "Text-LR [MCPTox]", "TlrB": "Text-LR [MCPTox+wild]", "VtwoLR": "v2-LR [MCPTox+wild]",
        "Ltwo": "TP-Detect L2 [MCPTox+wild]", "Ens": "TP-Detect L2 ensemble (v2 rules OR learned)"}
for k, n in keys.items():
    r = e1[n]
    for f, tag in [("mcptox_recall", "Rec"), ("mcptox_fpr", "Fpr"), ("wild_fpr", "Wfpr"), ("recall_successful", "Succ"),
                   ("ood1_recall", "Oone"), ("ood2_recall", "Otwo"), ("pooled_f1", "Fone"), ("auroc_mcptox", "Auc")]:
        m(f"eA{k}{tag}", pct(r[f]) if tag != "Auc" else f"{r[f]:.3f}")
    m(f"eA{k}RecCI", f"[{100*r['mcptox_recall_ci'][0]:.1f}, {100*r['mcptox_recall_ci'][1]:.1f}]")
    m(f"eA{k}WfprCI", f"[{100*r['wild_fpr_ci'][0]:.1f}, {100*r['wild_fpr_ci'][1]:.1f}]")
# wild style statistics
import sys; sys.path.insert(0, ".")
import numpy as np
from tpdetect.descriptor import rule_features, RULE_NAMES
D = json.load(open("data/mcptox_desc.json")); W = json.load(open("data/wild_benign.json"))
def prev(R, i): return float(np.mean([rule_features(r["description"], r["tool"], r["server_tools"])[i] > 0 for r in R]))
m("wildCross", pct(prev(W, 0))); m("mcpBenCross", pct(prev([r for r in D if not r["label"]], 0))); m("mcpMalCross", pct(prev([r for r in D if r["label"]], 0)))
m("wildMandate", pct(prev(W, 3))); m("mcpBenMandate", pct(prev([r for r in D if not r["label"]], 3)))
# E2
m("nDriftBenign", e2["counts"]["benign"]); m("nDriftMal", e2["counts"]["malicious"])
m("eBdet", pct(e2["main"]["TP-Detect L1"]["detect_rate"])); m("eBfa", pct(e2["main"]["TP-Detect L1"]["false_alarm_rate"]))
m("eBrealdet", pct(e2["poisoned_real_updates"]["TP-Detect L1"]["detect_rate"])); m("nDriftRealPois", e2["n_poisoned_real"])
m("eBheldoutdet", pct(e2["heldout_phrasing_rugpulls"]["TP-Detect L1"]["detect_rate"])); m("nDriftHeld", e2["n_heldout"])
m("nDriftServers", len({d["server"] for d in drift}))
m("nDriftGit", sum(1 for d in drift if d.get("source", "git") == "git")); m("nDriftRel", sum(1 for d in drift if d.get("source") == "releases"))
m("nDriftRelPkgs", len({d["server"] for d in drift if d.get("source") == "releases"}))
fs_ = e2.get("false_alarm_by_source", {})
m("eBfaGit", pct(fs_.get("git", {}).get("tpdetect", 0))); m("eBfaRel", pct(fs_.get("releases", {}).get("tpdetect", 0)))
# E3
agg = collections.defaultdict(collections.Counter)
for a in e3["attacks"]:
    for f in ["fired", "detected", "blocked", "benign_calls", "benign_alerts", "exfil_bytes"]: agg[(a["attack"], a["layers"], a["enforce"])][f] += a[f]
for att, tag in [("endpoint", "End"), ("dependency", "Dep"), ("lowslow", "Low"), ("output", "Out")]:
    m(f"eC{tag}Fired", agg[(att, "L2+L3+L4", True)]["fired"])
    for lay, lt in [("L3 only", "Lthree"), ("L4 only", "Lfour"), ("L2-resp only", "Lresp"), ("L2+L3+L4", "All")]:
        cc = agg[(att, lay, False)]; m(f"eC{tag}{lt}", pct(cc["detected"] / cc["fired"], 0))
    m(f"eC{tag}ExMon", agg[(att, "L2+L3+L4", False)]["exfil_bytes"]); m(f"eC{tag}ExEnf", agg[(att, "L2+L3+L4", True)]["exfil_bytes"])
tb = sum(v["benign_calls"] for k, v in agg.items()); ta = sum(v["benign_alerts"] for k, v in agg.items())
m("eCbenCalls", tb); m("eCbenAlerts", ta)
m("eCcleanCalls", sum(x["calls"] for x in e3["clean"])); m("eCcleanAlerts", sum(x["alerts"] for x in e3["clean"]))
for B in ["1", "2", "5", "10"]: m(f"burn{['','One','Two','','','Five','','','','','Ten'][int(B)]}", pct(e3["burnin"][B]["false_alert_rate"]))
m("nEpisodes", len(e3["attacks"]))
fi = sum(o["fired"] for o in e3b); de = sum(o["detected"] for o in e3b)
m("eCinFired", fi); m("eCinDet", de); m("eCinRate", pct(de / fi, 0))
# E4
def g(eps, rho, N, pol, f="exposure_mean"): return next(x[f] for x in e4 if x["eps"] == eps and x["rho"] == rho and x["N"] == N and x["policy"] == pol)
m("eDfleetOne", f"{g(0.01,0.1,400,'fleet'):.1f}"); m("eDisoOne", f"{g(0.01,0.1,400,'per-agent'):.0f}")
m("eDsessOne", f"{g(0.01,0.1,400,'per-session'):.0f}")
m("eDfleetThree", f"{g(0.03,0.1,400,'fleet'):.1f}"); m("eDisoThree", f"{g(0.03,0.1,400,'per-agent'):.0f}")
m("eDroundsOne", f"{g(0.01,0.1,400,'fleet','rounds_to_q_median'):.0f}"); m("eDroundsThree", f"{g(0.03,0.1,400,'fleet','rounds_to_q_median'):.0f}")
m("eDfleetMidOne", f"{g(0.01,0.03,400,'fleet'):.0f}"); m("eDisoMidOne", f"{g(0.01,0.03,400,'per-agent'):.0f}")
m("eDmaxFalseQ", f"{max(x['false_q_mean'] for x in e4):.0f}")
m("eDratio", f"{g(0.01,0.1,400,'per-agent')/g(0.01,0.1,400,'fleet'):.0f}")
# E5
over = [e5[f"{s}/full"]["p50"] - e5[f"{s}/raw"]["p50"] for s in ["calc", "notes", "web", "files"]]
sb = [e5[f"{s}/sandbox"]["p50"] - e5[f"{s}/raw"]["p50"] for s in ["calc", "notes", "web", "files"]]
m("eEoverMin", f"{min(over):.1f}"); m("eEoverMax", f"{max(over):.1f}"); m("eEsbMax", f"{max(sb):.2f}")
m("eEpNineNine", f"{max(e5[f'{s}/full']['p99'] for s in ['calc','notes','web','files']):.1f}")
m("eElistMax", f"{max(e5[f'{s}/full']['list_tools_ms'] for s in ['calc','notes','web','files']):.1f}")
m("eEltwo", f"{e5['l2_score_ms_per_item']:.1f}")
open(OUT, "w").write("\n".join(L) + "\n")
print(len(L), "macros")

# ---------------- Round 2 experiments ----------------
L2_ = []
def m2(name, val): L2_.append(f"\\newcommand{{\\{name}}}{{{val}}}")
e1 = json.load(open("results/e1_final.json"))
m2("nUnseen", e1["counts"]["unseen_in_design"])
for k, n in keys.items(): m2(f"eA{k}Unseen", pct(e1[n]["recall_unseen_in_design"]))
e6 = json.load(open("results/e6.json"))
m2("eFresp", f"{e6['responses']:,}"); m2("eFmodels", e6["models"]); m2("eFsucc", f"{e6['success_responses']:,}")
m2("eFlegit", f"{e6['legit_calls']:,}")
for k, t in [("none", "None"), ("L2_registration", "Reg"), ("L3a_guard", "Guard"), ("both", "Both")]:
    m2(f"eFasr{t}", pct(e6["overall"][k])); m2(f"eFun{t}", pct(e6["uninspected"]["asr"][k]))
m2("eFfalseHold", pct(e6["false_hold_rate_on_legit_calls"])); m2("eFunFalseHold", pct(e6["uninspected"]["false_hold"]))
m2("eFguardCatch", pct(e6["guard_catch_on_success"])); m2("eFunServers", e6["uninspected"]["servers"])
m2("eFpess", pct(e6["overall"]["L3a_guard"] * (1 - e1["TP-Detect L2 ensemble (v2 rules OR learned)"]["ood2_recall"])))
pm = e6["per_model"]; top = max(pm, key=lambda k: pm[k]["asr"])
m2("eFtopModel", top.replace("_", "\\_")); m2("eFtopAsr", pct(pm[top]["asr"])); m2("eFtopGuard", pct(pm[top]["asr_guard"])); m2("eFtopBoth", pct(pm[top]["asr_both"]))
e7 = json.load(open("results/e7.json")); e7b = json.load(open("results/e7b.json"))
for k, t in [("SkillSpector TP1-TP3", "SS"), ("mcp-watch (injection categories)", "MW"), ("mcp-watch (any finding)", "MWany")]:
    r = e7[k]
    for f, tt in [("mcptox_recall", "Rec"), ("mcptox_fpr", "Fpr"), ("wild_fpr", "Wfpr"), ("ood1_recall", "Oone"), ("ood2_recall", "Otwo")]: m2(f"eG{t}{tt}", pct(r[f]))
g = e7b["GuardBench (high+)"]
m2("eGGBRec", pct(g["mcptox_pois"])); m2("eGGBFpr", pct(g["mcptox_ben"])); m2("eGGBWfpr", pct(g["wild"])); m2("eGGBOone", pct(g["ood1"])); m2("eGGBOtwo", pct(g["ood2"]))
tp = e7b["thirdparty_corpus"]; m2("nTPpois", tp["n_poisoned"]); m2("nTPben", tp["n_benign"])
for k, t in [("SkillSpector TP1-TP3", "SS"), ("mcp-watch (injection)", "MW"), ("GuardBench (high+)", "GB"), ("Pattern scanner", "Pat"), ("v2 rules", "Vtwo"), ("TP-Detect L2", "Ltwo")]:
    m2(f"eGtp{t}", f"{tp['detectors'][k]['detected']}/{tp['n_poisoned']}"); m2(f"eGtpFP{t}", tp["detectors"][k]["false_pos"])
e8 = json.load(open("results/e8.json"))
am = e8["auto_manifest"]["per_attack"]
m2("eHautoFired", sum(v["fired"] for v in am.values())); m2("eHautoDet", sum(v["detected"] for v in am.values()))
m2("eHautoBen", sum(v["benign_calls"] for v in am.values())); m2("eHautoBenAl", sum(v["benign_alerts"] for v in am.values()))
m2("eHautoEx", sum(v["exfil_bytes"] for v in am.values()))
nd = e8["node"]["runs"]
for a, t in [("endpoint", "End"), ("lowslow", "Low"), ("none", "None")]:
    m2(f"eHnode{t}Fired", nd[a]["fired"]); m2(f"eHnode{t}Det", nd[a]["detected"]); m2(f"eHnode{t}BenAl", nd[a]["benign_alerts"])
    m2(f"eHnode{t}Calls", nd[a]["calls"]); m2(f"eHnode{t}Ex", nd[a]["exfil_bytes"])
m2("eHnodeTools", len(e8["node"]["tools"]))
e9 = json.load(open("results/e9.json"))
for x in e9:
    t = ("Iso" if x["policy"] == "isolated" else "Fleet") + ("Five" if x["N"] == 5 else "Twenty")
    m2(f"eI{t}Exp", x["exposure"]); m2(f"eI{t}Q", x["first_quarantine_round"] if x["first_quarantine_round"] is not None else "--")
m2("eIfalseQ", sum(x["false_quarantines"] for x in e9)); m2("eIbenAl", sum(x["benign_alerts"] for x in e9))
m2("eIcalls", f"{sum(x['calls'] for x in e9):,}")
open(OUT, "a").write("\n".join(L2_) + "\n")
print(len(L2_), "round-2 macros")
