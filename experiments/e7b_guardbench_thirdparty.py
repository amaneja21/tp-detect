import os
"""E7b: (i) MCP-GuardBench's metadata analyzer (high/critical findings, its documented --fail-on high
policy) on all description sets; (ii) every detector, ours and third-party, on a corpus written by
other authors: MCP-GuardBench lab servers and MCPSecBench attack servers."""
import json, subprocess, sys, numpy as np, os, re, shutil, tempfile, collections
sys.path.insert(0, ".")
from tpdetect.l2 import LearnedL2, L2Scorer
from tpdetect.descriptor_v2 import v2_score
from tpdetect.descriptor import rule_features, RULE_NAMES
D = json.load(open("data/mcptox_desc.json")); W = json.load(open("data/wild_benign.json"))
O1 = json.load(open("data/ood_attacks.json")); O2 = json.load(open("data/ood2_attacks.json"))
T = json.load(open("data/thirdparty_corpus.json"))
BASE = os.environ.get("BASELINES_DIR", os.path.join(os.path.dirname(__file__), "..", "baselines"))
GB = os.path.join(BASE, "gb/bin/python"); SS = os.path.join(BASE, "ss/bin/python")
def gb(items):
    json.dump([{"tool": r["tool"], "description": r.get("description", ""), "schema": r.get("schema"), "server_tools": r.get("server_tools", [])} for r in items], open("/tmp/gb_in.json", "w"))
    subprocess.run([GB, os.path.join(BASE, "run_gb.py"), "/tmp/gb_in.json", "/tmp/gb_out.json"], check=True)
    return np.array([any(s.lower() in ("high", "critical") for s in x) for x in json.load(open("/tmp/gb_out.json"))])
res = {}
sets = {"mcptox_pois": [r for r in D if r["label"]], "mcptox_ben": [r for r in D if not r["label"]], "wild": W, "ood1": O1, "ood2": O2}
res["GuardBench (high+)"] = {k: float(gb(v).mean()) for k, v in sets.items()}
print(res)
# third-party corpus: all detectors on description + parameter descriptions
txt = [dict(r, description=r["text_with_params"]) for r in T]; y = np.array([r["label"] for r in T])
json.dump([{"tool": r["tool"], "description": r["description"]} for r in txt], open("/tmp/tp_items.json", "w"))
subprocess.run([SS, os.path.join(BASE, "run_ss.py"), "/tmp/tp_items.json", "/tmp/tp_ss.json"], check=True)
ss = np.array([bool(x) for x in json.load(open("/tmp/tp_ss.json"))])
def mcpwatch(items):
    hit = collections.defaultdict(set)
    proj = tempfile.mkdtemp(); L = []
    for r in items:
        d = " ".join(r["description"].split()).replace('"', "'"); L += [f'name="{r["tool"]}"', f'description="{d}"']
    open(os.path.join(proj, "tools.py"), "w").write("\n".join(L) + "\n")
    t = subprocess.run(["node", os.path.join(BASE, "mcp-watch/dist/main.js"), "scan-local", proj, "--format", "json"], capture_output=True, text=True).stdout
    shutil.rmtree(proj)
    for c, l in re.findall(r'"category":\s*"([^"]+)",[^{}]*?"line":\s*(\d+)', t, re.S): hit[(int(l) - 1) // 2].add(c)
    INJ = {"tool-poisoning", "prompt-injection", "tool-mutation", "conversation-exfiltration", "ansi-injection", "parameter-injection"}
    return np.array([bool(hit.get(i, set()) & INJ) for i in range(len(items))])
def pattern(recs):
    out = []
    for r in recs:
        f = dict(zip(RULE_NAMES, rule_features(r["description"], r["tool"], r["server_tools"])))
        out.append(bool(f["R2_override"] or f["R5_conceal"] or f["R8_hidden"] or f["R6_sensitive"] > 0))
    return np.array(out)
l2 = L2Scorer(LearnedL2().fit(D + W))
dets = {"SkillSpector TP1-TP3": ss, "mcp-watch (injection)": mcpwatch(txt), "GuardBench (high+)": gb(T),
        "Pattern scanner": pattern(txt), "v2 rules": np.array([v2_score(r["description"], r["tool"], r["server_tools"]) >= .5 for r in txt]),
        "TP-Detect L2": np.array([l2(r) >= .5 for r in txt])}
res["thirdparty_corpus"] = {"n_poisoned": int(y.sum()), "n_benign": int((y == 0).sum()),
    "detectors": {k: dict(detected=int(v[y == 1].sum()), false_pos=int(v[y == 0].sum()),
                          missed=[T[i]["tool"] for i in np.where((y == 1) & ~v)[0]]) for k, v in dets.items()}}
json.dump(res, open("results/e7b.json", "w"), indent=1)
print(json.dumps(res["thirdparty_corpus"], indent=1))
