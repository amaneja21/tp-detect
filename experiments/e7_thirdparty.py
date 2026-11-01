import os
"""E7: real third-party scanners on the same descriptions (no re-implementation).
  * NVIDIA SkillSpector (Apache-2.0) static tool-poisoning checks TP1-TP3 (TP4 needs an LLM).
  * mcp-watch (open-source MCP scanner), all of its scanners, run on a generated project in which
    each tool is written as a name line and a description line; findings are mapped back by line.
Snyk Agent Scan (formerly MCP-Scan) sends tool descriptions to a remote analysis API and could
not be run offline in our environment."""
import json, os, subprocess, sys, shutil, tempfile, collections, numpy as np
BASE = os.environ.get("BASELINES_DIR", os.path.join(os.path.dirname(__file__), "..", "baselines"))
sys.path.insert(0, ".")
D = json.load(open("data/mcptox_desc.json")); W = json.load(open("data/wild_benign.json"))
O1 = json.load(open("data/ood_attacks.json")); O2 = json.load(open("data/ood2_attacks.json"))
items = [dict(r, set="mcptox") for r in D] + [dict(r, set="wild") for r in W] + [dict(r, set="ood1") for r in O1] + [dict(r, set="ood2") for r in O2]
json.dump([{"tool": r["tool"], "description": r["description"]} for r in items], open("/tmp/e7_items.json", "w"))
subprocess.run([os.path.join(BASE, "ss/bin/python"), os.path.join(BASE, "run_ss.py"), "/tmp/e7_items.json", "/tmp/e7_ss.json"], check=True)
ss = [bool(x) for x in json.load(open("/tmp/e7_ss.json"))]
hit = collections.defaultdict(set); import re
def scan(lo, hi):
    """Scan items[lo:hi]; split the batch if mcp-watch's report comes back truncated."""
    proj = tempfile.mkdtemp(prefix="mcpw_"); lines = []
    for r in items[lo:hi]:
        d = " ".join(r["description"].split()).replace('"', "'")
        lines.append(f'name="{r["tool"]}"'); lines.append(f'description="{d}"')
    open(os.path.join(proj, "tools.py"), "w").write("\n".join(lines) + "\n")
    txt = subprocess.run(["node", os.path.join(BASE, "mcp-watch/dist/main.js"), "scan-local", proj, "--format", "json"], capture_output=True, text=True).stdout
    shutil.rmtree(proj)
    vul = re.findall(r'"category":\s*"([^"]+)",[^{}]*?"line":\s*(\d+)', txt, re.S)
    tot = re.search(r'"totalVulnerabilities":\s*(\d+)', txt)
    nfile = len(re.findall(r'"file":\s*"[^"]*",\s*"evidence"', txt))
    if not (tot and int(tot.group(1)) == len(vul) + nfile and re.search(r"\n\}\n", txt)):
        assert hi - lo > 1, ("unparseable single item", lo)
        mid = (lo + hi) // 2; scan(lo, mid); scan(mid, hi); return
    for c, l in vul: hit[lo + (int(l) - 1) // 2].add(c)
for b0 in range(0, len(items), 40): scan(b0, min(len(items), b0 + 40))
vulns = [1 for v in hit.values() for _ in v]
mw = [bool(hit.get(i)) for i in range(len(items))]
INJ = {"tool-poisoning", "prompt-injection", "tool-mutation", "conversation-exfiltration", "ansi-injection", "parameter-injection"}
mw_inj = [bool(hit.get(i, set()) & INJ) for i in range(len(items))]
def summ(flags):
    f = np.array(flags); st = np.array([r["set"] for r in items]); y = np.array([r["label"] for r in items])
    return dict(mcptox_recall=float(f[(st == "mcptox") & (y == 1)].mean()), mcptox_fpr=float(f[(st == "mcptox") & (y == 0)].mean()),
                wild_fpr=float(f[st == "wild"].mean()), ood1_recall=float(f[st == "ood1"].mean()), ood2_recall=float(f[st == "ood2"].mean()))
out = {"SkillSpector TP1-TP3": summ(ss), "mcp-watch (any finding)": summ(mw), "mcp-watch (injection categories)": summ(mw_inj), "mcp_watch_categories": dict(collections.Counter(c for s in hit.values() for c in s)),
       "n_vulns": len(vulns)}
json.dump(out, open("results/e7.json", "w"), indent=1)
print(json.dumps(out, indent=1))
