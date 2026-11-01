import json, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams.update({"pdf.fonttype": 42, "ps.fonttype": 42, "font.family": "serif", "font.size": 8, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.edgecolor": "#888", "axes.labelcolor": "#222", "xtick.color": "#444", "ytick.color": "#444"})
C = ["#2a78d6", "#eb6834", "#1baf7a"]
e1 = json.load(open("results/e1_final.json"))
M = [("Pattern scanner (MCP-Scan-style)", "Pattern scanner"), ("Text-LR [MCPTox]", "Text-LR (MCPTox)"),
     ("v2 harm-directed rules (hand)", "v2 rules"), ("TP-Detect L2 ensemble (v2 rules OR learned)", "TP-Detect L2")]
fig, ax = plt.subplots(1, 2, figsize=(4.8, 1.9), gridspec_kw={"width_ratios": [2.2, 1]})
yy = np.arange(len(M)); h = 0.36
a = [e1[k]["mcptox_recall"] * 100 for k, _ in M]; b = [e1[k]["ood2_recall"] * 100 for k, _ in M]
ax[0].barh(yy - h / 2 - 0.01, a, h, color=C[0], label="MCPTox (held-out servers)")
ax[0].barh(yy + h / 2 + 0.01, b, h, color=C[1], label="OOD-2 (held-out phrasing)")
for i in range(len(M)):
    ax[0].text(a[i] + 1, yy[i] - h / 2, f"{a[i]:.0f}", va="center", fontsize=6.5, color="#222")
    ax[0].text(b[i] + 1, yy[i] + h / 2, f"{b[i]:.0f}", va="center", fontsize=6.5, color="#222")
ax[0].set_yticks(yy, [n for _, n in M]); ax[0].invert_yaxis(); ax[0].set_xlim(0, 112); ax[0].set_xlabel("Recall (%)")
ax[0].legend(frameon=False, fontsize=6.5, loc="lower left", bbox_to_anchor=(0.0, 1.0), ncol=2, handlelength=1.2)
w = [e1[k]["wild_fpr"] * 100 for k, _ in M]
ax[1].barh(yy, w, 0.55, color=C[2])
for i in range(len(M)): ax[1].text(w[i] + 0.2, yy[i], f"{w[i]:.1f}", va="center", fontsize=6.5, color="#222")
ax[1].set_yticks(yy, [""] * len(M)); ax[1].invert_yaxis(); ax[1].set_xlim(0, 10.5); ax[1].set_xlabel("FPR on live tools (%)")
fig.tight_layout(w_pad=0.6); fig.savefig("figures/fig_e1.pdf", bbox_inches="tight"); fig.savefig("figures/fig_e1.png", dpi=200, bbox_inches="tight")

e4 = json.load(open("results/e4.json"))
fig, ax = plt.subplots(1, 2, figsize=(4.8, 1.8), sharey=True)
Ns = [1, 10, 50, 100, 400]
for j, (eps, rho) in enumerate([(0.01, 0.1), (0.03, 0.1)]):
    for c, pol, lab in [(C[1], "per-agent", "Isolated (per-agent)"), (C[0], "fleet", "Fleet-pooled (L5)")]:
        v = [next(x["exposure_mean"] for x in e4 if x["eps"] == eps and x["rho"] == rho and x["N"] == n and x["policy"] == pol) for n in Ns]
        ax[j].plot(Ns, v, "-o", color=c, lw=1.6, ms=3.5, label=lab, markeredgecolor="white", markeredgewidth=0.6)
    ax[j].set_xscale("log"); ax[j].set_yscale("log"); ax[j].set_xlabel("Agents in fleet (N)")
    ax[j].set_title(f"ε = {eps:.0%},  ρ = {rho:.0%}", fontsize=7)
    ax[j].set_xticks([1, 10, 100, 400], ["1", "10", "100", "400"]); ax[j].minorticks_off()
    ax[j].grid(True, which="major", color="#e6e6e6", lw=0.5)
ax[0].set_ylabel("Malicious executions\nbefore quarantine")
ax[0].set_yticks([1, 10, 100, 1000], ["1", "10", "100", "1000"])
ax[0].legend(frameon=False, fontsize=6.5, loc="upper left")
fig.tight_layout(); fig.savefig("figures/fig_e4.pdf", bbox_inches="tight"); fig.savefig("figures/fig_e4.png", dpi=200, bbox_inches="tight")
print("ok")
