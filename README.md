# TP-Detect: lifecycle-wide detection of tool poisoning in MCP deployments

Artifact for the paper *Description Scanning Is Not Enough: Lifecycle-Wide Defence Against Tool Poisoning in MCP Agent Deployments* (Amit Aneja, Rajesh Purushothaman).

## Layout
- `tpdetect/` library: `pinning.py` (L1), `descriptor.py` (v1 cues), `descriptor_v2.py` + `l2.py` (L2), `argguard.py` (L3a),
  `strace_events.py` (L3/L4 for non-Python servers),
  `sandbox.py` (L3 audit-hook loader), `gateway.py` (L1 to L5 around a live MCP session), `reputation.py` (L5).
- `testbed/` five Python MCP servers, capability manifests, and the attack shim (`common.py`).
- `experiments/` every experiment and the script that turns result files into `paper/numbers.tex`.
- `data/` derived datasets (see below). `results/` raw outputs. `figures/` paper figures.
- `baselines/` wrappers used to run SkillSpector, MCP-GuardBench and mcp-watch on our corpora.

## Data sources
- MCPTox (AAAI 2026), https://github.com/zhiqiangwang4/MCPTox-Benchmark -> `experiments/build_dataset.py`.
- Live third-party servers: `wild_raw.json` holds the `tools/list` output of every PyPI/npm MCP server that started.
- Benign updates: `experiments/mine_drift.py` over the full history of https://github.com/modelcontextprotocol/servers.
- OOD-1 and OOD-2: author-written poisoned descriptions (`make_ood.py`, `make_ood2.py`). OOD-2 was generated after
  `descriptor_v2.py` was frozen (sha256 prefix e81f3788a7e04599) and evaluated once.

## MCPTox data
MCPTox is not redistributed here. Clone it and rebuild `data/mcptox_desc.json` with `build_dataset.py` (first command below).
`data/seen_in_design_sha256.json` lists hashes of the 702 poisoned descriptions available while `descriptor_v2.py` was designed;
the remaining 636 form the unseen-in-design test set reported in the paper.

## Reproduce (Python 3.11+, `pip install -r requirements.txt`)
```
python experiments/build_dataset.py <MCPTox dir> data/mcptox_desc.json
python experiments/build_wild.py data/wild_raw.json data/mcptox_desc.json data/wild_benign.json
python experiments/e1_final.py      # RQ1 description detection
python experiments/e2_drift.py      # RQ2 rug pulls
python experiments/e3_runtime.py && python experiments/e3_runtime.py --inmanifest   # RQ3 (uses /tmp/tpd, ports 8801/8802/9999)
python experiments/e4_fleet.py      # RQ4 fleet reputation
python experiments/e5_latency.py    # overhead
python experiments/e6_end_to_end.py <MCPTox dir>      # replay of recorded LLM decisions
python experiments/e7_thirdparty.py && python experiments/e7b_guardbench_thirdparty.py   # needs SkillSpector, mcp-watch, MCP-GuardBench installed
python experiments/e8_runtime_v2.py # learned manifests + Node server via strace
python experiments/e9_fleet_live.py # live fleet with the real ReputationStore
python experiments/mine_drift_versions.py data/versions_raw.json data/benign_drift.json data/benign_drift_all.json
python experiments/figures.py && python experiments/make_numbers.py
```
The testbed attacks are benign simulations against canary files under `/tmp/tpd` and a local TCP sink.

## Environment variables for third-party comparisons

- `BASELINES_DIR`: folder holding the SkillSpector (`ss/`) and GuardBench (`gb/`) virtualenvs, `run_ss.py`, `run_gb.py`, and a built `mcp-watch/`. Defaults to `../baselines`.
- `NODE_FS_BIN`: path to the `@modelcontextprotocol/server-filesystem` binary used by `e8_runtime_v2.py`. Defaults to `mcp-server-filesystem` on PATH.
