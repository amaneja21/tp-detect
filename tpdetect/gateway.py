"""TP-Detect gateway: wraps a live MCP client session and applies all five layers.

L1 PinStore      : definition pinning + drift triage            (tools/list)
L2 Descriptor    : description / response content analysis      (tools/list, tools/call result)
L3 Capability    : manifest enforcement inside the server process (audit hook, pre-emptive)
L4 Behaviour     : per-tool behavioural novelty vs. burn-in profile (tools/call)
L5 Reputation    : fleet-wide Bayesian quarantine                (shared across sessions)"""
import os, sys, json, time, tempfile
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from .pinning import PinStore
from .l2 import L2Scorer

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def signature(ev, root="/tmp/tpd"):
    k, x = ev["k"], ev["x"]
    if k.startswith("fs_"):
        rel = os.path.relpath(x, root) if x.startswith(root) else x
        parts = rel.split(os.sep)
        top = parts[0] if x.startswith(root) else os.sep.join(parts[:3])
        return f"{k}:{top}"
    if k == "exec": return "exec:" + os.path.basename(x.split()[0]) if x else "exec:?"
    return f"{k}:{x}"

class BehaviourProfile:
    def __init__(self): self.sig = {}; self.maxn = {}; self.frozen = False
    def learn(self, tool, events):
        s = self.sig.setdefault(tool, set()); s.update(signature(e) for e in events)
        self.maxn[tool] = max(self.maxn.get(tool, 0), len(events))
    def novelty(self, tool, events):
        s = self.sig.get(tool, set())
        new = sorted({signature(e) for e in events} - s)
        burst = len(events) > 2 * max(1, self.maxn.get(tool, 0))
        return new, burst

class GuardedSession:
    def __init__(self, name, script, manifest, *, scorer=None, reputation=None, profile=None,
                 layers=("L1", "L2", "L3", "L4", "L5"), enforce=True, env=None, desc_threshold=0.5,
                 sandbox=True, backend="audit", command=None, args=()):
        self.name, self.script, self.manifest = name, script, manifest
        self.scorer = scorer or L2Scorer(None)   # default: v2 harm-directed rules; pass a trained L2Scorer for the full L2
        self.layers = set(layers); self.enforce = enforce and "L3" in self.layers
        self.rep = reputation; self.profile = profile if profile is not None else BehaviourProfile()
        self.pins = PinStore(self.scorer, desc_threshold) if "L1" in self.layers else None
        self.th = desc_threshold; self.env = env or {}; self.sandbox = sandbox
        self.blocked_tools = set(); self.tool_names = []; self.timing = []
        self.backend, self.command, self.cmd_args = backend, command, list(args)
    async def __aenter__(self):
        self.stack = AsyncExitStack()
        fd, self.evfile = tempfile.mkstemp(prefix="tpd_ev_", suffix=".jsonl"); os.close(fd)
        mf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(self.manifest, mf); mf.close()
        env = {**os.environ, **self.env, "PYTHONPATH": PKG_ROOT + (os.pathsep + os.path.dirname(os.path.abspath(self.script)) if self.script else "")}
        if self.backend == "strace":   # language-agnostic monitoring (no prevention): any server binary
            cmd = "strace"
            args = ["-f", "-qq", "-e", "trace=openat,connect,execve", "-o", self.evfile, self.command, *self.cmd_args]
        elif self.sandbox:
            env.update(TPD_EVENT_FILE=self.evfile, TPD_MANIFEST=mf.name, TPD_ENFORCE="1" if self.enforce else "0")
            cmd, args = sys.executable, ["-m", "tpdetect.sandbox", self.script]
        else:
            cmd, args = sys.executable, [self.script]
        p = StdioServerParameters(command=cmd, args=args, env=env)
        r, w = await self.stack.enter_async_context(stdio_client(p))
        self.s = await self.stack.enter_async_context(ClientSession(r, w))
        await self.s.initialize()
        self._off = 0
        return self
    async def __aexit__(self, *a):
        await self.stack.aclose()
        try: os.unlink(self.evfile)
        except OSError: pass
    def _drain(self):
        with open(self.evfile) as f:
            f.seek(self._off); data = f.read(); self._off = f.tell()
        if self.backend == "strace":
            from .strace_events import parse, allowed
            return [dict(e, ok=allowed(self.manifest, e["k"], e["x"])) for e in parse(data)]
        return [json.loads(l) for l in data.splitlines() if l.strip()]
    async def list_tools(self):
        res = await self.s.list_tools()
        tools = [dict(name=t.name, description=t.description or "",
                      schema=getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}) for t in res.tools]
        self.tool_names = [t["name"] for t in tools]
        report = []
        drift = {}
        if self.pins is not None:
            for name, kind, sc in self.pins.observe(self.name, tools): drift[name] = (kind, sc)
        for t in tools:
            sc = None
            if "L2" in self.layers:
                sc = float(self.scorer({"description": t["description"], "tool": t["name"], "server_tools": self.tool_names}))
                if sc >= self.th: self.blocked_tools.add(t["name"])
            kind = drift.get(t["name"], ("n/a", None))[0]
            if kind == "drift_suspicious": self.blocked_tools.add(t["name"])
            if self.rep is not None and "L5" in self.layers: self.rep.set_prior(self._key(t["name"]), sc or 0.0)
            report.append(dict(tool=t["name"], desc_score=sc, drift=kind, blocked=t["name"] in self.blocked_tools))
        return tools, report
    def _key(self, tool): return f"{self.name}/{tool}"
    async def call_tool(self, tool, args, learn=False):
        v = dict(tool=tool, blocked=False, alerts=[], hard=False, quarantined=False)
        key = self._key(tool)
        if tool in self.blocked_tools or (self.rep is not None and key in self.rep.quarantined):
            v.update(blocked=True, quarantined=True); return None, v
        self._drain()
        t0 = time.perf_counter()
        res = await self.s.call_tool(tool, args)
        t1 = time.perf_counter()
        text = " ".join(getattr(c, "text", "") for c in (res.content or []))
        ev = self._drain()
        if learn:
            self.profile.learn(key, ev); return text, v
        viol = [e for e in ev if not e.get("ok", True)]
        if viol and "L3" in self.layers:
            v["hard"] = True; v["alerts"].append(("L3_violation", [signature(e) for e in viol]))
        if "L4" in self.layers:
            new, burst = self.profile.novelty(key, ev)
            if new: v["alerts"].append(("L4_novel", new))
            if burst: v["alerts"].append(("L4_burst", len(ev)))
        if "L2" in self.layers and text:
            sc = float(self.scorer({"description": text, "tool": tool, "server_tools": self.tool_names}))
            if sc >= self.th: v["alerts"].append(("L2_response", round(sc, 3)))
        t2 = time.perf_counter()
        if self.rep is not None and "L5" in self.layers:
            q = self.rep.update(key, bool(v["alerts"]))
            if v["hard"]: self.rep.quarantined.add(key); q = True
            v["quarantined"] = q
        t3 = time.perf_counter()
        self.timing.append((t1 - t0, t2 - t1, t3 - t2))
        if v["hard"] or any(a[0] == "L2_response" for a in v["alerts"]):
            v["blocked"] = True; return None, v   # result withheld from the agent
        return text, v
