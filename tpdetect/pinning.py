"""Layer 1: definition and code pinning with drift triage (rug-pull detection).

Every tools/list response is canonicalised and hashed per tool (name, description,
input schema). A changed hash is a *drift event*. Plain pinning (ETDI-style) blocks every
drift, which also blocks every legitimate update. TP-Detect triages drift by scoring only
the text that was added, in the context of the server's other tools, with Layer 2."""
import hashlib, json, difflib

def canon(tool: dict) -> str:
    return json.dumps({"name": tool.get("name"), "description": tool.get("description", ""),
                       "schema": tool.get("schema") or {}}, sort_keys=True, ensure_ascii=False)

def tool_hash(tool: dict) -> str:
    return hashlib.sha256(canon(tool).encode()).hexdigest()

def added_text(old: str, new: str) -> str:
    """Tokens present in the new description but not in the old one (word-level diff)."""
    a, b = (old or "").split(), (new or "").split()
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    out = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op in ("insert", "replace"): out.extend(b[j1:j2])
    return " ".join(out)

class PinStore:
    def __init__(self, scorer=None, threshold=0.5):
        self.pins = {}          # (server, tool) -> (hash, description)
        self.scorer = scorer    # callable(record) -> prob malicious
        self.th = threshold
    def observe(self, server: str, tools: list):
        """Returns list of events: (tool, kind, score). kind in new|unchanged|drift_benign|drift_suspicious."""
        names = [t["name"] for t in tools]
        ev = []
        for t in tools:
            k = (server, t["name"]); h = tool_hash(t)
            if k not in self.pins:
                self.pins[k] = (h, t.get("description", "")); ev.append((t["name"], "new", None)); continue
            if self.pins[k][0] == h:
                ev.append((t["name"], "unchanged", None)); continue
            if self.scorer is None:
                ev.append((t["name"], "drift_suspicious", 1.0)); continue
            delta = added_text(self.pins[k][1], t.get("description", ""))
            s = self.scorer({"description": delta, "tool": t["name"], "server_tools": names}) if delta.strip() else 0.0
            kind = "drift_suspicious" if s >= self.th else "drift_benign"
            if kind == "drift_benign": self.pins[k] = (h, t.get("description", ""))
            ev.append((t["name"], kind, s))
        return ev
