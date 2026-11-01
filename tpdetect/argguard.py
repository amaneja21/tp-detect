"""Layer 3a: argument provenance guard (wording-independent, call time).

A tool call is held if one of its string arguments (G1) names a secret or system credential
store, (G2) names an external endpoint (URL, e-mail, phone) that does not occur in the user's
request, or (G3) names a filesystem resource that does not occur in the user's request.
This is a lightweight data-provenance check in the spirit of CaMeL: resource identifiers that
an agent sends to a tool must come from the user, not from tool metadata."""
import re, os
from .descriptor_v2 import SECRET
# external endpoints: URLs, e-mail addresses, and phone numbers written with a leading + (not dates or counts)
EXTERNAL = re.compile(r"https?://[^\s'\"`)>]+|\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b|\+\d[\d\s().-]{7,}\d|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)

PATHLIKE = re.compile(r"^(~|/|\.{1,2}/|[A-Za-z]:\\)|[/\\][\w.-]+[/\\]|\.(txt|md|json|ya?ml|csv|log|py|js|ts|ini|conf|cfg|env|pem|key|db|sql|sh|pdf|docx?|xlsx?)$", re.I)
SYS = re.compile(r"^/(etc|root|var/lib|usr/lib|boot|proc|sys)\b|^~/\.|/\.ssh\b|/\.aws\b|/\.config\b", re.I)

def _strings(obj):
    if isinstance(obj, str): yield obj
    elif isinstance(obj, dict):
        for v in obj.values(): yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj: yield from _strings(v)

def _grounded(v, query):
    q = query.lower(); v0 = v.strip().strip("'\"").lower()
    if not v0: return True
    if v0 in q: return True
    base = os.path.basename(v0.rstrip("/"))
    return bool(base) and len(base) > 2 and base in q

def check(args, query):
    reasons = []
    for v in _strings(args):
        s = v.strip()
        if len(s) > 400: s = s[:400]
        if (SECRET.search(s) or SYS.search(s)) and not _grounded(s, query): reasons.append(("G1_secret", s[:60]))
        elif EXTERNAL.search(s) and not _grounded(EXTERNAL.search(s).group(0), query): reasons.append(("G2_external", s[:60]))
        elif PATHLIKE.search(s) and " " not in s.strip() and not _grounded(s, query): reasons.append(("G3_resource", s[:60]))
    return reasons
