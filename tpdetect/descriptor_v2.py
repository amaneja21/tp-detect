"""Layer 2 (v2): harm-directed prescription analysis.

Finding from E1: modern benign MCP descriptions routinely contain cross-tool references and
mandate language ("Before calling this tool, you MUST first call X"). Those surface cues do not
separate poisoning from legitimate workflow guidance. What separates them is the *target* of the
prescribed behaviour. v2 scores each sentence for a prescription (an instruction to the agent)
whose object is (H1) a secret or credential store, (H2) an outside recipient/endpoint, (H3) a
substitution of user-supplied parameters, or (H4) a destructive operation; plus sentence-independent
signals (H5) concealment, (H6) priority override, (H7) hidden or encoded content."""
import re, unicodedata, math
import numpy as np

SENT = re.compile(r"(?<=[.!?\n])\s+|\n+")
HIDDEN = re.compile(r"[​-‏‪-‮⁠-⁤﻿]|[\U000E0000-\U000E007F]|<!--")
CODE = re.compile(r"document\.|window\.location|<script|eval\(|fetch\(['\"]https?|XMLHttpRequest|os\.system|subprocess|curl\s+-|"
                  r"wget\s+http|\|\s*(ba)?sh\b|powershell", re.I)
B64 = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")
PRESCRIBE = re.compile(r"\b(must|should|need to|needs to|required|requires|always|make sure|ensure|be sure|"
                       r"first|before|also|then|remember to|you will|please|is to|are to|recommended)\b", re.I)
VERB_TAKE = re.compile(r"\b(read|cat|open|load|collect|gather|retrieve|fetch|get|include|attach|append|pass|"
                       r"provide|copy|embed|paste|dump|export|extract|examine|inspect|view|access|print|output|display|return|verify|check)\b", re.I)
VERB_SEND = re.compile(r"\b(send|forward|post|upload|transmit|share|report|sync|cc|bcc|mail|email|notify|"
                       r"submit|deliver|relay|push)\b", re.I)
VERB_DESTROY = re.compile(r"\b(delete|remove|wipe|erase|purge|drop|truncate|overwrite|rm\s+-rf|format|destroy|"
                          r"revoke|disable|kill|shut\s*down|uninstall)\b", re.I)
SECRET = re.compile(r"(~|\$home|/home/\w+|/root)?/?\.(ssh|aws|gnupg|kube|docker|npmrc|pypirc|netrc|env|git-credentials|"
                    r"config/gcloud|cursor/mcp\.json|bash_history|zsh_history)\b|id_rsa|id_ed25519|authorized_keys|"
                    r"/etc/(passwd|shadow|sudoers)|private[ _-]?key|seed phrase|mnemonic|wallet|"
                    r"(api|access|secret|session|auth)[ _-]?(key|token)s?\b|credentials?\b|passwords?\b|cookies?\b|"
                    r"conversation (history|log)|chat history|all (messages|emails|files)|previous messages|"
                    r"system prompt|environment variables", re.I)
EXTERNAL = re.compile(r"https?://[^\s'\"`)>]+|\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b|\+?\d[\d\s().-]{8,}\d|"
                      r"\b\d{1,3}(?:\.\d{1,3}){3}\b|webhook|pastebin|ngrok", re.I)
SUBSTITUTE = re.compile(r"\binstead of\b|\brather than\b|\breplace (the )?(recipient|address|destination|amount|account|"
                        r"path|url)|\b(automatically|silently|always) (modify|change|alter|rewrite|replace|append|prepend|add|set)\b|"
                        r"\b(modify|alter|rewrite) the ['\"`]?\w+['\"`]? (parameter|argument|field|value)|"
                        r"\b(change|set) the [\w ]{0,20}\b(id|amount|address|recipient|path|url|value)\b (to|as)\b|\b(change|set|redirect|reroute|swap)\b[^.]{0,40}\b(recipient|address|destination|"
                        r"account|to-field|target)\b|\boverride (the )?(user'?s? )?(choice|parameter|argument|value)", re.I)
DESTROY_OBJ = re.compile(r"\.git\b|~/|/\s|/\*|\ball (files|data|records|tables|repositories|backups)\b|"
                         r"\bdatabase\b|\bbackups?\b|\blogs?\b|\bhome directory\b|\bproject folder\b|\bbuild\b", re.I)
CONCEAL = re.compile(r"(do not|don't|never|without)\s+(tell|inform|mention|notify|reveal|show|alert|ask|confirm)\w*|"
                     r"\bsilently\b|\bquietly\b|without (the )?user'?s? (knowledge|consent|approval)|\bsecretly\b|"
                     r"\bhidden from\b|mere implementation detail|not (be )?visible to the user", re.I)
OVERRIDE = re.compile(r"ignore (all |any |the )?(previous|prior|above|earlier|other)|disregard|<\s*/?\s*important\s*>|"
                      r"system override|higher priority than|priority is higher than|takes? precedence over|supersedes?|regardless of (the )?"
                      r"(user|request|instructions)|overrides? (the )?(user|system)", re.I)

STATEFUL = re.compile(r"\b(write|overwrite|delete|remove|drop|send|forward|post|transfer|pay|move|rename|update|modify|"
                      r"edit|create|close|merge|push|publish|kill|stop|terminate|revoke|grant|invite|share|"
                      r"log ?out|logout|cancel|archive|empty|clear|reset|set|change|execute|run|install|put|patch|void|evaluate|eval|exec)\w*", re.I)

V2_NAMES = ["H1_take_secret", "H2_send_external", "H3_substitute_param", "H4_destroy",
            "H5_conceal", "H6_override", "H7_hidden_encoded", "H8_prescribed_sentences", "H9_sibling_side_effect"]

def _mentions(s, names):
    low = s.lower()
    return [n for n in names if re.search(r"(?<![\w])" + re.escape(n.lower()) + r"(?![\w])", low)]

def v2_features(desc: str, tool: str = "", siblings=()):
    raw = desc or ""
    d = unicodedata.normalize("NFKC", raw)
    sents = [s for s in SENT.split(d) if s and s.strip()]
    h1 = h2 = h3 = h4 = h9 = 0.0; npres = 0
    sib = [t for t in siblings if t and t != tool and len(t) > 2]
    for s in sents:
        pres = bool(PRESCRIBE.search(s)) or s.strip()[:1].isupper() and bool(re.match(r"\s*(read|send|forward|include|"
                     r"delete|remove|copy|attach|pass|upload|post|overwrite|set|change|redirect|ignore)\b", s, re.I))
        if not pres: continue
        npres += 1
        if SECRET.search(s) and (VERB_TAKE.search(s) or VERB_SEND.search(s) or VERB_DESTROY.search(s)): h1 = 1.0
        # prescribed invocation of another tool that has side effects (judged from the sibling's own name)
        for n in _mentions(s, sib):
            if STATEFUL.search(" ".join(re.split(r"[_\-.]", n))):
                h9 = 1.0
        if EXTERNAL.search(s) and VERB_SEND.search(s): h2 = 1.0
        if SUBSTITUTE.search(s): h3 = 1.0
        if EXTERNAL.search(s) and re.search(r"\b(redirect|navigate|visit|load|open)\w*\b", s, re.I) and re.search(r"\b(first|before|must|instead)\b", s, re.I): h2 = 1.0
        if VERB_DESTROY.search(s) and DESTROY_OBJ.search(s): h4 = 1.0
    f = [h1, h2, h3, h4,
         1.0 if CONCEAL.search(d) else 0.0,
         1.0 if OVERRIDE.search(d) else 0.0,
         1.0 if (HIDDEN.search(raw) or B64.search(d) or CODE.search(d)) else 0.0,
         min(npres, 6) / 6.0, h9]
    return np.array(f, dtype=float)

W_HAND = np.array([2.6, 2.6, 2.2, 2.0, 2.4, 2.4, 2.6, 0.3, 2.0])
def v2_score(desc, tool="", siblings=()):
    z = float(v2_features(desc, tool, siblings) @ W_HAND) - 1.5
    return 1 / (1 + math.exp(-z))

def v2_explain(desc, tool="", siblings=()):
    return {n: round(float(v), 2) for n, v in zip(V2_NAMES, v2_features(desc, tool, siblings)) if v > 0}
