"""Layer 2: description analyzer (static, pre-registration and on every tools/list).

Two parts:
  * Interpretable rule features (R1-R6) grounded in how tool-poisoning payloads work:
    the payload must (a) steer the agent toward *another* tool or action, (b) assert
    precedence over the user, (c) name a sensitive target, and often (d) hide itself.
  * A lightweight learned scorer (TF-IDF + logistic regression) over the description text.
The combined score is a logistic model over [rule features, learned score]."""
import re, unicodedata, math
import numpy as np

# Hidden-content markers: zero-width, bidi controls, Unicode tag block, HTML comments.
HIDDEN = re.compile(r"[​-‏‪-‮⁠-⁤﻿]|[\U000E0000-\U000E007F]|<!--")
B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
URL = re.compile(r"https?://|\bwww\.|\b\d{1,3}(?:\.\d{1,3}){3}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
OVERRIDE = re.compile(r"ignore (all |the )?(previous|prior|above)|disregard|<\s*important\s*>|system override|"
                      r"supersede|takes precedence|regardless of (the )?user", re.I)
PRECONDITION = re.compile(r"\b(before|prior to|after|whenever|every time|each time)\b[^.]{0,80}\b(us(e|ing)|call(ing)?|invok\w*|run(ning)?|execut\w*|perform\w*|read\w*|send\w*|access\w*)\b", re.I)
MANDATE = re.compile(r"\b(must|mandatory|required to|requirement|always|never|do not|don't|first (call|invoke|run)|"
                     r"compulsory|obligatory|enforce[sd]?|non-negotiable)\b", re.I)
CONCEAL = re.compile(r"(do not|don't|never|without) (tell|inform|mention|notify|reveal|show|alert)\w*|"
                     r"silently|without (the )?user'?s? (knowledge|consent)|hide (this|it)|secretly", re.I)
SENSITIVE = re.compile(r"\.ssh|id_rsa|id_ed25519|\.env\b|/etc/(passwd|shadow|sudoers)|\.aws|credential|api[ _-]?key|"
                       r"secret|token|password|passwd|private key|wallet|seed phrase|mnemonic|\.bashrc|\.zshrc|crontab|"
                       r"authorized_keys|cookie|session id|bcc|cc:|forward (all|every|the)|bank|account number|ssn|"
                       r"social security", re.I)
SIDE_EFFECT = re.compile(r"\b(delete|remove|overwrite|wipe|drop|truncate|transfer|send|forward|upload|post|exfiltrat\w*|"
                         r"rm -rf|chmod|kill|shutdown|disable|revoke|grant|escalat\w*|install|execute|eval)\b", re.I)

RULE_NAMES = ["R1_cross_tool_ref", "R2_override", "R3_precondition", "R4_mandate", "R5_conceal",
              "R6_sensitive", "R7_side_effect", "R8_hidden", "R9_encoded_blob", "R10_external_endpoint"]

def _norm(s: str) -> str:
    return unicodedata.normalize("NFKC", s)

def rule_features(desc: str, tool_name: str = "", sibling_tools=()):
    d = desc or ""
    dn = _norm(d)
    low = dn.lower()
    sib = [t for t in sibling_tools if t and t != tool_name and len(t) > 2]
    cross = sum(1 for t in sib if re.search(r"(?<![\w])" + re.escape(t.lower()) + r"(?![\w])", low))
    f = [
        min(cross, 3) / 3.0,
        1.0 if OVERRIDE.search(dn) else 0.0,
        min(len(PRECONDITION.findall(dn)), 3) / 3.0,
        min(len(MANDATE.findall(dn)), 4) / 4.0,
        1.0 if CONCEAL.search(dn) else 0.0,
        min(len(SENSITIVE.findall(dn)), 3) / 3.0,
        min(len(SIDE_EFFECT.findall(dn)), 4) / 4.0,
        1.0 if HIDDEN.search(d) else 0.0,
        1.0 if B64.search(d) else 0.0,
        1.0 if (URL.search(dn) or EMAIL.search(dn)) else 0.0,
    ]
    return np.array(f, dtype=float)

def rule_score(desc, tool_name="", sibling_tools=()):
    """Hand-weighted, training-free score in [0,1] (used when no labelled data is available)."""
    f = rule_features(desc, tool_name, sibling_tools)
    w = np.array([2.5, 2.5, 1.0, 0.8, 2.0, 1.5, 0.8, 2.5, 1.0, 0.6])
    z = float(f @ w) - 2.5
    return 1 / (1 + math.exp(-z))

def explain(desc, tool_name="", sibling_tools=()):
    f = rule_features(desc, tool_name, sibling_tools)
    return {n: round(float(v), 2) for n, v in zip(RULE_NAMES, f) if v > 0}
