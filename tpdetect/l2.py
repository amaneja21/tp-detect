"""Final Layer 2 scorer used by the gateway: max(v2 harm-directed rules, learned L2 model)."""
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.linear_model import LogisticRegression
from .models import TextLR
from .descriptor_v2 import v2_features, v2_score

class LearnedL2:
    def __init__(self, scale=4.0):
        self.t = TextLR(); self.s = scale
        self.m = LogisticRegression(C=2.0, max_iter=4000, class_weight="balanced")
    def X(self, recs, fit=False):
        Xt = self.t._X([r["description"] for r in recs], fit)
        F = np.vstack([v2_features(r["description"], r.get("tool", ""), r.get("server_tools", ())) for r in recs]) * self.s
        return hstack([Xt, csr_matrix(F)]).tocsr()
    def fit(self, recs): self.m.fit(self.X(recs, True), [r["label"] for r in recs]); return self
    def predict(self, recs): return self.m.predict_proba(self.X(recs))[:, 1]

class L2Scorer:
    def __init__(self, learned=None): self.learned = learned
    def __call__(self, rec):
        a = v2_score(rec["description"], rec.get("tool", ""), rec.get("server_tools", ()))
        b = float(self.learned.predict([rec])[0]) if self.learned is not None else 0.0
        return max(a, b)
