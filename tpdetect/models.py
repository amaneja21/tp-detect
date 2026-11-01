"""Learned description scorers used by Layer 2 and the ML baseline."""
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from .descriptor import rule_features

class TextLR:
    """Baseline: TF-IDF (word 1-2 + char 3-5) logistic regression on description text only."""
    def __init__(self, C=4.0):
        self.w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)
        self.c = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True, max_features=40000)
        self.m = LogisticRegression(C=C, max_iter=3000, class_weight="balanced")
    def _X(self, docs, fit=False):
        if fit: return hstack([self.w.fit_transform(docs), self.c.fit_transform(docs)]).tocsr()
        return hstack([self.w.transform(docs), self.c.transform(docs)]).tocsr()
    def fit(self, docs, y): self.m.fit(self._X(docs, True), y); return self
    def predict_proba(self, docs): return self.m.predict_proba(self._X(docs))[:, 1]

class RulesLR:
    """Rule features only, weights learned (10 interpretable parameters)."""
    def __init__(self): self.m = LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced")
    def feats(self, recs): return np.vstack([rule_features(r["description"], r["tool"], r["server_tools"]) for r in recs])
    def fit(self, recs, y): self.m.fit(self.feats(recs), y); return self
    def predict_proba(self, recs): return self.m.predict_proba(self.feats(recs))[:, 1]

class Combined:
    """TP-Detect Layer 2: text features + context-aware rule features in one model."""
    def __init__(self, C=4.0, rule_scale=3.0):
        self.t = TextLR(C); self.s = rule_scale
        self.m = LogisticRegression(C=C, max_iter=4000, class_weight="balanced")
    def _X(self, recs, fit=False):
        docs = [r["description"] for r in recs]
        Xt = self.t._X(docs, fit)
        R = np.vstack([rule_features(r["description"], r["tool"], r["server_tools"]) for r in recs]) * self.s
        return hstack([Xt, csr_matrix(R)]).tocsr()
    def fit(self, recs, y): self.m.fit(self._X(recs, True), y); return self
    def predict_proba(self, recs): return self.m.predict_proba(self._X(recs))[:, 1]
