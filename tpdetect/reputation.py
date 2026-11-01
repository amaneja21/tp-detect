"""Layer 5: fleet-wide tool reputation store.

Each runtime alert is weak evidence. For tool t the store keeps a Beta posterior over its
alert rate theta_t, pooled over every agent and session that invokes t. The fleet's benign
alert rate eps is estimated from all tools (robust median). A tool is quarantined when
    P(theta_t > k * eps | evidence) >= 1 - delta
i.e. when the store is confident the tool alerts materially more often than benign tools.
Static layers seed the prior: a higher description score shifts prior mass upward."""
from collections import defaultdict
from scipy.stats import beta as Beta

class ReputationStore:
    def __init__(self, eps=0.01, k=3.0, delta=0.01, prior_n=20.0, min_obs=5):
        self.eps, self.k, self.delta, self.prior_n, self.min_obs = eps, k, delta, prior_n, min_obs
        self.a = defaultdict(float); self.b = defaultdict(float); self.n = defaultdict(int)
        self.prior = {}
        self.quarantined = set()
    def set_prior(self, tool, static_score=0.0):
        # Prior mean between eps and 0.5 as static suspicion grows; weight prior_n pseudo-calls.
        m = self.eps + (0.5 - self.eps) * max(0.0, min(1.0, static_score)) ** 2
        self.prior[tool] = (m * self.prior_n, (1 - m) * self.prior_n)
    def _ab(self, tool):
        pa, pb = self.prior.get(tool, (self.eps * self.prior_n, (1 - self.eps) * self.prior_n))
        return pa + self.a[tool], pb + self.b[tool]
    def update(self, tool, alert: bool, weight: float = 1.0):
        if tool in self.quarantined: return True
        if alert: self.a[tool] += weight
        else: self.b[tool] += weight
        self.n[tool] += 1
        return self.check(tool)
    def p_bad(self, tool):
        a, b = self._ab(tool)
        return 1.0 - Beta.cdf(min(0.999, self.k * self.eps), a, b)
    def check(self, tool):
        if self.n[tool] >= self.min_obs and self.p_bad(tool) >= 1 - self.delta:
            self.quarantined.add(tool); return True
        return False
