class AntifragilityMetric:
    """
    Measures the system's ability to improve under adversarial stress.
    Formula: (initial_evasion - final_evasion) / initial_evasion
    """

    def __init__(self):
        self.initial_evasion = 0.0
        self.final_evasion = 0.0
        self.history = []

    def set_baseline(self, evasion_rate):
        self.initial_evasion = evasion_rate
        self.history = [{"round": 0, "evasion": evasion_rate}]

    def update(self, round_num, evasion_rate):
        self.final_evasion = evasion_rate
        self.history.append({"round": round_num, "evasion": evasion_rate})

    def compute(self):
        if self.initial_evasion == 0:
            return 0.0
        return (self.initial_evasion - self.final_evasion) / self.initial_evasion

    def compute_index(self, initial, final, rounds=None):
        if initial == 0:
            return 0.0
        return (initial - final) / initial

    def is_monotonically_improving(self):
        if len(self.history) < 2:
            return True
        rates = [h["evasion"] for h in self.history]
        return all(rates[i] >= rates[i+1] for i in range(len(rates)-1))

    def summary(self):
        return {
            "initial_evasion": self.initial_evasion,
            "final_evasion": self.final_evasion,
            "antifragility_index": self.compute(),
            "monotonically_improving": self.is_monotonically_improving(),
            "history": self.history
        }