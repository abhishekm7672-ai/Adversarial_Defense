import numpy as np

class AntifragilityMetric:
    """
    Computes Antifragility Index:
    (Robustness_final - Robustness_initial) / Attack_Diversity
    """
    def __init__(self):
        self.history = []

    def compute_index(self, initial_robustness, final_robustness, attack_diversity):
        """
        attack_diversity can be represented by number of rounds or 
        variance in adversarial perturbations.
        """
        if attack_diversity == 0:
            return 0.0
        
        index = (final_robustness - initial_robustness) / attack_diversity
        return float(index)

    def log_round(self, round_id, robustness):
        self.history.append({
            "round": round_id,
            "robustness": robustness
        })
