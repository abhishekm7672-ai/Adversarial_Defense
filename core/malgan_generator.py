import numpy as np
from core import config

def generate_adversarial_samples(features, num_samples):
    """
    Generates adversarial malware feature vectors that evade the detector 
    while preserving functionality using functional-preserving perturbations.
    """
    X = np.array(features)
    if len(X.shape) == 1:
        X = X.reshape(1, -1)
    
    n_features = X.shape[1]
    adv_samples = []

    for _ in range(num_samples):
        # Pick a random sample from the input features to mutate
        idx = np.random.randint(0, len(X))
        x_adv = X[idx].copy()
        
        # Diversity Engine: Choose a random attack style
        attack_style = np.random.choice(["obfuscation", "packing", "reordering", "noise"])
        
        if attack_style == "obfuscation":
            # Simulate obfuscation by metadata/header perturbations
            # metadata fields often at the start (heuristic for simplified model)
            perturb_idx = np.random.choice(range(min(20, n_features)), 5, replace=False)
            x_adv[perturb_idx] += np.random.normal(0, config.ADVERSARIAL_EPSILON, 5)
            
        elif attack_style == "packing":
            # Simulate packing-like features: Increase section counts/entropies
            # In our 518 features, entropy usually mid-range
            entropy_indices = range(3, min(13, n_features)) # based on pe_feature_extractor
            x_adv[list(entropy_indices)] = np.clip(x_adv[list(entropy_indices)] + 0.1, 0, 8.0)
            
        elif attack_style == "reordering":
            # Simulate API call ordering perturbations
            # API related features (simplified logic)
            api_indices = range(min(13, n_features), min(100, n_features))
            np.random.shuffle(x_adv[list(api_indices)])
            
        elif attack_style == "noise":
            # Random noise injection within valid bounds
            noise = np.random.normal(0, config.ADVERSARIAL_EPSILON, n_features)
            x_adv = x_adv + noise

        # Overlay byte padding simulation (adds "zero" noise to features)
        padding_mask = np.random.random(n_features) < 0.05
        x_adv[padding_mask] = 0
            
        adv_samples.append(x_adv)
        
    return np.array(adv_samples)
