import numpy as np
import torch
import random
from . import config

def set_seed(seed=config.RANDOM_SEED):
    """
    Sets the seed for reproducibility.
    """
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    
    # LightGBM reproducibility is handled via params but this is a good practice
    # Some torch operations are non-deterministic, but we'll stick to basic seeds for now
    print(f"[+] Reproducibility: Seed set to {seed}")
