from pathlib import Path
import os

# ===============================
# Reproducibility
# ===============================
RANDOM_SEED = 42

# ===============================
# Versioning
# ===============================
MODEL_VERSION = "1.0-production"

# ===============================
# Dataset Path
# ===============================
BASE_DIR = Path(__file__).parent.parent
DATA_PATH = BASE_DIR / "data" / "ember2018"

# ===============================
# LightGBM Parameters
# ===============================
LGB_PARAMS = {
    "objective": "binary",
    "metric": "binary_logloss",
    "boosting_type": "gbdt",
    "num_leaves": 64,
    "learning_rate": 0.05,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 5,
    "n_estimators": 100,
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
    "verbose": -1,
    "force_col_wise": True
}

# ===============================
# Thresholds
# ===============================
MALWARE_THRESHOLD = 0.5
SUSPICION_THRESHOLD = 0.05

# ===============================
# Risk Fusion (Inference Layer)
# ===============================
# Final risk score calculation:
# risk_score = (alpha * malware_prob) + (beta * suspicion_score)

RISK_ALPHA = 0.7
RISK_BETA = 0.3

# ===============================
# Feature Configuration
# ===============================
# EMBER feature vector size (518 static + 4 behavioral)
FEATURE_DIM = 522

# ===============================
# Adversarial Hardening
# ===============================
ADVERSARIAL_EPSILON = 0.02
HARDENING_ROUNDS = 7

MAX_ADV_PER_ROUND = 20000
MAX_ADV_BUFFER = 100000

# ===============================
# Poisoning Defense
# ===============================
SANITIZER_CONTAMINATION = 0.05

# ===============================
# Logging & Model Paths
# ===============================
MODEL_SAVE_PATH = BASE_DIR / "models"
LOG_PATH = BASE_DIR / "logs" / "training_log.json"

# ===============================
# GAN Configuration
# ===============================
GAN_ENABLED = True
LATENT_DIM = 128
GENERATOR_LR = 1e-4
DISCRIMINATOR_LR = 1e-4
GAN_EPOCHS = 5
GAN_BATCH_SIZE = 128