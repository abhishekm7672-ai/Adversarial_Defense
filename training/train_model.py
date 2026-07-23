import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
import logging
from sklearn.model_selection import train_test_split

from core import config
from core.reproducibility import set_seed
from core.dataset import load_data
from training.hardening_pipeline import run_hardening

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainModel")


def main():
    set_seed()
    logger.info("=" * 60)
    logger.info("  Navigo Adversarial Defense — Training Pipeline")
    logger.info("=" * 60)

    logger.info("[+] Loading EMBER 2018 dataset...")
    X_train_raw, X_test, y_train_raw, y_test = load_data()

    # Memory-safe subset for laptop training (8GB RAM)
    # Remove this block for full server training
    SUBSET_SIZE = 40000
    idx = np.random.RandomState(config.RANDOM_SEED).permutation(len(X_train_raw))[:SUBSET_SIZE]
    X_train_raw = X_train_raw[idx]
    y_train_raw = y_train_raw[idx]
    test_idx = np.random.RandomState(config.RANDOM_SEED).permutation(len(X_test))[:10000]
    X_test = X_test[test_idx]
    y_test = y_test[test_idx]
    logger.info(f"[+] Using memory-safe subset: {SUBSET_SIZE} train, 10000 test")

    # Filter unlabelled samples
    train_mask = y_train_raw != -1
    test_mask = y_test != -1
    X_train_raw = X_train_raw[train_mask].astype(np.float32)
    y_train_raw = y_train_raw[train_mask].astype(np.int32)
    X_test = X_test[test_mask].astype(np.float32)
    y_test = y_test[test_mask].astype(np.int32)

    # Split training into train + validation
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_raw, y_train_raw,
        test_size=0.1,
        random_state=config.RANDOM_SEED,
        stratify=y_train_raw
    )

    logger.info(f"[+] Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # Run hardening pipeline
    model, suspicion_model, report = run_hardening(
        X_train, y_train,
        X_val, y_val,
        X_test, y_test
    )

    logger.info("\n[✓] Training Complete. Summary:")
    logger.info(f"    Baseline Evasion:    {report['baseline_evasion_rate']:.4f}")
    logger.info(f"    Final Evasion:       {report['final_evasion_rate']:.4f}")
    logger.info(f"    Antifragility Index: {report['antifragility_index']:.4f}")
    logger.info(f"    Report saved to:     {config.LOG_PATH}")


if __name__ == "__main__":
    main()