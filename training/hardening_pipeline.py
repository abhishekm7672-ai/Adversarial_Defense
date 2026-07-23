import numpy as np
import json
import logging

from core.lightgbm_detector import LightGBMDetector
from core.suspicion import SuspicionModel
from core.data_sanitizer import sanitize_training_data
from core.reproducibility import set_seed
from core.antifragility import AntifragilityMetric
from core.gan.malgan import MalGAN
from core import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HardeningPipeline")


def expand_features(X):
    """Pad 518 EMBER features to 522 with neutral behavioral values."""
    if X.shape[1] == 518:
        behavioral = np.zeros((len(X), 4), dtype=np.float32)
        behavioral[:, 0] = 0.5  # neutral entropy
        return np.concatenate([X, behavioral], axis=1)
    return X


def compute_evasion_rate(model, X_malware, malgan, feature_min, feature_max):
    """
    Generate adversarial samples and measure how many evade the detector.
    Returns evasion_rate (lower = better for defender).
    """
    if len(X_malware) == 0:
        return 0.0

    X_adv = malgan.generate(X_malware, feature_min, feature_max)
    probs = model.predict_proba(X_adv)
    evasion_rate = float((probs < config.MALWARE_THRESHOLD).mean())
    return evasion_rate


def run_hardening(X_train, y_train, X_val, y_val, X_test, y_test):
    """
    Full adversarial hardening pipeline.
    Implements the Competitive Learning Loop from spec:
        Attack (MalGAN) -> Detect -> Retrain -> Sanitize

    Returns: (hardened_model, suspicion_model, report_dict)
    """
    set_seed()

    # Ensure 522-dim features throughout
    X_train = expand_features(X_train).astype(np.float32)
    X_val   = expand_features(X_val).astype(np.float32)
    X_test  = expand_features(X_test).astype(np.float32)
    y_train = y_train.astype(np.int32)
    y_val   = y_val.astype(np.int32)
    y_test  = y_test.astype(np.int32)

    # Feature bounds for functionality-preserving perturbations
    feature_min = X_train.min(axis=0)
    feature_max = X_train.max(axis=0)

    # --- Initialise Models ---
    logger.info("[+] Training baseline detector...")
    model = LightGBMDetector()
    model.train(X_train, y_train, X_val, y_val)

    suspicion_model = SuspicionModel()
    suspicion_model.train(X_train[y_train == 0])

    # --- Initialise MalGAN ---
    logger.info("[+] Initialising MalGAN...")
    malgan = MalGAN(input_dim=config.FEATURE_DIM, device="cpu")
    malgan.train_substitute(X_train, y_train.astype(np.float32))

    # --- Baseline Evasion Rate ---
    X_mal_test = X_test[y_test == 1]
    logger.info("[+] Measuring baseline evasion rate...")
    baseline_evasion = compute_evasion_rate(
        model, X_mal_test, malgan, feature_min, feature_max
    )
    logger.info(f"    Baseline Evasion Rate: {baseline_evasion:.4f}")

    antifragility = AntifragilityMetric()
    antifragility.set_baseline(baseline_evasion)

    history = []

    # --- Hardening Loop ---
    for r in range(config.HARDENING_ROUNDS):
        logger.info(f"\n[Hardening Round {r+1}/{config.HARDENING_ROUNDS}]")

        X_mal_train = X_train[y_train == 1]

        # 1. ATTACK — sync GAN with real detector, then generate adversarial samples
        logger.info("    [Attack] Syncing GAN with current detector...")
        malgan.sync_substitute(model.predict_proba, X_val)

        logger.info("    [Attack] Training generator...")
        malgan.train_generator(
            X_mal_train, feature_min, feature_max,
            epochs=config.GAN_EPOCHS
        )

        logger.info("    [Attack] Generating adversarial variants...")
        X_adv = malgan.generate(X_mal_train, feature_min, feature_max)
        y_adv = np.ones(len(X_adv), dtype=np.int32)

        # 2. DETECT — find samples that currently evade the model
        logger.info("    [Detect] Identifying evasive samples...")
        probs = model.predict_proba(X_adv)
        evading_mask = probs < config.MALWARE_THRESHOLD
        X_to_add = X_adv[evading_mask]
        y_to_add = y_adv[evading_mask]

        if len(X_to_add) == 0:
            logger.info("    [!] No evasive samples found — model already robust this round.")
            current_evasion = compute_evasion_rate(
                model, X_mal_test, malgan, feature_min, feature_max
            )
            antifragility.update(r + 1, current_evasion)
            history.append({
                "round": r + 1,
                "evasion_rate": current_evasion,
                "samples_added": 0
            })
            continue

        logger.info(f"    [Buffer] {len(X_to_add)} evasive samples found.")

        # 3. SANITIZE — poisoning protection before retraining
        logger.info("    [Sanitize] Cleaning combined training data...")
        X_combined = np.concatenate([X_train, X_to_add], axis=0)
        y_combined = np.concatenate([y_train, y_to_add], axis=0)
        X_clean, y_clean = sanitize_training_data(X_combined, y_combined)
        logger.info(f"    [Sanitize] {len(X_clean)} clean samples retained.")

        # 4. RETRAIN
        logger.info(f"    [Retrain] Retraining detector on {len(X_clean)} samples...")
        model = LightGBMDetector()
        model.train(X_clean, y_clean, X_val, y_val)

        # Update training set for next round
        X_train = X_clean
        y_train = y_clean

        # 5. MEASURE
        current_evasion = compute_evasion_rate(
            model, X_mal_test, malgan, feature_min, feature_max
        )
        logger.info(f"    [Metric] Evasion Rate: {current_evasion:.4f}")

        antifragility.update(r + 1, current_evasion)
        history.append({
            "round": r + 1,
            "evasion_rate": current_evasion,
            "samples_added": int(len(X_to_add))
        })

    # --- Final Metrics ---
    final_evasion = history[-1]["evasion_rate"] if history else baseline_evasion
    af_summary = antifragility.summary()

    logger.info(f"\n[✓] Hardening Complete.")
    logger.info(f"    Baseline Evasion:      {baseline_evasion:.4f}")
    logger.info(f"    Final Evasion:         {final_evasion:.4f}")
    logger.info(f"    Antifragility Index:   {af_summary['antifragility_index']:.4f}")
    logger.info(f"    Monotonic Improvement: {af_summary['monotonically_improving']}")

    # --- Save Production Artifacts ---
    model.save()
    suspicion_model.save()

    report = {
        "model_version": config.MODEL_VERSION,
        "baseline_evasion_rate": baseline_evasion,
        "final_evasion_rate": final_evasion,
        "antifragility_index": af_summary["antifragility_index"],
        "monotonically_improving": af_summary["monotonically_improving"],
        "rounds": history
    }

    config.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(config.LOG_PATH, "w") as f:
        json.dump(report, f, indent=4)

    logger.info(f"    Report saved to {config.LOG_PATH}")

    return model, suspicion_model, report