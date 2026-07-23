import numpy as np
from core import config
from core.lightgbm_detector import LightGBMDetector
from core.suspicion import SuspicionModel
from core.data_sanitizer import sanitize_training_data


class ModelLoader:
    """
    Handles loading, caching, and inference for all production models.
    Risk score = (RISK_ALPHA * malware_prob) + (RISK_BETA * suspicion_score)
    """

    def __init__(self):
        self.detector = LightGBMDetector()
        self.suspicion = SuspicionModel()
        self.version_tag = config.MODEL_VERSION
        self._loaded = False

    def load_models(self):
        """Load trained models from models/ directory."""
        try:
            self.detector.load()
            self.suspicion.load()
            self._loaded = True
            print(f"[+] Inference Engine Loaded (Version: {self.version_tag})")
        except Exception as e:
            self._loaded = False
            print(f"[!] Model load failed: {e}")
            raise e

    def is_ready(self):
        """Returns True if all models are loaded and ready for inference."""
        return self._loaded and self.suspicion.is_trained

    def predict(self, X):
        """
        Full inference pipeline. Accepts list or (1, 522) numpy array.
        Returns risk-fused score, individual scores, and decision.
        """
        if not isinstance(X, np.ndarray):
            X = np.array(X, dtype=np.float32)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        if X.shape[1] != config.FEATURE_DIM:
            if X.shape[1] == 518:
                X = np.pad(X, ((0, 0), (0, 4)), mode='constant')
            else:
                raise ValueError(
                    f"Expected {config.FEATURE_DIM} features, got {X.shape[1]}"
                )

        # Malware probability from LightGBM
        malware_prob = float(self.detector.predict_proba(X)[0])

        # Normalised suspicion score from IsolationForest [0, 1]
        raw_suspicion = self.suspicion.score_samples(X)
        suspicion_score = float(raw_suspicion[0])

        # Risk fusion
        final_risk_score = (
            config.RISK_ALPHA * malware_prob +
            config.RISK_BETA * suspicion_score
        )

        return {
            "malware_prob": malware_prob,
            "suspicion_score": suspicion_score,
            "risk_score": final_risk_score,
        }

    def extract_pe_features(self, file_bytes: bytes) -> list:
        """Extract static PE features from raw file bytes."""
        import tempfile, os
        from core.pe_feature_extractor import extract_pe_features
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            # File is closed here — now safe to read with pefile
            features = extract_pe_features(tmp_path)
            features = list(features) + [0, 0, 0, 0]
            return features
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

    def train(self, X_train, y_train, X_val, y_val):
        """
        Competitive training step using the real MalGAN generator.
        Attack -> Sanitize -> Retrain
        """
        print("[+] Starting Competitive Training Step...")

        X_malware = X_train[y_train == 1]

        if len(X_malware) > 0:
            feature_min = X_train.min(axis=0)
            feature_max = X_train.max(axis=0)

            from core.gan.malgan import MalGAN
            malgan = MalGAN(
                input_dim=config.FEATURE_DIM,
                device="cpu"
            )

            malgan.train_substitute(X_train, y_train.astype(np.float32))
            malgan.sync_substitute(self.detector.predict_proba, X_val)
            malgan.train_generator(X_malware, feature_min, feature_max)

            X_adv = malgan.generate(X_malware, feature_min, feature_max)
            y_adv = np.ones(len(X_adv), dtype=y_train.dtype)

            X_combined = np.concatenate([X_train, X_adv])
            y_combined = np.concatenate([y_train, y_adv])
        else:
            X_combined, y_combined = X_train, y_train

        X_clean, y_clean = sanitize_training_data(X_combined, y_combined)

        self.detector.train(X_clean, y_clean, X_val, y_val)
        self.detector.save()
        self._loaded = True

        print("[✓] Competitive Training Step Complete.")


# ---------------------------------------------------------------------------
# Singleton — import this everywhere
# ---------------------------------------------------------------------------

_loader: ModelLoader = None


def get_model_loader() -> ModelLoader:
    """Returns the singleton ModelLoader, loading models on first call."""
    global _loader
    if _loader is None:
        _loader = ModelLoader()
        _loader.load_models()
    return _loader