import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from . import config


class SuspicionModel:

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=config.SANITIZER_CONTAMINATION,
            random_state=config.RANDOM_SEED,
            n_jobs=-1
        )
        self.is_trained = False

    def train(self, X_benign):
        self.model.fit(X_benign)
        self.is_trained = True

    def score_samples(self, X):
        if not self.is_trained:
            raise RuntimeError("SuspicionModel must be trained before scoring")
        raw = self.model.decision_function(X)
        # Normalise to [0, 1] where 1 = most suspicious
        min_val = raw.min()
        max_val = raw.max()
        if max_val == min_val:
            return np.zeros(len(X))
        normalised = 1 - (raw - min_val) / (max_val - min_val + 1e-9)
        return normalised

    def predict(self, X):
        """
        Returns binary flags.
        1 = suspicious (anomaly), 0 = normal.
        """
        preds = self.model.predict(X)
        # IsolationForest returns -1 for anomalies and 1 for inliers.
        # We map -1 -> 1 (suspicious) and 1 -> 0 (normal).
        return np.where(preds == -1, 1, 0)

    def save(self):
        config.MODEL_SAVE_PATH.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, config.MODEL_SAVE_PATH / "suspicion_model.pkl")

    def load(self):
        self.model = joblib.load(config.MODEL_SAVE_PATH / "suspicion_model.pkl")
        self.is_trained = True