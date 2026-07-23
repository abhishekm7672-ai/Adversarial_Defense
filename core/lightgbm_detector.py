import lightgbm as lgb
import numpy as np
import joblib
from core import config


class LightGBMDetector:
    """
    Enterprise-grade LightGBM detector with strict memory safety 
    and adversarial feedback support.
    """
    def __init__(self):
        # Already set n_jobs=-1 and random_state in config.LGB_PARAMS
        self.model = lgb.LGBMClassifier(**config.LGB_PARAMS)
        self.is_trained = False

    def _cast(self, X, y=None):
        """Internal helper to enforce float32/int32 types."""
        X_cast = np.asarray(X, dtype=np.float32)
        if y is not None:
            y_cast = np.asarray(y, dtype=np.int32)
            return X_cast, y_cast
        return X_cast

    def train(self, X, y, X_val=None, y_val=None):
        """
        Trains the detector with safe type casting and validation support.
        Adapts to LightGBM 4.x callback-based logging.
        """
        X, y = self._cast(X, y)
        unique_classes = np.unique(y)
        
        print("\n[DEBUG] Training Class Distribution:",
              {int(c): int((y == c).sum()) for c in unique_classes})

        if len(unique_classes) < 2:
            raise ValueError("Training requires both classes (0 and 1).")

        # Prepare callbacks for LightGBM 4.x
        callbacks = [lgb.log_evaluation(period=10)]

        if X_val is not None and y_val is not None:
            X_val, y_val = self._cast(X_val, y_val)
            self.model.fit(
                X, y,
                eval_set=[(X_val, y_val)],
                eval_metric="binary_logloss",
                callbacks=callbacks
            )
        else:
            self.model.fit(X, y, callbacks=callbacks)

        self.is_trained = True

    def evaluate(self, X, y):
        """Calculates accuracy with strict typing."""
        X, y = self._cast(X, y)
        if not self.is_trained:
            return 0.0
        preds = self.model.predict(X)
        return (preds == y).mean()

    def predict(self, X):
        """Binary predictions (0/1)."""
        X = self._cast(X)
        return self.model.predict(X)

    def predict_proba(self, X):
        """Malware probability score."""
        X = self._cast(X)
        return self.model.predict_proba(X)[:, 1]

    def save(self):
        """Save model to enterprise registry."""
        config.MODEL_SAVE_PATH.mkdir(parents=True, exist_ok=True)
        save_path = config.MODEL_SAVE_PATH / "lgb_model.pkl"
        joblib.dump(self.model, save_path)
        print(f"[+] Model saved to {save_path}")

    def load(self):
        """Load model from enterprise registry."""
        load_path = config.MODEL_SAVE_PATH / "lgb_model.pkl"
        if not load_path.exists():
            raise FileNotFoundError(f"Model artifact not found at {load_path}")
        self.model = joblib.load(load_path)
        self.is_trained = True
        print(f"[+] Model loaded from {load_path}")
