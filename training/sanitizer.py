import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from core import config

class DataSanitizer:
    """
    Filters out anomalous samples from incoming training data 
    to prevent poisoning attacks.
    """
    def __init__(self, contamination=config.SANITIZER_CONTAMINATION):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=config.RANDOM_SEED,
            n_jobs=-1
        )
        self.logger = logging.getLogger("DataSanitizer")

    def sanitize(self, X, y):
        """
        Fits on data and returns filtered X, y.
        """
        if len(X) < 10:  # Too small to sanitize reliably
            return X, y

        preds = self.model.fit_predict(X)
        mask = preds == 1  # 1 for inliers, -1 for outliers
        
        X_clean = X[mask]
        y_clean = y[mask]
        
        num_rejected = len(X) - len(X_clean)
        if num_rejected > 0:
            self.logger.warning(f"Rejected {num_rejected} samples as potential poisoning.")
            print(f"[!] Sanitizer: Rejected {num_rejected} samples.")
            
        return X_clean, y_clean
