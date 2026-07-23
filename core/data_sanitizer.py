import numpy as np
from sklearn.ensemble import IsolationForest


class DataSanitizer:

    def __init__(self):
        self.detector = IsolationForest(contamination=0.01, random_state=42)

    def sanitize(self, X, y):

        print("Running data sanitizer...")

        preds = self.detector.fit_predict(X)

        mask = preds == 1

        removed = np.sum(preds == -1)

        print(f"Removed {removed} suspicious samples")

        return X[mask], y[mask]


# compatibility function for hardening pipeline
def sanitize_training_data(X, y):

    sanitizer = DataSanitizer()

    return sanitizer.sanitize(X, y)