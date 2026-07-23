import numpy as np
from sklearn.metrics import roc_curve


def find_optimal_threshold(y_true, y_probs, min_recall=0.80):
    """
    Select threshold using ROC curve.
    Goal:
        - Maintain recall >= min_recall
        - Minimize FPR

    Returns:
        best_threshold
    """

    fpr, tpr, thresholds = roc_curve(y_true, y_probs)

    best_threshold = 0.5
    best_fpr = 1.0

    for i in range(len(thresholds)):
        if tpr[i] >= min_recall:
            if fpr[i] < best_fpr:
                best_fpr = fpr[i]
                best_threshold = thresholds[i]

    return best_threshold