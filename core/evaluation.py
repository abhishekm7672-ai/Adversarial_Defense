import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)


def evaluate_layered(y_true, y_pred, suspicion_flags):

    # Force strict binary
    y_true = np.array(y_true).astype(int)
    y_pred = np.array(y_pred).astype(int)
    suspicion_flags = np.array(suspicion_flags).astype(int)

    # Safety clamp to 0/1
    y_pred = np.where(y_pred > 0, 1, 0)
    y_true = np.where(y_true > 0, 1, 0)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    precision = precision_score(
        y_true,
        y_pred,
        average="binary",
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        average="binary",
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        average="binary",
        zero_division=0
    )

    fpr = fp / (fp + tn + 1e-10)
    tpr = recall

    suspicion_trigger_rate = suspicion_flags.mean()

    return {
        "True Negatives": int(tn),
        "False Positives": int(fp),
        "False Negatives": int(fn),
        "True Positives": int(tp),
        "Precision": float(precision),
        "Recall (TPR)": float(tpr),
        "F1 Score": float(f1),
        "False Positive Rate": float(fpr),
        "Suspicion Trigger Rate": float(suspicion_trigger_rate)
    }