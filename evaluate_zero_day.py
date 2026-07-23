import json
import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from core import config

print("Loading model...")
model = joblib.load("models/lgb_model.pkl")

X = []
y = []

print("Reading JSONL dataset...")

with open("data/ember2018/test_features.jsonl", "r") as f:
    for line in f:
        data = json.loads(line)

        # Build the same 518 feature vector used in training
        features = []

        features.extend(data["histogram"])
        features.extend(data["byteentropy"])

        features.append(data["strings"]["numstrings"])
        features.append(data["strings"]["avlength"])
        features.append(data["strings"]["entropy"])

        features.append(data["general"]["size"])
        features.append(data["general"]["vsize"])
        features.append(data["general"]["imports"])

        X.append(features)
        y.append(data["label"])

X = np.array(X)
y = np.array(y)

print("Running predictions...")

y_pred = model.predict(X)
y_prob = model.predict_proba(X)[:,1]

print("Calculating metrics...")

tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()

precision = precision_score(y, y_pred)
recall = recall_score(y, y_pred)
f1 = f1_score(y, y_pred)

fpr = fp / (fp + tn)

# Suspicion trigger
suspicious = y_prob > config.SUSPICION_THRESHOLD
suspicion_rate = np.mean(suspicious)

print("\n==============================")
print("Zero-Day Deployment Results")
print("==============================")

print(f"True Negatives (TN): {tn}")
print(f"False Positives (FP): {fp}")
print(f"False Negatives (FN): {fn}")
print(f"True Positives (TP): {tp}")

print("\nPerformance Metrics:\n")

print(f"Precision: {precision*100:.2f}%")
print(f"Recall (True Positive Rate): {recall*100:.2f}%")
print(f"F1 Score: {f1*100:.2f}%")
print(f"False Positive Rate (FPR): {fpr*100:.2f}%")
print(f"Suspicion Trigger Rate: {suspicion_rate*100:.2f}%")