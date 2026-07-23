import os
import json
import numpy as np
from . import config

DATA_PATH = os.path.join("data", "ember2018")

def load_jsonl(path):
    X = []
    y = []
    print(f"    Loading {os.path.basename(path)}...")
    with open(path, "r") as f:
        for line in f:
            sample = json.loads(line)
            label = sample["label"]
            if label == -1:
                continue
            features = []
            features.extend(sample["histogram"])
            features.extend(sample["byteentropy"])
            features.append(sample["strings"]["numstrings"])
            features.append(sample["strings"]["avlength"])
            features.append(sample["strings"]["entropy"])
            features.append(sample["general"]["size"])
            features.append(sample["general"]["vsize"])
            features.append(sample["general"]["imports"])
            X.append(features)
            y.append(label)
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)

def load_data():
    print("Loading EMBER dataset...")
    X_list = []
    y_list = []

    for i in range(6):
        file_path = os.path.join(DATA_PATH, f"train_features_{i}.jsonl")
        X, y = load_jsonl(file_path)
        X_list.append(X)
        y_list.append(y)

    X_train = np.vstack(X_list)
    y_train = np.hstack(y_list)

    test_path = os.path.join(DATA_PATH, "test_features.jsonl")
    X_test, y_test = load_jsonl(test_path)

    print(f"Train shape: {X_train.shape}")
    print(f"Test shape: {X_test.shape}")

    return X_train, X_test, y_train, y_test                                                                                                                                                                                                                                       