import json
import numpy as np
from . import config
from .reproducibility import set_seed


def _load_jsonl(path):
    X = []
    y = []

    with open(path, "r") as f:
        for line in f:
            sample = json.loads(line)
            label = sample["label"]

            # Filter out unlabeled samples (-1)
            if label == -1:
                continue

            # EMBER 2018 structure
            features = []

            # Concatenate important numeric feature groups
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


def load_temporal_split_dataset():
    """
    Loads EMBER dataset with strict 4-way separation:
    - Train: Shards 0-2
    - Val: Shard 3
    - Test: Shard 4
    - Zero-Day: Shard 5
    """
    set_seed()
    data_path = config.DATA_PATH

    print(f"\n[+] Loading Temporal Split Dataset from {data_path}...")

    def log_distribution(name, y):
        unique, counts = np.unique(y, return_counts=True)
        dist = dict(zip(unique, counts))
        print(f"    {name} Distribution: {dist}")
        return dist

    # Helper to load multiple shards
    def load_shards(shards):
        X_list, y_list = [], []
        for s in shards:
            X_p, y_p = _load_jsonl(data_path / f"train_features_{s}.jsonl")
            X_list.append(X_p)
            y_list.append(y_p)
        return np.vstack(X_list), np.hstack(y_list)

    # 1. Train set (Shards 0, 1, 2)
    X_train, y_train = load_shards([0, 1, 2])
    log_distribution("Train", y_train)

    # 2. Validation set (Shard 3)
    X_val, y_val = load_shards([3])
    log_distribution("Validation", y_val)

    # 3. Test set (Shard 4 - Generalization)
    X_test, y_test = load_shards([4])
    log_distribution("Test", y_test)

    # 4. Zero-Day set (Shard 5 - Future/Attack)
    X_zeroday, y_zeroday = load_shards([5])
    log_distribution("Zero-Day", y_zeroday)

    # Defensive checks
    sets = [
        ("Train", y_train), 
        ("Validation", y_val), 
        ("Test", y_test), 
        ("Zero-Day", y_zeroday)
    ]
    for name, y in sets:
        unique = np.unique(y)
        if len(unique) < 2:
            raise ValueError(f"CRITICAL: {name} set only contains one class {unique}.")
        if not set(unique).issubset({0, 1}):
            raise ValueError(f"CRITICAL: {name} set contains invalid labels: {unique}.")

    print("\n[V] Dataset loaded and validated with strict separation.")
    return X_train, y_train, X_val, y_val, X_test, y_test, X_zeroday, y_zeroday
