import numpy as np
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from core import config, behavior_features, malgan_generator, data_sanitizer
from inference import model_loader

def test_feature_dimensions():
    print("[+] Testing feature dimensions...")
    assert config.FEATURE_DIM == 522
    print("    [V] config.FEATURE_DIM is 522.")

def test_behavior_extraction():
    print("[+] Testing behavior feature extraction...")
    # Using a dummy file for testing
    dummy_path = "temp_test.exe"
    with open(dummy_path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 100)
    
    feats = behavior_features.extract_behavior_features(dummy_path)
    assert len(feats) == 4
    print(f"    [V] Behavioral features extracted: {feats}")
    
    if os.path.exists(dummy_path):
        os.remove(dummy_path)

def test_adversarial_generation():
    print("[+] Testing adversarial generation...")
    X = np.random.rand(10, 522)
    adv = malgan_generator.generate_adversarial_samples(X, num_samples=5)
    assert adv.shape == (5, 522)
    assert not np.array_equal(X[0], adv[0])
    print("    [V] Adversarial samples generated correctly.")

def test_data_sanitization():
    print("[+] Testing data sanitization...")
    X = np.random.rand(20, 522)
    # Add an outlier
    X[0] = X[0] * 100 
    y = np.random.randint(0, 2, 20)
    
    sanitizer = data_sanitizer.DataSanitizer(contamination=0.1)
    X_clean, y_clean = sanitizer.sanitize_training_data(X, y)
    
    assert len(X_clean) < len(X)
    print(f"    [V] Sanitizer removed {len(X) - len(X_clean)} outliers.")

def test_model_loader_prediction():
    print("[+] Testing ModelLoader prediction (Mocked)...")
    loader = model_loader.ModelLoader()
    
    # Mocking detector and suspicion for testing logic
    class MockDetector:
        def predict_proba(self, X): return np.array([0.8])
    class MockSuspicion:
        def predict(self, X): return np.array([0])
        
    loader.detector = MockDetector()
    loader.suspicion = MockSuspicion()
    
    X_test = np.random.rand(1, 522)
    results = loader.predict(X_test)
    
    assert "malware_probability" in results
    assert "suspicion_score" in results
    assert "decision" in results
    assert results["decision"] == "Malicious"
    print(f"    [V] ModelLoader prediction format correct: {results}")

if __name__ == "__main__":
    try:
        test_feature_dimensions()
        test_behavior_extraction()
        test_adversarial_generation()
        test_data_sanitization()
        test_model_loader_prediction()
        print("\n[ALL TESTS PASSED] Enterprise components are functional.")
    except Exception as e:
        print(f"\n[TEST FAILED] {e}")
        sys.exit(1)
