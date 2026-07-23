import sys
import os
# Add project root to Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import streamlit as st
import torch
import numpy as np
import matplotlib.pyplot as plt

from core.dataset import load_data
from core.detector import XDRDetector, train_detector
from core.orchestrator import hardening_pipeline
from core import config

st.set_page_config(page_title="Adversarial Defense XDR", layout="wide")

st.title("🛡 Adversarial Defense - Production Prototype")
st.subheader("Multi-Round Adversarial Hardening Engine")

st.markdown("---")

# Load dataset
X_train, X_test, y_train, y_test = load_data()

# Baseline model
model = XDRDetector()
model = train_detector(model, X_train, y_train)
model.eval()

# Baseline evaluation
X_test_tensor = torch.FloatTensor(X_test)
y_test_tensor = torch.FloatTensor(y_test).unsqueeze(1)

with torch.no_grad():
    outputs = model(X_test_tensor)
    predictions = (outputs > 0.5).float()
    baseline_accuracy = (predictions == y_test_tensor).float().mean().item()

# Baseline adversarial evasion
malware_mask = y_test == 1
X_malware = X_test[malware_mask]
y_malware = y_test[malware_mask]

from core.orchestrator import fgsm_attack, evaluate_evasion

baseline_adv = fgsm_attack(model, X_malware, y_malware)
baseline_evasion = evaluate_evasion(model, baseline_adv)

st.success(f"Baseline Accuracy: {baseline_accuracy:.4f}")
st.error(f"Baseline Evasion Rate: {baseline_evasion:.4f}")

st.markdown("---")

if st.button("🛡 Run Multi-Round Adversarial Hardening"):

    with st.spinner("Running adversarial hardening rounds..."):
        hardened_model, logs = hardening_pipeline(
            X_train, y_train, X_test, y_test
        )

    final_evasion = logs[-1]["evasion"]
    antifragility_score = baseline_evasion - final_evasion

    st.success(f"Final Evasion After Hardening: {final_evasion:.4f}")
    st.info(f"Antifragility Score: {antifragility_score:.4f}")

    # Plot round-by-round curve
    rounds = [entry["round"] for entry in logs]
    evasions = [entry["evasion"] for entry in logs]

    fig, ax = plt.subplots()
    ax.plot(rounds, evasions, marker="o")
    ax.set_xlabel("Hardening Round")
    ax.set_ylabel("Evasion Rate")
    ax.set_title("Evasion Rate Across Hardening Rounds")

    st.pyplot(fig)