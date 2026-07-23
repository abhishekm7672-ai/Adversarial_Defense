@echo off
echo [%date% %time%] Starting Navigo retraining... >> C:\Users\HP\Desktop\Adversarial_Defense\logs\retrain.log
cd C:\Users\HP\Desktop\Adversarial_Defense
C:\Users\HP\Desktop\Adversarial_Defense\venv\Scripts\python.exe training/train_model.py >> C:\Users\HP\Desktop\Adversarial_Defense\logs\retrain.log 2>&1
echo [%date% %time%] Retraining complete. >> C:\Users\HP\Desktop\Adversarial_Defense\logs\retrain.log
