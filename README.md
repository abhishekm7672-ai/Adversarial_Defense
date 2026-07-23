# Adversarial Malware Defense System

Enterprise-ready malware detection system hardened against adversarial evasion using GAN-driven training.

## Project Structure

```
/training       - Competitive hardening pipeline & metrics
/inference      - Production FastAPI service
/core           - Shared modules (detector, dataset, config)
/models         - Saved model artifacts & metadata
/data           - EMBER dataset shards
Dockerfile      - Containerization
requirements.txt - Dependencies
```

## Setup

1. **Environment**:
   ```bash
   pip install -r requirements.txt
   cp .env.example .env
   ```

2. **Data**:
   Ensure EMBER 2018 shards are in `data/ember2018/`.

## Training

Run the adversarial hardening pipeline:
```bash
python -m training.train_model
```
This will:
- Load data with strict 4-way separation.
- Run a 7-round competitive attack-detect-retrain loop.
- Apply `DataSanitizer` to prevent poisoning.
- Calculate the **Antifragility Index**.
- Save logs to `logs/training_log.json`.

## Inference API

### Run Service
```bash
uvicorn inference.main:app --host 0.0.0.0 --port 8000
```
OR use Docker:
```bash
docker build -t navigo-defense .
docker run -p 8000:8000 navigo-defense
```

### Endpoints
- **POST /predict**:
  Headers: `Authorization: Bearer NavigoInternalKey-2026`
  Body: `{"features": [...]}`
  Returns: `malware_probability`, `suspicion_score`, `final_risk_score`, `decision`.

## KPI Reporting
Final metrics are stored in `logs/training_log.json` and `models/metadata.json`.
- **Antifragility Index**: Measures robustness gain per unit of attack diversity.
- **Evasion Rate**: Tracked per round in logs.
