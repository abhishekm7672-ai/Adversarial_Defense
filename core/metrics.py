import numpy as np

def calculate_evasion_rate(model, X_test, y_test, epsilon):
    malware_samples = X_test[y_test == 1]

    adversarial_samples = malware_samples + epsilon * np.sign(
        np.random.randn(*malware_samples.shape)
    )

    adversarial_samples = np.clip(adversarial_samples, 0, 1)

    predictions = model.predict(adversarial_samples)

    evasion_rate = 1 - np.mean(predictions)
    return evasion_rate