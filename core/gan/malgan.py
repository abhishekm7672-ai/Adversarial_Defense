import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

from .generator import Generator
from core import config


class SubstituteDetector(nn.Module):
    """
    Surrogate detector the Generator trains against.
    Periodically synced with the real detector's outputs.
    """

    def __init__(self, input_dim):
        super(SubstituteDetector, self).__init__()

        self.model = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.model(x)


class MalGAN:
    """
    Full MalGAN implementation.
    Generator learns to produce adversarial malware feature vectors that
    fool the SubstituteDetector, which is kept in sync with the real detector.
    Perturbations are strictly additive to preserve malware functionality.
    """

    def __init__(self, input_dim, device="cpu"):
        self.device = device
        self.input_dim = input_dim
        self.generator = Generator(input_dim).to(device)
        self.substitute = SubstituteDetector(input_dim).to(device)

        self.g_optimizer = optim.Adam(
            self.generator.parameters(), lr=config.GENERATOR_LR
        )
        self.d_optimizer = optim.Adam(
            self.substitute.parameters(), lr=config.DISCRIMINATOR_LR
        )

        self.criterion = nn.BCELoss()

    def train_substitute(self, X, y, epochs=None, batch_size=None):
        """
        Train the substitute detector on labelled data.
        Call this initially and after each hardening round to keep it synced.
        """
        epochs = epochs or config.GAN_EPOCHS
        batch_size = batch_size or config.GAN_BATCH_SIZE

        self.substitute.train()

        dataset = torch.utils.data.TensorDataset(
            torch.from_numpy(X).float(),
            torch.from_numpy(y).float().unsqueeze(1)
        )
        loader = torch.utils.data.DataLoader(
            dataset, batch_size=batch_size, shuffle=True
        )

        for _ in range(epochs):
            for xb, yb in loader:
                xb, yb = xb.to(self.device), yb.to(self.device)
                preds = self.substitute(xb)
                loss = self.criterion(preds, yb)
                self.d_optimizer.zero_grad()
                loss.backward()
                self.d_optimizer.step()

    def sync_substitute(self, real_detector_fn, X, batch_size=None):
        """
        Sync substitute with real detector's soft labels.
        real_detector_fn: callable that takes np array, returns probabilities.
        Call this after each hardening round so the GAN stays relevant.
        """
        batch_size = batch_size or config.GAN_BATCH_SIZE

        with torch.no_grad():
            soft_labels = real_detector_fn(X)  # shape (N,)

        soft_labels = soft_labels.astype(np.float32)
        self.train_substitute(X, soft_labels, epochs=3, batch_size=batch_size)

    def train_generator(self, X_malware, feature_min, feature_max,
                        epochs=None, batch_size=None, epsilon=None):
        """
        Train the generator to produce adversarial samples that fool
        the substitute detector. Perturbations are strictly additive.
        """
        epochs = epochs or config.GAN_EPOCHS
        batch_size = batch_size or config.GAN_BATCH_SIZE
        epsilon = epsilon or config.ADVERSARIAL_EPSILON

        self.generator.train()
        self.substitute.eval()

        dataset = torch.utils.data.TensorDataset(
            torch.from_numpy(X_malware).float()
        )
        loader = torch.utils.data.DataLoader(
            dataset, batch_size=batch_size, shuffle=True
        )

        fmin = torch.from_numpy(feature_min).float().to(self.device)
        fmax = torch.from_numpy(feature_max).float().to(self.device)

        if self.device == "cuda":
            torch.cuda.empty_cache()

        for _ in range(epochs):
            for (xb,) in loader:
                xb = xb.to(self.device)

                perturbation = self.generator(xb)
                adv_samples = xb + epsilon * perturbation

                # Clamp to valid feature range
                adv_samples = torch.clamp(adv_samples, fmin, fmax)

                # CRITICAL: Never decrease features — preserves malware functionality
                adv_samples = torch.max(adv_samples, xb)

                preds = self.substitute(adv_samples)

                # Generator wants substitute to output 0 (benign) — evasion goal
                target = torch.zeros_like(preds)
                loss = self.criterion(preds, target)

                self.g_optimizer.zero_grad()
                loss.backward()

                # Gradient clipping for training stability
                torch.nn.utils.clip_grad_norm_(
                    self.generator.parameters(), max_norm=1.0
                )

                self.g_optimizer.step()

    def generate(self, X_malware, feature_min, feature_max, epsilon=None):
        """
        Generate adversarial variants of malware feature vectors.
        Returns numpy array of same shape as input.
        """
        epsilon = epsilon or config.ADVERSARIAL_EPSILON

        self.generator.eval()

        X_tensor = torch.from_numpy(X_malware.astype(np.float32)).to(self.device)
        fmin = torch.from_numpy(feature_min.astype(np.float32)).to(self.device)
        fmax = torch.from_numpy(feature_max.astype(np.float32)).to(self.device)

        with torch.no_grad():
            perturbation = self.generator(X_tensor)
            adv_samples = X_tensor + epsilon * perturbation
            adv_samples = torch.clamp(adv_samples, fmin, fmax)
            adv_samples = torch.max(adv_samples, X_tensor)  # functionality preservation

        return adv_samples.cpu().numpy()

    def evasion_rate(self, X_adv, real_detector_fn):
        """
        Measure what % of generated adversarial samples evade the real detector.
        real_detector_fn: callable returning probabilities.
        Lower is better for the defender.
        """
        probs = real_detector_fn(X_adv)
        evaded = (probs < config.MALWARE_THRESHOLD).mean()
        return float(evaded)