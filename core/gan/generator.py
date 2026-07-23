import torch
import torch.nn as nn
from core import config


class Generator(nn.Module):
    """
    MalGAN-style Generator.
    Produces bounded, additive perturbations to malware feature vectors.
    Sigmoid output ensures perturbations are always in [0, 1] — never subtractive,
    preserving malware functionality as required by spec.
    """

    def __init__(self, input_dim, latent_dim=config.LATENT_DIM):
        super(Generator, self).__init__()

        self.latent_dim = latent_dim

        self.model = nn.Sequential(
            nn.Linear(input_dim + self.latent_dim, 512),
            nn.ReLU(),
            nn.BatchNorm1d(512),

            nn.Linear(512, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),

            nn.Linear(256, input_dim),
            nn.Sigmoid()  # Changed from Tanh: ensures perturbations in [0,1], always additive
        )

    def forward(self, x):
        batch_size = x.size(0)
        z = torch.randn(batch_size, self.latent_dim, device=x.device)
        combined = torch.cat((x, z), dim=1)
        perturbation = self.model(combined)
        return perturbation