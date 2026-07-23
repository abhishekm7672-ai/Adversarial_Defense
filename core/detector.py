import torch
import torch.nn as nn
import torch.optim as optim
from . import config


class XDRDetector(nn.Module):
    """
    PyTorch neural network detector.
    Used as the primary GAN-compatible discriminator.
    Dropout layers prevent overfitting to specific adversarial styles.
    """

    def __init__(self):
        super(XDRDetector, self).__init__()

        self.network = nn.Sequential(
            nn.Linear(config.NUM_FEATURES, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)


def train_detector(model, X_train, y_train, batch_size=256, verbose=False):
    """
    Trains the XDRDetector with mini-batch SGD.
    Returns the trained model.
    """
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=config.LEARNING_RATE)

    dataset = torch.utils.data.TensorDataset(
        torch.FloatTensor(X_train),
        torch.FloatTensor(y_train).unsqueeze(1)
    )
    loader = torch.utils.data.DataLoader(
        dataset, batch_size=batch_size, shuffle=True
    )

    model.train()  # ensure train mode before loop

    for epoch in range(config.EPOCHS):
        epoch_loss = 0.0
        for X_batch, y_batch in loader:
            optimizer.zero_grad()              # zero before forward pass
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        if verbose and (epoch + 1) % 10 == 0:
            avg_loss = epoch_loss / len(loader)
            print(f"  Epoch {epoch+1}/{config.EPOCHS} — Loss: {avg_loss:.4f}")

    model.eval()
    return model


def predict_proba(model, X):
    """
    Returns malware probability scores as numpy array.
    Safe for single-sample and batch inference.
    """
    model.eval()
    with torch.no_grad():
        tensor = torch.FloatTensor(X)
        outputs = model(tensor)
    return outputs.numpy().flatten()