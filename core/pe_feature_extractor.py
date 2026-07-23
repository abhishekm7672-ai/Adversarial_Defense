import pefile
import numpy as np


def extract_pe_features(file_path):
    pe = pefile.PE(file_path)

    features = []

    # File size
    features.append(pe.OPTIONAL_HEADER.SizeOfImage)

    # Number of sections
    features.append(len(pe.sections))

    # Imports
    imports = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports += len(entry.imports)

    features.append(imports)

    # Section entropy
    for section in pe.sections[:10]:
        features.append(section.get_entropy())

    # Pad to required dimension
    while len(features) < 518:
        features.append(0)

    return np.array(features[:518])