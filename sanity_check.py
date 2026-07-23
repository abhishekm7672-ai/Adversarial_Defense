import numpy as np
import psutil
import os
import sys

def get_ram_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

print(f"Python version: {sys.version}")
print(f"Numpy version: {np.version.version}")
print(f"RAM usage: {get_ram_usage():.2f} MB")
print("Sanity check passed.")
