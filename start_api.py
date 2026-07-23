import torch
import uvicorn
import os
import sys

# Ensure root is in path
sys.path.append(os.getcwd())

if __name__ == "__main__":
    print("[+] Starting Navigo API with torch pre-loaded...")
    uvicorn.run("inference.main:app", host="0.0.0.0", port=8000, reload=False)
