FROM python:3.11-slim

# System dependencies for PE feature extraction
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY core/ ./core/
COPY inference/ ./inference/
COPY training/ ./training/
COPY app/ ./app/

# Create required directories
RUN mkdir -p models logs data

# Non-root user for security
RUN useradd -m -u 1000 navigo && chown -R navigo:navigo /app
USER navigo

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "inference.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]