# =============================================================================
#  MIDGUARD — Dockerfile (Optimized for local ML models)
# =============================================================================

FROM python:3.11-slim

# Install system dependencies required to compile SpaCy's C-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the OPTIMIZED SpaCy model (Small is 10x faster than Large in CPU-only Docker)
RUN python -m spacy download en_core_web_sm

# Copy application code
COPY . .

# Expose gateway port
EXPOSE 8000

# Start the gateway
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]