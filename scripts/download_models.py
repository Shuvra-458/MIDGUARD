#!/usr/bin/env python
# =============================================================================
#  scripts/download_models.py
#  Pre-download DeBERTa model during Docker build
# =============================================================================

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def download_deberta():
    """Download and cache DeBERTa model."""
    try:
        from transformers import pipeline
        
        logger.info("=" * 60)
        logger.info("Pre-downloading DeBERTa model...")
        logger.info("=" * 60)
        
        # Set cache directory
        os.environ["HF_HOME"] = "/app/.cache/huggingface"
        os.environ["TRANSFORMERS_CACHE"] = "/app/.cache/huggingface/transformers"
        
        # Create cache directory
        os.makedirs("/app/.cache/huggingface", exist_ok=True)
        
        # Download and cache the model
        logger.info("Downloading protectai/deberta-v3-base-prompt-injection-v2...")
        classifier = pipeline(
            "text-classification",
            model="protectai/deberta-v3-base-prompt-injection-v2",
            top_k=2,
            device=-1
        )
        
        # Test the model with a sample
        logger.info("Testing model with sample input...")
        result = classifier("Hello, this is a test message.")
        logger.info("Model test successful!")
        
        logger.info("=" * 60)
        logger.info("DeBERTa model pre-downloaded successfully!")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Failed to download DeBERTa model: {e}")
        return False

if __name__ == "__main__":
    download_deberta()