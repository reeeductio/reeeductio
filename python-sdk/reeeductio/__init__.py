"""
reeeductio - High-level SDK for reeeductio encrypted spaces.

This module provides a convenient, higher-level interface on top of the
auto-generated reeeductio_client. It handles cryptography, authentication,
and common workflows.
"""

from .client import Space
from .crypto import (
    Ed25519KeyPair,
    generate_keypair,
    sign_data,
    verify_signature,
    compute_hash,
)

__all__ = [
    "Space",
    "Ed25519KeyPair",
    "generate_keypair",
    "sign_data",
    "verify_signature",
    "compute_hash",
]

__version__ = "1.0.0"
