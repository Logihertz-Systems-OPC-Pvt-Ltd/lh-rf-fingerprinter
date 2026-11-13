"""lh-rf-fingerprinter: Physical-Layer RF Transmitter Fingerprinting Engine & Posture Auditor.

Part of the Logihertz 60-Tool Open-Source Ecosystem.
Copyright (C) 2026 Logihertz Systems (OPC) Private Limited.
Architected and authored by Sameer Tawade (ops@logihertz.com).
"""

__version__ = "0.1.0"
__author__ = "Sameer Tawade"
__email__ = "ops@logihertz.com"
__license__ = "Apache-2.0"

from .rf_features import (
    RFFeatureVector,
    IQBurst,
    extract_rf_features,
    synthesize_impaired_iq_burst,
)
from .classifier import (
    TransmitterProfile,
    TransmitterDatabase,
    ClassificationResult,
    MahalanobisClassifier,
)
from .auditor import (
    RFFPostureConfig,
    AuditFinding,
    AuditReport,
    evaluate_policy,
)

__all__ = [
    "__version__",
    "RFFeatureVector",
    "IQBurst",
    "extract_rf_features",
    "synthesize_impaired_iq_burst",
    "TransmitterProfile",
    "TransmitterDatabase",
    "ClassificationResult",
    "MahalanobisClassifier",
    "RFFPostureConfig",
    "AuditFinding",
    "AuditReport",
    "evaluate_policy",
]
