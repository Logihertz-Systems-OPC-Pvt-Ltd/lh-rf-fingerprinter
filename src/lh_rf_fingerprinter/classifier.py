"""Mahalanobis Distance Transmitter Authentication & Spoofer Detection.

Authenticates physical-layer RF transmitters using 6-dimensional radiometric
biometric feature vectors, detects Layer-2 MAC address spoofing, and flags
exact digital IQ waveform replay attacks.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .rf_features import IQBurst, RFFeatureVector, extract_rf_features


@dataclass
class TransmitterProfile:
    """Enrolled physical-layer RF biometric profile for an authorized transmitter."""

    transmitter_id: str
    hardware_model: str
    mean_vector: List[float]  # 6D: [cfo_hz, gain_db, skew_deg, dc_i, dc_q, phase_noise_rms_deg]
    std_vector: List[float]   # 6D standard deviations
    enrolled_at_utc: str = "2026-11-13T00:00:00Z"
    burst_count: int = 100
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.mean_vector) != 6:
            raise ValueError(f"mean_vector must contain exactly 6 features, got {len(self.mean_vector)}")
        if len(self.std_vector) != 6:
            raise ValueError(f"std_vector must contain exactly 6 features, got {len(self.std_vector)}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transmitter_id": self.transmitter_id,
            "hardware_model": self.hardware_model,
            "mean_vector": [round(x, 4) for x in self.mean_vector],
            "std_vector": [round(x, 4) for x in self.std_vector],
            "enrolled_at_utc": self.enrolled_at_utc,
            "burst_count": self.burst_count,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TransmitterProfile:
        return cls(
            transmitter_id=str(data["transmitter_id"]),
            hardware_model=str(data.get("hardware_model", "Unknown")),
            mean_vector=[float(x) for x in data["mean_vector"]],
            std_vector=[float(x) for x in data["std_vector"]],
            enrolled_at_utc=str(data.get("enrolled_at_utc", "")),
            burst_count=int(data.get("burst_count", 1)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class TransmitterDatabase:
    """Database of authorized transmitter radiometric profiles."""

    profiles: Dict[str, TransmitterProfile] = field(default_factory=dict)
    signed: bool = True
    signature_hex: str = "3045022100e4b7..."

    def add_profile(self, profile: TransmitterProfile) -> None:
        self.profiles[profile.transmitter_id] = profile

    def get_profile(self, transmitter_id: str) -> Optional[TransmitterProfile]:
        return self.profiles.get(transmitter_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signed": self.signed,
            "signature_hex": self.signature_hex,
            "transmitter_count": len(self.profiles),
            "transmitters": {
                tx_id: prof.to_dict() for tx_id, prof in self.profiles.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TransmitterDatabase:
        db = cls(
            signed=bool(data.get("signed", False)),
            signature_hex=str(data.get("signature_hex", "")),
        )
        tx_dict = data.get("transmitters", {})
        for tx_id, p_data in tx_dict.items():
            db.add_profile(TransmitterProfile.from_dict(p_data))
        return db

    def save_to_file(self, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, filepath: str) -> TransmitterDatabase:
        with open(filepath, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


@dataclass
class ClassificationResult:
    """Detailed verdict and metrics for a physical-layer transmitter authentication query."""

    verdict: str  # AUTHENTIC_TRANSMITTER, MAC_SPOOFING_OR_ROGUE_TRANSMITTER, DIGITAL_IQ_REPLAY_DETECTED
    is_authentic: bool
    claimed_transmitter_id: Optional[str]
    best_match_id: Optional[str]
    mahalanobis_distance: float
    claimed_mahalanobis_distance: Optional[float]
    threshold: float
    extracted_features: RFFeatureVector
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "is_authentic": self.is_authentic,
            "claimed_transmitter_id": self.claimed_transmitter_id,
            "best_match_id": self.best_match_id,
            "mahalanobis_distance": round(self.mahalanobis_distance, 4),
            "claimed_mahalanobis_distance": (
                round(self.claimed_mahalanobis_distance, 4)
                if self.claimed_mahalanobis_distance is not None
                else None
            ),
            "threshold": self.threshold,
            "details": self.details,
            "extracted_features": self.extracted_features.to_dict(),
        }


class MahalanobisClassifier:
    """Performs regularized diagonal Mahalanobis distance classification on RF feature vectors."""

    def __init__(
        self,
        db: TransmitterDatabase,
        threshold: float = 3.5,
        epsilon_reg: float = 1e-4,
    ) -> None:
        self.db = db
        self.threshold = threshold
        self.epsilon_reg = epsilon_reg
        self.seen_burst_hashes: Set[str] = set()

    def compute_distance(
        self, vector_6d: List[float], profile: TransmitterProfile
    ) -> float:
        """Computes the regularized Mahalanobis distance between an observed vector and an enrolled profile."""
        if len(vector_6d) != 6:
            raise ValueError(f"Observed vector must have 6 features, got {len(vector_6d)}")

        d_sq = 0.0
        for i in range(6):
            diff = vector_6d[i] - profile.mean_vector[i]
            variance = (profile.std_vector[i] ** 2) + self.epsilon_reg
            d_sq += (diff * diff) / variance

        return math.sqrt(max(0.0, d_sq))

    def classify(
        self,
        burst: IQBurst,
        claimed_id: Optional[str] = None,
        check_replay: bool = True,
    ) -> ClassificationResult:
        """Authenticates an incoming IQ burst against the transmitter profile database."""
        burst_hash = burst.sha256_digest()

        # 1. Exact Digital IQ Waveform Replay Detection
        if check_replay and burst_hash in self.seen_burst_hashes:
            features = extract_rf_features(burst)
            return ClassificationResult(
                verdict="DIGITAL_IQ_REPLAY_DETECTED",
                is_authentic=False,
                claimed_transmitter_id=claimed_id,
                best_match_id=None,
                mahalanobis_distance=float("inf"),
                claimed_mahalanobis_distance=None,
                threshold=self.threshold,
                extracted_features=features,
                details=f"Identical burst SHA-256 hash ({burst_hash[:16]}...) detected in recent transmission history. Replay attack flagged.",
            )

        if check_replay:
            self.seen_burst_hashes.add(burst_hash)

        # 2. Extract radiometric biometric features
        features = extract_rf_features(burst)
        obs_6d = features.to_6d_vector()

        if not self.db.profiles:
            return ClassificationResult(
                verdict="MAC_SPOOFING_OR_ROGUE_TRANSMITTER",
                is_authentic=False,
                claimed_transmitter_id=claimed_id,
                best_match_id=None,
                mahalanobis_distance=float("inf"),
                claimed_mahalanobis_distance=None,
                threshold=self.threshold,
                extracted_features=features,
                details="Transmitter database is empty; cannot authenticate emitter.",
            )

        # 3. Compute Mahalanobis distance to all enrolled profiles
        distances: List[Tuple[str, float]] = []
        for tx_id, profile in self.db.profiles.items():
            dist = self.compute_distance(obs_6d, profile)
            distances.append((tx_id, dist))

        distances.sort(key=lambda item: item[1])
        best_id, best_dist = distances[0]

        claimed_dist: Optional[float] = None
        if claimed_id is not None:
            claimed_prof = self.db.get_profile(claimed_id)
            if claimed_prof is not None:
                claimed_dist = self.compute_distance(obs_6d, claimed_prof)
            else:
                claimed_dist = float("inf")

        # 4. Evaluation logic
        if claimed_id is not None:
            # Claimed identity scenario (e.g. 802.11 / tactical MAC address verification)
            if claimed_dist is None or claimed_dist == float("inf"):
                verdict = "MAC_SPOOFING_OR_ROGUE_TRANSMITTER"
                is_auth = False
                details = f"Claimed transmitter ID '{claimed_id}' is not enrolled in authorized database."
            elif claimed_dist > self.threshold:
                verdict = "MAC_SPOOFING_OR_ROGUE_TRANSMITTER"
                is_auth = False
                details = (
                    f"Physical-layer biometric mismatch for claimed ID '{claimed_id}': "
                    f"Mahalanobis distance D_M={claimed_dist:.2f} exceeds threshold tau={self.threshold:.2f}. "
                    f"(Closest enrolled profile was '{best_id}' at D_M={best_dist:.2f})."
                )
            else:
                verdict = "AUTHENTIC_TRANSMITTER"
                is_auth = True
                details = (
                    f"Physical-layer biometric match for claimed ID '{claimed_id}': "
                    f"D_M={claimed_dist:.2f} <= tau={self.threshold:.2f}."
                )
            eval_dist = claimed_dist if claimed_dist != float("inf") else best_dist
        else:
            # Blind emitter identification scenario
            if best_dist <= self.threshold:
                verdict = "AUTHENTIC_TRANSMITTER"
                is_auth = True
                details = f"Emitter classified as '{best_id}' with D_M={best_dist:.2f} <= tau={self.threshold:.2f}."
            else:
                verdict = "MAC_SPOOFING_OR_ROGUE_TRANSMITTER"
                is_auth = False
                details = (
                    f"Unenrolled rogue emitter: closest match was '{best_id}' with "
                    f"D_M={best_dist:.2f} exceeding threshold tau={self.threshold:.2f}."
                )
            eval_dist = best_dist

        return ClassificationResult(
            verdict=verdict,
            is_authentic=is_auth,
            claimed_transmitter_id=claimed_id,
            best_match_id=best_id,
            mahalanobis_distance=eval_dist,
            claimed_mahalanobis_distance=claimed_dist,
            threshold=self.threshold,
            extracted_features=features,
            details=details,
        )
