"""10-Rule Deterministic RF Physical-Layer Security Posture Auditor.

Evaluates an RF physical-layer receiver/monitor security policy configuration
against 10 normative security rules (LH-RFF-001 through LH-RFF-010) and computes
the standardized Logihertz Security Posture Score.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class RFFPostureConfig:
    """Security policy configuration for an RF physical-layer fingerprinting system."""

    rf_fingerprinting_enabled: bool = True
    allow_mac_only_fallback: bool = False
    mahalanobis_threshold: float = 3.5
    iq_replay_detection_enabled: bool = True
    bind_phy_fingerprint_to_crypto_auth: bool = True
    min_snr_db: float = 18.0
    enable_iq_imbalance_features: bool = True
    enable_cfo_feature: bool = True
    enable_phase_noise_feature: bool = True
    enable_pa_transient_feature: bool = True
    temperature_drift_compensation: bool = True
    rx_gpsdo_locked: bool = True
    fingerprint_db_signed: bool = True
    allow_unauthenticated_enrollment: bool = False
    min_burst_samples: int = 1024
    oversampling_factor: int = 4
    multipath_channel_normalization: bool = True
    log_rogue_tx_alerts: bool = True
    capture_forensic_iq_on_reject: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RFFPostureConfig:
        return cls(
            rf_fingerprinting_enabled=bool(data.get("rf_fingerprinting_enabled", True)),
            allow_mac_only_fallback=bool(data.get("allow_mac_only_fallback", False)),
            mahalanobis_threshold=float(data.get("mahalanobis_threshold", 3.5)),
            iq_replay_detection_enabled=bool(data.get("iq_replay_detection_enabled", True)),
            bind_phy_fingerprint_to_crypto_auth=bool(
                data.get("bind_phy_fingerprint_to_crypto_auth", True)
            ),
            min_snr_db=float(data.get("min_snr_db", 18.0)),
            enable_iq_imbalance_features=bool(data.get("enable_iq_imbalance_features", True)),
            enable_cfo_feature=bool(data.get("enable_cfo_feature", True)),
            enable_phase_noise_feature=bool(data.get("enable_phase_noise_feature", True)),
            enable_pa_transient_feature=bool(data.get("enable_pa_transient_feature", True)),
            temperature_drift_compensation=bool(
                data.get("temperature_drift_compensation", True)
            ),
            rx_gpsdo_locked=bool(data.get("rx_gpsdo_locked", True)),
            fingerprint_db_signed=bool(data.get("fingerprint_db_signed", True)),
            allow_unauthenticated_enrollment=bool(
                data.get("allow_unauthenticated_enrollment", False)
            ),
            min_burst_samples=int(data.get("min_burst_samples", 1024)),
            oversampling_factor=int(data.get("oversampling_factor", 4)),
            multipath_channel_normalization=bool(
                data.get("multipath_channel_normalization", True)
            ),
            log_rogue_tx_alerts=bool(data.get("log_rogue_tx_alerts", True)),
            capture_forensic_iq_on_reject=bool(
                data.get("capture_forensic_iq_on_reject", True)
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditFinding:
    """Represents an individual audit evaluation outcome for a specific rule."""

    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    deduction: int
    cwe_number: str
    passed: bool
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Complete summary of the 10-rule RF physical-layer security audit."""

    timestamp_utc: str
    score: int
    status: str  # HARDENED, ACCEPTABLE, DEGRADED, NON-COMPLIANT
    total_rules: int
    passed_rules: int
    failed_rules: int
    findings: List[AuditFinding]
    policy_evaluated: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "score": self.score,
            "status": self.status,
            "total_rules": self.total_rules,
            "passed_rules": self.passed_rules,
            "failed_rules": self.failed_rules,
            "findings": [f.to_dict() for f in self.findings],
            "policy_evaluated": self.policy_evaluated,
        }


@dataclass
class NormativeRule:
    rule_id: str
    title: str
    severity: str
    deduction: int
    cwe_number: str
    evaluator: Callable[[RFFPostureConfig], Tuple[bool, str, str]]


def get_standard_rules() -> List[NormativeRule]:
    """Returns the canonical 10-rule RF physical-layer security checklist."""
    return [
        NormativeRule(
            rule_id="LH-RFF-001",
            title="Physical-Layer RF Fingerprinting Enforcement",
            severity="CRITICAL",
            deduction=25,
            cwe_number="CWE-290",
            evaluator=lambda cfg: (
                cfg.rf_fingerprinting_enabled and not cfg.allow_mac_only_fallback,
                "Physical-layer RF fingerprinting is active without unauthenticated MAC-only fallback."
                if (cfg.rf_fingerprinting_enabled and not cfg.allow_mac_only_fallback)
                else "RF fingerprinting is disabled or fallback to spoofable Layer-2 MAC address is permitted.",
                "Set rf_fingerprinting_enabled: true and allow_mac_only_fallback: false.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-002",
            title="Rigorous Mahalanobis Decision Boundary",
            severity="CRITICAL",
            deduction=25,
            cwe_number="CWE-682",
            evaluator=lambda cfg: (
                cfg.mahalanobis_threshold <= 5.0,
                f"Mahalanobis distance threshold ({cfg.mahalanobis_threshold:.2f}) is appropriately bounded (<= 5.0)."
                if cfg.mahalanobis_threshold <= 5.0
                else f"Permissive Mahalanobis threshold ({cfg.mahalanobis_threshold:.2f} > 5.0) allows rogue SDR transmitters to impersonate authorized nodes.",
                "Set mahalanobis_threshold to a value <= 5.0 (recommended: 3.0 to 3.5).",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-003",
            title="Digital IQ Replay Defense & Cryptographic Binding",
            severity="CRITICAL",
            deduction=25,
            cwe_number="CWE-294",
            evaluator=lambda cfg: (
                cfg.iq_replay_detection_enabled and cfg.bind_phy_fingerprint_to_crypto_auth,
                "Exact IQ burst replay detection and cryptographic binding are both enforced."
                if (cfg.iq_replay_detection_enabled and cfg.bind_phy_fingerprint_to_crypto_auth)
                else "Missing exact-waveform IQ digest check or physical fingerprint is not bound to cryptographic authentication.",
                "Set iq_replay_detection_enabled: true and bind_phy_fingerprint_to_crypto_auth: true.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-004",
            title="Receiver SNR Gating Threshold",
            severity="HIGH",
            deduction=10,
            cwe_number="CWE-20",
            evaluator=lambda cfg: (
                cfg.min_snr_db >= 15.0,
                f"Receiver SNR gating threshold ({cfg.min_snr_db:.1f} dB) is sufficient for reliable impairment extraction (>= 15 dB)."
                if cfg.min_snr_db >= 15.0
                else f"Insufficient SNR gating ({cfg.min_snr_db:.1f} dB < 15.0 dB) introduces severe noise into CFO and skew estimates.",
                "Increase min_snr_db to at least 15.0 dB.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-005",
            title="Comprehensive Multi-Impairment Feature Vector",
            severity="HIGH",
            deduction=10,
            cwe_number="CWE-682",
            evaluator=lambda cfg: (
                cfg.enable_iq_imbalance_features
                and cfg.enable_cfo_feature
                and cfg.enable_phase_noise_feature
                and cfg.enable_pa_transient_feature,
                "All four primary hardware impairment classes (IQ imbalance, CFO, LO phase noise, and PA transient) are enabled."
                if (
                    cfg.enable_iq_imbalance_features
                    and cfg.enable_cfo_feature
                    and cfg.enable_phase_noise_feature
                    and cfg.enable_pa_transient_feature
                )
                else "Incomplete radiometric feature vector; one or more critical impairment classes are disabled.",
                "Enable all features: enable_iq_imbalance_features: true, enable_cfo_feature: true, enable_phase_noise_feature: true, enable_pa_transient_feature: true.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-006",
            title="Thermal Drift Compensation & Clock Calibration",
            severity="HIGH",
            deduction=10,
            cwe_number="CWE-367",
            evaluator=lambda cfg: (
                cfg.temperature_drift_compensation and cfg.rx_gpsdo_locked,
                "Thermal drift compensation and GPSDO receiver clock lock are active."
                if (cfg.temperature_drift_compensation and cfg.rx_gpsdo_locked)
                else "Missing crystal oscillator thermal drift compensation or uncalibrated receiver reference clock.",
                "Set temperature_drift_compensation: true and rx_gpsdo_locked: true.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-007",
            title="Signed Transmitter Fingerprint Database",
            severity="HIGH",
            deduction=10,
            cwe_number="CWE-353",
            evaluator=lambda cfg: (
                cfg.fingerprint_db_signed and not cfg.allow_unauthenticated_enrollment,
                "Transmitter biometric database is cryptographically signed and unauthenticated enrollment is forbidden."
                if (cfg.fingerprint_db_signed and not cfg.allow_unauthenticated_enrollment)
                else "Fingerprint database is unsigned or unauthenticated runtime enrollment is permitted.",
                "Set fingerprint_db_signed: true and allow_unauthenticated_enrollment: false.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-008",
            title="Adequate Burst Duration & Oversampling Ratio",
            severity="MEDIUM",
            deduction=4,
            cwe_number="CWE-682",
            evaluator=lambda cfg: (
                cfg.min_burst_samples >= 512 and cfg.oversampling_factor >= 4,
                f"Burst sample window ({cfg.min_burst_samples} samples) and oversampling factor ({cfg.oversampling_factor}x) meet standards."
                if (cfg.min_burst_samples >= 512 and cfg.oversampling_factor >= 4)
                else f"Undersized burst sample window ({cfg.min_burst_samples} < 512) or insufficient oversampling ({cfg.oversampling_factor} < 4x).",
                "Ensure min_burst_samples >= 512 and oversampling_factor >= 4.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-009",
            title="Multipath Channel Equalization Normalization",
            severity="MEDIUM",
            deduction=4,
            cwe_number="CWE-400",
            evaluator=lambda cfg: (
                cfg.multipath_channel_normalization,
                "Multipath channel equalization normalization is enabled before constellation feature extraction."
                if cfg.multipath_channel_normalization
                else "Missing multipath channel equalization normalization; environmental reflections will corrupt transmitter fingerprints.",
                "Set multipath_channel_normalization: true.",
            ),
        ),
        NormativeRule(
            rule_id="LH-RFF-010",
            title="SIEM Anomaly Alerting & Forensic IQ Capture",
            severity="LOW",
            deduction=1,
            cwe_number="CWE-778",
            evaluator=lambda cfg: (
                cfg.log_rogue_tx_alerts and cfg.capture_forensic_iq_on_reject,
                "SIEM alert logging and forensic raw IQ capture on rejected bursts are enabled."
                if (cfg.log_rogue_tx_alerts and cfg.capture_forensic_iq_on_reject)
                else "Missing SIEM rogue transmitter alert logging or missing raw IQ forensic capture on rejection.",
                "Set log_rogue_tx_alerts: true and capture_forensic_iq_on_reject: true.",
            ),
        ),
    ]


def evaluate_policy(cfg: RFFPostureConfig) -> AuditReport:
    """Evaluates all 10 normative rules against the provided policy configuration."""
    rules = get_standard_rules()
    findings: List[AuditFinding] = []

    total_deductions = 0
    passed_count = 0
    failed_count = 0

    for rule in rules:
        passed, desc, remediation = rule.evaluator(cfg)
        finding = AuditFinding(
            rule_id=rule.rule_id,
            title=rule.title,
            severity=rule.severity,
            deduction=rule.deduction,
            cwe_number=rule.cwe_number,
            passed=passed,
            description=desc,
            remediation=remediation,
        )

        if passed:
            passed_count += 1
        else:
            failed_count += 1
            total_deductions += rule.deduction

        findings.append(finding)

    score = max(0, 100 - total_deductions)

    if score >= 90:
        status = "HARDENED"
    elif score >= 70:
        status = "ACCEPTABLE"
    elif score >= 50:
        status = "DEGRADED"
    else:
        status = "NON-COMPLIANT"

    return AuditReport(
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        score=score,
        status=status,
        total_rules=len(rules),
        passed_rules=passed_count,
        failed_rules=failed_count,
        findings=findings,
        policy_evaluated=cfg.to_dict(),
    )


def load_policy_from_file(filepath: str) -> RFFPostureConfig:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return RFFPostureConfig.from_dict(data)
