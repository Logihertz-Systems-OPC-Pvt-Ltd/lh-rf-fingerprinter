"""Comprehensive Verification Test Suite for lh-rf-fingerprinter.

Contains 85+ deterministic unit and integration test assertions covering:
- Radiometric physical-layer hardware impairment feature extraction accuracy
- Mahalanobis distance transmitter authentication and MAC spoofing detection
- Exact digital IQ waveform replay detection
- 10-rule RF physical-layer security posture auditor & score math
- Output exporters (ANSI Table, Canonical JSON, OASIS SARIF v2.1.0)
- End-to-end CLI execution and subprocess exit codes
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure src/ is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lh_rf_fingerprinter.auditor import (
    AuditFinding,
    AuditReport,
    RFFPostureConfig,
    evaluate_policy,
    get_standard_rules,
    load_policy_from_file,
)
from lh_rf_fingerprinter.classifier import (
    ClassificationResult,
    MahalanobisClassifier,
    TransmitterDatabase,
    TransmitterProfile,
)
from lh_rf_fingerprinter.exporters import (
    format_canonical_json,
    format_sarif,
    format_terminal_table,
)
from lh_rf_fingerprinter.rf_features import (
    IQBurst,
    RFFeatureVector,
    extract_rf_features,
    synthesize_impaired_iq_burst,
)


class TestRFFeaturesExtraction(unittest.TestCase):
    """Test Group 1: Radiometric Hardware Impairment Feature Extraction."""

    def test_feature_extraction_accuracy_positive_cfo(self) -> None:
        """Verifies closed-form recovery of positive CFO, IQ imbalance, and DC offsets."""
        burst = synthesize_impaired_iq_burst(
            sample_rate_hz=1_000_000.0,
            num_samples=4096,
            cfo_hz=1250.0,
            iq_gain_db=0.50,
            iq_skew_deg=3.0,
            dc_i=0.04,
            dc_q=-0.03,
            lo_phase_noise_deg=1.2,
            pa_ramp_samples=128,
            snr_db=38.0,
            transmitter_id="TX-ALPHA-01",
            seed=42,
        )

        features = extract_rf_features(burst)

        # 1. DC Offsets
        self.assertAlmostEqual(features.dc_offset_i, 0.04, delta=0.005)
        self.assertAlmostEqual(features.dc_offset_q, -0.03, delta=0.005)

        # 2. IQ Gain Imbalance and Phase Skew
        self.assertAlmostEqual(features.iq_gain_imbalance_db, 0.50, delta=0.08)
        self.assertAlmostEqual(features.iq_phase_skew_deg, 3.0, delta=0.25)

        # 3. Carrier Frequency Offset
        self.assertAlmostEqual(features.cfo_hz, 1250.0, delta=15.0)

        # 4. PA Rise Time reflects ramp duration (between 10% and 90% of 128 us)
        self.assertGreaterEqual(features.pa_rise_time_us, 50.0)
        self.assertLessEqual(features.pa_rise_time_us, 130.0)

        # 5. Envelope Kurtosis
        self.assertGreater(features.envelope_kurtosis, 0.0)

        # 6. Sample count and 6D vector format
        self.assertEqual(features.sample_count, 4096)
        vec6d = features.to_6d_vector()
        self.assertEqual(len(vec6d), 6)
        self.assertEqual(vec6d[0], features.cfo_hz)
        self.assertEqual(vec6d[1], features.iq_gain_imbalance_db)
        self.assertEqual(vec6d[2], features.iq_phase_skew_deg)
        self.assertEqual(vec6d[3], features.dc_offset_i)
        self.assertEqual(vec6d[4], features.dc_offset_q)
        self.assertEqual(vec6d[5], features.lo_phase_noise_rms_deg)

    def test_feature_extraction_accuracy_negative_cfo(self) -> None:
        """Verifies closed-form recovery of negative CFO, negative gain, and negative skew."""
        burst = synthesize_impaired_iq_burst(
            sample_rate_hz=1_000_000.0,
            num_samples=8192,
            cfo_hz=-2800.0,
            iq_gain_db=-0.65,
            iq_skew_deg=-2.5,
            dc_i=-0.02,
            dc_q=0.05,
            lo_phase_noise_deg=2.0,
            pa_ramp_samples=96,
            snr_db=38.0,
            transmitter_id="TX-BRAVO-02",
            seed=101,
        )

        features = extract_rf_features(burst)

        self.assertAlmostEqual(features.dc_offset_i, -0.02, delta=0.005)
        self.assertAlmostEqual(features.dc_offset_q, 0.05, delta=0.005)
        self.assertAlmostEqual(features.iq_gain_imbalance_db, -0.65, delta=0.08)
        self.assertAlmostEqual(features.iq_phase_skew_deg, -2.5, delta=0.30)
        self.assertAlmostEqual(features.cfo_hz, -2800.0, delta=15.0)

    def test_iq_burst_invalid_lengths(self) -> None:
        """Verifies exception handling for mismatched I/Q lengths or undersized bursts."""
        with self.assertRaises(ValueError):
            IQBurst(
                sample_rate_hz=1e6,
                i_samples=[1.0, 2.0, 3.0],
                q_samples=[1.0, 2.0],
            )

        undersized = IQBurst(
            sample_rate_hz=1e6,
            i_samples=[0.1] * 32,
            q_samples=[0.1] * 32,
        )
        with self.assertRaises(ValueError):
            extract_rf_features(undersized)

    def test_burst_serialization_round_trip(self) -> None:
        """Verifies IQBurst to_dict and from_dict serialization."""
        burst = synthesize_impaired_iq_burst(
            sample_rate_hz=500_000.0,
            num_samples=128,
            cfo_hz=500.0,
            transmitter_id="TX-TEST",
        )
        b_dict = burst.to_dict()
        loaded = IQBurst.from_dict(b_dict)

        self.assertEqual(burst.sample_rate_hz, loaded.sample_rate_hz)
        self.assertEqual(burst.transmitter_id, loaded.transmitter_id)
        self.assertEqual(burst.sample_count, loaded.sample_count)
        self.assertEqual(burst.sha256_digest(), loaded.sha256_digest())


class TestTransmitterClassifier(unittest.TestCase):
    """Test Group 2: Mahalanobis Distance Classification & Spoofer Detection."""

    def setUp(self) -> None:
        self.prof_alpha = TransmitterProfile(
            transmitter_id="TX-ALPHA-01",
            hardware_model="Logihertz Tactical Node v2",
            mean_vector=[1250.0, 0.50, 3.0, 0.04, -0.03, 1.2],
            std_vector=[15.0, 0.05, 0.20, 0.005, 0.005, 0.15],
            enrolled_at_utc="2026-11-13T00:00:00Z",
            burst_count=200,
        )
        self.prof_bravo = TransmitterProfile(
            transmitter_id="TX-BRAVO-02",
            hardware_model="Logihertz Field Radio v1",
            mean_vector=[-2800.0, -0.65, -2.5, -0.02, 0.05, 2.1],
            std_vector=[20.0, 0.06, 0.25, 0.006, 0.006, 0.20],
            enrolled_at_utc="2026-11-13T00:00:00Z",
            burst_count=150,
        )
        self.db = TransmitterDatabase(signed=True, signature_hex="3045...")
        self.db.add_profile(self.prof_alpha)
        self.db.add_profile(self.prof_bravo)
        self.classifier = MahalanobisClassifier(self.db, threshold=3.5)

    def test_authentic_transmitter_verification(self) -> None:
        """Verifies that an authentic burst matches its enrolled profile with low distance."""
        burst = synthesize_impaired_iq_burst(
            cfo_hz=1250.0,
            iq_gain_db=0.50,
            iq_skew_deg=3.0,
            dc_i=0.04,
            dc_q=-0.03,
            lo_phase_noise_deg=1.2,
            transmitter_id="TX-ALPHA-01",
            seed=42,
        )

        res = self.classifier.classify(burst, claimed_id="TX-ALPHA-01")
        self.assertTrue(res.is_authentic)
        self.assertEqual(res.verdict, "AUTHENTIC_TRANSMITTER")
        self.assertEqual(res.claimed_transmitter_id, "TX-ALPHA-01")
        self.assertEqual(res.best_match_id, "TX-ALPHA-01")
        self.assertLess(res.mahalanobis_distance, 3.5)
        self.assertLess(res.mahalanobis_distance, 1.5)

    def test_mac_spoofing_detection(self) -> None:
        """Verifies that an adversary spoofing an authorized MAC ID is flagged via radiometric mismatch."""
        # Burst physically from Bravo, but claims to be Alpha
        burst = synthesize_impaired_iq_burst(
            cfo_hz=-2800.0,
            iq_gain_db=-0.65,
            iq_skew_deg=-2.5,
            dc_i=-0.02,
            dc_q=0.05,
            lo_phase_noise_deg=2.1,
            transmitter_id="TX-BRAVO-02",
            seed=99,
        )

        res = self.classifier.classify(burst, claimed_id="TX-ALPHA-01")
        self.assertFalse(res.is_authentic)
        self.assertEqual(res.verdict, "MAC_SPOOFING_OR_ROGUE_TRANSMITTER")
        self.assertEqual(res.claimed_transmitter_id, "TX-ALPHA-01")
        self.assertEqual(res.best_match_id, "TX-BRAVO-02")
        self.assertGreater(res.mahalanobis_distance, 10.0)

    def test_blind_emitter_identification(self) -> None:
        """Verifies blind classification without a claimed ID selects the closest profile."""
        burst = synthesize_impaired_iq_burst(
            cfo_hz=-2800.0,
            iq_gain_db=-0.65,
            iq_skew_deg=-2.5,
            dc_i=-0.02,
            dc_q=0.05,
            lo_phase_noise_deg=2.1,
            seed=77,
        )

        res = self.classifier.classify(burst, claimed_id=None)
        self.assertTrue(res.is_authentic)
        self.assertEqual(res.verdict, "AUTHENTIC_TRANSMITTER")
        self.assertEqual(res.best_match_id, "TX-BRAVO-02")
        self.assertLess(res.mahalanobis_distance, 3.5)

    def test_unenrolled_rogue_emitter(self) -> None:
        """Verifies that an unknown rogue SDR emitter is rejected."""
        burst = synthesize_impaired_iq_burst(
            cfo_hz=9500.0,  # Distinct rogue frequency
            iq_gain_db=2.50,
            iq_skew_deg=-8.0,
            dc_i=0.20,
            dc_q=-0.15,
            seed=123,
        )

        res = self.classifier.classify(burst, claimed_id=None)
        self.assertFalse(res.is_authentic)
        self.assertEqual(res.verdict, "MAC_SPOOFING_OR_ROGUE_TRANSMITTER")
        self.assertGreater(res.mahalanobis_distance, 3.5)

    def test_exact_digital_iq_replay_detection(self) -> None:
        """Verifies that replaying an identical burst is detected via bitwise SHA-256 match."""
        burst = synthesize_impaired_iq_burst(
            cfo_hz=1250.0,
            iq_gain_db=0.50,
            iq_skew_deg=3.0,
            dc_i=0.04,
            dc_q=-0.03,
            seed=42,
        )

        # First transmission -> Authentic
        res1 = self.classifier.classify(burst, claimed_id="TX-ALPHA-01", check_replay=True)
        self.assertTrue(res1.is_authentic)

        # Second transmission (identical burst replay) -> Replay Detected
        res2 = self.classifier.classify(burst, claimed_id="TX-ALPHA-01", check_replay=True)
        self.assertFalse(res2.is_authentic)
        self.assertEqual(res2.verdict, "DIGITAL_IQ_REPLAY_DETECTED")
        self.assertIn("Replay attack flagged", res2.details)

    def test_empty_database_classification(self) -> None:
        """Verifies classifier behavior on empty database."""
        empty_db = TransmitterDatabase()
        c = MahalanobisClassifier(empty_db)
        burst = synthesize_impaired_iq_burst(num_samples=128)
        res = c.classify(burst)
        self.assertFalse(res.is_authentic)
        self.assertIn("empty", res.details)

    def test_profile_validation_constraints(self) -> None:
        """Verifies that invalid vector lengths raise ValueError."""
        with self.assertRaises(ValueError):
            TransmitterProfile(
                transmitter_id="TX-BAD",
                hardware_model="SDR",
                mean_vector=[1.0, 2.0],  # only 2 features
                std_vector=[1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            )


class TestRFFPostureAuditor(unittest.TestCase):
    """Test Group 3: 10-Rule Posture Auditor & Security Score Math."""

    def test_hardened_policy_100_score(self) -> None:
        """Verifies that hardened policy satisfies all 10 rules with score 100/100."""
        cfg = RFFPostureConfig()
        report = evaluate_policy(cfg)

        self.assertEqual(report.score, 100)
        self.assertEqual(report.status, "HARDENED")
        self.assertEqual(report.total_rules, 10)
        self.assertEqual(report.passed_rules, 10)
        self.assertEqual(report.failed_rules, 0)
        for f in report.findings:
            self.assertTrue(f.passed)
            self.assertEqual(f.deduction, 25 if f.severity == "CRITICAL" else (10 if f.severity == "HIGH" else (4 if f.severity == "MEDIUM" else 1)))

    def test_vulnerable_policy_0_score(self) -> None:
        """Verifies that vulnerable policy fails all 10 rules with score 0/100."""
        cfg = RFFPostureConfig(
            rf_fingerprinting_enabled=False,
            allow_mac_only_fallback=True,
            mahalanobis_threshold=8.0,
            iq_replay_detection_enabled=False,
            bind_phy_fingerprint_to_crypto_auth=False,
            min_snr_db=5.0,
            enable_iq_imbalance_features=False,
            enable_cfo_feature=False,
            enable_phase_noise_feature=False,
            enable_pa_transient_feature=False,
            temperature_drift_compensation=False,
            rx_gpsdo_locked=False,
            fingerprint_db_signed=False,
            allow_unauthenticated_enrollment=True,
            min_burst_samples=128,
            oversampling_factor=1,
            multipath_channel_normalization=False,
            log_rogue_tx_alerts=False,
            capture_forensic_iq_on_reject=False,
        )
        report = evaluate_policy(cfg)

        self.assertEqual(report.score, 0)
        self.assertEqual(report.status, "NON-COMPLIANT")
        self.assertEqual(report.failed_rules, 10)
        self.assertEqual(report.passed_rules, 0)

    # Individual Rule Verification
    def test_rule_001_rf_fingerprinting_enforced(self) -> None:
        cfg = RFFPostureConfig(rf_fingerprinting_enabled=False)
        report = evaluate_policy(cfg)
        f = report.findings[0]
        self.assertEqual(f.rule_id, "LH-RFF-001")
        self.assertFalse(f.passed)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.cwe_number, "CWE-290")
        self.assertEqual(report.score, 75)

    def test_rule_002_mahalanobis_threshold_bound(self) -> None:
        cfg = RFFPostureConfig(mahalanobis_threshold=6.0)
        report = evaluate_policy(cfg)
        f = report.findings[1]
        self.assertEqual(f.rule_id, "LH-RFF-002")
        self.assertFalse(f.passed)
        self.assertEqual(report.score, 75)

    def test_rule_003_iq_replay_and_crypto_binding(self) -> None:
        cfg = RFFPostureConfig(iq_replay_detection_enabled=False)
        report = evaluate_policy(cfg)
        f = report.findings[2]
        self.assertEqual(f.rule_id, "LH-RFF-003")
        self.assertFalse(f.passed)
        self.assertEqual(report.score, 75)

    def test_rule_004_min_snr_gating(self) -> None:
        cfg = RFFPostureConfig(min_snr_db=10.0)
        report = evaluate_policy(cfg)
        f = report.findings[3]
        self.assertEqual(f.rule_id, "LH-RFF-004")
        self.assertFalse(f.passed)
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(report.score, 90)

    def test_rule_005_feature_vector_completeness(self) -> None:
        cfg = RFFPostureConfig(enable_phase_noise_feature=False)
        report = evaluate_policy(cfg)
        f = report.findings[4]
        self.assertEqual(f.rule_id, "LH-RFF-005")
        self.assertFalse(f.passed)
        self.assertEqual(report.score, 90)

    def test_rule_006_thermal_drift_and_clock(self) -> None:
        cfg = RFFPostureConfig(temperature_drift_compensation=False)
        report = evaluate_policy(cfg)
        f = report.findings[5]
        self.assertEqual(f.rule_id, "LH-RFF-006")
        self.assertFalse(f.passed)
        self.assertEqual(report.score, 90)

    def test_rule_007_signed_fingerprint_db(self) -> None:
        cfg = RFFPostureConfig(fingerprint_db_signed=False)
        report = evaluate_policy(cfg)
        f = report.findings[6]
        self.assertEqual(f.rule_id, "LH-RFF-007")
        self.assertFalse(f.passed)
        self.assertEqual(report.score, 90)

    def test_rule_008_burst_samples_and_oversampling(self) -> None:
        cfg = RFFPostureConfig(min_burst_samples=256)
        report = evaluate_policy(cfg)
        f = report.findings[7]
        self.assertEqual(f.rule_id, "LH-RFF-008")
        self.assertFalse(f.passed)
        self.assertEqual(f.severity, "MEDIUM")
        self.assertEqual(report.score, 96)

    def test_rule_009_multipath_equalization(self) -> None:
        cfg = RFFPostureConfig(multipath_channel_normalization=False)
        report = evaluate_policy(cfg)
        f = report.findings[8]
        self.assertEqual(f.rule_id, "LH-RFF-009")
        self.assertFalse(f.passed)
        self.assertEqual(report.score, 96)

    def test_rule_010_siem_logging_and_iq_capture(self) -> None:
        cfg = RFFPostureConfig(capture_forensic_iq_on_reject=False)
        report = evaluate_policy(cfg)
        f = report.findings[9]
        self.assertEqual(f.rule_id, "LH-RFF-010")
        self.assertFalse(f.passed)
        self.assertEqual(f.severity, "LOW")
        self.assertEqual(report.score, 99)

    def test_status_classifications(self) -> None:
        """Verifies posture classification boundaries (HARDENED, ACCEPTABLE, DEGRADED, NON-COMPLIANT)."""
        # Score 90 -> HARDENED
        r1 = evaluate_policy(RFFPostureConfig(min_snr_db=10.0))
        self.assertEqual(r1.status, "HARDENED")
        self.assertEqual(r1.score, 90)

        # Score 75 -> ACCEPTABLE (1 critical failure: -25)
        r2 = evaluate_policy(RFFPostureConfig(rf_fingerprinting_enabled=False))
        self.assertEqual(r2.status, "ACCEPTABLE")
        self.assertEqual(r2.score, 75)

        # Score 65 -> DEGRADED (1 critical -25, 1 high -10: 100 - 35 = 65)
        r3 = evaluate_policy(
            RFFPostureConfig(rf_fingerprinting_enabled=False, min_snr_db=10.0)
        )
        self.assertEqual(r3.status, "DEGRADED")
        self.assertEqual(r3.score, 65)

        # Score 40 -> NON-COMPLIANT (2 critical -50, 1 high -10: 100 - 60 = 40)
        r4 = evaluate_policy(
            RFFPostureConfig(
                rf_fingerprinting_enabled=False,
                mahalanobis_threshold=7.0,
                min_snr_db=10.0,
            )
        )
        self.assertEqual(r4.status, "NON-COMPLIANT")
        self.assertEqual(r4.score, 40)


class TestExporters(unittest.TestCase):
    """Test Group 4: Multi-Format Exporters."""

    def setUp(self) -> None:
        self.report = evaluate_policy(RFFPostureConfig())

    def test_terminal_table_output(self) -> None:
        table = format_terminal_table(self.report)
        self.assertIn("LOGIHERTZ RF TRANSMITTER FINGERPRINTER", table)
        self.assertIn("LH-RFF-001", table)
        self.assertIn("LH-RFF-010", table)
        self.assertIn("HARDENED", table)
        self.assertIn("100 / 100", table)

    def test_canonical_json_output(self) -> None:
        json_str = format_canonical_json(self.report)
        data = json.loads(json_str)
        self.assertEqual(data["score"], 100)
        self.assertEqual(data["status"], "HARDENED")
        self.assertEqual(len(data["findings"]), 10)

    def test_sarif_v210_output(self) -> None:
        # Create report with 1 finding
        report = evaluate_policy(RFFPostureConfig(rf_fingerprinting_enabled=False))
        sarif_str = format_sarif(report)
        sarif = json.loads(sarif_str)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", sarif["$schema"])
        runs = sarif["runs"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["tool"]["driver"]["name"], "lh-rf-fingerprint")
        self.assertEqual(len(runs[0]["tool"]["driver"]["rules"]), 10)
        self.assertEqual(len(runs[0]["results"]), 1)
        self.assertEqual(runs[0]["results"][0]["ruleId"], "LH-RFF-001")


class TestCLIExecution(unittest.TestCase):
    """Test Group 5: Subprocess CLI Execution and Exit Codes."""

    def setUp(self) -> None:
        self.cli_bin = REPO_ROOT / "bin" / "lh-rf-fingerprint"

    def test_cli_version_and_help(self) -> None:
        res_v = subprocess.run([sys.executable, str(self.cli_bin), "--version"], capture_output=True, text=True)
        self.assertEqual(res_v.returncode, 0)
        self.assertIn("lh-rf-fingerprint v0.1.0", res_v.stdout)

        res_h = subprocess.run([sys.executable, str(self.cli_bin), "--help"], capture_output=True, text=True)
        self.assertEqual(res_h.returncode, 0)
        self.assertIn("Physical-Layer RF Transmitter Fingerprinting Engine", res_h.stdout)

    def test_cli_scan_hardened_and_vulnerable(self) -> None:
        hardened_path = REPO_ROOT / "fixtures" / "hardened_rff_policy.json"
        vulnerable_path = REPO_ROOT / "fixtures" / "vulnerable_rff_policy.json"

        # Hardened policy -> exit code 0
        res_hard = subprocess.run(
            [sys.executable, str(self.cli_bin), "scan", str(hardened_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_hard.returncode, 0)
        self.assertIn("HARDENED", res_hard.stdout)
        self.assertIn("100 / 100", res_hard.stdout)

        # Vulnerable policy -> exit code 1
        res_vuln = subprocess.run(
            [sys.executable, str(self.cli_bin), "scan", str(vulnerable_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_vuln.returncode, 1)
        self.assertIn("NON-COMPLIANT", res_vuln.stdout)
        self.assertIn("0 / 100", res_vuln.stdout)

    def test_cli_scan_json_and_sarif_formats(self) -> None:
        hardened_path = REPO_ROOT / "fixtures" / "hardened_rff_policy.json"

        res_json = subprocess.run(
            [sys.executable, str(self.cli_bin), "scan", str(hardened_path), "--format", "json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_json.returncode, 0)
        parsed = json.loads(res_json.stdout)
        self.assertEqual(parsed["score"], 100)

        res_sarif = subprocess.run(
            [sys.executable, str(self.cli_bin), "scan", str(hardened_path), "--format", "sarif"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_sarif.returncode, 0)
        sarif = json.loads(res_sarif.stdout)
        self.assertEqual(sarif["version"], "2.1.0")

    def test_cli_extract_subcommand(self) -> None:
        sample_burst = REPO_ROOT / "fixtures" / "sample_rf_burst.json"
        res = subprocess.run(
            [sys.executable, str(self.cli_bin), "extract", str(sample_burst)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("PHYSICAL-LAYER RF TRANSMITTER BIOMETRIC FEATURE EXTRACTION", res.stdout)
        self.assertIn("Carrier Freq Offset", res.stdout)
        self.assertIn("IQ Gain Imbalance", res.stdout)
        self.assertIn("Burst SHA-256 Digest", res.stdout)

    def test_cli_verify_tx_authentic_and_spoofed(self) -> None:
        sample_burst = REPO_ROOT / "fixtures" / "sample_rf_burst.json"
        enrolled_db = REPO_ROOT / "fixtures" / "enrolled_transmitters_db.json"

        # Authentic claim -> exit code 0
        res_auth = subprocess.run(
            [
                sys.executable,
                str(self.cli_bin),
                "verify-tx",
                "--burst",
                str(sample_burst),
                "--db",
                str(enrolled_db),
                "--claimed-id",
                "TX-ALPHA-01",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_auth.returncode, 0)
        self.assertIn("AUTHENTIC_TRANSMITTER", res_auth.stdout)
        self.assertIn("Authentic Emitter      : YES", res_auth.stdout)

        # Spoofed claim -> exit code 1
        res_spoof = subprocess.run(
            [
                sys.executable,
                str(self.cli_bin),
                "verify-tx",
                "--burst",
                str(sample_burst),
                "--db",
                str(enrolled_db),
                "--claimed-id",
                "TX-BRAVO-02",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_spoof.returncode, 1)
        self.assertIn("MAC_SPOOFING_OR_ROGUE_TRANSMITTER", res_spoof.stdout)
        self.assertIn("Authentic Emitter      : NO", res_spoof.stdout)

    def test_cli_synth_burst_subcommand(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            res = subprocess.run(
                [
                    sys.executable,
                    str(self.cli_bin),
                    "synth-burst",
                    "--cfo-hz",
                    "850.0",
                    "--iq-gain-db",
                    "0.35",
                    "--iq-skew-deg",
                    "1.8",
                    "--samples",
                    "1024",
                    "--output",
                    tmp_path,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("Successfully generated and saved IQ burst", res.stdout)
            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["sample_count"], 1024)
            self.assertEqual(len(data["i_samples"]), 1024)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_cli_invalid_arguments_exit_code_2(self) -> None:
        res = subprocess.run(
            [sys.executable, str(self.cli_bin), "scan", "non_existent_file.json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
