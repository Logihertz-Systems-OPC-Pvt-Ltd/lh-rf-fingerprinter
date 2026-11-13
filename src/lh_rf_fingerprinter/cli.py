"""Command-Line Interface for lh-rf-fingerprinter.

Provides subcommands:
  scan        Audit physical-layer RF security policies against 10 posture rules
  extract     Extract radiometric hardware features from a complex IQ burst
  verify-tx   Authenticate a transmitter IQ burst against an enrolled profile DB
  synth-burst Synthesize an impaired complex IQ burst for testing
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from .auditor import evaluate_policy, load_policy_from_file
from .classifier import MahalanobisClassifier, TransmitterDatabase
from .exporters import format_canonical_json, format_sarif, format_terminal_table
from .rf_features import IQBurst, extract_rf_features, synthesize_impaired_iq_burst

VERSION = "0.1.0"
TOOL_NAME = "lh-rf-fingerprint"
COPYRIGHT = "Copyright (C) 2026 Logihertz Systems (OPC) Private Limited"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} - Physical-Layer RF Transmitter Fingerprinting Engine & Posture Auditor",
        epilog=f"{COPYRIGHT}. Author: Sameer Tawade (ops@logihertz.com)",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"{TOOL_NAME} v{VERSION}\n{COPYRIGHT}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan
    scan_p = subparsers.add_parser("scan", help="Audit an RF physical-layer security policy")
    scan_p.add_argument("policy_file", help="Path to policy JSON file (e.g. fixtures/hardened_rff_policy.json)")
    scan_p.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report output format (default: table)",
    )
    scan_p.add_argument("--output", help="Optional output filepath to save report")

    # extract
    extract_p = subparsers.add_parser("extract", help="Extract radiometric biometric features from an IQ burst")
    extract_p.add_argument("burst_file", help="Path to IQ burst JSON file")
    extract_p.add_argument("--lag-d", type=int, default=1, help="Autocorrelation lag D for CFO estimation (default: 1)")

    # verify-tx
    verify_p = subparsers.add_parser("verify-tx", help="Authenticate transmitter burst against enrolled DB")
    verify_p.add_argument("--burst", required=True, help="Path to received IQ burst JSON file")
    verify_p.add_argument("--db", required=True, help="Path to enrolled transmitter database JSON file")
    verify_p.add_argument("--claimed-id", help="Claimed transmitter/MAC ID to verify (optional)")
    verify_p.add_argument("--threshold", type=float, default=3.5, help="Mahalanobis acceptance threshold tau (default: 3.5)")
    verify_p.add_argument("--no-replay-check", action="store_true", help="Disable exact waveform replay detection")

    # synth-burst
    synth_p = subparsers.add_parser("synth-burst", help="Synthesize an impaired complex baseband IQ burst")
    synth_p.add_argument("--sample-rate", type=float, default=1_000_000.0, help="Sample rate in Hz (default: 1000000)")
    synth_p.add_argument("--samples", type=int, default=4096, help="Number of samples (default: 4096)")
    synth_p.add_argument("--cfo-hz", type=float, default=1250.0, help="Carrier frequency offset in Hz (default: 1250)")
    synth_p.add_argument("--iq-gain-db", type=float, default=0.50, help="IQ gain imbalance in dB (default: 0.50)")
    synth_p.add_argument("--iq-skew-deg", type=float, default=3.0, help="IQ phase skew in degrees (default: 3.0)")
    synth_p.add_argument("--dc-i", type=float, default=0.04, help="DC offset on I branch (default: 0.04)")
    synth_p.add_argument("--dc-q", type=float, default=-0.03, help="DC offset on Q branch (default: -0.03)")
    synth_p.add_argument("--lo-phase-noise-deg", type=float, default=1.2, help="LO phase noise RMS in degrees (default: 1.2)")
    synth_p.add_argument("--pa-ramp-samples", type=int, default=128, help="PA turn-on ramp samples (default: 128)")
    synth_p.add_argument("--snr-db", type=float, default=35.0, help="Signal-to-noise ratio in dB (default: 35.0)")
    synth_p.add_argument("--tx-id", default="TX-ALPHA-01", help="Transmitter ID (default: TX-ALPHA-01)")
    synth_p.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    synth_p.add_argument("--output", help="Optional output path to save burst JSON")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.policy_file):
        sys.stderr.write(f"Error: Policy file not found: {args.policy_file}\n")
        return 2

    try:
        cfg = load_policy_from_file(args.policy_file)
        report = evaluate_policy(cfg)
    except Exception as e:
        sys.stderr.write(f"Error evaluating policy: {e}\n")
        return 2

    if args.format == "json":
        text = format_canonical_json(report)
    elif args.format == "sarif":
        text = format_sarif(report)
    else:
        text = format_terminal_table(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            print(f"Report written to {args.output}")
        except Exception as e:
            sys.stderr.write(f"Error writing to output file: {e}\n")
            return 2
    else:
        print(text)

    # Return exit code 0 if score >= 50, else exit code 1
    return 0 if report.score >= 50 else 1


def run_extract(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.burst_file):
        sys.stderr.write(f"Error: Burst file not found: {args.burst_file}\n")
        return 2

    try:
        with open(args.burst_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        burst = IQBurst.from_dict(data)
        features = extract_rf_features(burst, lag_d=args.lag_d)
    except Exception as e:
        sys.stderr.write(f"Error processing burst: {e}\n")
        return 2

    print("===================================================================")
    print("      PHYSICAL-LAYER RF TRANSMITTER BIOMETRIC FEATURE EXTRACTION   ")
    print("===================================================================")
    print(f" Transmitter ID         : {burst.transmitter_id or 'UNKNOWN'}")
    print(f" Sample Count           : {features.sample_count}")
    print(f" Carrier Freq Offset    : {features.cfo_hz:+.2f} Hz")
    print(f" IQ Gain Imbalance      : {features.iq_gain_imbalance_db:+.4f} dB")
    print(f" IQ Phase Skew          : {features.iq_phase_skew_deg:+.4f} deg")
    print(f" DC Offset (I branch)   : {features.dc_offset_i:+.5f}")
    print(f" DC Offset (Q branch)   : {features.dc_offset_q:+.5f}")
    print(f" LO Phase Noise (RMS)   : {features.lo_phase_noise_rms_deg:.4f} deg")
    print(f" PA Rise Time (10%-90%) : {features.pa_rise_time_us:.2f} us")
    print(f" Envelope Kurtosis (k4) : {features.envelope_kurtosis:.4f}")
    print(f" Burst SHA-256 Digest   : {features.burst_sha256}")
    print(f" 6D Classification Vec  : {features.to_6d_vector()}")
    print("===================================================================")
    return 0


def run_verify_tx(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.burst):
        sys.stderr.write(f"Error: Burst file not found: {args.burst}\n")
        return 2
    if not os.path.isfile(args.db):
        sys.stderr.write(f"Error: Database file not found: {args.db}\n")
        return 2

    try:
        with open(args.burst, "r", encoding="utf-8") as f:
            burst_data = json.load(f)
        burst = IQBurst.from_dict(burst_data)

        db = TransmitterDatabase.load_from_file(args.db)
        classifier = MahalanobisClassifier(db, threshold=args.threshold)
        result = classifier.classify(
            burst,
            claimed_id=args.claimed_id,
            check_replay=not args.no_replay_check,
        )
    except Exception as e:
        sys.stderr.write(f"Error running transmitter verification: {e}\n")
        return 2

    print("===================================================================")
    print("         PHYSICAL-LAYER RF TRANSMITTER AUTHENTICATION RESULT       ")
    print("===================================================================")
    print(f" Verdict                : {result.verdict}")
    print(f" Authentic Emitter      : {'YES' if result.is_authentic else 'NO'}")
    print(f" Claimed ID             : {result.claimed_transmitter_id or 'None (Blind Classify)'}")
    print(f" Best Match Enrolled ID : {result.best_match_id or 'None'}")
    print(f" Mahalanobis Distance   : {result.mahalanobis_distance:.4f}")
    if result.claimed_mahalanobis_distance is not None:
        print(f" Claimed ID Distance    : {result.claimed_mahalanobis_distance:.4f}")
    print(f" Decision Threshold     : {result.threshold:.2f}")
    print(f" Details                : {result.details}")
    print("-------------------------------------------------------------------")
    f_dict = result.extracted_features.to_dict()
    print(f" Extracted CFO          : {f_dict['cfo_hz']:+.2f} Hz")
    print(f" Extracted IQ Gain      : {f_dict['iq_gain_imbalance_db']:+.4f} dB")
    print(f" Extracted IQ Skew      : {f_dict['iq_phase_skew_deg']:+.4f} deg")
    print(f" Extracted LO Noise RMS : {f_dict['lo_phase_noise_rms_deg']:.4f} deg")
    print("===================================================================")

    return 0 if result.is_authentic else 1


def run_synth_burst(args: argparse.Namespace) -> int:
    try:
        burst = synthesize_impaired_iq_burst(
            sample_rate_hz=args.sample_rate,
            num_samples=args.samples,
            cfo_hz=args.cfo_hz,
            iq_gain_db=args.iq_gain_db,
            iq_skew_deg=args.iq_skew_deg,
            dc_i=args.dc_i,
            dc_q=args.dc_q,
            lo_phase_noise_deg=args.lo_phase_noise_deg,
            pa_ramp_samples=args.pa_ramp_samples,
            snr_db=args.snr_db,
            transmitter_id=args.tx_id,
            seed=args.seed,
        )
    except Exception as e:
        sys.stderr.write(f"Error synthesizing burst: {e}\n")
        return 2

    out_data = burst.to_dict()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(out_data, f, indent=2)
            print(f"Successfully generated and saved IQ burst: {args.output}")
            print(f"  Samples: {burst.sample_count} | CFO: {args.cfo_hz} Hz | SHA-256: {burst.sha256_digest()[:16]}...")
        except Exception as e:
            sys.stderr.write(f"Error saving burst to {args.output}: {e}\n")
            return 2
    else:
        print(json.dumps(out_data, indent=2))

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    elif args.command == "extract":
        return run_extract(args)
    elif args.command == "verify-tx":
        return run_verify_tx(args)
    elif args.command == "synth-burst":
        return run_synth_burst(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
