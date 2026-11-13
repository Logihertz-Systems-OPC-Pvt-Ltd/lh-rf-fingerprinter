# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **Radiometric Hardware Impairment Extractor (`rf_features.py`)**:
  - Carrier Frequency Offset (CFO) estimation via lag-$D$ complex autocorrelation.
  - Quadrature mixer IQ gain imbalance ($\hat{\epsilon}_{\text{dB}}$) and phase skew ($\hat{\phi}_{\text{skew, deg}}$) estimation.
  - Origin / carrier leak DC offset estimation ($\hat{\mu}_I, \hat{\mu}_Q$) and centering.
  - Local Oscillator (LO) phase noise residual RMS ($\sigma_{\phi,\text{rms}}$) after CFO derotation and phase unwrapping.
  - Power Amplifier (PA) turn-on transient rise time ($T_{\text{rise, us}}$) from 10% to 90% steady-state amplitude.
  - Normalized 4th-order envelope kurtosis ($\kappa_4$) metric.
  - Deterministic synthetic impaired IQ burst synthesizer (`synthesize_impaired_iq_burst`).
- **Mahalanobis Transmitter Classifier & Anomaly Detector (`classifier.py`)**:
  - 6-dimensional feature vector parameterization: $\mathbf{x} = [\hat{f}_{\text{CFO}}, \hat{\epsilon}_{\text{dB}}, \hat{\phi}_{\text{skew, deg}}, \hat{\mu}_I, \hat{\mu}_Q, \sigma_{\phi,\text{rms}}]^T$.
  - Regularized diagonal Mahalanobis distance calculation against enrolled transmitter profiles.
  - Layer-2 MAC address spoofing and rogue transmitter detection against claimed device IDs.
  - Exact digital IQ waveform replay detection via SHA-256 burst fingerprinting and noise floor variance checks.
- **10-Rule RF Physical-Layer Posture Auditor (`auditor.py`)**:
  - Normative compliance evaluation covering rules `LH-RFF-001` through `LH-RFF-010`.
  - Standardized Logihertz Security Posture Score ($S_{\text{posture}} \in [0, 100]$) with status categorization: `HARDENED`, `ACCEPTABLE`, `DEGRADED`, and `NON-COMPLIANT`.
  - ANSI terminal table, canonical JSON, and OASIS SARIF v2.1.0 exporters (`exporters.py`).
- **Production CLI (`bin/lh-rf-fingerprint` & `cli.py`)**:
  - `scan`: Audit RF physical-layer security configuration against the 10 normative rules.
  - `extract`: Extract and display hardware biometric feature vectors and PA transients from complex IQ bursts.
  - `verify-tx`: Authenticate received IQ bursts against enrolled transmitter profiles and flag spoofers.
  - `synth-burst`: Generate synthetic impaired IQ bursts for testing and algorithm validation.
  - `--version` and `--help` global flags.
- **Zero External Dependencies**:
  - Built strictly using Python 3.11+ standard library (`math`, `cmath`, `hashlib`, `statistics`, `argparse`, `dataclasses`, `typing`).
