# Security Policy: lh-rf-fingerprinter

## Threat Model & Physical-Layer RF Fingerprinting Guarantees

`lh-rf-fingerprinter` provides physical-layer radiometric hardware fingerprinting, RF emitter identification, and transmission anomaly detection for tactical wireless, cognitive radio, and SDR ecosystems.

The security architecture addresses the following threat classes:
1. **Layer-2 MAC / Emitter ID Spoofing**: Adversaries transmitting forged MAC addresses or transmitter IDs using Software-Defined Radios (SDRs) are identified and rejected via distinctive analog silicon hardware impairments (Carrier Frequency Offset, IQ gain imbalance, IQ phase skew, DC origin leak, LO phase noise, and PA turn-on transients).
2. **Digital IQ Waveform Replay Attacks**: Adversaries recording and replaying pre-recorded raw IQ transmissions are detected via exact bitwise SHA-256 burst fingerprint matching and thermal noise variance floor verification.
3. **Eavesdropping & Sybil Attacks**: Unauthenticated emitters masquerading as multiple authorized field nodes are clustered and flagged via regularized Mahalanobis distance profiling.
4. **Permissive Classification Boundaries**: Guarding against overly loose acceptance thresholds ($\tau_{\text{threshold}} > 5.0$) that would allow commercial off-the-shelf SDRs to spoof authentic profiles.

## Reporting a Vulnerability

Please report security vulnerabilities or bypasses to `security@logihertz.com` with a copy to `ops@logihertz.com`. We coordinate disclosure and issue remediation advisories promptly.
