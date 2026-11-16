# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-047`  
**Repository**: `lh-rf-fingerprinter`  
**CLI Executable**: `lh-rf-fingerprint`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-047` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-rf-fingerprinter` (`lh-rf-fingerprint`) |
| **Target Language / Platform** | `Python` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-rf-fingerprinter](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-rf-fingerprinter) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-rf-fingerprint` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `Python`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: Multivariate Mahalanobis Physical Transmitter Distance

The underlying computational core of `lh-rf-fingerprinter` is formally governed by the following mathematical and algorithmic formulations:

$$D_M(\mathbf{x}, \mathbf{\mu}) = \sqrt{(\mathbf{x} - \mathbf{\mu})^T \mathbf{\Sigma}^{-1} (\mathbf{x} - \mathbf{\mu})}$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-RFF-001` | `CRITICAL` | `25` | `CWE-290` | rf_fingerprinting_enabled == true && allow_mac_only_fallback == false | Enforce physical-layer RF fingerprinting; disallow unauthenticated MAC fallback. |
| `LH-RFF-002` | `CRITICAL` | `25` | `CWE-682` | mahalanobis_threshold <= 5.0 | Bound Mahalanobis decision boundary to prevent SDR impersonation ($\tau \le 5.0$). |
| `LH-RFF-003` | `CRITICAL` | `25` | `CWE-294` | iq_replay_detection_enabled == true && bind_phy_fingerprint_to_crypto_auth == true | Enforce digital IQ burst replay checks and bind physical biometrics to crypto auth. |
| `LH-RFF-004` | `HIGH` | `10` | `CWE-20` | min_snr_db >= 15.0 | Gate burst processing on receiver SNR threshold ($\ge 15.0\text{ dB}$). |
| `LH-RFF-005` | `HIGH` | `10` | `CWE-682` | All 4 impairment classes enabled (IQ imbalance, CFO, LO noise, PA transient) | Enable comprehensive multi-feature extraction across all analog domains. |
| `LH-RFF-006` | `HIGH` | `10` | `CWE-367` | temperature_drift_compensation == true && rx_gpsdo_locked == true | Calibrate receiver clock using GPSDO reference and thermal drift compensation. |
| `LH-RFF-007` | `HIGH` | `10` | `CWE-353` | fingerprint_db_signed == true && allow_unauthenticated_enrollment == false | Sign transmitter profile database and disallow unauthenticated runtime enrollment. |
| `LH-RFF-008` | `MEDIUM` | `4` | `CWE-682` | min_burst_samples >= 512 && oversampling_factor >= 4 | Ensure adequate preamble sample window and ADC oversampling ratio. |
| `LH-RFF-009` | `MEDIUM` | `4` | `CWE-400` | multipath_channel_normalization == true | Normalize multipath channel distortion prior to constellation feature extraction. |
| `LH-RFF-010` | `LOW` | `1` | `CWE-778` | log_rogue_tx_alerts == true && capture_forensic_iq_on_reject == true | Enable SIEM alert forwarding and forensic raw IQ capture upon burst rejection. |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-rf-fingerprint` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-rf-fingerprint <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-RFF-001` .. `LH-RFF-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## 6. Standalone Future Development Roadmap (`v0.2.0` — `v0.5.0`)

`lh-rf-fingerprinter` is developed as an independent, standalone open-source project. The following roadmap defines the planned architectural, algorithmic, and protocol enhancements for upcoming point releases of `lh-rf-fingerprinter`:

| Target Release | Milestone Focus | Planned Technical Deliverables for `lh-rf-fingerprinter` |
|---|---|---|
| **`v0.2.0`** | Parser & Protocol Expansion | Add Welch PSD spectral flatness, Higher-Order Cumulants ($C_{40}, C_{41}, C_{42}$), and carrier phase-noise power-law slope ($1/f^2, 1/f^3$) feature extractors. |
| **`v0.3.0`** | Deep Algorithmic & Stateful Analysis | Implement full covariance matrix inversion for correlated multi-dimensional Mahalanobis distance and Support Vector Domain Description (SVDD) novelty detection. |
| **`v0.4.0`** | Remediation, Synthesis & Format Interop | Add adaptive multipath channel equalization (CMA / LMS blind equalizer) prior to radiometric feature extraction to neutralize indoor reflections. |
| **`v0.5.0`** | High-Throughput Performance & Formal Verification | Support VITA-49 (VRT) and SigMF IQ stream ingestion with automated crystal temperature-drift kalman tracking. |

### 6.1 `v0.2.0` — Parser & Protocol Expansion
- **Format & Protocol Ingestion**: Add Welch PSD spectral flatness, Higher-Order Cumulants ($C_{40}, C_{41}, C_{42}$), and carrier phase-noise power-law slope ($1/f^2, 1/f^3$) feature extractors.
- **Zero-Dependency Architecture**: Pure standard library implementation with deterministic parsing guarantees and strict error handling.
- **Verification & Telemetry**: Regression test suites verifying schema edge-cases, malformed payload rejections, and SARIF v2.1.0 output fidelity.

### 6.2 `v0.3.0` — Deep Algorithmic & Stateful Analysis
- **Algorithmic Core**: Implement full covariance matrix inversion for correlated multi-dimensional Mahalanobis distance and Support Vector Domain Description (SVDD) novelty detection.
- **State Machine & Analysis Engine**: High-fidelity state tracking, cycle detection, and invariant checking with minimal computational overhead.
- **Differential & Regression Verification**: Comprehensive test harnesses covering stateful transitions, edge conditions, and mathematical boundary constraints.

### 6.3 `v0.4.0` — Remediation, Synthesis & Format Interoperability
- **Synthesis & Interoperability**: Add adaptive multipath channel equalization (CMA / LMS blind equalizer) prior to radiometric feature extraction to neutralize indoor reflections.
- **Automated Remediation Workflows**: Idempotent generation of verified configuration patches, policy rules, and standardized cross-format exports.
- **Contract & Artifact Validation**: Cryptographic baseline verification and end-to-end integration testing for synthesized deliverables.

### 6.4 `v0.5.0` — High-Throughput Performance & Formal Verification
- **High-Throughput Optimization**: Support VITA-49 (VRT) and SigMF IQ stream ingestion with automated crystal temperature-drift kalman tracking.
- **Hardware & Kernel Acceleration**: Vectorized SIMD/eBPF/sub-millisecond streaming execution with bounded memory allocation.
- **Formal Verification & Assurance**: Mathematical proof of invariant preservation, false-positive calibration, and high-assurance certification baselines.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
