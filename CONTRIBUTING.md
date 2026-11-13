# Contributing to lh-rf-fingerprinter

Thank you for your interest in contributing to `lh-rf-fingerprinter` (`lh-rf-fingerprint`). This repository is part of the Logihertz 60-Tool Open-Source Ecosystem, providing a physical-layer RF transmitter fingerprinting engine, hardware impairment feature extractor, Mahalanobis device classifier, and 10-rule physical-layer security posture auditor.

## Core Architectural Mandates

1. **Zero External Runtime Dependencies**:
   `lh-rf-fingerprinter` is engineered exclusively using the Python 3.11+ Standard Library (`math`, `cmath`, `hashlib`, `statistics`, `argparse`, `dataclasses`, `typing`, `json`, `pathlib`). No third-party packages (NumPy, SciPy, scikit-learn, etc.) are permitted at runtime.
2. **Mathematical Precision & Rigor**:
   All DSP algorithms (autocorrelation CFO estimation, IQ gain imbalance, phase skew arcsin estimation, phase noise unwrapping, and Mahalanobis distance) must be numerically stable and implement regularized division to prevent divide-by-zero on low-energy or silent bursts.
3. **Deterministic Testing**:
   Unit tests must achieve 100% reproducible results without nondeterministic random seeds. All synthetic IQ burst generators must support deterministic seed parameters.

## Development Workflow

### Prerequisites
- Python 3.11, 3.12, or 3.13
- Git

### Running Tests
Execute the unit test suite across Python versions:
```bash
python3 -m unittest discover -s tests -v
```

### Checking Syntax & Lint
```bash
python3 -m py_compile src/lh_rf_fingerprinter/*.py tests/*.py
```

## Pull Request Guidelines
- Ensure all new features or bug fixes include deterministic assertions in `tests/test_rf_fingerprinter.py`.
- Maintain clean code formatting and type hints according to PEP 8.
- Update documentation and the 10-rule posture checklist when modifying physical-layer audit rules.
