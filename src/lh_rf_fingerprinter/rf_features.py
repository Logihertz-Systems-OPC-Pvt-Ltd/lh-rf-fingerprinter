"""Physical-Layer Radiometric Hardware Impairment Extractor & Synthetic Burst Generator.

Extracts Carrier Frequency Offset (CFO), IQ gain imbalance, IQ phase skew,
origin DC offsets, LO phase noise RMS, and Power Amplifier (PA) turn-on transients.
"""

from __future__ import annotations

import cmath
import hashlib
import json
import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IQBurst:
    """Represents a complex baseband IQ burst captured at a physical-layer receiver."""

    sample_rate_hz: float
    i_samples: List[float]
    q_samples: List[float]
    timestamp_utc: str = ""
    transmitter_id: str = ""
    snr_db: float = 30.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.i_samples) != len(self.q_samples):
            raise ValueError(
                f"I and Q sample lengths must match: len(I)={len(self.i_samples)}, len(Q)={len(self.q_samples)}"
            )

    @property
    def sample_count(self) -> int:
        return len(self.i_samples)

    def sha256_digest(self) -> str:
        """Computes a deterministic SHA-256 digest over the raw quantized sample values."""
        hasher = hashlib.sha256()
        for i_val, q_val in zip(self.i_samples, self.q_samples):
            hasher.update(f"{i_val:.8f},{q_val:.8f};".encode("ascii"))
        return hasher.hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_rate_hz": self.sample_rate_hz,
            "transmitter_id": self.transmitter_id,
            "timestamp_utc": self.timestamp_utc,
            "snr_db": self.snr_db,
            "sample_count": self.sample_count,
            "burst_sha256": self.sha256_digest(),
            "metadata": self.metadata,
            "i_samples": self.i_samples,
            "q_samples": self.q_samples,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IQBurst:
        return cls(
            sample_rate_hz=float(data["sample_rate_hz"]),
            i_samples=[float(x) for x in data["i_samples"]],
            q_samples=[float(x) for x in data["q_samples"]],
            timestamp_utc=str(data.get("timestamp_utc", "")),
            transmitter_id=str(data.get("transmitter_id", "")),
            snr_db=float(data.get("snr_db", 30.0)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class RFFeatureVector:
    """Extracted physical-layer radiometric transmitter fingerprint feature vector."""

    cfo_hz: float
    iq_gain_imbalance_db: float
    iq_phase_skew_deg: float
    dc_offset_i: float
    dc_offset_q: float
    lo_phase_noise_rms_deg: float
    pa_rise_time_us: float
    envelope_kurtosis: float
    burst_sha256: str
    sample_count: int

    def to_6d_vector(self) -> List[float]:
        """Returns the canonical 6-dimensional feature vector for Mahalanobis classification."""
        return [
            self.cfo_hz,
            self.iq_gain_imbalance_db,
            self.iq_phase_skew_deg,
            self.dc_offset_i,
            self.dc_offset_q,
            self.lo_phase_noise_rms_deg,
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cfo_hz": round(self.cfo_hz, 3),
            "iq_gain_imbalance_db": round(self.iq_gain_imbalance_db, 4),
            "iq_phase_skew_deg": round(self.iq_phase_skew_deg, 4),
            "dc_offset_i": round(self.dc_offset_i, 5),
            "dc_offset_q": round(self.dc_offset_q, 5),
            "lo_phase_noise_rms_deg": round(self.lo_phase_noise_rms_deg, 4),
            "pa_rise_time_us": round(self.pa_rise_time_us, 2),
            "envelope_kurtosis": round(self.envelope_kurtosis, 4),
            "burst_sha256": self.burst_sha256,
            "sample_count": self.sample_count,
            "vector_6d": [round(x, 4) for x in self.to_6d_vector()],
        }


def synthesize_impaired_iq_burst(
    sample_rate_hz: float = 1_000_000.0,
    num_samples: int = 4096,
    cfo_hz: float = 1250.0,
    iq_gain_db: float = 0.50,
    iq_skew_deg: float = 3.0,
    dc_i: float = 0.04,
    dc_q: float = -0.03,
    lo_phase_noise_deg: float = 1.2,
    pa_ramp_samples: int = 128,
    snr_db: float = 38.0,
    transmitter_id: str = "TX-ALPHA-01",
    seed: int = 42,
) -> IQBurst:
    """Generates a synthetic complex IQ burst with exact radiometric hardware impairments.

    Models:
    - Baseband carrier preamble with Power Amplifier (PA) envelope turn-on ramp (raised cosine)
    - Carrier Frequency Offset (CFO) and Local Oscillator (LO) phase jitter
    - Quadrature Mixer IQ gain imbalance and phase non-orthogonality
    - Transmitter Origin DC carrier leakage
    - Additive White Gaussian Noise (AWGN) at specified SNR
    """
    rng = random.Random(seed)

    # 1. Baseband carrier with PA turn-on envelope ramp
    env_i: List[float] = []
    for n in range(num_samples):
        if n < pa_ramp_samples:
            ramp = 0.5 * (1.0 - math.cos(math.pi * n / pa_ramp_samples))
        else:
            ramp = 1.0
        env_i.append(ramp)

    # 2. Carrier Frequency Offset (CFO) and LO Phase Noise
    sigma_phase_rad = lo_phase_noise_deg * (math.pi / 180.0)
    cfo_i: List[float] = []
    cfo_q: List[float] = []

    for n in range(num_samples):
        jitter = rng.gauss(0.0, sigma_phase_rad)
        theta = 2.0 * math.pi * cfo_hz * (n / sample_rate_hz) + jitter
        cfo_i.append(env_i[n] * math.cos(theta))
        cfo_q.append(env_i[n] * math.sin(theta))

    # 3. Quadrature Mixer IQ gain imbalance and phase skew
    gain_linear = 10.0 ** (iq_gain_db / 20.0)
    skew_rad = iq_skew_deg * (math.pi / 180.0)

    imb_i = [gain_linear * cfo_i[n] for n in range(num_samples)]
    imb_q = [
        math.sin(skew_rad) * cfo_i[n] + math.cos(skew_rad) * cfo_q[n]
        for n in range(num_samples)
    ]

    # Center AC components to ensure exact DC offset calibration
    mean_imb_i = sum(imb_i) / num_samples
    mean_imb_q = sum(imb_q) / num_samples
    ac_i = [x - mean_imb_i for x in imb_i]
    ac_q = [y - mean_imb_q for y in imb_q]

    # 4. DC Origin Carrier Leakage & AWGN noise injection
    noise_sigma = 10.0 ** (-snr_db / 20.0) / math.sqrt(2.0)
    final_i: List[float] = []
    final_q: List[float] = []

    for n in range(num_samples):
        n_i = rng.gauss(0.0, noise_sigma)
        n_q = rng.gauss(0.0, noise_sigma)
        final_i.append(ac_i[n] + dc_i + n_i)
        final_q.append(ac_q[n] + dc_q + n_q)

    return IQBurst(
        sample_rate_hz=sample_rate_hz,
        i_samples=final_i,
        q_samples=final_q,
        timestamp_utc="2026-11-13T12:00:00Z",
        transmitter_id=transmitter_id,
        snr_db=snr_db,
        metadata={
            "synthetic": True,
            "configured_cfo_hz": cfo_hz,
            "configured_iq_gain_db": iq_gain_db,
            "configured_iq_skew_deg": iq_skew_deg,
            "configured_dc_i": dc_i,
            "configured_dc_q": dc_q,
            "configured_lo_phase_noise_deg": lo_phase_noise_deg,
            "configured_pa_ramp_samples": pa_ramp_samples,
        },
    )


def extract_rf_features(burst: IQBurst, lag_d: int = 1) -> RFFeatureVector:
    """Extracts radiometric physical-layer hardware biometric impairments from an IQ burst."""
    n = burst.sample_count
    if n < 64:
        raise ValueError(f"Insufficient burst sample length: {n} (minimum required is 64)")

    fs = burst.sample_rate_hz
    i_raw = burst.i_samples
    q_raw = burst.q_samples

    # 1. Normalized DC Offsets (Origin Carrier Leakage)
    mean_i = sum(i_raw) / n
    mean_q = sum(q_raw) / n

    # Centered components
    i_centered = [x - mean_i for x in i_raw]
    q_centered = [y - mean_q for y in q_raw]

    # 2. Quadrature Mixer IQ Gain Imbalance and Phase Skew
    var_i = sum(x * x for x in i_centered) / n
    var_q = sum(y * y for y in q_centered) / n
    std_i = math.sqrt(max(1e-18, var_i))
    std_q = math.sqrt(max(1e-18, var_q))

    # Gain imbalance (in dB)
    iq_gain_imbalance_db = 20.0 * math.log10((std_i / (std_q + 1e-12)) + 1e-15)

    # Phase skew (in degrees)
    cov_iq = sum(x * y for x, y in zip(i_centered, q_centered)) / n
    corr_coeff = cov_iq / ((std_i * std_q) + 1e-12)
    clamped_corr = max(-1.0, min(1.0, corr_coeff))
    iq_phase_skew_deg = math.asin(clamped_corr) * (180.0 / math.pi)

    # 3. Lag-D Autocorrelation Carrier Frequency Offset (CFO)
    # Form orthogonalized, compensated complex baseband signal
    skew_rad = iq_phase_skew_deg * (math.pi / 180.0)
    cos_skew = math.cos(skew_rad)
    sin_skew = math.sin(skew_rad)
    gain_lin = 10.0 ** (iq_gain_imbalance_db / 20.0)

    s_real: List[float] = []
    s_imag: List[float] = []
    for x, y in zip(i_centered, q_centered):
        # Invert mixer matrix
        s_i = x / (gain_lin + 1e-12)
        s_q = (y - sin_skew * s_i) / (cos_skew + 1e-12)
        s_real.append(s_i)
        s_imag.append(s_q)

    # Compute autocorrelation at lag D
    if lag_d < 1 or lag_d >= n:
        lag_d = 1

    r_real = sum(
        s_real[k] * s_real[k - lag_d] + s_imag[k] * s_imag[k - lag_d]
        for k in range(lag_d, n)
    )
    r_imag = sum(
        s_imag[k] * s_real[k - lag_d] - s_real[k] * s_imag[k - lag_d]
        for k in range(lag_d, n)
    )

    delta_theta = math.atan2(r_imag, r_real)
    cfo_hz = (fs * delta_theta) / (2.0 * math.pi * lag_d)

    # 4. LO Phase Noise RMS Calculation
    # Derotate estimated CFO and unwrap phase residuals over steady-state portion
    steady_start = min(128, n // 4)
    phases: List[float] = []
    for k in range(steady_start, n):
        theta_derot = -2.0 * math.pi * cfo_hz * (k / fs)
        cos_d = math.cos(theta_derot)
        sin_d = math.sin(theta_derot)
        dr_r = s_real[k] * cos_d - s_imag[k] * sin_d
        dr_i = s_real[k] * sin_d + s_imag[k] * cos_d
        phases.append(math.atan2(dr_i, dr_r))

    if len(phases) > 1:
        unwrapped = [phases[0]]
        for k in range(1, len(phases)):
            diff = phases[k] - phases[k - 1]
            while diff > math.pi:
                diff -= 2.0 * math.pi
            while diff < -math.pi:
                diff += 2.0 * math.pi
            unwrapped.append(unwrapped[-1] + diff)

        # Remove linear trend (least squares line fit)
        np_pts = len(unwrapped)
        sum_x = (np_pts * (np_pts - 1)) / 2.0
        sum_x2 = (np_pts * (np_pts - 1) * (2 * np_pts - 1)) / 6.0
        sum_y = sum(unwrapped)
        sum_xy = sum(i * unwrapped[i] for i in range(np_pts))
        denom = (np_pts * sum_x2 - sum_x * sum_x) or 1.0
        slope = (np_pts * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / np_pts

        residuals = [unwrapped[i] - (slope * i + intercept) for i in range(np_pts)]
        var_res = sum(r * r for r in residuals) / np_pts
        lo_phase_noise_rms_deg = math.sqrt(max(0.0, var_res)) * (180.0 / math.pi)
    else:
        lo_phase_noise_rms_deg = 0.0

    # 5. PA Turn-On Transient Rise Time & Envelope Kurtosis
    envelopes = [math.sqrt(x * x + y * y) for x, y in zip(i_raw, q_raw)]

    # Steady state amplitude estimation (median of 50%..90% window)
    sorted_steady = sorted(envelopes[int(n * 0.5) : int(n * 0.9) + 1])
    if sorted_steady:
        steady_amp = sorted_steady[len(sorted_steady) // 2]
    else:
        steady_amp = max(envelopes)

    t10_threshold = 0.10 * steady_amp
    t90_threshold = 0.90 * steady_amp

    idx_10: Optional[int] = None
    idx_90: Optional[int] = None

    for i, amp in enumerate(envelopes):
        if idx_10 is None and amp >= t10_threshold:
            idx_10 = i
        if idx_90 is None and amp >= t90_threshold:
            idx_90 = i
            break

    if idx_10 is not None and idx_90 is not None and idx_90 >= idx_10:
        pa_rise_time_us = ((idx_90 - idx_10) / fs) * 1e6
    else:
        pa_rise_time_us = 0.0

    # 4th-order Envelope Kurtosis
    mean_env = sum(envelopes) / n
    var_env = sum((e - mean_env) ** 2 for e in envelopes) / n
    std_env = math.sqrt(max(1e-18, var_env))
    fourth_moment = sum((e - mean_env) ** 4 for e in envelopes) / n
    envelope_kurtosis = fourth_moment / ((std_env ** 4) + 1e-12)

    return RFFeatureVector(
        cfo_hz=cfo_hz,
        iq_gain_imbalance_db=iq_gain_imbalance_db,
        iq_phase_skew_deg=iq_phase_skew_deg,
        dc_offset_i=mean_i,
        dc_offset_q=mean_q,
        lo_phase_noise_rms_deg=lo_phase_noise_rms_deg,
        pa_rise_time_us=pa_rise_time_us,
        envelope_kurtosis=envelope_kurtosis,
        burst_sha256=burst.sha256_digest(),
        sample_count=n,
    )
