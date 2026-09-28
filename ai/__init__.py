"""WiFiSentinel AI - detection engine.

Passive, explainable risk assessment of observed Wi-Fi access points. The
engine answers one question:

    Does this access point belong to the expected wireless infrastructure, and
    does its fingerprint deviate from the normal profile?

It does **not** treat a duplicated SSID as an attack signal - a single
legitimate network routinely spans many BSSIDs.

Quick start (this is the whole integration surface)::

    from scanner import scan_wifi
    from ai.pipeline import analyze_scan
    from ai.profile_store import ProfileStore

    report = analyze_scan(scan_wifi(), profiles=ProfileStore().load())

    for result in report["results"]:
        print(result["bssid"], result["risk_score"], result["classification"])
        for reason in result["reasons"]:
            print("   -", reason)

Every access point analysed here was really observed by the local Wi-Fi
adapter. This package ships no example networks and no built-in baseline: a
BSSID becomes trusted only when an operator records one from a real scan
(``python run_scan.py trust "<SSID>"``), and an unfamiliar site reports
``UNVERIFIED`` rather than inventing a comparison.

Security boundary: this package performs passive analysis of wireless metadata
supplied by the scanner. It contains no active probing, no packet injection,
no deauthentication and no credential handling.
"""

from .anomaly import AnomalyDetector
from .features import FEATURE_NAMES, build_feature_matrix, extract_features
from .identity import NetworkIdentity, OuiRegistry, identity_of, oui_of
from .models import (
    AnomalyResult,
    Classification,
    DetectionResult,
    ProfileComparison,
    RuleResult,
    TrustedProfile,
    WiFiNetwork,
)
from .pipeline import analyze_network, analyze_networks, analyze_scan
from .profile_store import (
    DEFAULT_PROFILE_PATH,
    ProfileStore,
    build_profile_from_observations,
    load_trusted_profiles,
)
from .risk_engine import DEFAULT_CONFIG, ScoringConfig
from .rules import evaluate_rules
from .verdict import EvidenceLevel, FraudAssessment, SignalFamily, Verdict, assess_fraud
from .trusted_profile import (
    ProvisionalBaseline,
    build_provisional_profile,
    compare_to_profile,
    load_profiles,
)

__all__ = [
    "analyze_network",
    "analyze_networks",
    "analyze_scan",
    "AnomalyDetector",
    "AnomalyResult",
    "Classification",
    "DetectionResult",
    "ProfileComparison",
    "ProfileStore",
    "DEFAULT_PROFILE_PATH",
    "RuleResult",
    "TrustedProfile",
    "WiFiNetwork",
    "ScoringConfig",
    "DEFAULT_CONFIG",
    "evaluate_rules",
    "Verdict",
    "EvidenceLevel",
    "SignalFamily",
    "FraudAssessment",
    "assess_fraud",
    "extract_features",
    "build_feature_matrix",
    "FEATURE_NAMES",
    "compare_to_profile",
    "NetworkIdentity",
    "identity_of",
    "OuiRegistry",
    "oui_of",
    "build_profile_from_observations",
    "build_provisional_profile",
    "ProvisionalBaseline",
    "load_profiles",
    "load_trusted_profiles",
]

__version__ = "0.1.0"
