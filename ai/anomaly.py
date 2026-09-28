"""Isolation Forest anomaly detection over wireless metadata.

The model learns what "normal" looks like for a wireless environment from a
baseline of observations, then reports how far a new observation sits from
that baseline.

What the score is, and is not
-----------------------------
``IsolationForest.decision_function`` returns ``score_samples`` minus the offset
chosen at fit time: **positive for inliers, negative for outliers**, with 0 as
the decision boundary. The raw value is a poor UI number - on a small baseline
it occupies a narrow band around the boundary, so an obvious outlier and a
marginal one come out as 0.62 and 0.45.

The score is therefore rescaled **relative to the fitted baseline's own observed
decision range** rather than through a fixed function:

.. code-block:: text

    span     = max_decision - min_decision        # from the training rows
    score    = clamp((max_decision - decision) / (2 * span), 0, 1)

so ``0`` means "the most normal-looking value the baseline produced", ``0.5``
means "the least normal baseline observation" and ``1`` means "further out
than any baseline observation was". The transform is strictly monotone, so the
model's own ordering is preserved exactly.

This is a **relative deviation indicator**, not a probability. A score of 0.84
does not mean "84% chance of attack"; it means "this observation sits far into
the tail of the learned baseline". The name ``anomaly_score`` is deliberate and
must not be renamed to anything implying attack likelihood.

What this model can and cannot do
---------------------------------
Stated plainly, because it was measured rather than assumed (see the
"Known limitation" section of the README for the experiment):

* It **corroborates**. A correctly-verified in-profile AP scores low; an
  observation far outside the site profile scores comparatively high.
* It **does not separate cleanly**. Isolation Forest scores a point by how
  quickly random axis-aligned splits isolate it. A point outside the training
  support and a point at the tail of a single feature are *both* isolated in
  O(1) splits, so their decisions saturate into the same narrow band. On this
  problem a rogue AP and a weak-signal legitimate AP receive comparable scores.

Consequences, both deliberate:

1. The **profile comparison is the primary evidence** and the ML is a
   secondary, corroborating signal. :mod:`ai.risk_engine` is built that way.
2. A fully profile-matching AP is **never** penalised by the anomaly score
   (``_anomaly_allowed`` in the risk engine). Authoritative profile evidence
   outranks a model whose tail ranking is known to be coarse, and this removes
   the only realistic false-positive path - a genuine AP with a faint signal.

The engineering conclusion is that the rules carry the classification and the
forest adds a second, independent opinion. Inflating the model's role to
compensate would mean discarding the Isolation Forest requirement, and the
brief explicitly prefers a simple, explainable working system over a
sophisticated one that does not work.

Baseline
--------
Fitting needs a baseline, and a baseline has to be real. There is no built-in
set of example access points: scoring a genuine network against an invented one
would produce a confident-looking number meaning nothing.

There are two legitimate sources, and only two:

1. The site's **configured trusted profile** (best for a known site) - a
   declared "WPA2 on 5 GHz channels 36-48" profile expands into a family of
   plausible normal observations.
2. A **provisional profile learned on site** from repeated real observations,
   for a location that has no configuration yet.

If neither is available the detector stays unfitted, reports
``available=False``, and the pipeline adds a reason saying so. That is a normal
state, not an error: at a site with no configuration there is genuinely no
"normal" to deviate from.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, List, Optional, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES, MODEL_VERSION, build_feature_matrix
from .models import AnomalyResult, ProfileComparison, WiFiNetwork

__all__ = [
    "AnomalyDetector",
    "SLOPE",
    "baseline_from_profiles",
]


#: Logistic slope retained for callers that want the absolute-boundary
#: transform. The default scoring is baseline-relative (see
#: :meth:`AnomalyDetector._to_score`); this is exported for comparison.
SLOPE = 4.0

#: Floor for the baseline decision span, so a degenerate baseline (all rows
#: identical) cannot produce a division by zero or a wildly amplified score.
MIN_DECISION_SPAN = 1e-3

#: Below this many baseline samples a fitted forest is not trustworthy, so the
#: detector reports ``available=False`` and the pipeline omits the ML reason.
MIN_BASELINE_ROWS = 4

#: Signal bounds (dBm) used when synthesising a baseline. Deliberately wider
#: than any real operator's operating range so that weak-but-legitimate APs sit
#: *inside* the learned distribution instead of on its edge - see
#: :data:`BASELINE_SAMPLES` for why that matters.
BASELINE_SIGNAL_LOW = -88
BASELINE_SIGNAL_HIGH = -32

#: Observations synthesised per profile. A small regular grid (the previous
#: approach) gave the forest a 3-dimensional, near-deterministic cloud whose
#: path lengths all saturated into the same band; a denser, jittered sample
#: gives the ensemble a genuine distribution to measure against.
BASELINE_SAMPLES = 160

#: Fixed seed. The demo must produce the same numbers on every run, otherwise
#: "the same input scored differently" becomes a question nobody can answer
#: during a live demo.
BASELINE_SEED = 1337


def baseline_from_profiles(
    profiles: Iterable[Any],
    samples: int = BASELINE_SAMPLES,
    seed: int = BASELINE_SEED,
) -> List[List[float]]:
    """Synthesise a feature baseline from configured trusted profiles.

    A profile already states the normal fingerprint (security, channels,
    frequencies, BSSIDs, vendors), so we expand it into plausible observations
    drawn from that fingerprint. This is how the demo works without a
    training-data pipeline: drop in a profile, get a fitted baseline.

    The synthesis is stochastic but **seeded**, so the same profiles always
    produce the same baseline and therefore the same anomaly scores.

    Signal strength is sampled across a wide realistic range rather than a few
    fixed values. Signal depends on where the observer is standing, not on
    whether an AP is genuine: a legitimate AP at the far end of a terminal can
    be as weak as -85 dBm. Sampling that spread means a weak signal reads as
    "ordinary here" rather than as an outlier.

    Optional fields are populated exactly as the profile constrains them (a
    vendor appears only when the profile lists vendors, and then from that
    list), so a baseline row is indistinguishable from a real verified
    observation in every column the model sees.
    """
    from .models import TrustedProfile  # local import keeps module import order simple
    from .trusted_profile import compare_to_profile

    rng = np.random.default_rng(seed)
    rows: List[List[float]] = []
    for raw in profiles or ():
        profile = TrustedProfile.from_dict(raw)
        channels = profile.expected_channels or [36]
        frequencies = profile.expected_frequencies or []
        securities = profile.security or ["WPA2"]
        vendors = profile.known_vendors or []
        bssids = profile.known_bssids or [f"00:00:00:00:00:{i:02X}" for i in range(1, 4)]

        for _ in range(max(1, samples)):
            index = int(rng.integers(0, len(channels)))
            channel = channels[index]
            frequency = frequencies[index] if index < len(frequencies) else None
            if frequency is None:
                # Fall back to the standard plan so the row stays coherent.
                frequency = 2412 + 5 * (channel - 1) if channel <= 14 else 5000 + 5 * channel
            net = WiFiNetwork(
                ssid=profile.ssid,
                bssid=str(rng.choice(bssids)),
                signal=int(rng.integers(BASELINE_SIGNAL_LOW, BASELINE_SIGNAL_HIGH)),
                channel=channel,
                frequency=frequency,
                security=str(rng.choice(securities)),
                vendor=str(rng.choice(vendors)) if vendors else None,
            )
            # Compared against the same profile: these are, by
            # construction, in-profile observations, so every agreement
            # column is 1.0 and every deviation column is 0.0.
            rows.extend(build_feature_matrix([net], [compare_to_profile(net, profile)]))
    return rows


class AnomalyDetector:
    """Thin, explainable wrapper around ``sklearn.ensemble.IsolationForest``.

    Parameters mirror the sklearn arguments that matter here. ``random_state``
    is pinned so two runs on the same baseline give identical scores - a
    demo that re-rolls its own numbers each time is not demonstrable.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: str = "auto",
        max_samples: str = "auto",
        random_state: int = 42,
        slope: float = SLOPE,
        min_rows: int = MIN_BASELINE_ROWS,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples
        self.random_state = random_state
        self.slope = slope
        self.min_rows = min_rows
        self.model: Optional[IsolationForest] = None
        self.baseline_size = 0
        self.model_version = MODEL_VERSION
        #: Observed decision range of the training rows, used to rescale
        #: scores. Set in :meth:`fit`.
        self._decision_min = 0.0
        self._decision_max = 0.0
        self._decision_span = MIN_DECISION_SPAN

    # -- fitting -----------------------------------------------------------

    def fit(self, rows: Sequence[Sequence[float]]) -> "AnomalyDetector":
        """Fit the forest on a feature matrix (rows from ``build_feature_matrix``)."""
        matrix = self._validate(rows)
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=1,
        )
        self.model.fit(matrix)
        self.baseline_size = int(matrix.shape[0])
        decisions = self.model.decision_function(matrix)
        self._decision_min = float(decisions.min())
        self._decision_max = float(decisions.max())
        self._decision_span = max(self._decision_max - self._decision_min, MIN_DECISION_SPAN)
        return self

    def fit_networks(
        self,
        networks: Sequence[Any],
        comparisons: Optional[Sequence[Optional[ProfileComparison]]] = None,
    ) -> "AnomalyDetector":
        """Convenience: fit directly on raw observations."""
        return self.fit(build_feature_matrix(networks, comparisons))

    def fit_from_profiles(self, profiles: Iterable[Any]) -> "AnomalyDetector":
        """Fit on observations synthesised from trusted profiles.

        If the supplied profiles yield too few rows to learn from, the
        detector is left **unfitted** rather than falling back to some
        built-in set of invented access points. A fallback baseline would mean
        scoring real networks against a fiction, and would report a confident
        anomaly score at a site the model has never seen. Returning
        ``available=False`` is the honest answer, and the pipeline says so in
        the result's reasons.
        """
        rows = baseline_from_profiles(profiles)
        if len(rows) < self.min_rows:
            return self
        return self.fit(rows)

    @classmethod
    def default(cls) -> "AnomalyDetector":
        """An unfitted detector - the correct state when no baseline exists.

        There is no built-in baseline to fall back on. Deviation is only
        meaningful relative to something real: the site's own configured
        profile, or observations gathered at that site. Without either, the
        detector reports ``available=False`` and contributes nothing.
        """
        return cls()

    @property
    def is_fitted(self) -> bool:
        return self.model is not None

    # -- scoring -----------------------------------------------------------

    def score(
        self,
        network: Any,
        comparison: Optional[ProfileComparison] = None,
    ) -> AnomalyResult:
        """Score one observation.

        Returns ``available=False`` rather than a fabricated number when the
        detector is unfitted or its baseline is too small.
        """
        if not self.is_fitted:
            return AnomalyResult(anomaly_score=0.0, is_anomaly=False, available=False, baseline_size=0)
        if self.baseline_size < self.min_rows:
            return AnomalyResult(
                anomaly_score=0.0, is_anomaly=False, available=False, baseline_size=self.baseline_size
            )

        from .features import extract_features, feature_row

        row = np.asarray([feature_row(extract_features(network, comparison))], dtype=float)
        decision = float(self.model.decision_function(row)[0])
        score = self._to_score(decision)
        return AnomalyResult(
            anomaly_score=score,
            raw_score=decision,
            is_anomaly=decision < 0.0,
            available=True,
            baseline_size=self.baseline_size,
        )

    def score_matrix(self, rows: Sequence[Sequence[float]]) -> List[AnomalyResult]:
        """Score a batch of feature rows."""
        if not self.is_fitted:
            return [
                AnomalyResult(anomaly_score=0.0, is_anomaly=False, available=False, baseline_size=0)
                for _ in rows
            ]
        matrix = self._validate(rows, require_min=False)
        decisions = self.model.decision_function(matrix)
        return [
            AnomalyResult(
                anomaly_score=self._to_score(float(decision)),
                raw_score=float(decision),
                is_anomaly=float(decision) < 0.0,
                available=True,
                baseline_size=self.baseline_size,
            )
            for decision in decisions
        ]

    def _to_score(self, decision: float) -> float:
        """Rescale a decision value to ``[0, 1]`` against the baseline range.

        ``0`` = the most normal baseline observation, ``0.5`` = the least
        normal baseline observation, ``1`` = further out than any of them.
        This is a relative deviation indicator, not a probability.
        """
        if self.baseline_size <= 1:
            # Nothing to compare against; report neutral rather than extreme.
            return 0.0
        value = (self._decision_max - decision) / (2.0 * self._decision_span)
        return round(min(1.0, max(0.0, value)), 4)

    # -- internals ---------------------------------------------------------

    def _validate(self, rows: Sequence[Sequence[float]], require_min: bool = True) -> np.ndarray:
        if rows is None or len(rows) == 0:
            raise ValueError("baseline must contain at least one observation")
        matrix = np.asarray(rows, dtype=float)
        expected = len(FEATURE_NAMES)
        if matrix.ndim != 2 or matrix.shape[1] != expected:
            raise ValueError(
                f"baseline rows must have {expected} features ({len(FEATURE_NAMES)}), got shape {matrix.shape}"
            )
        if not np.isfinite(matrix).all():
            # Defensive: imputation should make this impossible, but a NaN in a
            # tree ensemble propagates into a meaningless score silently.
            raise ValueError("baseline contains non-finite feature values")
        if require_min and matrix.shape[0] < self.min_rows:
            raise ValueError(
                f"baseline needs at least {self.min_rows} observations, got {matrix.shape[0]}"
            )
        return matrix


_DEFAULT_DETECTOR: Optional[AnomalyDetector] = None


def get_default_detector() -> AnomalyDetector:
    """Return the process-wide default detector, fitting it on first use."""
    global _DEFAULT_DETECTOR
    if _DEFAULT_DETECTOR is None:
        _DEFAULT_DETECTOR = AnomalyDetector.default()
    return _DEFAULT_DETECTOR


def set_default_detector(detector: Optional[AnomalyDetector]) -> None:
    """Override (or clear, with ``None``) the process-wide default detector."""
    global _DEFAULT_DETECTOR
    _DEFAULT_DETECTOR = detector
