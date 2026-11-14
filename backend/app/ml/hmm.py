"""Hidden Markov Model over event sequences: hidden states = kill-chain stages, observations = coarse
event symbols. Parameters are estimated by supervised counting (maximum likelihood with Laplace
smoothing) from labelled sequences, then hmmlearn's Viterbi decoder recovers the most likely stage
sequence for an unseen incident."""

from collections import defaultdict

import numpy as np
from hmmlearn import hmm

from app.ml.features import EventRow
from app.ml.taxonomy import OBSERVATIONS, STAGE_SEVERITY, STAGES

_OBS_INDEX = {o: i for i, o in enumerate(OBSERVATIONS)}
_STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}
SEQUENCE_GAP_SECONDS = 2 * 3600


class StageHMM:
    def __init__(self, startprob: np.ndarray, transmat: np.ndarray, emissionprob: np.ndarray):
        self.model = hmm.CategoricalHMM(
            n_components=len(STAGES), n_features=len(OBSERVATIONS), init_params="", params="")
        self.model.startprob_ = startprob
        self.model.transmat_ = transmat
        self.model.emissionprob_ = emissionprob

    @classmethod
    def fit_supervised(cls, sequences: list[tuple[list[str], list[str]]], alpha: float = 1.0) -> "StageHMM":
        n, m = len(STAGES), len(OBSERVATIONS)
        start = np.full(n, alpha)
        trans = np.full((n, n), alpha)
        emit = np.full((n, m), alpha)
        for observations, stages in sequences:
            s_idx = [_STAGE_INDEX[s] for s in stages]
            o_idx = [_OBS_INDEX[o] for o in observations]
            start[s_idx[0]] += 1
            for a, b in zip(s_idx, s_idx[1:]):
                trans[a, b] += 1
            for s, o in zip(s_idx, o_idx):
                emit[s, o] += 1
        return cls(start / start.sum(), trans / trans.sum(axis=1, keepdims=True),
                   emit / emit.sum(axis=1, keepdims=True))

    def decode(self, observations: list[str]) -> tuple[list[str], list[float]]:
        """Viterbi path plus the posterior probability of each decoded stage."""
        if not observations:
            return [], []
        X = np.array([_OBS_INDEX[o] for o in observations]).reshape(-1, 1)
        _, path = self.model.decode(X, algorithm="viterbi")
        posteriors = self.model.predict_proba(X)
        return [STAGES[s] for s in path], [float(posteriors[i, s]) for i, s in enumerate(path)]

    def to_dict(self) -> dict:
        return {
            "states": STAGES,
            "observations": OBSERVATIONS,
            "startprob": self.model.startprob_.round(5).tolist(),
            "transmat": self.model.transmat_.round(5).tolist(),
            "emissionprob": self.model.emissionprob_.round(5).tolist(),
        }


def labelled_sequences(rows: list[EventRow], labels: dict) -> list[tuple[list[str], list[str]]]:
    """Split each entity's events into sessions (gap > 2h) and pair observations with true stages."""
    by_entity: dict[str, list[EventRow]] = defaultdict(list)
    for r in rows:
        by_entity[r.entity].append(r)
    sequences = []
    for evs in by_entity.values():
        obs, stages, last = [], [], None
        for e in evs:
            if last is not None and e.ts - last > SEQUENCE_GAP_SECONDS and obs:
                sequences.append((obs, stages))
                obs, stages = [], []
            label = labels.get(e.event_id)
            obs.append(e.observation)
            stages.append(label.stage if label else "NORMAL")
            last = e.ts
        if obs:
            sequences.append((obs, stages))
    return sequences


def sequence_severity(stages: list[str]) -> float:
    """S term of the risk score: how far along the kill chain, plus breadth of distinct stages."""
    attack = {s for s in stages if s != "NORMAL"}
    if not attack:
        return 0.0
    deepest = max(STAGE_SEVERITY[s] for s in attack)
    breadth = min(1.0, (len(attack) - 1) / 3)
    return round(0.7 * deepest + 0.3 * breadth, 4)
