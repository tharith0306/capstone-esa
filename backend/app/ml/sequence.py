"""Deep sequence models for attack-stage decoding (research extension, compared with the HMM in E4).

Input per event: observation symbol embedding + log time-gap to the previous event + layer one-hot.
Output: a kill-chain stage per event. Two architectures:
  * BiLSTM (2 layers)
  * Transformer encoder (2 layers, 4 heads, learned positions)
Requires the optional `deep` extra (PyTorch). The production pipeline keeps the HMM, which is
interpretable and needs no GPU; these models exist to answer "does a deep model do better?".
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from app.ml.features import EventRow
from app.ml.taxonomy import OBSERVATIONS, STAGES

try:
    import torch
    from torch import nn

    # Small models; one thread also avoids a macOS crash when PyTorch's OpenMP runtime meets the one
    # XGBoost/scikit-learn already loaded.
    torch.set_num_threads(1)
except ImportError:  # pragma: no cover - optional dependency
    torch = None
    nn = None

LAYERS = ["identity", "network", "compute", "storage", "management", "application"]
_OBS = {o: i + 1 for i, o in enumerate(OBSERVATIONS)}  # 0 = padding
_STAGE = {s: i for i, s in enumerate(STAGES)}
_LAYER = {l: i for i, l in enumerate(LAYERS)}
MAX_LEN = 128
GAP_SPLIT = 2 * 3600


def available() -> bool:
    return torch is not None


@dataclass
class Batch:
    obs: "torch.Tensor"
    cont: "torch.Tensor"
    stages: "torch.Tensor"
    mask: "torch.Tensor"


def sequences(rows: list[EventRow], labels: dict | None) -> list[tuple[list[EventRow], list[int]]]:
    """Per-entity sessions (split on 2h gaps), chunked to MAX_LEN events."""
    by_entity = defaultdict(list)
    for r in rows:
        by_entity[r.entity].append(r)
    out = []
    for evs in by_entity.values():
        session: list[EventRow] = []
        for e in evs:
            if session and e.ts - session[-1].ts > GAP_SPLIT:
                out.extend(_chunks(session, labels))
                session = []
            session.append(e)
        if session:
            out.extend(_chunks(session, labels))
    return out


def _chunks(session, labels):
    for i in range(0, len(session), MAX_LEN):
        part = session[i:i + MAX_LEN]
        stages = [_STAGE[labels[e.event_id].stage] if labels and e.event_id in labels else 0 for e in part]
        yield part, stages


def encode(seqs: list[tuple[list[EventRow], list[int]]]) -> Batch:
    n, length = len(seqs), max(len(s[0]) for s in seqs)
    obs = np.zeros((n, length), dtype=np.int64)
    cont = np.zeros((n, length, 1 + len(LAYERS)), dtype=np.float32)
    stages = np.full((n, length), -100, dtype=np.int64)  # -100 = ignored by the loss
    mask = np.zeros((n, length), dtype=bool)
    for i, (events, st) in enumerate(seqs):
        prev = None
        for j, (e, s) in enumerate(zip(events, st)):
            obs[i, j] = _OBS[e.observation]
            cont[i, j, 0] = math.log1p(max(0.0, e.ts - prev)) / 10 if prev is not None else 0.0
            cont[i, j, 1 + _LAYER.get(e.layer, 5)] = 1.0
            stages[i, j] = s
            mask[i, j] = True
            prev = e.ts
    return Batch(torch.from_numpy(obs), torch.from_numpy(cont), torch.from_numpy(stages), torch.from_numpy(mask))


if torch is not None:
    class StageTagger(nn.Module):
        def __init__(self, arch: str = "lstm", dim: int = 64):
            super().__init__()
            self.arch = arch
            self.embed = nn.Embedding(len(OBSERVATIONS) + 1, dim - 1 - len(LAYERS), padding_idx=0)
            if arch == "lstm":
                self.encoder = nn.LSTM(dim, dim // 2, num_layers=2, batch_first=True, bidirectional=True, dropout=0.1)
            else:
                self.position = nn.Embedding(MAX_LEN, dim)
                layer = nn.TransformerEncoderLayer(dim, nhead=4, dim_feedforward=2 * dim, dropout=0.1, batch_first=True)
                self.encoder = nn.TransformerEncoder(layer, num_layers=2, enable_nested_tensor=False)
            self.head = nn.Linear(dim, len(STAGES))

        def forward(self, obs, cont, mask):
            x = torch.cat([self.embed(obs), cont], dim=-1)
            if self.arch == "lstm":
                x, _ = self.encoder(x)
            else:
                pos = torch.arange(x.shape[1], device=x.device).unsqueeze(0)
                x = self.encoder(x + self.position(pos), src_key_padding_mask=~mask)
            return self.head(x)


def train_tagger(rows: list[EventRow], labels: dict, arch: str = "lstm", epochs: int = 6, seed: int = 0,
                 batch_size: int = 64) -> tuple["StageTagger", dict]:
    if torch is None:
        raise RuntimeError("PyTorch is not installed: pip install '.[deep]'")
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    seqs = sequences(rows, labels)
    # Attack sessions are rare; oversample sessions that contain any attack stage.
    attack = [s for s in seqs if any(st != 0 for st in s[1])]
    normal = [s for s in seqs if not any(st != 0 for st in s[1])]
    model = StageTagger(arch)
    opt = torch.optim.AdamW(model.parameters(), lr=3e-3, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss(ignore_index=-100)
    t0 = time.time()
    for _ in range(epochs):
        pool = normal + attack * 5
        order = rng.permutation(len(pool))
        model.train()
        for i in range(0, len(order), batch_size):
            batch = encode([pool[k] for k in order[i:i + batch_size]])
            logits = model(batch.obs, batch.cont, batch.mask)
            loss = loss_fn(logits.reshape(-1, len(STAGES)), batch.stages.reshape(-1))
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
    params = sum(p.numel() for p in model.parameters())
    return model, {"arch": arch, "epochs": epochs, "sessions": len(seqs), "attack_sessions": len(attack),
                   "parameters": params, "train_seconds": round(time.time() - t0, 1)}


def decode(model: "StageTagger", rows: list[EventRow]) -> list[str]:
    """Stage for each row, decoding each entity's sessions independently (like the HMM path)."""
    model.eval()
    index = {r.event_id: i for i, r in enumerate(rows)}
    out = ["NORMAL"] * len(rows)
    seqs = sequences(rows, None)
    with torch.no_grad():
        for i in range(0, len(seqs), 128):
            part = seqs[i:i + 128]
            batch = encode(part)
            pred = model(batch.obs, batch.cont, batch.mask).argmax(-1).numpy()
            for b, (events, _) in enumerate(part):
                for j, e in enumerate(events):
                    out[index[e.event_id]] = STAGES[int(pred[b, j])]
    return out
