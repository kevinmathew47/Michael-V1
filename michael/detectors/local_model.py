"""Local fast classifier: decides clear cases in milliseconds, with no network call.

Two small models, averaged:
  - n-gram model: logistic regression over hashed character/word n-grams (plain numpy)
  - embedding model: logistic regression over all-MiniLM-L6-v2 sentence embeddings (CPU)

It is the first stage of the input gate:

    rules  ->  local model (confident?)  ->  remote Prompt Guard + policy judge

Only cases the local model is unsure about pay for a network round-trip. The
"confident" thresholds are chosen by 5-fold cross-validation so that confident
decisions keep the accuracy of the full gate.

Training data: the DEV half of the public AgentShield Benchmark corpus plus our
own suite prompts. The benchmark's TEST half is never used for training or tuning.

    python -m michael.detectors.local_model     # train + calibrate + save
"""
import json
import re
import sys
import zlib
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "results" / "local_model.npz"
META_PATH = ROOT / "results" / "local_model.json"
EMBED_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DIM = 2 ** 18


# --- n-gram model -----------------------------------------------------------

def _ngrams(text: str):
    t = re.sub(r"\s+", " ", text.lower()).strip()
    padded = f" {t} "
    feats = [padded[i:i + n] for n in (3, 4, 5) for i in range(len(padded) - n + 1)]
    words = re.findall(r"[a-z0-9_@./$-]+", t)
    feats += ["w:" + w for w in words] + ["b:" + a + " " + b for a, b in zip(words, words[1:])]
    idx = {}
    for f in feats:
        h = zlib.crc32(f.encode()) % DIM
        idx[h] = idx.get(h, 0) + 1
    keys = np.fromiter(idx.keys(), dtype=np.int64)
    vals = np.log1p(np.fromiter(idx.values(), dtype=np.float32))
    return keys, vals / (np.linalg.norm(vals) or 1.0)


def _sig(z):
    return 1.0 / (1.0 + np.exp(-z))


class NgramModel:
    def __init__(self):
        self.w, self.b = np.zeros(DIM, dtype=np.float32), 0.0

    def fit(self, texts, y, epochs=40, lr=0.5, l2=1e-5, seed=0):
        data = [_ngrams(t) for t in texts]
        rng = np.random.default_rng(seed)
        for _ in range(epochs):
            for i in rng.permutation(len(data)):
                k, v = data[i]
                g = _sig(float(self.w[k] @ v) + self.b) - y[i]
                self.w[k] -= lr * (g * v + l2 * self.w[k])
                self.b -= lr * g * 0.1
        return self

    def prob(self, text):
        k, v = _ngrams(text)
        return float(_sig(float(self.w[k] @ v) + self.b))


# --- embedding model ----------------------------------------------------------

_encoder = None


def _encode(texts):
    global _encoder
    if _encoder is None:
        try:
            import os
            os.environ.setdefault("USE_TF", "0")      # TensorFlow is installed but not needed
            os.environ.setdefault("USE_TORCH", "1")
            from sentence_transformers import SentenceTransformer
            _encoder = SentenceTransformer(EMBED_NAME, device="cpu")
        except Exception:
            _encoder = False
    if _encoder is False:
        return None
    return np.asarray(_encoder.encode(list(texts), normalize_embeddings=True, batch_size=32), dtype=np.float32)


class EmbedModel:
    def __init__(self):
        self.w, self.b = None, 0.0

    def fit(self, X, y, epochs=400, lr=2.0, l2=1e-3):
        self.w = np.zeros(X.shape[1], dtype=np.float32)
        for _ in range(epochs):  # full-batch gradient descent, small data
            p = _sig(X @ self.w + self.b)
            g = p - y
            self.w -= lr * (X.T @ g / len(y) + l2 * self.w)
            self.b -= lr * g.mean()
        return self

    def prob_vec(self, x):
        return float(_sig(float(x @ self.w) + self.b))


# --- combined model + thresholds -----------------------------------------------

class LocalGate:
    def __init__(self, ngram, embed, lo, hi):
        self.ngram, self.embed, self.lo, self.hi = ngram, embed, lo, hi

    def probability(self, text):
        p = self.ngram.prob(text)
        if self.embed is not None:
            x = _encode([text])
            if x is not None:
                p = (p + self.embed.prob_vec(x[0])) / 2
        return p

    def decide(self, text):
        p = self.probability(text)
        return "block" if p >= self.hi else "allow" if p <= self.lo else None


def training_data():
    """Dev half of the benchmark corpus + our suite prompts (never the test half)."""
    import yaml
    from michael import benchmark
    from michael.detectors import normalize
    texts, labels = [], []
    for c in benchmark.load_corpus():
        if benchmark.split_of(c["id"]) == "dev":
            texts.append(c["input_text"])
            labels.append(1 if c["expected_behavior"] == "block" else 0)
    suite = yaml.safe_load((ROOT / "attacks" / "suite.yaml").read_text(encoding="utf-8"))
    for c in suite["attacks"]:
        texts.append(c["prompt"])
        labels.append(1 if c["category"] == "jailbreak" else 0)  # other attacks hide in the data, not the prompt
    for c in suite["benign"]:
        texts.append(c["prompt"]); labels.append(0)
    synthetic = ROOT / "results" / "synthetic.jsonl"  # LLM-written examples (public category names only)
    if synthetic.exists():
        for line in synthetic.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                texts.append(r["text"]); labels.append(int(r["label"]))
    return [normalize.normalize(t)[0] for t in texts], np.asarray(labels, dtype=np.float32)


def _fit(texts, y, X):
    ng = NgramModel().fit(texts, y)
    em = EmbedModel().fit(X, y) if X is not None else None
    return ng, em


def _probs(ng, em, texts, X):
    p = np.array([ng.prob(t) for t in texts])
    return (p + np.array([em.prob_vec(x) for x in X])) / 2 if em is not None else p


def train():
    sys.stdout.reconfigure(encoding="utf-8")
    texts, y = training_data()
    X = _encode(texts)
    print(f"{len(texts)} training examples ({int(y.sum())} attacks) · embeddings: {'yes' if X is not None else 'no'}")
    # 5-fold cross-validation to pick thresholds where confident decisions stay ~100% correct
    folds = np.arange(len(texts)) % 5
    cv = np.zeros(len(texts))
    for f in range(5):
        tr, te = folds != f, folds == f
        ng, em = _fit([texts[i] for i in np.where(tr)[0]], y[tr], X[tr] if X is not None else None)
        cv[te] = _probs(ng, em, [texts[i] for i in np.where(te)[0]], X[te] if X is not None else None)
    print(f"cross-validated accuracy on its own: {((cv > .5) == y).mean():.3f}")
    best = None
    for lo in np.arange(0.02, 0.5, 0.02):
        for hi in np.arange(0.98, 0.5, -0.02):
            conf = (cv <= lo) | (cv >= hi)
            if not conf.any():
                continue
            acc = (((cv >= hi) == y)[conf]).mean()
            if acc >= 0.995 and (best is None or conf.mean() > best[2]):
                best = (float(lo), float(hi), float(conf.mean()), float(acc))
    lo, hi, cover, acc = best or (0.0, 1.0, 0.0, 1.0)
    print(f"thresholds lo={lo:.2f} hi={hi:.2f}: decides {cover:.0%} of cases locally at {acc:.1%} accuracy (CV)")
    ng, em = _fit(texts, y, X)
    np.savez_compressed(MODEL_PATH, ng_idx=np.nonzero(ng.w)[0], ng_val=ng.w[np.nonzero(ng.w)[0]], ng_b=[ng.b],
                        em_w=em.w if em is not None else np.zeros(0), em_b=[em.b if em is not None else 0.0])
    META_PATH.write_text(json.dumps({"lo": lo, "hi": hi, "cv_coverage": cover, "cv_confident_accuracy": acc,
                                     "cv_accuracy": float(((cv > .5) == y).mean()), "examples": len(texts),
                                     "embedding_model": EMBED_NAME if em is not None else None}, indent=2))
    print(f"saved -> {MODEL_PATH.name}, {META_PATH.name}")


_gate = None


def get():
    global _gate
    if _gate is None:
        if not (MODEL_PATH.exists() and META_PATH.exists()):
            _gate = False
        else:
            d, meta = np.load(MODEL_PATH), json.loads(META_PATH.read_text())
            ng = NgramModel()
            ng.w[d["ng_idx"]] = d["ng_val"]
            ng.b = float(d["ng_b"][0])
            em = None
            if d["em_w"].size:
                em = EmbedModel()
                em.w, em.b = d["em_w"], float(d["em_b"][0])
            _gate = LocalGate(ng, em, meta["lo"], meta["hi"])
    return _gate or None


def decide(text):
    g = get()
    return g.decide(text) if g else None


def probability(text):
    g = get()
    return g.probability(text) if g else None


if __name__ == "__main__":
    train()
