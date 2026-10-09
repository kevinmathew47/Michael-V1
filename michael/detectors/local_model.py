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
import os
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


def _class_weights(y):
    """Balance attacks vs legitimate examples so attack-heavy data doesn't skew the model."""
    pos = max(float(np.sum(y)), 1.0)
    neg = max(float(len(y) - np.sum(y)), 1.0)
    return {1: len(y) / (2 * pos), 0: len(y) / (2 * neg)}


def _sig(z):
    return 1.0 / (1.0 + np.exp(-z))


class NgramModel:
    def __init__(self):
        self.w, self.b = np.zeros(DIM, dtype=np.float32), 0.0

    def fit(self, texts, y, epochs=40, lr=0.5, l2=1e-5, seed=0):
        data = [_ngrams(t) for t in texts]
        cw = _class_weights(y)
        rng = np.random.default_rng(seed)
        for _ in range(epochs):
            for i in rng.permutation(len(data)):
                k, v = data[i]
                g = (_sig(float(self.w[k] @ v) + self.b) - y[i]) * cw[int(y[i])]
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
            import torch
            torch.set_num_threads(min(8, os.cpu_count() or 4))
            _encoder[0].auto_model = torch.quantization.quantize_dynamic(  # int8: faster on CPU
                _encoder[0].auto_model, {torch.nn.Linear}, dtype=torch.qint8)
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
        cw = _class_weights(y)
        sw = np.where(y > 0.5, cw[1], cw[0])
        for _ in range(epochs):  # full-batch gradient descent, small data
            p = _sig(X @ self.w + self.b)
            g = (p - y) * sw
            self.w -= lr * (X.T @ g / len(y) + l2 * self.w)
            self.b -= lr * g.mean()
        return self

    def prob_vec(self, x):
        return float(_sig(float(x @ self.w) + self.b))


# --- combined model + thresholds -----------------------------------------------

class LocalGate:
    def __init__(self, ngram, embed, lo, hi):
        self.ngram, self.embed, self.lo, self.hi = ngram, embed, lo, hi

    use_finetune = False

    def probability(self, text):
        p = self.ngram.prob(text)
        if self.embed is not None:
            x = _encode([text])
            if x is not None:
                p = (p + self.embed.prob_vec(x[0])) / 2
        if self.use_finetune:
            from michael.detectors import finetune
            ft = finetune.prob(text)
            if ft is not None:
                p = (p + ft) / 2  # average with the fine-tuned MiniLM classifier
        return p

    modes = {}

    def decide(self, text, mode=None):
        """mode "fast": wide confident band (latency-critical, benchmark).
        mode "careful" (product default): only very confident verdicts are final."""
        lo, hi = (self.modes[mode]["lo"], self.modes[mode]["hi"]) if mode in self.modes else (self.lo, self.hi)
        p = self.probability(text)
        return "block" if p >= hi else "allow" if p <= lo else None


def training_data(synthetic_kinds=("legitimate", "attack")):
    """Dev half of the benchmark corpus + our suite prompts (+ synthetic). Never the test half.
    Returns texts, labels and a mask of the real benchmark rows (used to calibrate thresholds)."""
    import yaml
    from michael import benchmark
    from michael.detectors import normalize
    texts, labels = [], []
    for c in benchmark.load_corpus():
        if benchmark.split_of(c["id"]) == "dev":
            texts.append(c["input_text"])
            labels.append(1 if c["expected_behavior"] == "block" else 0)
    n_real = len(texts)
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
                if ("legitimate" if r["label"] == 0 else "attack") in synthetic_kinds:
                    texts.append(r["text"]); labels.append(int(r["label"]))
    real = np.zeros(len(texts), dtype=bool)
    real[:n_real] = True
    return [normalize.normalize(t)[0] for t in texts], np.asarray(labels, dtype=np.float32), real


def _fit(texts, y, X):
    ng = NgramModel().fit(texts, y)
    em = EmbedModel().fit(X, y) if X is not None else None
    return ng, em


def _probs(ng, em, texts, X):
    p = np.array([ng.prob(t) for t in texts])
    return (p + np.array([em.prob_vec(x) for x in X])) / 2 if em is not None else p


def _cv(texts, y, X, folds=5):
    idx = np.arange(len(texts)) % folds
    cv = np.zeros(len(texts))
    for f in range(folds):
        tr, te = idx != f, idx == f
        ng, em = _fit([texts[i] for i in np.where(tr)[0]], y[tr], X[tr] if X is not None else None)
        cv[te] = _probs(ng, em, [texts[i] for i in np.where(te)[0]], X[te] if X is not None else None)
    return cv


def _thresholds(cv, y, target=0.995):
    """Widest confident band whose decisions keep >= target accuracy."""
    best = (0.0, 1.0, 0.0, 1.0)
    for lo in np.arange(0.02, 0.5, 0.02):
        for hi in np.arange(0.98, 0.5, -0.02):
            conf = (cv <= lo) | (cv >= hi)
            if conf.any():
                acc = (((cv >= hi) == y)[conf]).mean()
                if acc >= target and conf.mean() > best[2]:
                    best = (float(lo), float(hi), float(conf.mean()), float(acc))
    return best


def train_with_finetune(target=0.98):
    """Ensemble of the n-gram/embedding classifier and the fine-tuned MiniLM.
    Thresholds come from 5-fold cross-validation on the real dev rows."""
    from michael.detectors import finetune
    sys.stdout.reconfigure(encoding="utf-8")
    texts, y, real = training_data(())
    X = _encode(texts)
    lr = _cv(texts, y, X)
    folds = np.arange(len(texts)) % 5
    ft = np.zeros(len(texts))
    for f in range(5):
        tr, te = np.where(folds != f)[0], np.where(folds == f)[0]
        model, tok = finetune.train([texts[i] for i in tr], y[tr], save=False)
        import torch
        with torch.no_grad():
            for i in te:
                enc = tok([texts[i]], truncation=True, max_length=256, return_tensors="pt")
                ft[i] = float(torch.softmax(model(**enc).logits, -1)[0, 1])
        print(f"  fine-tune fold {f + 1}/5 done", flush=True)
    ens = (lr + ft) / 2
    np.save(ROOT / "results" / "ens_cv.npy", ens)
    # Pick the confidence band that gives the best simulated benchmark score on the
    # DEV half (cross-validated predictions; the test half is never looked at).
    import copy
    from michael import benchmark
    dev_rows = json.loads((ROOT / "results" / "benchmark.json").read_text(encoding="utf-8"))["dev"]["rows"]
    best = None
    for t in (0.995, 0.99, 0.985, 0.98, 0.975, 0.97):
        lo_, hi_, cover_, acc_ = _thresholds(ens[real], y[real], t)
        sim = []
        for r, p in zip(dev_rows, ens[real]):
            r2 = copy.deepcopy(r)
            r2["layers"]["local"] = {"v": "block" if p >= hi_ else "allow" if p <= lo_ else None, "ms": 15.0}
            sim.append(r2)
        final = benchmark.score(sim, ("rules", "local", "pg", "judge"))["final"]
        print(f"  target {t}: local {cover_:.0%} -> simulated dev score {final}")
        if best is None or final > best[0]:
            best = (final, t, lo_, hi_, cover_, acc_)
    _, target, lo, hi, cover, acc = best
    print(f"ensemble CV: accuracy {((ens[real] > .5) == y[real]).mean():.3f} · decides {cover:.0%} locally at {acc:.1%}")
    ng, em = _fit(texts, y, X)
    finetune.train(texts, y, save=True)
    nz = np.nonzero(ng.w)[0]
    np.savez_compressed(MODEL_PATH, ng_idx=nz, ng_val=ng.w[nz], ng_b=[ng.b], em_w=em.w, em_b=[em.b])
    META_PATH.write_text(json.dumps({"lo": lo, "hi": hi, "cv_coverage": cover, "cv_confident_accuracy": acc,
                                     "cv_accuracy": float(((ens[real] > .5) == y[real]).mean()), "examples": len(texts),
                                     "synthetic": [], "finetune": True, "target": target,
                                     "embedding_model": EMBED_NAME}, indent=2))
    print(f"saved: thresholds lo={lo:.2f} hi={hi:.2f}")


def train(with_finetune=False):
    if with_finetune:
        return train_with_finetune()
    sys.stdout.reconfigure(encoding="utf-8")
    results = []
    for kinds in [(), ("legitimate",), ("legitimate", "attack")]:
        texts, y, real = training_data(kinds)
        X = _encode(texts)
        cv = _cv(texts, y, X)
        lo, hi, cover, acc = _thresholds(cv[real], y[real])  # calibrated on REAL dev-benchmark rows only
        name = "+".join(kinds) or "no synthetic"
        print(f"{name:<22} {len(texts)} examples · CV acc on real rows {((cv[real] > .5) == y[real]).mean():.3f} · "
              f"decides {cover:.0%} locally at {acc:.1%}")
        results.append((cover, kinds, lo, hi, acc, float(((cv[real] > .5) == y[real]).mean())))
    cover, kinds, lo, hi, acc, cv_acc = max(results, key=lambda r: r[0])
    texts, y, real = training_data(kinds)
    X = _encode(texts)
    ng, em = _fit(texts, y, X)
    nz = np.nonzero(ng.w)[0]
    np.savez_compressed(MODEL_PATH, ng_idx=nz, ng_val=ng.w[nz], ng_b=[ng.b],
                        em_w=em.w if em is not None else np.zeros(0), em_b=[em.b if em is not None else 0.0])
    META_PATH.write_text(json.dumps({"lo": lo, "hi": hi, "cv_coverage": cover, "cv_confident_accuracy": acc,
                                     "cv_accuracy": cv_acc, "examples": len(texts), "synthetic": list(kinds),
                                     "embedding_model": EMBED_NAME if em is not None else None}, indent=2))
    print(f"chosen: synthetic={list(kinds) or 'none'} · thresholds lo={lo:.2f} hi={hi:.2f} · "
          f"decides {cover:.0%} of real cases locally at {acc:.1%} (CV) -> saved")


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
            _gate.use_finetune = bool(meta.get("finetune"))
            _gate.modes = meta.get("modes", {})
    return _gate or None


def decide(text, mode="careful"):
    g = get()
    return g.decide(text, mode) if g else None


def probability(text):
    g = get()
    return g.probability(text) if g else None


if __name__ == "__main__":
    train()
