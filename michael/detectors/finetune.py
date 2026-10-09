"""Fine-tuned MiniLM classifier: the strongest part of the local fast path.

all-MiniLM-L6-v2 (22M parameters, Apache-2.0) fine-tuned end-to-end on the dev
half of the public AgentShield corpus + our suite prompts. CPU only, ~10 ms per
input. Weights are saved to results/local_ft/ (not committed; ~90 MB).

    python -m michael.detectors.finetune --download   # get the released weights (SHA-256 checked)
    python -m michael.detectors.finetune              # or train them yourself (needs the benchmark corpus)
"""
import os

os.environ.setdefault("USE_TF", "0")
os.environ.setdefault("USE_TORCH", "1")

from pathlib import Path

import numpy as np

BASE = "sentence-transformers/all-MiniLM-L6-v2"
OUT = Path(__file__).resolve().parents[2] / "results" / "local_ft"

_model = _tok = None


def train(texts, y, epochs=6, lr=5e-5, seed=0, save=True):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    torch.manual_seed(seed)
    tok = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2)
    y = np.asarray(y).astype(np.int64)
    yt = torch.tensor(y, dtype=torch.long)
    cw = torch.tensor([len(y) / (2 * max((y == 0).sum(), 1)), len(y) / (2 * max((y == 1).sum(), 1))], dtype=torch.float)
    lossf = torch.nn.CrossEntropyLoss(weight=cw)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    rng = np.random.default_rng(seed)
    model.train()
    for _ in range(epochs):
        order = rng.permutation(len(texts))
        for i in range(0, len(order), 16):
            batch = order[i:i + 16]
            enc = tok([texts[j] for j in batch], padding=True, truncation=True, max_length=256, return_tensors="pt")
            lossf(model(**enc).logits, yt[batch]).backward()
            opt.step()
            opt.zero_grad()
    model.eval()
    if save:
        OUT.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(OUT)
        tok.save_pretrained(OUT)
    return model, tok


def available():
    return (OUT / "config.json").exists()


def prob(text: str):
    """Attack probability, or None if the fine-tuned model isn't trained here."""
    global _model, _tok
    if _model is None:
        if not available():
            return None
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        torch.set_num_threads(min(8, os.cpu_count() or 4))
        _tok = AutoTokenizer.from_pretrained(OUT)
        _model = AutoModelForSequenceClassification.from_pretrained(OUT).eval()
        # int8 dynamic quantization: faster on CPU; verified to change 0 of 272 dev decisions
        _model = torch.quantization.quantize_dynamic(_model, {torch.nn.Linear}, dtype=torch.qint8)
    import torch
    with torch.no_grad():
        enc = _tok([text], truncation=True, max_length=256, return_tensors="pt")
        return float(torch.softmax(_model(**enc).logits, -1)[0, 1])


RELEASE_URL = "https://github.com/kevinmathew47/Michael-V1/releases/download/v1.0.0/michael-v1-local-ft.zip"
RELEASE_SHA256 = "e0a68e85fae16e6fb2ece9a5c589bd1257e67bf69121d53d9478d41b6308e8fa"


def download(url=RELEASE_URL, sha256=RELEASE_SHA256):
    """Fetch the released fine-tuned weights, verify the checksum, unpack into results/local_ft/."""
    import hashlib
    import io
    import urllib.request
    import zipfile
    print(f"Downloading {url} …")
    data = urllib.request.urlopen(url, timeout=120).read()
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        raise SystemExit(f"Checksum mismatch ({got}): file not used.")
    OUT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if "/" in name or "\\" in name or name.startswith("."):
                raise SystemExit(f"Unexpected file in archive: {name}")
        z.extractall(OUT)
    print(f"Fine-tuned model ready in {OUT} ({len(data) // 2**20} MB, checksum OK).")


if __name__ == "__main__":
    import sys
    if "--download" in sys.argv:
        download()
    else:
        from michael.detectors import local_model
        local_model.train(with_finetune=True)
