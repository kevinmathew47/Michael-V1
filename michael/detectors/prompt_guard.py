"""Injection / jailbreak classifier using Llama Prompt Guard 2 (86M) on Groq.

The model returns the probability (0-1) that a text is a prompt attack.

Speed tricks:
  - cache: identical text is never scanned twice (keyed by SHA-256)
  - chunking + parallelism: long text is split and all chunks are scored at once
"""
import hashlib
import threading
from concurrent.futures import Future, ThreadPoolExecutor

from michael import llm

MODEL = "meta-llama/llama-prompt-guard-2-86m"
THRESHOLD = 0.5
CHUNK_CHARS = 1500  # Prompt Guard reads up to 512 tokens per call

_cache = {}
_inflight = {}  # text hash -> Future, so a text being scanned is never sent twice
_lock = threading.Lock()
_pool = ThreadPoolExecutor(max_workers=8)


def _score_chunk(text: str) -> float:
    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with _lock:
        if key in _cache:
            return _cache[key]
        future = _inflight.get(key)
        owner = future is None
        if owner:
            future = _inflight[key] = Future()
    if not owner:
        return future.result()  # someone (e.g. a prefetch) is already scanning it
    try:
        resp = llm.create(model=MODEL, messages=[{"role": "user", "content": text}])
        score = float(resp.choices[0].message.content.strip())
        _cache[key] = score
        future.set_result(score)
        return score
    except Exception as e:
        future.set_exception(e)
        raise
    finally:
        with _lock:
            _inflight.pop(key, None)


def prefetch(texts):
    """Scan content in the background ahead of time ("scan on arrival")."""
    for text in texts:
        for chunk in _chunks(text):
            _pool.submit(_score_chunk, chunk)


def _chunks(text: str):
    return [text[i:i + CHUNK_CHARS] for i in range(0, len(text), CHUNK_CHARS)] or [""]


def score_many(texts):
    """Score several texts in parallel. Returns one max-score per text."""
    jobs = [(i, c) for i, t in enumerate(texts) for c in _chunks(t)]
    scores = list(_pool.map(lambda job: _score_chunk(job[1]), jobs))
    best = [0.0] * len(texts)
    for (i, _), s in zip(jobs, scores):
        best[i] = max(best[i], s)
    return best


def score(text: str) -> float:
    return score_many([text])[0]


def score_async(text: str):
    """Start scoring in the background; call .result() when the verdict is needed."""
    return _pool.submit(score, text)
