"""Thin wrapper around the Groq chat completions API.

Every Groq call in the project goes through create(), which keeps each model
under Groq's free-tier limits - requests/minute AND tokens/minute - using a
shared limiter across all threads, and honours Groq's retry-after hints.
"""
import threading
import time
from collections import defaultdict, deque

from groq import BadRequestError, Groq, RateLimitError

from michael import config

_client = None

REQUESTS_PER_MINUTE = 28                      # free tier: 30
TOKENS_PER_MINUTE = defaultdict(lambda: 7500)  # free tier: 8000 for gpt-oss models
TOKENS_PER_MINUTE["meta-llama/llama-prompt-guard-2-86m"] = 14000

_sent = defaultdict(deque)     # model -> request timestamps
_tokens = defaultdict(deque)   # model -> (timestamp, tokens used)
_last_size = defaultdict(lambda: 1500)  # model -> tokens used by the last call (estimate)
_lock = threading.Lock()


def client() -> Groq:
    global _client
    if _client is None:
        if not config.GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY is not set. Copy .env.example to .env and add your key.")
        _client = Groq(api_key=config.GROQ_API_KEY, max_retries=0)
    return _client


def _wait_for_slot(model):
    while True:
        with _lock:
            now = time.monotonic()
            sent, toks = _sent[model], _tokens[model]
            while sent and now - sent[0] > 60:
                sent.popleft()
            while toks and now - toks[0][0] > 60:
                toks.popleft()
            used = sum(n for _, n in toks)
            if len(sent) < REQUESTS_PER_MINUTE and used + _last_size[model] <= TOKENS_PER_MINUTE[model]:
                sent.append(now)
                return
            # wait until the oldest request / token batch leaves the 60 s window
            waits = [60 - (now - sent[0])] if len(sent) >= REQUESTS_PER_MINUTE else []
            if toks:
                waits.append(60 - (now - toks[0][0]))
            delay = max(min(waits) if waits else 1.0, 0.2)
        time.sleep(delay)


def _record(model, resp):
    used = getattr(getattr(resp, "usage", None), "total_tokens", None)
    if used:
        with _lock:
            _tokens[model].append((time.monotonic(), used))
            _last_size[model] = used


def create(**kwargs):
    """Rate-limited chat completion with retries. Returns the full response."""
    model = kwargs["model"]
    for attempt in range(12):
        _wait_for_slot(model)
        try:
            resp = client().chat.completions.create(**kwargs)
            _record(model, resp)
            return resp
        except BadRequestError as e:
            # Groq rejects malformed tool calls with a 400; a retry usually succeeds.
            if "tool_use_failed" not in str(e) or attempt >= 2:
                raise
        except RateLimitError as e:
            if attempt == 11:
                raise
            retry_after = e.response.headers.get("retry-after") if e.response is not None else None
            time.sleep(float(retry_after) + 0.5 if retry_after else min(2 ** attempt, 30))


def chat(messages, tools=None, temperature=0.2):
    kwargs = {"model": config.GROQ_MODEL, "messages": messages, "temperature": temperature}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    return create(**kwargs).choices[0].message
