"""Thin wrapper around the Groq chat completions API."""
import threading
import time
from collections import deque

from groq import BadRequestError, Groq, RateLimitError

from michael import config

_client = None

# Groq's free tier allows 30 requests/minute for the agent model. A shared
# limiter keeps all threads (suite, dashboard) under it instead of failing.
REQUESTS_PER_MINUTE = 28
_sent = deque()
_lock = threading.Lock()


def client() -> Groq:
    global _client
    if _client is None:
        if not config.GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY is not set. Copy .env.example to .env and add your key.")
        _client = Groq(api_key=config.GROQ_API_KEY, max_retries=2)
    return _client


def _wait_for_slot():
    while True:
        with _lock:
            now = time.monotonic()
            while _sent and now - _sent[0] > 60:
                _sent.popleft()
            if len(_sent) < REQUESTS_PER_MINUTE:
                _sent.append(now)
                return
            delay = 60 - (now - _sent[0]) + 0.1
        time.sleep(delay)


def chat(messages, tools=None, temperature=0.2):
    kwargs = {"model": config.GROQ_MODEL, "messages": messages, "temperature": temperature}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    for attempt in range(8):
        _wait_for_slot()
        try:
            return client().chat.completions.create(**kwargs).choices[0].message
        except BadRequestError as e:
            # Groq rejects malformed tool calls with a 400; a retry usually succeeds.
            if "tool_use_failed" not in str(e) or attempt >= 2:
                raise
        except RateLimitError:
            if attempt == 7:
                raise
            time.sleep(min(2 ** attempt, 20))
