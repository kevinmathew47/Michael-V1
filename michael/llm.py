"""Thin wrapper around the Groq chat completions API."""
from groq import BadRequestError, Groq

from michael import config

_client = None


def client() -> Groq:
    global _client
    if _client is None:
        if not config.GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY is not set. Copy .env.example to .env and add your key.")
        _client = Groq(api_key=config.GROQ_API_KEY)
    return _client


def chat(messages, tools=None, temperature=0.2):
    kwargs = {"model": config.GROQ_MODEL, "messages": messages, "temperature": temperature}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    # Groq rejects malformed tool calls with a 400; one retry usually succeeds.
    for attempt in range(3):
        try:
            return client().chat.completions.create(**kwargs).choices[0].message
        except BadRequestError as e:
            if "tool_use_failed" not in str(e) or attempt == 2:
                raise
