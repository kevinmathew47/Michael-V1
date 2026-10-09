"""Provenance tracking: remembers which text entered the agent from untrusted sources.

Every tool result from an untrusted tool (inbox, files, web) is recorded with
its source. When the agent later wants to call a risky tool, we can ask:
"did this argument value come from the user, or was it copied out of an
untrusted email / web page?"

All checks are plain string lookups - no model calls - so they cost well
under a millisecond.
"""
import json


def _norm(value) -> str:
    return str(value).strip().lower()


class ProvenanceTracker:
    def __init__(self, user_prompt: str):
        self.user_text = _norm(user_prompt)
        self.untrusted = []  # list of (source label, normalized text)

    def add_untrusted(self, source: str, content):
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
        self.untrusted.append((source, _norm(text)))

    def origin_of(self, value):
        """Return 'user', the untrusted source label, or None if unknown."""
        v = _norm(value)
        if not v:
            return None
        if v in self.user_text:
            return "user"
        for source, text in self.untrusted:
            if v in text:
                return source
        return None
