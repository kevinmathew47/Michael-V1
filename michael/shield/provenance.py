"""Provenance tracking: remembers which text entered the agent from untrusted sources.

Every tool result from an untrusted tool (inbox, files, web) is recorded with
its source. When the agent later wants to call a risky tool, we can ask:
"did this argument value come from the user, or was it copied out of an
untrusted email / web page?"

Hardened against "laundering": values are compared after removing case,
look-alike Unicode, invisible characters, spaces and punctuation, so
"9988 7766", "9988-7766" and "９９８８７７６６" all trace back to the same source.

All checks are plain string lookups - no model calls - so they cost well
under a millisecond.
"""
import json
import re
import unicodedata

INVISIBLE = re.compile(r"[​-‏⁠-⁤﻿­]")
MIN_COMPACT = 6  # compact (punctuation-free) matching only for values this long


def _norm(value) -> str:
    text = unicodedata.normalize("NFKC", str(value))
    return re.sub(r"\s+", " ", INVISIBLE.sub("", text)).strip().lower()


def _compact(text: str) -> str:
    return re.sub(r"[^0-9a-z@.]", "", text)


class ProvenanceTracker:
    def __init__(self, user_prompt: str):
        self.user_text = _norm(user_prompt)
        self.user_compact = _compact(self.user_text)
        self.untrusted = []  # list of (source label, normalized text, compact text)

    def add_user_context(self, content):
        """Text that counts as the user's own words (e.g. memories the user saved earlier)."""
        text = _norm(content if isinstance(content, str) else json.dumps(content, ensure_ascii=False))
        self.user_text += " " + text
        self.user_compact += _compact(text)

    def add_untrusted(self, source: str, content):
        text = _norm(content if isinstance(content, str) else json.dumps(content, ensure_ascii=False))
        self.untrusted.append((source, text, _compact(text)))

    def origin_of(self, value):
        """Return 'user', the untrusted source label, or None if unknown."""
        v = _norm(value)
        if not v:
            return None
        c = _compact(v)
        if v in self.user_text or (len(c) >= MIN_COMPACT and c in self.user_compact):
            return "user"
        for source, text, compact in self.untrusted:
            if v in text or (len(c) >= MIN_COMPACT and c in compact):
                return source
        return None

    def explain(self, value):
        """Step-by-step account of origin_of(), for showing people how a target is judged."""
        raw = str(value)
        v, hidden = _norm(raw), len(INVISIBLE.findall(raw))
        c = _compact(v)
        steps = {"raw": raw, "normalized": v, "compact": c, "hidden_chars": hidden,
                 "reshaped": unicodedata.normalize("NFKC", raw) != raw, "matches": []}

        def where(text, compact, label):
            if v and v in text:
                i = text.index(v)
                return {"source": label, "how": "exact", "snippet": text[max(i - 50, 0):i + len(v) + 50], "at": [min(i, 50), len(v)]}
            if len(c) >= MIN_COMPACT and c in compact:
                return {"source": label, "how": "after removing spaces and punctuation", "snippet": None}
            return {"source": label, "how": None}

        steps["matches"].append(where(self.user_text, self.user_compact, "user"))
        for source, text, compact in self.untrusted:
            steps["matches"].append(where(text, compact, source))
        steps["origin"] = self.origin_of(value)
        return steps

