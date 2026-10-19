"""Redaction helpers so scanner commands and output can be stored/displayed safely."""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence

REDACTED = "[REDACTED]"

# Flags whose *next* argument is a secret value.
_SECRET_FLAGS = {
    "--cookie", "--cookies", "-c", "--auth", "--auth-cred", "--auth-pass", "--auth-user",
    "--authorization", "--header", "-H", "--headers", "--proxy-auth", "--token", "--api-key",
    "--apikey", "--password", "--pass", "-p", "--passwd", "-U", "-P", "--user", "--username",
    "--basic-auth", "--bearer", "--secret", "--key",
}
# Only treated as secret flags when the NEXT value looks like a credential header/cookie.
_AMBIGUOUS_FLAGS = {"-p", "-H", "--header", "--headers", "--key"}
_SECRET_HEADER_RE = re.compile(r"^(authorization|cookie|x-api-key|x-auth-token|proxy-authorization)\s*:", re.I)

_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\b(\s*[=:]\s*|\s+)(?!\[REDACTED\])([^\s,;&\"']+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_URL_CRED_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_AWS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def redact_text(text: str | None) -> str:
    """Mask credentials, tokens and URL userinfo in free-form text."""
    if not text:
        return text or ""
    value = _URL_CRED_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}:{REDACTED}@", text)
    value = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", value)
    value = _JWT_RE.sub(REDACTED, value)
    value = _AWS_KEY_RE.sub(REDACTED, value)
    value = _GITHUB_TOKEN_RE.sub(REDACTED, value)
    value = _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
    return value


def redact_command(command: Sequence[str]) -> List[str]:
    """Return a copy of an argv list that is safe to log or persist."""
    redacted: List[str] = []
    mask_next = False
    for raw in command:
        arg = str(raw)
        if mask_next:
            redacted.append(REDACTED)
            mask_next = False
            continue
        if "=" in arg and arg.startswith("--"):
            flag, _, value = arg.partition("=")
            if flag in _SECRET_FLAGS and flag not in _AMBIGUOUS_FLAGS:
                redacted.append(f"{flag}={REDACTED}")
                continue
            if flag in _AMBIGUOUS_FLAGS and _SECRET_HEADER_RE.match(value):
                redacted.append(f"{flag}={REDACTED}")
                continue
        if arg in _SECRET_FLAGS and arg not in _AMBIGUOUS_FLAGS:
            redacted.append(arg)
            mask_next = True
            continue
        if arg in _AMBIGUOUS_FLAGS:
            # Value is masked on the next iteration only if it looks like a credential header.
            redacted.append(arg)
            continue
        if _SECRET_HEADER_RE.match(arg):
            redacted.append(REDACTED)
            continue
        redacted.append(redact_text(arg))
    return redacted


def redact_lines(lines: Iterable[str]) -> List[str]:
    return [redact_text(line) for line in lines]
