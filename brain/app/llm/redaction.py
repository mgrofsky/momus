"""Outgoing text passes through the scanner's own redaction module before any provider call.

One source of truth: the file is scanner/pipeline/redact.py. The brain's image copies it to /opt/brain/shared/redact.py
at build time (brain/Dockerfile); in a working copy (the tests mount the repository) it is read from the repository.
It is loaded under a private module name and never forked. If neither copy can be loaded, the analyst refuses to
run (fail closed): load() raises.

Two uses:
  field(text)    one target-derived value inside a tool result: redact_text(strict=True), as storage does (secrets,
                 credentials in URLs, email addresses reduced to their domain, long random-looking tokens masked)
  outgoing(text) each free-text segment of a prompt (the chat question, an accepted note, an untrusted part of a tool
                 result, a corrective note), never the assembled prompt: redact_text(strict=False) (patterns and URLs; no
                 entropy masking). Run over the whole prompt it would rewrite identifiers in the
                 data parts (a finding key with a card-like digit run, a JSON field name)."""
import hashlib
import importlib.util
import os
import threading

_HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # /opt/brain or <repo>/brain
CANDIDATES = (os.path.join(_HERE, "shared", "redact.py"),                                    # the image
              os.path.join(os.path.dirname(_HERE), "scanner", "pipeline", "redact.py"))      # a working copy
_lock = threading.Lock()
_mod = None


class RedactionUnavailable(Exception):
    pass


def source_path():
    for p in CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


def load():
    global _mod
    with _lock:
        if _mod is not None:
            return _mod
        p = source_path()
        if p is None:
            raise RedactionUnavailable("The redaction module (scanner/pipeline/redact.py) is not in this image.")
        spec = importlib.util.spec_from_file_location("_momus_scanner_redact", p)
        m = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(m)
        except Exception:
            raise RedactionUnavailable("The redaction module could not be loaded.") from None
        if not all(callable(getattr(m, f, None)) for f in ("redact_text", "redact", "redact_url")):
            raise RedactionUnavailable("The redaction module does not have the expected functions.")
        _mod = m
        return m


def digest():
    p = source_path()
    if p is None:
        return None
    with open(p, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def field(text, cap=None):
    if text is None:
        return None
    return load().redact_text(text if isinstance(text, str) else str(text), strict=True, cap=cap)


def outgoing(text):
    return load().redact_text(text, strict=False)
