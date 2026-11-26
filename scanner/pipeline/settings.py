"""settings.py - optional policy overrides for the pipeline (standard library only).

load() returns the policy the pipeline runs with. With no scanner/config/policy.json it returns the built-in
defaults below; with one, each key present in the file replaces (lists) or updates (day tables) the default.

  sla_days               fix-by days per band on an ordinary host (whole days, 1 to 3650)
  strict_sla_days        stricter fix-by days per band on a host in the strict-SLA host list
                         (bands not named here use sla_days; same bounds)
  strict_sla_hosts_file  file name, under the scan root's scope/ folder, of the strict-SLA host list
                         (one hostname or parent domain per line; a host matches itself or any name under it).
                         A host in that list does two things in scoring.py: its findings get the shorter
                         strict_sla_days allowance, and its impact floor is higher (a readable credential or
                         personal data scores impact 5 there instead of 4)
  noise_tags             nuclei tags whose info-level results are stored as technology, not findings
  noise_ids              nuclei template IDs treated the same way

Example policy.json:
  {"sla_days": {"Medium": 120}, "strict_sla_days": {"High": 14, "Critical": 14}}

A file that is not valid JSON, has an unknown key, or has a value of the wrong type raises PolicyError, so a
typo never silently falls back to the defaults.
"""
import copy
import json
import os

POLICY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "policy.json")
BANDS = ("Critical", "High", "Medium", "Low")
MIN_DAYS, MAX_DAYS = 1, 3650

DEFAULTS = {
    "sla_days": {"Critical": 30, "High": 90, "Medium": 180, "Low": 180},
    "strict_sla_days": {"High": 30},
    "strict_sla_hosts_file": "strict_sla_hosts.txt",
    "noise_tags": ["tech", "fingerprint", "detect"],
    "noise_ids": [
        "tech-detect", "ssl-dns-names", "ssl-issuer", "waf-detect", "favicon-detect", "fingerprinthub-web-fingerprints",
        "caa-fingerprint", "mx-fingerprint", "nameserver-fingerprint", "txt-fingerprint", "dns-saas-service-detection",
        "http-trace", "robots-txt-endpoint", "options-method", "tls-version", "spf-record-detect",
        "dmarc-detect", "dnssec-detection", "mx-service-detector", "wildcard-tls", "aws-detect", "azure-domain-tenant",
        # DNS fingerprints: the dns source already raises internal-ip-disclosure per host, so the nuclei templates
        # that fire on the same private address would only repeat it
        "dns-internal-ip-disclosure", "dns-rebinding", "aaaa-fingerprint", "ec2-detection", "srv-service-detect",
        "dkim-record-detect", "wildcard-dns-detect",
    ],
}


class PolicyError(ValueError):
    pass


def _days(path, key, value):
    if not isinstance(value, dict):
        raise PolicyError(f"{path}: {key} must be an object of band -> days")
    for band, days in value.items():
        if band not in BANDS:
            raise PolicyError(f"{path}: {key}: unknown band {band!r} (expected one of {', '.join(BANDS)})")
        if isinstance(days, bool) or not isinstance(days, int) or not MIN_DAYS <= days <= MAX_DAYS:
            raise PolicyError(f"{path}: {key}.{band} must be a whole number of days from {MIN_DAYS} to {MAX_DAYS}")
    return value


def _strings(path, key, value):
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PolicyError(f"{path}: {key} must be a list of non-empty strings")
    return [v.strip() for v in value]


def load(path=POLICY_FILE):
    """The policy dict: defaults, updated from the JSON file at path when it exists."""
    policy = copy.deepcopy(DEFAULTS)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return policy
    try:
        data = json.loads(text)
    except ValueError as e:
        raise PolicyError(f"{path}: not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: the top level must be a JSON object")
    for key, value in data.items():
        if key in ("sla_days", "strict_sla_days"):
            policy[key].update(_days(path, key, value))
        elif key == "strict_sla_hosts_file":
            if not isinstance(value, str) or value.strip() in ("", ".", "..") or "/" in value or "\\" in value:
                raise PolicyError(f"{path}: strict_sla_hosts_file must be a plain file name")
            policy[key] = value.strip()
        elif key in ("noise_tags", "noise_ids"):
            policy[key] = _strings(path, key, value)
        else:
            raise PolicyError(f"{path}: unknown key {key!r} (expected one of {', '.join(DEFAULTS)})")
    return policy
