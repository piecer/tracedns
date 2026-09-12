"""Redact configured credentials in both JSON values and keys."""
import hashlib

SECRET_KEYS = {'api_key', 'vt_api_key', 'teams_webhook', 'ens_rpc_url',
               'DEFAULT_SNS_PROXY_HOSTS', 'DEFAULT_SOLAR_PROXY_HOSTS'}


def sanitize(payload, config):
    secrets = set()

    def collect(value, sensitive=False):
        if isinstance(value, dict):
            for key, child in value.items():
                collect(child, sensitive or key in SECRET_KEYS)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child, sensitive)
        elif sensitive and isinstance(value, str) and value:
            secrets.add(value)

    collect(config)
    replacements = [(s, 'redacted-' + hashlib.sha256(s.encode()).hexdigest()[:12])
                    for s in sorted(secrets, key=len, reverse=True)]

    def scrub(value):
        if isinstance(value, dict):
            return {scrub(k): scrub(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [scrub(v) for v in value]
        if isinstance(value, str):
            for secret, replacement in replacements:
                if value == secret or len(secret) >= 4:
                    value = value.replace(secret, replacement)
        return value

    return scrub(payload)
