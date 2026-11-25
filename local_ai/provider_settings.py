"""Pure, closed provider configuration; no persistence or transport execution.

Legacy ``origin`` is accepted only by normalization, never in a settings patch.
Credential binding uses the exact provider, base URL and endpoint policy; even
an optional trailing slash is a binding change. Public projection is the only
secret-free settings shape and is not a valid persistence/update input.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass

from local_ai.contracts import AIError
from local_ai.provider import ProviderError, _origin

_NATIVE_FIELDS = {"enabled", "provider", "base_url", "model", "model_digest"}
_REMOTE_FIELDS = {"enabled", "provider", "base_url", "model", "endpoint_policy", "token_limit_field", "api_key"}
_LEGACY_FIELDS = {"enabled", "origin", "model", "model_digest"}


def _object(value):
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise AIError("invalid_request")


def _text(value, limit):
    if type(value) is not str or len(value) > limit or not value.isascii():
        raise AIError("invalid_request")
    return value


@dataclass(frozen=True)
class Endpoint:
    """Validated target; transport must vet DNS and pin addresses separately."""

    scheme: str
    host: str
    port: int
    authority: str
    path: str
    family: int | None


def parse_openai_url(base_url, endpoint_policy) -> Endpoint:
    """Parse without repair or resolution; accepted base URLs remain unchanged.

    Prefix grammar: no path, ``/``, or slash-separated ASCII unreserved
    segments, with at most one trailing slash. Empty internal/dot segments,
    escapes, userinfo, query, fragment and an appended chat endpoint are refused.
    ``localhost`` stays the original hostname for verified TLS SNI; pinning it
    to 127.0.0.1, and checking every public DNS answer, belongs to the transport.
    """
    _text(base_url, 1024)
    if type(endpoint_policy) is not str or endpoint_policy not in ("public_https", "loopback"):
        raise AIError("invalid_request")
    match = re.fullmatch(
        r"(https?)://((\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::([1-9][0-9]{0,4}))?)"
        r"((?:/[A-Za-z0-9._~-]+)*/?)",
        base_url,
    )
    if match is None:
        raise AIError("invalid_request")
    scheme, authority, raw_host, explicit_port, prefix = match.groups()
    port = int(explicit_port) if explicit_port else (443 if scheme == "https" else 80)
    prefix = prefix.removesuffix("/")
    if port > 65535 or any(part in (".", "..") for part in prefix.split("/")) or prefix.endswith("/chat/completions"):
        raise AIError("invalid_request")
    host = raw_host[1:-1] if raw_host.startswith("[") else raw_host
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if (
            str(address) != host
            or raw_host.startswith("[") != (address.version == 6)
            or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
        ):
            raise AIError("invalid_request")
    elif raw_host.startswith("[") or not _dns_name(host):
        raise AIError("invalid_request")
    if endpoint_policy == "loopback":
        if host != "localhost" and (address is None or not address.is_loopback):
            raise AIError("invalid_request")
    elif scheme != "https" or host.lower() == "localhost" or (address is not None and not _public_literal(address)):
        raise AIError("invalid_request")
    family = socket.AF_INET if host == "localhost" else None
    if address is not None:
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    return Endpoint(scheme, host, port, authority, prefix + "/chat/completions", family)


def _dns_name(host):
    labels = host.split(".")
    return (
        len(host) <= 253
        and re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", labels[-1]) is None
        and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)
    )


def _public_literal(address):
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if address.version == 6:
        # Do not route around the IPv4 policy through translation/tunneling.
        if address.ipv4_mapped or address.sixtofour or address.teredo or address.is_site_local:
            return False
        if any(address in ipaddress.IPv6Network(prefix) for prefix in ("64:ff9b::/96", "64:ff9b:1::/48")):
            return False
        if (int(address) >> 32) & 0xFFFFFFFF in (0x00005EFE, 0x02005EFE):  # ISATAP
            return False
    return True


def _fields(provider):
    if type(provider) is not str or provider not in ("ollama", "openai_compatible"):
        raise AIError("invalid_request")
    return _NATIVE_FIELDS if provider == "ollama" else _REMOTE_FIELDS


def merge_settings(current, patch, clear_fields=()):
    """Validate a closed partial update; blank keys retain, explicit clears remove."""
    _object(patch)
    if not patch:
        raise AIError("invalid_request")
    if (
        type(clear_fields) not in (list, tuple)
        or len(clear_fields) > 1
        or any(type(field) is not str or field != "api_key" for field in clear_fields)
    ):
        raise AIError("invalid_request")
    prior = normalize_settings(current)
    fields = _fields(patch.get("provider", prior["provider"]))
    if patch.keys() - fields:
        raise AIError("invalid_request")
    # Reject custom leaves before comparing credential-binding values. A str
    # subclass must not get to execute its comparison hooks at this boundary.
    if any(type(value) is not (bool if name == "enabled" else str) for name, value in patch.items()):
        raise AIError("invalid_request")
    update = dict(patch)
    replacement = _key(update["api_key"]) if "api_key" in update else None
    if clear_fields and replacement is not None:
        raise AIError("invalid_request")
    if replacement is None:
        update.pop("api_key", None)
    candidate = {name: value for name, value in prior.items() if name in fields}
    candidate.update(update)
    binding = ("provider", "base_url", "endpoint_policy")
    changed = any(candidate.get(name) != prior.get(name) for name in binding)
    if prior.get("api_key") and changed and replacement is None and not clear_fields:
        raise AIError("invalid_request")
    if clear_fields:
        candidate.pop("api_key", None)
    return normalize_settings(candidate)


def public_settings(value):
    """Return canonical nonsecret settings and a detached credential indicator."""
    result = normalize_settings(value)
    configured = bool(result.pop("api_key", None))
    result["configured"] = {"api_key": configured}
    return result


def normalize_settings(value=None):
    """Return detached canonical settings, accepting only the legacy startup shape."""
    if value is None:
        value = {}
    _object(value)
    value = dict(value)
    if "provider" not in value:
        if value.keys() - _LEGACY_FIELDS:
            raise AIError("invalid_request")
        value["provider"] = "ollama"
        if "origin" in value:
            value["base_url"] = value.pop("origin")
    provider = value["provider"]
    fields = _fields(provider)
    if value.keys() - fields:
        raise AIError("invalid_request")
    result = {"enabled": False, "provider": provider, "base_url": "", "model": ""}
    if provider == "ollama":
        result["model_digest"] = ""
    else:
        result.update(endpoint_policy="public_https", token_limit_field="max_completion_tokens")
    result.update(value)
    if type(result["enabled"]) is not bool:
        raise AIError("invalid_request")
    url = _text(result["base_url"], 1024)
    model = _text(result["model"], 256)
    if result["enabled"] and not all((url, model)):
        raise AIError("invalid_request")
    if provider == "openai_compatible":
        _compatible_values(result, url, model)
    else:
        _native_values(result, url, model)
    return result


def _native_values(result, url, model):
    digest = _text(result["model_digest"], 64)
    if result["enabled"] and not digest:
        raise AIError("invalid_request")
    if url:
        try:
            _origin(url)
        except ProviderError:
            raise AIError("invalid_request") from None
    # Keep the native constructor's exact tag/digest and cloud-name semantics,
    # without constructing an adapter or doing discovery for partial settings.
    if model and (
        "cloud" in model.lower()
        or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*", model) is None
    ):
        raise AIError("invalid_request")
    if digest and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AIError("invalid_request")


def _key(value):
    _text(value, 4096)
    if not value or value.isspace():
        return None
    if re.fullmatch(r"[\x21-\x7e]+", value) is None:
        raise AIError("invalid_request")
    return value


def _compatible_values(result, url, model):
    policy = result["endpoint_policy"]
    token = result["token_limit_field"]
    if (
        type(policy) is not str
        or policy not in ("public_https", "loopback")
        or type(token) is not str
        or token not in ("max_completion_tokens", "max_tokens")
    ):
        raise AIError("invalid_request")
    if url:
        parse_openai_url(url, policy)
    if model and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}", model) is None:
        raise AIError("invalid_request")
    if "api_key" in result and _key(result["api_key"]) is None:
        del result["api_key"]
    if result["enabled"] and policy == "public_https" and not result.get("api_key"):
        raise AIError("invalid_request")
