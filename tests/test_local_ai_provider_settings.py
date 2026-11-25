"""Pure provider settings: synthetic values only, never provider/application I/O."""

import importlib
from pathlib import Path

import pytest


def load_settings():
    try:
        module = importlib.import_module("local_ai.provider_settings")
    except ModuleNotFoundError:
        pytest.fail("pure provider settings module is missing")
    assert module.__file__ is not None
    assert Path(module.__file__).resolve() == Path(__file__).resolve().parents[1] / "local_ai/provider_settings.py"
    return module


@pytest.mark.parametrize("value", [None, {}])
def test_missing_settings_are_detached_disabled_native_defaults(value):
    settings = load_settings()
    expected = {"enabled": False, "provider": "ollama", "base_url": "", "model": "", "model_digest": ""}
    result = settings.normalize_settings(value)
    assert result == expected
    assert result is not value
    result["model"] = "changed:tag"
    assert settings.normalize_settings(value) == expected
    if value is not None:
        assert value == {}


@pytest.fixture
def settings():
    return load_settings()


def invalid(call):
    from local_ai.contracts import AIError

    with pytest.raises(AIError) as caught:
        call()
    assert caught.value.code == "invalid_request"
    assert caught.value.status == 400
    assert caught.value.args == ("invalid_request",)
    assert str(caught.value) == "invalid_request"
    assert caught.value.__cause__ is None


NATIVE = {
    "enabled": True,
    "provider": "ollama",
    "base_url": "http://localhost:11434",
    "model": "qwen3.5:9b",
    "model_digest": "a" * 64,
}


@pytest.mark.parametrize("legacy", [False, True])
def test_native_normalization_preserves_values_and_input(settings, legacy):
    value = dict(NATIVE)
    if legacy:
        value.pop("provider")
        value["origin"] = value.pop("base_url")
    before = dict(value)
    assert settings.normalize_settings(value) == NATIVE
    assert value == before


class CustomDict(dict):
    pass


class CustomStr(str):
    pass


@pytest.mark.parametrize(
    "value",
    [
        [],
        (),
        "",
        0,
        False,
        CustomDict(),
        {1: "invalid"},
        {"unknown": "value"},
        {"provider": "openai"},
        {"provider": None},
        {"provider": CustomStr("ollama")},
        {"provider": "ollama", "origin": "http://localhost:11434"},
        {"base_url": "http://localhost:11434"},
        {"origin": "http://localhost:11434", "base_url": "http://localhost:11434"},
        {"provider": "ollama", "api_key": ""},
        {"provider": "ollama", "endpoint_policy": "loopback"},
        {"provider": "ollama", "token_limit_field": "max_tokens"},
    ],
)
def test_native_shape_is_closed_and_legacy_origin_is_startup_only(settings, value):
    invalid(lambda: settings.normalize_settings(value))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("enabled", 1),
        ("enabled", "false"),
        ("enabled", None),
        ("base_url", None),
        ("base_url", CustomStr("http://localhost:11434")),
        ("base_url", "http://127.1:11434"),
        ("base_url", "http://localhost:011434"),
        ("base_url", "http://localhost:65536"),
        ("base_url", "http://localhost:11434/"),
        ("base_url", "https://localhost:11434"),
        ("base_url", "http://example.test:11434"),
        ("base_url", "http://192.168.1.1:11434"),
        ("base_url", " http://localhost:11434"),
        ("model", None),
        ("model", CustomStr("local:tag")),
        ("model", "untagged"),
        ("model", "local:cloud"),
        ("model", "CLOUD:tag"),
        ("model", "a:b:c"),
        ("model", "local:tag\n"),
        ("model", "local:ta g"),
        ("model", "é:tag"),
        ("model", "a" * 255 + ":b"),
        ("model_digest", None),
        ("model_digest", "A" * 64),
        ("model_digest", "a" * 63),
        ("model_digest", "sha256:" + "a" * 64),
        ("model_digest", "a" * 64 + "\n"),
    ],
)
@pytest.mark.parametrize("enabled", [False, True])
def test_native_nonblank_values_are_validated_even_when_disabled(settings, field, bad, enabled):
    value = {**NATIVE, "enabled": enabled, field: bad}
    invalid(lambda: settings.normalize_settings(value))


@pytest.mark.parametrize("field", ["base_url", "model", "model_digest"])
def test_native_blanks_only_allowed_while_disabled(settings, field):
    value = {**NATIVE, "enabled": False, field: ""}
    assert settings.normalize_settings(value) == value
    invalid(lambda: settings.normalize_settings({**value, "enabled": True}))


@pytest.mark.parametrize("url", ["http://127.0.0.2:1", "http://[::1]:65535"])
def test_native_retains_existing_loopback_origin_semantics(settings, url):
    value = {**NATIVE, "base_url": url, "model": "a" * 254 + ":b"}
    assert settings.normalize_settings(value) == value


@pytest.mark.parametrize(
    "url,policy,expected",
    [
        (
            "https://api.example.test",
            "public_https",
            ("https", "api.example.test", 443, "api.example.test", "/chat/completions", None),
        ),
        (
            "https://API.example.test:443/",
            "public_https",
            ("https", "API.example.test", 443, "API.example.test:443", "/chat/completions", None),
        ),
        (
            "https://api.example.test:1/v1/a_b-1.~x/",
            "public_https",
            ("https", "api.example.test", 1, "api.example.test:1", "/v1/a_b-1.~x/chat/completions", None),
        ),
        (
            "https://8.8.8.8:65535/v1",
            "public_https",
            ("https", "8.8.8.8", 65535, "8.8.8.8:65535", "/v1/chat/completions", "AF_INET"),
        ),
        (
            "https://[2606:4700:4700::1111]/v1/",
            "public_https",
            ("https", "2606:4700:4700::1111", 443, "[2606:4700:4700::1111]", "/v1/chat/completions", "AF_INET6"),
        ),
        (
            "http://localhost:8080/prefix",
            "loopback",
            ("http", "localhost", 8080, "localhost:8080", "/prefix/chat/completions", "AF_INET"),
        ),
        ("https://localhost", "loopback", ("https", "localhost", 443, "localhost", "/chat/completions", "AF_INET")),
        ("http://127.0.0.2/", "loopback", ("http", "127.0.0.2", 80, "127.0.0.2", "/chat/completions", "AF_INET")),
        ("https://[::1]:8443/v1", "loopback", ("https", "::1", 8443, "[::1]:8443", "/v1/chat/completions", "AF_INET6")),
    ],
)
def test_endpoint_fields_preserve_configured_authority_and_host(settings, url, policy, expected):
    import socket
    from dataclasses import FrozenInstanceError, fields

    endpoint = settings.parse_openai_url(url, policy)
    assert type(endpoint) is settings.Endpoint
    names = ("scheme", "host", "port", "authority", "path", "family")
    assert tuple(field.name for field in fields(endpoint)) == names
    expected = (*expected[:-1], getattr(socket, expected[-1]) if expected[-1] else None)
    assert tuple(getattr(endpoint, name) for name in names) == expected
    with pytest.raises(FrozenInstanceError):
        endpoint.host = "other.example.test"


@pytest.mark.parametrize(
    "url",
    [
        None,
        1,
        b"https://api.example.test",
        CustomStr("https://api.example.test"),
        "",
        " https://api.example.test",
        "https://api.example.test\n",
        "https://api.example.test\t/v1",
        "HTTPS://api.example.test",
        "ftp://api.example.test",
        "//api.example.test",
        "https:///v1",
        "https://user:pass@api.example.test",
        "https://api.example.test?",
        "https://api.example.test#",
        "https://api.example.test?a=b",
        "https://api.example.test/#fragment",
        "https://api.example.test\\v1",
        "https://api.example.test:",
        "https://api.example.test:0",
        "https://api.example.test:01",
        "https://api.example.test:+443",
        "https://api.example.test:65536",
        "https://api.example.test:１２",
        "https://api.example.test//",
        "https://api.example.test/v1//x",
        "https://api.example.test/v1//",
        "https://api.example.test/.",
        "https://api.example.test/../v1",
        "https://api.example.test/v1/./",
        "https://api.example.test/v1/..",
        "https://api.example.test/v1/%2e",
        "https://api.example.test/v1/%41",
        "https://api.example.test/v 1",
        "https://api.example.test/é",
        "https://api.example.test/v1;param",
        "https://api.example.test/chat/completions",
        "https://api.example.test/v1/chat/completions/",
        "https://api.example.test/" + "x" * 1001,
    ],
)
def test_endpoint_rejects_noncanonical_url_and_path_grammar(settings, url):
    invalid(lambda: settings.parse_openai_url(url, "public_https"))


@pytest.mark.parametrize("policy", [None, [], "", "public", "PUBLIC_HTTPS", CustomStr("loopback")])
def test_endpoint_policy_is_explicit_closed_enum(settings, policy):
    invalid(lambda: settings.parse_openai_url("https://api.example.test", policy))


def test_endpoint_url_exact_byte_limit(settings):
    base = "https://api.example.test/"
    url = base + "a" * (1024 - len(base))
    assert (
        settings.parse_openai_url(url, "public_https").path
        == url[len("https://api.example.test") :] + "/chat/completions"
    )
    invalid(lambda: settings.parse_openai_url(url + "a", "public_https"))


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.1.2.3",
        "240.0.0.1",
        "255.255.255.255",
        "127.1",
        "2130706433",
        "0177.0.0.1",
        "0x7f000001",
        "0x7f.0.0.0x1",
        "127.000.000.001",
        "8.8.8.008",
        "example.123",
        "example.0x10",
        "api.example.test.",
        "api..test",
        "-a.test",
        "a-.test",
        "_api.example.test",
        "é.example.test",
        "a" * 64 + ".test",
        ".".join(["a" * 63] * 4),
        "[8.8.8.8]",
        "[example.test]",
        "[:::1]",
        "[::]",
        "[::1]",
        "[fc00::1]",
        "[fe80::1]",
        "[fec0::1]",
        "[ff02::1]",
        "[ff0e::1]",
        "[2001:db8::1]",
        "[::ffff:8.8.8.8]",
        "[::ffff:808:808]",
        "[::8.8.8.8]",
        "[64:ff9b::808:808]",
        "[64:ff9b:1::808:808]",
        "[2002:808:808::1]",
        "[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
        "[2001:4860::5efe:808:808]",
        "[2001:4860::200:5efe:808:808]",
        "[2606:4700:4700:0:0:0:0:1111]",
        "[2001:4860:4860::ABCD]",
        "[fe80::1%eth0]",
        "[::1%25lo]",
        "2606:4700:4700::1111",
    ],
)
def test_public_policy_rejects_nonpublic_ambiguous_or_noncanonical_hosts(settings, host):
    invalid(lambda: settings.parse_openai_url("https://" + host, "public_https"))


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8",
        "http://api.example.test",
        "http://localhost",
        "http://127.0.0.1",
    ],
)
def test_public_policy_requires_https(settings, url):
    invalid(lambda: settings.parse_openai_url(url, "public_https"))


@pytest.mark.parametrize(
    "host",
    [
        "api.example.test",
        "LOCALHOST",
        "localhost.",
        "sub.localhost",
        "8.8.8.8",
        "10.0.0.1",
        "0.0.0.0",
        "127.1",
        "2130706433",
        "0177.0.0.1",
        "[::ffff:127.0.0.1]",
        "[::]",
        "[0:0:0:0:0:0:0:1]",
        "[2606:4700:4700::1111]",
    ],
)
def test_loopback_policy_never_accepts_dns_aliases_or_nonloopback(settings, host):
    invalid(lambda: settings.parse_openai_url("http://" + host, "loopback"))


@pytest.mark.parametrize("host", ["a", "a-b.example", ".".join(["a" * 63] * 3 + ["b" * 61])])
def test_public_canonical_dns_boundaries_need_no_lookup(settings, host):
    endpoint = settings.parse_openai_url("https://" + host, "public_https")
    assert endpoint.host == host
    assert endpoint.family is None


REMOTE = {
    "enabled": True,
    "provider": "openai_compatible",
    "base_url": "https://api.example.test/v1/",
    "model": "org/model-1@rev+2",
    "endpoint_policy": "public_https",
    "token_limit_field": "max_completion_tokens",
    "api_key": "synthetic-opaque!key",
}


def test_compatible_normalization_defaults_are_explicit(settings):
    assert settings.normalize_settings({"provider": "openai_compatible"}) == {
        "enabled": False,
        "provider": "openai_compatible",
        "base_url": "",
        "model": "",
        "endpoint_policy": "public_https",
        "token_limit_field": "max_completion_tokens",
    }
    value = {key: val for key, val in REMOTE.items() if key not in ("endpoint_policy", "token_limit_field")}
    before = dict(value)
    assert settings.normalize_settings(value) == REMOTE
    assert value == before


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": 1},
        {"base_url": None},
        {"base_url": "http://api.example.test/v1"},
        {"base_url": "https://api.example.test/v1//"},
        {"model": None},
        {"model": "é"},
        {"model": "a" * 257},
        {"model": "-model"},
        {"model": "model name"},
        {"model": "model\n"},
        {"model": "model?version"},
        {"model": CustomStr("model")},
        {"model_digest": ""},
        {"origin": "http://localhost:11434"},
        {"unknown": True},
        {"endpoint_policy": None},
        {"endpoint_policy": "auto"},
        {"endpoint_policy": CustomStr("public_https")},
        {"token_limit_field": None},
        {"token_limit_field": "max_output_tokens"},
        {"token_limit_field": CustomStr("max_tokens")},
        {"api_key": None},
        {"api_key": 1},
        {"api_key": CustomStr("key")},
        {"api_key": "a" * 4097},
        {"api_key": " a"},
        {"api_key": "a "},
        {"api_key": "a b"},
        {"api_key": "a\rb"},
        {"api_key": "a\nb"},
        {"api_key": "a\tb"},
        {"api_key": "a\x00b"},
        {"api_key": "a\x7fb"},
        {"api_key": "clé"},
        {"api_key": "\u00a0"},
    ],
)
@pytest.mark.parametrize("enabled", [False, True])
def test_compatible_nonblank_values_and_closed_fields(settings, changes, enabled):
    invalid(lambda: settings.normalize_settings({**REMOTE, "enabled": enabled, **changes}))


@pytest.mark.parametrize("field", ["base_url", "model"])
def test_compatible_incomplete_configuration_is_disabled_only(settings, field):
    value = {**REMOTE, "enabled": False, field: ""}
    assert settings.normalize_settings(value) == value
    invalid(lambda: settings.normalize_settings({**value, "enabled": True}))


@pytest.mark.parametrize("key", ["", " ", "\t\r\n "])
def test_compatible_empty_key_is_absent_and_public_enable_requires_key(settings, key):
    value = {**REMOTE, "enabled": False, "api_key": key}
    expected = {name: val for name, val in value.items() if name != "api_key"}
    assert settings.normalize_settings(value) == expected
    invalid(lambda: settings.normalize_settings({**value, "enabled": True}))
    invalid(lambda: settings.normalize_settings({**expected, "enabled": True}))


@pytest.mark.parametrize("token_field", ["max_completion_tokens", "max_tokens"])
def test_compatible_loopback_is_explicit_and_can_be_anonymous(settings, token_field):
    value = {
        **REMOTE,
        "base_url": "http://localhost:8000/v1",
        "endpoint_policy": "loopback",
        "token_limit_field": token_field,
    }
    value.pop("api_key")
    assert settings.normalize_settings(value) == value
    invalid(lambda: settings.normalize_settings({**value, "endpoint_policy": "public_https"}))


def test_compatible_model_and_key_exact_bounds_and_opaque_bytes(settings):
    opaque = "".join(chr(number) for number in range(33, 127))
    value = {**REMOTE, "model": "A" + "a._:/@+-" * 31 + "1234567", "api_key": (opaque * 44)[:4096]}
    assert len(value["model"]) == 256
    assert settings.normalize_settings(value) == value
    assert settings.normalize_settings({**value, "model": "a"})["model"] == "a"


@pytest.mark.parametrize(
    "current,patch",
    [
        (None, {"enabled": False}),
        ({}, {"model": "local:tag"}),
        (NATIVE, {"model": "other:tag"}),
        (NATIVE, {"model_digest": "b" * 64}),
        (REMOTE, {"model": "other/model"}),
        (REMOTE, {"token_limit_field": "max_tokens"}),
        (REMOTE, {"enabled": False}),
        (REMOTE, {"base_url": REMOTE["base_url"]}),
    ],
)
def test_merge_partial_updates_are_detached_and_preserve_omitted_fields(settings, current, patch):
    expected = {**settings.normalize_settings(current), **patch}
    before_current = None if current is None else dict(current)
    before_patch = dict(patch)
    result = settings.merge_settings(current, patch)
    assert result == expected
    result["model"] = "mutated:tag"
    assert current == before_current
    assert patch == before_patch


@pytest.mark.parametrize(
    "patch",
    [
        None,
        {},
        [],
        "",
        CustomDict({"enabled": False}),
        {1: "bad"},
        {"unknown": True},
        {"origin": "http://localhost:11434"},
        {"enabled": None},
        {"provider": None},
        {"provider": "openai"},
        {"provider": CustomStr("ollama")},
        {"base_url": None},
        {"model": None},
    ],
)
def test_merge_patch_is_nonempty_closed_canonical_object(settings, patch):
    invalid(lambda: settings.merge_settings(NATIVE, patch))


@pytest.mark.parametrize(
    "current,patch",
    [
        (NATIVE, {"api_key": ""}),
        (NATIVE, {"api_key": "synthetic-new"}),
        (NATIVE, {"endpoint_policy": "loopback"}),
        (NATIVE, {"token_limit_field": "max_tokens"}),
        (REMOTE, {"model_digest": ""}),
        (REMOTE, {"model_digest": "b" * 64}),
        (REMOTE, {"base_url": "https://example.test//"}),
        (REMOTE, {"model": "bad model"}),
        (REMOTE, {"api_key": None}),
        (REMOTE, {"api_key": " leading-space"}),
    ],
)
def test_merge_disallows_fields_of_other_provider_and_invalid_values(settings, current, patch):
    before_current, before_patch = dict(current), dict(patch)
    invalid(lambda: settings.merge_settings(current, patch))
    assert current == before_current
    assert patch == before_patch


def test_merge_accepts_legacy_current_but_not_legacy_patch(settings):
    current = {key: value for key, value in NATIVE.items() if key not in ("provider", "base_url")}
    current["origin"] = NATIVE["base_url"]
    assert settings.merge_settings(current, {"enabled": False}) == {**NATIVE, "enabled": False}
    invalid(lambda: settings.merge_settings({"enabled": "false"}, {"enabled": False}))


@pytest.mark.parametrize("key", ["", " ", "\t\n\r", " " * 4096])
@pytest.mark.parametrize("enabled", [False, True])
def test_merge_blank_key_keeps_prior_bytes_for_unchanged_binding(settings, key, enabled):
    current = {**REMOTE, "enabled": enabled}
    assert settings.merge_settings(current, {"api_key": key}) == current
    no_key = {name: value for name, value in current.items() if name != "api_key"}
    no_key["enabled"] = False
    assert settings.merge_settings(no_key, {"api_key": key}) == no_key


def test_merge_key_replacement_preserves_exact_opaque_bytes(settings):
    key = "synthetic!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    assert settings.merge_settings(REMOTE, {"api_key": key}) == {**REMOTE, "api_key": key}


@pytest.mark.parametrize("clear_fields", [("api_key",), ["api_key"]])
@pytest.mark.parametrize("patch", [{"enabled": False}, {"enabled": False, "api_key": " \t"}])
def test_merge_explicit_clear_removes_secret_without_mutating_inputs(settings, clear_fields, patch):
    before_clear, before_patch = list(clear_fields), dict(patch)
    result = settings.merge_settings(REMOTE, patch, clear_fields)
    assert result == {name: val for name, val in {**REMOTE, "enabled": False}.items() if name != "api_key"}
    assert list(clear_fields) == before_clear
    assert patch == before_patch
    assert REMOTE["api_key"] == "synthetic-opaque!key"


@pytest.mark.parametrize(
    "clear_fields",
    [
        None,
        "api_key",
        {"api_key"},
        {"api_key": True},
        ["api_key", "api_key"],
        ["model"],
        ["api_key", "model"],
        [1],
        [None],
        [CustomStr("api_key")],
    ],
)
def test_merge_clear_fields_is_a_unique_closed_sequence(settings, clear_fields):
    invalid(lambda: settings.merge_settings(REMOTE, {"enabled": False}, clear_fields))


def test_merge_clear_requires_nonempty_patch_and_forbids_nonblank_replacement(settings):
    invalid(lambda: settings.merge_settings(REMOTE, {}, ["api_key"]))
    invalid(lambda: settings.merge_settings(REMOTE, {"api_key": "new-synthetic-key"}, ["api_key"]))
    invalid(lambda: settings.merge_settings(REMOTE, {"enabled": True}, ["api_key"]))
    assert settings.merge_settings(NATIVE, {"enabled": False}, ["api_key"]) == {**NATIVE, "enabled": False}
    loopback = {**REMOTE, "endpoint_policy": "loopback", "base_url": "https://localhost/v1"}
    result = settings.merge_settings(loopback, {"enabled": True}, ["api_key"])
    assert result == {name: value for name, value in loopback.items() if name != "api_key"}


@pytest.mark.parametrize("key", [" " * 4097, "\x00", "\x7f", "\u00a0", "bad\tkey", "key\r\nheader:bad"])
def test_merge_key_validation_precedes_clear_or_keep_semantics(settings, key):
    invalid(lambda: settings.merge_settings(REMOTE, {"api_key": key}))
    invalid(lambda: settings.merge_settings(REMOTE, {"api_key": key, "enabled": False}, ["api_key"]))


@pytest.mark.parametrize(
    "binding_patch",
    [
        {"base_url": "https://other.example.test/v1/"},
        {"base_url": REMOTE["base_url"].removesuffix("/")},
        {"base_url": "https://api.example.test:443/v1/"},
        {"base_url": "https://API.example.test/v1/"},
        {"base_url": "https://localhost/v1", "endpoint_policy": "loopback"},
    ],
)
@pytest.mark.parametrize("key_patch", [{}, {"api_key": ""}, {"api_key": " \t"}])
@pytest.mark.parametrize("enabled", [False, True])
def test_changed_credential_binding_never_silently_carries_key(settings, binding_patch, key_patch, enabled):
    current = {**REMOTE, "enabled": enabled}
    patch = {**binding_patch, **key_patch}
    before = dict(current)
    invalid(lambda: settings.merge_settings(current, patch))
    assert current == before


def test_policy_change_alone_is_a_credential_binding_change(settings):
    # A blank disabled URL allows both policies; no URL-policy error can mask the guard.
    current = {**REMOTE, "enabled": False, "base_url": ""}
    invalid(lambda: settings.merge_settings(current, {"endpoint_policy": "loopback"}))
    assert settings.merge_settings(current, {"endpoint_policy": "loopback", "api_key": "new-key"}) == {
        **current,
        "endpoint_policy": "loopback",
        "api_key": "new-key",
    }


@pytest.mark.parametrize(
    "patch",
    [
        {"base_url": "https://other.example.test/v1"},
        {"base_url": "https://localhost/v1", "endpoint_policy": "loopback"},
    ],
)
def test_changed_binding_requires_explicit_replacement_or_clear(settings, patch):
    assert settings.merge_settings(REMOTE, {**patch, "api_key": "new-synthetic"}) == {
        **REMOTE,
        **patch,
        "api_key": "new-synthetic",
    }
    cleared = settings.merge_settings(REMOTE, {**patch, "enabled": False}, ["api_key"])
    assert cleared == {
        name: value for name, value in {**REMOTE, **patch, "enabled": False}.items() if name != "api_key"
    }
    no_key = {name: value for name, value in {**REMOTE, "enabled": False}.items() if name != "api_key"}
    assert settings.merge_settings(no_key, patch) == {**no_key, **patch}


@pytest.mark.parametrize("enabled", [False, True])
def test_switch_to_native_requires_explicit_clear_of_remote_key(settings, enabled):
    patch = {**NATIVE, "enabled": enabled}
    invalid(lambda: settings.merge_settings(REMOTE, patch))
    assert settings.merge_settings(REMOTE, patch, ["api_key"]) == patch
    no_key = {name: value for name, value in {**REMOTE, "enabled": False}.items() if name != "api_key"}
    assert settings.merge_settings(no_key, patch) == patch


def test_switch_to_compatible_removes_native_digest_and_uses_remote_defaults(settings):
    patch = {key: value for key, value in REMOTE.items() if key not in ("endpoint_policy", "token_limit_field")}
    assert settings.merge_settings(NATIVE, patch) == REMOTE
    assert settings.merge_settings(
        NATIVE,
        {
            "provider": "openai_compatible",
            "endpoint_policy": "loopback",
        },
    ) == {
        "enabled": True,
        "provider": "openai_compatible",
        "base_url": NATIVE["base_url"],
        "model": NATIVE["model"],
        "endpoint_policy": "loopback",
        "token_limit_field": "max_completion_tokens",
    }


@pytest.mark.parametrize(
    "patch",
    [
        {**NATIVE, "api_key": ""},
        {**NATIVE, "api_key": "new-key"},
        {**NATIVE, "endpoint_policy": "loopback"},
        {**NATIVE, "token_limit_field": "max_tokens"},
    ],
)
def test_switch_to_native_cannot_smuggle_remote_patch_fields(settings, patch):
    invalid(lambda: settings.merge_settings(REMOTE, patch, ["api_key"]))


def test_switch_to_compatible_rejects_explicit_native_digest(settings):
    invalid(lambda: settings.merge_settings(NATIVE, {**REMOTE, "model_digest": ""}))


@pytest.mark.parametrize("value", [None, NATIVE, REMOTE, {**REMOTE, "enabled": False, "api_key": ""}])
def test_public_projection_is_closed_secret_free_and_detached(settings, value):
    canonical = settings.normalize_settings(value)
    before = None if value is None else dict(value)
    expected = {name: val for name, val in canonical.items() if name != "api_key"}
    expected["configured"] = {"api_key": bool(canonical.get("api_key"))}
    public = settings.public_settings(value)
    assert public == expected
    assert "api_key" not in public
    assert "synthetic-opaque!key" not in repr(public)
    public["configured"]["api_key"] = "mutated"
    public["model"] = "mutated"
    assert settings.public_settings(value) == expected
    assert value == before


def test_public_projection_normalizes_legacy_without_writeback(settings):
    value = {
        "enabled": False,
        "origin": NATIVE["base_url"],
        "model": NATIVE["model"],
        "model_digest": NATIVE["model_digest"],
    }
    before = dict(value)
    assert settings.public_settings(value) == {**NATIVE, "enabled": False, "configured": {"api_key": False}}
    assert value == before
    invalid(lambda: settings.public_settings({**REMOTE, "configured": {"api_key": True}}))


def test_all_pure_entrypoints_have_zero_io_attempts(settings, monkeypatch):
    import builtins
    import io
    import os
    import socket
    import subprocess
    import threading
    from local_ai import provider

    calls = []

    def denied(*args, **kwargs):
        calls.append("unexpected I/O")
        raise AssertionError("pure settings attempted I/O")

    class NoEnvironment(dict):
        __getitem__ = get = items = keys = values = __iter__ = __contains__ = denied

    # Imports and harness setup happen before the no-effect boundary. Nothing
    # inside these spies delegates to a real resolver, socket, file or worker.
    with monkeypatch.context() as guard:
        for owner, names in [
            (builtins, ("open",)),
            (io, ("open",)),
            (os, ("open", "getenv", "system")),
            (Path, ("open", "read_text", "read_bytes", "write_text", "write_bytes")),
            (
                socket,
                ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"),
            ),
            (subprocess, ("Popen",)),
            (threading.Thread, ("start",)),
            (provider.OllamaProvider, ("__init__", "generate")),
        ]:
            for name in names:
                guard.setattr(owner, name, denied)
        guard.setattr(os, "environ", NoEnvironment())
        assert settings.normalize_settings(None)["enabled"] is False
        assert settings.normalize_settings(NATIVE) == NATIVE
        assert settings.normalize_settings(REMOTE) == REMOTE
        assert settings.merge_settings(REMOTE, {"model": "other"})["api_key"] == REMOTE["api_key"]
        assert settings.merge_settings(REMOTE, NATIVE, ["api_key"]) == NATIVE
        assert settings.public_settings(REMOTE)["configured"] == {"api_key": True}
        assert settings.parse_openai_url("https://api.example.test/v1", "public_https").family is None
        assert settings.parse_openai_url("https://localhost/v1", "loopback").host == "localhost"
        invalid(lambda: settings.normalize_settings({**REMOTE, "api_key": "bad\nkey"}))
        invalid(lambda: settings.parse_openai_url("https://127.1", "public_https"))
        invalid(lambda: settings.merge_settings(REMOTE, {"base_url": "https://other.example.test"}))
    assert calls == []


def test_errors_and_public_output_never_echo_synthetic_credentials(settings, capsys, caplog):
    from local_ai.contracts import AIError

    sentinel = "synthetic-error-secret-DO-NOT-REFLECT"
    current = {**REMOTE, "api_key": sentinel}
    for patch in ({"base_url": "https://other.example.test"}, {"api_key": sentinel + "\n"}, {"api_key": None}):
        with pytest.raises(AIError) as caught:
            settings.merge_settings(current, patch)
        assert str(caught.value) == "invalid_request"
        assert sentinel not in repr(caught.value.__dict__)
    assert sentinel not in repr(settings.public_settings(current))
    output = capsys.readouterr()
    assert output.out == output.err == ""
    assert not caplog.records


@pytest.mark.parametrize("field", ["provider", "base_url", "endpoint_policy", "token_limit_field", "model", "api_key"])
def test_custom_patch_leaf_is_rejected_before_any_comparison_hook(settings, field):
    calls = []

    class UntrustedString(str):
        def __ne__(self, other):
            calls.append("comparison")
            raise AssertionError("untrusted comparison must not execute")

    value = UntrustedString(REMOTE[field])
    invalid(lambda: settings.merge_settings(REMOTE, {field: value}))
    invalid(lambda: settings.normalize_settings({**REMOTE, field: value}))
    assert calls == []
