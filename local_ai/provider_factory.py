"""Inert selected-provider construction; compatible dependencies load lazily."""
import time

from .provider import OllamaProvider
from .provider_settings import normalize_settings


def create_resolver(*, clock=time.monotonic):
    from .resolver import ResolverOwner
    return ResolverOwner(clock=clock)


def create_provider(settings, *, resolver, clock=time.monotonic, compatible_factory=None):
    settings = normalize_settings(settings)
    if not settings['enabled']:
        return None
    if settings['provider'] == 'ollama':
        return OllamaProvider(settings['base_url'], settings['model'], settings['model_digest'])
    if compatible_factory is None:
        from .openai_provider import OpenAICompatibleProvider
        compatible_factory = OpenAICompatibleProvider
    return compatible_factory(settings, resolver=resolver, clock=clock)
