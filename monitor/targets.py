"""Canonical configured targets and their active provider voting scope."""
from config_manager import domain_storage_name
from .repository import normalized_domain_specs


def providers_for(domain, servers=(), ens_rpc_url=None, sns_proxy_hosts=()):
    kind = str(domain.type or 'A').upper()
    values = ([ens_rpc_url] if ens_rpc_url else []) if kind == 'ENS' else (
        sns_proxy_hosts if kind == 'SNS' else servers)
    return tuple(dict.fromkeys(str(v).strip() for v in (values or ()) if str(v or '').strip()))


def active_target_projection(domains, servers=(), ens_rpc_url=None, sns_proxy_hosts=()):
    return {domain_storage_name(vars(d)): frozenset(providers_for(
        d, servers, ens_rpc_url, sns_proxy_hosts)) for d in normalized_domain_specs(domains)}
