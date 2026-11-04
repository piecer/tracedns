"""Application-owned target leases for monitor state publication.

The configuration owner changes target membership. Collectors retain the lease
captured with their configuration, never reacquiring authority by target name.
"""
from dataclasses import dataclass, field
from copy import deepcopy
import os
import threading

from config_manager import domain_storage_name, normalize_domains
from history_manager import history_file_path
from models import DomainSpec, coerce_domains
from .runtime_state import bump_state_version, state_lock


def normalized_domain_specs(domains):
    items = list(domains) if isinstance(domains, (list, tuple)) else [domains]
    return coerce_domains(normalize_domains([
        vars(item) if isinstance(item, DomainSpec) else item for item in items
    ]))


@dataclass(eq=False)
class _Target:
    definition: object
    active: bool = True
    failures: dict = field(default_factory=dict)
    version: int = 0
    lookup_failed: bool = False
    lookup_uncertain: bool = True


@dataclass(frozen=True)
class TargetLease:
    name: str
    target: _Target
    current: dict
    history: dict


class MonitorStateRepository:
    def __init__(self, current, history, history_dir, domains=(), *, startup=False):
        self.current = current
        self.history = history
        self.history_dir = history_dir
        self._coord = threading.RLock()
        self._providers = None
        self.delivery_runtime = None
        self.lookup_runtime = None
        self.generation = 0
        self._lookup_in_flight = 0
        self._lookup_attempt = None
        self._lookup_success = None
        self._lookup_coverage = 'unknown'
        self._pending_cleanup = set()
        self._targets = {
            domain_storage_name(vars(domain)): _Target(deepcopy(domain))
            for domain in normalized_domain_specs(domains)
        }
        if startup:
            # Discover malformed files too: the history loader skips them.
            from urllib.parse import unquote
            names = set(current) | set(history)
            if history_dir:
                try:
                    names.update(unquote(f[:-5]) for f in os.listdir(history_dir)
                                 if f.endswith('.json'))
                except FileNotFoundError:
                    pass
                # Other discovery failures abort startup: no unsafe admission.
            self._pending_cleanup.update(names - set(self._targets))
            with state_lock():
                for name in self._pending_cleanup:
                    current.pop(name, None)
                    history.pop(name, None)
            self.retry_cleanup()

    def _publish_lookup_health(self):
        # Producer-only aggregation under repository ownership; HTTP never calls
        # this method or walks the target registry.
        if self.delivery_runtime is None:
            return
        from .delivery_progress import counter
        self.delivery_runtime.publish_lookup_health({
            'last_attempt_at': self._lookup_attempt, 'last_success_at': self._lookup_success,
            'in_flight': counter(self._lookup_in_flight),
            'failed_targets': counter(sum(t.lookup_failed for t in self._targets.values())),
            'uncertain_targets': counter(sum(t.lookup_uncertain for t in self._targets.values())),
            'coverage': self._lookup_coverage, 'counts_stale': False,
        })

    def lookup_provider_progress(self, lease, *, starting):
        with self._coord:
            # Capacity belongs to the actual callback, even after its target's
            # authority is retired. Only current leases may update target facts.
            self._lookup_in_flight = max(0, self._lookup_in_flight + (1 if starting else -1))
            if starting and self.valid(lease) and self.delivery_runtime is not None:
                from .delivery_progress import counter
                self._lookup_attempt = counter(self.delivery_runtime.clock())
                lease.target.lookup_uncertain = True
                self._lookup_coverage = 'partial'
            self._publish_lookup_health()

    def lookup_target_progress(self, lease, *, complete, accepted, successful):
        with self._coord:
            if not self.valid(lease) or self.delivery_runtime is None:
                return
            lease.target.lookup_failed = not complete
            lease.target.lookup_uncertain = not (complete and accepted)
            if accepted and successful:
                from .delivery_progress import counter
                self._lookup_success = counter(self.delivery_runtime.clock())
            self._publish_lookup_health()

    def lookup_full_progress(self, complete):
        with self._coord:
            # DHT positive evidence does not certify global network coverage.
            self._lookup_coverage = ('complete' if complete and not any(
                t.lookup_uncertain or str(t.definition.type).upper() == 'DHT'
                for t in self._targets.values()) else 'partial')
            self._publish_lookup_health()

    def configure(self, config, removed=()):
        """Config lock must cover this call and configuration publication.

        Disk replacement is the caller's authoritative commit point. Revoke
        immediately; cleanup failures return sanitized warnings, never claim
        rollback. Call validate_config before persistence to block pending re-adds.
        Retries coordinate with history commits and touch only obsolete names.
        """
        definitions = {domain_storage_name(vars(domain)): deepcopy(domain)
                       for domain in normalized_domain_specs(config.get('domains') or [])}
        providers = deepcopy({key: config.get(key) for key in (
            'servers', 'ens_rpc_url', 'DEFAULT_SNS_PROXY_HOSTS', 'DEFAULT_SOLAR_PROXY_HOSTS',
            'custom_decoders', 'custom_a_decoders')})
        with self._coord:
            return self._configure_state(definitions, providers, removed)

    def _configure_state(self, definitions, providers, removed):
        with state_lock():
            retired = (set(self._targets) - set(definitions)) | set(removed)
            changed_providers = self._providers is not None and self._providers != providers
            changed_targets = set(definitions) != set(self._targets) or any(
                self._targets[name].definition != definition for name, definition in definitions.items()
                if name in self._targets)
            if changed_targets or changed_providers:
                self.generation += 1
            for name, target in self._targets.items():
                if name not in definitions or target.definition != definitions[name] or changed_providers:
                    target.active = False
            self._targets = {
                name: (self._targets[name] if name in self._targets and self._targets[name].active
                       else _Target(definition))
                for name, definition in definitions.items()
            }
            self._providers = providers
            if changed_targets or changed_providers:
                self._lookup_coverage = 'unknown'
            self._publish_lookup_health()
            for name in retired:
                self.current.pop(name, None)
                self.history.pop(name, None)
                self._pending_cleanup.add(name)
            if retired or changed_providers:
                bump_state_version()
            return self.retry_cleanup()

    def validate_config(self, config):
        """Pre-commit check: obsolete files must not be reused by re-adds."""
        names = {domain_storage_name(vars(d))
                 for d in normalized_domain_specs(config.get('domains') or [])}
        with self._coord:
            if names & self._pending_cleanup:
                raise ValueError('history_cleanup_pending')

    def retry_cleanup(self):
        """Retry only revoked names; never unlink replacement state."""
        with self._coord:
            for name in list(self._pending_cleanup):
                if name in self._targets:
                    continue
                try:
                    if self.history_dir:
                        os.unlink(history_file_path(self.history_dir, name))
                except FileNotFoundError:
                    pass
                except OSError:
                    continue
                if self.delivery_runtime is not None and not self.delivery_runtime.store.retire_dht(name):
                    continue
                self._pending_cleanup.discard(name)
            return ['history_cleanup_pending'] if self._pending_cleanup else []

    def capture(self):
        """Called while the configuration owner's lock is held in production."""
        with self._coord, state_lock():
            root_sizes = (len(self.current), len(self.history))
            leases = {
                name: TargetLease(
                    name, target, self.current.setdefault(name, {}),
                    self.history.setdefault(name, {'meta': {}, 'events': [], 'current': {}}),
                )
                for name, target in self._targets.items() if target.active
            }
            if root_sizes != (len(self.current), len(self.history)):
                bump_state_version()
            return leases

    def valid(self, lease):
        # This method never takes _coord: result publication already holds the
        # state lock, and taking locks in reverse order would deadlock purge.
        with state_lock():
            return bool(
                lease is not None and lease.target.active
                and self.current.get(lease.name) is lease.current
                and self.history.get(lease.name) is lease.history
            )

    def observation_candidate(self, lease):
        """Detach source state once; the version remains part of admission CAS."""
        with self._coord, state_lock():
            if not self.valid(lease):
                return None
            return (lease.target.version, deepcopy(lease.current), deepcopy(lease.history),
                    deepcopy(lease.target.failures))

    def begin_dht(self, lease, version, history):
        from .dht_support import checkpoint, restore_checkpoint
        runtime = self.delivery_runtime
        # The scheduler's same-target/single-flight owner has quiesced the prior
        # collector before this entry. Only durable, finalized evidence can be
        # restored; pending tickets and unresolved commits remain fences.
        available, durable = runtime.store.load_dht_checkpoint(lease.name, settled=True)
        if not available:
            return None
        restored = None
        if durable is not None and durable != checkpoint(history):
            try:
                restored = restore_checkpoint(lease.target.definition, durable,
                                              previous=history.get('meta', {}).get('dht_state'))
            except (ValueError, TypeError, KeyError):
                return None
        with runtime.config.lock, self._coord:
            if self.producer_stopping or runtime.stopping or not self.valid(lease) or lease.target.version != version:
                return None
            if restored is not None:
                available, exact = runtime.store.load_dht_checkpoint(lease.name, settled=True)
                if not available or exact != durable:
                    return None
                state, snapshot = restored
                with state_lock():
                    if self.producer_stopping or runtime.stopping:
                        return None
                    lease.history.setdefault('meta', {})['dht_state'] = state
                    if snapshot is not None:
                        lease.current['DHT'] = snapshot.to_dict()
                        lease.history.setdefault('current', {})['DHT'] = snapshot.to_dict()
                    lease.target.version += 1
                    bump_state_version()
                history = lease.history
            return runtime.store.begin_dht(lease.name, checkpoint(history),
                                           lambda: runtime.stopping or self.producer_stopping)

    def accept_observation(self, lease, version, current, history, failures, observation, *, dht_token=None,
                           eligible=None):
        runtime = self.delivery_runtime
        with runtime.config.lock, self._coord:
            with state_lock():
                valid = (not self.producer_stopping and not runtime.stopping
                         and self.valid(lease) and lease.target.version == version
                         and (eligible is None or eligible()))
            if not valid:
                if dht_token is not None and self.lookup_runtime is None:
                    runtime.store.abort_dht(lease.name, dht_token)
                return False
            if dht_token is not None:
                from .dht_support import checkpoint
                if not runtime.store.finish_dht(lease.name, dht_token, checkpoint(history),
                                                lambda: runtime.stopping or self.producer_stopping
                                                or (eligible is not None and not eligible())):
                    if runtime.stopping and self.lookup_runtime is None:
                        runtime.store.abort_dht(lease.name, dht_token)
                    return False
            if observation is not None:
                observation['projection_signature'] = runtime.signature(lease)
                if eligible is not None and not eligible():
                    return False
                admission = {}
                if self.lookup_runtime is not None or eligible is not None:
                    admission['cancelled'] = lambda: runtime.stopping or self.producer_stopping \
                        or (eligible is not None and not eligible())
                result = runtime.store.record_domain(observation, runtime.authority(), runtime.bindings(),
                                                     **admission)
                if result['outcome'] == 'stale':
                    return False
            # The original lease cannot be revoked between admission and publish.
            # SQL and rendering above run WITHOUT state_lock.
            with state_lock():
                if runtime.stopping or self.producer_stopping or (eligible is not None and not eligible()):
                    return False
                lease.current.clear()
                lease.current.update(current)
                lease.history.clear()
                lease.history.update(history)
                lease.target.failures.clear()
                lease.target.failures.update(failures)
                lease.target.version += 1
                bump_state_version()
            if observation is not None:
                from .delivery_progress import counter
                self._lookup_success = counter(runtime.clock())
                self._publish_lookup_health()
            return True

    def admit_force_positive(self, leases, cancel):
        with self._coord, state_lock():
            if not all(self.valid(lease) for lease in leases.values()):
                return False
            cancel()
            return True

    def admit_reconciliation(self, generation, leases, reconcile):
        """Validate the entire configured generation and admit local state only.

        The config owner holds its lock; callers deliver returned intents after
        releasing every lock. Empty scans are generation-fenced too.
        """
        with self._coord, state_lock():
            if (generation != self.generation or set(leases or {}) != set(self._targets)
                    or not all(self.valid(lease) for lease in (leases or {}).values())):
                return False, []
            return True, reconcile()

    def commit_history(self, lease, temporary, destination, *, eligible=None):
        """Final file publication and purge share the same short lock boundary."""
        with self._coord, state_lock():
            if self.producer_stopping or not self.valid(lease) or (eligible is not None and not eligible()):
                return False
            os.replace(temporary, destination)
            return True

    @property
    def producer_stopping(self):
        # A lock-free permanent latch: stop must not wait behind local I/O.
        return self.lookup_runtime is not None and self.lookup_runtime.stopping

    def admit_additions(self, leases, entries, dedupe):
        """Admission/dedupe is atomic with revocation; delivery occurs unlocked."""
        with self._coord, state_lock():
            admitted = [entry for entry in entries if self.valid(leases.get(entry[1]))]
            return dedupe('Added', admitted) if admitted else []
