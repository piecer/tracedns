"""Per-application delivery composition; no provider work in source publication."""
from copy import deepcopy
import hashlib
import hmac
import json
import time

from alerts import render_teams_body, select_alert_configuration
from .delivery_adapters import DestinationRegistry
from .delivery_store import DeliveryStore
from .delivery_worker import DeliveryWorker
from .state_utils import collect_domain_managed_ips
from .targets import providers_for
from .removal_grace import load_legacy_grace


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def render_batch(entries, action, created):
    # Explicit three-argument adapter: created is NOT the renderer's context.
    return render_teams_body(action, entries, {'created': created})


class DeliveryRuntime:
    def __init__(self, config_store, *, history_dir, clock=time.time, limits=None,
                 transport=None, ini_path='config.ini'):
        self.config = config_store
        self.repository = config_store.state_repository
        self.clock = clock
        self.store = DeliveryStore(history_dir, clock=clock, limits=limits, render=render_batch)
        self._transport = transport
        self.registry = None
        self._pending_bindings = None
        self._repair_channels = {}
        self._channel = 0
        self._sighting_progress = {}
        self.stopping = False
        self.history_persistence = 'saved'
        with self.config.lock, self.repository._coord:
            self.selected_alerts = select_alert_configuration(self.config.raw, ini_path)
            self.store.bootstrap(self.projection(), load_legacy_grace(history_dir), self.authority())
            self.repository.delivery_runtime = self
        self._attach_registry()
        from mispupdate_code import run_observation_hook
        self.worker = DeliveryWorker(self.store, claim_admission=self.claim_admission, clock=clock,
                                     observation_hook=run_observation_hook, sightings_step=self.sightings_step)

    def revision(self):
        return self.config.raw.get('_config_revision', self.config.raw.get('config_revision', 0))

    def signature(self, lease):
        cfg = self.config.raw
        definition = vars(lease.target.definition)
        return digest([definition, providers_for(lease.target.definition, cfg.get('servers', []),
                       cfg.get('ens_rpc_url'), cfg.get('DEFAULT_SNS_PROXY_HOSTS',
                       cfg.get('DEFAULT_SOLAR_PROXY_HOSTS', []))),
                       cfg.get('custom_decoders', []), cfg.get('custom_a_decoders', [])])

    def authority(self):
        leases = self.repository.capture()
        return {'valid': not self.stopping, 'revision': self.revision(),
                'signature': digest({name: self.signature(lease) for name, lease in leases.items()})}

    def projection(self):
        cfg = self.config.raw
        result = {}
        for name, lease in self.repository.capture().items():
            domain = lease.target.definition
            providers = providers_for(domain, cfg.get('servers', []), cfg.get('ens_rpc_url'),
                                      cfg.get('DEFAULT_SNS_PROXY_HOSTS', cfg.get('DEFAULT_SOLAR_PROXY_HOSTS', [])))
            result[name] = {'ips': sorted(collect_domain_managed_ips(
                self.repository.current, name, rtype=domain.type, active_servers=providers)),
                'signature': self.signature(lease), 'label': name}
        return result

    def _attach_registry(self):
        with self.config.lock, self.repository._coord:
            key = self.store.binding_key()
            revision = self.revision()
            selected = deepcopy(self.selected_alerts)
        if key is None:
            return
        registry = DestinationRegistry(key, transport=self._transport)
        try:
            registry.apply(selected, revision=revision)
        except Exception:
            registry.apply(selected, revision=revision, applied=False)
        with self.config.lock, self.repository._coord:
            if self.revision() == revision and not self.stopping and self._pending_bindings is None:
                self.registry = registry

    def bindings(self):
        if self._pending_bindings is not None:
            return deepcopy(self._pending_bindings)
        if self.registry is None:
            return []
        return [self.registry.capture(channel, value['binding_id'], 'Added',
                revision=self.revision()).descriptor()
                for channel, value in self.registry.descriptors().items()]

    def configuration_committed(self, candidate, repair_channels=()):
        """Cheap descriptor fencing inside CONFIG -> repository; no adapter I/O."""
        with self.repository._coord:
            self.selected_alerts = deepcopy(candidate['alerts'] if 'alerts' in candidate else self.selected_alerts)
            key = self.store.binding_key()
            pending = []
            if key is not None:
                config = self.selected_alerts if isinstance(self.selected_alerts, dict) else {}
                for channel in ('teams', 'misp'):
                    endpoint = str(config.get('teams_webhook' if channel == 'teams' else 'misp_url') or '')
                    event = str(config.get('push_event_id') or '') if channel == 'misp' else ''
                    raw = json.dumps([channel, endpoint, event], separators=(',', ':')).encode()
                    pending.append({'channel': channel, 'binding_id': hmac.new(key, raw, hashlib.sha256).hexdigest(),
                        'enabled': bool(endpoint), 'ready': False,
                        'allow_removed': channel == 'teams' or str(config.get('misp_remove_on_absent', '')).lower()
                            in ('true', '1', 'yes', 'on'), 'error': 'adapter_unapplied'})
            self._pending_bindings = pending
            self._repair_channels.update({channel: self.revision() for channel in repair_channels})
            refreshed = self.store.refresh_configuration(self.authority(), self.projection())
            return [] if refreshed['ledger_committed'] else ['delivery_configuration_refresh_failed']

    def apply_configuration(self, candidate):
        # ConfigService's writer serializes this phase. No config/state locks
        # while validating local CA files or replacing immutable adapters.
        selected = deepcopy(candidate['alerts'] if 'alerts' in candidate else self.selected_alerts)
        revision = candidate['config_revision']
        warnings = []
        registry = self.registry
        key = self.store.binding_key()
        if registry is None and key is not None:
            registry = DestinationRegistry(key, transport=self._transport)
        if registry is not None:
            try:
                registry.apply(selected, revision=revision)
            except Exception:
                warnings.append('alerts_runtime_apply_failed')
                try:
                    registry.apply(selected, revision=revision, applied=False)
                except Exception:
                    registry = None
        with self.config.lock, self.repository._coord:
            self.selected_alerts = selected
            self.registry = registry
            self._pending_bindings = None if registry is not None or key is None else self._pending_bindings
            applied = self.store.configuration_applied(self._repair_channels, apply_epochs=self._repair_channels)
            if applied['ledger_committed']:
                self._repair_channels = {}
            elif self._repair_channels:
                warnings.append('delivery_configuration_apply_failed')
        self.worker.wake()
        return warnings

    @staticmethod
    def apply_local_settings(alerts):
        from vt_lookup import set_api_key, set_cache_ttl_days
        warnings = []
        for setter, value, code in (
            (set_api_key, alerts.get('vt_api_key', ''), 'vt_api_key_apply_failed'),
            (set_cache_ttl_days, alerts.get('vt_cache_ttl_days', 1), 'vt_cache_ttl_apply_failed'),
        ):
            try:
                setter(value)
            except Exception:
                warnings.append(code)
        return warnings

    def claim_admission(self, now):
        with self.config.lock:
            if self.stopping:
                return None
            if self._pending_bindings is not None:
                for descriptor in self._pending_bindings:
                    self.store.claim_next(descriptor, now)
                return None
            if self.registry is None:
                return None
            descriptors = self.registry.descriptors()
            channels = ('teams', 'misp')
            first = self._channel
            self._channel = (first + 1) % 2
            for channel in (channels[first], channels[1 - first]):
                descriptor = descriptors[channel]
                adapter = self.registry.capture(channel, descriptor['binding_id'], 'Added', revision=self.revision())
                claim = self.store.claim_next(adapter.descriptor(), now)
                if claim:
                    adapter = self.registry.capture(channel, claim['binding_id'], claim['action'], revision=self.revision())
                    return claim, adapter
            return None

    def sightings_step(self):
        from mispupdate_code import flush_sightings_step
        from .delivery_types import provider_result
        with self.config.lock:
            if self.stopping or self.registry is None or self._pending_bindings is not None:
                self._sighting_progress = {}
                return {'provider_calls': 0, 'has_more': False}
            descriptor = self.registry.descriptors()['misp']
            adapter = self.registry.capture('misp', descriptor['binding_id'], 'Added', revision=self.revision())
            if self._sighting_progress.get('binding_id') != adapter.binding_id:
                self._sighting_progress = {}
            if not adapter.ready:
                self._sighting_progress = {}
                return {'provider_calls': 0, 'has_more': False}
            progress = deepcopy(self._sighting_progress)
        # Exactly one immutable outbound admission; no config/SQL/state lock.
        outcome = provider_result(flush_sightings_step(adapter, progress))
        self._sighting_progress = deepcopy(outcome['progress']) if outcome['state'] == 'continue' else {}
        return {'provider_calls': outcome['provider_calls'],
                'has_more': outcome['provider_calls'] == 1 and outcome['state'] not in ('blocked', 'failed')}

    def complete(self, snapshot, current):
        active = {ip: sorted(labels) for ip, labels in current.items()}
        with self.config.lock, self.repository._coord:
            leases = snapshot.target_leases or {}
            if snapshot.force_req is not None:
                leases = snapshot.force_req.get('_target_leases', {})
                valid = (snapshot.force_req.get('_terminal_outcome') != 'failure'
                         and '_target_leases' in snapshot.force_req
                         and all(self.repository.valid(lease) for lease in leases.values()))
                if valid:
                    self.store.cancel_force_positive(self.authority(), getattr(current, 'positive', {}))
            else:
                valid = (snapshot.generation == self.repository.generation
                         and set(leases) == set(self.repository.capture())
                         and all(self.repository.valid(lease) for lease in leases.values()))
                if valid and getattr(current, 'complete', True):
                    if self.store.health_snapshot()['coverage'] != 'covered':
                        self.store.recover_gap(self.authority(), self.projection(), {
                            'active_map': active, 'completed_at': self.clock(), 'bindings': self.bindings()})
                    else:
                        self.store.reconcile_full(self.authority(), active, self.clock(), self.bindings())
                elif valid:
                    # Errors cannot establish new absence, but actual positive
                    # evidence remains safe for cancellation under the full gate.
                    self.store.cancel_force_positive(self.authority(), getattr(current, 'positive', {}))
            self.store.seal_cycle(None)
        if self.registry is None and self._pending_bindings is None:
            self._attach_registry()
        wake = False
        with self.config.lock, self.repository._coord:
            if (self._repair_channels and self._pending_bindings is None and self.registry is not None
                    and self.registry.revision == self.revision() and not self.stopping
                    and self.store.health_snapshot()['coverage'] == 'covered'):
                applied = self.store.configuration_applied(self._repair_channels, apply_epochs=self._repair_channels)
                if applied['ledger_committed']:
                    self._repair_channels = {}
                    wake = True
        if wake:
            self.worker.wake()
        return valid

    def note_history_failure(self):
        self.store.note_history_failure()

    def stop(self, *, join_seconds=3.0):
        with self.config.lock, self.repository._coord:
            self.stopping = True
        self.store.seal_cycle(None)
        result = self.worker.stop(join_seconds=join_seconds)
        if result['stopped']:
            result['closed'] = self.store.close(clean=True)
        else:
            result['closed'] = False
        return result
