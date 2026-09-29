"""One serialized writer for persistent configuration and decoder publication.

Atomic file replace is the commit point. Optional effects are ordered by the
writer mutex, but execute outside the configuration/state/registry locks.
"""
from contextlib import nullcontext
from copy import deepcopy
import re
import threading

import config_manager
import decoder_registry

_creation_lock = threading.Lock()


class ConfigError(ValueError):
    def __init__(self, message, status=400, **details):
        super().__init__(message)
        self.status = status
        self.payload = {'error': message, 'status': 'error', **details}


def persistent(config):
    return deepcopy({k: v for k, v in config.items() if not k.startswith('_')})


def prepare_decoders(candidate):
    import txt_decoder
    import a_decoder
    from http_api.decoder_crud import _validate_steps

    live = decoder_registry.snapshot_registry()
    maps = []
    for key, kind, source, builtin, factory in (
        ('custom_decoders', 'TXT', live.txt, txt_decoder._BUILTIN_DECODE_METHODS, txt_decoder.create_custom_decoder),
        ('custom_a_decoders', 'A', live.a, a_decoder._BUILTIN_A_DECODE_METHODS, a_decoder.create_custom_a_decoder),
    ):
        result = {name: source[name] for name in builtin}
        definitions = candidate.get(key, [])
        if not isinstance(definitions, list):
            raise ConfigError(f'{key} must be a list')
        for definition in definitions:
            if not isinstance(definition, dict):
                raise ConfigError('decoder definition must be an object')
            name = definition.get('name')
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_\-]+', name):
                raise ConfigError('invalid decoder name')
            if name in result:
                raise ConfigError('decoder name conflict')
            if str(definition.get('decoder_type', kind)).upper() != kind:
                raise ConfigError('decoder_type does not match collection')
            steps = deepcopy(definition.get('steps'))
            valid, error = _validate_steps(steps, kind)
            if not valid:
                raise ConfigError(error)
            try:
                decoder = factory(steps)
            except Exception:
                raise ConfigError('invalid decoder steps') from None
            if decoder is None:
                raise ConfigError('invalid decoder steps')
            result[name] = decoder
        maps.append(result)
    return decoder_registry.RegistryView(*maps)


def catalog(config, view):
    from ens_decoder import ENS_DECODE_METHODS
    txt = deepcopy(config.get('custom_decoders', []))
    a = deepcopy(config.get('custom_a_decoders', []))
    return {
        'revision': config.get('config_revision', 0),
        'decoders': sorted(view.txt), 'a_decoders': sorted(view.a),
        'ens_decoders': sorted(ENS_DECODE_METHODS), 'custom': txt, 'custom_a': a,
        'custom_all': [{**d, 'decoder_type': 'TXT'} for d in txt] + [{**d, 'decoder_type': 'A'} for d in a],
    }


class ConfigService:
    def __init__(self, shared_config, config_lock, config_path, *, state_repository=None,
                 read_model=None, purge_removed_domains_state=None, current_results=None,
                 history=None, history_dir=''):
        self.shared_config = shared_config
        self.config_lock = config_lock if config_lock is not None else threading.RLock()
        self.config_path = config_path
        self.state_repository = state_repository
        self.read_model = read_model
        self.purge = purge_removed_domains_state
        self.current_results = current_results
        self.history = history
        self.history_dir = history_dir
        self._writer = threading.Lock()
        self.delivery_runtime = None

    def snapshot(self):
        with self.config_lock:
            config = persistent(self.shared_config)
            config['config_revision'] = self.shared_config.get('_config_revision', config.get('config_revision', 0))
            return config

    def catalog(self):
        with self.config_lock:
            config = persistent(self.shared_config)
            config['config_revision'] = self.shared_config.get('_config_revision', config.get('config_revision', 0))
            return catalog(config, decoder_registry.snapshot_registry())

    def initialize_decoders(self):
        with self._writer, self.config_lock:
            decoder_registry.publish(prepare_decoders(persistent(self.shared_config)))

    def _decoder_candidate(self, candidate, command, data):
        kind = str(data.get('decoder_type', 'TXT')).upper()
        if kind not in ('TXT', 'A'):
            raise ConfigError('decoder_type must be TXT or A')
        key = 'custom_decoders' if kind == 'TXT' else 'custom_a_decoders'
        name = data.get('name')
        if not isinstance(name, str) or not name:
            raise ConfigError('name required')
        definitions = candidate.get(key, [])
        exists = any(d.get('name') == name for d in definitions)
        if command == 'decoder_create' and exists:
            raise ConfigError('decoder name conflict')
        if command == 'decoder_delete' and not exists:
            raise ConfigError('not removed (builtin or not found)')
        candidate[key] = [d for d in definitions if d.get('name') != name]
        if command != 'decoder_delete':
            candidate[key].append({'name': name, 'steps': deepcopy(data.get('steps')), 'decoder_type': kind})

    def _config_candidate(self, candidate, data):
        from datetime import datetime, timezone
        from monitor.runtime_state import state_lock
        cm = config_manager
        removed = []
        if 'domains' in data:
            prev = cm.normalize_domains(candidate.get('domains', []))
            normalized = cm.normalize_domains(deepcopy(data['domains']))
            identities = {cm.domain_identity(d) for d in normalized}
            storage = {cm.domain_storage_name(d).rstrip('.').lower() for d in normalized}
            removed = {cm.domain_storage_name(d) for d in prev if cm.domain_identity(d) not in identities}
            with state_lock():
                keys = set(self.current_results or {}) | set(self.history or {})
            removed.update(str(k) for k in keys if k and str(k).rstrip('.').lower() not in storage)
            previous = {cm.domain_identity(d): d for d in prev}
            prior_metadata = candidate.get('domain_metadata') or {}
            now = datetime.now(timezone.utc).isoformat()
            metadata = {}
            for domain in normalized:
                identity = cm.domain_identity(domain)
                old = previous.get(identity)
                dates = dict(prior_metadata.get(identity) or {}) if old is not None else {}
                if old is None:
                    dates = {'created_at': now, 'updated_at': now}
                elif old != domain:
                    dates['updated_at'] = now
                metadata[identity] = dates
            candidate['domain_metadata'] = metadata
            candidate['domains'] = normalized
        if 'servers' in data:
            if not isinstance(data['servers'], list):
                raise ConfigError('servers must be a list')
            servers = [str(s).strip() for s in data['servers'] if str(s or '').strip()]
            if len(servers) > 64:
                raise ConfigError('servers must contain at most 64 entries')
            candidate['servers'] = servers
        for key, maximum in (('interval', 86400), ('max_workers', 64)):
            if key in data:
                value = data[key]
                if type(value) is not int or not 1 <= value <= maximum:
                    raise ConfigError(f'{key} must be an integer between 1 and {maximum}')
                candidate[key] = value
        if 'ens_rpc_url' in data and str(data['ens_rpc_url'] or '').strip():
            candidate['ens_rpc_url'] = str(data['ens_rpc_url']).strip()
        if 'DEFAULT_SNS_PROXY_HOSTS' in data:
            hosts = data['DEFAULT_SNS_PROXY_HOSTS']
            if not isinstance(hosts, list):
                raise ConfigError('DEFAULT_SNS_PROXY_HOSTS must be a list')
            if hosts:
                candidate['DEFAULT_SNS_PROXY_HOSTS'] = [str(h).strip() for h in hosts if str(h or '').strip()]
        for key in data.get('clear_fields', []):
            if key == 'ens_rpc_url':
                candidate.pop(key, None)
            elif key == 'DEFAULT_SNS_PROXY_HOSTS':
                candidate[key] = []
        for key in ('custom_decoders', 'custom_a_decoders'):
            if key in data:
                candidate[key] = deepcopy(data[key])
        return sorted(removed)

    def _settings_candidate(self, candidate, data):
        from http_api.settings_handlers import SECRET_FIELDS, get_cache_ttl_days
        alerts = data.get('alerts')
        if not isinstance(alerts, dict):
            raise ConfigError('alerts object required')
        alerts = deepcopy(alerts)
        alerts.pop('configured', None)
        vt = alerts.get('vt_api_key')
        if vt is not None and str(vt).strip():
            vt = str(vt).strip()
            if re.search(r'\s', vt) or not 20 <= len(vt) <= 128:
                raise ConfigError('invalid vt_api_key (bad format or length)')
            if not re.fullmatch(r'[A-Za-z0-9\-_=]+', vt):
                raise ConfigError('invalid vt_api_key (unexpected characters)')
            alerts['vt_api_key'] = vt
        ttl = alerts.get('vt_cache_ttl_days')
        try:
            ttl = get_cache_ttl_days() if ttl in (None, '') else int(str(ttl).strip())
            if not 1 <= ttl <= 3650:
                raise ValueError()
        except (ValueError, TypeError):
            raise ConfigError('vt_cache_ttl_days must be between 1 and 3650') from None
        if 'vt_cache_ttl_days' in alerts:
            alerts['vt_cache_ttl_days'] = ttl
        if 'misp_remove_on_absent' in alerts:
            raw = alerts['misp_remove_on_absent']
            alerts['misp_remove_on_absent'] = raw if isinstance(raw, bool) else str(raw).strip().lower() in ('1', 'true', 'yes', 'on', 'y')
        if 'misp_ca_bundle' in alerts:
            from monitor.delivery_adapters import validated_tls_verify
            try:
                validated_tls_verify(alerts['misp_ca_bundle'])
            except ValueError:
                raise ConfigError('invalid MISP CA bundle') from None
        merged = dict(candidate.get('alerts') or (self.delivery_runtime.selected_alerts
                      if self.delivery_runtime is not None else {}))
        previous = dict(merged)
        merged.update({k: v for k, v in alerts.items() if k not in SECRET_FIELDS or str(v or '').strip()})
        cleared = set(data.get('clear_fields', []))
        for key in cleared:
            merged.pop(key, None)
        merged.setdefault('vt_cache_ttl_days', get_cache_ttl_days())
        candidate['alerts'] = merged
        # Redacted normal forms submit blank secrets to preserve them. Only an
        # explicit nonblank reapply (even the same credential) is repair intent.
        # Decide before publication, after clear precedence, against the same
        # selected configuration used by the merge, including INI provenance.
        reapplied = {key for key, value in alerts.items() if key in SECRET_FIELDS
                     and key not in cleared and str(value or '').strip()}

        def effective(config, key):
            # Match DestinationRegistry's values, not raw JSON types or field
            # presence. Do not trim endpoints/event IDs: binding uses exact text.
            if key == 'misp_remove_on_absent':
                return str(config.get(key, '')).lower() in ('true', '1', 'yes', 'on')
            return str(config.get(key) or '')

        return tuple(channel for channel, keys in (
            ('teams', {'teams_webhook'}),
            ('misp', {'misp_url', 'api_key', 'push_event_id', 'misp_ca_bundle', 'misp_remove_on_absent'}),
        ) if reapplied & keys or any(effective(previous, key) != effective(merged, key) for key in keys))

    def commit(self, command, data, *, expected_revision):
        with self._writer:
            with self.config_lock:
                revision = self.shared_config.get('_config_revision', self.shared_config.get('config_revision', 0))
                if type(expected_revision) is not int or expected_revision != revision:
                    raise ConfigError('config revision conflict', 409, revision=revision)
                candidate = persistent(self.shared_config)
                removed = []
                repair_channels = ()
                if command == 'config':
                    removed = self._config_candidate(candidate, data)
                elif command == 'settings':
                    repair_channels = self._settings_candidate(candidate, data)
                else:
                    self._decoder_candidate(candidate, command, data)
                view = prepare_decoders(candidate)
                for key, field in (('custom_decoders', 'txt_decode'), ('custom_a_decoders', 'a_decode')):
                    old_names = {d['name'] for d in self.shared_config.get(key, [])}
                    new_names = {d['name'] for d in candidate.get(key, [])}
                    deleted = old_names - new_names
                    if any(d.get(field) in deleted for d in config_manager.normalize_domains(candidate.get('domains', []))):
                        raise ConfigError('decoder is referenced by a configured target')
                candidate['config_revision'] = revision + 1
                validate = getattr(self.state_repository, 'validate_config', None)
                if validate is not None:
                    try:
                        validate(candidate)
                    except ValueError:
                        raise ConfigError('target history cleanup pending') from None
                if self.config_path:
                    try:
                        config_manager.write_config(self.config_path, candidate)
                    except Exception:
                        raise ConfigError('config save failed', 500, code='config_save_failed') from None
                warnings = []
                if self.read_model is not None:
                    self.read_model.invalidate(hard=True)
                if self.state_repository is not None:
                    warnings.extend(self.state_repository.configure(candidate, removed) or [])
                elif removed and callable(self.purge):
                    try:
                        self.purge(self.current_results, self.history, self.history_dir, removed)
                    except OSError:
                        warnings.append('history_cleanup_pending')
                private = {k: v for k, v in self.shared_config.items() if k.startswith('_')}
                self.shared_config.clear()
                self.shared_config.update(candidate)
                self.shared_config.update(private)
                self.shared_config['_config_revision'] = revision + 1
                if self.delivery_runtime is not None:
                    warnings.extend(self.delivery_runtime.configuration_committed(candidate, repair_channels))
                decoder_registry.publish(view)
                condition = self.shared_config.get('_monitor_condition')
                if condition is not None:
                    condition.notify_all()
                if self.read_model is not None:
                    self.read_model.invalidate(hard=True)
                result = {'status': 'ok', 'revision': revision + 1,
                          'catalog': catalog(candidate, view), 'config': deepcopy(candidate), 'warnings': warnings}
            if self.delivery_runtime is not None:
                result['warnings'].extend(self.delivery_runtime.apply_configuration(candidate))
            if command == 'settings':
                result['alerts'] = deepcopy(candidate['alerts'])
                if self.delivery_runtime is None:
                    from http_api.settings_handlers import apply_runtime_settings
                    result['warnings'].extend(apply_runtime_settings(deepcopy(candidate['alerts'])))
                else:
                    result['warnings'].extend(self.delivery_runtime.apply_local_settings(candidate['alerts']))
            return result


def get_config_service(ctx):
    """Explicit app injection preferred; legacy helper contexts share one writer."""
    with _creation_lock, (ctx.config_lock if ctx.config_lock is not None else nullcontext()):
        service = ctx.shared_config.get('_config_service')
        supplied = getattr(ctx, 'config_service', None)
        if service is not None and supplied is not None and service is not supplied:
            raise ValueError('conflicting configuration service for application')
        service = service or supplied
        if service is None:
            service = ConfigService(ctx.shared_config, ctx.config_lock, ctx.config_path,
                **{key: getattr(ctx, key, None) for key in (
                    'state_repository', 'read_model', 'purge_removed_domains_state',
                    'current_results', 'history', 'history_dir')})
        # HTTP bootstrap can attach its read model to the app's earlier owner.
        for key in ('state_repository', 'read_model'):
            value = getattr(ctx, key, None)
            if value is not None:
                setattr(service, key, value)
        ctx.shared_config['_config_service'] = service
        ctx.config_service = service
        return service


def commit_request(ctx, handler, command, data):
    """Keep the historical no-principal direct-helper exemption at HTTP boundary."""
    from http_api.utils import send_json
    service = get_config_service(ctx)
    expected = data.get('revision')
    if getattr(handler, 'principal', None) is None:
        expected = service.snapshot()['config_revision']
    try:
        return service.commit(command, data, expected_revision=expected)
    except ConfigError as exc:
        send_json(handler, exc.payload, exc.status)
        return None
