"""Private immutable outbound authority; public descriptors contain no secrets.

Capture under the committed configuration lock *before* persisting a claim.
Never persist adapters, their repr, or provider response objects.
"""
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import ipaddress
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit, unquote
import threading

import requests

from monitor.delivery_types import encode_body

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def result(state, reason=None, *, progress=None, calls=0, retry_after=None, hook=None):
    return {'state': state, 'reason': reason, 'progress': progress or {},
            'retry_after': retry_after, 'provider_calls': calls, 'observation_hook': hook}


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('provider_protocol')
            value[key] = item
        return value

    def reject_constant(_):
        raise ValueError('provider_protocol')

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, TypeError, RecursionError):
        raise ValueError('provider_protocol') from None


class _NoRedirectSession(requests.Session):
    def resolve_redirects(self, *args, **kwargs):
        # Even allow_redirects=False ordinarily drains 3xx bodies to build
        # Response.next. That defeats a streaming byte cap before we see it.
        return iter(())


class RequestsTransport:
    """One Session per operation: no ambient credentials, retries or redirects."""
    def request(self, method, url, **kwargs):
        # Response owns a live stream; Session.close does not consume it.
        with _NoRedirectSession() as session:
            session.trust_env = False
            session.mount('https://', requests.adapters.HTTPAdapter(max_retries=0))
            return session.request(method, url, **kwargs)


def provider_request(transport, method, endpoint, *, body=None, key='', verify=True):
    response = None
    try:
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        if key:
            headers['Authorization'] = key
        response = (transport or RequestsTransport()).request(
            method, endpoint, data=encode_body(body) if body is not None else None,
            headers=headers, timeout=(3, 10), allow_redirects=False, stream=True, verify=verify)
        status = response.status_code
        if type(status) is not int:
            return result('retry', 'provider_protocol', calls=1), None
        retry_after = None
        try:
            retry_after = max(30, min(3600, int(response.headers.get('Retry-After', ''))))
        except (TypeError, ValueError):
            pass
        if status in (401, 403):
            return result('blocked', 'provider_auth', calls=1), None
        if status == 429 or 500 <= status <= 599:
            return result('retry', 'provider_transient', calls=1, retry_after=retry_after), None
        if not 200 <= status <= 299:
            return result('failed', 'provider_http', calls=1), None
        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            if len(chunks) + len(chunk) > MAX_RESPONSE_BYTES:
                return result('failed', 'response_limit', calls=1), None
            chunks.extend(chunk)
        length = response.headers.get('Content-Length')
        if length is not None and not response.headers.get('Content-Encoding'):
            if not str(length).isdigit() or int(length) != len(chunks):
                return result('retry', 'provider_protocol', calls=1), None
        return None, bytes(chunks)
    except requests.exceptions.SSLError:
        return result('blocked', 'tls_error', calls=1), None
    except Exception:
        return result('retry', 'transport_error', calls=1), None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass  # response is already classified; never leak cleanup errors


def validated_tls_verify(ca_bundle=None):
    """Return True or an explicit parseable CA file; never False or a directory.

    Same returned value is accepted by requests.verify and PyMISP.ssl.
    The operator owns this file and must replace it only through config apply.
    """
    if ca_bundle is None or ca_bundle == '':
        return True
    try:
        if not isinstance(ca_bundle, str):
            raise ValueError
        path = Path(ca_bundle)
        if not path.is_absolute() or not path.is_file() or path.stat().st_size > MAX_RESPONSE_BYTES:
            raise ValueError
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=ca_bundle)
        if not context.get_ca_certs():
            raise ValueError
        return ca_bundle
    except Exception:
        raise ValueError('tls_config') from None


def valid_endpoint(endpoint, channel):
    try:
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.hostname.lower() == 'x'
                or parsed.username or parsed.password or parsed.fragment
                or any(ord(c) <= 32 for c in endpoint) or '\\' in endpoint):
            return False
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        if channel == 'misp' and (parsed.query or any(
                p in ('.', '..') for p in unquote(parsed.path).split('/'))):
            return False
        return True
    except ValueError:
        return False


def valid_id(value):
    return type(value) in (str, int) and re.fullmatch(r'[1-9][0-9]{0,19}', str(value)) is not None


def valid_attribute(attribute, event_id):
    if isinstance(attribute, dict) and attribute.get('type') == 'ip-src':
        try:
            ip = attribute.get('value')
            if not isinstance(ip, str) or '%' in ip:
                return False
            ipaddress.ip_address(ip)
        except ValueError:
            return False
    return (isinstance(attribute, dict) and valid_id(attribute.get('id'))
            and str(attribute.get('event_id')) == event_id
            and isinstance(attribute.get('type'), str)
            and isinstance(attribute.get('value'), str)
            and attribute.get('deleted', False) in (False, 0, '0'))


def event_attributes(envelope, event_id):
    """Reject incomplete/unsupported event projections, never infer absence."""
    if not isinstance(envelope, dict) or 'errors' in envelope or 'error' in envelope:
        raise ValueError('provider_protocol')
    event = envelope.get('Event')
    if not isinstance(event, dict) or str(event.get('id')) != event_id:
        raise ValueError('provider_protocol')
    attributes = event.get('Attribute')
    if not isinstance(attributes, list):
        raise ValueError('provider_protocol')
    if event.get('truncated') or envelope.get('truncated'):
        raise ValueError('provider_protocol')
    objects = event.get('Object', [])
    if not isinstance(objects, list):
        raise ValueError('provider_protocol')
    if len(attributes) > 2000 or len(objects) > 2000:
        raise ValueError('attribute_limit')
    attributes = list(attributes)
    for obj in objects:
        if (not isinstance(obj, dict) or not valid_id(obj.get('id'))
                or str(obj.get('event_id')) != event_id or obj.get('truncated')
                or not isinstance(obj.get('Attribute'), list)):
            raise ValueError('provider_protocol')
        if len(attributes) + len(obj['Attribute']) > 2000:
            raise ValueError('attribute_limit')
        attributes.extend(obj['Attribute'])
    if 'attribute_count' in event and str(event['attribute_count']) != str(len(attributes)):
        raise ValueError('provider_protocol')
    if any(not valid_attribute(a, event_id) for a in attributes):
        raise ValueError('provider_protocol')
    if len({str(a['id']) for a in attributes}) != len(attributes):
        raise ValueError('provider_protocol')
    return attributes


def validated_add(envelope, event_id, ip):
    if not isinstance(envelope, dict) or 'errors' in envelope or 'error' in envelope:
        return False
    attribute = envelope.get('Attribute')
    return (valid_attribute(attribute, event_id) and attribute['type'] == 'ip-src'
            and attribute['value'] == ip)


def validated_delete(envelope):
    return (isinstance(envelope, dict) and 'errors' not in envelope and 'error' not in envelope
            and envelope.get('success') is True
            and envelope.get('saved', True) is True)


def valid_claim(claim, channel):
    keys = {'claim_id', 'attempt_token', 'channel', 'binding_id', 'action', 'attempt',
            'provider_calls', 'progress', 'payload', 'observation_hook_consumed'}
    if not isinstance(claim, dict) or set(claim) != keys:
        return False
    if (claim['channel'] != channel or claim['action'] not in ('Added', 'Removed')
            or type(claim['attempt']) is not int or not 1 <= claim['attempt'] <= 8
            or type(claim['provider_calls']) is not int or claim['provider_calls'] < 0
            or type(claim['observation_hook_consumed']) is not bool
            or not all(isinstance(claim[k], str) and 0 < len(claim[k]) <= 256
                       for k in ('claim_id', 'attempt_token', 'binding_id'))):
        return False
    progress = claim['progress']
    if not isinstance(progress, dict):
        return False
    if progress:
        phase = progress.get('phase')
        if phase not in ('read', 'add', 'delete'):
            return False
        expected = {'phase', 'attribute_id'} if phase == 'delete' else {'phase'}
        if set(progress) != expected:
            return False
    payload = claim['payload']
    if not isinstance(payload, dict):
        return False
    entries = payload.get('entries')
    if not isinstance(entries, (list, tuple)) or not entries:
        return False
    # Count limits are checked separately so their stable resource reason wins.
    if len(entries) > 60:
        return channel == 'teams'
    for entry in entries:
        if (not isinstance(entry, (list, tuple)) or len(entry) != 3
                or not all(isinstance(v, str) for v in entry)):
            return False
        ip, label, source = entry
        try:
            address = ipaddress.ip_address(ip)
            if ('%' in ip or address.is_loopback or address.is_unspecified
                    or len(label.encode()) > 1024 or source not in ('TXT', 'A', 'ENS', 'SNS')):
                return False
        except ValueError:
            return False
    return True


@dataclass(frozen=True)
class BoundDestinationAdapter:
    channel: str
    binding_id: str
    enabled: bool = False
    ready: bool = False
    allow_removed: bool = False
    error: str | None = None
    _endpoint: str = field(default='', repr=False)
    _key: str = field(default='', repr=False)
    _event: str = field(default='', repr=False)
    _verify: object = field(default=True, repr=False)
    _transport: object = field(default=None, repr=False, compare=False)

    def execute_step(self, claim):
        if not valid_claim(claim, self.channel):
            return result('failed', 'payload_invalid')
        if self.error:
            return result('blocked', self.error)
        if claim.get('binding_id') != self.binding_id:
            return result('blocked', 'old_binding_blocked')
        if claim.get('action') == 'Removed' and not self.allow_removed:
            return result('blocked', 'removal_disabled')
        # Includes this call's already-durable reservation, not just completed
        # calls. The store refuses to reserve a new call at previous >=4096.
        if claim.get('provider_calls', 0) > 4096:
            return result('failed', 'provider_work_limit')
        if self.channel == 'misp':
            return self._misp_step(claim)
        try:
            body = claim['payload']['body']
            if (not isinstance(body, dict) or set(body) != {'title', 'text'} or
                    not all(isinstance(v, str) for v in body.values())):
                return result('failed', 'payload_invalid')
            if len(encode_body(body)) > 24 * 1024 or len(claim['payload']['entries']) > 60:
                return result('failed', 'payload_limit')
        except (KeyError, TypeError, ValueError):
            return result('failed', 'payload_invalid')
        error, _ = provider_request(self._transport, 'POST', self._endpoint,
                                    body=body, verify=self._verify)
        return error or result('acked', calls=1)

    def _misp_step(self, claim):
        try:
            entries = claim['payload']['entries']
            if len(entries) != 1 or len(entries[0]) != 3:
                raise ValueError
            ip, label, source_type = entries[0]
            address = ipaddress.ip_address(ip)
            if address.is_loopback or address.is_unspecified or not isinstance(label, str):
                raise ValueError
            if len(label.encode()) > 1024 or source_type not in ('TXT', 'A', 'ENS', 'SNS'):
                raise ValueError
            progress = claim['progress']
            phase = progress.get('phase', 'read')
            if phase not in ('read', 'add', 'delete'):
                raise ValueError
            if phase == 'delete' and (claim['action'] != 'Removed' or
                                      not valid_id(progress.get('attribute_id'))):
                raise ValueError
            if phase == 'add' and claim['action'] != 'Added':
                raise ValueError
        except (KeyError, TypeError, ValueError):
            return result('failed', 'payload_invalid')
        body = None
        method = 'GET'
        path = f'events/view/{self._event}'
        if phase == 'add':
            method, path = 'POST', f'attributes/add/{self._event}'
            prefix = 'NST-2-1' if source_type == 'A' else 'NST-2-2'
            body = {'type': 'ip-src', 'value': ip, 'comment': f'{prefix} {label}'}
        elif phase == 'delete':
            method, path = 'POST', f"attributes/delete/{progress['attribute_id']}"
            body = {}
        error, raw = provider_request(self._transport, method, self._endpoint.rstrip('/') + '/' + path,
                                      body=body, key=self._key, verify=self._verify)
        if error:
            return error  # retries deliberately reset to authoritative read
        try:
            envelope = strict_json(raw)
        except (ValueError, TypeError, UnicodeError):
            return result('retry', 'provider_protocol', calls=1)
        if phase == 'add':
            if validated_add(envelope, self._event, ip):
                return result('acked', calls=1)
            return result('retry', 'provider_protocol', calls=1)
        if phase == 'delete':
            if validated_delete(envelope):
                return result('continue', progress={'phase': 'read'}, calls=1)
            return result('retry', 'provider_protocol', calls=1)
        try:
            attributes = event_attributes(envelope, self._event)
        except ValueError as error:
            reason = str(error)
            return result('failed' if reason == 'attribute_limit' else 'retry', reason, calls=1)
        matches = [a for a in attributes if a['type'] == 'ip-src' and a['value'] == ip]
        if claim['action'] == 'Removed':
            if matches:
                return result('continue', calls=1, progress={
                    'phase': 'delete', 'attribute_id': str(matches[0]['id'])})
            return result('acked', calls=1, hook={
                'kind': 'remove_queued_sightings', 'event_id': self._event, 'ip': ip})
        if not matches:
            return result('continue', calls=1, progress={'phase': 'add'})
        hook = None
        if claim['attempt'] == 1 and not claim['observation_hook_consumed']:
            hook = {'kind': 'enqueue_sightings', 'event_id': self._event, 'ip': ip}
        return result('acked', calls=1, hook=hook)

    def sighting_step(self, ip, progress=None):
        """Separate best-effort work; never invoked by execute_step retries."""
        if self.error or self.channel != 'misp':
            return result('blocked', self.error or 'destination_invalid')
        progress = progress or {}
        try:
            ipaddress.ip_address(ip)
            if progress and (set(progress) != {'phase', 'ip', 'attribute_id', 'binding_id'}
                             or progress['phase'] != 'sighting' or progress['ip'] != ip
                             or progress['binding_id'] != self.binding_id
                             or not valid_id(progress['attribute_id'])):
                raise ValueError
        except (ValueError, TypeError):
            return result('failed', 'payload_invalid')
        path = f'events/view/{self._event}'
        body = None
        method = 'GET'
        if progress:
            method, path = 'POST', f"sightings/add/{progress['attribute_id']}"
            body = {'event_id': self._event, 'value': ip, 'type': '0'}
        error, raw = provider_request(self._transport, method, self._endpoint.rstrip('/') + '/' + path,
                                      body=body, key=self._key, verify=self._verify)
        if error:
            return error
        try:
            envelope = strict_json(raw)
            if not progress:
                attributes = event_attributes(envelope, self._event)
                match = next((a for a in attributes if a['type'] == 'ip-src' and a['value'] == ip), None)
                if not match:
                    return result('failed', 'sighting_absent', calls=1)
                return result('continue', calls=1, progress={'phase': 'sighting', 'ip': ip,
                    'attribute_id': str(match['id']), 'binding_id': self.binding_id})
            sighting = envelope.get('Sighting')
            if (not isinstance(sighting, dict) or 'errors' in envelope or 'error' in envelope
                    or not valid_id(sighting.get('id'))
                    or str(sighting.get('event_id')) != self._event
                    or str(sighting.get('attribute_id')) != str(progress['attribute_id'])
                    or str(sighting.get('type')) != '0'):
                raise ValueError
            return result('acked', calls=1)
        except (ValueError, TypeError, AttributeError):
            return result('retry', 'provider_protocol', calls=1)

    def descriptor(self):
        return {k: getattr(self, k) for k in (
            'channel', 'binding_id', 'enabled', 'ready', 'allow_removed', 'error')}


class DestinationRegistry:
    """A replacement registry, not a cache of retired credentials.

    The caller supplies the ledger-owned persistent private fingerprint key.
    Config ownership must encompass apply/capture and durable claim admission.
    """
    def __init__(self, fingerprint_key, *, transport=None):
        if not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32:
            raise ValueError('invalid_binding_key')
        self._key = fingerprint_key
        self._transport = transport
        self._lock = threading.RLock()
        self.apply({}, revision=None)

    def _binding(self, channel, endpoint, event):
        raw = json.dumps([channel, endpoint, event], separators=(',', ':')).encode()
        return hmac.new(self._key, raw, hashlib.sha256).hexdigest()

    def apply(self, config, *, revision, applied=True):
        if not isinstance(config, dict):
            config, applied = {}, False
        snapshots = {}
        for channel in ('teams', 'misp'):
            endpoint = str(config.get('teams_webhook' if channel == 'teams' else 'misp_url') or '')
            event = str(config.get('push_event_id') or '') if channel == 'misp' else ''
            key = str(config.get('api_key') or '') if channel == 'misp' else ''
            enabled = bool(endpoint)
            error = None
            verify = True
            if not enabled:
                error = 'destination_disabled'
            elif not applied:
                error = 'adapter_unapplied'
            elif (not valid_endpoint(endpoint, channel) or
                  (channel == 'misp' and (not key or not valid_id(event)))):
                error = 'destination_invalid'
            elif channel == 'misp':
                try:
                    verify = validated_tls_verify(config.get('misp_ca_bundle'))
                except ValueError:
                    error = 'tls_config'
            snapshots[channel] = BoundDestinationAdapter(
                channel, self._binding(channel, endpoint, event), enabled,
                error is None, channel == 'teams' or str(config.get('misp_remove_on_absent', '')).lower() in ('true', '1', 'yes', 'on'),
                error, endpoint, key, event, _verify=verify, _transport=self._transport)
        with self._lock:
            self._adapters = snapshots
            self.revision = revision

    def descriptors(self):
        with self._lock:
            return {k: v.descriptor() for k, v in self._adapters.items()}

    def capture(self, channel, binding_id, action, *, revision=None):
        with self._lock:
            adapter = self._adapters[channel]
            error = adapter.error
            if revision is not None and revision != self.revision:
                error = 'adapter_unapplied'
            if error is None and binding_id != adapter.binding_id:
                error = 'old_binding_blocked'
            if error is None and action == 'Removed' and not adapter.allow_removed:
                error = 'removal_disabled'
            return replace(adapter, error=error, ready=error is None)
