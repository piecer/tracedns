import ssl
from unittest import mock

import pytest

import alerts
from monitor import delivery_adapters as adapters


@pytest.mark.parametrize('value', [False, 0, 1, {}, 'missing/SECRET.pem'])
def test_private_ca_invalid_never_disables_verification(value):
    assert hasattr(adapters, 'validated_tls_verify'), 'explicit CA validator missing'
    with pytest.raises(ValueError, match='^tls_config$'):
        adapters.validated_tls_verify(value)


def test_private_ca_valid_bundle_default_and_registry_rotation(tmp_path):
    assert hasattr(adapters, 'validated_tls_verify'), 'explicit CA validator missing'
    assert adapters.validated_tls_verify(None) is True
    assert adapters.validated_tls_verify('') is True
    ca = tmp_path / 'private-ca.pem'
    der = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca.write_text(ssl.DER_cert_to_PEM_cert(der))
    assert adapters.validated_tls_verify(str(ca)) == str(ca)
    registry = adapters.DestinationRegistry(b'k' * 32)
    config = {'misp_url': 'https://misp.invalid', 'api_key': 'secret', 'push_event_id': 12}
    registry.apply(config, revision=1)
    binding = registry.descriptors()['misp']['binding_id']
    registry.apply(dict(config, misp_ca_bundle=str(ca)), revision=2)
    assert registry.capture('misp', binding, 'Added')._verify == str(ca)
    ca.write_text('SECRET_INVALID_CERT')
    registry.apply(dict(config, misp_ca_bundle=str(ca)), revision=3)
    assert registry.capture('misp', binding, 'Added').error == 'tls_config'


@pytest.mark.parametrize('endpoint', ['http://misp.invalid', 'https://u:SECRET@misp.invalid',
                                     'https://misp.invalid?SECRET', 'https://misp.invalid/#fragment',
                                     'https://misp.invalid/../other', 'https://X'])
def test_registry_rejects_unsafe_misp_endpoint(endpoint):
    registry = adapters.DestinationRegistry(b'k' * 32)
    registry.apply({'misp_url': endpoint, 'api_key': 'SECRET', 'push_event_id': 12}, revision=1)
    assert registry.descriptors()['misp']['error'] == 'destination_invalid'


def test_pure_provenance_selection_performs_no_client_initialization(tmp_path):
    assert hasattr(alerts, 'select_alert_configuration'), 'pure selector missing'
    ini = tmp_path / 'config.ini'
    ini.write_text('[global]\napi_key=INI_SECRET\nmisp_url=https://misp.invalid\npush_event_id=12\n')
    with mock.patch.object(alerts, 'PyMISP', side_effect=AssertionError('network forbidden')):
        assert alerts.select_alert_configuration({'alerts': {}}, str(ini)) == {}
        assert alerts.select_alert_configuration({'alerts': None}, str(ini)) == {}
        selected = alerts.select_alert_configuration({}, str(ini))
        assert selected['api_key'] == 'INI_SECRET'
    original = {'alerts': {'teams_webhook': 'https://teams.invalid/SECRET'}}
    selected = alerts.select_alert_configuration(original, str(ini))
    selected.clear()
    assert original['alerts']


def test_alert_provenance_not_client_readiness():
    assert hasattr(alerts, 'init_from_configuration'), 'provenance selector missing'
    with mock.patch.object(alerts, 'init_from_alerts', return_value=False) as json_init, \
            mock.patch.object(alerts, 'init_from_config') as ini_init:
        alerts.init_from_configuration({'alerts': {}})
        json_init.assert_called_once_with({})
        ini_init.assert_not_called()
        alerts.init_from_configuration({})
        ini_init.assert_called_once_with('config.ini')


def test_legacy_pymisp_private_ca_and_error_sanitized(tmp_path, caplog):
    ca = tmp_path / 'ca.pem'
    der = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca.write_text(ssl.DER_cert_to_PEM_cert(der))
    with mock.patch.object(alerts, 'PyMISP', side_effect=RuntimeError('SECRET_CANARY')) as factory:
        alerts.init_from_alerts({'misp_url': 'https://misp.invalid', 'api_key': 'key',
                                 'push_event_id': 12, 'misp_ca_bundle': str(ca)})
    assert factory.call_args.args[2] == str(ca)
    assert 'SECRET_CANARY' not in caplog.text
    assert alerts.mispupdate_code.misp is None
