"""A scan owns a callable view, not the subsequently published registry."""
import importlib.util
import threading

import a_decoder
import txt_decoder


def test_pinned_registry_keeps_old_callable_and_live_aliases():
    assert importlib.util.find_spec('decoder_registry') is not None, 'pinned registry API missing'
    import decoder_registry as registry
    txt = txt_decoder.TXT_DECODE_METHODS
    a = a_decoder.A_DECODE_METHODS
    old = registry.snapshot_registry()
    try:
        txt['pinned_test'] = lambda values, **kw: ['1.1.1.1']
        a['pinned_test'] = lambda values, **kw: ['1.1.1.1']
        view = registry.snapshot_registry()
        txt['pinned_test'] = lambda values, **kw: ['2.2.2.2']
        a['pinned_test'] = lambda values, **kw: ['2.2.2.2']
        with registry.use_registry(view):
            assert txt_decoder.decode_txt_hidden_ips([], 'pinned_test') == ['1.1.1.1']
            assert a_decoder.decode_a_hidden_ips([], 'pinned_test') == ['1.1.1.1']
            finished = threading.Event()
            thread = threading.Thread(target=lambda: (registry.snapshot_registry(), finished.set()))
            thread.start()
            assert finished.wait(1), 'view must not hold the registry lock'
            thread.join()
        assert txt_decoder.decode_txt_hidden_ips([], 'pinned_test') == ['2.2.2.2']
        assert a_decoder.decode_a_hidden_ips([], 'pinned_test') == ['2.2.2.2']
        assert txt is txt_decoder.TXT_DECODE_METHODS and a is a_decoder.A_DECODE_METHODS
    finally:
        registry.publish(old)



def test_analysis_iteration_survives_registry_publication_inside_decoder():
    import decoder_registry as registry
    original = registry.snapshot_registry()
    called = []

    def modifying(values, **kwargs):
        txt_decoder.TXT_DECODE_METHODS['added_during_analysis'] = lambda values, **kwargs: ['4.4.4.4']
        called.append(True)
        return ['3.3.3.3']

    try:
        txt_decoder.TXT_DECODE_METHODS['modify_during_analysis'] = modifying
        result = txt_decoder.analyze_domain_decoding('local.invalid', '1.2.3.4')
        assert called and result
    finally:
        registry.publish(original)


def test_decoder_callable_executes_without_registry_lock():
    import decoder_registry as registry
    original = registry.snapshot_registry()
    checked = []

    def decode(values, **kwargs):
        event = threading.Event()
        thread = threading.Thread(target=lambda: (registry.snapshot_registry(), event.set()))
        thread.start()
        try:
            checked.append(event.wait(1))
        finally:
            thread.join(2)
        return ['1.2.3.4']

    try:
        txt_decoder.TXT_DECODE_METHODS['unlocked'] = decode
        assert txt_decoder.decode_txt_hidden_ips([], 'unlocked') == ['1.2.3.4']
        assert checked == [True]
    finally:
        registry.publish(original)
