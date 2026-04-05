import os
import tempfile
import unittest

from tracedns import alerts


class TestAlertsRuntime(unittest.TestCase):
    def setUp(self):
        self.old_initialized = alerts._initialized
        self.old_cfg = alerts._cfg
        self.old_event_id = alerts._misp_event_id
        self.old_webhook = alerts._teams_webhook
        self.old_remove_on_absent = getattr(alerts, '_misp_remove_on_absent', False)
        self.old_misp = getattr(alerts.mispupdate_code, 'misp', None)

    def tearDown(self):
        alerts._initialized = self.old_initialized
        alerts._cfg = self.old_cfg
        alerts._misp_event_id = self.old_event_id
        alerts._teams_webhook = self.old_webhook
        alerts._misp_remove_on_absent = self.old_remove_on_absent
        alerts.mispupdate_code.misp = self.old_misp

    def test_init_from_alerts_rejects_placeholder_webhook(self):
        ok = alerts.init_from_alerts({'teams_webhook': 'https://X'})
        self.assertFalse(ok)
        self.assertIsNone(alerts._teams_webhook)

    def test_init_from_alerts_sets_misp_event_and_webhook(self):
        ok = alerts.init_from_alerts({
            'teams_webhook': 'https://example.com/webhook',
            'push_event_id': '123',
            'misp_remove_on_absent': True,
        })
        self.assertTrue(ok)
        self.assertEqual(alerts._teams_webhook, 'https://example.com/webhook')
        self.assertEqual(alerts._misp_event_id, 123)
        self.assertTrue(alerts._misp_remove_on_absent)

    def test_init_from_config_without_global_section(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            path = f.name
        try:
            ok = alerts.init_from_config(path)
            self.assertFalse(ok)
            self.assertIsNone(alerts._teams_webhook)
            self.assertIsNone(alerts._misp_event_id)
        finally:
            os.unlink(path)

    def test_alert_new_ips_does_not_raise_when_misp_client_missing(self):
        alerts._initialized = True
        alerts._teams_webhook = None
        alerts._misp_event_id = 999
        alerts.mispupdate_code.misp = None
        alerts.alert_new_ips([('1.2.3.4', 'unit-test')])

    def test_alert_removed_ips_does_not_raise_when_misp_client_missing(self):
        alerts._initialized = True
        alerts._teams_webhook = None
        alerts._misp_event_id = 999
        alerts._misp_remove_on_absent = True
        alerts.mispupdate_code.misp = None
        alerts.alert_removed_ips([('1.2.3.4', 'unit-test')])

    def test_alert_removed_ips_skips_misp_delete_when_disabled(self):
        alerts._initialized = True
        alerts._teams_webhook = None
        alerts._misp_event_id = 777
        alerts._misp_remove_on_absent = False
        alerts.mispupdate_code.misp = object()

        called = {'n': 0}
        old_remove = alerts.mispupdate_code.remove_ips
        try:
            def fake_remove(event_id, entries):
                called['n'] += 1
                return True
            alerts.mispupdate_code.remove_ips = fake_remove
            alerts.alert_removed_ips([('9.9.9.9', 'demo')])
        finally:
            alerts.mispupdate_code.remove_ips = old_remove

        self.assertEqual(called['n'], 0)

    def test_alert_removed_ips_calls_misp_delete_when_enabled(self):
        alerts._initialized = True
        alerts._teams_webhook = None
        alerts._misp_event_id = 777
        alerts._misp_remove_on_absent = True
        alerts.mispupdate_code.misp = object()

        called = {'n': 0, 'event_id': None}
        old_remove = alerts.mispupdate_code.remove_ips
        try:
            def fake_remove(event_id, entries):
                called['n'] += 1
                called['event_id'] = event_id
                return True
            alerts.mispupdate_code.remove_ips = fake_remove
            alerts.alert_removed_ips([('9.9.9.9', 'demo')])
        finally:
            alerts.mispupdate_code.remove_ips = old_remove

        self.assertEqual(called['n'], 1)
        self.assertEqual(called['event_id'], 777)

    def test_alert_new_ips_uses_structured_message(self):
        alerts._initialized = True
        alerts._misp_event_id = None
        alerts._teams_webhook = "https://example.com/webhook"

        sent = {}
        old_send = alerts._send_teams
        try:
            def fake_send(message, title=''):
                sent['title'] = title
                sent['message'] = message
                return True
            alerts._send_teams = fake_send

            alerts.alert_new_ips([
                ('1.2.3.4', 'a.example'),
                ('1.2.3.4', 'a.example'),
                ('5.6.7.8', 'b.example'),
            ])
        finally:
            alerts._send_teams = old_send

        self.assertEqual(sent.get('title'), 'C2 IOC Add Alert')
        msg = sent.get('message', '')
        self.assertIn('Action: Added', msg)
        self.assertIn('Time (Local): ', msg)
        self.assertIn('Entries: 2', msg)
        self.assertIn('Unique IPs: 2', msg)
        self.assertIn('Source Types: TXT:2', msg)
        self.assertIn('- [TXT] 1.2.3.4 | source=a.example', msg)
        self.assertIn('- [TXT] 5.6.7.8 | source=b.example', msg)

    def test_alert_removed_ips_uses_structured_message(self):
        alerts._initialized = True
        alerts._misp_event_id = None
        alerts._teams_webhook = "https://example.com/webhook"

        sent = {}
        old_send = alerts._send_teams
        try:
            def fake_send(message, title=''):
                sent['title'] = title
                sent['message'] = message
                return True
            alerts._send_teams = fake_send

            alerts.alert_removed_ips([
                ('9.9.9.9', 'x.example'),
            ])
        finally:
            alerts._send_teams = old_send

        self.assertEqual(sent.get('title'), 'C2 IOC Remove Alert')
        msg = sent.get('message', '')
        self.assertIn('Action: Removed', msg)
        self.assertIn('Time (Local): ', msg)
        self.assertIn('Entries: 1', msg)
        self.assertIn('Unique IPs: 1', msg)
        self.assertIn('- [TXT] 9.9.9.9 | source=x.example', msg)


if __name__ == '__main__':
    unittest.main()
