import unittest

from history_manager import MAX_HISTORY_EVENTS, trim_history_events


class TestHistoryRetention(unittest.TestCase):
    def test_retains_only_newest_events(self):
        events = [{"ts": i} for i in range(MAX_HISTORY_EVENTS + 25)]
        retained = trim_history_events(events)
        self.assertEqual(len(retained), MAX_HISTORY_EVENTS)
        self.assertEqual(retained[0]["ts"], 25)
        self.assertEqual(retained[-1]["ts"], MAX_HISTORY_EVENTS + 24)

    def test_invalid_event_collection_becomes_empty(self):
        self.assertEqual(trim_history_events({"ts": 1}), [])


if __name__ == "__main__":
    unittest.main()
