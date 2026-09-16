from models import Snapshot
from monitor import engine


def test_history_snapshot_preserves_decoder_provenance():
    snap = Snapshot(
        type="TXT",
        values=["payload"],
        decoded_ips=["8.8.8.8"],
        ts=123,
        txt_decode="cafebabe_xor_base64",
    )

    assert engine._history_snapshot(snap) == {
        "values": ["payload"],
        "decoded_ips": ["8.8.8.8"],
        "ts": 123,
        "txt_decode": "cafebabe_xor_base64",
    }


def test_snapshot_change_detects_decoder_provenance_only_change():
    previous = Snapshot(
        type="TXT",
        values=["payload"],
        decoded_ips=["8.8.8.8"],
        ts=123,
        txt_decode="decoder-A",
    )
    current = Snapshot(
        type="TXT",
        values=["payload"],
        decoded_ips=["8.8.8.8"],
        ts=124,
        txt_decode="decoder-B",
    )

    assert engine._snapshot_changed(previous, current) is True
    assert engine._snapshot_changed(current, current) is False


def test_snapshot_history_and_change_detection_preserve_decoded_endpoints():
    previous = Snapshot(
        type="ENS",
        values=["encoded"],
        decoded_ips=["49.217.50.98"],
        decoded_endpoints=["49.217.50.98:15850"],
        ts=123,
    )
    current = Snapshot(
        type="ENS",
        values=["encoded"],
        decoded_ips=["49.217.50.98"],
        decoded_endpoints=["49.217.50.98:27310"],
        ts=124,
    )

    assert engine._history_snapshot(previous)["decoded_endpoints"] == ["49.217.50.98:15850"]
    assert engine._snapshot_changed(previous, current) is True


def test_snapshot_legacy_positional_constructor_keeps_fourth_argument_as_timestamp():
    snapshot = Snapshot("ENS", ["encoded"], ["49.217.50.98"], 123)

    assert snapshot.ts == 123
    assert snapshot.decoded_endpoints == []


def test_snapshot_round_trip_preserves_decoded_endpoints():
    original = Snapshot(
        type="ENS",
        values=["encoded"],
        decoded_ips=["49.217.50.98"],
        decoded_endpoints=["49.217.50.98:15850"],
        ts=123,
    )

    restored = Snapshot.from_legacy(original.to_dict())

    assert restored.decoded_endpoints == ["49.217.50.98:15850"]
    assert restored.ts == 123
