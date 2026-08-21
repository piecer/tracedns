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
