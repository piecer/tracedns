"""Bounded clock projection; no I/O, locks, or mutable shared snapshots."""
from dataclasses import dataclass
import math

MAX_COUNTER = (1 << 63) - 1
STALL_AFTER_SECONDS = 60


def finite(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def counter(value):
    value = finite(value)
    return None if value is None else min(MAX_COUNTER, max(0, int(value)))


def elapsed(now, then):
    now, then = finite(now), finite(then)
    return None if now is None or then is None else max(0, now - then)


@dataclass(frozen=True)
class Progress:
    state: str = 'not_started'
    operation: str | None = None
    channel: str | None = None
    started: float | None = None
    completed: float | None = None
    completed_wall: int | None = None
    attempts: tuple = (None, None)

    def project(self, now, stopping=False):
        age = elapsed(now, self.started)
        since = elapsed(now, self.completed)
        state = self.state
        if state != 'failed' and stopping and state != 'stopped':
            state = 'stopping'
        elif state in ('active', 'idle') and (age if age is not None else since) is not None:
            if (age if age is not None else since) >= STALL_AFTER_SECONDS:
                state = 'stalled'
        return {'state': state, 'operation': self.operation, 'channel': self.channel,
                'last_progress_at': self.completed_wall,
                'last_progress_age_seconds': counter(since),
                'in_flight_age_seconds': counter(age), 'stall_after_seconds': STALL_AFTER_SECONDS,
                'channels': {c: {'state': ('unavailable' if state == 'failed' else 'stalled' if state == 'stalled' else 'active')
                                if self.channel == c and self.operation else 'idle',
                                'last_attempt_at': self.attempts[i],
                                'in_flight_age_seconds': counter(age) if self.channel == c else None}
                             for i, c in enumerate(('teams', 'misp'))}}
