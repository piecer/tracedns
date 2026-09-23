"""Server-owned enrichment: request threads only inspect memory and enqueue."""
from collections import OrderedDict, deque
from ipaddress import ip_address
from itertools import islice
import math
import threading
import time


def _compact(report):
    """Project on workers, never copy raw data or invoke its hooks under a lock.

    Six signed-63-bit integers and at most 264 Unicode characters keep even
    ASCII-escaped JSON below 4096 bytes, including freshness fields.
    """
    if not isinstance(report, dict):
        return None
    result = {}
    for field in ("malicious", "suspicious", "harmless", "undetected",
                  "last_analysis_date", "asn"):
        value = report.get(field)
        if type(value) is int and 0 <= value < 2**63:
            result[field] = value
    for field, limit in (("as_owner", 256), ("country", 8)):
        value = report.get(field)
        if type(value) is str and value:
            result[field] = value[:limit]
    return result or None


class BackgroundEnrichment:
    """Bounded memory and worker ownership; lookup(None) is never invoked.

    Pass ``lookup=None`` to disable. Counts may be configured downward, not
    above the defaults. Successes and failure cooldowns share an LRU capped
    at max_entries (at most max_entries * 4096 serialized report bytes).
    Eviction may shorten TTL/cooldown retention; no unbounded tombstones exist.
    """

    def __init__(self, lookup, workers=4, capacity=256, max_entries=2048,
                 ttl=3600, retry_after=30, per_owner=64):
        for name, value, maximum in (("workers", workers, 4), ("capacity", capacity, 256),
                                     ("max_entries", max_entries, 2048),
                                     ("per_owner", per_owner, 64)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer from 1 to {maximum}")
        for name, value in (("ttl", ttl), ("retry_after", retry_after)):
            if type(value) not in (int, float) or not 0 <= value < math.inf:
                raise ValueError(f"{name} must be finite and nonnegative")
        self._lookup = lookup
        self._workers = workers
        self._capacity = capacity
        self._max_entries = max_entries
        self._ttl = ttl
        self._retry_after = retry_after
        self._per_owner = per_owner
        self._condition = threading.Condition()
        self._threads = []
        self._queue = deque()
        self._pending = {}
        self._owners = {}
        self._entries = OrderedDict()
        self._started = False
        self._stopped = False
        self._running = 0
        self._version = 0

    def start(self):
        with self._condition:
            if self._started or self._stopped or self._lookup is None:
                return
            self._started = True
            try:
                for _ in range(self._workers):
                    thread = threading.Thread(target=self._work, daemon=True,
                                              name="background-enrichment")
                    thread.start()
                    self._threads.append(thread)
            except BaseException:
                self._stopped = True
                self._condition.notify_all()
                raise

    def request(self, ips, *, budget=200, owner="local"):
        """Inspect at most 5000 inputs and admit at most budget NEW lookups.

        Only canonical global unicast IP strings count as requested. Cached
        counts fresh successes; pending includes queued and running lookups;
        deferred covers cooldown, quotas, budget and stopped/not-started work.
        Those three counts partition requested. Stale reports are additionally
        returned with their original fetched_at and stale=True, and counted in
        stale (overlapping pending/deferred). Version is a service-wide change
        counter, not a principal identifier or a promise about wall-clock TTL.
        No source-cache access, disk access, lookup or waiting occurs here.
        """
        if type(owner) is not str or len(owner) > 256:
            raise ValueError("owner must be a string of at most 256 characters")
        reports = {}
        cached = pending = deferred = stale = 0
        unique = {}
        for value in islice(ips, 5000):
            if not isinstance(value, str) or len(value) > 45 or "%" in value:
                continue
            try:
                address = ip_address(value)
            except ValueError:
                continue
            if address.is_global and not address.is_multicast:
                unique[str(address)] = None
        ips = unique
        budget = max(0, min(5000, int(budget)))
        with self._condition:
            now = time.monotonic()
            for ip in ips:
                entry = self._entries.get(ip)
                if entry and entry[0]:
                    is_stale = now >= entry[1]
                    reports[ip] = dict(entry[0], stale=is_stale)
                    self._entries.move_to_end(ip)
                    if not is_stale:
                        cached += 1
                        continue
                    stale += 1
                if ip in self._pending:
                    pending += 1
                elif (self._started and not self._stopped and budget
                      and (not entry or now >= entry[2])
                      and len(self._pending) < self._capacity
                      and self._owners.get(owner, 0) < self._per_owner):
                    self._pending[ip] = owner
                    self._owners[owner] = self._owners.get(owner, 0) + 1
                    self._queue.append(ip)
                    self._version += 1
                    budget -= 1
                    pending += 1
                else:
                    deferred += 1
            self._condition.notify_all()
            status = ("ready" if cached == len(ips) else "partial" if reports
                      else "pending" if pending else "unavailable")
            if self._lookup is None:
                status = "disabled"
            return reports, dict(status=status, requested=len(ips), cached=cached,
                                 pending=pending, deferred=deferred, stale=stale,
                                 version=self._version)

    def _work(self):
        while True:
            with self._condition:
                self._condition.wait_for(lambda: self._queue or self._stopped)
                if self._stopped:
                    return
                ip = self._queue.popleft()
                self._running += 1
            try:
                report = _compact(self._lookup(ip))
            except Exception:
                report = None
            with self._condition:
                now = time.monotonic()
                if report:
                    self._entries[ip] = (dict(report, fetched_at=time.time()),
                                         now + self._ttl, 0)
                else:
                    previous = self._entries.get(ip, (None, 0, 0))
                    self._entries[ip] = (previous[0], previous[1], now + self._retry_after)
                self._entries.move_to_end(ip)
                while len(self._entries) > self._max_entries:
                    self._entries.popitem(last=False)
                self._release(ip)
                self._running -= 1
                self._version += 1
                self._condition.notify_all()

    def _release(self, ip):
        owner = self._pending.pop(ip)
        self._owners[owner] -= 1
        if not self._owners[owner]:
            del self._owners[owner]

    def stop_admission(self):
        """Permanently stop admission and discard queued, never running, work."""
        with self._condition:
            if not self._stopped:
                self._version += 1
            self._stopped = True
            while self._queue:
                self._release(self._queue.popleft())
            self._condition.notify_all()

    def close(self, timeout=1):
        """Share one join deadline; timed-out daemon lookups remain accounted."""
        self.stop_admission()
        deadline = time.monotonic() + max(0, timeout)
        for thread in self._threads:
            thread.join(max(0, deadline - time.monotonic()))
        with self._condition:
            return dict(remaining=len(self._pending), running=self._running,
                        queued=len(self._queue))
