"""Internal capture/decode bridge, not sanitation or HTTP authorization.

The scheduler calls slice once. Capture, seal, take, decoder, admission and
transfer are distinct phases. Immutable encoded bytes and the private decoded
graph overlap actual reservations; only the existing admission mints a handle.
"""
import math
import re
import time

from http_api.read_capture import Capture, CaptureBudget, CaptureOwners
from security.derived_redaction import OwnedPayload, RedactionBudget, Reject

_NUMBER = re.compile(rb'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')


class _Decoder:
    """Source-free iterative JSON parser; no whole-body JSON decoder."""

    def __init__(self, data, lease):
        self.data, self.lease = data, lease
        self.pos = self.nodes = self.steps = self.max_chunk = 0
        self.frames = []
        self.result = None
        self.complete = False
        self.string = None
        self.key_string = False
        self.escape = False

    def _node(self):
        if self.nodes == 4096:
            raise Reject('capacity')
        self.lease.reserve(metadata=32)
        self.nodes += 1

    def _accept(self, value):
        if not self.frames:
            self.result = value
            self.complete = True
            return
        frame = self.frames[-1]
        if frame[0] == 'list':
            if len(frame[1]) >= 4096:
                raise Reject('capacity')
            frame[1].append(value)
        else:
            if len(frame[1]) >= 128:
                raise Reject('capacity')
            frame[1][frame[3]] = value
            frame[3] = None
        frame[2] = 'comma'

    def _string_step(self):
        # The bounded source-byte loop also bounds produced codepoints. Escape
        # lookahead is <=12 bytes; UTF8 carry stays in the owned byte buffer.
        count = 0
        while self.pos < len(self.data) and count < 1024:
            byte = self.data[self.pos]
            self.pos += 1
            count += 1
            if byte == 34:
                value = self.string.decode('utf8')
                self.string = None
                if self.key_string:
                    if len(value) > 256 or len(value.encode('utf8')) > 1024:
                        raise Reject('capacity')
                    self.frames[-1][3] = value
                    self.frames[-1][2] = 'colon'
                else:
                    self._accept(value)
                break
            if byte == 92:
                if self.pos >= len(self.data):
                    raise Reject('invalid')
                escape = self.data[self.pos]
                self.pos += 1
                if escape == 117:
                    code = self._hex()
                    if 0xD800 <= code <= 0xDBFF:
                        if self.data[self.pos:self.pos + 2] != b'\\u':
                            raise Reject('invalid')
                        self.pos += 2
                        low = self._hex()
                        if not 0xDC00 <= low <= 0xDFFF:
                            raise Reject('invalid')
                        code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00
                    elif 0xDC00 <= code <= 0xDFFF:
                        raise Reject('invalid')
                    self.string.extend(chr(code).encode('utf8'))
                else:
                    index = b'"\\/bfnrt'.find(bytes((escape,)))
                    if index < 0:
                        raise Reject('invalid')
                    self.string.append(b'"\\/\b\f\n\r\t'[index])
            elif byte < 32:
                raise Reject('invalid')
            else:
                self.string.append(byte)
        self.max_chunk = max(self.max_chunk, count)
        if self.string is not None and self.pos == len(self.data):
            raise Reject('invalid')

    def _hex(self):
        end = self.pos + 4
        data = self.data[self.pos:end]
        if len(data) != 4 or any(c not in b'0123456789abcdefABCDEF' for c in data):
            raise Reject('invalid')
        self.pos = end
        return int(data, 16)

    def step(self):
        self.steps += 1
        if self.string is not None:
            self._string_step()
            return
        if self.pos == len(self.data):
            if not self.complete or self.frames:
                raise Reject('invalid')
            return
        byte = self.data[self.pos]
        if byte in b' \r\n\t':
            self.pos += 1
            return
        if self.complete:
            raise Reject('invalid')
        if self.frames:
            frame = self.frames[-1]
            phase = frame[2]
            closing = 93 if frame[0] == 'list' else 125
            if phase in ('first', 'comma') and byte == closing:
                self.pos += 1
                self.frames.pop()
                self._accept(frame[1])
                return
            if phase == 'comma':
                if byte != 44:
                    raise Reject('invalid')
                frame[2] = 'next'
                self.pos += 1
                return
            if phase == 'colon':
                if byte != 58:
                    raise Reject('invalid')
                frame[2] = 'value'
                self.pos += 1
                return
            if frame[0] == 'dict' and phase in ('first', 'next'):
                if byte != 34:
                    raise Reject('invalid')
                self._node()
                self.key_string = True
                self.string = bytearray()
                self.pos += 1
                return
        self._node()
        if len(self.frames) >= 32:
            raise Reject('capacity')
        if byte in (123, 91):
            self.frames.append(['dict' if byte == 123 else 'list', {} if byte == 123 else [], 'first', None])
            self.pos += 1
        elif byte == 34:
            self.key_string = False
            self.string = bytearray()
            self.pos += 1
        else:
            begin = self.pos
            while self.pos < len(self.data) and self.data[self.pos] not in b',]} \r\n\t':
                if self.pos - begin >= 64:
                    raise Reject('invalid')
                self.pos += 1
            token = self.data[begin:self.pos]
            if token == b'null':
                value = None
            elif token == b'true':
                value = True
            elif token == b'false':
                value = False
            elif not _NUMBER.fullmatch(token):
                raise Reject('invalid')
            elif b'.' in token or b'e' in token or b'E' in token:
                value = float(token)
                if not math.isfinite(value):
                    raise Reject('invalid')
            else:
                value = int(token)
                if value.bit_length() > 128:
                    raise Reject('invalid')
            self._accept(value)

    def slice(self, budget):
        start = time.monotonic()
        before = self.steps
        while self.steps - before < 512:
            budget.check()
            if self.steps != before and time.monotonic() - start >= .002:
                return 'more'
            self.step()
            if self.complete and self.pos == len(self.data):
                return 'done'
        return 'more'


class CapturedPayload:
    """One exclusively owned unit; take transfers a genuine same-budget input."""

    def __init__(self, owners, root_name, path, *, capture_budget, budget,
                 unit_bytes=65536, skip_fields=(), projection='complete'):
        if type(owners) is not CaptureOwners or type(capture_budget) is not CaptureBudget or type(budget) is not RedactionBudget:
            raise TypeError('exact owners and budgets required')
        if capture_budget.ledger is not budget:
            raise ValueError('cross-budget capture')
        Capture.validate(owners, root_name, path, budget=capture_budget,
                         unit_bytes=unit_bytes, skip_fields=skip_fields, projection=projection)
        self.budget, self.capture_budget = budget, capture_budget
        self.status, self.phase = 'more', 'capture'
        self._running = self._cancelled = False
        self._lease = self.capture = self.decoder = self.admission = self.output = None
        self.encoded = self.graph = None
        self.slices = self.decode_steps = self.decode_nodes = self.max_decode_chunk = 0
        self.unit_bytes = unit_bytes
        try:
            if capture_budget._cancelled:
                raise Reject('stopped')
            self._lease = budget.reserve(worker=131072, metadata=131072)
            self.capture = Capture(owners, root_name, path, budget=capture_budget,
                                   unit_bytes=unit_bytes, skip_fields=skip_fields, projection=projection)
            if self.capture.status != 'more':
                raise Reject(self.capture.status)
        except (Reject, MemoryError) as exc:
            self.status = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        owners = path = skip_fields = None
        retry = False
        while self.status != 'more':
            try:
                self._dispose()
                break
            except MemoryError as exc:
                self.status = 'invalid'
                exc.__traceback__ = exc.__context__ = exc.__cause__ = None
            if retry:
                raise RuntimeError('two-fault bridge constructor')
            retry = True

    def _advance(self):
        self.budget.check()
        if self.phase == 'capture':
            status = self.capture.slice()
            if status == 'done':
                self.phase = 'seal'
            elif status != 'more':
                raise Reject(status)
        elif self.phase == 'seal':
            if self.capture.seal() != 'done':
                raise Reject(self.capture.status)
            self.phase = 'bytes'
        elif self.phase == 'bytes':
            # Paid before Capture.take copies and drops its original charge.
            self._lease.reserve(worker=128 + self.unit_bytes)
            self.encoded = self.capture.take()
            if self.encoded is None:
                raise Reject(self.capture.status)
            self.capture = None
            self.phase = 'decode_start'
        elif self.phase == 'decode_start':
            # <=4096 nodes, total UTF8/codepoints <= source-byte cap. Pays graph,
            # container overallocation, UTF8 accumulator plus native decode
            # output simultaneously, and bounded numeric/string scratch.
            self._lease.reserve(worker=8 * self.unit_bytes + 4096 * 256 + 65536)
            self.decoder = _Decoder(self.encoded, self._lease)
            self.phase = 'decode'
        elif self.phase == 'decode':
            if self.decoder.slice(self.budget) == 'done':
                self.graph = self.decoder.result
                self.decode_steps, self.decode_nodes = self.decoder.steps, self.decoder.nodes
                self.max_decode_chunk = self.decoder.max_chunk
                self.decoder = None
                self.phase = 'admit_start'
        elif self.phase == 'admit_start':
            self.admission = OwnedPayload.admit_sliced(self.graph, budget=self.budget)
            if self.admission.status != 'more':
                raise Reject(self.admission.status)
            self.phase = 'admit'
        elif self.phase == 'admit':
            status = self.admission.slice()
            if status == 'done':
                self.phase = 'admit_take'
            elif status != 'more':
                raise Reject(status)
        elif self.phase == 'admit_take':
            self.output = self.admission.take()
            if self.output is None:
                raise Reject(self.admission.status)
            self.admission = None
            self.graph = self.encoded = None
            self.status = 'done'
        self.budget.check()

    def _invoke(self, action):
        # The bridge has its own nondestructive guard. Child capture/admission
        # operations acquire the common active slot themselves; never nest it.
        b = self.budget
        with b._lock:
            if self._running:
                if action == 'discard':
                    self._cancelled = True
                return None if action == 'take' else 'lock_busy'
            if self._lease is None or (action == 'take' and self.status != 'done'):
                return None if action == 'take' else self.status
            if action == 'slice' and self.status != 'more':
                return self.status
            self._running = True
        entered = False
        result = None
        try:
            if action == 'discard':
                self._cancelled = True
            else:
                if action == 'take' or self.phase in ('decode_start', 'decode', 'admit_start'):
                    b.enter(self)
                    entered = True
                if self.capture_budget._cancelled:
                    raise Reject('stopped')
                b.check()
                if action == 'slice':
                    self._advance()
                    self.slices += 1
        except (Reject, MemoryError, ValueError, UnicodeError) as exc:
            self.status = exc.args[0] if type(exc) is Reject else 'invalid'
            exc.__traceback__ = exc.__context__ = exc.__cause__ = None
        # Work frame and exception scopes have quiesced before any credit can
        # be reused. Cleanup entry is itself within the one-fault retry guard.
        retry = False
        try:
            while True:
                try:
                    with b._lock:
                        if self._cancelled or self.capture_budget._cancelled:
                            self.status = 'stopped'
                        elif b._closed:
                            self.status = 'invalid'
                        elif time.monotonic() >= b.deadline:
                            self.status = 'deadline'
                        if self.status not in ('more', 'done'):
                            self._dispose()
                        elif action == 'take':
                            self._lease.close()
                            self._lease = None
                            result = self.output
                            self.output = None
                            self.status = 'taken'
                    break
                except MemoryError as exc:
                    self.status = 'invalid'
                    exc.__traceback__ = exc.__context__ = exc.__cause__ = None
                if retry:
                    raise RuntimeError('two-fault bridge cleanup')
                retry = True
        finally:
            with b._lock:
                if entered and b._active is self:
                    b._active = None
                self._running = False
        return result if action == 'take' else self.status

    def _dispose(self):
        if self.capture is not None:
            self.capture.discard()
            self.capture = None
        if self.admission is not None:
            self.admission.discard()
            self.admission = None
        if self.output is not None:
            self.output.close()
            self.output = None
        self.decoder = self.graph = self.encoded = None
        if self._lease is not None:
            self._lease.close()
            self._lease = None

    def slice(self):
        return self._invoke('slice')

    def take(self):
        return self._invoke('take')

    def discard(self):
        return self._invoke('discard')

    def counters(self):
        return dict(status=self.status, phase=self.phase, slices=self.slices,
                    decode_steps=self.decode_steps, decode_nodes=self.decode_nodes,
                    max_decode_chunk=self.max_decode_chunk)
