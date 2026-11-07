"""Thread-local instrumentation windows that leave caller hooks intact."""
from contextlib import contextmanager
import sys
import threading


@contextmanager
def temporary_trace(callback, *, opcodes=False):
    previous = sys.gettrace()
    frame = sys._getframe()
    previous_opcodes = frame.f_trace_opcodes
    try:
        # CPython 3.12 inspects existing frames at settrace time to enable
        # opcode events. Setting the target flag in its call event is too late
        # on the first installation. Seed this live frame, not a warmup call.
        if opcodes:
            frame.f_trace_opcodes = True
        sys.settrace(callback)
        yield
    finally:
        frame.f_trace_opcodes = previous_opcodes
        # A callback exception disables tracing; still restore the caller.
        sys.settrace(previous)
        del frame


@contextmanager
def temporary_opcodes(code, callback):
    """Observe this thread's exact instruction sites without global opcode state."""
    monitoring = getattr(sys, 'monitoring', None)
    if monitoring is None:
        def trace(frame, event, arg):
            if frame.f_code is not code:
                return None
            if event == 'call':
                frame.f_trace_opcodes = True
            elif event == 'opcode':
                callback(frame, event, arg)
            return trace

        with temporary_trace(trace, opcodes=True):
            yield
        return

    # On CPython 3.12 f_trace_opcodes permanently enables an interpreter-wide
    # instruction path for later legacy tracers, even after frame restoration.
    # Local monitoring events avoid both that cost and legacy event-cache reuse.
    # Refuse overlapping instruction owners: CPython 3.12 can drop the first
    # tool's callbacks when a second tool instruments the same instructions.
    for tool in range(6):
        events = monitoring.get_events(tool) | monitoring.get_local_events(tool, code)
        if events & monitoring.events.INSTRUCTION:
            raise RuntimeError('instruction events already owned for this code')
    for tool in range(6):
        try:
            monitoring.use_tool_id(tool, 'tracedns-instruction-window')
            break
        except ValueError:
            continue
    else:
        raise RuntimeError('no monitoring tool available for instruction window')

    owner = threading.get_ident()

    def instruction(actual_code, offset):
        if threading.get_ident() != owner:
            return
        frame = sys._getframe(1)
        try:
            assert frame.f_code is actual_code is code
            assert frame.f_lasti == offset
            callback(frame, 'opcode', None)
        finally:
            del frame

    try:
        monitoring.register_callback(tool, monitoring.events.INSTRUCTION, instruction)
        monitoring.set_local_events(tool, code, monitoring.events.INSTRUCTION)
        yield
    finally:
        try:
            monitoring.set_local_events(tool, code, 0)
        finally:
            try:
                monitoring.register_callback(tool, monitoring.events.INSTRUCTION, None)
            finally:
                monitoring.free_tool_id(tool)


@contextmanager
def temporary_profile(callback):
    previous = sys.getprofile()
    try:
        sys.setprofile(callback)
        yield
    finally:
        sys.setprofile(previous)
