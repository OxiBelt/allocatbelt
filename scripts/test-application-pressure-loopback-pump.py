#!/usr/bin/env python3
"""Deterministic socket-state and timing tests for the loopback echo pump."""
from __future__ import annotations

import ast
import errno
import pathlib
import time
import types
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parent
DRIVER = HERE / 'application-pressure-driver.py'

class PressureError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise PressureError(message)

def load_function(path, name, namespace=None):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name)
    env = {'PressureError': PressureError, 'require': require, 'time': time,
           'select': __import__('select'), '_WORKER_STOP_REQUESTED': False}
    if namespace:
        env.update(namespace)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), env)
    return env[name], env, tree

EXCHANGE, EXCHANGE_GLOBALS, CANDIDATE_TREE = load_function(DRIVER, '_loopback_echo_exchange')

def timed_exchange(exchange, client, server, payload, clock, waiter, stop_requested=lambda: False):
    """Mirror the caller's original RTT boundaries and post-helper guard."""
    sent = clock.now()
    deadline_ns = sent + 2_000_000_000
    echoed = exchange(client, server, payload, deadline_ns, stop_requested=stop_requested,
                      clock_ns=clock.now, wait_ready=waiter)
    if echoed is None:
        return None
    received = clock.now()
    if received > deadline_ns:
        raise PressureError('loopback exchange crossed the absolute caller deadline')
    return sent, received, echoed

class FakeClock:
    def __init__(self): self.value = 1_000_000
    def now(self): return self.value
    def advance(self, nanoseconds): self.value += nanoseconds

class FakeSocket:
    def __init__(self, name, clock, max_send, max_recv):
        self.name = name
        self.clock = clock
        self.max_send = max_send
        self.max_recv = max_recv
        self.peer = None
        self.incoming = bytearray()
        self.fail_sends = 0
        self.fail_recvs = 0
        self.eof = False
        self.writes_enabled = True
        self.sent = bytearray()
        self.received = bytearray()
        self.first_send_attempt_ns = None
        self.first_send_ns = None
        self.last_recv_ns = None
        self.full_receive_ns = None
        self.expected_receive_size = None
        self.delay_after_full_receive_ns = 0
        self.on_receive = None
        self.on_send = None
        self.corrupt_send = False
    def send(self, data):
        if self.first_send_attempt_ns is None:
            self.first_send_attempt_ns = self.clock.now()
        if self.fail_sends:
            self.fail_sends -= 1
            self.clock.advance(100)
            raise BlockingIOError(errno.EAGAIN, 'scripted send EAGAIN')
        if self.first_send_ns is None:
            self.first_send_ns = self.clock.now()
        block = bytes(data[:self.max_send])
        if self.corrupt_send and self.name == 'server' and block:
            block = bytes([block[0] ^ 1]) + block[1:]
        if not block:
            return 0
        self.peer.incoming.extend(block)
        self.sent.extend(block)
        self.clock.advance(100)
        if self.on_send is not None:
            self.on_send()
        return len(block)
    def recv(self, size):
        if self.fail_recvs:
            self.fail_recvs -= 1
            self.clock.advance(100)
            raise BlockingIOError(errno.EWOULDBLOCK, 'scripted receive EAGAIN')
        if self.eof:
            return b''
        if self.incoming:
            block = bytes(self.incoming[:min(size, self.max_recv)])
            del self.incoming[:len(block)]
            self.received.extend(block)
            self.clock.advance(100)
            self.last_recv_ns = self.clock.now()
            if self.expected_receive_size is not None and len(self.received) == self.expected_receive_size:
                self.full_receive_ns = self.clock.now()
                if self.delay_after_full_receive_ns:
                    self.clock.advance(self.delay_after_full_receive_ns)
            if self.on_receive is not None:
                self.on_receive()
            return block
        raise BlockingIOError(errno.EAGAIN, 'not readable')
    def close(self):
        self.eof = True

def paired_sockets(clock):
    client = FakeSocket('client', clock, max_send=5, max_recv=4)
    server = FakeSocket('server', clock, max_send=3, max_recv=2)
    client.peer = server
    server.peer = client
    return client, server

def fake_waiter(clock, never_ready=False, first_delay_ns=0):
    waits = []
    first = [True]
    def wait(reads, writes, errors, timeout):
        waits.append(timeout)
        if first[0] and first_delay_ns:
            clock.advance(first_delay_ns)
        first[0] = False
        if never_ready:
            clock.advance(max(1, int(timeout * 1_000_000_000)))
            return [], [], []
        ready_read = [sock for sock in reads if sock.incoming or sock.eof]
        ready_write = [sock for sock in writes if sock.writes_enabled]
        if not ready_read and not ready_write:
            clock.advance(max(1, int(timeout * 1_000_000_000)))
        return ready_read, ready_write, []
    return wait, waits

class LoopbackPumpTests(unittest.TestCase):
    def test_actual_worker_caller_includes_helper_work_and_rejects_late_return(self):
        worker = next(node for node in ast.parse(DRIVER.read_text()).body
                      if isinstance(node, ast.FunctionDef) and node.name == '_worker_loopback')
        body = next(node.body for node in ast.walk(worker)
                    if isinstance(node, ast.While) and any(
                        isinstance(item, ast.Assign) and any(
                            isinstance(target, ast.Name) and target.id == 'sent'
                            for target in item.targets) for item in node.body))
        start = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'sent'
                             for target in node.targets))
        end = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'latency'
                           for target in node.targets))
        # Execute the real caller statements, including its stop and deadline
        # branches, without starting a worker or opening a socket.
        block = ast.For(target=ast.Name(id='_once', ctx=ast.Store()),
                        iter=ast.Tuple(elts=[ast.Constant(None)], ctx=ast.Load()),
                        body=body[start:end + 1], orelse=[])
        code = compile(ast.fix_missing_locations(ast.Module(body=[block], type_ignores=[])),
                       str(DRIVER), 'exec')
        for delay in (800_000_000, 2_000_000_001):
            with self.subTest(delay_ns=delay):
                clock = FakeClock()
                payload = b'complete echoed frame'

                def exchange(_client, _server, data, _deadline):
                    clock.advance(delay)
                    return data

                namespace = {'time': types.SimpleNamespace(monotonic_ns=clock.now),
                             '_loopback_echo_exchange': exchange, 'client': None,
                             'connection': None, 'payload_bytes': payload, 'require': require}
                if delay > 2_000_000_000:
                    with self.assertRaises(PressureError):
                        exec(code, namespace)
                else:
                    exec(code, namespace)
                    self.assertEqual(namespace['latency'], delay)

    def test_partial_four_direction_io_eagain_and_caller_timestamps(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        payload = b'frame-id-and-seeded-body'
        server.expected_receive_size = len(payload)
        client.expected_receive_size = len(payload)
        client.fail_sends = server.fail_sends = client.fail_recvs = server.fail_recvs = 1
        waiter, waits = fake_waiter(clock, first_delay_ns=800_000_000)
        start = clock.now()
        result = timed_exchange(EXCHANGE, client, server, payload, clock, waiter)
        sent, received, echoed = result
        self.assertEqual(sent, start)
        self.assertGreaterEqual(received - sent, 800_000_000)
        self.assertEqual(echoed, payload)
        self.assertEqual(bytes(client.sent), payload)
        self.assertEqual(bytes(server.received), payload)
        self.assertEqual(bytes(server.sent), payload)
        self.assertEqual(bytes(client.received), payload)
        self.assertLess(sent, client.first_send_attempt_ns)
        self.assertEqual(received, clock.now())
        self.assertGreaterEqual(server.first_send_ns, server.full_receive_ns)
        self.assertGreater(received, sent)
        self.assertGreater(len(waits), 1)
        self.assertLessEqual(max(waits), 0.05)

    def test_helper_return_and_frame_assembly_delay_stay_inside_rtt(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        payload = b'delay-frame'
        server.expected_receive_size = client.expected_receive_size = len(payload)
        waiter, _ = fake_waiter(clock)
        old_bytes = EXCHANGE_GLOBALS.get('bytes')
        conversion_count = [0]
        def slow_bytes(value):
            result = bytes(value)
            if isinstance(value, bytearray) and len(value) == len(payload):
                conversion_count[0] += 1
                if conversion_count[0] == 2:
                    clock.advance(600_000)
            return result
        EXCHANGE_GLOBALS['bytes'] = slow_bytes
        try:
            helper_return = [None]
            def delayed_helper(*args, **kwargs):
                result = EXCHANGE(*args, **kwargs)
                helper_return[0] = clock.now()
                clock.advance(700_000)
                return result
            sent, received, echoed = timed_exchange(delayed_helper, client, server, payload, clock, waiter)
        finally:
            if old_bytes is None:
                EXCHANGE_GLOBALS.pop('bytes', None)
            else:
                EXCHANGE_GLOBALS['bytes'] = old_bytes
        self.assertEqual(echoed, payload)
        self.assertEqual(conversion_count[0], 2)
        self.assertGreaterEqual(received - sent, 1_300_000)
        self.assertGreaterEqual(received, helper_return[0] + 700_000)

    def test_final_receive_after_absolute_deadline_rejects(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        payload = b'late-read-frame'
        client.expected_receive_size = len(payload)
        client.delay_after_full_receive_ns = 2_000_000_001
        waiter, _ = fake_waiter(clock)
        with self.assertRaisesRegex(PressureError, 'after final receive'):
            timed_exchange(EXCHANGE, client, server, payload, clock, waiter)

    def test_frame_assembly_crossing_absolute_deadline_rejects(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        payload = b'late-assembly-frame'
        waiter, _ = fake_waiter(clock)
        old_bytes = EXCHANGE_GLOBALS.get('bytes')
        conversion_count = [0]
        def slow_final_assembly(value):
            result = bytes(value)
            if isinstance(value, bytearray) and len(value) == len(payload):
                conversion_count[0] += 1
                if conversion_count[0] == 2:
                    clock.advance(2_000_000_001)
            return result
        EXCHANGE_GLOBALS['bytes'] = slow_final_assembly
        try:
            with self.assertRaisesRegex(PressureError, 'after frame assembly'):
                timed_exchange(EXCHANGE, client, server, payload, clock, waiter)
        finally:
            if old_bytes is None:
                EXCHANGE_GLOBALS.pop('bytes', None)
            else:
                EXCHANGE_GLOBALS['bytes'] = old_bytes
        self.assertEqual(conversion_count[0], 2)

    def test_post_helper_descheduling_is_checked_at_caller_timestamp(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        payload = b'post-helper-delay'
        waiter, _ = fake_waiter(clock)
        def delayed_helper(*args, **kwargs):
            echoed = EXCHANGE(*args, **kwargs)
            clock.advance(2_000_000_001)
            return echoed
        with self.assertRaisesRegex(PressureError, 'caller deadline'):
            timed_exchange(delayed_helper, client, server, payload, clock, waiter)

    def test_timeout_is_bounded_and_waits_without_busy_spin(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        waiter, waits = fake_waiter(clock, never_ready=True)
        with self.assertRaises(PressureError):
            timed_exchange(EXCHANGE, client, server, b'bounded-frame', clock, waiter)
        self.assertLessEqual(clock.now() - 1_000_000, 2_000_000_100)
        self.assertLessEqual(len(waits), 45)

    def test_absolute_deadline_still_expires_after_partial_progress(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        def block_after_first_client_write():
            client.writes_enabled = False
            server.writes_enabled = False
        client.on_send = block_after_first_client_write
        waiter, waits = fake_waiter(clock)
        with self.assertRaisesRegex(PressureError, '2s I/O bound'):
            timed_exchange(EXCHANGE, client, server, b'partial-progress-frame', clock, waiter)
        self.assertGreater(len(client.sent), 0)
        self.assertLessEqual(clock.now() - 1_000_000, 2_000_000_100)
        self.assertLessEqual(len(waits), 45)

    def test_stop_is_observed_during_each_pump_stage(self):
        stages = ('client_send', 'server_receive', 'server_send', 'client_receive')
        for stage in stages:
            with self.subTest(stage=stage):
                clock = FakeClock()
                client, server = paired_sockets(clock)
                stopped = [False]
                if stage == 'client_send': client.on_send = lambda: stopped.__setitem__(0, True)
                elif stage == 'server_receive': server.on_receive = lambda: stopped.__setitem__(0, True)
                elif stage == 'server_send': server.on_send = lambda: stopped.__setitem__(0, True)
                else: client.on_receive = lambda: stopped.__setitem__(0, True)
                waiter, _ = fake_waiter(clock)
                result = timed_exchange(EXCHANGE, client, server, b'long-enough-to-force-partial-progress', clock,
                                        waiter, stop_requested=lambda: stopped[0])
                self.assertIsNone(result)

    def test_maximum_supported_frame_uses_partial_progress_on_both_legs(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        client.max_send, client.max_recv = 8191, 4093
        server.max_send, server.max_recv = 4093, 8191
        payload = bytes((i * 17) & 0xff for i in range(65536))
        server.expected_receive_size = len(payload)
        waiter, _ = fake_waiter(clock)
        sent, received, echoed = timed_exchange(EXCHANGE, client, server, payload, clock, waiter)
        self.assertEqual(sent, client.first_send_attempt_ns)
        self.assertGreater(received, sent)
        self.assertEqual(echoed, payload)
        self.assertEqual(bytes(server.received), payload)
        self.assertEqual(bytes(server.sent), payload)
        self.assertEqual(bytes(client.received), payload)
        self.assertGreaterEqual(server.first_send_ns, server.full_receive_ns)

    def test_eof_fails_instead_of_returning_a_partial_echo(self):
        for endpoint in ('server', 'client'):
            with self.subTest(endpoint=endpoint):
                clock = FakeClock()
                client, server = paired_sockets(clock)
                if endpoint == 'client': client.eof = True
                else: server.eof = True
                waiter, _ = fake_waiter(clock)
                with self.assertRaisesRegex(PressureError, 'closed'):
                    timed_exchange(EXCHANGE, client, server, b'frame', clock, waiter)

    def test_corrupt_echo_is_rejected_by_preserved_caller_check(self):
        clock = FakeClock()
        client, server = paired_sockets(clock)
        server.corrupt_send = True
        waiter, _ = fake_waiter(clock)
        payload = b'client-request-frame'
        sent, received, echoed = timed_exchange(EXCHANGE, client, server, payload, clock, waiter)
        self.assertNotEqual(echoed, payload)
        self.assertGreater(received, sent)
        with self.assertRaises(PressureError):
            require(echoed == payload, 'loopback echo payload differs from the seeded request')

    def test_setup_failure_closes_all_created_sockets_before_any_worker_output(self):
        class SetupSocket:
            def __init__(self, name, fail_nonblocking=False):
                self.name = name
                self.fail_nonblocking = fail_nonblocking
                self.closed = 0
                self.sent = 0
                self.received = 0
            def setsockopt(self, *args): pass
            def bind(self, *args): pass
            def listen(self, *args): pass
            def settimeout(self, *args): pass
            def getsockname(self): return ('127.0.0.1', 23456)
            def connect(self, *args): pass
            def accept(self): return accepted, ('127.0.0.1', 23457)
            def getpeername(self): return ('127.0.0.1', 23456)
            def setblocking(self, value):
                if self.fail_nonblocking and value is False:
                    raise OSError('scripted setup failure')
            def close(self): self.closed += 1
        listener = SetupSocket('listener')
        client = SetupSocket('client')
        accepted = SetupSocket('accepted', fail_nonblocking=True)
        sockets = iter((listener, client))
        fake_socket = types.SimpleNamespace(
            AF_INET=2, SOCK_STREAM=1, SOL_SOCKET=1, SO_REUSEADDR=2,
            IPPROTO_TCP=6, TCP_NODELAY=1, socket=lambda *args: next(sockets),
        )
        worker, env, _ = load_function(DRIVER, '_worker_loopback', {
            'socket': fake_socket,
            'os': types.SimpleNamespace(stat=lambda _path: types.SimpleNamespace(st_ino=1)),
            '_worker_emit': lambda value: emitted.append(value),
        })
        emitted = []
        with self.assertRaisesRegex(OSError, 'scripted setup failure'):
            worker(types.SimpleNamespace())
        self.assertEqual([listener.closed, client.closed, accepted.closed], [1, 1, 1])
        self.assertEqual([listener.sent, client.sent, accepted.sent], [0, 0, 0])
        self.assertEqual([listener.received, client.received, accepted.received], [0, 0, 0])
        self.assertEqual(emitted, [])


if __name__ == '__main__':
    unittest.main()
