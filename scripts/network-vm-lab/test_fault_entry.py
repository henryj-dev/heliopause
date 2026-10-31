#!/usr/bin/env python3
import threading
import unittest
from fault_entry import boundary_event, holder, park


class SynchronousBarrier(unittest.TestCase):
    """The thread that reaches the boundary must not pass it, even when the stop does not hold."""

    def run_through(self, at, point):
        calls, release, passed = [], threading.Event(), threading.Event()
        # `freeze` returns at once: the case where SIGSTOP lands late or SIGCONT resumes the process.
        event = boundary_event(lambda a: calls.append(('production', a)), point,
                               lambda a: calls.append(('record', a)), lambda: calls.append(('freeze',)), release.wait)

        def worker():  # Executor.save: durable write, then event, then the next step
            event(at)
            passed.set()
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return calls, release, passed, thread

    def test_the_reaching_thread_is_held_after_record_and_freeze(self):
        calls, release, passed, thread = self.run_through('awaiting-confirm', 'awaiting-confirm')
        self.assertFalse(passed.wait(0.3), 'thread passed the boundary')
        self.assertTrue(thread.is_alive())
        self.assertEqual(calls, [('production', 'awaiting-confirm'), ('record', 'awaiting-confirm'), ('freeze',)])
        release.set(); thread.join(2)

    def test_other_boundaries_pass_through(self):
        calls, release, passed, thread = self.run_through('configured', 'awaiting-confirm')
        self.assertTrue(passed.wait(2))
        self.assertEqual(calls, [('production', 'configured')])


class Release(unittest.TestCase):
    """`stop` lets a graceful stop run the Agent's own shutdown from the boundary (review MAJOR 2)."""

    def test_never_is_the_permanent_park(self):
        self.assertIs(holder('never', lambda: self.fail('stop event is not consulted')), park)

    def test_stop_holds_until_the_agent_is_asked_to_stop(self):
        stop, passed = threading.Event(), threading.Event()
        event = boundary_event(lambda a: None, 'prepared', lambda a: None, lambda: None, holder('stop', lambda: stop))
        thread = threading.Thread(target=lambda: (event('prepared'), passed.set()), daemon=True)
        thread.start()
        self.assertFalse(passed.wait(0.3), 'thread passed the boundary before the stop')
        stop.set()
        self.assertTrue(passed.wait(2), 'stop did not release the boundary')


if __name__ == '__main__':
    unittest.main()
