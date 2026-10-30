#!/usr/bin/env python3
import threading
import unittest
from fault_entry import boundary_event


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


if __name__ == '__main__':
    unittest.main()
