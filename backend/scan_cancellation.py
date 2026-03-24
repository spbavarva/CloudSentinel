from __future__ import annotations

import subprocess
import threading
from typing import Any, Callable


class ScanCancelledError(RuntimeError):
    """Raised when a user explicitly stops an in-flight scan."""


class ScanCancellationRegistry:
    """Tracks live scan sessions and their cancellation state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, threading.Event] = {}
        self._active_jobs: dict[str, int] = {}
        self._processes: dict[str, set[subprocess.Popen[Any]]] = {}

    def begin_job(self, session_id: str) -> None:
        with self._lock:
            self._events.setdefault(session_id, threading.Event())
            self._active_jobs[session_id] = self._active_jobs.get(session_id, 0) + 1

    def finish_job(self, session_id: str) -> None:
        with self._lock:
            current = self._active_jobs.get(session_id, 0)
            if current <= 1:
                self._active_jobs.pop(session_id, None)
                self._events.pop(session_id, None)
                self._processes.pop(session_id, None)
                return
            self._active_jobs[session_id] = current - 1

    def request_cancel(self, session_id: str) -> int:
        processes: list[subprocess.Popen[Any]]
        with self._lock:
            event = self._events.setdefault(session_id, threading.Event())
            event.set()
            processes = list(self._processes.get(session_id, ()))

        for process in processes:
            self._terminate_process(process)
        return len(processes)

    def is_cancelled(self, session_id: str) -> bool:
        with self._lock:
            event = self._events.get(session_id)
            return bool(event and event.is_set())

    def has_session(self, session_id: str) -> bool:
        with self._lock:
            return (
                session_id in self._events
                or session_id in self._active_jobs
                or session_id in self._processes
            )

    def should_cancel(self, session_id: str) -> Callable[[], bool]:
        return lambda: self.is_cancelled(session_id)

    def register_process(self, session_id: str, process: subprocess.Popen[Any]) -> None:
        with self._lock:
            self._processes.setdefault(session_id, set()).add(process)

    def unregister_process(self, session_id: str, process: subprocess.Popen[Any]) -> None:
        with self._lock:
            processes = self._processes.get(session_id)
            if not processes:
                return
            processes.discard(process)
            if not processes and session_id not in self._active_jobs:
                self._processes.pop(session_id, None)

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._events.pop(session_id, None)
            self._active_jobs.pop(session_id, None)
            self._processes.pop(session_id, None)

    @staticmethod
    def _terminate_process(process: subprocess.Popen[Any]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=0.4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=0.4)
        except OSError:
            pass
