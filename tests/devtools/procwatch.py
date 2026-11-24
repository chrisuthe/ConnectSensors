"""A subprocess whose output lines a test can wait on, instead of sleeping."""

from __future__ import annotations

import re
import subprocess
import threading
import time


class Watched:
    def __init__(self, argv: list[str], stdin: bool = False, merge_stderr: bool = True):
        """With merge_stderr False, stderr is kept apart in err_lines and lines holds stdout only."""
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
                                     text=True, bufsize=1)
        self.lines: list[str] = []
        self.err_lines: list[str] = []
        self._cond = threading.Condition()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        self._err_reader = None
        if not merge_stderr:
            self._err_reader = threading.Thread(target=self._read_err, daemon=True)
            self._err_reader.start()

    def _read_err(self) -> None:
        for line in self.proc.stderr:
            self.err_lines.append(line.rstrip("\n"))

    def _read(self) -> None:
        for line in self.proc.stdout:
            with self._cond:
                self.lines.append(line.rstrip("\n"))
                self._cond.notify_all()
        with self._cond:
            self._cond.notify_all()

    def mark(self) -> int:
        """Position to pass as since=, so a wait only sees lines printed after now."""
        with self._cond:
            return len(self.lines)

    def wait_for(self, pattern: str, timeout: float = 5.0, since: int = 0) -> re.Match | None:
        """The first line at or after since that matches pattern, waiting up to timeout."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        pos = since
        with self._cond:
            while True:
                for i in range(pos, len(self.lines)):
                    m = rx.search(self.lines[i])
                    if m:
                        return m
                pos = len(self.lines)
                left = deadline - time.monotonic()
                if left <= 0 or (self.proc.poll() is not None and not self._reader.is_alive()):
                    return None
                self._cond.wait(left)

    def wait_latest(self, pattern: str, good: str, timeout: float = 5.0, since: int = 0,
                    settle: float = 1.0) -> bool:
        """Wait until the newest line matching pattern also matches good, and has for
        settle seconds: for a state that can flip back, such as a proxy withdrawing
        downlinks after a loop stall, which it reports on the pass after the stall."""
        rx, ok = re.compile(pattern), re.compile(good)
        deadline = time.monotonic() + timeout
        good_since = None
        with self._cond:
            while True:
                latest = next((x for x in reversed(self.lines[since:]) if rx.search(x)), None)
                now = time.monotonic()
                if latest is not None and ok.search(latest):
                    good_since = good_since or now
                    if now - good_since >= settle:
                        return True
                else:
                    good_since = None
                left = deadline - now
                if left <= 0 or (self.proc.poll() is not None and not self._reader.is_alive()):
                    return False
                self._cond.wait(min(left, 0.1))

    def send(self, line: str) -> None:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def stop(self) -> str:
        """Terminate (or let finish) the process and return everything it printed."""
        if self.proc.poll() is None:
            if self.proc.stdin:
                try:
                    self.proc.stdin.close()
                except OSError:
                    pass
            self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self._reader.join(timeout=5)
        if self._err_reader is not None:
            self._err_reader.join(timeout=5)
        return "\n".join(self.lines)
