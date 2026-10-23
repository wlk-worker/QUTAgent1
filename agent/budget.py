"""Wall-clock bounds include DNS, headers and slow response bodies."""
import queue
import threading
import time


class BudgetExpired(TimeoutError):
    pass


def remaining(deadline, ceiling=90.0, clock=time.monotonic):
    seconds = ceiling if deadline is None else min(ceiling, deadline - clock())
    if seconds <= 0:
        raise BudgetExpired("deadline")
    return seconds


def bounded_call(function, seconds):
    """Abandon a stalled daemon worker; a timed-out mutation may still occur."""
    output = queue.Queue(maxsize=1)

    def worker():
        try:
            output.put((True, function()))
        except BaseException as exc:
            output.put((False, exc))

    threading.Thread(target=worker, daemon=True).start()
    try:
        ok, value = output.get(timeout=seconds)
    except queue.Empty:
        raise BudgetExpired("operation_deadline") from None
    if not ok:
        raise value
    return value


def wait(seconds, deadline, sleep=time.sleep, clock=time.monotonic):
    if seconds >= remaining(deadline, float("inf"), clock):
        raise BudgetExpired("retry_exceeds_deadline")
    sleep(seconds)
