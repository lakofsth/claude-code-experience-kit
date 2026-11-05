"""Per-run process names for the hook tests — sleeper comm names must be unique per test RUN.

The sleeper fixtures start `cp /bin/sleep <name>` children and count them with a HOST-WIDE
`pgrep -x <name> == 2`. With a fixed comm name, two concurrent suites (or a suite and a stale
sleeper) would see 4 and fail their setup. A per-run
suffix makes each run count only its own sleepers; stems keep the names recognizable in ps.

comm truncates at 15 chars, so a stem plus the 6-hex-digit pid suffix must stay <= 15. The suffix
is pid mod 2**24: injective for any pid_max up to 16777216 (the kernel maximum is 4194304), so
two live runs can never share a suffix.

sleeper() starts one such child that lives exactly as long as the test that started it: no finite
lifetime (a timed sleep can expire on a loaded host before the rows that count it run), and the
kernel ends it when its parent dies (PR_SET_PDEATHSIG),
so a test killed by its timeout leaves no sleeper behind. Teardown still stops it by its pid.
"""
import ctypes
import os
import signal
import subprocess

_PR_SET_PDEATHSIG = 1
_libc = ctypes.CDLL(None, use_errno=True)

_SUFFIX = "%06x" % (os.getpid() % 0x1000000)


def proc_name(stem):
    """A comm name: `stem` (keep it <= 9 chars) + this run's suffix."""
    name = stem + _SUFFIX
    assert len(name) <= 15, f"comm truncates at 15: {name!r}"
    return name


def tied(argv, **kw):
    """Popen of argv, SIGKILLed by the kernel when this process dies; a parent already gone by
    the time the child is tied makes the child exit."""
    parent = os.getpid()

    def tie():
        _libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        if os.getppid() != parent:
            os._exit(1)

    return subprocess.Popen(argv, preexec_fn=tie, **kw)


def sleeper(exe, **kw):
    """`exe infinity` (exe a copy of /bin/sleep), tied to this process."""
    return tied([exe, "infinity"], **kw)


# The same tie, for a fixture that is itself a python starting sleepers: a child it runs with
# preexec_fn=TIE_SRC's `tie` dies with it, as it dies with us.
TIE_SRC = "import ctypes; tie = lambda: ctypes.CDLL(None).prctl(1, 9); "
