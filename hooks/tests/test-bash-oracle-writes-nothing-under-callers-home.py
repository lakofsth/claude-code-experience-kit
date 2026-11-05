"""Check of mh-a-hooks-tests-shell-writes-nothing-under-the-callers-home (hooks/tests/INVARIANTS.md).

The sentence: a line handed to `bash_oracle.argv(...)` / `bash_oracle.run(...)` runs with a HOME
that is not the caller's real home (its passwd entry) unless the caller set HOME to a directory of
its own, with HISTFILE and every XDG_*_HOME pointing into that HOME, so a shell that saves its
history or state on exit writes nothing under the caller's home.

WHY. Without its own HOME, an interactive bash in the namespace saves its history to the
caller's HOME on exit, and the tests' fixtures (`echo RAN >m`, `echo hi`, `echo STDIN-RAN`) land
in the caller's shell history.

HOW, WITHOUT WRITING TO THE REAL HOME WHEN IT IS RED. Row 1 only reads what HOME, HISTFILE and the
XDG variables are inside the namespace, with the caller's env naming the real home for each. The
rows that run an interactive shell (2, 3) run only if row 1 held; where it did not they FAIL
unrun, so a red oracle never appends to the real history. Row 6 compares the real
~/.bash_history's stat before and after the whole test.

ROWS:
  1. caller HOME = real home, HISTFILE and XDG_*_HOME under it: none of them is under it inside;
  2. `bash -i` reading code from a pipe saves its history into the namespace's HOME (positive
     control: the marker IS in $HOME/.bash_history there, so the history was written, elsewhere);
  3. a shell whose code is the oracle's stdin (`run(["bash", "-i"], input=...)`), same, flushed
     with `history -a` so it can be read before the shell exits;
  4. a caller that sets HOME to a directory of its own keeps it;
  5. the namespace's HOME is gone once run() returns;
  6. the real ~/.bash_history is unchanged by the whole test.
"""
import os, pwd, sys, tempfile, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bash_oracle  # noqa: E402  (import after the sys.path line)

FAILS = []
REAL = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
HIST = os.path.join(REAL, ".bash_history")
XDG = ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME")


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        FAILS.append(what)


def under_real(v):
    v = os.path.realpath(v)
    return v == REAL or v.startswith(REAL.rstrip("/") + "/")


def stat_of(p):
    try:
        st = os.stat(p)
        return (st.st_ino, st.st_size, st.st_mtime_ns)
    except FileNotFoundError:
        return None


before = stat_of(HIST)
env = dict(os.environ, HOME=REAL, HISTFILE=HIST,
           **{k: os.path.join(REAL, ".x-" + k.lower()) for k in XDG})
names = ["HOME", "HISTFILE"] + list(XDG)
p = bash_oracle.run(["bash", "-c", 'for n in "$@"; do eval "printf \'%s\\n\' \\"\\${$n-}\\""; done',
                     "-"] + names, env=env, capture_output=True, text=True, timeout=30)
seen = dict(zip(names, p.stdout.splitlines()))
print("1. inside: %r" % seen)
held = p.returncode == 0 and len(seen) == len(names)
for n in names:
    ok = held and bool(seen.get(n)) and not under_real(seen[n])
    held = held and ok
    check(ok, "row 1: %s inside is not under the real home %s (%r)" % (n, REAL, seen.get(n)))

mark = "ORACLE-HOME-MARK-" + uuid.uuid4().hex[:12]
if held:
    p = bash_oracle.run(["bash", "-c", 'printf "echo %s\\n" "$1" | bash -i >/dev/null 2>&1; '
                         'grep -c -- "$1" "$HOME/.bash_history"', "-", mark],
                        env=env, capture_output=True, text=True, timeout=30)
    check(p.stdout.strip() == "1", "row 2: bash -i from a pipe saved its history in the namespace's HOME "
          "(grep -c %r)" % p.stdout.strip())
    p = bash_oracle.run(["bash", "-i"], input="echo %s\nhistory -a\ngrep -c -- %s \"$HOME/.bash_history\"\nexit\n"
                        % (mark, mark), env=env, capture_output=True, text=True, timeout=30)
    check(p.returncode == 0 and p.stdout.splitlines()[-1:] == ["1"],
          "row 3: a shell reading its code from the oracle's stdin wrote its history in the namespace's "
          "HOME (exit %d, stdout %r)" % (p.returncode, p.stdout[-80:]))
else:
    check(False, "row 2: not run -- row 1 did not hold, and an interactive shell would write to the real home")
    check(False, "row 3: not run -- row 1 did not hold")

with tempfile.TemporaryDirectory() as own:
    p = bash_oracle.run(["bash", "-c", 'printf %s "$HOME"'], env=dict(env, HOME=own),
                        capture_output=True, text=True, timeout=30)
    check(p.stdout == own, "row 4: a caller's own HOME %s is kept (%r)" % (own, p.stdout))

p = bash_oracle.run(["bash", "-c", 'printf %s "$HOME"'], env=env, capture_output=True, text=True, timeout=30)
check(bool(p.stdout) and not under_real(p.stdout) and not os.path.exists(p.stdout),
      "row 5: the namespace's HOME %r is removed once run() returns" % p.stdout)

after = stat_of(HIST)
check(before == after, "row 6: the real %s is unchanged (%r -> %r)" % (HIST, before, after))

if FAILS:
    print("FAIL: %d row(s)" % len(FAILS))
    sys.exit(1)
print("PASS")
