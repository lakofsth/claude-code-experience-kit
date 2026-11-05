"""Check of mh-a-kill-the-runtime-guard-cannot-see-is-refused (hooks/tests/INVARIANTS.md), written
from the SENTENCE alone.

The sentence is one-sided: hooks/block-unsafe-kill.sh REFUSES every command whose text holds a
process lister together with a kill sent by a route the run-time guard cannot see. So every row
below must be refused (exit 2). Nothing is promised about what passes; the one control row (a plain
`kill PID` beside the same listers, which the run-time guard does see) must stay silent only so
that a hook refusing everything cannot make this file green.

Every direction the sentence names is a row family, and each family is asked with every kill word
the sentence names where the route carries a kill COMMAND (`kill`, `pkill`, `killall`), every
lister it names (a `pgrep`, a `pidof`, a `ps` piped on), and three placements of the lister:
before the kill in the same command, as the kill's own pid source (`$(...)` or a pipe), and inside
code the guard reads as code (a `bash -c` string beside the kill). The process names are of no
live process, so no name count is what refuses: the route is.

  shells other than bash  -c string; pipe (echo, printf); herestring; heredoc — for sh, dash,
                          zsh, ksh, mksh, posh, busybox sh, fish, csh, tcsh and paths to sh/dash
  SH_RUNNER strings       watch (quoted and as bare words), at, batch (pipe, herestring,
                          heredoc), git (alias `!`, core.pager, core.sshCommand, core.editor,
                          `git config ... && git ...`), sg (bare and -c), newgrp (its
                          command operand, and -c; on a util-linux host newgrp(1) is util-linux's, whose
                          command is the string it hands on — with none it starts the login
                          shell on stdin, which is not the string the sentence names)
  another login           ssh and mosh, to any host, bare words and one quoted string, options
                          before the host, `--`
  privilege               sudo (and -u, -E, -n), doas, su -c, runuser (-u --, -l -c), pkexec,
                          run0, env -i in every spelling (-i, -, --ignore-environment, a cluster
                          such as -iu, with assignments after)
  by a path               /bin/, /usr/bin/, ./, /usr/local/bin/
  builtin / command       builtin, command, command -p
  tamper beside a kill    unset -f kill; an assignment to, unset of, or export of each of
                          KILL_GUARD_RUNTIME, CLAUDE_PID, BASH_ENV (prefix assignment, own
                          statement, export NAME=, export NAME, unset NAME)
  interpreters            argv, herestring, heredoc, echo pipe, printf pipe — for python3, perl,
                          ruby, node, php, lua, tclsh, awk, gawk, sed, and a program of no known
                          name — whose code holds `kill`, `pkill`, `<x>.kill`, `_kill`, `killpg`
                          or `send_signal` (kill after no letter but p).

Nothing is signalled: only the hook is run, with the command as its Bash tool input.
"""
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from bash_parse import SHELLS  # noqa: E402  the shells whose code the guard reads as code
HOOK = os.path.join(os.path.dirname(HERE), "block-unsafe-kill.sh")
N = "kgsent%d" % os.getpid()
PID = "48213"

KILLS = ["kill %s" % PID, "kill -9 %s" % PID, "pkill -x %s" % N, "killall %s" % N]
LISTERS = ["pgrep -x %s" % N, "pidof %s" % N, "ps -e | grep %s" % N]


def placements(route_of, pid_source):
    """route_of(kill_cmd) -> the route command. Yields (placement, full command)."""
    for lister in LISTERS:
        for k in KILLS:
            yield "before", "%s; %s" % (lister, route_of(k))
            yield "as-code", "bash -c '%s'; %s" % (lister.replace("'", ""), route_of(k))
        # the lister as the kill's own pid source: asked only where the kill stands in code the
        # guard reads as code (the sentence's lister clause), so not inside a string handed to a
        # shell the guard does not read, another login's quoted string, or a SH_RUNNER's string
        if pid_source:
            yield "pid-source", route_of("kill $(%s)" % lister)


def sq(s):
    return "'" + s.replace("'", "'\\''") + "'"


ROWS = []   # (direction, placement, command)


def fam(direction, route_of, pid_source=True):
    for pl, cmd in placements(route_of, pid_source):
        ROWS.append((direction, pl, cmd))


# 1. a shell other than bash
SHS = ["sh", "dash", "zsh", "ksh", "mksh", "posh", "fish", "csh", "tcsh", "/bin/sh", "/usr/bin/dash"]
for s in SHS:
    ps = os.path.basename(s) in SHELLS
    fam("non-bash shell -c (%s)" % s, lambda k, s=s: "%s -c %s" % (s, sq(k)), ps)
    fam("non-bash shell, echo pipe (%s)" % s, lambda k, s=s: "echo %s | %s" % (sq(k), s), ps)
    fam("non-bash shell, printf pipe (%s)" % s, lambda k, s=s: "printf '%%s\\n' %s | %s" % (sq(k), s), ps)
    fam("non-bash shell, herestring (%s)" % s, lambda k, s=s: "%s <<< %s" % (s, sq(k)), ps)
    fam("non-bash shell, heredoc (%s)" % s, lambda k, s=s: "%s <<'EOF'\n%s\nEOF" % (s, k), ps)
fam("non-bash shell -c (busybox sh)", lambda k: "busybox sh -c %s" % sq(k), False)
fam("non-bash shell -s herestring (sh -s)", lambda k: "sh -s <<< %s" % sq(k))

# 2. the strings watch, at, batch, git, sg, newgrp hand to /bin/sh
fam("watch, quoted string", lambda k: "watch -n 1 %s" % sq(k), False)
fam("watch, bare words", lambda k: "watch -n 1 %s" % k)
fam("watch, after --", lambda k: "watch -- %s" % sq(k), False)
for prog in ("at now", "batch"):
    fam("%s, echo pipe" % prog, lambda k, p=prog: "echo %s | %s" % (sq(k), p), False)
    fam("%s, herestring" % prog, lambda k, p=prog: "%s <<< %s" % (p, sq(k)), False)
    fam("%s, heredoc" % prog, lambda k, p=prog: "%s <<'EOF'\n%s\nEOF" % (p, k), False)
fam("git alias ! (-c)", lambda k: "git -c alias.zz=%s zz" % sq("!" + k), False)
fam("git core.pager (-c)", lambda k: "git -c core.pager=%s log" % sq(k), False)
fam("git core.sshCommand (-c)", lambda k: "git -c core.sshCommand=%s fetch" % sq(k), False)
fam("git core.editor (-c)", lambda k: "git -c core.editor=%s commit" % sq(k), False)
fam("git config alias then run", lambda k: "git config alias.zz %s && git zz" % sq("!" + k), False)
fam("sg, bare string", lambda k: "sg adm %s" % sq(k), False)
fam("sg -c", lambda k: "sg adm -c %s" % sq(k), False)
fam("newgrp, command operand", lambda k: "newgrp adm %s" % sq(k), False)
fam("newgrp -c", lambda k: "newgrp -c %s adm" % sq(k), False)

# 3. another login, to any host
for r in ("ssh", "mosh"):
    fam("%s, bare words" % r, lambda k, r=r: "%s otherhost %s" % (r, k))
    fam("%s, one quoted string" % r, lambda k, r=r: "%s otherhost %s" % (r, sq(k)), False)
    fam("%s, after --" % r, lambda k, r=r: "%s otherhost -- %s" % (r, k))
fam("ssh, options before host", lambda k: "ssh -p 2222 -o BatchMode=yes alice@otherhost %s" % k)
fam("ssh, localhost", lambda k: "ssh localhost %s" % sq(k), False)

# 4. privilege and env -i
PRIV = {
    "sudo": lambda k: "sudo %s" % k,
    "sudo -u": lambda k: "sudo -u root %s" % k,
    "sudo -E": lambda k: "sudo -E %s" % k,
    "sudo -n": lambda k: "sudo -n %s" % k,
    "doas": lambda k: "doas %s" % k,
    "su -c": lambda k: "su -c %s" % sq(k),
    "su root -c": lambda k: "su root -c %s" % sq(k),
    "runuser -u --": lambda k: "runuser -u alice -- %s" % k,
    "runuser -l -c": lambda k: "runuser -l alice -c %s" % sq(k),
    "pkexec": lambda k: "pkexec %s" % k,
    "run0": lambda k: "run0 %s" % k,
    "env -i": lambda k: "env -i %s" % k,
    "env -": lambda k: "env - %s" % k,
    "env --ignore-environment": lambda k: "env --ignore-environment %s" % k,
    "env -iu cluster": lambda k: "env -iu HOME %s" % k,
    "env -i with assignment": lambda k: "env -i PATH=/usr/bin:/bin %s" % k,
    "env - with assignment": lambda k: "env - PATH=/bin %s" % k,
    "/usr/bin/env -i": lambda k: "/usr/bin/env -i %s" % k,
}
for name, f in PRIV.items():
    fam("privilege/env (%s)" % name, f)

# 5. named by a path; after builtin or command
for pre in ("/bin/", "/usr/bin/", "./", "/usr/local/bin/"):
    fam("by a path (%s)" % pre, lambda k, pre=pre: pre + k)
for pre in ("builtin ", "command ", "command -p "):
    fam("after %s" % pre.strip(), lambda k, pre=pre: pre + k)

# 6. beside unset -f kill, or an assignment to / unset / export of a guard variable
fam("beside unset -f kill", lambda k: "unset -f kill; %s" % k)
for v in ("KILL_GUARD_RUNTIME", "CLAUDE_PID", "BASH_ENV"):
    fam("tamper: prefix assignment %s" % v, lambda k, v=v: "%s=0 %s" % (v, k))
    fam("tamper: own assignment %s" % v, lambda k, v=v: "%s=; %s" % (v, k))
    fam("tamper: unset %s" % v, lambda k, v=v: "unset %s; %s" % (v, k))
    fam("tamper: export %s=" % v, lambda k, v=v: "export %s=0; %s" % (v, k))
    fam("tamper: export %s" % v, lambda k, v=v: "%s=0; export %s; %s" % (v, v, k))
    fam("tamper: after the kill %s" % v, lambda k, v=v: "%s; unset %s" % (k, v))

# 7. code handed to an interpreter that holds kill after no letter but p, or send_signal
CODES = {
    "python3": ["import os; os.kill(%s, 15)" % PID, "import os; os.killpg(%s, 15)" % PID,
                "p.send_signal(15)", "import subprocess; subprocess.run(['pkill','-x','%s'])" % N],
    "perl": ["kill 15, %s" % PID, "kill 'TERM', %s" % PID],
    "ruby": ["Process.kill(15, %s)" % PID],
    "node": ["process.kill(%s)" % PID],
    "php": ["posix_kill(%s, 15);" % PID],
    "lua": ["os.execute('kill %s')" % PID],
    "tclsh": ["exec kill %s" % PID],
    "kgnointerp": ["kill %s" % PID],
}
OPT = {"python3": "-c", "perl": "-e", "ruby": "-e", "node": "-e", "php": "-r", "lua": "-e",
       "tclsh": None, "kgnointerp": "-e"}
for prog, codes in CODES.items():
    for code in codes:
        d = "interpreter %s: %s" % (prog, code[:28])
        o = OPT[prog]
        forms = {"herestring": "%s <<< %s" % (prog, sq(code)),
                 "heredoc": "%s <<'EOF'\n%s\nEOF" % (prog, code),
                 "echo pipe": "echo %s | %s" % (sq(code), prog),
                 "printf pipe": "printf '%%s\\n' %s | %s" % (sq(code), prog)}
        if o:
            forms["argv"] = "%s %s %s" % (prog, o, sq(code))
        if prog == "python3":
            forms["heredoc, -"] = "python3 - <<'EOF'\n%s\nEOF" % code
        for form, c in forms.items():
            for lister in LISTERS:
                ROWS.append((d + " / " + form, "before", "%s; %s" % (lister, c)))
                ROWS.append((d + " / " + form, "piped", "%s | %s" % (lister, c)
                             if form == "argv" else "%s; %s" % (lister, c)))
for awk in ("awk", "gawk"):
    for lister in LISTERS:
        ROWS.append(("interpreter %s system()" % awk, "piped",
                     "%s | %s '{system(\"kill \" $1)}'" % (lister, awk)))
        ROWS.append(("interpreter %s BEGIN" % awk, "before",
                     "%s; %s 'BEGIN{system(\"kill %s\")}'" % (lister, awk, PID)))
for lister in LISTERS:
    ROWS.append(("interpreter sed e", "piped", "%s | sed 's/^/kill /e'" % lister))
    ROWS.append(("interpreter sed e command", "before", "%s; sed -n '1e kill %s' /dev/null" % (lister, PID)))
    ROWS.append(("interpreter sed, heredoc script", "before",
                 "%s; sed -f /dev/stdin /dev/null <<'EOF'\n1e kill %s\nEOF" % (lister, PID)))

CONTROLS = ["%s; kill %s" % (lister, PID) for lister in LISTERS] + \
           ["pgrep -x %s; echo done" % N, "kill %s" % PID]


def refused(cmd):
    p = subprocess.run(["bash", HOOK], input=json.dumps({"tool_name": "Bash",
                                                         "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=60)
    return p.returncode == 2, p.returncode, p.stderr.strip().splitlines()[:1]


def main():
    seen, rows = set(), []
    for r in ROWS:
        if r[2] not in seen:
            seen.add(r[2]); rows.append(r)
    with ThreadPoolExecutor(max_workers=max(2, (os.cpu_count() or 2))) as ex:
        res = list(ex.map(lambda r: refused(r[2]), rows))
        cres = list(ex.map(refused, CONTROLS))
    bad_controls = [(c, r) for c, r in zip(CONTROLS, cres) if r[0] or r[1] != 0]
    missed = [(row, r) for row, r in zip(rows, res) if not r[0]]
    by_dir = {}
    for (d, pl, c), r in zip(rows, res):
        t = by_dir.setdefault(d, [0, 0]); t[0] += 1; t[1] += 0 if r[0] else 1
    print("hook: %s — %d must-refuse rows in %d directions, %d controls" % (
        HOOK, len(rows), len(by_dir), len(CONTROLS)))
    for d in sorted(by_dir):
        tot, miss = by_dir[d]
        print("  %s %-60s %d/%d refused" % ("ok  " if not miss else "MISS", d, tot - miss, tot))
    for c, r in bad_controls:
        print("CONTROL NOT SILENT (exit %d): %r %s" % (r[1], c, r[2]))
    for (d, pl, c), r in missed:
        print("NOT REFUSED (exit %d) [%s | %s]: %r" % (r[1], d, pl, c))
    if missed or bad_controls:
        print("\nFAIL: %d of %d rows not refused, %d control(s) not silent" % (
            len(missed), len(rows), len(bad_controls)))
        sys.exit(1)
    print("\nOK: all %d rows refused, controls silent" % len(rows))


if __name__ == "__main__":
    main()
