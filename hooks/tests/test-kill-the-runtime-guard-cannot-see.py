"""Check of mh-a-kill-the-runtime-guard-cannot-see-is-refused (hooks/tests/INVARIANTS.md).

The sentence is ONE-SIDED and LEXICAL: hooks/block-unsafe-kill.sh refuses every command whose text
holds a lister (pgrep, pidof, a ps listing piped on) together with a kill sent by a route the
run-time guard (the original's, not shipped in this kit) cannot see. So
every row here must be REFUSED, and nothing is promised about what passes. The process table plays
no part: each lister names NAME, which no process on the host carries, so the name count of
mh-every-name-keyed-kill-is-counted is silent and the refusal is the route's alone.

THE ROUTES ARE DERIVED FROM THE HOST, not written from the cases the design measured:
  - shells other than bash: every /etc/shells entry that runs `-c` code and reports no
    BASH_VERSION there (bash reads BASH_ENV, and the guard's function with it), together with
    bash_parse.SHELLS, the shells the hook reads code for;
  - interpreters: every program a `#!` line on this host's PATH directories names, that resolves
    on PATH and is not one of those shells, plus POSIX's two program-text utilities, awk (and its
    installed variants) and sed. Each one's inline-code options are read from its own help text,
    and its own signal senders from the interpreter itself: python's os and signal callables whose
    first parameter is a pid, process group, pidfd or thread and whose doc says they send a signal;
    perl's Pod::Functions entries whose description sends a signal; node's process functions whose
    first parameter is `pid`. An interpreter with none (tclsh, awk, sed) signals through a shell
    it runs, which is the row it gets. So a new interpreter, or a new sender in one, that the
    hook's INTERP_KILL does not match turns this file red;
  - kill, pkill and killall by every path `which -a` finds, and by /bin and /usr/bin.
Nothing here signals anything: only the hook is run, and the interpreters only to describe
themselves.
"""
import glob, json, os, re, shutil, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(os.path.dirname(HERE), "block-unsafe-kill.sh")
sys.path.insert(0, os.path.dirname(HERE))
from bash_parse import SHELLS  # noqa: E402

NAME = "kgnone-%d" % os.getpid()
LISTERS = ["pgrep -f %s" % NAME, "pgrep -x %s" % NAME, "pidof %s" % NAME,
           "ps aux | grep %s | awk '{print $2}'" % NAME]


def probe(argv, stdin=""):
    try:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None


def non_bash_shells():
    out = set(SHELLS) - {"bash"}
    for line in open("/etc/shells"):
        line = line.strip()
        if not line.startswith("/") or not os.access(line, os.X_OK):
            continue
        p = probe(bash_oracle.argv([line, "-c", 'echo "${BASH_VERSION-}"; exit 7']))
        if p is not None and p.returncode == 7 and not p.stdout.strip():
            out.add(os.path.basename(line))
    return sorted(out)


def shebang_interpreters(shells):
    names = set()
    for d in ("/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin"):
        for f in glob.glob(os.path.join(d, "*")):
            try:
                with open(f, "rb") as fh:
                    head = fh.readline(200)
            except OSError:
                continue
            if not head.startswith(b"#!"):
                continue
            w = head[2:].decode("latin-1").split()
            if not w:
                continue
            n = os.path.basename(w[0])
            if n == "env":
                w = [x for x in w[1:] if not x.startswith("-")]
                if not w:
                    continue
                n = os.path.basename(w[0])
            names.add(n)
    names |= {"awk", "gawk", "mawk", "nawk", "sed"}
    return sorted(n for n in names
                  if shutil.which(n) and n not in shells and n not in ("bash", "rbash", "env"))


# An option whose own description says it takes the program TEXT: python's "program passed in as
# string", perl's "one line of program", node's "evaluate script". Not `-i ... after running
# script` or `-m ... module as a script`, which name a script without taking one.
CODE_OPT = re.compile(r"^\s*(-[A-Za-z])\b[ ,][^\n]*(?:\b(?:program|script|cmd|code)\b[^\n]*"
                      r"\b(?:as string|as a string)\b|\bone line of (?:program|script)\b|"
                      r"\bevaluate script\b)", re.M)


def code_options(n):
    """The inline-code options n's own help names (`-c cmd : program passed in as string`)."""
    opts = set()
    for flag in ("--help", "-h"):
        p = probe([n, flag])
        if p is not None:
            opts |= {m.group(1) for m in CODE_OPT.finditer(p.stdout + p.stderr)}
    return sorted(opts)


def senders(n):
    """(interpreter, the code of one kill per signal sender the interpreter itself names)."""
    base = re.sub(r"[\d.]+$", "", n)
    if base == "python":
        p = probe(bash_oracle.argv([n, "-c", r"""
import inspect, os, signal
for mod in (os, signal):
    for k in dir(mod):
        f = getattr(mod, k)
        try:
            first = next(iter(inspect.signature(f).parameters))
        except Exception:
            continue
        said = (f.__doc__ or "").strip().split(".")[0].lower()
        if first in ("pid", "pgid", "pidfd", "thread_id") and "signal" in said and (
                "send" in said or "kill" in said):
            print(mod.__name__, k)
"""]))
        found = [l.split() for l in p.stdout.split("\n") if l.strip()] if p else []
        return ["import os,signal,sys\nfor x in sys.stdin: %s.%s(%s, 15)" % (
            m, k, "os.pidfd_open(int(x))" if k.startswith("pidfd") else "int(x)") for m, k in found]
    if base.startswith("perl"):
        p = probe([n, "-MPod::Functions", "-e",
                   'for (sort keys %Flavor) { print "$_\\n" if $Flavor{$_} =~ /send.*signal/i }'])
        return ["%s 15, $_" % k for k in (p.stdout.split() if p else [])]
    if base in ("node", "nodejs"):
        p = probe([n, "-e", 'for (const k of Object.getOwnPropertyNames(process)) {'
                   ' const f = process[k]; if (typeof f === "function" &&'
                   ' /^function \\w*\\(pid\\b/.test(f.toString())) console.log(k) }'])
        return ["require('readline').createInterface({input: process.stdin})"
                ".on('line', l => process.%s(+l, 15))" % k for k in (p.stdout.split() if p else [])]
    if base in ("awk", "gawk", "mawk", "nawk"):
        return ['{system("kill " $1)}', '{print "kill " $1 | "sh"}']
    if base == "sed":
        return ["s/^/kill /e"]
    if base == "tclsh":
        return ["foreach p [split [read stdin]] {exec kill $p}"]
    return ["kill 15 $pid"]                     # a language this file cannot ask: its own word


def q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def routes():
    shells = non_bash_shells()
    rows = []
    for sh in shells:
        rows += [("shell %s" % sh, "%s -c 'kill \"$SRV\"'" % sh),
                 ("shell %s" % sh, "%s -c 'pkill -x other'" % sh),
                 ("shell %s" % sh, "echo 'kill \"$SRV\"' | %s" % sh),
                 ("shell %s" % sh, "%s <<< 'kill \"$SRV\"'" % sh),
                 ("shell %s" % sh, "%s <<'EOF'\nkill \"$SRV\"\nEOF" % sh),
                 ("shell %s" % sh, "{L} | %s -c 'xargs kill'" % sh)]
    rows += [("/bin/sh runner", "watch -n1 'kill \"$SRV\"'"),
             ("/bin/sh runner", "echo 'kill \"$SRV\"' | at now"),
             ("/bin/sh runner", "git rebase -x 'kill \"$SRV\"' HEAD~1")]
    for host in ("localhost", "otherhost"):
        rows += [("ssh", "ssh %s kill \"$SRV\"" % host), ("ssh", "{L} | ssh %s xargs kill" % host),
                 ("ssh", "ssh %s 'kill \"$SRV\"'" % host)]
    rows += [("mosh", "mosh otherhost -- kill \"$SRV\"")]
    for pr in ("sudo", "doas", "pkexec", "run0"):
        rows += [("privilege", "%s kill \"$SRV\"" % pr), ("privilege", "{L} | %s xargs kill" % pr)]
    rows += [("privilege", "su -c 'kill \"$SRV\"'"), ("privilege", "runuser -u u -- kill \"$SRV\""),
             ("privilege", "runuser -u u -c 'kill \"$SRV\"'"),
             ("privilege", "sudo bash -c 'kill \"$SRV\"'")]
    for e in ("env -i", "env -", "env --ignore-environment", "env -iC /"):
        rows += [("env -i", "%s kill \"$SRV\"" % e), ("env -i", "{L} | %s xargs kill" % e)]
    rows += [("env -i", "env -i bash -c 'kill \"$SRV\"'")]
    for k in ("kill", "pkill", "killall"):
        paths = set(subprocess.run(["which", "-a", k], capture_output=True, text=True).stdout.split())
        paths |= {"/bin/" + k, "/usr/bin/" + k}
        arg = "\"$SRV\"" if k == "kill" else "-x other"
        for p in sorted(paths):
            rows += [("path", "%s %s" % (p, arg)), ("path", "{L} | xargs %s" % p),
                     ("path", "find . -maxdepth 0 -exec %s %s \\;" % (p, arg))]
    rows += [("skips the function", "builtin kill \"$SRV\""),
             ("skips the function", "command kill \"$SRV\""),
             ("skips the function", "unset -f kill; kill \"$SRV\""),
             ("skips the function", "KILL_GUARD_RUNTIME=0 kill \"$SRV\""),
             ("skips the function", "KILL_GUARD_RUNTIME=0; kill \"$SRV\""),
             ("skips the function", "CLAUDE_PID= kill \"$SRV\""),
             ("skips the function", "env -u CLAUDE_PID kill \"$SRV\""),
             ("skips the function", "unset KILL_GUARD_RUNTIME; kill \"$SRV\""),
             ("skips the function", "export BASH_ENV=; bash -c 'kill \"$SRV\"'")]
    interps = shebang_interpreters(set(shells))
    for n in interps:
        opts = code_options(n)
        for code in senders(n):
            if opts:
                for o in opts:
                    rows.append(("interpreter %s" % n, "{L} | %s %s %s" % (n, o, q(code))))
            elif os.path.basename(n) in ("awk", "gawk", "mawk", "nawk", "sed"):
                rows.append(("interpreter %s" % n, "{L} | %s %s" % (n, q(code))))
            rows += [("interpreter %s" % n, "{L} > f; %s <<'EOF'\n%s\nEOF" % (n, code)),
                     ("interpreter %s" % n, "{L} > f; %s <<< %s" % (n, q(code))),
                     ("interpreter %s" % n, "{L} > f; printf '%%s\\n' %s | %s" % (q(code), n))]
    return rows, shells, interps


def verdict(cmd):
    p = subprocess.run(["bash", HOOK], input=json.dumps({"tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode


def cases(rows):
    out = []
    for kind, r in rows:
        for L in LISTERS:
            if "{L}" in r:
                out.append((kind, r.replace("{L}", L)))
            else:
                out += [(kind, "%s; %s" % (L, r)), (kind, "%s && %s" % (r, L))]
    return out


def main():
    rows, shells, interps = routes()
    kinds = {k for k, _ in rows}
    for need in ("shell sh", "shell dash", "interpreter python3", "interpreter perl"):
        if need not in kinds:                   # the derivation itself is the thing under test
            print("FAIL: the derivation found no %r on this host" % need)
            return 1
    # The instrument's control: a plain kill by PID beside the same listers is not refused, so a
    # refusal below is the route's and not the lister's alone.
    ctl = [c for _, c in cases([("control", "kill \"$SRV\"")])]
    with ThreadPoolExecutor(8) as ex:
        bad_ctl = [c for c, rc in zip(ctl, ex.map(verdict, ctl)) if rc != 0]
    if bad_ctl:
        print("FAIL: the control was refused, so this file cannot tell a route's refusal apart:")
        for c in bad_ctl:
            print("   ", c.replace("\n", "\\n"))
        return 1
    todo = cases(rows)
    with ThreadPoolExecutor(8) as ex:
        got = list(ex.map(verdict, [c for _, c in todo]))
    missed = [(k, c) for (k, c), rc in zip(todo, got) if rc != 2]
    for k, c in missed:
        print("NOT REFUSED [%s]: %s" % (k, c.replace("\n", "\\n")))
    print("shells other than bash: %s; interpreters: %s" % (" ".join(shells), " ".join(interps)))
    if missed:
        print("FAIL: %d of %d not refused" % (len(missed), len(todo)))
        return 1
    print("OK: %d cases (%d routes, %d listers, each placement), every one refused" % (
        len(todo), len(rows), len(LISTERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
