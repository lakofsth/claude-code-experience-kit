"""A matcher that does not answer is not read as "nothing selected"
(hooks/tests/INVARIANTS.md, mh-a-matcher-that-does-not-answer-selects-nothing-only-when-it-says-so).

block-unsafe-kill.sh counts a name-keyed kill by running the command's own matcher (pgrep or
pidof) in live_count(). Read by stdout alone, an exit status above 1, a timeout or a matcher that
did not start would all read as "fewer than two", and the kill would pass. A procps that rejects
`--env` (exit 2), an option the hook's own tables carry, would let `pkill --env FOO=1 NAME` pass
uncounted however many processes held NAME.

THE SITES ARE DERIVED, not hand-listed: the call sites are every `live_count(` call in the hook (read off
its python: shared_name() for pkill and pgrep-into-a-kill, and the pidof-into-a-kill path), and the rejected options are every count option of the hook's own tables (PG_COUNT_SHORT,
PG_COUNT_LONG, by an AST walk) that /usr/bin/pgrep, asked here, exits above 1 on. Each rejected
option gets the A rows below; a derived call site with no row is red.

ROWS, against this test's own sleepers (SHARED: two processes, SOLO: one):
  A  each rejected option: `pkill OPT V SHARED`, `kill $(pgrep OPT V SHARED)`, `pgrep OPT V SHARED
     | xargs kill` refused, naming the option left out; the SOLO twins silent. Only that option
     is left out (`pkill -u <a uid owning neither sleeper> OPT V SHARED` silent), and under
     --inverse a filter left out is every process (`pkill --inverse OPT V .` refused).
  S  a stub matcher first on PATH: one rejecting `-u` (exit 2, a message naming nothing) -> counted
     without -u, refused on SHARED, silent on SOLO; one that always exits 2, one that always exits
     3, one that times out, and no matcher on PATH at all -> refused, saying the count could not
     be taken; the same for pidof (exit 2 on -c, always 2, a timeout).
  C  case-blind widening (stub, because procps names the rejected option itself, so the
     fallback is reached only through a stub): the stub rejects `-u` with a message naming
     nothing; the sleepers CASE (lower case) and its upper-case twin are one process each, so
     the fallback's count is 2 only if it KEEPS -i/--ignore-case: `pkill -i -u X CASE` and
     `pkill --ignore-case -u X CASE` refused, `pkill -u X CASE` (case-sensitive: 1) silent, and
     the real pgrep refuses `pkill -i CASE` (twin proving the fixture is a positive). Mutant C5
     (WIDENING emptied) turns the first two silent.
  N  negative controls: a stub that exits 1 with no output -> silent on SHARED (whose
     real count is refused, the twin row proving the instrument sees a positive); a pgrep error
     naming the pattern or a value ("regex error", "invalid user name"), which pkill reads with
     the same code and exits on -> silent.

THIS CHECK READS THE PROCESS TABLE. Fixture: this test's own children only, named per run, tied
to this process and stopped by PID. A stub that times out is `exec sleep`, so the process the hook
kills at its timeout is the stub itself.
"""
import ast, json, os, re, shutil, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))
SHARED, SOLO = proc_name("mhme"), proc_name("mhmo")
CASE = proc_name("mhmc")
CASE_UP = CASE.upper()
PGREP = shutil.which("pgrep") or "/usr/bin/pgrep"
PIDOF = shutil.which("pidof") or "/usr/bin/pidof"
OTHER_UID = "0" if os.getuid() != 0 else "65534"     # a uid that owns none of our sleepers


def hook_py():
    src = open(HOOK).read()
    return src[src.index("<<'PY'\n") + len("<<'PY'\n"):src.index("\nPY\n")]


def tables():
    got = {}
    for node in ast.parse(hook_py()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in ("PG_ARG_SHORT", "PG_ARG_LONG", "PG_COUNT_SHORT",
                                           "PG_COUNT_LONG"):
            got[node.targets[0].id] = eval(compile(ast.Expression(node.value), "t", "eval"),
                                           {"set": set})
    if len(got) != 4:
        sys.exit("SETUP FAILED: found %s of the four option tables in %s" % (sorted(got), HOOK))
    return got


def call_sites():
    """Names of the functions (or <module>) holding a live_count( call, by an AST walk."""
    sites = []

    def walk(node, owner):
        for ch in ast.iter_child_nodes(node):
            o = ch.name if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) else owner
            if isinstance(ch, ast.Call) and getattr(ch.func, "id", None) == "live_count":
                sites.append(owner)
            walk(ch, o)
    walk(ast.parse(hook_py()), "<module>")
    return sites


def rejected_options(t):
    """Count options of the hook's tables that this host's pgrep exits above 1 on."""
    out = []
    opts = sorted("-" + c for c in t["PG_COUNT_SHORT"]) + sorted(t["PG_COUNT_LONG"])
    for o in opts:
        takes = o in t["PG_ARG_LONG"] or (len(o) == 2 and o[1] in t["PG_ARG_SHORT"])
        argv = [PGREP, o] + (["1"] if takes else []) + ["zz-no-such-name"]
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode > 1 and re.search(r"(unrecognized|invalid) option", r.stderr):
            out.append((o, takes))
    return out


def verdict(cmd, path=None):
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = path
    p = subprocess.run(["bash", HOOK], input=json.dumps({"tool_name": "Bash",
                                                         "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, env=env, timeout=60)
    if p.returncode not in (0, 2):
        return "rc%d" % p.returncode, p.stderr
    return ("DENY" if p.returncode == 2 and "BLOCKED:" in p.stderr else "pass"), p.stderr


def count(name):
    r = subprocess.run([PGREP, "-x", name], capture_output=True, text=True)
    return len([x for x in r.stdout.split() if x.isdigit()])


def stub_dir(root, name, tool, body):
    d = os.path.join(root, name)
    os.makedirs(d)
    with open(os.path.join(d, tool), "w") as fh:
        fh.write("#!/bin/bash\n" + body + "\n")
    os.chmod(os.path.join(d, tool), 0o755)
    return d + os.pathsep + os.environ["PATH"]


def no_matcher_path(root):
    """A PATH holding every program of the current PATH but pgrep and pidof (links)."""
    d = os.path.join(root, "nomatcher")
    os.makedirs(d)
    for p in os.environ["PATH"].split(os.pathsep):
        if not os.path.isdir(p):
            continue
        for f in os.listdir(p):
            if f in ("pgrep", "pidof") or os.path.lexists(os.path.join(d, f)):
                continue
            os.symlink(os.path.join(p, f), os.path.join(d, f))
    return d


def main():
    t = tables()
    sites = call_sites()
    rej = rejected_options(t)
    print("live_count call sites: %s" % sites)
    print("count options this host's pgrep rejects: %s" % [o for o, _ in rej])
    if len(sites) < 2:
        print("SETUP FAILED: fewer than two live_count( call sites read off the hook")
        return 2
    rows = []   # (label, cmd, path, expected, must_say)

    for o, takes in rej:
        v = " FOO=1" if o == "--env" else (" 1" if takes else "")
        for tmpl, lab in (("pkill %s%s %s", "pkill"), ("kill $(pgrep %s%s %s)", "kill $(pgrep)"),
                          ("pgrep %s%s %s | xargs kill", "pgrep | xargs kill")):
            rows.append(("A %s %s SHARED" % (lab, o), tmpl % (o, v, SHARED), None, "DENY",
                         "counted without " + o))
            rows.append(("A %s %s SOLO" % (lab, o), tmpl % (o, v, SOLO), None, "pass", None))
        # only the rejected option is left out: an owner filter that excludes both sleepers stays
        rows.append(("A only %s left out (-u %s kept)" % (o, OTHER_UID),
                     "pkill -u %s %s%s %s" % (OTHER_UID, o, v, SHARED), None, "pass", None))
        # under --inverse, a filter left out is every process (the pattern `.` alone selects none)
        rows.append(("A --inverse %s ." % o, "pkill --inverse %s%s ." % (o, v), None, "DENY",
                     "counted without " + o))

    root = tempfile.mkdtemp(prefix="mh-merr-")
    rej_u = stub_dir(root, "rej_u", "pgrep",
                     'for a; do [ "$a" = -u ] && { echo "pgrep: cannot read the process table" >&2; exit 2; }; '
                     'done; exec %s "$@"' % PGREP)
    rc2 = stub_dir(root, "rc2", "pgrep", 'echo "pgrep: something went wrong" >&2; exit 2')
    rc3 = stub_dir(root, "rc3", "pgrep", 'echo "pgrep: fatal" >&2; exit 3')
    slow = stub_dir(root, "slow", "pgrep", "exec sleep 30")
    none = stub_dir(root, "none", "pgrep", "exit 1")
    nomatch = no_matcher_path(root)
    p_rej_c = stub_dir(root, "p_rej_c", "pidof",
                       'for a; do [ "$a" = -c ] && exit 2; done; exec %s "$@"' % PIDOF)
    p_rc2 = stub_dir(root, "p_rc2", "pidof", "exit 2")
    p_slow = stub_dir(root, "p_slow", "pidof", "exec sleep 30")

    for opt in ("-i", "--ignore-case"):
        rows.append(("C stub rejects -u, %s kept" % opt, "pkill %s -u nosuchuserzz %s" % (opt, CASE),
                     rej_u, "DENY", "counted without -u"))
    rows += [
        ("C stub rejects -u, case-sensitive", "pkill -u nosuchuserzz %s" % CASE, rej_u, "pass", None),
        ("C real pgrep -i (twin)", "pkill -i %s" % CASE, None, "DENY", None),
    ]

    CANT = "could not be taken"
    for lab, tmpl in (("pkill", "pkill %s"), ("kill $(pgrep)", "kill $(pgrep %s)"),
                      ("pgrep | xargs kill", "pgrep %s | xargs kill")):
        rows += [
            ("S rejects -u %s SHARED" % lab, tmpl % ("-u nosuchuserzz " + SHARED), rej_u, "DENY",
             "counted without -u"),
            ("S rejects -u %s SOLO" % lab, tmpl % ("-u nosuchuserzz " + SOLO), rej_u, "pass", None),
            ("S exit 2 %s" % lab, tmpl % SHARED, rc2, "DENY", CANT),
            ("S exit 3 %s" % lab, tmpl % SOLO, rc3, "DENY", CANT),
            ("S timeout %s" % lab, tmpl % SOLO, slow, "DENY", "timed out"),
            ("S no matcher %s" % lab, tmpl % SOLO, nomatch, "DENY", CANT),
            ("N exit 1 %s SHARED" % lab, tmpl % SHARED, none, "pass", None),
            ("N real %s SHARED (twin of N)" % lab, tmpl % SHARED, None, "DENY", None),
        ]
    rows += [
        ("S pidof rejects -c SHARED", "kill $(pidof -c %s)" % SHARED, p_rej_c, "DENY",
         "counted without -c"),
        ("S pidof rejects -c SOLO", "kill $(pidof -c %s)" % SOLO, p_rej_c, "pass", None),
        ("S pidof exit 2", "kill $(pidof %s)" % SOLO, p_rc2, "DENY", CANT),
        ("S pidof timeout", "kill $(pidof %s)" % SOLO, p_slow, "DENY", "timed out"),
        ("S pidof no matcher", "kill $(pidof %s)" % SOLO, nomatch, "DENY", CANT),
        ("N pidof SOLO", "kill $(pidof %s)" % SOLO, None, "pass", None),
        # a pgrep error naming the pattern or a value: pkill reads it the same and exits, zero
        ("N regex error in the pattern", "pkill '{}%s'" % SHARED, None, "pass", None),
        ("N value error (no such user)", "pkill -u nosuchuserzz %s" % SHARED, None, "pass", None),
        ("N regex error, data to find -exec grep", "find . -name '*.sh' -exec grep -l pkill {} +",
         None, "pass", None),
    ]
    if "shared_name" not in sites or not any(s != "shared_name" for s in sites):
        print("SETUP FAILED: call sites %s are not shared_name plus the pidof path" % sites)
        return 2

    d = os.path.join(root, "bin")
    os.makedirs(d)
    shared, solo = os.path.join(d, SHARED), os.path.join(d, SOLO)
    shutil.copy2("/bin/sleep", shared); shutil.copy2("/bin/sleep", solo)
    lo, up = os.path.join(d, CASE), os.path.join(d, CASE_UP)
    shutil.copy2("/bin/sleep", lo); shutil.copy2("/bin/sleep", up)
    procs = [sleeper(shared) for _ in range(2)] + [sleeper(solo), sleeper(lo), sleeper(up)]
    try:
        for _ in range(60):
            if count(SHARED) == 2 and count(SOLO) == 1 and count(CASE) == 1 and count(CASE_UP) == 1:
                break
            time.sleep(0.1)
        else:
            print("SETUP FAILED: want 2 x %s and 1 x %s, have %d and %d"
                  % (SHARED, SOLO, count(SHARED), count(SOLO)))
            return 2
        bad = 0
        for label, cmd, path, want, say in rows:
            got, err = verdict(cmd, path)
            ok = got == want and (say is None or say in err)
            bad += not ok
            print("%s %-44s %-5s want %-5s %s" % ("ok  " if ok else "FAIL", label, got, want,
                                                  "" if ok or say is None else "(must say %r)" % say))
            if not ok and err:
                print("      " + err.strip().splitlines()[0][:200])
        print("%d rows, %d failed" % (len(rows), bad))
        return 1 if bad else 0
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
