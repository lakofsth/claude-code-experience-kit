"""A kill whose targets are the whole account or the caller's process group is refused, pkill/pgrep
-n/-o with no other criterion is refused, and pkill/pgrep long options are read the way procps
resolves them (hooks/tests/INVARIANTS.md, mh-a-whole-account-kill-is-refused).

Read only for the listers that feed it, `kill -9 -1`, `kill -- -1`, `kill 0` and `kill $(ps -u
"$USER" -o pid=)` would pass; so would `pkill -n` (counted as `pgrep -n .`, one process: the
host's newest), and `pkill --eu "$USER"` (procps reads --eu as --euid; a full-name reader would
take it for a flag and "$USER" for a process name).

NOTHING IS SIGNALLED AND THE PROCESS TABLE IS NOT READ BY THE HOOK. Every row runs the hook on the
command TEXT with a stub `pgrep` and a stub `ps` first on PATH; each prints STUB_N pids (this
test's own pid, repeated) and logs its argv, so a row pins whether the hook asked, and with what.
The only real program run is /usr/bin/pgrep, asked about OPTION SPELLINGS with a pattern that
matches nothing and a uid nobody has (pgrep sends no signal), to derive procps's own long-option
table and its prefix rule.

ROWS
  A  whole-account targets: `kill` with PID -1 (every process the sender may signal) or PID 0 (the
     sender's process group), in every grammar bash's kill and /bin/kill read a target in (after a
     signal word, `-s SIG`, `-n NUM`, `--`; through a path, sudo, `bash -c`, `trap`, xargs), and
     `kill -1` on its own: refused, the matcher never asked.
  S  an owner-selected or unselected ps listing whose pids reach a kill without a pipe (`kill
     $(ps -u "$USER" -o pid=)`, `kill $(ps -o pid=)` -- with no tty, plain ps is every process of
     the account -- `ps x`, `ps -e`, `--user`, a for loop): refused.
  N  pkill/pgrep-into-a-kill with -n/-o (any spelling, abbreviations included) and no other
     criterion: refused with the stub at ONE pid (what real pgrep -n answers), the stub never asked.
  P  procps's long-option table, derived from /usr/bin/pgrep (its --help, and the possibilities
     getopt prints for every one-letter prefix), equals the hook's PG_LONG_ALL; and every prefix of
     every option resolves in the hook's pg_long() the way pgrep resolves it (accepted when
     unique or exact, ambiguous otherwise -- each asked of the real pgrep).
  U  every unique abbreviation of --euid and --uid, separate and `=`, through pkill and
     `kill $(pgrep ...)`: refused at a stub count of 3 with the owner-only message and the stub
     asked with the full option and the session's user; silent at a count of 1 (the count decides).
     Every unique abbreviation of --full: refused as a pattern kill.
  R  Negatives, each beside a red twin above: `kill -9 <literal pid>`, `kill -- -<literal
     pgid>`, `kill %1`, `kill -1 <pid>` (SIGHUP to a pid), `kill -0 <pid>`, `kill -0 -1` and
     `kill -s 0 -1` (signal 0 sends nothing), `kill -l`, `kill -L`, `kill -l 9`, `pkill -P $$`,
     `pkill -x somename -u "$USER"` at one, `pkill -n NAME` at one, `pkill -n -P $$`, a ps listing
     by pid or parent into a kill, a ps listing with no kill, and one beside a kill it does not
     feed (`ps aux; kill 12345`).
"""
import ast, json, os, pwd, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))
REAL_PGREP = shutil.which("pgrep") or "/usr/bin/pgrep"
UID = str(os.getuid())
USER = pwd.getpwuid(os.getuid()).pw_name
OWNER_MSG = "names no process"
WHOLE_MSG = "every process"
NEWEST_MSG = "newest or oldest"
NOBODY_UID = "4294967290"
NOMATCH = "zz-no-such-process-qq"

STUB = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps([os.path.basename(sys.argv[0])] + sys.argv[1:]) + "\n")
n = int(open(os.environ["STUB_N_FILE"]).read())
print("\n".join([os.environ["STUB_PID"]] * n))
sys.exit(0 if n else 1)
"""


def setup():
    d = tempfile.mkdtemp(prefix="whole-account-")
    os.mkdir(os.path.join(d, "bin"))
    for prog in ("pgrep", "ps", "pidof"):
        p = os.path.join(d, "bin", prog)
        with open(p, "w") as fh:
            fh.write(STUB)
        os.chmod(p, 0o755)
    return d


def run(d, cmd, n):
    log, nf = os.path.join(d, "log"), os.path.join(d, "n")
    open(log, "w").close()
    with open(nf, "w") as fh:
        fh.write(str(n))
    env = dict(os.environ, PATH=os.path.join(d, "bin") + os.pathsep + os.environ["PATH"],
               STUB_LOG=log, STUB_N_FILE=nf, STUB_PID=str(os.getpid()))
    r = subprocess.run(["bash", HOOK], input=json.dumps({"tool_input": {"command": cmd}}),
                       capture_output=True, text=True, env=env, timeout=60)
    calls = [json.loads(l) for l in open(log) if l.strip()]
    return r.returncode, r.stderr, calls


# --- procps's own long-option table ---------------------------------------------------------------
def pgrep_says(opt):
    """How the real pgrep reads `--opt`: 'ambiguous', 'unrecognized' or 'accepted'. It is asked
    with a uid nobody has and a pattern nothing matches; pgrep only lists, never signals."""
    r = subprocess.run([REAL_PGREP, "--" + opt, NOBODY_UID, NOMATCH], capture_output=True,
                       text=True, timeout=10)
    if "is ambiguous" in r.stderr:
        return "ambiguous"
    if "unrecognized option" in r.stderr:
        return "unrecognized"
    return "accepted"


def procps_long_options():
    """Every long option pgrep/pkill's getopt table holds, read off the tool: the names its --help
    prints, and the possibilities getopt prints for each ambiguous one-letter prefix. pkill is the
    same program (pgrep.c) with the same table: pgrep's own ambiguity list names --echo and
    --signal, which are pkill's."""
    names = set()
    for prog in (REAL_PGREP, os.path.join(os.path.dirname(REAL_PGREP), "pk" + "ill")):
        if os.path.exists(prog):
            out = subprocess.run([prog, "--help"], capture_output=True, text=True, timeout=10)
            names |= set(re.findall(r"(?<![\w-])--([a-z][a-z-]+)", out.stdout + out.stderr))
    for ch in "abcdefghijklmnopqrstuvwxyz":
        r = subprocess.run([REAL_PGREP, "--" + ch, NOMATCH], capture_output=True, text=True,
                           timeout=10)
        m = re.search(r"possibilities:(.*)", r.stderr)
        if m:
            names |= set(re.findall(r"'--([a-z-]+)'", m.group(1)))
    return {n for n in names if pgrep_says(n) == "accepted"}


def hook_python():
    src = open(HOOK).read()
    return src.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def hook_table_and_resolver():
    py = hook_python()
    tree = ast.parse(py)
    table = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "PG_LONG_ALL"
                                                for t in node.targets):
            table = ast.literal_eval(node.value)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
               and n.name == "pg_long"), None)
    ns = {}
    if table is not None and fn is not None:
        ns["PG_LONG_ALL"] = table
        exec(compile(ast.Module([fn], []), HOOK, "exec"), ns)
    return table, ns.get("pg_long")


def unique_prefixes(opt, table):
    out = []
    for k in range(1, len(opt) + 1):
        p = opt[:k]
        if p == opt or sum(1 for t in table if t.startswith(p)) == 1:
            out.append(p)
    return out


def main():
    d = setup()
    bad, total = [], 0

    def check(label, ok, why):
        nonlocal total
        total += 1
        if not ok:
            bad.append("%s: %s" % (label, why))

    try:
        # --- A: kill -1 / kill 0 ---------------------------------------------------------------
        A = ["kill -9 -1", "kill -- -1", "kill -1", "kill -KILL -1", "kill -SIGKILL -1",
             "kill -s KILL -1", "kill -s 9 -1", "kill -n 9 -1", "kill -9 -- -1", "kill -TERM -- -1",
             "kill -1 -1", "kill 1234 -1", "/bin/kill -9 -1", "command kill -9 -1",
             "sudo kill -9 -1", "bash -c 'kill -9 -1'", "kill -9 -1 2>/dev/null; echo done",
             "echo cleanup && kill -- -1", "kill 0", "kill -9 0", "kill -- 0", "kill -TERM 0",
             "kill -s HUP 0", "kill -9 -- 0", "kill -9 -0", "trap 'kill 0' EXIT; sleep 1",
             "sleep 1 & kill 0", "kill -9 '-1'", 'kill -9 "-1"', "timeout 5 kill -9 -1"]
        for cmd in A:
            rc, err, calls = run(d, cmd, 3)
            check("A " + cmd, rc == 2 and WHOLE_MSG in err and not calls,
                  "rc %d, asked %r: %s" % (rc, calls, err.strip()[:160]))

        # --- S: an owner-selected (or unselected) ps listing into a kill -------------------------
        S = ['kill $(ps -u "$USER" -o pid=)', "kill `ps -U $UID -o pid=`",
             'kill -9 $(ps -u "$USER" -o pid=)', "kill $(ps -o pid=)", "kill $(ps x -o pid=)",
             "kill $(ps -eo pid=)", "kill $(ps -A -o pid=)", 'kill $(ps --user "$USER" -o pid=)',
             'kill $(ps --User "$USER" -o pid=)', 'kill $(ps U "$USER" -o pid=)',
             'P=$(ps -u "$USER" -o pid=); kill $P',
             'for p in $(ps -u "$USER" -o pid=); do kill "$p"; done',
             'kill $(ps -u "$USER" -o pid= -p 1234)']
        for cmd in S:
            rc, err, calls = run(d, cmd, 3)
            check("S " + cmd, rc == 2 and WHOLE_MSG in err,
                  "rc %d: %s" % (rc, err.strip()[:160]))

        # --- N: -n / -o with no other criterion --------------------------------------------------
        N = ["pkill -n", "pkill -o", "pkill --newest", "pkill --oldest", "pkill -9 -n",
             "pkill -KILL -o", "pkill -n -x", "pkill -nx", "pkill --ne", "pkill --oldes",
             "kill $(pgrep -n)", "kill $(pgrep --oldest)", "pgrep -n | xargs kill",
             "kill -9 `pgrep -o`", "pkill -i -n", "pkill -v -n"]
        for cmd in N:
            rc, err, calls = run(d, cmd, 1)
            check("N " + cmd, rc == 2 and NEWEST_MSG in err and not calls,
                  "rc %d, asked %r: %s" % (rc, calls, err.strip()[:160]))

        # --- P: the hook reads procps's table the way procps does --------------------------------
        table = procps_long_options()
        check("P derived table is not empty", {"euid", "uid", "full", "newest"} <= table,
              "derived %r" % sorted(table))
        hook_table, resolver = hook_table_and_resolver()
        check("P hook carries PG_LONG_ALL", hook_table is not None and resolver is not None,
              "PG_LONG_ALL or pg_long() not found in the hook's python")
        if hook_table is not None:
            hook_names = {n[2:] for n in hook_table}
            check("P PG_LONG_ALL is procps's table", hook_names == table,
                  "hook lacks %r, has extra %r" % (sorted(table - hook_names),
                                                   sorted(hook_names - table)))
        if resolver is not None:
            for opt in sorted(table):
                for k in range(1, len(opt) + 1):
                    p = opt[:k]
                    tool = pgrep_says(p)
                    got = resolver("--" + p)
                    hits = [t for t in table if t.startswith(p)]
                    want = p if p in table else (hits[0] if len(hits) == 1 else None)
                    if tool == "accepted":
                        check("P --%s is getopt's prefix rule" % p, want is not None,
                              "pgrep accepts --%s, which is no exact or unique prefix of %r"
                              % (p, hits))
                        check("P --%s -> --%s" % (p, want), got == "--%s" % want,
                              "pgrep reads --%s as --%s, the hook as %r" % (p, want, got))
                    else:
                        check("P --%s (%s)" % (p, tool), want is None and got == "--" + p,
                              "pgrep finds it %s, hook resolves it to %r" % (tool, got))

        # --- U: owner abbreviations, and --full ------------------------------------------------
        for opt, val in (("euid", USER), ("uid", USER)):
            for p in unique_prefixes(opt, table):
                if p == opt:
                    continue
                for cmd in ('pkill --%s "$USER"' % p, 'pkill --%s="$USER"' % p,
                            'kill $(pgrep --%s "$USER")' % p):
                    rc, err, calls = run(d, cmd, 3)
                    check("U " + cmd, rc == 2 and OWNER_MSG in err, "rc %d: %s"
                          % (rc, err.strip()[:160]))
                    check("U " + cmd + " counted", any(
                        c[1:] == ["--" + opt, val, "."] for c in calls),
                        "stub asked %r" % calls)
                    rc, err, calls = run(d, cmd, 1)
                    check("U " + cmd + ", one", rc == 0, "refused at one: %s" % err[:160])
        for p in unique_prefixes("full", table):
            for cmd in ("pkill --%s srv" % p, "kill $(pgrep --%s srv)" % p):
                rc, err, _ = run(d, cmd, 1)
                check("U " + cmd, rc == 2 and "pattern" in err, "rc %d: %s" % (rc, err[:160]))

        # --- R: negatives -------------------------------------------------------------------
        R = [("kill -9 12345", 3), ("kill -- -4242", 3), ("kill %1", 3), ("kill -1 12345", 3),
             ("kill -HUP 12345", 3), ("kill -0 12345", 3), ("kill -0 -1", 3), ("kill -s 0 -1", 3),
             ("kill -l", 3), ("kill -L", 3), ("kill -l 9", 3), ("kill -9 12345 23456", 3),
             ("pkill -P $$", 3), ('pkill -x somename -u "$USER"', 1), ("pkill -n somename", 1),
             ("pkill -n -P $$", 3), ("kill $(ps -o pid= -p 1234)", 3),
             ("kill $(ps -o pid= --ppid $$)", 3), ('ps -u "$USER" -o pid,cmd', 3),
             ("sleep 5 & P=$!; kill $P", 3), ("kill -- -$(ps -o pgid= $$)", 3),
             ("ps aux; kill 12345", 3), ('ps -u "$USER" -o pid,cmd && kill 12345', 3),
             ("ps -o pid= -p 12345 >/dev/null && kill 12345", 3)]
        for cmd, n in R:
            rc, err, _ = run(d, cmd, n)
            check("R " + cmd, rc == 0, "refused: %s" % err.strip()[:200])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    for b in bad:
        print("  FAIL " + b)
    print("%d of %d rows failed" % (len(bad), total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
