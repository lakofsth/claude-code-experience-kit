"""Check for hooks/tests/INVARIANTS.md `mh-the-kill-guards-separator-scans-hold-expansions-whole`:
every place hooks/block-unsafe-kill.sh splits a command at a separator does so over a view in
which `${...}`, `$[...]` and `$((...))` are word characters, so a `;`, `|`, `&` or newline inside
an expansion never ends a pipeline, a substitution host or a command for the guard.

Four halves.

  S. SITES -- every scan of bash_parse.SEP in the hook, derived by a regex over its source (any
     `SEP.<method>(`), must read `hv`, and every `hv` must be bound from held(v, subs). A site
     added tomorrow that scans v is red here without this file changing.
  E. END TO END -- each row is a line with a separator inside an expansion, at one site's
     structure (a pipeline's end, a substitution's host, an assignment's end, a call's end, a
     compound's redirection), and a CONTROL twin with the separator outside the expansion. Bash is
     the oracle: the line is run in bash_oracle.py's namespace with pgrep/pidof printing a marker
     pid and kill a shim recording its operands, and the hook must refuse exactly when the marker
     reaches a kill (y is unset, so each `${y:-...}` takes its default).
  H. HELD -- held() itself, lifted out of the hook's python by an AST walk and run on masks: an
     expansion is FILL at the top level and inside a substitution's body, while the separators of
     a substitution nested in an expansion stay for the scans of that body. The over-filling
     variant (word_chars over the whole of v) is caught here and not end to end: a lister in a
     substitution nested in `${...}` is counted by the guard whatever the scans read.
  M. MUTANTS -- for each site, a copy of the hook whose one scan reads v again; the rows pinned
     to that site must go red against it, so each row is shown to reach the site it is named
     for. Sites with no pinned row are printed as such (no line was found whose verdict that
     site's cut changes: the other routes of the guard decide every line tried).

"""
import json, os, re, shutil, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
HOOK = os.environ.get("HOOK", os.path.join(ROOT, "hooks", "block-unsafe-kill.sh"))
MARK = "4242"

# (site, description, line). site names the function whose scan the row reaches; None: control.
ROWS = [
    # downstream(): the end of the lister's pipeline
    ("downstream", "${...} holding | after pgrep -f, then ; kill", "pgrep -f X ${y:-|} ; kill 1"),
    ("downstream", "$[...] holding | after pgrep -f, then ; kill", "pgrep -f X $[1|2] ; kill 1"),
    (None, "control: | outside, into xargs kill", "pgrep -f X ${y:-a} | xargs kill"),
    (None, "control: $((...)) holding | then ; kill", "pgrep -f X $((1|2)) ; kill 1"),
    (None, "control: plain ; kill", "pgrep -f X ${y:-a} ; kill 1"),
    ("downstream", "${...} holding | inside a substitution's body, then ; kill",
     "echo $(pgrep -f X ${y:-|} ; kill 1)"),
    (None, "control: the same body, no expansion", "echo $(pgrep -f X ${y:-a} ; kill 1)"),
    # subst_host(): where the host of a substitution starts
    ("subst_host", "${...} holding ; before $(pgrep -f) in an echo, then ; kill",
     "echo ${y:-;} $(pgrep -f X) ; kill 1"),
    ("subst_host", "${...} holding ; between xargs and kill, herestring $(pgrep -f)",
     "xargs ${y:-env A=;} kill <<< $(pgrep -f X)"),
    (None, "control: echo $(pgrep -f) ; kill", "echo ${y:-a} $(pgrep -f X) ; kill 1"),
    (None, "control: xargs kill <<< $(pgrep -f)", "xargs ${y:-} kill <<< $(pgrep -f X)"),
    (None, "control: ; outside, before the echo", "echo ${y:-a}; echo $(pgrep -f X) ; kill 1"),
    # resets(): whether an assignment stands alone (ends what the name held)
    ("resets", "${...} holding | in a later assignment, then ; kill $P",
     "P=$(pgrep -f X); P=x${y:-|} ; kill $P"),
    ("resets", "${...} holding ; in an assignment that is a pipeline member",
     "P=$(pgrep -f X); P=x${y:-;} | true; kill $P"),
    ("resets", "$[...] holding | in a later assignment, then ; kill $P",
     "P=$(pgrep -f X); P=x$[1|2] ; kill $P"),
    (None, "control: plain reset, then kill $P", "P=$(pgrep -f X); P=x${y:-a} ; kill $P"),
    (None, "control: assignment piped, then kill $P", "P=$(pgrep -f X); P=x${y:-a} | true; kill $P"),
    # end_of(): where a function call ends, so what its words bind is before its body runs
    ("end_of", "${...} holding ; before an arithmetic binding in a call's words",
     "f() { kill $P; }; f ${y:-;} $(( P = $(pgrep -f X) ))"),
    ("end_of", "${...} holding ; before a ${P:=...} binding in a call's words",
     "f() { kill $P; }; f ${y:-;} ${P:=$(pgrep -f X)}"),
    ("end_of", "$[...] holding | before a ${P:=...} binding in a call's words",
     "f() { kill $P; }; f $[1|2] ${P:=$(pgrep -f X)}"),
    (None, "control: binding in the call's words, no expansion before it",
     "f() { kill $P; }; f x ${P:=$(pgrep -f X)}"),
    (None, "control: binding after the call", "f() { kill $P; }; f ${y:-a}; P=$(pgrep -f X)"),
    # climb(): a compound command's redirection into >(...)
    ("climb", "${...} holding ; in a group's redirection before > >(xargs kill)",
     "{ pgrep -f X; } 2>${y:-;} > >(xargs kill)"),
    (None, "control: the group's redirection with no separator",
     "{ pgrep -f X; } 2>${y:-a} > >(xargs kill)"),
    (None, "control: a ; outside, the >(...) on a later command",
     "{ pgrep -f X; } 2>/dev/null; true > >(xargs kill)"),
    # handed_to_kill(): the end of a host that hands code on. No line found whose verdict its cut
    # changes; these pin that the verdict holds with the expansion there.
    (None, "handed: ${...} holding ; before bash -c with $(pgrep -f) in its code",
     "env ${y:-A=;} bash -c \"kill $(pgrep -f X)\""),
    (None, "handed: $[...] before sh -c with $(pgrep -f) in its code",
     "timeout $[1|2] bash -c \"kill $(pgrep -f X)\""),
    # analyse()'s eval: the end of the eval command. Likewise no verdict-changing line found.
    (None, "eval: ${...} holding ; before the code word", "eval ${y:-: ;} 'P=$(pgrep -f X)'; kill $P"),
    (None, "eval: $[...] holding | before the code word", "eval : $[1|2] \\; 'P=$(pgrep -f X)'; kill $P"),
    (None, "eval: control, code word alone", "eval 'P=$(pgrep -f X)'; kill $P"),
]

# The sites, by the name of the function each scan sits in, derived in half S.
NO_LINE = {"handed_to_kill", "analyse"}


def shim_dir():
    d = tempfile.mkdtemp(prefix="sepscan-")
    for name in ("pgrep", "pidof"):
        with open(os.path.join(d, name), "w") as f:
            f.write("#!/bin/sh\necho %s\n" % MARK)
    with open(os.path.join(d, "kill"), "w") as f:
        f.write("#!/bin/sh\necho \"KILL $*\" >> \"$SEPSCAN_LOG\"\n")
    for name in os.listdir(d):
        os.chmod(os.path.join(d, name), 0o755)
    return d


def bash_reaches(line, shims):
    """Whether bash, running line with y unset, hands the marker pid to a kill."""
    log = os.path.join(shims, "log")
    open(log, "w").close()
    pre = ("kill(){ \"%s/kill\" \"$@\"; }; pgrep(){ \"%s/pgrep\"; }; export -f kill pgrep\n"
           % (shims, shims))
    env = dict(os.environ, PATH=shims + ":" + os.environ["PATH"], SEPSCAN_LOG=log)
    env.pop("y", None)
    bash_oracle.run(["bash", "-c", pre + line], capture_output=True, text=True, timeout=20,
                    env=env, cwd=shims, stdin=subprocess.DEVNULL)
    return any(MARK in l.split() for l in open(log).read().splitlines() if l.startswith("KILL"))


def hook_refuses(hook, line):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": line}})
    p = subprocess.run(["bash", hook], input=payload, capture_output=True, text=True, timeout=60)
    return p.returncode != 0


def lift_held(src):
    """held() as the hook defines it, run against bash_parse (the hook's own imports)."""
    import ast
    sys.path.insert(0, os.path.dirname(os.path.abspath(HOOK)))
    import bash_parse
    from quote_mask import mask_quoted, substitutions
    py = src.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    fn = next(n for n in ast.walk(ast.parse(py)) if isinstance(n, ast.FunctionDef) and n.name == "held")
    ns = {"FILL": bash_parse.FILL, "word_chars": bash_parse.word_chars}
    exec(compile(ast.Module([fn], []), "held", "exec"), ns)
    return lambda t: ns["held"](mask_quoted(t, fill=bash_parse.FILL, live=True), substitutions(t)), \
        bash_parse.FILL


# (text, a key of the same length: F must be FILL in the held view, K must keep its character)
HELD_ROWS = [
    ("a ${y:-|} b",                "..FFFFFFF.."),
    ("a $[1|2] b",                 "..FFFFFF.."),
    ("a $((1|2)) b",               "..FFFFFFFF.."),
    ("a ${y:-;} | b",              "..FFFFFFF.K.."),
    ("a $(b ${y:-;} ; c) d",       "......FFFFFFF.K..K.."),
    ("a ${y:-$(b | c)} d",         "..FFFFFKK..K..KF.."),
    ("a ${y:-$(b ${z:-;} | c)} d", "..FFFFFKK..FFFFFFF.K..KF.."),
    ("a <(b $[1&2] & c)",          "...K..FFFFFF.K..K"),
]


SCAN = re.compile(r"\bSEP\.(\w+)\(\s*([A-Za-z_]\w*)")


def sites(src):
    """[(line number, enclosing def, variable scanned)] for every SEP.<method>( in src."""
    out, lines = [], src.splitlines()
    for m in SCAN.finditer(src):
        n = src.count("\n", 0, m.start())
        fn, low = None, len(lines[n]) - len(lines[n].lstrip())
        for l in reversed(lines[:n]):          # the innermost def whose body holds line n
            if not l.strip():
                continue
            ind = len(l) - len(l.lstrip())
            if ind < low:
                d = re.match(r"\s*def (\w+)", l)
                if d:
                    fn = d.group(1)
                    break
                low = ind
        out.append((n + 1, fn, m.group(2), m.start(2), m.end(2)))
    return out


def main():
    src = open(HOOK).read()
    fails = []
    # S. SITES
    found = sites(src)
    if len(found) < 7:
        fails.append("S: only %d SEP scans found; the derivation is broken" % len(found))
    for n, fn, var, _, _ in found:
        if var != "hv":
            fails.append("S: line %d (%s) scans %s, not the held view hv" % (n, fn, var))
    for m in re.finditer(r"\bhv\s*=([^\n]*)", src):
        if "held(v, subs)" not in m.group(1):
            fails.append("S: hv bound from %r" % m.group(1).strip())
    if "def held(" not in src:
        fails.append("S: no held()")
    print("S: %d SEP scan sites: %s" % (len(found), ", ".join("%s@%d" % (f, n) for n, f, *_ in found)))

    # H. HELD
    if "def held(" in src:
        held, fill = lift_held(src)
        for t, key in HELD_ROWS:
            assert len(key) == len(t), (t, key)
            hv = held(t)
            must_fill = [i for i, k in enumerate(key) if k == "F"]
            must_keep = [i for i, k in enumerate(key) if k == "K"]
            bad = [i for i in must_fill if hv[i] != fill] + [i for i in must_keep if hv[i] == fill]
            print("H %-4s %r -> %r" % ("ok" if not bad else "FAIL", t, hv.replace(fill, "_")))
            if bad:
                fails.append("H: %r held as %r (offsets %s)" % (t, hv.replace(fill, "_"), bad))

    # E. END TO END, against the oracle
    shims = shim_dir()
    try:
        truth = {line: bash_reaches(line, shims) for _, _, line in ROWS}
    finally:
        shutil.rmtree(shims, ignore_errors=True)
    for site, desc, line in ROWS:
        got = hook_refuses(HOOK, line)
        mark = "ok" if got == truth[line] else "FAIL"
        print("E %-4s %-12s bash %-9s hook %-8s %s" % (mark, site or "-", "reaches" if truth[line]
              else "no-reach", "refuses" if got else "allows", desc))
        if got != truth[line]:
            fails.append("E: %s: %r (bash %s, hook %s)" % (desc, line, truth[line], got))

    # M. MUTANTS: one site at a time reads v again
    if os.environ.get("SEPSCAN_NO_MUTANTS") != "1" and not any(f.startswith("S:") for f in fails):
        tmp = tempfile.mkdtemp(prefix="sepscan-mut-")
        try:
            hooks = os.path.dirname(os.path.abspath(HOOK))
            for name in os.listdir(hooks):
                if name.endswith(".py"):
                    shutil.copy(os.path.join(hooks, name), tmp)
            for n, fn, _, a, b in found:
                mut = os.path.join(tmp, "mut.sh")
                with open(mut, "w") as f:
                    f.write(src[:a] + "v" + src[b:])
                pinned = [(d, l) for s, d, l in ROWS if s == fn]
                if not pinned:
                    if fn not in NO_LINE:
                        fails.append("M: site %s@%d has no pinned row and is not stated as none" % (fn, n))
                    print("M %s@%d: no line found whose verdict this site's cut changes" % (fn, n))
                    continue
                red = [d for d, l in pinned if hook_refuses(mut, l) != truth[l]]
                print("M %s@%d: %d of %d pinned rows red against its mutant" % (fn, n, len(red), len(pinned)))
                if not red:
                    fails.append("M: reverting %s@%d leaves every row pinned to it green" % (fn, n))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    for f in fails:
        print("FAIL", f)
    print("%s: %d failure(s)" % ("PASS" if not fails else "FAIL", len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
