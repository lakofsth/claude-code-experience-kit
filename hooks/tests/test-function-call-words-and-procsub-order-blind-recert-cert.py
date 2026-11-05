"""Check of the function-and-procsub clause of mh-code-handed-to-a-shell-is-code
(hooks/tests/INVARIANTS.md), written from the hooks/tests/INVARIANTS.md clause alone:

  hooks/block-unsafe-kill.sh reads text that reaches a shell reading code on its stdin through a
  function body at the place it is called, or through stdout redirected into a `>(...)` that runs
  such a shell, as that shell's code, as bash runs it; and it refuses none of these when bash
  hands the shell no such text.

THE ORACLE IS BASH. Every row holds the text
`pkill -f SRVX` and is run by `bash -c ROW` through hooks/tests/bash_oracle.py, in an empty
directory, with a stand-in `pkill` first on PATH that appends to a marker file.
  - marker written  =>  the hook must REFUSE the row       (direction R)
  - marker absent   =>  the hook must stay SILENT on the row (direction S)
No row is labelled by hand.

DIRECTIONS (two "as bash runs it" readings)
  A  "at the place it is called": a function body is the copy the CALL makes, so the words of
     the call are the body's positional parameters. The text handed in as `$1`, `$2`, `${1}`,
     `$*` reaches the shell when the body writes it (echo, printf, herestring, unquoted heredoc)
     into a shell, or when the body is itself the shell fed from `$1`; every call form the
     clause already reads (bare, an assignment before it, through another function, `2>&1 |`,
     `> >(bash)`), every quoting of the argument, and part of the text from the argument.
     Silent siblings: the body writes another parameter, no argument is given, `'$1'` or a
     quoted heredoc keeps the name literal, the sink is not a shell, stdout goes elsewhere.
  B  "stdout redirected into a `>(...)`", as bash runs the redirections: the word of each
     redirection is expanded with the earlier ones already in force, so a later `>(...)` is
     started with its stdout on the pipe into an earlier `>(bash)`. `CMD > >(bash) > >(cat)`
     hands bash the text through cat; with `>(cat >/dev/null)` or `>(grep x)` last it does not.
  Z  controls: the bare kill, the plain pipe into bash, the text as data.

Out of scope, as hooks/tests/INVARIANTS.md states it: branches bash would not take, `exec > >(bash)`, a
`>(bash)` that is a file operand, shells other than the ones the clause names. Controls: the rows
asked in each direction are printed, and an empty direction is red.
"""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOK = os.environ.get("HOOK", os.path.join(ROOT, "hooks", "block-unsafe-kill.sh"))
K = "pkill -f SRVX"
QK = "'%s'" % K


def rows():
    R = []

    def add(d, r):
        R.append((d, r))

    # Z
    add("Z", K)
    add("Z", "echo %s | bash" % QK)
    add("Z", "echo %s" % QK)

    # A: the call's words are the body's parameters
    writers = [
        ('echo "$1"', "%s"),
        ('echo "${1}"', "%s"),
        ('echo "$*"', "%s"),
        ('echo $1', "%s"),
        ("printf '%s\\n' \"$1\"", "%s"),
        ('cat <<< "$1"', "%s"),
        ('echo "$2"', "x %s"),
        ('cat <<EOF\n$1\nEOF\n', "%s"),
    ]
    for w, args in writers:
        sep = "" if w.endswith("\n") else ";"
        d = "f() { %s%s }" % (w, sep)
        J = "\n" if "\n" in w else "; "
        a = args % QK
        for call in ("f %s | bash", "f %s | sh", "f %s | bash -s", "X=1 f %s | bash",
                     "f %s 2>&1 | bash", "f %s > >(bash)", "{ f %s; } | bash"):
            add("A", d + J + call % a)
        # silent siblings of the same body
        for call in ("f %s | cat", "f %s >/dev/null | bash", "f %s > >(cat)"):
            add("A", d + J + call % a)
        add("A", d + J + "f | bash")
        add("A", d + J + "f 'echo hi' | bash")
    for a in ('"%s"' % K, "pkill\\ -f\\ SRVX"):
        add("A", 'f() { echo "$1"; }; f %s | bash' % a)
    add("A", 'f() { echo "$1"; }; g() { f "$1"; }; g %s | bash' % QK)
    add("A", 'f() { echo "$1"; }; g() { f "$2"; }; g x %s | bash' % QK)
    add("A", 'f() { echo "$1"; }; g() { f "$1"; }; g x %s | bash' % QK)
    add("A", 'f() { echo "$1 -f SRVX"; }; f pkill | bash')
    add("A", 'f() { echo "$1 -f SRVX"; }; f true | bash')
    add("A", 'f() { echo "$2"; }; f %s x | bash' % QK)
    add("A", "f() { echo '$1'; }; f %s | bash" % QK)
    add("A", "f() { cat <<'EOF'\n$1\nEOF\n}\nf %s | bash" % QK)
    # the body is the shell, fed from its parameter
    for b in ('echo "$1" | bash', 'bash <<< "$1"', "printf '%s\\n' \"$1\" | sh",
              'echo "$1" > >(bash)'):
        add("A", "f() { %s; }; f %s" % (b, QK))
        add("A", "f() { %s; }; f 'echo hi'" % b)
        add("A", "f() { %s; }; f" % b)
    add("A", 'f() { echo "$1" | cat; }; f %s' % QK)

    # B: a later >(...) starts with stdout on the earlier >(bash)
    for w in ("echo %s" % QK, "printf '%%s\\n' %s" % QK, "cat <<< %s" % QK):
        for tail in ("> >(cat)", "> >(tee /dev/null)", ">> >(cat)", "1> >(cat)"):
            add("B", "%s > >(bash) %s" % (w, tail))
        for tail in ("> >(cat >/dev/null)", "> >(grep x)", "> >(wc -l)", ">/dev/null"):
            add("B", "%s > >(bash) %s" % (w, tail))
        add("B", "%s > >(cat) > >(cat)" % w)
    d = "f() { echo %s; }" % QK
    add("B", d + "; f > >(bash) > >(cat)")
    add("B", d + "; f > >(bash) > >(grep x)")
    add("B", "{ echo %s; } > >(bash) > >(cat)" % QK)
    add("B", "{ echo %s; } > >(bash) > >(wc -l)" % QK)
    return R


def oracle(T, row):
    mark = os.path.join(T, "ran")
    if os.path.exists(mark):
        os.unlink(mark)
    env = {"PATH": os.path.join(T, "bin") + ":/usr/bin:/bin", "HOME": T, "LC_ALL": "C",
           "MARK": mark}
    bash_oracle.run(["bash", "-c", row], stdin=subprocess.DEVNULL, capture_output=True,
                    cwd=T, env=env, timeout=30)
    return os.path.exists(mark)


def refused(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=60)
    return p.returncode != 0


def main():
    T = tempfile.mkdtemp(prefix="fn-words-procsub-cert-")
    fails, n = [], {}
    try:
        os.mkdir(os.path.join(T, "bin"))
        stand = os.path.join(T, "bin", "pkill")
        with open(stand, "w") as fh:
            fh.write('#!/bin/sh\necho "pkill $*" >> "$MARK"\n')
        os.chmod(stand, 0o755)
        seen = set()
        for d, row in rows():
            if row in seen:
                continue
            seen.add(row)
            ran = oracle(T, row)
            ref = refused(row)
            way = "R" if ran else "S"
            n[d + way] = n.get(d + way, 0) + 1
            shown = row.replace("\n", "\\n")
            print("  %s %s %s %s" % ("ok  " if ref == ran else "FAIL", way, d, shown))
            if ref != ran:
                fails.append("[%s %s] bash %s; hook %s: %s" % (
                    d, way, "RAN the text as code" if ran else "did not run the text",
                    "REFUSED" if ref else "was SILENT", shown))
    finally:
        shutil.rmtree(T, ignore_errors=True)
    print("asked %d rows: %s" % (sum(n.values()),
                                 ", ".join("%s=%d" % kv for kv in sorted(n.items()))))
    for k in ("AR", "AS", "BR", "BS"):
        if not n.get(k):
            fails.append("vacuous: direction %s has no rows (%r)" % (k, n))
    if fails:
        print("FAILED %d:" % len(fails))
        for f in fails:
            print("  - " + f)
        sys.exit(1)
    print("all held")


main()
