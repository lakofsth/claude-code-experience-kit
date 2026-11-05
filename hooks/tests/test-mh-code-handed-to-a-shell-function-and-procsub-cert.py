"""Check of the function-body and `>(...)` amendment of `mh-code-handed-to-a-shell-is-code`
(2026-10-30).

The sentence checked:

    hooks/block-unsafe-kill.sh reads text that reaches a shell reading code on its stdin through a
    function body at the place it is called, or through stdout redirected into a `>(...)` that
    runs such a shell, as that shell's code, as bash runs it; and it refuses none of these when
    bash hands the shell no such text.

Written from the hooks/tests/INVARIANTS.md clause alone. Its directions:

  FW  FUNCTION WRITES -- a function whose body writes the text (echo, printf, a heredoc, a
                         herestring through cat, a subshell body, a pipe inside the body, a
                         nested function call, the later of two definitions) is called with its
                         stdout piped into a shell that reads stdin as code.
  FR  FUNCTION READS  -- the shell is in the function body, and the text reaches it at the
                         call: piped in, a herestring or a heredoc on the call.
  PW  PROCSUB         -- stdout redirected into `>(bash)` / `>(sh)` / `>(bash -s)`: every
                         spelling of the stdout redirection (`>`, `1>`, `>>`, `>|`, `&>`, before
                         the command word, the last of two redirections, `exec >`), every writer
                         (echo, printf, heredoc, herestring, a `{ }` and a `( )` compound), a
                         reader behind a wrapper or a pipe inside the `>(...)`, a reader that is
                         a function, and a function as the writer.
  N   NO SUCH TEXT    -- the same danger text where bash hands no shell any of it: the function
                         is not piped, piped to cat, sends its text to /dev/null or stderr, the
                         reader runs `bash -c` (not its stdin) or `cat`; the `>(bash)` is an
                         argument and not a redirection, takes stderr only, reads nothing as
                         code, or is overridden by a later stdout redirection.

Bash is the oracle (hooks/tests/bash_oracle.py, a pid namespace with no host process in it):
before the hook is asked, every row is run by bash with `pkill`, `killall` and `pgrep` replaced
on PATH by stand-ins that leave a mark, and the mark must show that bash ran the danger (a
must-refuse row) or did not (a must-stay-silent row). A row whose oracle disagrees with its
column is a fault of this check, reported as such, not a verdict on the hook.

Not asked here, by choice of scope: `unset -f` before the call, and a call written before the
definition (bash hands nothing there; the sentence covers them, and they are unpinned here).
"""
import json, os, stat, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bash_oracle  # noqa: E402

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))
X = "mhfnproccert-no-such-pattern"
PK = "pkill -f %s" % X
KA = "killall %s" % X
PG = "kill $(pgrep -f %s)" % X

MUST_REFUSE = [
    # FW  function writes the text, called with stdout piped into a shell
    ("FW echo | bash",                 "f() { echo '%s'; }; f | bash" % PK),
    ("FW function kw | sh",            "function f { echo '%s'; }; f | sh" % PK),
    ("FW function kw () printf",       "function f() { printf '%%s\\n' '%s'; }; f | bash" % PK),
    ("FW subshell body",               "f() ( echo '%s' ); f | bash" % PK),
    ("FW heredoc body, lines",         "f() {\ncat <<'EOF'\n%s\nEOF\n}\nf | bash" % PK),
    ("FW herestring body",             "f() { cat <<< '%s'; }; f | bash" % PK),
    ("FW pipe inside body",            "f() { echo '%s' | cat; }; f | bash" % PK),
    ("FW nested call",                 "g() { echo '%s'; }; f() { g; }; f | bash" % PK),
    ("FW call lines later",            "f() { echo '%s'; }\necho hi\nf | bash" % PK),
    ("FW call in { }",                 "f() { echo '%s'; }; { f; } | bash" % PK),
    ("FW later definition wins",       "f() { echo hi; }; f() { echo '%s'; }; f | bash" % PK),
    ("FW killall",                     "f() { echo '%s'; }; f | bash" % KA),
    ("FW kill $(pgrep -f)",            "f() { echo '%s'; }; f | bash" % PG),
    ("FW | bash -s",                   "f() { echo '%s'; }; f | bash -s" % PK),
    # FR  function body is the reading shell
    ("FR piped into f",                "f() { bash; }; echo '%s' | f" % PK),
    ("FR sh -s piped into f",          "f() { sh -s; }; echo '%s' | f" % PK),
    ("FR herestring on call",          "f() { bash; }; f <<< '%s'" % PK),
    ("FR heredoc on call",             "f() { bash; }\nf <<'EOF'\n%s\nEOF" % PK),
    ("FR writer fn | reader fn",       "w() { echo '%s'; }; r() { bash; }; w | r" % PK),
    # PW  stdout redirected into >(shell)
    ("PW echo > >(bash)",              "echo '%s' > >(bash)" % PK),
    ("PW 1> >(bash)",                  "echo '%s' 1> >(bash)" % PK),
    ("PW >> >(bash)",                  "echo '%s' >> >(bash)" % PK),
    ("PW >| >(bash)",                  "echo '%s' >| >(bash)" % PK),
    ("PW &> >(bash)",                  "echo '%s' &> >(bash)" % PK),
    ("PW printf > >(sh)",              "printf '%%s\\n' '%s' > >(sh)" % PK),
    ("PW > >(bash -s)",                "echo '%s' > >(bash -s)" % PK),
    ("PW heredoc > >(bash)",           "cat <<'EOF' > >(bash)\n%s\nEOF" % PK),
    ("PW herestring > >(bash)",        "cat <<< '%s' > >(bash)" % PK),
    ("PW { } > >(bash)",               "{ echo '%s'; } > >(bash)" % PK),
    ("PW ( ) > >(bash)",               "(echo '%s') > >(bash)" % PK),
    ("PW redirection first",           "> >(bash) echo '%s'" % PK),
    ("PW last of two wins",            "echo '%s' > /dev/null > >(bash)" % PK),
    ("PW exec > >(bash)",              "exec > >(bash); echo '%s'" % PK),
    ("PW >(nice bash)",                "echo '%s' > >(nice bash)" % PK),
    ("PW >(cat | bash)",               "echo '%s' > >(cat | bash)" % PK),
    ("PW killall",                     "echo '%s' > >(bash)" % KA),
    ("PW kill $(pgrep -f)",            "echo '%s' > >(bash)" % PG),
    ("PW function writer",             "f() { echo '%s'; }; f > >(bash)" % PK),
    ("PW function reader",             "r() { bash; }; echo '%s' > >(r)" % PK),
]

MUST_STAY_SILENT = [
    ("N fn not piped",                 "f() { echo '%s'; }; f" % PK),
    ("N fn | cat",                     "f() { echo '%s'; }; f | cat" % PK),
    ("N fn defined, bash fed else",    "f() { echo '%s'; }; echo hi | bash" % PK),
    ("N fn body >/dev/null",           "f() { echo '%s' >/dev/null; }; f | bash" % PK),
    ("N fn body >&2",                  "f() { echo '%s' >&2; }; f | bash" % PK),
    ("N reader fn runs bash -c",       "f() { bash -c 'echo hi'; }; echo '%s' | f" % PK),
    ("N reader fn runs cat",           "f() { cat; }; echo '%s' | f" % PK),
    ("N fn 2> >(bash)",                "f() { echo '%s'; }; f 2> >(bash)" % PK),
    ("N fn > >(cat)",                  "f() { echo '%s'; }; f > >(cat)" % PK),
    ("N >(bash) is an argument",       "echo '%s' >(bash)" % PK),
    ("N > >(cat)",                     "echo '%s' > >(cat)" % PK),
    ("N 2> >(bash)",                   "echo '%s' 2> >(bash)" % PK),
    ("N > >(bash -c 'echo hi')",       "echo '%s' > >(bash -c 'echo hi')" % PK),
    ("N later > /dev/null wins",       "echo '%s' > >(bash) > /dev/null" % PK),
]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def make_stubs(d):
    """pkill, killall and pgrep on PATH that only append their argv to `mark`."""
    mark = os.path.join(d, "mark")
    bindir = os.path.join(d, "bin")
    os.mkdir(bindir)
    for name in ("pkill", "killall", "pgrep"):
        path = os.path.join(bindir, name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\necho \"%s $*\" >> '%s'\n" % (name, mark))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return bindir, mark


def bash_ran_danger(cmd, d):
    bindir, mark = make_stubs(d)
    env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
    bash_oracle.run(["bash", "-c", cmd], env=env, cwd=d, capture_output=True, text=True,
                    timeout=30, stdin=subprocess.DEVNULL)
    try:
        with open(mark) as fh:
            return X in fh.read()
    except FileNotFoundError:
        return False


bad, oracle_bad, n = [], [], 0
for want_refuse, rows in ((True, MUST_REFUSE), (False, MUST_STAY_SILENT)):
    for label, cmd in rows:
        n += 1
        with tempfile.TemporaryDirectory() as d:
            ran = bash_ran_danger(cmd, d)
        if ran != want_refuse:
            oracle_bad.append("ORACLE        %-30s bash %s the danger: %r" %
                              (label, "ran" if ran else "did not run", cmd))
            continue
        fired, err = verdict(cmd)
        one = cmd.replace("\n", "\\n")
        if want_refuse and not fired:
            bad.append("NOT REFUSED   %-30s %s" % (label, one))
        elif not want_refuse and fired:
            bad.append("REFUSED       %-30s %s :: %s" % (label, one, err.strip()[:120]))
        else:
            print("ok %-10s %-30s %s" % ("refused" if fired else "silent", label, one))

for b in oracle_bad + bad:
    print(b)
print("%d of %d cases red (%d oracle disagreements)" % (len(bad) + len(oracle_bad), n, len(oracle_bad)))
sys.exit(1 if bad or oracle_bad else 0)
