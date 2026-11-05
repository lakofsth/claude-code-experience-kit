"""Check `mh-a-dollar-double-paren-is-arithmetic-only-where-bash-reads-it`.

The sentence: hooks/quote_mask.py reads `$((` (and a bare `((`) as bash does -- arithmetic only
when the `)` that balances the second `(` is followed at once by `)`; otherwise `$((` opens a
command substitution whose body starts with a subshell, and a bare `((` two subshells. `<((` and
`>((` are always process substitutions. So the command in `$(( cmd ) )`, `$((cmd) )` or
`$((a); (b))` is a command to every reader of substitutions(), and real arithmetic
(`$((1<<2))`, `$(( (a+b) * 2 ))`, `$(( $(L) + 0 ))`) stays arithmetic.

The oracle is bash itself: each row is run by bash with a stand-in program `mark` on PATH that
leaves a file behind, so the row says whether bash RUNS a command where `mark` is written. The
scanner's answer for the same row is whether some `mark` in it is read as code: the innermost
span substitutions() records around it is not kind "arith" (or there is none). Every row is
first checked to parse (`bash -n`).

Its directions:
  O   the oracle rows, fixed and a grid of spellings x contexts (unquoted, an assignment, inside
      "...", an unquoted heredoc body): the scanner reads `mark` as code exactly when bash runs
      it, and the mask keeps its input's length under four caller settings.
  G   block-unsafe-kill.sh end to end: a pattern lister or pattern kill written in `$(( ... ) )`
      (unquoted, in "...", in a heredoc body, in `<((...))`) is refused; a lister in real
      arithmetic beside a kill keeps its verdict (refused); arithmetic holding no command is
      silent, and each silent row has a sibling carrying the danger refused in the same run
      (the controls).
  M   the arithmetic rows are live: a copy of the scanner that never reads `((` as arithmetic
      gets at least one O row wrong.


Run: python3 hooks/tests/test-quote-mask-dollar-double-paren.py   (exit 0 all pass, 1 otherwise)
"""
import json, os, re, shutil, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HOOKS)
import quote_mask  # noqa: E402

FAILS = []
K = "ki" + "ll"                     # spelled apart so the kit's own kill guard does not read this file's text
PG = "pg" + "rep"
PK = "pk" + "ill"


def check(ok, label):
    print(("  ok: " if ok else "  FAIL: ") + label)
    if not ok:
        FAILS.append(label)


print("  oracle: " + subprocess.run(["bash", "--version"], capture_output=True, text=True).stdout.splitlines()[0])

STUB = tempfile.mkdtemp(prefix="qm-dparen-")
with open(os.path.join(STUB, "mark"), "w") as f:
    f.write('#!/bin/sh\n: > "$MARKFILE"\necho 3\n')
os.chmod(os.path.join(STUB, "mark"), 0o755)


def bash_parses(t):
    return bash_oracle.run(["bash", "-n", "-c", t], capture_output=True).returncode == 0


def bash_runs(t):
    mf = os.path.join(STUB, "ran")
    if os.path.exists(mf):
        os.unlink(mf)
    env = dict(os.environ, PATH=STUB + os.pathsep + os.environ.get("PATH", ""), MARKFILE=mf)
    bash_oracle.run(["bash", "-c", t], env=env, cwd=STUB, capture_output=True, timeout=20)
    return os.path.exists(mf)


def scanner_runs(t, qm):
    subs = qm.substitutions(t)
    shown = qm.mask_quoted(t)          # outside every span, a word is code where the mask shows it
    for m in re.finditer(r"\bmark\b", t):
        o = m.start()
        inner = [s for s in subs if s["body"][0] <= o < s["body"][1]]
        if inner and max(inner, key=lambda s: s["body"][0])["kind"] != "arith":
            return True
        if not inner and shown[o:o + 4] == "mark":
            return True
    return False


FIXED = [
    "x=$(( mark ) )", "x=$((mark) )", "echo $((mark))", "echo $(( mark ))",
    "echo $((mark); (mark))", "echo $(( (mark) ))", "echo $(( (1+2) * 2 ))", "echo $((1<<2))",
    "echo $(( $(mark) + 0 ))", "echo $(( (mark) ) )", "echo $(((mark)))", "echo $(( ( 1 ) ))",
    "echo $((mark)|cat)", "echo $(( (2) * (mark) ))", "echo $(( ((mark)) + 1 ))",
    "echo $(( ( (mark) ) ) )", "echo $(( mark )\n)", "echo $(( `mark` ))",
    "echo $(( \"$(mark)\" ))", "echo $(( ')' ) )",
    "cat <((mark))", "cat <((mark) )", "cat < <((mark) )", "echo x > >((mark))",
    "(( mark ) )", "((mark) )", "(( (mark) ))", "(( mark ))", "((x=1)); ((mark) ); echo",
    "(( $(mark) ))", "echo $( (( mark ) ) )", "echo $( (( mark )) )",
]
SPELL = ["$(( mark ) )", "$((mark) )", "$((mark))", "$(( (mark) ))", "$((mark); (mark))",
         "$((mark)|cat)", "$(( $(mark) ))", "$(( (mark) ) )", "$(((mark)))", "$(( (1+2) * mark ))",
         "$(( (mark) | cat ))", "$(( (1) ); mark)"]
CTX = [("echo ", ""), ("x=", ""), ("echo \"", "\""), ("cat <<E\n", "\nE"), ("echo $(echo ", ")")]
ROWS = FIXED + [a + s + b for s in SPELL for a, b in CTX]

CFGS = ({}, {"fill": "\x01", "live": True}, {"fill": "x"}, {"quotes": "'", "keep": "`"})


def o_rows(qm, quiet=False):
    wrong = []
    for t in ROWS:
        if not bash_parses(t):
            check(False, "O oracle: the row parses: %r" % t); continue
        want = bash_runs(t)
        try:
            got = scanner_runs(t, qm)
            lens = all(len(qm.mask_quoted(t, **c)) == len(t) for c in CFGS)
        except quote_mask.MaskMismatch as e:
            got, lens = None, str(e)
        ok = got == want and lens is True
        if not ok:
            wrong.append(t)
        if not quiet:
            check(ok, "O %r: bash runs mark %s, scanner reads it as code %s; length holds %s"
                  % (t, want, got, lens))
    return wrong


o_rows(quote_mask)


def guard(cmd):
    p = subprocess.run(["bash", os.path.join(HOOKS, "block-unsafe-kill.sh")],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode


DENY = [
    K + " $(( " + PG + " -f myserver ) )",
    K + " $((" + PG + " -f myserver) )",
    K + " \"$(( " + PG + " -f myserver ) )\"",
    "P=\"$((" + PG + " -f myserver) )\"; " + K + " $P",
    K + " $((" + PG + " -f myserver) | head -1)",
    "for p in $(( " + PG + " -f myserver ) ); do " + K + " $p; done",
    "x=$(( " + PK + " -f myserver ) )",
    "echo \"$(( " + PK + " -f myserver ) )\"",
    "cat <<E\n$(( " + PK + " -f myserver ) )\nE",
    "cat <<E\n$((" + PK + " -f myserver); (true))\nE",
    "cat <((" + PK + " -f myserver))",
    "(( " + PK + " -f myserver ) )",
    K + " $(( $(" + PG + " -f myserver) ))",          # real arithmetic with a lister: kept
    K + " $(( $(" + PG + " -f myserver) + 0 ))",
]
for cmd in DENY:
    check(guard(cmd) == 2, "G block-unsafe-kill denies %r" % cmd)

# Controls: each silent row beside its sibling carrying the danger, refused in the same run.
PAIRS = [
    ("echo $(( (1+2) * 2 ))", "echo $(( (" + PK + " -f myserver) ) )"),
    ("echo \"$(( (1+2) * 2 ))\"", "echo \"$(( (" + PK + " -f myserver) ) )\""),
    ("cat <<E\n$(( (1<<2) + 1 ))\nE", "cat <<E\n$(( (" + PK + " -f myserver) ) )\nE"),
    (K + " $(( 12345 + 0 )) 2>/dev/null || true", K + " $(( " + PG + " -f myserver ) ) 2>/dev/null || true"),
    ("(( x = (1+2) * 2 )); echo $x", "(( " + PK + " -f myserver ) ); echo $x"),
]
for silent, danger in PAIRS:
    s, d = guard(silent), guard(danger)
    check(s == 0 and d == 2, "G silent on %r (%s) and denies its sibling %r (%s)" % (silent, s, danger, d))

# M: the arithmetic rows are live. A copy of the scanner whose _arith never answers yes must get
# at least one O row wrong.
src = open(os.path.join(HOOKS, "quote_mask.py")).read()
MARK = 'def _arith(t, i):\n'
if MARK in src and '"""\n    if t[i + 1:i + 2] != "(":' in src:
    d = tempfile.mkdtemp(prefix="qm-dparen-mut-")
    with open(os.path.join(d, "quote_mask_mut.py"), "w") as f:
        f.write(src.replace('"""\n    if t[i + 1:i + 2] != "(":', '"""\n    return False\n    if t[i + 1:i + 2] != "(":', 1))
    sys.path.insert(0, d)
    import quote_mask_mut  # noqa: E402
    wrong = o_rows(quote_mask_mut, quiet=True)
    check(len(wrong) >= 1, "M a scanner that never reads arithmetic gets %d O row(s) wrong" % len(wrong))
    shutil.rmtree(d, ignore_errors=True)
else:
    check(False, "M the arithmetic decision (%r) is in quote_mask.py to mutate" % MARK)

shutil.rmtree(STUB, ignore_errors=True)
print("%d failed" % len(FAILS))
sys.exit(1 if FAILS else 0)
