"""Check for hooks/tests/INVARIANTS.md `mh-a-words-value-is-bash-quote-removal`, the clause "a command
or process substitution kept as the code it is", at the site where the shared scanner
(hooks/quote_mask.py, _after_word_break()) decides whether a `#` opens a comment. The closing `)`
of a `$(...)`, `<(...)`, `>(...)` or `$((...))` ends the expansion, not the word it is in, so a
`#` straight after it is a word character; the `)` of a subshell, a `((...))` command or a case
pattern ends a word, and a `#` after it opens a comment.

Bash is the oracle: each line is run with `pkill` defined as a function that prints RAN (inside
bash_oracle.py's namespace), and `hooks/bash_parse.py` parse() must name `pkill` exactly when bash
runs it. Then hooks/block-unsafe-kill.sh must refuse the pattern kill bash runs.

The shape that founds it: `printf %s $(true)#x; pkill -f X`, where the `#` begins no comment.
"""
import json, os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import bash_parse  # noqa: E402

CASES = [
    # (description, command line)
    ("# after $(...)", "printf %s $(true)#x; pkill -f X"),
    ("# after <(...)", "printf %s <(true)#x; pkill -f X"),
    ("# after >(...)", "printf %s >(true)#x; pkill -f X"),
    ("# after $((...))", "printf %s $((1))#x; pkill -f X"),
    ("# after $((...)) holding a base #", "printf %s $((2#101))#x; pkill -f X"),
    ("# after two $(...)", "printf %s $(true)$(true)#x; pkill -f X"),
    ("# after $(...) in a word", "printf %s a$(true)#x; pkill -f X"),
    ("# after $(...) holding a )", "printf %s $(case a in a) true;; esac)#x; pkill -f X"),
    ("# after $(...) inside $(...)", "printf %s $(printf %s $(true)#x; true); pkill -f X"),
    ("# after $(...) in a case arm", "case a in a) printf %s $(true)#x; pkill -f X;; esac"),
    ("# after $(...), then a quote", "printf %s $(true)#x'y; pkill -f X'\ntrue"),
    # the controls: a `)` that ends a word, and a space, open a comment
    ("# after a subshell's )", "(true)#x; pkill -f X"),
    ("# after a (( )) command", "((1))#x; pkill -f X"),
    ("# after a case pattern's )", "case a in a)#x; pkill -f X\n;; esac"),
    ("# after $(...) and a space", "printf %s $(true) #x; pkill -f X"),
    ("# after <(...) and a space", "printf %s <(true) #x; pkill -f X"),
]


# Every program a fixture could signal with is a function here, so the oracle runs nothing real.
SHADOW = "pkill(){ echo RAN; }; kill(){ :; }; pgrep(){ :; }; killall(){ :; }\n"


def bash_runs(line):
    p = bash_oracle.run(["bash", "-c", SHADOW + line],
                        capture_output=True, text=True, timeout=20)
    return "RAN" in p.stdout


def hook_exit(line):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": line}})
    p = subprocess.run(["bash", os.path.join(ROOT, "hooks", "block-unsafe-kill.sh")],
                       input=payload, capture_output=True, text=True, timeout=30)
    return p.returncode


red, positives = [], 0
for desc, line in CASES:
    want = bash_runs(line)
    positives += want
    got = "pkill" in [c.name for c in bash_parse.parse(line) if c.kw is None]
    rc = hook_exit(line)
    ok = got == want and ((rc == 2) if want else True)
    print("  %s %-38s bash runs pkill: %-5s parse names it: %-5s hook exit %d"
          % ("ok " if ok else "RED", desc, want, got, rc))
    if not ok:
        red.append(desc)

# Controls: the oracle must have said yes and no, or the comparison proves nothing.
if positives in (0, len(CASES)):
    red.append("oracle gave the same answer for every case (%d of %d run pkill)" % (positives, len(CASES)))
print("%d of %d red" % (len(red), len(CASES)))
sys.exit(1 if red else 0)
