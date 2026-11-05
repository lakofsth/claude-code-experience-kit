"""Check for hooks/tests/INVARIANTS.md `mh-a-words-value-is-bash-quote-removal`, the clause "an
unquoted backslash escaping any character", at the sites where the shared scanner
(hooks/quote_mask.py) decides what the character BEFORE a position is: a `#` opens a comment
only after a word break, and `<<` is a heredoc unless a `<` comes before it. A character a
backslash escaped is a word character, never a break or an operator, and a continuation
(backslash-newline) is removed before bash lexes, while a backslash inside a comment is text.

Bash is the oracle: each line is run with `pkill` defined as a function that prints RAN, and
`hooks/bash_parse.py` parse() must name `pkill` exactly when bash runs it. Then
hooks/block-unsafe-kill.sh must refuse the pattern kill bash runs.

The shape that founds it: `echo a\\;#; pkill -f X`, where the `#` begins no comment.
"""
import json, os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import bash_parse  # noqa: E402

CASES = [
    # (description, command line)
    ("# after an escaped ;", "echo a\\;#; pkill -f X"),
    ("# after an escaped space", "echo a\\ #b; pkill -f X"),
    ("# after an escaped |", "echo a\\|#b; pkill -f X"),
    ("# after an escaped (", "echo a\\(#b; pkill -f X"),
    ("# after an escaped tab", "echo a\\\t#b; pkill -f X"),
    ("# after an escaped newline in a word", "echo a\\\n#b; pkill -f X"),
    ("# after an escaped ; inside $(...)", "echo $(echo a\\;#b); pkill -f X"),
    ("# after an escaped ; with an apostrophe after", "echo a\\;#'b; pkill -f X"),
    # the controls: a real comment hides the kill, and a backslash in a comment is text
    ("# after a space", "echo a #b; pkill -f X"),
    ("# after a continuation", "echo \\\n#b; pkill -f X"),
    ("a comment ending in a backslash", "# x \\\npkill -f X"),
    ("a comment ending in a backslash, then a #", "true # x \\\n#'y\npkill -f X"),
    # `<<` after an escaped `<` is still a heredoc; its body is not code
    ("<< after an escaped <", "cat \\<<<EOF\ndon't\nEOF\npkill -f X"),
    ("<< after an escaped <, body holds the kill", "cat \\<<<EOF\npkill -f X\nEOF\ntrue"),
    ("<<< is a herestring", "cat <<<x\npkill -f X"),
]


# Every program a fixture could signal with is a function here, so the oracle runs nothing real.
SHADOW = ("pkill(){ echo RAN; }; kill(){ :; }; pgrep(){ :; }; killall(){ :; }; "
          "cat(){ command cat >/dev/null; }\n")


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
    print("  %s %-48s bash runs pkill: %-5s parse names it: %-5s hook exit %d"
          % ("ok " if ok else "RED", desc, want, got, rc))
    if not ok:
        red.append(desc)

# Controls: the oracle must have said yes and no, or the comparison proves nothing.
if positives in (0, len(CASES)):
    red.append("oracle gave the same answer for every case (%d of %d run pkill)" % (positives, len(CASES)))
print("%d of %d red" % (len(red), len(CASES)))
sys.exit(1 if red else 0)
