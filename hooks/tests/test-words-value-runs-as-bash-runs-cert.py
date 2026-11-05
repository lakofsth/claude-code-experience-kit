#!/usr/bin/env python3
"""A word's value is bash's quote removal, checked by RUNNING the code bash_parse reads off.

The sentence (hooks/tests/INVARIANTS.md mh-a-words-value-is-bash-quote-removal):

  hooks/bash_parse.py gives every word the value bash's quote removal gives it -- '...' literal,
  an unquoted backslash escaping any character, a backslash inside "..." or $"..." escaping only
  $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
  substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
  runs it as code is read as the code bash runs.

Written from the hooks/tests/INVARIANTS.md clause alone, beside test-words-value-blind-recertify.py, which states a substitution's expected value as its text
kept verbatim. This check states none: every expectation is a real bash run.

  Q. a word with no expansion in it ('...', unquoted \\, \\ in "..." and $"...", $'...') has the
     value bash prints for it, through unquote() and as parse() reads it in a command;
  C. "kept as the code it is", read by running it: the code parse() says `eval WORD` or `bash -c
     WORD` hands on, run by bash, prints what bash prints running the original command. A
     substitution kept as text that bash would run differently fails here -- a backtick body
     whose \\$, \\` and \\\\ (and, inside "...", \\") bash un-escapes before running it. Each
     fixture's substitutions print no quote, backslash, `$` or blank, because the outer shell
     re-reads a substitution's OUTPUT as code and running the handed code directly does not;
     the two runs agree only where that output reads the same either way;
  B. the words of a substitution's body are words too: the printf a `...` or $(...) body runs is
     read by parse() with the arguments bash gives that printf.
"""
import os, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bash_parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
CWD = tempfile.mkdtemp()
failures, total = [], 0


def bash(script):
    return bash_oracle.run(["bash", "--norc", "--noprofile", "-c", script], capture_output=True,
                          cwd=CWD, env=ENV, timeout=20).stdout.decode("utf-8", "surrogateescape")


def check(label, got, want):
    global total
    total += 1
    if got != want:
        failures.append(label)
        print(f"  RED  {label}\n         bash: {want!r}\n         ours: {got!r}")


print("Q: a word with no expansion has the value bash's quote removal gives it")
Q_WORDS = [
    r"'a\b'", r"'a\"b'", r"'$(x)'", r"'`x`'",                         # '...' literal
    r"a\ b", r"\q", r"\'", r'\"', r"\$x", r"\`x\`", r"\\", r"a\\\\b",  # unquoted \
    r'"\q"', r'"\$"', r'"\`"', r'"\""', r'"\\"', r'"\'"', '"a\\\nb"', r'"\n\t"',  # \ in "..."
    r'$"\q"', r'$"\$\`\"\\"', '$"a\\\nb"', r'''$"it's\a"''',                   # $"..."
    r"$'a\nb'", r"$'\x41\101\u263a'", r"$'\'\"\\'", r"$'\cA\e'", r"$'\q'",   # $'...'
    r"""a'b'"c"$'d'$"e"\f""", "'\"'\"'\"'\"'", r'"$'"'"'a'"'"'"',            # mixed
]
for word in Q_WORDS:
    want = bash("printf '%s\\0' " + word).split("\0")[0]
    check(f"[Q] unquote({word})", bash_parse.unquote(word), want)
    cmds = [c for c in bash_parse.parse("printf %s " + word) if c.kw is None]
    check(f"[Q] parse(printf %s {word})", [v for _, v in cmds[0].words[2:]] if cmds else None,
          [want])
print(f"  Q: {len(Q_WORDS) * 2} checked")


print("C: the code handed to eval / bash -c, run by bash, does what bash does with the original")
C_CMDS = [
    r'''eval "$(printf %s 'printf [%s] c1')"''',
    r'''eval "`printf %s \"printf [%s] c2\"`"''',
    r"""eval `echo printf [%s] \$((2+3))`""",
    r'''eval "x=\`printf %s \\\"c 6\\\"\`; printf [%s] \"\$x\""''',
    r'''bash -c "`printf %s \"printf [%s] c7\"`"''',
    r'''bash -c "printf [%s] $(printf %s \"c8\" | wc -c)"''',
    r'''bash -c "printf [%s] \"`printf %s \\\"c9\\\" | wc -c`\""''',
    r"""eval cat <(printf [c10])""",
    r"""eval 'printf [%s] "$(printf %s "c 11")"'""",
]
for cmd in C_CMDS:
    want = bash(cmd)
    if not want:
        check(f"[C] fixture {cmd}", "<bash prints nothing: not a fixture>", "<output>"); continue
    head = cmd.split()[0]
    hosts = [c for c in bash_parse.parse(cmd) if c.kw is None and c.name == head]
    codes = hosts[0].codes if hosts else []
    got = bash(codes[0]) if len(codes) == 1 else f"<{len(codes)} codes: {codes!r}>"
    check(f"[C] {cmd}  (handed {codes!r})", got, want)
print(f"  C: {len(C_CMDS)} checked")


print("B: the words of a substitution's body are the words bash gives the command it runs")
B_CMDS = [
    r''': "`printf '<%s>' \"b 1\" b2`"''',
    r""": `printf '<%s>' '\$b3' \\\\b4`""",
    r''': "`printf '<%s>' \\\$b6 '\"b7\"'`"''',
    r""": $(printf '<%s>' \"b8 b9\" '\$b10')""",
    r''': "$(printf '<%s>' "b 11" \\b12)"''',
]
for cmd in B_CMDS:
    want = bash(cmd.replace(": ", "printf %s ", 1))
    inner = [c for c in bash_parse.parse(cmd) if c.kw is None and c.name == "printf"]
    if not inner:
        check(f"[B] {cmd}", "<no printf read in the body>", want); continue
    vals = [v for _, v in inner[0].words[1:]]
    got = "".join(f"<{v}>" for v in vals[1:]) if vals[:1] == ["<%s>"] else f"<format {vals[:1]!r}>"
    check(f"[B] {cmd}", got, want)
print(f"  B: {len(B_CMDS)} checked")


print(f"{total - len(failures)} of {total} green")
if failures:
    print(f"RED: {len(failures)} case(s) where bash_parse's value is not the one bash gives")
    sys.exit(1)
