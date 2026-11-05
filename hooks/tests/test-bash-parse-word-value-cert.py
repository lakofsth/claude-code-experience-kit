#!/usr/bin/env python3
"""Check for hooks/tests/INVARIANTS.md `mh-a-words-value-is-bash-quote-removal`.

The sentence: hooks/bash_parse.py gives every word the value bash's quote removal gives it --
'...' literal, an unquoted backslash escaping any character, a backslash inside "..." or $"..."
escaping only $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
runs it as code is read as the code bash runs.

Written from the hooks/tests/INVARIANTS.md clause alone. Directions:

  A. single quotes are literal (a backslash inside them is a backslash);
  B. an unquoted backslash escapes any character;
  C. inside "..." a backslash escapes $ ` " \\ (and newline) and NOTHING else -- `\\q` stays two
     characters, `\\$` is one `$`;
  D. $"..." reads as "..." does (the translation is the identity in the C locale);
  E. $'...' has its ANSI-C escapes decoded;
  F. a $(...), `...`, <(...) or >(...) inside a word is kept as its own code, byte for byte, and
     the word stays ONE word around it;
  G. the consequence: the string eval or bash -c runs (Cmd.codes) is the value bash gives it, so
     an escaped `\\$(...)` inside double quotes is read as the live substitution it becomes.

Directions A-E and G take their expected value from bash itself (each word is printed by a real
`bash -c 'printf "%s\\0" WORD'`), never from a table written here. Direction F's expectation is
the substitution's own text, which bash would run rather than print.
"""
import os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bash_parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")


def bash_value(word):
    """The value bash gives WORD after quote removal (no expansion happens in these fixtures)."""
    out = bash_oracle.run(["bash", "--norc", "--noprofile", "-c", "printf '%s\\0' " + word],
                         capture_output=True, env=ENV, check=True).stdout
    vals = out.split(b"\0")[:-1]
    assert len(vals) == 1, f"fixture {word!r} is not one word to bash: {vals!r}"
    return vals[0].decode("utf-8")


# Words with no expansion in them, so bash's printed value IS the value of quote removal.
PLAIN = [
    # A. single quotes literal
    ("A", r"'a\b'"), ("A", r"'a\\b'"), ("A", r"'a\"b'"), ("A", "'a$b'"), ("A", "'a`b'"),
    ("A", r"'a\nb'"), ("A", "'a\"b'"), ("A", "'a b'"),
    # B. unquoted backslash escapes any character
    ("B", r"a\b"), ("B", r"a\q"), ("B", r"a\$b"), ("B", r"a\`b"), ("B", r"a\"b"), ("B", r"a\'b"),
    ("B", r"a\\b"), ("B", r"a\ b"), ("B", r"a\;b"), ("B", r"a\|b"), ("B", r"a\(b\)"),
    ("B", r"\$\(id\)"), ("B", r"a\nb"),
    # C. backslash in double quotes escapes only $ ` " \
    ("C", r'"a\$b"'), ("C", r'"a\`b"'), ("C", r'"a\"b"'), ("C", r'"a\\b"'), ("C", r'"a\qb"'),
    ("C", r'"a\nb"'), ("C", r'''"a\'b"'''), ("C", r'"a\ b"'), ("C", r'"\$\(id\)"'),
    ("C", r'"a\\\$b"'), ("C", r'"a\\\\b"'), ("C", r'"a\\\qb"'), ("C", r'''"a'b"'''),
    ("C", r'"\$(pgrep -f x)"'), ("C", r'"\`pgrep -f x\`"'),
    # D. $"..." reads as "..."
    ("D", r'$"a\$b"'), ("D", r'$"a\`b"'), ("D", r'$"a\"b"'), ("D", r'$"a\\b"'), ("D", r'$"a\qb"'),
    ("D", r'$"a b"'), ("D", r'x$"y"z'),
    # E. $'...' escapes decoded
    ("E", r"$'a\nb'"), ("E", r"$'a\tb'"), ("E", r"$'a\\b'"), ("E", r"$'a\'b'"), ("E", r"$'a\"b'"),
    ("E", r"$'a\x41b'"), ("E", r"$'a\101b'"), ("E", r"$'a\u00e9b'"), ("E", r"$'a\rb'"),
    ("E", r"$'a\ab'"), ("E", r"$'a\eb'"), ("E", r"$'a\vb'"), ("E", r"$'a\fb'"), ("E", r"$'a\?b'"),
    ("E", r"$'a\qb'"), ("E", r"$'a$b'"), ("E", r"$'a b'"), ("E", r"x$'\x24(id)'y"),
    # concatenations of every kind in one word
    ("ABCE", r"""'a\'b\ "c\$d"$'\x65'"""), ("BCD", r'''a\ "b\q"$"c\$"'''),
]

# F. a substitution inside a word: (word, the value it must have -- the substitution as its code).
SUBST = [
    ('x$(echo "a b")y', 'x$(echo "a b")y'),
    ("x$(echo 'a b')y", "x$(echo 'a b')y"),
    ('"x$(echo "a b")y"', 'x$(echo "a b")y'),
    ('"x$(printf \'%s\' "a\\qb")y"', 'x$(printf \'%s\' "a\\qb")y'),
    ('"$(pgrep -f "my job")"', '$(pgrep -f "my job")'),
    ('x`echo a`y', 'x`echo a`y'),
    ('"x`echo a`y"', 'x`echo a`y'),
    ('<(echo "a b")', '<(echo "a b")'),
    ('x>(cat)', 'x>(cat)'),
    ("a\\ $(echo 'b c')", "a $(echo 'b c')"),
    ("'q'$(echo 'b c')\"d\\$\"", "q$(echo 'b c')d$"),
]


def word_value(word):
    """The value bash_parse gives WORD as the third word of `printf %s WORD`: the printf at offset
    0, since a substitution's own commands are listed beside it (a `printf` inside one too)."""
    cmds = [c for c in bash_parse.parse("printf %s " + word) if c.name == "printf" and c.pos == 0]
    if len(cmds) != 1:
        return f"<{len(cmds)} printf commands>"
    w = cmds[0].words
    if len(w) != 3:
        return f"<printf read as {len(w)} words: {[v for _, v in w]!r}>"
    return w[2][1]


def handed_code(prefix, word):
    """The code strings bash_parse says `PREFIX WORD` hands a shell."""
    codes = []
    for c in bash_parse.parse(prefix + " " + word):
        codes += c.codes
    return codes


failures, total = [], 0


def check(label, got, want):
    global total
    total += 1
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: got {got!r}" + ("" if ok else f", bash: {want!r}"))
    if not ok:
        failures.append(label)


print("A-E: the value of a plain word is bash's quote removal")
for d, word in PLAIN:
    check(f"[{d}] printf %s {word}", word_value(word), bash_value(word))

print("F: a substitution in a word is kept as its own code, in one word")
for word, want in SUBST:
    check(f"[F] printf %s {word}", word_value(word), want)

print("G: the string eval / bash -c / sh -c runs is the value bash gives it")
CODE_WORDS = [
    r'"kill \$(pgrep -f x)"', r'"kill \`pgrep -f x\`"', r"'kill $(pgrep -f x)'",
    r"$'kill $(pgrep -f x)'", r"$'kill \x24(pgrep -f x)'", r'kill\ \$\(pgrep\ -f\ x\)',
    r'$"kill \$(pgrep -f x)"', r'"echo \"a\\b\" \q"', r"$'echo a\nkill 1'",
]
for prefix in ("eval", "bash -c", "sh -c"):
    for word in CODE_WORDS:
        check(f"[G] {prefix} {word}", handed_code(prefix, word), [bash_value(word)])
# eval joins its arguments with spaces, after quote removal of each
multi = ['kill', r'"\$(pgrep"', r"$'-f'", r"x\)"]
check("[G] eval " + " ".join(multi), handed_code("eval", " ".join(multi)),
      [" ".join(bash_value(w) for w in multi)])

print(f"{total - len(failures)} of {total} green")
if failures:
    print(f"RED: {len(failures)} word(s) not given bash's value")
    sys.exit(1)
