"""Check for hooks/tests/INVARIANTS.md mh-a-words-value-is-bash-quote-removal, written from the hooks/tests/INVARIANTS.md clause alone:

  hooks/bash_parse.py gives every word the value bash's quote removal gives it -- '...' literal,
  an unquoted backslash escaping any character, a backslash inside "..." or $"..." escaping only
  $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
  substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
  runs it as code is read as the code bash runs.

THE ORACLE IS BASH. For a word with no expansion left in it after quoting, bash's own
`printf '%s\\0' WORD...` prints exactly the values quote removal gives, and the words it prints
are exactly where bash ends each word. So every such case is asserted against bash run on this
host, never against a value typed here. The directions, each a way the sentence can be false:

  SQ      '...' literal: a backslash, `$`, `"`, a newline, `$(...)` and a backtick inside it.
  BS      an unquoted backslash escapes ANY character -- quote characters, `$`, a backslash, a
          letter, a space (no word break), and every operator character (`;` `|` `&` `<` `>`
          `(` `)` `#`), none of which may then separate or start anything.
  DQ      inside "...", a backslash escapes only $ ` " \\ and a newline; before anything else
          (a letter, `'`, `n`) it is kept. `$'` inside "..." is no ANSI quote.
  LDQ     $"..." exactly as "...".
  ANSI    $'...' with every escape bash decodes: the named ones, octal \\nnn, \\xHH, \\uHHHH,
          \\UHHHHHHHH, \\cx, multi-byte UTF-8 from byte escapes, and an escape bash does not know
          kept backslash and all.
  MIX     several quoting forms glued into one word, and several words in one command (where
          each word ends).
  SUBST   a command or process substitution kept as the code it is: the value holds the
          substitution's text exactly as written, in or out of "...", whatever quotes,
          backslashes, parentheses, comments or nested substitutions are inside it, and the word
          does not end inside it. (Hand-stated expectations: bash would run it, not print it.)
  CODE    the consequence: the code handed to `eval` (its words' values joined by spaces, as
          bash's eval joins them), `bash -c`, and the programs that run one string as shell code
          (`su -c`, `flock F -c`, `script -c`, `watch`, `trap`, `sg -c`, `git rebase -x`,
          `ssh localhost`), is the value bash hands them -- checked for every bash-oracle word.
  NAME    a command word's value is the name it runs: `k'i'll`, `$'\\x6b'ill`, `ba\\sh <<E`.

Exit 0 when every case matches; otherwise each mismatch is printed with its direction and the
exit status is 1.
"""
import os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOKS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, HOOKS)
import bash_parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
NL = "\n"

# (direction, the words as a shell writes them -- one or more, space separated)
ORACLE = [
    ("SQ", "'a b'"), ("SQ", "'a\\b'"), ("SQ", "'a\\\\b'"), ("SQ", "'$x'"), ("SQ", "'\"'"),
    ("SQ", "'a\\'"), ("SQ", "'$(pgrep -f X)'"), ("SQ", "'`pgrep -f X`'"), ("SQ", "'a\\nb'"),
    ("SQ", "''"), ("SQ", "'line1" + NL + "line2'"), ("SQ", "'it'\\''s'"), ("SQ", "'a;b|c&d'"),
    ("SQ", "'\\" + NL + "x'"), ("SQ", "'#x'"),
    ("BS", "a\\ b"), ("BS", "\\$x"), ("BS", "\\'"), ("BS", '\\"'), ("BS", "\\\\"), ("BS", "\\a"),
    ("BS", "\\n"), ("BS", "a\\;b"), ("BS", "a\\|b"), ("BS", "a\\&b"), ("BS", "a\\>b"),
    ("BS", "a\\<b"), ("BS", "\\(a\\)"), ("BS", "\\#x"), ("BS", "\\*"), ("BS", "\\~"),
    ("BS", "a\\" + NL + "b"), ("BS", "\\\\\\$"), ("BS", "\\$\\(pgrep -f X\\)"), ("BS", "\\`x\\`"),
    ("BS", "a\\\tb"), ("BS", "\\$'x'"), ("BS", "\\{a,b\\}"),
    ("DQ", '"a b"'), ("DQ", '"\\$x"'), ("DQ", '"\\`"'), ("DQ", '"\\""'), ("DQ", '"\\\\"'),
    ("DQ", '"\\a"'), ("DQ", '"\\n"'), ("DQ", '"\\\'"'), ("DQ", '"a\\' + NL + 'b"'), ("DQ", '"\'"'),
    ("DQ", '"$\'x\'"'), ("DQ", '"a;b|c&d"'), ("DQ", '"#x"'), ("DQ", '"\\\\\\$"'), ("DQ", '"x\\\\"y'),
    ("DQ", '""'), ("DQ", '"\\$(pgrep -f X)"'), ("DQ", '"\\`pgrep -f X\\`"'), ("DQ", '"$"'),
    ("DQ", '"a' + NL + 'b"'), ("DQ", '"\\\\$"'), ("DQ", '"(a)"'), ("DQ", '"\\{"'),
    ("LDQ", '$"a b"'), ("LDQ", '$"\\$x"'), ("LDQ", '$"\\a"'), ("LDQ", '$"\\""'), ("LDQ", '$"\\\\"'),
    ("LDQ", '$"\\`"'), ("LDQ", '$"x\\' + NL + 'y"'), ("LDQ", '$"\'"'),
    ("ANSI", "$'a\\nb'"), ("ANSI", "$'\\t'"), ("ANSI", "$'\\x41'"), ("ANSI", "$'\\x4'"),
    ("ANSI", "$'\\x4g'"), ("ANSI", "$'\\101'"), ("ANSI", "$'\\1012'"), ("ANSI", "$'\\7'"),
    ("ANSI", "$'\\u00e9'"), ("ANSI", "$'\\U0001F600'"), ("ANSI", "$'\\u41'"), ("ANSI", "$'\\cA'"),
    ("ANSI", "$'\\ca'"), ("ANSI", "$'\\c['"), ("ANSI", "$'\\e'"), ("ANSI", "$'\\E'"),
    ("ANSI", "$'\\''"), ("ANSI", "$'\\\"'"), ("ANSI", "$'\\\\'"), ("ANSI", "$'\\?'"),
    ("ANSI", "$'\\q'"), ("ANSI", "$'\\xg'"), ("ANSI", "$'\\$'"), ("ANSI", "$'it\\'s'"),
    ("ANSI", "$'\\xc3\\xa9'"), ("ANSI", "$'a b'"), ("ANSI", "$'\\x24(pgrep -f X)'"),
    ("ANSI", "$'\\8'"), ("ANSI", "$'\\a\\b\\f\\v\\r'"), ("ANSI", "$'\\c?'"), ("ANSI", "$'\\x'"),
    ("ANSI", "$'\\u'"), ("ANSI", "$'\\cz'"), ("ANSI", "$'\\0101'"), ("ANSI", "$'\\x7e\\x41'"),
    ("ANSI", "$'\\303\\251'"), ("ANSI", "$'\\u00e9\\x41'"), ("ANSI", "$'\\`'"), ("ANSI", "$'\\('"),
    ("ANSI", "$'\\" + NL + "x'"), ("ANSI", "$'\"'"), ("ANSI", "$'\\x{41}'"), ("ANSI", "$'\\c\\\\'"),
    ("ANSI", "$'\\U41'"), ("ANSI", "$'\\x41\\x42\\x43'"), ("ANSI", "$'\\x{7e}'"), ("ANSI", "$'\\cA\\cb'"), ("ANSI", "$'\\101\\102'"),
    ("MIX", "a'b'\"c\"$'d'\\e$\"f\""), ("MIX", "$'\\x41'\"\\$\"'$'"), ("MIX", "a\\ b c"),
    ("MIX", '"a b"c d'), ("MIX", "$'a\\tb' c"), ("MIX", "'a;b' c"), ("MIX", "a\\;b c"),
    ("MIX", "'a'\"b\" $'c'd \\e"), ("MIX", "\"'\"'\"'"), ("MIX", "x\"\\$\"'\\$'$'\\x24'"),
    ("MIX", "'' \"\" $'' $\"\""), ("MIX", "\"a\\\"b\" 'c\\'"), ("MIX", "\\'\\\" '\\'"),
]

# (direction, word, the value it must have: the substitution's text kept as written)
SUBST = [
    ("SUBST", "x$(echo a b)y", "x$(echo a b)y"),
    ("SUBST", '"x$(echo "a b")y"', 'x$(echo "a b")y'),
    ("SUBST", "\"$(printf '%s' \"\\$x\")\"", "$(printf '%s' \"\\$x\")"),
    ("SUBST", "$(echo ')')", "$(echo ')')"),
    ("SUBST", '"a$(echo ")")b"', 'a$(echo ")")b'),
    ("SUBST", "$(echo $(echo a))", "$(echo $(echo a))"),
    ("SUBST", "\"$(echo 'it'\\''s')\"", "$(echo 'it'\\''s')"),
    ("SUBST", "$(case a in a) echo;; esac)", "$(case a in a) echo;; esac)"),
    ("SUBST", "$(echo a # )" + NL + ")", "$(echo a # )" + NL + ")"),
    ("SUBST", "<(echo a b)", "<(echo a b)"),
    ("SUBST", ">(cat -n)", ">(cat -n)"),
    ("SUBST", "`echo a b`", "`echo a b`"),
    ("SUBST", '"`echo a b`"', "`echo a b`"),
    ("SUBST", "'q'$(echo \\\" \"$x\")'q'", "q$(echo \\\" \"$x\")q"),
    ("SUBST", "\\$$(echo a)", "$$(echo a)"),
    ("SUBST", "\"\\\\$(echo a)\"", "\\$(echo a)"),
    ("SUBST", "$'a'$(echo \"\\n\")", "a$(echo \"\\n\")"),
    ("SUBST", "\"$(echo \"$(echo 'a b')\")\"", "$(echo \"$(echo 'a b')\")"),
    ("SUBST", "$(echo a\\)b)", "$(echo a\\)b)"),
    ("SUBST", "$( (echo a) )", "$( (echo a) )"),
    ("SUBST", "$(case a in (a) echo;; esac)", "$(case a in (a) echo;; esac)"),
    ("SUBST", '"$(case a in a) echo x;; esac)"', "$(case a in a) echo x;; esac)"),
    ("SUBST", "$(echo `echo a`)", "$(echo `echo a`)"),
    ("SUBST", "$(echo $((1+2)))", "$(echo $((1+2)))"),
    ("SUBST", "a$(echo b)c$(echo d)e", "a$(echo b)c$(echo d)e"),
    ("SUBST", "\"$(cat <<'E'" + NL + ")" + NL + "E" + NL + ")\"", "$(cat <<'E'" + NL + ")" + NL + "E" + NL + ")"),
]

# Programs that run ONE word as shell code: (template with W, how to find the Cmd by name)
RUNNERS = [
    ("eval W", "eval"), ("bash -c W", "bash"), ("sh -c W", "sh"), ("su -c W", "su"),
    ("flock /tmp/l -c W", "flock"), ("script -qc W /dev/null", "script"), ("watch W", "watch"),
    ("trap W EXIT", "trap"), ("sg users -c W", "sg"), ("git rebase -x W", "git"),
    ("ssh localhost W", "ssh"),
]


def bash_values(words):
    p = bash_oracle.run(["bash", "--norc", "--noprofile", "-c", "printf '%s\\0' " + words],
                       capture_output=True, env=ENV)
    if p.returncode != 0:
        raise SystemExit("bash refused the oracle case %r: %r" % (words, p.stderr))
    return [b.decode("utf-8", "surrogateescape") for b in p.stdout.split(b"\0")[:-1]]


def top(text, name=None):
    cmds = [c for c in bash_parse.parse(text) if c.kw is None]
    at0 = [c for c in cmds if c.pos == 0]
    if name is None:
        return at0[0] if at0 else None
    return next((c for c in cmds if c.name == name), None)


fails, cases = [], 0


def check(direction, what, got, want):
    global cases
    cases += 1
    if got != want:
        fails.append("%-5s %s\n        got  %r\n        want %r" % (direction, what, got, want))


def safe(fn, *a):
    try:
        return fn(*a)
    except Exception as e:                          # a reader that raises gives no value
        return "<raised %s: %s>" % (type(e).__name__, e)


def printf_words(text):
    c = top(text)
    return [v for _, v in c.words[2:]] if c and c.name == "printf" else "<no printf at offset 0>"


for d, w in ORACLE:
    want = bash_values(w)
    check(d, "printf '%%s\\0' %s" % w, safe(printf_words, "printf '%s\\0' " + w), want)
    # CODE: eval joins its arguments with spaces; the others take the one word
    for tmpl, name in RUNNERS:
        if name != "eval" and len(want) != 1:
            continue
        text = tmpl.replace("W", w)
        code = " ".join(want) if name == "eval" else want[0]
        got = safe(lambda t, n: (top(t).codes if top(t) else "<no %s>" % n), text, name)
        if isinstance(got, list):
            got = code if code in got else got
        check("CODE", "%s  [%s]" % (text, d), got, code)

for d, w, want in SUBST:
    check(d, "printf '%%s\\0' %s" % w, safe(printf_words, "printf '%s\\0' " + w), [want])
    for tmpl, name in RUNNERS[:2]:
        text = tmpl.replace("W", w)
        got = safe(lambda t, n: (top(t).codes if top(t) else "<no %s>" % n), text, name)
        if isinstance(got, list):
            got = want if want in got else got
        check("CODE", "%s  [%s]" % (text, d), got, want)

# CODE, end to end: a kill whose pids come from a substitution, handed on through quoting.
for text in ['eval "kill \\$(pgrep -f X)"', "eval $'kill \\x24(pgrep -f X)'",
             "eval kill \\$\\(pgrep -f X\\)", "eval \"P=\\$(pgrep -f X)\"\\; kill '\"$P\"'",
             'bash -c "a=\\"\\$(pgrep -f X)\\"; kill \\$a"', "eval $\"kill \\$(pgrep -f X)\"",
             "eval 'kill '\"\\$(\"'pgrep -f X)'"]:
    want = " ".join(bash_values(text.split(" ", 1)[1] if text.startswith("eval") else text[8:]))
    c = top(text)
    got = c.codes if c else []
    check("CODE", text, want in got and want or got, want)
    inner = [x.name for x in safe(bash_parse.parse, want) or [] if getattr(x, "kw", 1) is None] \
        if want in got else []
    check("CODE", "%s  -> commands of the handed code" % text, "pgrep" in inner, True)

# NAME: a command word's value is the program it runs.
for w in ["k'i'll", '"kill"', "k\\ill", "$'\\x6b'ill", "$'kill'", '$"kill"', "\\kill", "'k'\"i\"ll"]:
    c = top(w + " 1")
    check("NAME", w + " 1", c.name if c else None, "kill")
for w in ["ba\\sh", "'bash'", '"ba"sh', "$'\\x62ash'", "$'bash'"]:
    text = w + " <<'E'" + NL + "pgrep -f X" + NL + "E" + NL
    names = [x.name for x in safe(bash_parse.parse, text) or [] if getattr(x, "kw", 1) is None]
    base = [x.name for x in bash_parse.parse("bash <<'E'" + NL + "pgrep -f X" + NL + "E" + NL) if x.kw is None]
    check("NAME", repr(text), "pgrep" in names, "pgrep" in base)

for f in fails:
    print("FAIL", f)
print("%d of %d cases red" % (len(fails), cases))
sys.exit(1 if fails else 0)
