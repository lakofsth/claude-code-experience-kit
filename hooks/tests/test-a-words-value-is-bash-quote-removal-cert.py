"""Check for hooks/tests/INVARIANTS.md mh-a-words-value-is-bash-quote-removal, written from the hooks/tests/INVARIANTS.md clause alone:

  hooks/bash_parse.py gives every word the value bash's quote removal gives it -- '...' literal,
  an unquoted backslash escaping any character, a backslash inside "..." or $"..." escaping only
  $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
  substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
  runs it as code is read as the code bash runs.

The oracle is bash itself, never a table written here: each word is handed to
`bash -c 'printf "%s\\0" WORD'` (LC_ALL=C.UTF-8) and what bash prints is the value. The value
bash_parse gives is read through its public reader, parse(): the word is the operand of a neutral
command (`wordprobe WORD`) and its value is that Cmd's words[1][1] (SUBST excepted, below). The directions, each a way the
sentence can be false:

  SQ      '...' literal: every printable ASCII character inside single quotes, backslash and
          `$(` included;
  BS      an unquoted backslash before every printable ASCII character, and a backslash with
          nothing after it (the end of the text), which bash keeps;
  DQ      a backslash before every printable ASCII character inside "..." and inside $"...":
          removed before $ ` " \\ and a newline, kept before anything else;
  ANSI    $'...' with every escape bash decodes -- the letters, \\' \\" \\\\ \\?, \\xH and \\xHH,
          octal \\N \\NN \\NNN, \\uH..HHHH, \\UH..HHHHHHHH, \\cX for every X -- and an unknown
          escape kept; only escapes whose value is ASCII or a whole UTF-8 character are asked
          (a lone byte >= 0x80 has no single str spelling), and none whose value is NUL;
  MIX     words concatenating every context, and quotes that look like other contexts ("$'x'",
          '"', "'");
  SUBST   $(...), `...`, <(...) and >(...), unquoted and inside "...", with quotes, backslashes
          and `)` in the body, kept as written while the text around them is quote-removed (the
          oracle is bash's value of the same word with the substitution replaced by a token).
          parse() reads a substitution's body as commands of their own, so a word holding one
          is never one Cmd word; its value is asked of unquote(), which hooks/tests/INVARIANTS.md's site
          derivation names the one place a word's value is made;
  CODE    the same words handed to `eval WORD` and `bash -c WORD`: the code string parse()
          hands on is bash's value of the word, for words that spell code through each context
          ($'\\x24(...)', "\\$(...)", $'\\044(...)', ...).

Every case is printed with its verdict; an empty corpus is red.
"""
import os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOKS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, HOOKS)
from bash_parse import parse, unquote  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8")
PRINTABLE = [chr(c) for c in range(0x20, 0x7f)]


def bash_value(word):
    p = bash_oracle.run(["bash", "-c", 'printf "%s\\0" ' + word], capture_output=True, env=ENV)
    if p.returncode != 0 or not p.stdout.endswith(b"\0") or p.stdout.count(b"\0") != 1:
        return None
    return p.stdout[:-1].decode("utf-8", "surrogateescape")


def parsed_value(word):
    cmds = [c for c in parse("wordprobe " + word) if c.kw is None]
    if len(cmds) != 1 or len(cmds[0].words) != 2:
        return ("<not one word: %r>" % [[w for w in c.words] for c in cmds])
    return cmds[0].words[1][1]


def sq(s):
    return "'" + s.replace("'", "'\\''") + "'"


cases = []   # (direction, word)

# SQ
cases += [("SQ", "'%s'" % c) for c in PRINTABLE if c != "'"]
cases += [("SQ", w) for w in [r"'a\b\\c'", "'$(x)'", "'`x`'", "'a\"b'", r"'\'", "'$HOME'", "'a\nb'"]]

# BS
cases += [("BS", "\\" + c) for c in PRINTABLE]
cases += [("BS", "a\\" + c + "b") for c in PRINTABLE]
cases += [("BS", w) for w in ["a\\", "\\\\\\", "\\\\\\\\"]]

# DQ
cases += [("DQ", '"\\%s"' % c) for c in PRINTABLE]
cases += [("DQ", '$"\\%s"' % c) for c in PRINTABLE]
cases += [("DQ", w) for w in ['"a\\\nb"', '$"a\\\nb"', '"a\nb"', '"\\\\\\""', '"\\\\$x"' if False else '"\\\\\\$x"']]

# ANSI
ansi = [c for c in "abeEfnrtv'\"\\?"] + ["z", "q", "%", "y", "8", "9"]
ansi += ["x41", "x7e", "x7", "x4", "x41B", "xg", "x"]
ansi += ["101", "7", "17", "177", "18", "0101", "1011", "44", "044"]
ansi += ["u41", "u263a", "u00e9", "u263aX", "u", "U1F600", "U0001F600", "U41", "U000000e9"]
ansi += ["c" + c for c in PRINTABLE if c not in "'\\" and ord(c) & 0x1f] + ["c\\\\"]
for e in ansi:
    cases.append(("ANSI", "$'\\%s'" % e))
    cases.append(("ANSI", "$'<\\%s>'" % e))

# MIX
cases += [("MIX", w) for w in [
    "a'b'\"c\"$'d'\\e$\"f\"", "\"$'x'\"", "\"'\"", "'\"'", "$'\\''", "\\$'x'", "\"\\$'x'\"",
    "'a'\\''b'", "$'a\\'b'\"c\\\"d\"", "\"$\"", "a$'\\x24'b", "\"a\"'b'\\ c", "$\"\"$''\"\"''"]]

# SUBST: (prefix, substitution, suffix) inside a word, unquoted or in "..."
subs = ['$(lst -f "a b")', "$(echo 'x)' \\$y \"q\\\"\")", "$(f \"$(g 'h')\")", "`lst x`",
        "<(lst -f X)", ">(cat -)", "$(case a in a) echo;; esac)"]
for s in subs:
    shapes = [("", ""), ("a\\$b", "'c d'"), ("$'\\x41'", "\\e")]
    if not s.startswith(("<(", ">(")):
        shapes += [('"pre\\$', 'post\\""'), ('"', '"'), ('$"\\\\', '"')]
    for pre, post in shapes:
        cases.append(("SUBST", (pre, s, post)))

# CODE: words spelling code through each context, handed to eval and to bash -c
code_words = ["\"zap \\$(lst -f X)\"", "$'zap \\x24(lst -f X)'", "$'zap \\044(lst -f X)'",
              "$'z\\141p 1'", "$'zap\\x201'", "'P=$(lst)'\"; zap \\$P\"", "z\\ap\\ 1",
              "$'zap \\u0024(lst)'", "\"zap \\`lst\\`\"", "$\"zap \\$(lst)\""]

fails, n = [], 0
for d, w in cases:
    n += 1
    if d == "SUBST":
        pre, s, post = w
        word = pre + s + post
        tok = "@@SUBST@@"
        bv = bash_value(pre + tok + post)
        want = None if bv is None else bv.replace(tok, s)
    else:
        word = w
        want = bash_value(word)
    if want is None:
        fails.append("%-5s %r: bash gave no single value for the case (the case is malformed)" % (d, word))
        print("  BAD-CASE %-5s %r" % (d, word))
        continue
    got = unquote(word) if d == "SUBST" else parsed_value(word)
    ok = got == want
    print("  %s %-5s %r -> %r%s" % ("ok  " if ok else "FAIL", d, word, got, "" if ok else "  bash: %r" % want))
    if not ok:
        fails.append("%-5s %r: bash_parse gives %r, bash gives %r" % (d, word, got, want))

for w in code_words:
    want = bash_value(w)
    for host in ("eval", "bash -c"):
        n += 1
        text = "%s %s" % (host, w)
        cmds = [c for c in parse(text) if c.kw is None]
        codes = [x for c in cmds for x in c.codes]
        ok = want is not None and want in codes
        print("  %s CODE  %r -> codes %r%s" % ("ok  " if ok else "FAIL", text, codes,
                                               "" if ok else "  bash runs: %r" % want))
        if not ok:
            fails.append("CODE  %r: handed-on code %r, bash runs %r" % (text, codes, want))

print("cases: %d, failed: %d" % (n, len(fails)))
if n == 0:
    print("RED: empty corpus"); sys.exit(1)
if fails:
    print("RED: mh-a-words-value-is-bash-quote-removal does not hold:")
    for f in fails:
        print("  " + f)
    sys.exit(1)
print("GREEN: every word's value is bash's quote removal, and every handed-on code is what bash runs")
