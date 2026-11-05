#!/usr/bin/env python3
"""Check of hooks/tests/INVARIANTS.md `mh-a-words-value-is-bash-quote-removal`.

The sentence: hooks/bash_parse.py gives every word the value bash's quote removal gives it --
'...' literal, an unquoted backslash escaping any character, a backslash inside "..." or $"..."
escaping only $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
runs it as code is read as the code bash runs.

Written from the hooks/tests/INVARIANTS.md clause alone. Directions, each a way the sentence can be false:

  A. '...' is literal: a backslash, `$`, `"` or backtick inside it is itself;
  B. an unquoted backslash escapes ANY character, and the word goes on after it: an escaped
     space, `;`, `|`, `(`, `&` is a character of the word, and so is a `#` that follows one
     (a `#` starts a comment only at the start of a word);
  C. inside "..." a backslash escapes $ ` " \\ and a newline and nothing else;
  D. $"..." reads as "..." does (the C locale's translation is the identity);
  E. $'...' has its escapes decoded as bash decodes them -- every named escape, every \\cX, the
     numeric escapes at and past their limits, \\c before a character of more than one byte;
  F. a $(...), `...`, <(...) or >(...) in a word is kept as its own text, and the word stays one
     word around it;
  G. the consequence: the code eval and bash -c are handed (Cmd.codes) is the value bash gives
     the word, and a command after such a word is still read as a command.

A-E and G take the expected value from bash itself (`bash -c 'printf "%s\\0" Q WORD'`), never
from a table here; a fixture bash does not read as exactly one word after Q is a fixture error,
not a pass. F's expectation is the substitution's own text, which bash would run, not print.
Every word is followed by more text in the command line, so bash's handling of a word at the
very end of its input is not what is measured.
"""
import itertools, os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bash_parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
os.environ.update(LC_ALL="C.UTF-8", LANG="C.UTF-8")


def bash_value(word):
    """bash's value of WORD, or raise if bash does not read it as exactly one word."""
    r = bash_oracle.run(["bash", "--norc", "--noprofile", "-c",
                        "set -f +B +H; printf '%s\\0' Q " + word + " ; printf 'E\\0'"],
                       capture_output=True, env=ENV)
    vals = r.stdout.split(b"\0")[:-1]
    if r.returncode or r.stderr or len(vals) != 3 or vals[0] != b"Q" or vals[2] != b"E":
        raise ValueError("fixture %r is not one word to bash: %r %r" % (word, vals, r.stderr))
    return vals[1].decode("utf-8", "surrogateescape")


FAILS, COUNT = [], [0]


def check(direction, word, want, got):
    COUNT[0] += 1
    if got != want:
        FAILS.append("%s %r: bash gives %r, bash_parse %r" % (direction, word, want, got))


def codes_of(name, text):
    cs = [c for c in bash_parse.parse(text) if c.kw is None and c.name == name]
    return cs[0].codes if cs else None


def names_of(text):
    return [c.name for c in bash_parse.parse(text) if c.kw is None]


def word_case(direction, word, want=None):
    """unquote(word), the word's value in a parsed command, and the code eval / bash -c are
    handed, all against bash's value; and the command after the word is still a command."""
    if want is None:
        want = bash_value(word)
    check(direction + " unquote", word, want, bash_parse.unquote(word))
    cs = [c for c in bash_parse.parse("printf %s " + word + " ; true") if c.kw is None]
    printf = [c for c in cs if c.name == "printf" and c.pos == 0]
    check(direction + " word", word, [want],
          [v for _, v in printf[0].words[2:]] if printf else None)
    check(direction + " next-command", word, True, "true" in [c.name for c in cs])
    if not (want.startswith("-") and want != "-"):   # eval takes a first word of `-` and more as an option and runs no code (`--` ends its options)
        check(direction + " eval", word, [want], codes_of("eval", "eval " + word + " ; true"))
    if not want.startswith(("-", "+")):         # bash -c would read it as an option
        check(direction + " bash -c", word, [want],
              codes_of("bash", "bash -c " + word + " ; true"))


PRINTABLE = [chr(c) for c in range(0x21, 0x7f)]

# A. single quotes
for ch in PRINTABLE + [" ", "\t", "\n"]:
    if ch != "'":
        word_case("A", "'a" + ch + "b'")
word_case("A", "'\\'")
word_case("A", "'$(pgrep -f X)'", "$(pgrep -f X)")

# B. an unquoted backslash before every character, and the word going on after it
for ch in PRINTABLE + [" ", "\t"]:
    word_case("B", "a\\" + ch + "b")
    word_case("B", "\\" + ch + "x")
for ch in " ;|&()<>'\"\\`$!*?[{}=":
    word_case("B #", "a\\" + ch + "#b")             # `#` mid-word after an escape
for w in ("x\\ #y", "\\;#", "'a'#b", '"a"#b', "$'a'#b", "a\\\\#b", "kill\\ X\\;#"):
    word_case("B #", w)

# C. a backslash in "..." before every character
for ch in PRINTABLE + [" ", "\t", "\n"]:
    word_case("C", '"a\\' + ch + 'b"')
    # D. the same inside $"..."
    word_case("D", '$"a\\' + ch + 'b"')
for w in ('"\\$(pgrep -f X)"', '"kill \\`pgrep X\\`"', '$"kill \\$(pgrep -f X)"', '"a\\\nb"'):
    word_case("C", w)

# E. $'...' escapes
named = list("abeEfnrtv\\'\"?") + ["q", "8", "9", "z", " "]
for e in named:
    word_case("E", "$'<\\" + e + ">'")
for x in PRINTABLE + ["é", "☺", "\U0001F600"]:
    if x not in "'":
        word_case("E \\c", "$'<\\c" + x + ">'")
for num in ("0", "7", "77", "101", "377", "400", "777", "1011", "x4", "x41", "x411", "xZ",
            "x{24}", "x{263a}", "x{}", "u", "u2", "u263a", "u263a1", "U1F600", "U0001F600",
            "U0010FFFF", "U00110000", "U7FFFFFFF", "UFFFFFFFF", "u{24}", "U{24}",
            "xc3\\xa9", "xc3", "xe2\\x98", "xff", "0\\101"):
    word_case("E num", "$'<\\" + num + ">'")
for w in ("$'kill \\x24(pgrep -f X)'", "$'\\c\\\\x'", "$'a'\"b\"'c'"):
    word_case("E", w)

# F. substitutions kept as their own code: each quoted span's quote removal, the substitution's
# text verbatim
for w, want in (("$(echo a)", "$(echo a)"), ("x$(echo a)y", "x$(echo a)y"),
                ('"a$(echo ")")b"', 'a$(echo ")")b'), ("\"$(echo 'a)b')\"", "$(echo 'a)b')"),
                ("$(case a in a) echo;; esac)", "$(case a in a) echo;; esac)"),
                ('"$(echo "$(echo x)")"', '$(echo "$(echo x)")'), ('"`echo a`"', "`echo a`"),
                ("`echo a`b", "`echo a`b"), ("<(echo a)", "<(echo a)"), (">(cat)", ">(cat)"),
                ("x<(echo a)y", "x<(echo a)y"), ("$( (echo a) )", "$( (echo a) )"),
                ("\"$(echo a # )\n)\"", "$(echo a # )\n)"),
                ("a\\ $(pgrep -f X)", "a $(pgrep -f X)"),
                ("'a'$(pgrep -f X)\"b\"", "a$(pgrep -f X)b")):
    word_case("F", w, want)

# Mixed: seeded words over the contexts above, bash as the oracle.
PARTS = ["a", "\\ ", "\\;", "\\#", "#", "\\\\", "'x\\'", "'#'", '"\\$"', '"\\q"', '"\\""',
         "$'\\x41'", "$'\\cé'", "$'\\U00110000'", "$'\\c?'", '$"\\`"', "\\|", "\\(", "\\&"]
for combo in itertools.islice(itertools.product(PARTS, repeat=3), 0, None, 7):
    w = "".join(combo)
    if w.startswith("#"):
        continue
    word_case("mixed", w)

# G. a command after such a word is read as a command (the kill guard's own reading)
for text, want in (("echo a\\;#; pkill -f X", ["echo", "pkill"]),
                   ("echo a\\ #b; pkill -f X", ["echo", "pkill"]),
                   ("eval kill\\ \\$\\(pgrep\\ -f\\ X\\)\\;# ; true", ["eval", "true"])):
    check("G names", text, want, names_of(text))

print("%d of %d red" % (len(FAILS), COUNT[0]))
for f in FAILS:
    print("  RED", f)
sys.exit(1 if FAILS else 0)
