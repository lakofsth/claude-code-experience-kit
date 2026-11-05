#!/usr/bin/env python3
"""Independent check for hooks/tests/INVARIANTS.md `mh-a-words-value-is-bash-quote-removal`.

The sentence: hooks/bash_parse.py gives every word the value bash's quote removal gives it --
'...' literal, an unquoted backslash escaping any character, a backslash inside "..." or $"..."
escaping only $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
runs it as code is read as the code bash runs.

Written from the hooks/tests/INVARIANTS.md clause alone. The oracle is bash: every word is printed by a real bash (`set -f`, `set +B`,
LC_ALL=C.UTF-8, `printf '%s\\0' WORD`), and the comparison is of BYTES (bash_parse's str
encoded with surrogateescape), so a byte escape split across two $'...' spans is still one
value. A substitution is not printed by bash but run, so its word is asked of bash with each
substitution replaced by a bare token, and the token is then replaced by the substitution's
own text: that is "kept as the code it is".

The value bash_parse gives is read through parse(), the public reader, at the command at offset
0: `wordprobe WORD` must be a command of exactly two words, and its second word's value is the
one compared -- so where a word ENDS is asked as well as what it holds.

Directions, each a way the sentence can be false:

  SQ     '...' literal, every printable character and a newline inside it;
  BS     an unquoted backslash before every printable character, before a newline, and at the
         end of the text;
  DQ     "..." and $"...": a backslash before every printable character, removed only before
         $ ` " \\ and a newline;
  ANSI   $'...' escapes as bash decodes them: the letters, \\' \\" \\\\ \\?, octal, \\xH(H), the
         braced \\x{H...} form (any number of digits, the low byte kept, the brace optional),
         \\u, \\U (code points a str can hold: none past U+10FFFF), \\cX, an escape bash does
         not know, and a NUL, which ends the $'...' span's value there -- so a word whose
         $'...' starts with one runs as the text after it (`eval $'\\0'"kill ..."` runs kill);
  SUBST  $(...), `...`, <(...), >(...) unquoted and in "...", kept as written, the word whole;
  CODE   the same values handed on as code by `eval WORD`, `bash -c WORD`, `sh -c WORD` and
         `bash <<< WORD`;
  FUZZ   words concatenated from every context above, from a fixed seed, so the contexts are
         asked in each other's company and not only alone.

Every failing case is printed with both values; each direction's count is printed; an empty
corpus is red.
"""
import os, random, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOKS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, HOOKS)
from bash_parse import parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8")
PRINTABLE = [chr(c) for c in range(0x20, 0x7f)]
PRELUDE = "set -f; set +B\n"


def bash_values(words):
    """bash's value of each word, as bytes, or None where bash did not print one field."""
    script = PRELUDE + "".join("printf '%%s\\0' %s\nprintf '\\1\\0'\n" % w for w in words)
    p = bash_oracle.run(["bash", "-c", script], capture_output=True, env=ENV)
    fields = p.stdout.split(b"\0")
    out, k = [], 0
    for _ in words:
        if k + 1 < len(fields) and fields[k + 1] == b"\1":
            out.append(fields[k]); k += 2
        else:
            return [bash_value(w) for w in words]   # one word broke the batch: ask each alone
    return out


def bash_value(word):
    p = bash_oracle.run(["bash", "-c", PRELUDE + "printf '%s\\0' " + word], capture_output=True, env=ENV)
    if p.returncode != 0 or p.stdout.count(b"\0") != 1 or not p.stdout.endswith(b"\0"):
        return None
    return p.stdout[:-1]


def as_bytes(s):
    try:
        return s.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return s.encode("utf-8", "surrogatepass")


def head_cmd(text):
    cmds = [c for c in parse(text) if c.kw is None and c.pos == 0]
    return cmds[0] if len(cmds) == 1 else None


def parsed_value(word):
    c = head_cmd("wordprobe " + word)
    if c is None or len(c.words) != 2:
        return None, "not one word after the command: %r" % (c and [w[0] for w in c.words])
    return as_bytes(c.words[1][1]), None


# ---- the corpus: (direction, word, substitutions) -- substitutions is [(token, text)] ----
cases = []


def add(direction, word, subs=()):
    cases.append((direction, word, list(subs)))


# SQ
for c in PRINTABLE:
    if c != "'":
        add("SQ", "'%s'" % c)
for w in ["'a\\b'", "'\\\\'", "'\\'", "'$(id)'", "'`id`'", "'a\nb'", "'$HOME'", "'\"'", "''x"]:
    add("SQ", w)

# BS
for c in PRINTABLE:
    add("BS", "\\" + c)
    add("BS", "x\\" + c + "y")
add("BS", "a\\")
add("BS", "a\\\nb")
add("BS", "\\\\\\\\")

# DQ and $"..."
for c in PRINTABLE:
    add("DQ", '"\\%s"' % c)
    add("DQ", '"a\\%sb"' % c)
    add("DQ", '$"\\%s"' % c)
for w in ['"a\\\nb"', '$"a\\\nb"', '"\'x\'"', '"$\'x\'"', '"a\\\\\\$b"', '""x', '"\\\\\\\\"']:
    add("DQ", w)

# ANSI
ANSI_BODIES = (
    [e for e in "abeEfnrtv"] + ["\\\\", "\\'", '\\"', "\\?"]
    + ["\\" + o for o in ["0101", "101", "7", "77", "377", "1234", "8", "9"]]
    + ["\\x4", "\\x41", "\\x414", "\\xg", "\\x", "\\xff", "\\xc3\\xa9", "\\xc3"]
    + ["\\x{41}", "\\x{41}B", "\\x{263a}", "\\x{0041}", "\\x{000000041}", "\\x{41", "\\x{41z}",
       "\\x{4 1}", "\\x{fFf}", "\\x{c3}\\x{a9}", "\\x{24}(pgrep -f X)", "\\x{}z", "\\x{g}z",
       "a\\x{100}b", "\\x{3}", "\\x{7e}\\x{7E}"]
    + ["\\u41", "\\u263a", "\\u00e9x", "\\U0001F600", "\\U00000041", "\\u", "\\U"]
    + ["\\c" + c for c in PRINTABLE if c not in "'\\"] + ["\\c\\\\", "\\c\\\\x"]
    + ["\\q", "\\z", "\\%", "\\ ", "a\\0b", "a\\x00b", "\\0"]
)
for b in ANSI_BODIES:
    body = b if b.startswith("\\") or b.startswith("a") else "\\" + b
    add("ANSI", "$'%s'" % body)
    add("ANSI", "x$'%s'y" % body)

# SUBST: (template with {T} where the substitution stands, substitution text)
SUBS = ["$(id)", "$(echo 'a)b')", "$(echo \"x\\\"y\")", "`id`", "`echo \\`id\\``",
        "<(ls)", ">(cat)", "$(printf '%s' \"$(id)\")", "$(case x in x) echo y;; esac)"]
for s in SUBS:
    for tpl in ["{T}", "a{T}b", "'q'{T}\\$", '"{T}"' if not s.startswith(("<(", ">(")) else "{T}c",
                '"a\\${T}\\"b"' if not s.startswith(("<(", ">(")) else "\\ {T}"]:
        add("SUBST", tpl.replace("{T}", "SUBTOKENX"), [("SUBTOKENX", s)])

# CODE: words spelling code through each context, asked as handed-on code below
CODE_WORDS = ["\"kill \\$(pgrep -f X)\"", "$'kill \\x24(pgrep -f X)'", "$'kill \\x{24}(pgrep -f X)'",
              "$'kill \\044(pgrep -f X)'", "'kill $(pgrep -f X)'", "kill\\ \\$\\(pgrep\\ -f\\ X\\)",
              "$\"P=\\$(pgrep X); kill \\$P\"", "$'\\x{6b}ill \\u0024(pgrep X)'",
              "\"a\\b\\$c\"", "$'k\\x{69}ll'\" \\$(id)\"", "$'\\0'\"kill \\$(pgrep -f X)\"",
              "$'\\c@x'kill\\ \\$\\(id\\)"]
for w in CODE_WORDS:
    add("CODE", w)

# FUZZ
rng = random.Random(20261028)
SAFE = "abcdefgxyzKLM0129._-/,:@%+="
DQ_PLAIN = [c for c in PRINTABLE if c not in '"\\$`'] + ["\n"]
ANSI_PLAIN = [c for c in PRINTABLE if c not in "'\\"]
ANSI_ESC = [b for b in ANSI_BODIES if b.startswith("\\") and "\\0" not in b and "x00" not in b
            and "{}" not in b and "{g}" not in b and b != "\\U"]


def seg():
    k = rng.randrange(7)
    if k == 0:
        return "".join(rng.choice(SAFE) for _ in range(rng.randint(1, 4)))
    if k == 1:
        return "\\" + rng.choice(PRINTABLE + ["\n"])
    if k == 2:
        return "'" + "".join(rng.choice([c for c in PRINTABLE if c != "'"] + ["\n"])
                             for _ in range(rng.randint(0, 5))) + "'"
    if k in (3, 4):
        parts = []
        for _ in range(rng.randint(0, 5)):
            parts.append(rng.choice(DQ_PLAIN) if rng.random() < 0.6 else "\\" + rng.choice(PRINTABLE + ["\n"]))
        return ("$\"" if k == 4 else '"') + "".join(parts) + '"'
    parts = []
    for _ in range(rng.randint(0, 4)):
        parts.append(rng.choice(ANSI_PLAIN) if rng.random() < 0.5 else rng.choice(ANSI_ESC))
    return "$'" + "".join(parts) + "'"


for _ in range(1200):
    w = "".join(seg() for _ in range(rng.randint(1, 5)))
    if w[0] in "#~-+":
        w = "z" + w
    add("FUZZ", w)

# ---- the run ----
if not cases:
    print("RED: empty corpus"); sys.exit(1)

oracle_words = []
for d, w, subs in cases:
    oracle_words.append(w)
oracle = bash_values(oracle_words)

counts, fails = {}, []
for (d, w, subs), want in zip(cases, oracle):
    n = counts.setdefault(d, [0, 0]); n[0] += 1
    if want is None:
        fails.append((d, w, "bash printed no single field for this word -- a corpus fault", None)); n[1] += 1
        continue
    for tok, text in subs:
        want = want.replace(tok.encode(), text.encode())
    probe_w = w
    for tok, text in subs:
        probe_w = probe_w.replace(tok, text)
    got, why = parsed_value(probe_w)
    bad = []
    if got != want:
        bad.append("value %r, bash gives %r%s" % (got, want, " (%s)" % why if why else ""))
    if d in ("CODE", "ANSI", "DQ", "FUZZ") and not subs:
        for prog in ("eval", "bash -c", "sh -c", "bash <<<"):
            if prog.endswith("-c") and want[:1] in (b"-", b"+"):
                continue                     # an option to the shell there, not its code
            if prog == "eval" and want[:1] == b"-" and want != b"-":
                continue                     # eval takes a first word of `-` and more as an option and runs no code (`--` ends its options)
            c = head_cmd(prog + " " + probe_w)
            codes = [as_bytes(x) for x in (c.codes if c else [])]
            if want not in codes:
                bad.append("`%s WORD` hands on %r, bash runs %r" % (prog, codes, want))
    if bad:
        n[1] += 1
        fails.append((d, probe_w, "; ".join(bad), want))

for d, w, msg, _ in fails:
    print("FAIL %-5s %r: %s" % (d, w, msg))
total = sum(n[0] for n in counts.values())
nfail = sum(n[1] for n in counts.values())
for d, (n, f) in counts.items():
    print("%-5s %4d case(s), %d red" % (d, n, f))
print("%s: %d case(s), %d red" % ("RED" if nfail else "GREEN", total, nfail))
sys.exit(1 if nfail else 0)
