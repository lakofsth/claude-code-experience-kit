#!/usr/bin/env python3
"""Check for hooks/tests/INVARIANTS.md `mh-a-words-value-is-bash-quote-removal`, a fuzzed check
written from the hooks/tests/INVARIANTS.md clause alone.

The sentence: hooks/bash_parse.py gives every word the value bash's quote removal gives it --
'...' literal, an unquoted backslash escaping any character, a backslash inside "..." or $"..."
escaping only $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
runs it as code is read as the code bash runs.

Directions, each a way the sentence can be false:
  Q  a '...' span is not literal;
  U  an unquoted backslash does not escape the character after it (any character: a space, a
     newline, a quote, a character past ASCII);
  D  inside "..." a backslash escapes something other than $ ` " \\ newline, or fails to;
  L  $"..." is read otherwise than "..." is;
  A  a $'...' escape is not decoded as bash decodes it;
  S  a $(...), `...` or <(...) is not kept, byte for byte, as its code, or splits its word, or
     its body's quotes and parentheses leak into the word around it;
  M  the forms above, concatenated into one word, in any order;
  E  where the word ENDS is part of its value: a word cut short leaves its tail to be read as
     something else, and what follows it (`; pkill -f X`) is read, or lost, accordingly;
  G  the consequence: what `eval WORD`, `bash -c WORD` and `sh -c WORD` are said to hand a shell
     is not that same value.

The oracle is bash itself. Each word is printed by a real `bash -c "printf '%s\\0' WORD"` in an
empty directory. A substitution is made to print a marker of its own (SUBn), and the expected
value is bash's output with each marker put back as the substitution's own text, which is what
"kept as the code it is" means; a <(...) prints /dev/fd/N and is put back the same way. A word
bash does not read as exactly one word is dropped from the sample, and counted.

Fixed words cover each direction alone; 3000 seeded words mix them.
"""
import os, random, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import bash_parse  # noqa: E402
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8",
       "HOME": "/nonexistent"}
EMPTY = tempfile.mkdtemp(prefix="wv-fuzz-")


def bash_word(word):
    """bash's value of WORD (bytes decoded as bash_parse holds them), or None when bash does not
    read it as one word."""
    p = bash_oracle.run(["bash", "--norc", "--noprofile", "-c", "printf '%s\\0' . " + word],
                       capture_output=True, env=ENV, cwd=EMPTY, timeout=20)
    if p.returncode != 0:
        return None
    vals = p.stdout.split(b"\0")[:-1]
    if len(vals) != 2 or vals[0] != b".":   # `.` first, so a word that is no word is seen
        return None
    return vals[1].decode("utf-8", "surrogateescape")


def expected(word, subs):
    """bash's value with each substitution's marker put back as its text. subs: [(marker, text)],
    a marker of None being a <(...), which bash prints as /dev/fd/N."""
    got = bash_word(word)
    if got is None:
        return None
    for marker, text in subs:
        if marker is None:
            m = re.search(r"/dev/fd/(?:6[0-3]|[1-5][0-9])", got)   # bash counts down from 63
            if not m:
                return None
            got = got[:m.start()] + text + got[m.end():]
        else:
            if got.count(marker) != 1:
                return None
            got = got.replace(marker, text)
    return got


def parsed_word(word):
    cmds = [c for c in bash_parse.parse("printf %s " + word) if c.name == "printf" and c.pos == 0]
    if len(cmds) != 1:
        return "<%d printf commands at 0>" % len(cmds)
    w = cmds[0].words
    if len(w) != 3:
        return "<printf read as %d words: %r>" % (len(w), [v for _, v in w])
    return w[2][1]


def handed(prefix, word):
    out = []
    for c in bash_parse.parse(prefix + " " + word):
        out += c.codes
    return out


# ---- the pieces a word is made of --------------------------------------------------------------
PRINT = [chr(c) for c in range(0x21, 0x7f)] + [" ", "\t", "\n", "é", "→", "😀"]
PLAIN = list("abz09_=%,-:@./+^]#!{}") + ["é", "→"]  # unquoted, no expansion, no glob
SQ_IN = [c for c in PRINT if c != "'"]
DQ_PLAIN = [c for c in PRINT if c not in '"\\$`']
ANSI_ESC = [r"\n", r"\t", r"\\", r"\'", r"\"", r"\?", r"\a", r"\b", r"\e", r"\E", r"\f", r"\r",
            r"\v", r"\q", r"\x41", r"\x4", r"\x4g", r"\xe2\x86\x92", r"\101", r"\7", r"\0101",
            r"é", r"→", r"\U0001F600", r"\u", r"\x", r"\cA", r"\ca", r"\c?", r"\c[",
            r"\x{41}", r"\x{263a}", r"\x24", r"\044", r"\$", r"\`", r"\ ", "\\\n"]


def sq(r):
    return "'" + "".join(r.choice(SQ_IN) for _ in range(r.randint(0, 4))) + "'"


def dq_body(r, subs, k):
    out = []
    for _ in range(r.randint(0, 4)):
        x = r.random()
        if x < 0.45:
            out.append(r.choice(DQ_PLAIN))
        elif x < 0.85:
            out.append("\\" + r.choice(PRINT))
        elif x < 0.95:
            out.append(sub(r, subs, k, quoted=True))
        else:
            out.append("$")                     # a `$` before the closing quote is literal
            break
    return "".join(out)


BODY_TAIL = ["", "; : ')'", '; : ")"', "; : \\)", "; : '\"('", '; : "a b"', "; : $'\\')'",
             '; : "$(: \')\')"', "; : '#'", "; # )", "; : `: x`", ' ; : "\\")"',
             "; case a in a) :;; esac", "; case a in (a) :;; esac", "; : $((1+(2)))",
             "; ( : )", "; : ${x:-')'}", "; : ${x:-\\)}", "\n# )\n", "; : <<'E'\n)\nE\n",
             "; : <<E\n)\nE\n", "; : $(: $(: ')'))", "; : \\`", "; : a#')'", "; : \\#')'"]


def sub(r, subs, k, quoted=False):
    k[0] += 1
    marker = "SUB%d" % k[0]
    say = r.choice(["printf %s " + marker, 'printf %s "' + marker + '"',
                    "printf %s '" + marker + "'", "printf %s S'U'B\"" + marker[3:] + '"'])
    kind = r.random()
    if kind < 0.6:
        text = "$(" + say + r.choice(BODY_TAIL) + ")"
    elif kind < 0.85 or quoted:
        text = "`" + say + "`"
    else:
        text = "<(:" + r.choice(["", " ')'", ' ")"']) + ")"
        subs.append((None, text))
        return text
    subs.append((marker, text))
    return text


def piece(r, subs, k):
    x = r.random()
    if x < 0.14:
        return r.choice(PLAIN)
    if x < 0.30:
        return "\\" + r.choice(PRINT)
    if x < 0.44:
        return sq(r)
    if x < 0.62:
        return '"' + dq_body(r, subs, k) + '"'
    if x < 0.70:
        return '$"' + dq_body(r, subs, k) + '"'
    if x < 0.86:
        return "$'" + "".join(r.choice(ANSI_ESC) if r.random() < 0.6
                              else r.choice([c for c in PRINT if c not in "'\\"])
                              for _ in range(r.randint(0, 3))) + "'"
    return sub(r, subs, k)


def word(r):
    subs, k, parts = [], [0], []
    for _ in range(r.randint(1, 4)):
        parts.append(piece(r, subs, k))
    w = "".join(parts)
    return w, subs


# Each direction alone (the S words carry their substitutions).
FIXED = []
for c in PRINT:
    if c != "'":
        FIXED.append(("Q", "'a" + c + "b'", []))
    FIXED.append(("U", "a\\" + c + "b", []))
    if c not in "$`":
        FIXED.append(("D", '"a\\' + c + 'b"', []))
        FIXED.append(("L", '$"a\\' + c + 'b"', []))
FIXED += [("D", '"a\\$b"', []), ("D", '"a\\`b"', []), ("L", '$"a\\$b"', []), ("U", "a\\", [])]
for e in ANSI_ESC:
    FIXED.append(("A", "$'a" + e + "b'", []))
for tail in BODY_TAIL:
    t = "$(printf %s SUB1" + tail + ")"
    FIXED.append(("S", "x" + t + "y", [("SUB1", t)]))
    FIXED.append(("S", '"x' + t + 'y"', [("SUB1", t)]))
    FIXED.append(("S", "'q'" + t + "\\ z", [("SUB1", t)]))
FIXED.append(("S", "x`printf %s SUB1`y", [("SUB1", "`printf %s SUB1`")]))
FIXED.append(("S", '"x`printf %s SUB1`y"', [("SUB1", "`printf %s SUB1`")]))
FIXED.append(("S", "x<(: ')')y", [(None, "<(: ')')")]))
# A `#` inside a word is a character of it wherever it stands after the first: after a quote, an
# escape, and after each kind of substitution. Bash opens a comment only where a word begins.
for before, subs in (("'a'", []), ('"a"', []), ("$'a'", []), ('$"a"', []), ("\\a", []),
                     ("$(printf %s SUB1)", [("SUB1", "$(printf %s SUB1)")]),
                     ("`printf %s SUB1`", [("SUB1", "`printf %s SUB1`")]),
                     ("<(:)", [(None, "<(:)")])):
    FIXED.append(("S", before + "#z", subs))
    FIXED.append(("S", "q" + before + "#'z'", subs))

rng = random.Random(22081490)
MIXED = [("M",) + word(rng) for _ in range(int(os.environ.get("WV_FUZZ_N", "3000")))]

fails, total, dropped = [], 0, 0
by = {}


def check(label, got, want):
    global total
    total += 1
    if got != want:
        fails.append("%s: got %r, bash %r" % (label, got, want))
        by[label.split("]")[0] + "]"] = by.get(label.split("]")[0] + "]", 0) + 1


for d, w, subs in FIXED + MIXED:
    want = expected(w, subs)
    if want is None:
        dropped += 1
        continue
    check("[%s] printf %%s %s" % (d, w), parsed_word(w), want)
    # G: the same word handed to a shell as code
    for prefix in ("eval", "bash -c", "sh -c"):
        if prefix != "eval" and want[:1] in "-+":
            continue                            # an option word to the shell, not its -c operand
        if prefix == "eval" and want[:1] == "-" and want != "-":
            continue                            # eval takes a first word of `-` and more as an option and runs no code (`--` ends its options)
        got = handed(prefix, w)
        if want not in got:
            check("[G] %s %s" % (prefix, w), got, [want])
        else:
            check("[G] %s %s" % (prefix, w), want, want)

# E: the command after each fixed word is still a command -- bash runs it (pkill shadowed by a
# function that prints RAN), and parse() must list it.
for d, w, subs in FIXED:
    line = "printf %s " + w + "; pkill -f X"
    p = bash_oracle.run(["bash", "--norc", "--noprofile", "-c",
                        "pkill() { printf RAN; }; " + line], capture_output=True, env=ENV, cwd=EMPTY,
                       timeout=20)
    if p.returncode != 0 or not p.stdout.endswith(b"RAN"):
        continue
    names = [c.name for c in bash_parse.parse(line)]
    check("[E] %s" % line, "pkill" in names, True)

for f in fails[:200]:
    print("  FAIL " + f)
if len(fails) > 200:
    print("  ... and %d more" % (len(fails) - 200))
print("cases: %d (%d fixed, %d seeded words; %d word(s) bash does not read as one word dropped)"
      % (total, len(FIXED), len(MIXED), dropped))
print("red by direction: %s" % (", ".join("%s %d" % kv for kv in sorted(by.items())) or "none"))
if fails:
    print("RED: %d of %d cases: a word's value, or the code handed on, is not bash's" % (len(fails), total))
    sys.exit(1)
if total < 1000:
    print("RED: only %d cases ran -- the sample is too small to be evidence" % total)
    sys.exit(1)
print("GREEN: %d cases, every word's value and every handed-on code is bash's" % total)
