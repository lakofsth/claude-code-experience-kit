"""Check for hooks/tests/INVARIANTS.md mh-a-words-value-is-bash-quote-removal, written from the hooks/tests/INVARIANTS.md clause alone:

  hooks/bash_parse.py gives every word the value bash's quote removal gives it -- '...' literal,
  an unquoted backslash escaping any character, a backslash inside "..." or $"..." escaping only
  $, `, ", \\ and a newline, $'...' with its escapes decoded, and a command or process
  substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
  runs it as code is read as the code bash runs.

The oracle is bash itself (bash_oracle, LC_ALL=C.UTF-8, `set -f +B`), never a table written here.
Every line is one bash script file run once; a probe function `wp` writes `$#` and each argument
NUL-terminated to fd 3, so the value bash gives a word is what `wp` received, compared as BYTES
(a str holding a surrogate escape and the UTF-8 character it completes are the same bytes). The
value bash_parse gives is read through parse(): the `wp` command's words, and the code strings
each command hands on (Cmd.codes, read again until nothing new appears).

Each direction is a way the sentence can be false:

  SQ      '...' literal: every printable ASCII character and some UTF-8 inside single quotes;
  BS      an unquoted backslash before every printable ASCII character, a UTF-8 character, a
          newline (a continuation, removed) and nothing (kept);
  DQ      a backslash before every printable ASCII character and a newline inside "..." and
          inside $"...": removed before $ ` " \\ and a newline, kept before anything else;
  ANSI    $'...' escapes: the letters, \\' \\" \\\\ \\?, \\xH \\xHH \\x{H...}, octal, \\u \\U in
          every UTF-8 length and past it, \\cX, NUL ending the value, unknown escapes kept, and
          byte escapes that join into one character;
  MIX     seeded words concatenating every context, including UTF-8 and lone bytes;
  CODE    the same words handed to `eval W`, `eval W1 W2` (joined by a space), `bash -c W`,
          `sh -c W` and `bash <<< W`: the code handed on is bash's value of the word;
  SUBST   $(...), `...`, <(...), >(...), unquoted and inside "..." and $"...", with quotes,
          backslashes, `)` and nesting in the body: the word's value is the text around the
          substitution quote-removed plus a piece of code that bash, run as `x=CODE`, turns into
          what the substitution gave in its own place (<(...) and >(...) kept as written);
  BODY    the same words as arguments of a command inside a substitution body ($(...), "$(...)",
          `...` and "`...`" escaped as bash requires, nested, process substitutions) and after
          ! time ( { if while case for coproc-less compound openers: the words bash hands that
          command;
  END     where a word ends is the other half of its value: a word glued to a redirection
          operator (W>/dev/null, W<<<x, W>&2, W<>/dev/null, W2>/dev/null) ends where bash ends
          it, and an arithmetic $((...)) is one word, so the command gets exactly the words bash
          gives it and no phantom command is read out of the word's text.

Every case is printed with its verdict; an empty corpus is red, and so is a corpus whose oracle
answered for fewer than nine in ten of its rows.
"""
import os
import random
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
from bash_parse import parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8")
PRINTABLE = [chr(c) for c in range(0x20, 0x7F)]
U8 = ["é", "€", "😀", "\udcff", "\udcc3"]   # the last two: lone bytes 0xff, 0xc3
B = lambda s: s.encode("utf-8", "surrogateescape")  # noqa: E731

rows = []      # (direction, label, line, kind, extra) -- kind says how the line is judged
fails, passes, unasked = [], 0, 0


def add(direction, label, line, kind="word", extra=None):
    rows.append((direction, label, line, kind, extra))


# ---- the words -----------------------------------------------------------------------------
def sq_words():
    out = ["'" + c + "'" for c in PRINTABLE if c != "'"] + ["'" + u + "'" for u in U8]
    out += ["''", "'a b'", "'\\'", "'\\\\'", "'$(x)'", "'`x`'", "'\"'", "'a\nb'", "'\\\nx'"]
    return out


def bs_words():
    out = ["a\\" + c for c in PRINTABLE] + ["a\\" + u for u in U8]
    out += ["a\\\nb", "\\\nab", "\\\\", "\\'", '\\"', "\\$'x'", '\\$"x"']
    return out


def dq_words():
    out = []
    for open_ in ('"', '$"'):
        out += [open_ + "a\\" + c + '"' for c in PRINTABLE if c != "\\"]
        out += [open_ + "a\\\\" + '"', open_ + "a\\\nb" + '"', open_ + "\\é" + '"',
                open_ + "'" + '"', open_ + "$" + '"', open_ + "a$ b" + '"', open_ + "\\$(x)" + '"',
                open_ + "\\`x\\`" + '"', open_ + "\\$'x'" + '"']
    return out


ANSI = ["\\a", "\\b", "\\e", "\\E", "\\f", "\\n", "\\r", "\\t", "\\v", "\\\\", "\\'", '\\"', "\\?",
        "\\x41", "\\x4", "\\x4g", "\\x", "\\x{41}", "\\x{263a}", "\\x{}", "\\x{4", "\\101", "\\7",
        "\\0101", "\\400", "\\777", "\\8", "\\u", "\\U", "\\u41", "\\u00e9", "\\u20ac", "\\uD800",
        "\\U0001F600", "\\U00110000", "\\U7FFFFFFF", "\\U80000000", "\\cA", "\\ca", "\\c?",
        "\\c@", "\\c[", "\\c\\\\", "\\cé", "\\q", "\\é", "\\ ", "\\\n", "\\$", "\\`", "\\0",
        "\\x00z", "\\xc3\\xa9", "\\xe2\\x82\\xac", "\\xe2\\x82", "\\x80\\x41", "\\303\\251"]


def ansi_words():
    out = ["$'" + e + "'" for e in ANSI] + ["$'a" + e + "z'" for e in ANSI]
    out += ["$'\\xe2'$'\\x82\\xac'", "\\$'x'", "$''", "$'\\''", "a$'b c'd"]
    return out


LIT = "aZ09-_.,:=+/@%^~#!?*[]{}éxy€😀\r\udcff\udcc3"


def mix_words(n, seed):
    rnd = random.Random(seed)
    lit = lambda: rnd.choice("aZ09-_.,:=+/@%^é€😀\udcff")  # noqa: E731
    def bs():
        return "\\" + rnd.choice(LIT + "\\'\"$` \t\n;|&()<>abnt")
    def sq():
        return "'" + "".join(rnd.choice(LIT + "\\\"$` \n()") for _ in range(rnd.randint(0, 4))) + "'"
    def dq():
        parts = [rnd.choice([lit(), "\\" + rnd.choice(LIT + "\\\"$`'\n abnt"), "'", " ", "$ ", "\n"])
                 for _ in range(rnd.randint(0, 4))]
        return rnd.choice(['"', '$"']) + "".join(parts) + '"'
    def ansi():
        return "$'" + "".join(rnd.choice(ANSI + list("ab $\"`é")) for _ in range(rnd.randint(0, 4))) + "'"
    gens = [lit, lit, bs, sq, dq, ansi]
    out = []
    while len(out) < n:
        w = "".join(rnd.choice(gens)() for _ in range(rnd.randint(1, 5)))
        if w[:1] in "~#-+":
            continue
        out.append(w)
    return out


WORDS = {"SQ": sq_words(), "BS": bs_words(), "DQ": dq_words(), "ANSI": ansi_words(),
         "MIX": mix_words(900, 20261029)}

for direction, ws in WORDS.items():
    for k, w in enumerate(ws):
        add(direction, "%s#%d" % (direction, k), "wp " + w, "word", w)
        add("CODE", "eval %s#%d" % (direction, k), "eval " + w, "code1", w)
        add("CODE", "bash -c %s#%d" % (direction, k), "bash -c " + w, "code1", w)
        add("CODE", "sh -c %s#%d" % (direction, k), "sh -c " + w, "code1", w)
        add("CODE", "herestring %s#%d" % (direction, k), "bash <<< " + w, "code1", w)
mixed = WORDS["MIX"]
for k in range(0, 300, 2):
    add("CODE", "eval W1 W2 MIX#%d" % k, "eval %s %s" % (mixed[k], mixed[k + 1]), "code2", (mixed[k], mixed[k + 1]))


# ---- SUBST ---------------------------------------------------------------------------------
DOLLAR = ['printf %s A', 'printf %s "a b"', "printf %s 'x)y'", 'printf %s "\\"q\\""', 'printf %s \\)',
          'printf %s "$(printf %s in)"', 'printf a; printf b', "printf '%s' \"\\$\"",
          'case a in a) printf c;; esac', 'printf %s \\\\\\\\', 'printf %s a # )\n',
          "printf %s $'\\x41'", 'printf %s `printf %s t`', 'printf %s "`printf %s \\"u\\"`"',
          "printf %s \"'\"", 'printf %s "\\`"', 'printf %s $"d\\"q"', "printf %s 'a\\\nb'"]
TICK = ['printf %s A', 'printf %s \\"a\\"', 'printf %s "a b"', 'printf %s \\\\\\\\',
        'printf %s \\`printf %s n\\`', 'printf %s \\$', "printf %s 'x\\$y'", 'printf %s \\"',
        "printf %s 'q\\\"'", 'printf %s \\\\\\"', 'printf %s "\\\\"', 'printf %s "\\$(printf %s z)"']
SUBS = ["$(" + b + ")" for b in DOLLAR] + ["`" + b + "`" for b in TICK]
CTX = [("", ""), ("a", "b"), ("'s'", "\\x"), ('"', '"'), ('"p ', ' q"'), ('$"', '"'), ('$"p\\$', '\\""'),
       ("$'\\x41'", "'z'"), ('"\'', '\'"')]
for k, s in enumerate(SUBS):
    for c, (pre, suf) in enumerate(CTX):
        add("SUBST", "sub%d ctx%d" % (k, c), pre + s + suf, "subst", (pre + "QTOKQ" + suf))
for k, body in enumerate(["printf %s A", "printf '%s' ')'", 'printf "%s" "a b"']):
    for op in "<>":
        for pre, suf in (("", ""), ("a", "b"), ("'q'", "$'\\x41'")):
            add("SUBST", "proc%d %s(" % (k, op), pre + op + "(" + body + ")" + suf, "proc", pre + "QTOKQ" + suf)


# ---- BODY ----------------------------------------------------------------------------------
def tick_escape(text, indq):
    return "".join("\\" + ch if ch in "\\`$" or (indq and ch == '"') else ch for ch in text)


FORMS = [("$(%s)", None), ('"$(%s)"', None), ('$"$(%s)"', None), ("`%s`", False), ('"`%s`"', True),
         ('"$(echo "$(%s)")"', None), ("$( $(%s) )", None), ("$(echo `%s`)", False), ("x=\"`%s`\"", True),
         ("cat <(%s)", None), ("echo >(%s)", None), ("! %s", None), ("time %s", None), ("(%s)", None),
         ("{ %s; }", None), ("if %s; then :; fi", None), ("while %s; do break; done", None),
         ("case a in a) %s;; esac", None), ("for i in 1; do %s; done", None), ("true &&\n%s", None),
         ("%s | cat", None), ("%s &", None), ("%s # c", None), ("bash <<'EOF'\n%s\nEOF", None)]
for k, w in enumerate(mixed[:160]):
    for j, (form, tk) in enumerate(FORMS):
        inner = "wp " + w
        if tk is not None:
            inner = tick_escape(inner, tk)
        line = form % inner
        if form[:1] in "$\"`":
            line = ": " + line
        add("BODY", "MIX#%d form%d" % (k, j), line, "body", w)


# ---- END -----------------------------------------------------------------------------------
for k, w in enumerate(mixed[:200]):
    for j, glue in enumerate([">/dev/null", "<<<x", ">&2", "<>/dev/null", "2>/dev/null", "&>/dev/null"]):
        add("END", "MIX#%d %s" % (k, glue), "wp " + w + glue, "end", w)
for k, w in enumerate(["$((1+2))", "a$((1+2))b", "$(( 1 + 2 ))", '"$((1+2))"', "$(( $(printf 1) + 2 ))",
                       "x$(( (1) ))y", "$((2>1))", "$(( 1 ));"[:-1], "$((1))'q'"]):
    add("END", "arith%d" % k, "wp " + w + " z", "count", w)


# ---- the oracle ----------------------------------------------------------------------------
def run_script(lines):
    """{label: [arg bytes...]} as bash's `wp` received them, one script for all lines."""
    # Every other command's stdout goes to /dev/null: `echo >(wp ...)` printed /dev/fd/63 into
    # the stream an asynchronous wp writes to, and a race could splice it into wp's value.
    script = ["set -f +B", "wp() { printf '%s\\0' \"$#\" \"$@\" >&3; }", "exec 3>&1 >/dev/null"]
    for i, line in enumerate(lines):
        script.append("printf '@@MK%d\\0' >&3" % i)
        script.append(line)
        script.append("wait")
    fd, path = tempfile.mkstemp(suffix=".sh")
    try:
        os.write(fd, B("\n".join(script) + "\n"))
        os.close(fd)
        p = bash_oracle.run(["bash", path], capture_output=True, env=ENV, timeout=600)
    finally:
        os.unlink(path)
    got = {}
    for chunk in p.stdout.split(b"@@MK")[1:]:
        idx, rest = chunk.split(b"\0", 1)
        vals = rest.split(b"\0")[:-1]
        if vals and vals[0].isdigit() and len(vals) == int(vals[0]) + 1:
            got[int(idx)] = vals[1:]
    return got


# What bash gives each row: for word and code rows, the value of the word; for body, end and count
# rows, the arguments `wp` received in that very line; for a substitution, the word's value with
# the substitution run and with it replaced by a token (the text around it, quote-removed).
oracle_lines = []
for direction, label, line, kind, extra in rows:
    if kind in ("word", "code1"):
        oracle_lines.append("wp " + extra)
    elif kind == "code2":
        oracle_lines.append("wp %s %s" % extra)
    elif kind == "subst":
        oracle_lines.append("x=%s; y=%s; wp \"$x\" \"$y\"" % (line, extra))
    elif kind == "proc":
        oracle_lines.append("y=%s; wp \"$y\"" % extra)
    else:
        oracle_lines.append(line)
bash_says = run_script(oracle_lines)


def codes_of(line, depth=4):
    """Every code string parse() hands on for line, read again until nothing new appears."""
    out, todo = [], [line]
    while todo and depth:
        nxt = []
        for t in todo:
            for c in parse(t):
                if c.kw is None:
                    for k in c.codes:
                        if k not in out:
                            out.append(k)
                            nxt.append(k)
        todo, depth = nxt, depth - 1
    return out


# A redirection word as bash lexes one: an optional fd (digits or {NAME}) and an operator, never
# a process substitution (`&>` takes no fd). Cmd.words keeps a command's redirections in place (every consumer skips
# them), so the argv a command is given is its words without these and their separate targets
# (Cmd.words is not the argv).
REDIR_WORD = re.compile(r"^(?:(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})(?!&))?(?:&>>|&>|<<<|<<-|<<|<>|<&|>&|>>|>\||<|>)(?!\()(.*)$",
                        re.S)


def argv(words):
    out, k = [], 0
    while k < len(words):
        m = REDIR_WORD.match(words[k][0])
        if m:
            k += 1 if m.group(1) else 2
            continue
        out.append(words[k])
        k += 1
    return out


def wp_words(line, deep=True):
    """[[value bytes...]] for every `wp` command parse() reads in line or in code it hands on."""
    found = []
    for t in [line] + (codes_of(line) if deep else []):
        for c in parse(t):
            if c.kw is None and c.name == "wp":
                found.append([B(v) for _, v in argv(c.words[1:])])
    return found


def verdict(direction, label, line, ok, detail):
    global passes
    if ok:
        passes += 1
        print("  ok   %-6s %s" % (direction, label))
    else:
        fails.append((direction, label, line, detail))
        print("  FAIL %-6s %s  %r  %s" % (direction, label, line, detail))


# Each code runner's check is the same: run the code string(s) parse() hands on as bash would
# read them is beyond a value comparison, so the code must BE bash's value of the word.
x_lines, x_rows = [], []
for i, (direction, label, line, kind, extra) in enumerate(rows):
    if kind in ("subst", "proc"):
        got = bash_says.get(i)
        if got is None or len(got) != (2 if kind == "subst" else 1):
            unasked += 1
            continue
        pre, suf = got[-1].split(b"QTOKQ")
        vals = wp_words("wp " + line, deep=False)
        v = vals[0][0] if len(vals) == 1 and len(vals[0]) == 1 else None
        if v is None or not (v.startswith(pre) and v.endswith(suf)) or len(v) < len(pre) + len(suf):
            verdict(direction, label, line, False, "value %r is not %r + code + %r (%r)" % (v, pre, suf, vals))
            continue
        code = v[len(pre):len(v) - len(suf)]
        if kind == "proc":           # kept as written: it is unquoted, and <(...) is its own text
            sub = line[line.index("(") - 1:line.rindex(")") + 1]
            verdict(direction, label, line, code == B(sub), "kept %r, written %r" % (code, sub))
            continue
        full = got[0]
        out = full[len(pre):len(full) - len(suf)]
        x_lines.append("x=%s; wp \"$x\"" % code.decode("utf-8", "surrogateescape"))
        x_rows.append((i, out, v))
        continue
    got = bash_says.get(i)
    if got is None:
        unasked += 1
        continue
    if kind == "word":
        if len(got) != 1:
            unasked += 1
            continue
        vals = wp_words(line, deep=False)
        verdict(direction, label, line, vals == [[got[0]]], "bash %r, parse %r" % (got[0], vals))
    elif kind == "code1":
        if len(got) != 1 or got[0][:1] in (b"-", b"+"):
            unasked += 1
            continue
        codes = [B(k) for k in codes_of(line)]
        ok = got[0] in codes or got[0] + b"\n" in codes
        verdict(direction, label, line, ok, "bash %r, codes %r" % (got[0], codes))
    elif kind == "code2":
        if len(got) != 2 or (got[0][:1] == b"-" and got[0] != b"-"):
            unasked += 1                 # eval takes a first word of `-` and more as an option and runs no code (`--` ends its options)
            continue
        want = got[0] + b" " + got[1]
        codes = [B(k) for k in codes_of(line)]
        verdict(direction, label, line, want in codes, "bash %r, codes %r" % (want, codes))
    elif kind in ("body", "end"):
        if kind == "end" and len(got) != 1:
            unasked += 1
            continue
        vals = wp_words(line)
        ok = got in vals and all(v == got for v in vals)
        verdict(direction, label, line, ok, "bash %r, parse %r" % (got, vals))
    elif kind == "count":
        cmds = [c for c in parse(line) if c.kw is None]
        wps = [c for c in cmds if c.name == "wp"]
        others = [c.name for c in cmds if c.name not in ("wp", "printf")]
        ok = len(wps) == 1 and len(argv(wps[0].words[1:])) == len(got) and not others
        verdict(direction, label, line, ok, "bash gives %d words, parse %r, other commands %r"
                % (len(got), [w for _, w in argv(wps[0].words[1:])] if wps else None, others))

if x_lines:
    g = run_script(x_lines)
    for n, (i, out, v) in enumerate(x_rows):
        direction, label, line = rows[i][:3]
        ran = g.get(n)
        verdict(direction, label, line, ran == [out],
                "the substitution gave %r in place; the kept code %r gives %r" % (out, v, ran))

asked = passes + len(fails)
print()
by = {}
for d, *_ in fails:
    by[d] = by.get(d, 0) + 1
print("rows %d, asked %d, unasked %d" % (len(rows), asked, unasked))
print("failed by direction: %s" % (", ".join("%s %d" % kv for kv in sorted(by.items())) or "none"))
print("passed %d, failed %d" % (passes, len(fails)))
if asked == 0 or asked < 0.9 * len(rows):
    print("RED: the oracle answered for too few rows (%d of %d)" % (asked, len(rows)))
    sys.exit(1)
sys.exit(1 if fails else 0)
