"""Shared quote mask for every hook that pattern-matches SHELL CODE (ledger D740).

Invariant (hooks/tests/INVARIANTS.md, key `mh-quote-mask-bash-aware`): every hook that strips
quotes before pattern-matching shell code uses THIS bash-aware, length-preserving mask.
Inside "..." an apostrophe is a letter, and inside '...' a double quote is. The naive pair of
regexes (`re.sub(r"'[^']*'", ...)` then `re.sub(r'"[^"]*"', ...)`, and the sed equivalent)
pairs the apostrophe of "it's" with the next literal quote character and deletes everything
between — including the danger the guard is matching — which is the fail-open direction:
`echo "it's fine" ; pkill -f 'myserver'` would pass.

LENGTH-PRESERVING: every quote mark and every masked span character becomes exactly
ONE character (a space unless the caller asks for another fill; an escape pair becomes
two), so an index into the mask is an index into the raw text and separators can be
found in the mask and applied to the raw text. An UNBALANCED quote masks the rest of the
text as data — the fail-open direction, chosen deliberately by the sites.

bash LEXES more than two quote types, and every construct it lexes that a scanner does not is a
place an apostrophe could open a span bash never opens. So these are modelled too:
  - a `#` at the START OF A WORD outside any quote begins a COMMENT running to the end of
    the line; bash gives no quote meaning to anything inside it, so the apostrophe of `# don't
    touch the other servers` opens nothing and the line after it is still read. A comment masks
    to SPACES and keeps its newline, so the line after it is code again.
  - `$'...'` (ANSI-C quoting): inside it a backslash escapes ANY character, `\\'` included,
    so `echo $'it\\'s' ; pkill -f x` closes where bash closes it.
  - the HEREDOC BODY, by bash's own rules:
  - `<<` or `<<-` (never `<<<`) outside any quote, followed by a delimiter WORD in any form
    bash accepts (`EOF`, `'EOF'`, `"EOF"`, `\\EOF`, `'END-NOTE'`, `E"O"F`, `"E\\"OF"`, `$'AB'`,
    `$"AB"`, ...): the word after bash's quote removal is the terminator, and any quoting in it
    makes the body literal (a continuation in it is removed and quotes nothing; _heredoc_word());
  - the body starts after the next unquoted newline and runs to the first line that is
    exactly the terminator (leading tabs stripped first for `<<-`), or to the end of text; in an
    unquoted body a backslash-newline joins two lines into that one line first (_body_end()),
    and such a pair in a body fed to a shell is a continuation of its code;
  - a QUOTED-delimiter body reads as a single-quoted span (masked when "'" is in `quotes`),
    an UNQUOTED one as a double-quoted span with no closing mark (masked when '"' is; with
    `live=True` its `$(...)` and backticks stay as the code they are, because they run).
    Nothing in a body opens a quote or a comment. A masked body and its terminator line
    become SPACES and keep their newlines, whatever `fill` is -- a body is not an argument
    word -- so the line after the terminator is code again.
`heredocs(t)` returns the spans, for a caller that decides something per heredoc (a body fed
to a bare shell is CODE, and hooks/bash_parse.py names those in `code_bodies`).

STRUCTURE DOES NOT DEPEND ON WHAT IS SHOWN. Every substitution (`$(`, a backtick, `<(`, `>(`) is
scanned as the code it is wherever it opens, in unquoted code, in "..." and in an unquoted heredoc
body, so a heredoc inside `"$(...)"` is seen and a `"` inside the body of `git commit -m "$(cat
<<'EOF' ... EOF)"` does not close the outer span; `live`, `quotes` and `fill` decide only what the
mask SHOWS of it. `substitutions(t)` returns those spans.

THE LENGTH HOLDS OR THE CALL RAISES (ledger D1259; hooks/tests/INVARIANTS.md
`mh-the-mask-is-its-inputs-length-or-the-call-is-refused`). A heredoc body bounds what is read
inside it: a substitution in an unquoted body that never closes ends at the body's end, and a
heredoc that substitution opens has no lines to read; a search that looked past that bound
(`cat <<A`, `$(<<B`, `A`, `pkill -f X`) could make a mask longer than the input, and a caller
reading it would see no commands. Every public function below checks the length of what it
scanned and raises MaskMismatch when it differs, and every caller refuses the call when it gets
one: a guard that cannot read a command does not get to allow it.

This is the single implementation. Do not re-inline it at a call site.
"""

# A `#` begins a comment only at the start of a word: at the start of the text, or after
# whitespace or one of bash's metacharacters. `a#b`, `$#` and `${#x}` are not comments.
_WORD_START = " \t\n;&|()<>"


def _after_word_break(t, i, k, esc):
    """True when the character before t[i] ends a word as bash lexes it: whitespace or a
    metacharacter that is no word's, in the scan context opened at k. `esc` holds the index of
    every metacharacter in this context that is still a word's: one a backslash escaped, and the
    closing `)` of a `$(...)`, `<(...)`, `>(...)` or `$((...))`, which ends the expansion and not
    the word it is in (the `)` of a subshell, a `((...))` command or a case pattern does end one:
    bash opens a comment after it). A continuation
    (backslash-newline) is removed before bash lexes, so it is stepped over to the character
    before it. An expansion's `)` is no break, so `printf %s $(true)#x; pkill -f X` is not cut at
    `$(true)` with the rest of the line read as a comment; and an escaped character is no break,
    so the `#` of `a\\;#b` begins no comment."""
    j = i - 1
    while j > k and t[j] == "\n" and j in esc:
        j -= 2
    return j >= 0 and t[j] in _WORD_START and j not in esc

# A word bash may read as a reserved word: no quote, escape or expansion in it. The reserved
# words after which the next word is still in command position.
import bisect
import re as _re
_PLAIN_WORD = _re.compile(r"[^\s;&|()<>'\"`$\\]+")
_KEEPS_CMDPOS = {"then", "do", "else", "elif", "if", "while", "until", "!", "{", "time"}


class MaskMismatch(ValueError):
    """The scan's output is not the input's length: no offset into it can be trusted. A caller
    that judges shell code refuses the call ("could not read this command") rather than allow it."""


def _run(t, quotes="'\"", keep="", fill=" ", live=True, code_bodies=(), cont=False):
    """Scan t whole; (mask, state). Raises MaskMismatch when the mask is not t's length."""
    out = []
    st = {"pending": [], "spans": [], "code": set(code_bodies)}
    if cont:
        st["cont"] = []
    _scan(t, 0, len(t), out, None, quotes, keep, fill, live, st)
    m = "".join(out)
    if len(m) != len(t):
        raise MaskMismatch("mask is %d characters, input %d" % (len(m), len(t)))
    return m, st


def mask_quoted(t, quotes="'\"", keep="", fill=" ", live=False, code_bodies=()):
    """Length-preserving bash-aware mask of t.

    BOTH quote types are always SCANNED — that is what bash-awareness means: a span
    opened by " swallows any apostrophe inside it, and only the scanner that knows the
    double-quoted span is open can know the apostrophe is a letter. (A parser that only
    tracks the quote types it masks is the D740 defect in new clothes: the apostrophe in
    "don't" opens a fake single-quoted span again.) Comments and `$'...'` are scanned too
    (module docstring); `$'...'` masks when "'" is in `quotes`.

    `quotes` decides which span types are MASKED; content of a scanned-but-not-masked
    span passes through unchanged (a substitution inside it is code, and is shown as scanned,
    its own quotes masked by this same rule). Quote marks themselves always mask. `keep` names
    escaped characters (backslash + c, inside "...") that survive masking in place of the pair;
    an escaped character is LITERAL to bash, so a caller asking "does the shell run this?" never
    wants it kept.

    `fill` is the character a masked quote mark, span character or escape pair becomes
    (comments always become spaces). A non-space fill keeps a quoted argument a WORD in
    the mask, so words found in the mask can be read back out of the raw text.

    `live=True` leaves the command substitutions inside a masked "..." span — `$(...)` and
    `` `...` `` — UNMASKED and in place, scanned by these same rules as the code they are:
    `until [ -z "$(pgrep -x X)" ]` masks to a gate whose pgrep still sits after its
    `until`. Default off, which is the behaviour every other site was written against.

    Escapes per bash: outside any span a backslash escapes the next character (the pair
    masks); inside "...", only before another backslash, a double quote, a backtick, or
    $; inside '...' nothing escapes; inside $'...' a backslash escapes anything.

    Heredoc bodies are read as bash reads them (module docstring). `code_bodies` names the
    start offsets (heredocs(t)'s "body"[0]) of bodies to scan as CODE instead.
    """
    return _run(t, quotes, keep, fill, live, code_bodies)[0]


def continuations(t, code_bodies=()):
    """The offsets of the backslash of every backslash-newline pair bash removes as a LINE
    CONTINUATION, in textual order: one in unquoted code (a `$(...)`, a backtick body and a
    heredoc body fed to a shell as code included) or inside "...". Bash deletes such a pair
    before it splits words or reads an operator, so `&\\<NL>&` is `&&`. A pair inside '...',
    `$'...'`, a comment or a data heredoc body is NOT one (the backslash is literal there, and a
    comment ends at the newline), and neither is a newline after an escaped backslash `\\\\`.
    In an UNQUOTED heredoc body fed to a shell (code_bodies) every pair bash removes from the body
    is one, inside the body's own '...' or comment too: the body is joined before the shell it
    feeds reads it (`bash <<EOF` over `pk'\\<NL>ill' -f X` runs pkill). Offsets are returned
    sorted, each once. hooks/bash_parse.py removes these pairs from the whole text BEFORE it
    finds separators, so a pair inside `&&` or `||` joins the operator."""
    return sorted(set(_run(t, code_bodies=code_bodies, cont=True)[1]["cont"]))


def heredocs(t):
    """The heredocs of t in textual order, as bash reads them: one dict each, with "op" (the
    offset of its `<<`), "delim" (the terminator, quotes removed), "quoted" (any quoting in
    the delimiter word: the body is literal), "strip" (`<<-`), "body" ((start, end) of the
    body) and "end" (the offset of the newline ending its terminator line, or len(t))."""
    return _run(t)[1]["spans"]


def substitutions(t, code_bodies=()):
    """The command and process substitutions of t, innermost last among those sharing a start:
    one dict each, with "kind" ("cmd" for `$(...)` and backticks, "proc" for `<(...)` and
    `>(...)`), "open" (the offset of its `$`, `<`, `>` or opening backtick) and "body" ((start,
    end) of the text between its delimiters; end is the offset of the closing character, or
    len(t) when it never closes). Read by the same scan as mask_quoted(live=True) with the same
    `code_bodies`, so an offset into that mask is an offset here: a lister's enclosing
    substitution is found from these spans, not from the one character before its pipeline. An
    unquoted arithmetic `((...))` (or `$((...))`) is recorded too, kind "arith", "open" at its
    first `(` and "body" between the double parentheses; the substitutions inside it are recorded
    as any others, so `kill $(( $(pgrep -f X) ))` has one. An arith record's "dollar" is the
    offset of the `$` of a `$((` expansion, None for a `((` command; a reader asks it, never
    t[open - 1] (hooks/tests/INVARIANTS.md `mh-an-arithmetic-expansion-is-known-by-its-record`):
    in a backtick body the `$` may be written a de-escaped `\\\\<NL>` before the `((`."""
    return _run(t, code_bodies=code_bodies)[1].get("subs", [])


def _heredoc_word(t, k, n):
    """(end, terminator, quoted) of the heredoc delimiter word at t[k:], or None.

    THE WORD IS LEXED AS BASH LEXES IT, AND ITS VALUE IS BASH'S QUOTE REMOVAL: inside "..." (and
    $"...") a backslash escapes `\\`, `"`, `$` and a backtick and is kept before anything else;
    $'...' decodes its escapes; a backslash-newline is a continuation, removed wherever it is not
    inside '...' and quoting nothing. The value is bash_parse.unquote()'s, the one reading of a
    word's quote removal, so `cat <<"E\\"OF"` (terminator E"OF), `<<$'AB'`, `<<$"AB"` and
    `<<E$'\\t'F` end where bash ends them."""
    j = k
    while j < n and t[j] not in " \t\n;&|()<>":
        c = t[j]
        if c == "\\":
            j += 2
        elif c == "'" and j > k and t[j - 1] == "$" and not _escaped(t, j - 1):
            j += 1
            while j < n and t[j] != "'":
                j += 2 if t[j] == "\\" else 1
            j += 1
        elif c == "'":
            e = t.find("'", j + 1, n)
            j = n if e < 0 else e + 1
        elif c == '"':
            j += 1
            while j < n and t[j] != '"':
                j += 2 if t[j] == "\\" else 1
            j += 1
        else:
            j += 1
    j = min(j, n)
    if j == k:
        return None
    raw = t[k:j]
    from bash_parse import unquote     # imported here: bash_parse imports this module
    quoted = any(c in "'\"\\" for c in raw.replace("\\\n", ""))
    return j, unquote(raw), quoted


def _body_end(t, i, n, hd):
    """(start of the terminator line, offset of the newline ending it or n, [the backslash of every
    backslash-newline pair bash removes]) for the heredoc body hd starting at t[i]. Lines are read as
    bash reads them: in an UNQUOTED body a backslash-newline joins two lines into one before the
    line is compared with the terminator, and a backslash before any other character is a pair that
    joins nothing (`\\\\<NL>` ends its line); a quoted body's lines are its physical lines. `<<-`
    strips the leading tabs of the joined line, so the body of `cat <<EOF` ends at `EO\\<NL>F`,
    which bash reads as its terminator."""
    joins = []
    while i < n:
        parts, j = [], i
        while j < n and t[j] != "\n":
            if t[j] == "\\" and not hd["quoted"] and j + 1 < n:
                if t[j + 1] == "\n":
                    joins.append(j)
                else:
                    parts.append(t[j:j + 2])
                j += 2
                continue
            parts.append(t[j]); j += 1
        line = "".join(parts)
        if (line.lstrip("\t") if hd["strip"] else line) == hd["delim"]:
            return i, j, joins
        i = j + 1 if j < n else n
    return n, n, joins


def _bodies(t, i, n, out, quotes, keep, fill, live, st):
    """Read the pending heredoc bodies, the first starting at t[i] (just past the unquoted
    newline that ended their command line). Returns the index after the last one."""
    pending, st["pending"] = st["pending"], []
    for hd in pending:
        b, end, joins = _body_end(t, i, n, hd)   # bounded: inside a body, the body is all there is
        a = i
        if a in st["code"]:
            # A body fed to a shell: scanned as code, BOUNDED by its terminator, because the outer
            # shell ends the body there and the inner shell sees nothing past it. A quote, comment,
            # substitution or heredoc of the body left open ends at the body's end (the inner
            # shell's error stays inside it); the terminator line is blanked, and a heredoc pending
            # after this one on the line is read next, as its own body: `bash <<EOF` over `echo
            # 'x` does not run its quote past `EOF`, and `bash <<A 3<<B` reads B's body as data.
            # The pairs bash removes from an unquoted body are continuations of that code wherever
            # they sit, inside '...' or a comment of it too, because the body is joined before the
            # shell it feeds reads it (`bash <<EOF` over `pk'\\<NL>ill' -f X` runs pkill).
            if "cont" in st:
                st["cont"].extend(joins)
            _scan(t, a, b, out, None, quotes, keep, fill, live, st)
            st["pending"] = []                 # a heredoc the body left open ends with it
            out.append(_blank(t[b:end]))
            i = end
            if i < n:
                out.append("\n"); i += 1
            continue
        hd.update(body=(a, b), end=end)
        st["spans"].append(hd)
        masked = ("'" in quotes) if hd["quoted"] else ('"' in quotes)
        if hd["quoted"]:
            out.append(_blank(t[a:end]) if masked else t[a:end])
        else:                              # its substitutions are read whatever is shown
            buf = []
            _body_live(t, a, b, buf, quotes, keep, fill, live, st)
            if not masked:
                out.append(t[a:end])
            else:
                out.extend(buf if live else [_blank(t[a:b])])
                out.append(_blank(t[b:end]))
        i = end
        if i < n:                          # the newline that ends the terminator line
            out.append("\n"); i += 1
    return i


def _blank(s):
    return "".join("\n" if ch == "\n" else " " for ch in s)


def _body_live(t, i, n, out, quotes, keep, fill, live, st):
    """An unquoted heredoc body: spaces, but its substitutions stay as code (the caller blanks
    them too unless live=True; they are SCANNED either way, so what follows is read the same)."""
    while i < n:
        c = t[i]
        if c == "\\" and i + 1 < n:
            out.append(_blank(t[i:i + 2])); i += 2
            continue
        if _opens_sub(t, i):
            i = _sub(t, i, n, out, quotes, keep, fill, live, st)
            continue
        out.append("\n" if c == "\n" else " "); i += 1


def _opens_sub(t, i):
    """True when t[i] opens a command or process substitution: `$(` (and a `$((` bash does not
    read as arithmetic, see _arith), `<(`, `>(` (a `<((` too: bash has no arithmetic there), or
    a backtick."""
    c = t[i]
    if c == "`":
        return True
    if c in "<>":
        return t[i + 1:i + 2] == "("
    return c == "$" and t[i + 1:i + 2] == "(" and not _arith(t, i + 1)


def _arith(t, i):
    """True when the `((` at t[i] is arithmetic as bash reads it (hooks/tests/INVARIANTS.md
    `mh-a-dollar-double-paren-is-arithmetic-only-where-bash-reads-it`): bash reads on from the
    second `(` to the `)` that balances it, and only when the very next character is `)` is the
    whole `((...))` arithmetic. Otherwise `$((` is `$(` with a body that opens with a subshell,
    and a bare `((` two nested subshells: `$(( cmd ) )`, `$((cmd) )` and `$((a); (b))` all run
    commands. A `((` whose second paren never closes stays arithmetic (bash refuses the text; the
    mask is the same either way)."""
    if t[i + 1:i + 2] != "(":
        return False
    e = _arith_walk(t, i + 2, len(t), [], "'\"", "", " ", False,
                    {"pending": [], "spans": [], "code": set()})
    return e >= len(t) or t[e + 1:e + 2] == ")"


def _arith_walk(t, j, n, out, quotes, keep, fill, live, st):
    """Walk t[j:] (just past a `((`) as bash reads it, appending to out, to the `)` that balances
    the second `(`; returns its offset (not appended), or n when there is none. Quotes are read as
    quotes (`'it)s'` holds no paren) and every substitution is scanned and recorded: the one walk
    both _arith's decision and the arithmetic span's end come from, so they cannot differ."""
    depth = 0
    while j < n:
        c = t[j]
        if c == "\\" and j + 1 < n:
            if t[j + 1] == "\n":                # a continuation, as in _scan, so a backtick's
                st.setdefault("cont", []).append(j)  # `(( \\$\\\\<NL>(L) ))` holds its `$(`
            out.append(t[j:j + 2]); j += 2
            continue
        if _opens_sub(t, j):
            j = _sub(t, j, n, out, quotes, keep, fill, live, st)
            continue
        if c == "'":
            j = _span_single(t, j, n, out, quotes, fill)
            continue
        if c == '"':
            j = _span_double(t, j, n, out, quotes, keep, fill, live, st)
            continue
        if c == ")" and depth == 0:
            return j
        depth += {"(": 1, ")": -1}.get(c, 0)
        out.append(c); j += 1
    return n


def _sub(t, i, n, out, quotes, keep, fill, live, st, dq=False):
    """Scan the substitution opening at t[i] as the code it is, record it, append it as scanned.
    Returns the index just past its closing character. dq: it opens inside "...".

    A BACKTICK BODY'S SUBSTITUTIONS ARE THOSE OF THE CODE BASH RUNS (backtick_code()). The scan
    finds where the body ends; what it holds is read from its de-escaped text, and each
    substitution found there is recorded at the offset of the character it was written as, so
    kill `echo \\`pgrep -f X\\`` holds its lister. That code is read with the run's code bodies
    (st["code"]) carried into it (_code_at()), so a heredoc body fed to a shell there is code at
    every backtick depth; and with its own line continuations removed (joined()), as bash removes
    them when it reads it: de-escaping turns a written `\\\\<NL>` into `\\<NL>`, a continuation
    there (hooks/bash_parse.py's tick_code() joins the same code). And the body is MASKED as that
    code (hooks/tests/INVARIANTS.md `mh-a-backtick-body-is-masked-as-the-code-bash-runs`): the
    same read of the code gives the mask, each character at the offset it was written at, and a
    character the de-escaping or the join removes masks to `fill`, as an escape pair does; masked
    as written, the `\\"` of "`kill \\"\\$(( \\$(pgrep -f X) ))\\"`" would be an escape pair that
    quotes nothing and leaves the `((` live."""
    k = i + (1 if t[i] == "`" else 2)
    out.append(t[i:k])
    rec = {"kind": "proc" if t[i] in "<>" else "cmd", "open": i}
    subs = st.setdefault("subs", [])
    subs.append(rec)
    mine = len(subs)
    # A HEREDOC PENDING WHEN THE SUBSTITUTION OPENS IS READ AFTER IT CLOSES: bash reads the body to
    # its close before it reads any heredoc pending on the line, so a newline inside the body
    # reads none of them and every line before the close is the body's code. They are set aside
    # here and restored below. A heredoc a `$(` or `<(` body opens and does not read is read FIRST,
    # from the lines after the substitution's line, then the outer ones (`cat <<A $(cat <<B)` NL
    # `bb` NL `B` NL `aa` NL `A` gives B `bb` and A `aa`).
    outer, st["pending"] = st["pending"], []
    if t[i] == "`":
        # A backtick body ends at the first backtick no backslash escapes, a quote or a `$(`
        # around it included: bash finds the end before it reads the body's quotes, so
        # "`p \"q'r\"`" ends at its second backtick.
        e = k
        while e < n and t[e] != "`":
            e += 2 if t[e] == "\\" else 1
        e = min(e, n)
        buf = []                                                   # the body as written
        _scan(t, k, e, buf, None, quotes, keep, fill, live, st)    # nothing in it closes it
        # A heredoc the body opened and did not read is read by bash from the backtick's own text,
        # which ends here: its body is empty, and the lines after the backtick are the outer
        # shell's. A `$(` or `<(` is not so: bash reads such a heredoc's body from the lines after
        # the substitution's line.
        st["pending"] = outer
        j, closed = min(e + 1, n), e < n
    else:
        j = _scan(t, k, n, out, ")", quotes, keep, fill, live, st)
        closed = j <= n and j > k and t[j - 1] == ")"
        st["pending"] = st["pending"] + outer
    rec["body"] = (k, j - 1 if closed else j)
    if t[i] == "`":
        rec["dq"] = dq
        code, src = backtick_code(t, rec)
        try:                                 # the join reads the code as the re-read does
            code, src = joined(code, src, lambda c, s: _code_at(st["code"], s))
        except MaskMismatch:
            code = None
        if code is not None and code != t[k:rec["body"][1]]:
            try:
                m, inner = _run(code, quotes, keep, fill, live, _code_at(st["code"], src))
                inner = inner.get("subs", [])
            except MaskMismatch:
                inner = None
            if inner is not None:
                del subs[mine:]
                subs.extend(_mapped(s, src, rec["body"][1]) for s in inner)
                buf = [fill] * (rec["body"][1] - k)
                for p, s in enumerate(src):
                    buf[s - k] = m[p]
        out.extend(buf)
        if closed:
            out.append("`")
    return j


def backtick_code(t, rec):
    """(the code bash runs for the backtick substitution rec of t, [the offset in t of each of its
    characters]). Before it reads a backtick body as code bash removes the backslash before `$`,
    a backtick and `\\` in it, and before `"` too when the backticks sit inside "..." (rec["dq"]):
    a pre-pass over the text, quotes inside the body included, so "`printf %s \\"a b\\"`" runs
    `printf %s "a b"`, and a `\\`` or `\\$(` opens a substitution of the body's own. A backslash
    before anything else is kept."""
    lo, hi = rec["body"]
    esc = '$`\\"' if rec.get("dq") else "$`\\"
    code, src, k = [], [], lo
    while k < hi:
        if t[k] == "\\" and k + 1 < hi and t[k + 1] in esc:
            k += 1
        code.append(t[k]); src.append(k); k += 1
    return "".join(code), src


def joined(code, src, bodies_of):
    """(code with every line continuation removed, the offsets src gives code's characters, kept
    for those it keeps), as bash removes them before it reads a word or an operator.
    bodies_of(code, src) names the heredoc bodies fed to a shell in code (offsets into it), which
    continuations() reads as code; it is asked again after each pass, because a join can change
    what an operator line feeds. Repeated (up to four passes) until a pass removes nothing, as
    hooks/bash_parse.py _joined() is, whose bodies_of reads the joined text; _sub()'s reads offsets
    carried from the outer text, so one pass removes every pair there. Raises MaskMismatch as
    continuations() does."""
    for _ in range(4):
        cuts = continuations(code, code_bodies=bodies_of(code, src))
        if not cuts:
            break
        drop = set(cuts) | {k + 1 for k in cuts}
        keep = [k for k in range(len(code)) if k not in drop]
        code, src = "".join(code[k] for k in keep), [src[k] for k in keep]
    return code, src


def _code_at(bodies, src):
    """The code bodies `bodies` (start offsets in t) that start inside the backtick code whose
    characters sit at the offsets src of t, as offsets into that code. A body starts just past the
    newline ending its operator line, and de-escaping keeps every newline, so its start in the
    code is the position after that newline's, whatever escape the body opens with."""
    out = set()
    for s in bodies:
        p = bisect.bisect_left(src, s)
        if 0 < p < len(src) and src[p - 1] == s - 1:
            out.add(p)
    return out


def _dollar(t, i, esc):
    """The offset of the `$` of the arithmetic `((` at t[i], or None when it is an arithmetic
    command: the unescaped `$` before it, line continuations between them skipped as bash removes
    them (a newline in esc is one a backslash escapes)."""
    j = i - 1
    while j > 0 and t[j] == "\n" and j in esc:
        j -= 2
    return j if j >= 0 and t[j] == "$" and j not in esc else None


def _mapped(s, src, end):
    """The record s of a backtick body's code, at the offsets of t its characters were written at
    (end, the body's end in t, for an offset past the code). An arith record's "dollar" is mapped
    with its "open": in the code bash runs the `$` sits just before the `((`, but in the text it
    may be written a de-escaped `\\\\<NL>` earlier, so no reader can find it as t[open - 1]."""
    def at(p):
        return src[p] if p < len(src) else end
    a, b = s["body"]
    m = dict(s, open=at(s["open"]), body=(at(a), src[b - 1] + 1 if a < b <= len(src) else at(b)))
    if s.get("dollar") is not None:
        m["dollar"] = at(s["dollar"])
    return m


def _case_step(t, i, k, c, depth, cs, cmdpos, out, esc):
    """One step of the `case ... esac` reader of a `)`-closed body (see _scan). cs is the stack of
    open cases, each [state, depth it opened at, at a pattern's start]; state is "subj" (before
    the subject word), "in" (before `in`), "pat" (reading patterns) or "body" (an arm's commands).
    Returns (next index, cmdpos) when it consumed t[i], else (None, cmdpos)."""
    top = cs[-1] if cs and cs[-1][1] == depth else None
    if top and top[0] == "pat":
        if c == ")":                              # a pattern's `)`: the arm's commands follow
            top[0] = "body"; out.append(c); return i + 1, True
        if c == "(" and top[2]:                   # the optional `(` of `(x)`: no depth
            top[2] = False; out.append(c); return i + 1, cmdpos
    if top and top[0] == "body" and c == ";" and t[i + 1:i + 2] in (";", "&"):
        e = i + (3 if t.startswith(";;&", i) else 2)
        top[0], top[2] = "pat", True             # `;;`, `;&`, `;;&`: the next arm's patterns
        out.append(t[i:e]); return e, True
    if c in " \t\n;&|()<>" or not (i == k or _after_word_break(t, i, k, esc)):
        return None, cmdpos
    if c == "#":                                  # a comment: _scan skips it
        return None, cmdpos
    m = _PLAIN_WORD.match(t, i)
    w = m.group(0) if m and (m.end() == len(t) or t[m.end()] in " \t\n;&|()<>") else ""
    if top and top[0] == "subj":                  # the subject, in any form
        top[0] = "in"
        return None, False
    if top and top[0] == "in":
        if w != "in":
            return None, False
        top[0], top[2] = "pat", True
    elif top and top[0] == "pat":                 # a pattern word, or the `esac` of no more arms
        if not (w == "esac" and top[2]):
            top[2] = False
            return None, False
        cs.pop()
    elif cmdpos and w == "case":
        cs.append(["subj", depth, False])
    elif cmdpos and w == "esac" and top:
        cs.pop()
    elif not (cmdpos and w in _KEEPS_CMDPOS):
        return None, False
    out.append(w)
    return i + len(w), w in _KEEPS_CMDPOS


def _scan(t, i, n, out, close, quotes, keep, fill, live, st):
    """Scan t[i:] in UNQUOTED context, appending to out, until `close` ends the context
    (")" for a $(...) body, "`" for a backtick body, None for the top level). Returns the
    index just past the closing character, which is appended as itself.

    A `)`-closed body ends where bash ends it, a `case ... esac` in it included
    (hooks/tests/INVARIANTS.md `mh-a-substitution-ends-where-bash-ends-it`): `case` read as a word
    in command position opens one, and until its `esac` a pattern's `)` (`x)`, `(x)`, `a|x)`) is a
    pattern's, not the body's close, so `$(case a in a) pgrep -f X;; esac)` holds its arm.

    A HEREDOC'S DELIMITER WORD IS NO WORD OF THAT READER: bash takes the word after `<<` as the
    delimiter, never as `case`, `esac` or a pattern, and the next word is no longer in command
    position. The word's offset is held in `hw`, and k, the context start, is never moved to it."""
    depth, k, cs, cmdpos, esc, hw = 0, i, [], True, set(), -1
    while i < n:
        c = t[i]
        if close == ")" and i == hw:
            cmdpos = False
        elif close == ")":
            j, cmdpos = _case_step(t, i, k, c, depth, cs, cmdpos, out, esc)
            if j is not None:
                i = j
                continue
        if close == ")" and c == ")" and depth == 0:
            out.append(c); return i + 1
        if close == "`" and c == "`":
            out.append(c); return i + 1
        if c == "#" and (i == 0 or _after_word_break(t, i, k, esc)):
            j = t.find("\n", i, n)
            j = n if j < 0 else j
            if close == "`":                      # a backtick ends the body even in a comment
                k = t.find("`", i, j)
                j = k if k >= 0 else j
            out.append(" " * (j - i)); i = j
            continue
        if c == "\\" and i + 1 < n:
            if t[i + 1] == "\n":
                st.setdefault("cont", []).append(i)
            esc.add(i + 1)
            out.append(fill * 2); i += 2
            continue
        if c == "\n" and st["pending"]:
            out.append(c)
            i = _bodies(t, i + 1, n, out, quotes, keep, fill, live, st)
            continue
        if c == "(" and _arith(t, i):           # arithmetic: `$((1<<2))` shifts, opens no
            rec = {"kind": "arith", "open": i,  # heredoc; a `$(...)` or backtick in it is still
                   "dollar": _dollar(t, i, esc)}  # a substitution, scanned and recorded as one
            st.setdefault("subs", []).append(rec)
            out.append("((")
            e = _arith_walk(t, i + 2, n, out, quotes, keep, fill, live, st)
            rec["body"] = (i + 2, e)
            if e < n:                           # its `))`
                out.append(t[e:min(e + 2, n)])
                if rec["dollar"] is not None:
                    esc.add(e + 1)              # an expansion's `))` is inside its word
            i = min(e + 2, n)
            continue
        if c == "<" and t.startswith("<<", i) and not t.startswith("<<<", i) \
                and not (i > 0 and t[i - 1] == "<" and (i - 1) not in esc):
            w0 = i + 2 + (t[i + 2:i + 3] == "-")
            while w0 < n and t[w0] in " \t":
                w0 += 1
            w = _heredoc_word(t, w0, n)
            if w:
                st["pending"].append({"op": i, "delim": w[1], "quoted": w[2],
                                      "strip": t[i + 2:i + 3] == "-"})
                out.append(t[i:w0]); i = hw = w0  # the word itself is lexed as the shell lexes it
                continue
        if _opens_sub(t, i):
            j = _sub(t, i, n, out, quotes, keep, fill, live, st)
            if t[j - 1] == ")" and j - 1 > i + 1:
                esc.add(j - 1)                  # a substitution's `)` is inside its word
            i = j
            continue
        if c == "'" and i > 0 and t[i - 1] == "$" and not _escaped(t, i - 1):
            i = _span_ansi(t, i, n, out, quotes, fill)
            continue
        if c == "'":
            i = _span_single(t, i, n, out, quotes, fill)
            continue
        if c == '"':
            i = _span_double(t, i, n, out, quotes, keep, fill, live, st)
            continue
        if close == ")":
            depth += {"(": 1, ")": -1}.get(c, 0)
            if c in ";&|(\n":                     # a separator: a command word may follow
                cmdpos = True
        out.append(c); i += 1
    return i


def _escaped(t, i):
    """True when t[i] is preceded by an odd run of backslashes."""
    k = i - 1
    while k >= 0 and t[k] == "\\":
        k -= 1
    return (i - 1 - k) % 2 == 1


def _span_single(t, i, n, out, quotes, fill):
    out.append(fill); i += 1                       # the opening mark
    while i < n:
        c = t[i]
        if c == "'":
            out.append(fill); return i + 1
        out.append(fill if "'" in quotes else c); i += 1
    return i


def _span_ansi(t, i, n, out, quotes, fill):
    out.append(fill); i += 1
    while i < n:
        c = t[i]
        if c == "\\" and i + 1 < n:
            out.append(fill * 2 if "'" in quotes else t[i:i + 2]); i += 2
            continue
        if c == "'":
            out.append(fill); return i + 1
        out.append(fill if "'" in quotes else c); i += 1
    return i


def _span_double(t, i, n, out, quotes, keep, fill, live, st):
    out.append(fill); i += 1
    masked = '"' in quotes
    while i < n:
        c = t[i]
        if c == "\\" and i + 1 < n and t[i + 1] in '\\"$`':
            nxt = t[i + 1]
            if nxt in keep:
                out.append(fill); out.append(nxt)
            else:
                out.append(fill * 2)
            i += 2
            continue
        if c == "\\" and t[i + 1:i + 2] == "\n":       # a continuation: bash removes the pair
            st.setdefault("cont", []).append(i)
            out.append(fill * 2 if masked else t[i:i + 2]); i += 2
            continue
        if c == '"':
            out.append(fill); return i + 1
        if c in "$`" and _opens_sub(t, i):          # code inside "...": read whatever is shown
            buf = []
            i2 = _sub(t, i, n, buf, quotes, keep, fill, live, st, dq=True)
            out.extend(buf if (live or not masked) else [fill * (i2 - i)])
            i = i2
            continue
        out.append(fill if masked else c); i += 1
    return i
