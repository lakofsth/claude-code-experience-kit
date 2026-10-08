"""Shared quote mask for every hook that pattern-matches SHELL CODE (ledger D740).

Invariant (tests/INVARIANTS.md, key `mh-quote-mask-bash-aware`): every hook that strips
quotes before pattern-matching shell code uses THIS bash-aware, length-preserving mask.
Inside "..." an apostrophe is a letter, and inside '...' a double quote is; the two
regexes this replaces (`re.sub(r"'[^']*'", ...)` then `re.sub(r'"[^"]*"', ...)`, and the
sed equivalent) paired the apostrophe of "it's" with the next literal quote character
and deleted everything between — including the danger the guard was matching — which is
the fail-open direction. Ledger D740 reproduced it live on block-unsafe-kill.sh at
12c4a60: `echo "it's fine" ; pkill -f 'llama-server'` exited 0, silent.

LENGTH-PRESERVING: every quote mark and every masked span character becomes exactly
ONE space (an escape pair becomes two), so an index into the mask is an index into the
raw text and separators can be found in the mask and applied to the raw text
(block-record-skim.sh's 2026-09-09 widening). An UNBALANCED quote masks the rest of the
text as data — the fail-open direction, chosen deliberately by the sites.

This is the single implementation. Do not re-inline it at a call site; the fixture matrix
(hooks/tests/test-quote-mask-matrix.py) derives the call-site set from each site's import
of this module and bans the naive idiom repo-wide.
"""


def mask_quoted(t, quotes="'\"", keep=""):
    """Length-preserving bash-aware mask of t.

    BOTH quote types are always SCANNED — that is what bash-awareness means: a span
    opened by " swallows any apostrophe inside it, and only the scanner that knows the
    double-quoted span is open can know the apostrophe is a letter. (A parser that only
    tracks the quote types it masks is the D740 defect in new clothes: the apostrophe in
    "don't" opens a fake single-quoted span again.)

    `quotes` decides which span types are MASKED to spaces; content of a scanned-but-
    not-masked span passes through unchanged — that is how block-backtick-prose.sh keeps
    the LIVE backticks of interpolating "..." visible while single-quoted backticks
    (data) mask away. Quote marks themselves always mask. `keep` names escaped
    characters (backslash + c, inside "...") that survive masking in place of the pair.

    Escapes per bash: outside any span a backslash escapes the next character (the pair
    masks); inside "...", only before another backslash, a double quote, a backtick, or
    $; inside '...' nothing escapes.
    """
    out, i, n, q = [], 0, len(t), None
    while i < n:
        c = t[i]
        if q is None:
            if c in "'\"":
                q = c; out.append(" ")
            elif c == "\\" and i + 1 < n:
                out.append("  "); i += 1
            else:
                out.append(c)
        else:
            esc = c == "\\" and i + 1 < n and q == '"' and t[i + 1] in '\\"$`'
            if esc:
                nxt = t[i + 1]
                if nxt in keep:
                    out.append(" "); out.append(nxt)
                else:
                    out.append("  ")
                i += 2
                continue
            if c == q:
                q = None; out.append(" ")
            elif q in quotes:
                out.append(" ")
            else:
                out.append(c)
        i += 1
    return "".join(out)
