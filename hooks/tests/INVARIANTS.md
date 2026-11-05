# hooks/tests/INVARIANTS.md — the invariants the kit's hooks and their tests cite

Every `mh-*` id that the hooks, their tests and `README.md` cite resolves to a `## \`<id>\``
heading below. Each entry states one invariant (**Invariant.**), how the sites it binds are
derived from the code rather than listed by hand (**Site derivation.**), what it deliberately
does not cover, and the tests in `hooks/tests/` that pin it. Entries are keyed by subject, never
by a running number, so a citation keeps resolving as entries are added. A clause added after an
entry was first written is marked "amended" with its date.

Fixture names, not ids: `mh-no-such-pattern`, `mh-cert-no-such-pattern`, `mh-no-such-process-xyz`
(patterns and process names the tests use because nothing on a host matches them).

`hooks/tests/test-cited-invariants-resolve.py` checks this file against the tree: every id cited
in the shipped text resolves here, every heading here is cited from somewhere outside its own
entry, no heading is stated twice, and each fixture name above is still used.

## `mh-quote-mask-bash-aware`

**Invariant.** Every hook that strips quotes before pattern-matching shell code strips
them with the single shared implementation `hooks/quote_mask.py::mask_quoted` — a
scanner that is bash-aware (it always tracks both quote types, so an apostrophe inside
`"…"` and a double quote inside `'…'` are letters, never delimiters) and
length-preserving (every quote mark and masked character becomes exactly one space, so
an index into the mask is an index into the raw text) — and no call site re-implements
quote stripping with its own regex or sed.

**Site derivation (mechanical).** A call site is any `hooks/*.sh` importing
`quote_mask`, derived by scanning the directory; a fixture matrix of the original (not shipped)
fails if the derived set differs from the expected one, if a derived site has no payload routed
to it, or if the naive quote-eating idiom (a `'[^']*'` / `"[^"]*"` class used as an
`re.sub`/`sed` strip) reappears in any hook.

## `mh-every-name-keyed-kill-is-counted`

**Invariant.** `hooks/block-unsafe-kill.sh` counts every kill keyed on a process name —
`pkill` without `-f` in any spelling of its options, and `pgrep` without `-f` or `pidof`
whose pids reach a `kill` — with the command's own matcher and selection options, and refuses
it when that count is more than one. Every option the tool reads as taking a value (`-U`, `-G`,
`-P`, `-u`, `-g`, `-s`, `-t`, `-F`, `-O`, `-r` and their long forms), and every argument `pkill`
reads as its signal word (`-9`, `-term`, `-SIGsegv`, …), is read as such, so the counted name is
the name the tool matches. *(Amended 2026-10-28.)*

**Pinned by.** `hooks/tests/test-name-keyed-kill-count.py`, `hooks/tests/test-name-kill-filter-held-in-an-expansion-cert.py`, `hooks/tests/test-name-kill-uid-gid-filters.py`.

## `mh-every-pattern-keyed-kill-is-refused`

**Invariant.** `hooks/block-unsafe-kill.sh` refuses a kill whose pids are chosen by matching a
full command line — `pkill -f`/`--full` with any options or option arguments around it,
`pgrep -f` into a kill, and a `ps` listing piped on into a kill — whatever path, escape or
wrapper (`sudo`, `timeout`, `env`, `xargs`, …) precedes the command word, where a wrapper is
every program that runs its operands as a command by its own man page (`chroot`, `systemd-run`,
`nsenter`, `docker exec`, find's `-exec`, …). (Amended 2026-10-28: every such program.)

**Site derivation (mechanical).** The names the refusal arms decide on are an AST walk of
the hook's embedded Python: every string `analyse()` compares with a command's `.name`, less those
with no executable (`eval`). Each must be in `CARRIED`, the set carried_kill() reads an unlisted
wrapper past to. The shells whose `-c` operand is read are derived from two registries, the host's
`/etc/shells` and the Debian archive's `shells` section (`Section: shells` stanzas of
`/var/lib/apt/lists/*_Packages`): each member is in `bash_parse.SHELLS` or stated out with its reason,
and every member of `SHELLS` is asked with `NAME -c 'pkill -f X'`, `kill $(NAME -c 'pgrep -f X')` and
`NAME -c 'echo hi'`. The option clusters a `-c` stands behind are derived by running the shells:
`shutil.which` over `bash_parse.SHELLS` names the installed ones, and each is the oracle for which
word its `-c` runs, over every cluster of `e u x o O c` up to three letters.
The programs whose code a command behind an unlisted wrapper runs are an AST walk of
`hooks/bash_parse.py`: every string constant `resolve()`, `command_codes()` and `handed_code()`
compare a command's `name` or `base` with, every member of `bash_parse.SHELLS`, and every key of
`bash_parse.WRAPPERS` (followed by `sh -c`); each must have a template that runs code through it.

**Pinned by.** `hooks/tests/test-block-unsafe-kill-command-runners.py`, `hooks/tests/test-pattern-keyed-kill-blind-recertify-2-cert.py`, `hooks/tests/test-pattern-keyed-kill-blind-recertify-cert.py`, `hooks/tests/test-pattern-keyed-kill-carried-kill.py`, `hooks/tests/test-pattern-keyed-kill-code-behind-unlisted-wrapper.py`, `hooks/tests/test-pattern-keyed-kill-every-command-runner-cert.py`, `hooks/tests/test-pattern-keyed-kill-every-shell-and-consumer.py`, `hooks/tests/test-pattern-keyed-kill-recertify-1029-cert.py`, `hooks/tests/test-pattern-keyed-kill-refused.py`.

## `mh-code-handed-to-a-shell-is-code`

**Invariant.** `hooks/block-unsafe-kill.sh` analyses as shell code, by the same rules as the
command itself, every string the command hands another shell to run: the argument of
`bash|sh -c` (behind any wrapper), of `eval` and of `env -S` (in every spelling env's
getopt_long accepts: `--split`, `--s`, `--spli=STR`; amended 2026-10-30), and a heredoc, herestring or
`echo`/`printf` pipe read by a bare shell — a heredoc or herestring read by a program whose
stdout is its stdin's text (`cat`, `tee`, `dd`, `pv`, `sponge`, in the spellings that keep it
so) and piped, through any number of such programs, into a shell that runs its stdin included,
and an unquoted body read as the shell that reads it expands it (amended
2026-10-28); and the same streams through a compound command in the pipeline, as bash runs them —
every command in a `( … )`, `{ …; }`, if, for/while/until/select or case writes to the
compound's stdout unless it redirects its own, and the first stdin reader inside one reads the
compound's stdin, so `(cat <<EOF) | bash`, `{ cat <<< '…'; } | bash`, `(cat) <<EOF | bash`,
`(echo '…') | bash` and `cat <<EOF | (bash)` hand the shell the text, nested and over lines
alike (amended 2026-10-28); and text that reaches a shell reading code on its stdin
through a function body at the place it is called, or through stdout redirected into a `>(…)` that
runs such a shell, is read as that shell's code, as bash runs it — `f() { cat <<EOF; }; f | bash`,
`function f { echo '…'; }; g() { f; }; g | bash`, `f() { bash; }; echo '…' | f`, `cat <<EOF >
>(bash)`, `{ echo '…'; } > >(sh)` (amended 2026-10-30), the redirection written on the command or
held for every later command of its shell by an `exec` with no command, `exec > >(bash); echo '…'`
(amended 2026-10-30) — and every string a program runs as shell code by
its own documented reading: `flock FILE -c`, `su`/`runuser -c` (and `runuser -u U -- CMD`),
`watch`'s command words (argv with `-x`), `script -c`, `trap`'s action, `tmux`'s
shell-command arguments and `send-keys`, the keys `screen -X` types into a window (`stuff`,
and `at`, `eval` and `register` carrying one; amended 2026-10-30), fish's `-C`/`--init-command`
code (amended 2026-10-30), and an `at`/`batch` job read on stdin. (Amended 2026-10-27: the
programs.) The rule is general (amended 2026-10-28): every program whose own
page sends a string to a shell has that string read as code — among them `parallel -- CMD`
(and GNU's `:::` and stdin), `sg`/`newgrp`, `git rebase -x`, `git submodule foreach`, `git bisect
run`, `git filter-branch`'s filters, and `ssh` to this host — and every program that runs its
operands as argv is a wrapper the guard sees through, find's `-exec`/`-execdir`/`-ok`/`-okdir`
clauses included, its options read as the wrapper reads them — a long option in every spelling
the wrapper's getopt_long accepts (any unambiguous prefix, `--opt ARG` as well as `--opt=ARG`, an
optional argument only after `=`: `timeout --sig KILL 5 CMD`, `xargs --replace CMD`; amended
2026-10-30) — so the command it runs is judged as if written alone. The strings a program hands
to a shell are read from every spelling of its code-taking option that the program's own option
parser accepts — the full long name, every unambiguous prefix of it, `=ARG` and the next word — so
block-unsafe-kill gives the abbreviated spelling the verdict of the full one (amended 2026-10-30:
`su --comm`, `script --comm`, `sg G --comm`, `git rebase --exe`, `fish --init`).

**Site derivation.** `handed_code()`, `reads_code_on_stdin()` and the `flock`, `docker|podman
exec`, `parallel` and `screen -X` (`screen_x_codes()`) arms of `resolve()` in `hooks/bash_parse.py`, which fill `Cmd.codes` and find
the command word; `analyse()` in `hooks/block-unsafe-kill.sh` is their one reader for this guard.
A wrapper's options are read by `opt_words()` (the `WRAPPERS` loop of `resolve()` and its `flock`
arm), its long options through `long_option()` over `LONG_OPTS`, the one getopt_long reader env's
`env_long()` shares; the wrappers are every key of `WRAPPERS`, each either a row of `WRAPPER_LONG`,
measured from the program by `hooks/tests/test-wrapper-long-option-abbreviations.py`, or stated in
that check's `NO_LONG` with the reason it has no getopt_long grammar.
A code-taking long option of `handed_code()` and `_shell_read()` is read by `long_code()` over the
same `LONG_OPTS`, whose `HANDED_LONG` rows (su, runuser, script, sg, newgrp, watch, fish,
git-rebase) `hooks/tests/test-handed-code-long-option-prefixes.py` measures or states as documented;
its AST walk finds every `--NAME` literal the two functions still compare in full, and each must be
in its `IN_FULL` with the reason its program reads that option in full.
A program is in the code table when its man page says the string goes to a shell; a program
whose operands are argv is a wrapper in `WRAPPERS`. The table was derived by scanning installed
man1/man8 SYNOPSIS lines for a trailing `COMMAND [ARG]...` / `program [arguments]` and for a
string passed to a shell, and reading each hit's page (the scanning script is original only); subcommand dispatchers (`docker`, `gpg`, `go`, `virsh`) are not
wrappers, save `docker|podman exec`.
Out of purpose, by the guard's own purpose — the processes of THIS host: a command `ssh` (or
`mosh`, or `systemd-run -H`) runs on another host, and one a remote docker daemon runs (`-H
tcp://…`). Their processes are another machine's; the guard's counts read this host's table and
say nothing about them. (Narrowed 2026-10-28: a kill among the words `ssh` or `mosh` carry, to
any host, in a command that also holds a lister here, is refused by
`mh-a-kill-the-runtime-guard-cannot-see-is-refused`; the text cannot show that the host is not
this one.) `ssh` to this host's own names (`localhost`, 127.*, `::1`, its hostname)
is read. A running container's processes (`docker|podman exec`) ARE this host's: they share its
kernel, its process table holds them, and a pattern kill there matches the container's own shell
as one here matches ours; a name-keyed kill there is counted against this host's whole table,
which can over-count. Not read, stated rather than discovered: a fresh container (`docker run`,
`systemd-nspawn`), whose new pid namespace holds only what that command starts; `bwrap`, `pasta`
and `perf`, whose option grammars the table does not carry; GNU parallel's `-S` remote logins,
read as this host's (where `parallel` is moreutils', it has none).
GNU parallel's stdin (amended 2026-10-28): with a command and no `:::`/`::::`
source and no `-a FILE` (or with one of them `-`), what parallel reads on stdin is put where its
command template holds a replacement string, appended when it holds none, and given to each
job's stdin under `--pipe` — `parallel_stdin()` in `hooks/bash_parse.py` reads that, and
`parallel_feeds()` in `hooks/block-unsafe-kill.sh` writes a lister there, so `pgrep -f X |
parallel 'kill {}'` is read as `kill $(pgrep -f X)`. Read by parallel(1)'s documentation, not by
running GNU parallel. Not read: options added from outside the command text — a
`--profile`/`-J` file, `~/.parallel/config`, `$PARALLEL` — which can turn on `--pipe`, `-a` or a
`--rpl` the text does not show. Read wide, so it can only refuse more: any blank-free `{…}` in
the template is taken for a replacement string, `{//}` (a pid's dirname, `.`) included.

**Pinned by.** `hooks/tests/test-block-unsafe-kill-command-runners.py`, `hooks/tests/test-block-unsafe-kill-handed-code-cert.py`, `hooks/tests/test-block-unsafe-kill-handed-code.py`, `hooks/tests/test-block-unsafe-kill-parallel-stdin.py`, `hooks/tests/test-block-unsafe-kill-shell-code-programs-cert.py`, `hooks/tests/test-function-and-procsub-handed-text-blind-recert-cert.py`, `hooks/tests/test-function-call-words-and-procsub-order-blind-recert-cert.py`, `hooks/tests/test-handed-code-long-option-prefixes-cert.py`, `hooks/tests/test-handed-code-long-option-prefixes.py`, `hooks/tests/test-mh-code-handed-to-a-shell-function-and-procsub-cert.py`, `hooks/tests/test-mh-code-handed-to-a-shell-parallel-stdin-cert.py`, `hooks/tests/test-pattern-keyed-kill-refused.py`, `hooks/tests/test-wrapper-long-option-abbreviations.py`.

## `mh-no-substring-allows-a-command`

**Invariant.** No word or substring anywhere in a command exempts it from
`hooks/block-unsafe-kill.sh`: naming the safe helper `safe_kill_pat` allows only that helper's
own invocation, and every other simple command in the same command is still inspected.

**Pinned by.** `hooks/tests/test-safe-kill-helper-exempts-only-itself.py`.

## `mh-a-line-continuation-is-no-word`

**Invariant.** The shared command reader `hooks/bash_parse.py` removes every backslash-newline
line continuation before it reads a word — one standing alone, one glued to the next word, one
inside a word — so every guard that reads commands through it judges a command split over lines
by continuations exactly as it judges the same command written on one line.

**Site derivation.** The guards that import `parse` from `hooks/bash_parse.py`
(`block-unsafe-kill.sh` here; also `block-live-script-edit.sh`, original only). Which backslash-newline pairs are
continuations is decided once, by the shared scanner (`hooks/quote_mask.py`, `continuations()`),
and `bash_parse.join_lines` removes them from the whole text before any separator or word is read
— so a pair inside an operator (`&\<NL>&`, `|\<NL>|`) is joined too, and one inside `'...'`, a
comment or a data heredoc body, or after an escaped backslash, stays literal.

## `mh-a-lister-counts-only-when-its-pids-reach-a-kill`

**Invariant.** `hooks/block-unsafe-kill.sh` treats a `pgrep` or `pidof` as choosing what a kill
stops only when that lister's output reaches the kill — in the kill's pipeline, in a substitution
the kill expands, or through a variable, `for` loop or `read` the kill expands — and a lister
whose output reaches no kill in the command neither causes a refusal nor is named in one.

**Narrowed 2026-10-28.** Save where the command also holds a kill the run-time guard cannot see:
then `mh-a-kill-the-runtime-guard-cannot-see-is-refused` refuses it by its words, whatever the
lister feeds (`pgrep -a NAME; sudo kill 999999`).

**Pinned by.** `hooks/tests/test-lister-reaches-kill-cert.py`.

## `mh-a-lister-in-a-substitution-is-followed-by-its-structure`

**Invariant.** `hooks/block-unsafe-kill.sh` finds the substitution a `pgrep` or `pidof` sits in,
and the command that substitution is a word of, from the shared scanner's substitution spans
(`hooks/quote_mask.py`, `substitutions()`) — so a newline or space after the opening, another
command before the lister inside the substitution, another substitution earlier in the same
command, an array literal `v=( … )` wherever in it the substitution sits, a herestring or process
substitution read by its host (a kill, a `read`, or a command passing it on), and an arithmetic
`$((…))` or `((…))` each carry the lister's pids to the kill exactly as the one-line `kill
$(pgrep …)` does — and the pids are refused exactly when they reach a kill: a `read` of another
variable beside it, or an arithmetic count that is only a status or a value no kill expands,
refuses nothing; and a lister whose substitution sits in no command it can read is counted, never
passed in silence. (Amended 2026-10-27: herestring host, process substitution, arithmetic and
"exactly when".)

**Narrowed 2026-10-28.** "Refuses nothing" holds save where the command also holds a kill the
run-time guard cannot see, which `mh-a-kill-the-runtime-guard-cannot-see-is-refused` refuses by
its words, whatever the substitution feeds.

**Site derivation.** `feeds_kill()` and `subst_host()` in `hooks/block-unsafe-kill.sh`, the only
readers of where a lister's output goes; the spans are recorded by `quote_mask._sub`, which every
substitution opening (`$(`, a backtick, `<(`, `>(`) in unquoted code, inside `"…"` and inside an
unquoted heredoc body passes through, and by `quote_mask._scan` for an unquoted arithmetic
`((…))`, recorded as kind `arith` with the substitutions inside it.

**Pinned by.** `hooks/tests/test-block-unsafe-kill.py`, `hooks/tests/test-lister-substitution-host-cert.py`, `hooks/tests/test-lister-substitution-structure-cert.py`.

## `mh-a-lister-reaches-a-kill-through-every-binding-site`

**Invariant.** `hooks/block-unsafe-kill.sh` refuses a `pgrep` or `pidof` whose pids bash
carries to a kill through any binding site it has — a pipeline, the output of a compound
command (`{ }`, `( )`, a loop, `if`, `case`) piped on, an output process substitution `>(…)`,
a substitution, a variable assigned by `=`, `declare`/`local`, `printf -v`, `${P:=…}` or `eval`,
the positional parameters bound by `set`, a function call or `sh -c CODE NAME ARGS`, xargs'
replace string in `sh -c` code, a `for`, a `read`, a string handed to a program that runs it
(`bash -c "kill $(L)"`, `find . -exec kill $(L) \;`, `ssh localhost kill $(L)`; amended
2026-10-28) — and through any command that expands such a binding and writes it on; and it
refuses none of them when bash carries the pids to no kill.

**Retired 2026-10-28.** Superseded by its one-sided restatement, `mh-a-kill-the-runtime-guard-cannot-see-is-refused`. Its tests still pass and stay as regression checks.

**Site derivation.** `feeds_kill()` in `hooks/block-unsafe-kill.sh` (its `climb()`,
`compounds()`, `shell_takes_pids()`, `handed_to_kill()` and the binding loop after it) and the `eval` re-reading in
`analyse()`: the only readers of where a lister's pids go. The binding sites are bash's own:
the builtins that bind a name from their operands (`read`, `mapfile`, `printf -v`, `set`,
`declare` and its kin, `for`, `eval`), parameter-expansion assignment, function and `sh -c`
arguments, and the redirections and pipes a compound command's output takes. Not followed: a
file, a named pipe, a coprocess, an fd opened by `exec`, a function's stdin.

**Pinned by.** `hooks/tests/test-block-unsafe-kill-binding-sites.py`, `hooks/tests/test-block-unsafe-kill-command-runners.py`, `hooks/tests/test-block-unsafe-kill-parallel-stdin.py`, `hooks/tests/test-lister-binding-order-and-scope.py`, `hooks/tests/test-lister-binding-sites-cert.py`, `hooks/tests/test-lister-bound-name-and-order-cert.py`, `hooks/tests/test-lister-every-binding-site-cert.py`.

## `mh-a-words-value-is-bash-quote-removal`

**Invariant.** `hooks/bash_parse.py` gives every word the value bash's quote removal gives it —
`'…'` literal, an unquoted backslash escaping any character, a backslash inside `"…"` or `$"…"`
escaping only `$`, `` ` ``, `"`, `\` and a newline, `$'…'` with its escapes decoded, and a
command or process substitution kept as the code it is — so a string handed to `eval`, `bash -c`
or any program that runs it as code is read as the code bash runs.

**Site derivation.** `unquote()` in `hooks/bash_parse.py`, the one place a word's value is made:
every `Cmd.words` value and every code string `parse()` and `resolve()` hand on are its output. Its `$'…'` escapes are
`ansi_escape()`. Where a word ENDS is the other half of its value, and is made in two places:
`parse()` (`_region()`), which reads each substitution's span as part of the word it sits in and
its body as commands of their own, and `code_heredocs()`, which reads the command a heredoc
feeds the same way. A command word is named with its expansions left out, and one of nothing
but unquoted expansions may vanish (`command_word()`, read by `Cmd.name`, `resolve()`,
`handed_code()`, `reads_code_on_stdin()` and block-unsafe-kill's substitution host), since a
word that now keeps `$(true)` whole would otherwise name no program where bash runs the next.

**Site derivation (`\u`/`\U`).** `u32_to_utf8()` in `hooks/bash_parse.py`, the one place a code
point becomes text: `ansi_escape()` reaches it from both `ANSI_NUM` groups that read a code point
(`u…` and `U…`), and every `$'…'` value is `ansi_escape()`'s output; the code points it binds are
every value 0..0xFFFFFFFF that eight hex digits spell, derived as the band boundaries of bash's
`u32toutf8()` (`lib/sh/unicode.c`) plus seeded values from each band.

**Site derivation (the character before a position).** Where the shared scanner reads the
character before a position to decide what the one at it is (does a `#` open a comment, a word
open a `case`, a `<<` begin a heredoc rather than end a `<<<`). That character is a break only
when no backslash escaped it, and a continuation is stepped over. Every such test is listed by
`grep -nE "t\[i - 1\]|_after_word_break\(" hooks/quote_mask.py`, which names four, all in
`_scan()`/`_case_step()`: the comment, the `case` word and the heredoc operator, which read the
set of escaped positions `_scan()` records, and the `$'` opener, which asks `_escaped()`. The
`\cx` escape is `ANSI_NUM` group 5 in `ansi_escape()`, which works on the first BYTE of the
character after `\c`, as bash's `TOCTRL` does.

**Site derivation (a backtick body).** The code bash runs for a backtick body is
`backtick_code()` in `hooks/quote_mask.py`, the one place it is made, and its end is the first
backtick no backslash escapes (`_sub()`). Its readers are every reader of a recorded span,
`grep -n '"body"\]' hooks/*.py hooks/*.sh`: those that read the text between the delimiters as
code read `backtick_code()`'s output — `parse()` (`_backtick_region()`) and `compound_flow()` in
`hooks/bash_parse.py`, listed by `grep -n 'backtick_code(' hooks/*.py`; those that read offsets
only (block-unsafe-kill's structure) read the substitutions `_sub()` records from that code, at
the offsets they were written at; and `unquote()` keeps a backtick inside "…" with the backslash
of each `\"` in its body dropped, the code it is outside them.

**Site derivation (an expansion's closing paren).** A `#` opens a comment only where a word
begins, and the closing `)` of an expansion — `$(…)`, `<(…)`, `>(…)`, `$((…))` — ends the
expansion, not the word; the `)` of a subshell, a `((…))` command or a case pattern ends the word.
`grep -nE "_after_word_break\(|esc\.add\(|_opens_sub\(t, i\)|_arith\(t, i\)" hooks/quote_mask.py`
lists both ends of the class. The readers are the two calls of `_after_word_break()`, the comment
in `_scan()` and the word start in `_case_step()`, and both read the set `_scan()` keeps of
metacharacters that are still a word's. The writers are the places an expansion is entered in
unquoted context, the `_opens_sub()` and `_arith()` branches of `_scan()`, each of which adds its
closing paren to that set (`_arith()` only when a `$` no backslash escaped comes before it). The
other two `_opens_sub()` calls are in `_arith_walk()` and `_span_double()`, where no `#` opens a
comment.

**Site derivation (where a word ends).** bash ends a word at a blank, a separator, and an unquoted
`<` or `>` (with the `&` of `&>`), and never inside a `$((…))`, `${…}` or `$[…]`.
`grep -nE "SEP\.finditer|_tokens\(|split_words\(" hooks/bash_parse.py` lists every place
bash_parse.py splits a segment into words: `_region()` (read by `parse()` and
`_backtick_region()`), `_line_words()` and the line prefix in `code_heredocs()`, which scan `SEP`
and split with `split_words()`, and `compound_flow()`, which tokenises with `_tokens()`. Each one
fills its mask with `word_chars()` before it scans, and splits words with `word_spans()` or
`_redir_cuts()`, so a redirection's fd stays in its word (digits or `{NAME}`, never before `&>`).
`REDIR` reads the same fd forms, and `SEP` does not cut the `|` of `>|`.

**Pinned by.** `hooks/tests/test-a-words-value-is-bash-quote-removal-cert.py`, `hooks/tests/test-bash-parse-word-value-cert.py`, `hooks/tests/test-escaped-char-is-no-word-break.py`, `hooks/tests/test-expansion-close-is-no-word-break.py`, `hooks/tests/test-word-value-bash-oracle-cert.py`, `hooks/tests/test-word-value-is-quote-removal-independent-cert.py`, `hooks/tests/test-words-value-blind-recertify-2-cert.py`, `hooks/tests/test-words-value-blind-recertify.py`, `hooks/tests/test-words-value-fuzz-recertify.py`, `hooks/tests/test-words-value-recertify-93b2f8e.py`, `hooks/tests/test-words-value-runs-as-bash-runs-cert.py`, `hooks/tests/test-words-value-sentence-recertify.py`.

## `mh-the-mask-reads-code-in-double-quotes-whatever-it-shows`

**Invariant.** `hooks/quote_mask.py` reads the same structure — every quote span, comment,
heredoc and substitution — inside a `$(…)` or backtick within `"…"`, and inside an unquoted
heredoc body, whatever its `live`, `quotes` and `fill` arguments, so `heredocs()` (from which
`hooks/bash_parse.py` `code_heredocs()` names the bodies fed to a shell) finds every heredoc
`parse()` reads, and a quote inside such a heredoc body never closes the enclosing `"…"` at any
site of the mask.

**Site derivation.** `_span_double()` and `_body_live()` in `hooks/quote_mask.py`, the two places
code nests inside a span that may be masked; the sites are every importer of `quote_mask`.

**Pinned by.** `hooks/tests/test-quote-mask-nested-structure-cert.py`.

## `mh-the-mask-is-its-inputs-length-or-the-call-is-refused`

**Invariant.** The shared mask (`hooks/quote_mask.py`: `mask_quoted`, and the scan behind
`heredocs`, `substitutions` and `continuations`) is the input's length on every input, and any
caller that gets a mismatch refuses rather than allows: the scan raises `MaskMismatch`,
`hooks/bash_parse.py` `parse()` lets it out instead of returning no commands, each guard that
reads the mask (here block-unsafe-kill) denies, saying it could not read the command.

**Site derivation.** Every hook that imports `quote_mask` or `bash_parse`, derived from those
imports.

## `mh-a-substitution-ends-where-bash-ends-it`

**Invariant.** Every span `hooks/quote_mask.py` `substitutions()` records for a `$(…)`, `<(…)` or
`>(…)` ends at the paren bash closes that substitution with, a `case … esac` in its body
included: the word `case` in command position opens one, and until its `esac` a pattern's `)`
(`x)`, `(x)`, `a|x)`, an extglob `@(a|b))`) is the pattern's, never the body's close; the word
`case` as an argument, or quoted, opens nothing, so a `)` that does close the substitution still
closes it. The mask keeps its input's length, and a body the scan cannot read still raises
`MaskMismatch` (`mh-the-mask-is-its-inputs-length-or-the-call-is-refused`), never a short span.

**Site derivation.** `_scan()` in `hooks/quote_mask.py` (with `_case_step()`), the one scan of a
`)`-closed body, and every reader of the spans it records, by grep of `substitutions(` under
`hooks/`: `hooks/bash_parse.py` `unquote()`, `code_heredocs()` and `parse()` (whose regions and
words feed block-unsafe-kill and the handed-code readers) and `hooks/block-unsafe-kill.sh` (its
lister and binding readers, two calls).

**Pinned by.** `hooks/tests/test-quote-mask-case-in-substitution.py`.

## `mh-a-dollar-double-paren-is-arithmetic-only-where-bash-reads-it`

**Invariant.** `hooks/quote_mask.py` reads `$((` (and a bare `((`) as bash does: it is
arithmetic only when the `)` that balances its second `(` (quotes and substitutions read as
bash reads them) is followed at once by `)`; otherwise `$((` opens a command substitution whose
body starts with a subshell, and a bare `((` two subshells, so the command in `$(( cmd ) )`,
`$((cmd) )`, `$((a); (b))` or `$((cmd)|cat)` is recorded by `substitutions()` as code (kind
`cmd`, never `arith`) in unquoted code, in `"…"` and in an unquoted heredoc body alike, and
`<((` and `>((` are always process substitutions. Real arithmetic (`$((1<<2))`, `$(( (a+b) * 2
))`, `$(( $(L) + 0 ))`, nested parentheses) stays kind `arith`, with the substitutions in it
recorded as before; the mask keeps its input's length on every such input
(`mh-the-mask-is-its-inputs-length-or-the-call-is-refused`).

**Site derivation.** `_arith()` and `_arith_walk()` in `hooks/quote_mask.py`: the one decision,
asked by `_opens_sub()` (every `$(` in unquoted code, in `"…"`, in an unquoted heredoc body and
inside arithmetic) and by `_scan()` before it records an `arith` span, and the one walk both the
decision and that span's end come from. Every reader of the spans, as listed for
`mh-a-substitution-ends-where-bash-ends-it` (bash_parse, block-unsafe-kill).

**Pinned by.** `hooks/tests/test-quote-mask-dollar-double-paren.py`.

## `mh-a-kill-the-runtime-guard-cannot-see-is-refused`

**Invariant.** `hooks/block-unsafe-kill.sh` refuses every command whose text holds a process
lister (a `pgrep` or `pidof` command, or a `ps` command piped on, in the command or in any code
the guard reads as code) together with a kill sent by a route the run-time kill guard
(a prototype of the original, not shipped) cannot see: a `kill`, `pkill` or `killall` command in code a shell
other than bash runs (its `-c` string; a pipe, herestring or heredoc into it; the string `watch`,
`at`, `batch`, `git`, `sg` or `newgrp` hands to `/bin/sh`); one among the words after `ssh` or
`mosh`, to any host; one run by `sudo`, `doas`, `su`, `runuser`, `pkexec`, `run0` or `env -i`;
one named by a path, or after `builtin` or `command`; one beside `unset -f kill`, or beside an
assignment to, or `unset` or `export` of, `KILL_GUARD_RUNTIME`, `CLAUDE_PID` or `BASH_ENV`; and
code handed to an interpreter (any program the guard reads as none of a shell, a wrapper, a kill
or a data tool; `awk` and `sed` included) on its argv, a herestring, a heredoc or an
`echo`/`printf` pipe, that holds `kill` after no letter but `p`, or `send_signal`.

**Sentence form.** one-sided — it promises refusal on a lexical class of words and nothing about
what passes.

**Site derivation.** `unseen_route()` in `hooks/block-unsafe-kill.sh`, asked after `analyse()`
on every command, is the one reader. Its walk reads the command with the hook's own `parse()`,
and recurses into every string `bash_parse` hands on as code (`Cmd.codes`) and every heredoc a
stdin-code reader takes (`reads_code_on_stdin()`), carrying the route that string took. The
routes are those measured live to be invisible to the run-time guard (a shell other than bash,
another login, a reset environment, a path to the binary, an interpreter), plus the bash
spellings that skip that guard's own `kill` function (`builtin`, `command`, `unset -f`, its
switch variables), read off that guard's source (original only). Interpreters are not listed: any
program outside `NOT_INTERPRETERS` counts, and its argv words that are not a plain path, option
or number are its code. The interpreters of the host the check runs on, and each one's own signal senders, are
derived by the check from the interpreters themselves. A program the hook's `parse()` reads past
to its kill word (`carried_kill()`: `watch -n 1 kill N` read from `kill`) keeps its route: the
program carried past is `Cmd.carrier`, and a carrier in `SH_RUNNERS`, a shell other than bash, or
in `PRIVILEGE` adds its route to the kill it carries. The words read past to are every kill and
lister the guard reads (`CARRIED`: kill, pkill, killall, pgrep, pidof). The strings git hands to
`/bin/sh` include its configuration: a `!` alias, and the keys git-config(1) runs as a command
(`bash_parse.GIT_SH_KEYS`), set by `-c NAME=VALUE`, by `git config [set] NAME VALUE`, or through
the variables in `GIT_SH_ENV` set before a git. And `env -` is read as `env -i`.

**Stated limits.** A lister inside an interpreter's own code (`subprocess.run(["pgrep", …])`)
is not a lister here, and neither is a script run by path. A `PATH` reassigned before an `xargs
kill` is not read. A kill word assembled at run time is not seen, and nor is `systemctl kill`
or `docker kill`, which are not kill words. The routes named are those the run-time guard misses when it is
loaded as `BASH_ENV` plus PATH shims. Loaded any other way it misses more (a kill in `bash -c`, a
bash script, `xargs kill`, `env kill`, `timeout … kill`), which this sentence does not name.

**Pinned by.** `hooks/tests/test-kill-the-runtime-guard-cannot-see-cert.py`, `hooks/tests/test-kill-the-runtime-guard-cannot-see-sentence-cert.py`, `hooks/tests/test-kill-the-runtime-guard-cannot-see.py`.

## `mh-a-hooks-tests-shell-runs-where-no-host-process-can-be-signalled`

**Invariant.** Every hooks test (a Python file in hooks/tests) that gives a shell code on its argv builds
that argv inside `bash_oracle.argv(...)` or `bash_oracle.run(...)` (`bash_oracle.py`, beside the tests in hooks/tests),
which runs it in a fresh user and pid namespace with its own `/proc`
(`unshare --user --map-current-user --pid --fork --mount-proc --kill-child`) and in a session and
process group of its own (`bash_oracle.INIT` calls `setsid()` before it forks the line), where no
host process can be listed or signalled, by its pid or by a signal to the line's own process group.

**Amended 2026-11-03.** A pid namespace leaves its processes in the caller's HOST process
group, so `kill 0`, `kill -s KILL 0`, `os.killpg(0, ...)` and `kill -- -PGID` from inside signal
every host process in that group. The process-group clause and `setsid()` were added.

**Sentence form.** one-sided — the guard refuses a lexical class of argv and says nothing about a
shell that gets its code another way (below).

**Site derivation.** An AST walk over every Python file in hooks/tests but the helper. A site is an argv
display (list or tuple) that holds a shell name followed by a short-option cluster holding `c`
(`-c`, `-lc`, `-ec`); or that holds such a cluster after a first element that is not a string
constant and not `sys.executable`; or that starts with one (a tail spliced onto a shell argv);
and every `shell=` other than `False`, `os.system`, `os.popen`, `subprocess.getoutput`,
`subprocess.getstatusoutput`, and an `os.exec*`/`os.spawn*` call whose arguments read as such an
argv. The shell names are the basenames of `/etc/shells` together with `bash_parse.SHELLS`. A site
is routed when it lies inside the first argument of a call to `bash_oracle.argv` or
`bash_oracle.run`. The routes a line has to a host process are derived from what the kernel
addresses a signal by: a pid (`kill(2)` with pid > 0, pidfd), every process (`kill -1`), and a
process group (`kill(2)` with pid 0 or -PGID, `killpg`); the first two are closed by the pid
namespace (no host pid is nameable, `kill -1` stops at its border), the third by `setsid()`
(the line's group is INIT's, pgid 1, and no host group is nameable from inside, since a group
whose leader is outside the namespace reads as pgid 0). Both `argv()` and `run()` build their argv
from the one `PREFIX`, whose INIT is the one place the session is made.

**Why pid 1 is a reaper.** A namespace ends when its pid 1 does. With the line's shell as pid 1,
a `>( )` reader or a backgrounded stage that outlives the shell by milliseconds would be killed
mid-write. So pid 1 is `bash_oracle.INIT`, which runs
the argv, keeps its exit status, and waits up to `GRACE` (2 s) for what the line left running.
`--map-current-user` rather than `--map-root-user` because `sg` and `newgrp` cannot switch to an
unmapped group, and `test-block-unsafe-kill-command-runners.py`'s oracle asks them to.

**Stated limits.** `unshare` itself stays in the caller's process group; it is outside the
namespace, so no pid the line can name reaches it. After `setsid()` the line has no controlling
terminal, so `/dev/tty` cannot be opened from it. `_prove()`'s WINCH half is a negative only where
no other thread of the caller has SIGWINCH unblocked (it skips itself when the caller already
blocks it); its pgid/sid half does not depend on threads. A shell given its code on stdin or in a script file (`bash run.sh`), or an
argv whose `-c` arrives in a variable, is not a site: every `bash <file>` in `hooks/tests`
runs a hook under test or a fixed `sleep`. A shell killed by signal N reads as exit 128+N, not -N. Proven
under one uid only, on a kernel that lets an unprivileged user create user namespaces. Where `unshare` cannot make the namespace, the helper raises and the test goes red;
the line is never run on the host.

**Pinned by.** `hooks/tests/test-bash-oracle-own-process-group-cert.py`, `hooks/tests/test-bash-oracle-sees-no-host-process.py`, `hooks/tests/test-block-unsafe-kill-command-runners.py`, `hooks/tests/test-escaped-char-is-no-word-break.py`, `hooks/tests/test-lister-bound-name-and-order-cert.py`, `hooks/tests/test-quote-mask-dollar-double-paren.py`.

## `mh-a-hooks-tests-oracle-line-dies-with-its-caller`

**Invariant.** Every process `bash_oracle` starts for a hooks test (unshare, the namespace's INIT
and the line) dies when the process that called `bash_oracle.argv(...)` or `bash_oracle.run(...)`
dies, whatever ended it, including a SIGTERM to the caller's process group that the line's own
session does not receive.

**Site derivation.** `bash_oracle.PREFIX` is the one argv head: an AST walk of
`hooks/tests/bash_oracle.py` (`prefix_rows()` in the check) finds every `subprocess`/`os` spawning
call in the helper and requires its argv to be `argv(...)` or to start `list(PREFIX)`; the guard of
`mh-a-hooks-tests-shell-runs-where-no-host-process-can-be-signalled` routes every shell-code argv
of hooks/tests through `argv()`/`run()`. PREFIX starts `setpriv --pdeathsig KILL`, so the kernel
SIGKILLs unshare when its caller dies, and `--kill-child` takes INIT and the line with it.

**Stated limits.** The parent-death signal follows the calling THREAD: a caller that runs
`argv()`/`run()` from a thread that exits before the line ends has the line killed then. A caller
that dies between its fork and setpriv's `prctl` leaves an untied unshare (microseconds, not
closed). Hooks tests that start a hook run or a sleeper with `start_new_session=True` are held by
`mh-a-hooks-tests-session-child-is-tied-to-its-test` instead.

**Pinned by.** `hooks/tests/test-bash-oracle-line-dies-with-its-caller-cert.py`, `hooks/tests/test-bash-oracle-sees-no-host-process.py`.

## `mh-a-hooks-tests-shell-writes-nothing-under-the-callers-home`

**Invariant.** A line handed to `bash_oracle.argv(...)` or `bash_oracle.run(...)` runs with a HOME
that is not the caller's real home (its passwd entry) unless the caller set HOME to a directory of
its own, and with HISTFILE and every XDG_*_HOME that named a path under the real home pointing
into that HOME instead, so a shell that saves its history or state on exit writes nothing under the
caller's home; the oracle's HOME is removed when its INIT exits.

**Site derivation.** Every oracle line is exec'd by `bash_oracle.INIT` (the guard of
`mh-a-hooks-tests-shell-runs-where-no-host-process-can-be-signalled` routes every shell-code argv
of hooks/tests through `argv()`/`run()`, and `prefix_rows()` of
`mh-a-hooks-tests-oracle-line-dies-with-its-caller` holds that PREFIX, ending in INIT, is the one
argv head), so INIT's environment is the one site. The variables are what a shell's default write
locations are derived from: HOME (bash, zsh, python `-i` history and rc files), HISTFILE (bash's
override), and the XDG base-directory variables (fish's history and state).

**Stated limits.** An INIT killed by SIGKILL before its loop ends leaves its directory in
`$TMPDIR`. A program that writes to a path it reads from `/etc/passwd` rather than from HOME is
outside the sentence.

**Pinned by.** `hooks/tests/test-bash-oracle-writes-nothing-under-callers-home.py`, `hooks/tests/test-handed-code-long-option-prefixes-cert.py`.

## `mh-a-heredoc-in-a-backtick-is-read-where-bash-reads-it`

**Invariant.** A heredoc inside a backtick body is read by `hooks/bash_parse.py` from the code
bash runs there (`quote_mask.backtick_code()`), however the backtick's de-escaping shifts the
text before the heredoc, in its delimiter line or in its body. Its body is the text bash's
heredoc holds, at the offsets it was written at. The commands read from it, and the code they
hand on (an unquoted code body's expansion included), are those the same code gets when read
unwrapped, at the offsets that code was written at. A code body named inside a backtick is named
at the offset `quote_mask.heredocs()` gives that body as written, whatever its first character:
an escape the de-escaping removes (`\``, `\$`, `\\`, `\"` inside "…") is part of the body as
written.

**Site derivation.** Every reader of a heredoc record in `hooks/bash_parse.py`,
`grep -n 'heredocs(' hooks/bash_parse.py`: `code_heredocs()` (its own loop over the text as
written, skipping every heredoc whose operator lies in a backtick body, then itself over each
outermost backtick's `backtick_code()` mapped back, then `compound_flow()`), `compound_flow()` (a backtick body read by itself over
`backtick_code()`'s output and mapped back through its offset list), `_backtick_region()`
(`code_heredocs()` of that code, its mask and its regions) and `_expanded_bodies()`. That last
one is called by `parse()` over the text as written, skipping every heredoc whose operator lies
in a backtick body, and by `_backtick_region()` over the code. Every site that maps a
backtick's code body back to the text (`grep -n '_body_at(' hooks/bash_parse.py`: the backtick
loop of `code_heredocs()` and the body offsets of `compound_flow()`) maps it by `_body_at()`, the
offset just past the written newline that ends its operator line; a site that maps a CHARACTER
(a command's offset in `_backtick_region()`, the command offsets of `compound_flow()`) maps it by
`src[p]`. Every one of those readers takes a backtick's code from `tick_code()`, which is
`backtick_code()` with the code's own line continuations removed (`_joined()`, the offset-keeping
core of `join_lines()`), because de-escaping turns a written `\\<NL>` into `\<NL>`, a continuation
of the code. `code_heredocs()` reads the text with its continuations removed and maps what it
names back. `hooks/quote_mask.py` `_sub()` is the one other caller of `backtick_code()`; it
re-reads a backtick's substitutions from that code joined (`quote_mask.joined()`, with the run's
code bodies carried in by `_code_at()`) and records each at the offset it was written at.
`bash_parse._joined()` is that same `quote_mask.joined()`, so both readers of a backtick body
share one join.
A heredoc whose operator lies in a backtick body that closes on the operator's own line has an
EMPTY body, as bash gives it: bash reads that heredoc from the backtick's own text, warns it was
delimited by end-of-file, and the outer shell runs the lines after the backtick. Every bounded
scan that can leave a heredoc pending is a call of `_scan(` in `hooks/quote_mask.py`: the top
level (bounded by the text's end), a code heredoc body in `_bodies()` (its pending ones end with
the body), a `$(…)` or `<(…)` body in `_sub()` (bash reads its heredoc from the lines after the
substitution's line, so it stays pending) and a backtick body in `_sub()`, which drops every
heredoc it opened and did not read.
A heredoc pending OUTSIDE a substitution when it opens is read where bash reads it, however many
lines the substitution spans: bash reads a backtick, `$(…)` or `<(…)` body to its close first, so
its lines are the body's code, and the outer heredoc's body starts on the line after the
substitution's close. A heredoc a `$(…)` or `<(…)` body opens and does not read is read before
the outer one. Every place a substitution body is scanned is `_sub()`, the one callee of
`_opens_sub(` (the top-level scan, `_body_live()`, `_arith_walk()` and `_span_double()` all call
it), and it sets the pending heredocs aside for the body and restores them after it. Not covered:
a parameter expansion `${…}` spanning a newline, which quote_mask does not model as a word.

## `mh-the-kill-guards-separator-scans-hold-expansions-whole`

**Invariant.** Every place `hooks/block-unsafe-kill.sh` splits a command at a separator
(`bash_parse.SEP`) does so over a view in which `${...}`, `$[...]` and `$((...))` are word
characters, so a `;`, `|`, `&` or newline inside an expansion never ends a pipeline, a
substitution host or a command for the guard.

**Site derivation (mechanical).** Every `SEP.<method>(` call in the hook's source, found
by the regex `\bSEP\.(\w+)\(\s*([A-Za-z_]\w*)` and named by the `def` whose body holds it; seven: `subst_host()` (where a substitution's host starts), and in `feeds_kill()`
`end_of()` (where a call ends), `resets()` (whether an assignment stands alone), `downstream()`
(where a pipeline ends), `handed_to_kill()` (where a host that hands code on ends), `climb()` (a
compound's redirection into `>(...)`), and `analyse()`'s eval (where the eval command ends). Each
reads `hv`, bound from `held(v, subs)`: `bash_parse.word_chars()` applied level by level (the top
level and each command or process substitution's body, with the substitutions nested in it
filled), so a substitution inside an expansion keeps its own separators for the scans of its body.

**Pinned by.** `hooks/tests/test-unsafe-kill-sep-scan-holds-expansions-whole.py`.

## `mh-an-eval-is-read-as-the-code-bash-runs`

**Invariant.** The code `hooks/bash_parse.py` hands on for an `eval`, and the code
`hooks/block-unsafe-kill.sh` re-reads the call with when it spells the eval as what it runs, is
the string bash's eval runs — its argument words' values joined by single spaces, after a leading
`--`, with no redirection or redirection target among them — and that code ends where bash's string
ends, so nothing in it (a `#` comment, a quote) reaches the commands written after the eval.

**Site derivation.** Every reader of an eval's code, found by `grep -nE '"eval"|codes\['
hooks/*.py hooks/*.sh`: at 94ab4fc three. `bash_parse.parse()` builds the code (now
`eval_code()`), which every `for code in c.codes` reader of the hook analyses alone;
`analyse()`'s eval re-read splices it into the call (it took `c.codes[-1]`, now `eval_code()`,
standing as `{ CODE` newline `}`); the binding loop of `feeds_kill()` (`if name == "eval"`) reads
each word for an assignment, which a redirection target can only over-bind (a refusal, not a
pass), so it is not a site of this sentence. The one site that splices handed code into the call
(so that code can reach what follows it) is found by `grep -n 'analyse(text\[:'
hooks/block-unsafe-kill.sh`: at 41d06c7 the eval re-read alone; every other `analyse()` of a
code reads it with nothing after it. Of a string bash cannot parse whole, that site reads what
`eval_runs()` names: the longest whole-line prefix `bash -n` accepts, since bash's eval runs its
lines up to the first syntax error and then the call goes on (every whole-line prefix where bash
cannot be asked, reading too much rather than too little). What a code that `bash -n` accepts
can still leave open at its end is what bash accepts open at the end of its input: `bash -n`
exits 0 there only with its `delimited by end-of-file` warning, a here-document's, so the open
here-documents are the remainder of the class, and the site closes each at the code's end
(`heredocs_closed()`, read by the `quote_mask.heredocs()` the call is read with). The same site
stands a piped eval's code as `( CODE` newline `)`, since bash runs a pipeline member in a
subshell (`lastpipe` aside): `eval 'P=$(pgrep -f X) <<E' | cat; kill $P` binds nothing after it.

**Pinned by.** `hooks/tests/test-eval-re-read-is-the-code-bash-runs-cert.py`, `hooks/tests/test-eval-re-read-is-the-code-bash-runs.py`.

## `mh-an-arithmetic-expansion-is-known-by-its-record`

**Invariant.** Whether an arithmetic `((` that `hooks/quote_mask.py` `substitutions()` records is a
`$((` expansion, and where that expansion opens and ends, is read from its record (its "dollar",
the offset of the `$` bash opens it at, line continuations between them skipped, mapped back to
the offset it was written at in a backtick body; its `))`), never from the characters of the text
beside its first `(`, so block-unsafe-kill gives a kill whose lister sits in a `$((` in a backtick
the verdict of the same code unwrapped, however a de-escaped `\\<NL>` or a written `\\$`
separates the `$` from the `((`.

**Site derivation.** In `hooks/block-unsafe-kill.sh`, every reading of an arithmetic record's opening
or extent, `grep -nE 'open"\] - 1\]|open"\] - \(|\[o - 1\] == "\$"|\(s\["open"\], s\["body"\]\[1\]\)' hooks/block-unsafe-kill.sh`
11 lines: `subst_host()` (`t0[o - 1] == "$"`), `feeds_kill()`'s arithmetic step (the
same test), its two `takes_input()` calls (`sub["open"] - (kind == "arith")`), its `glued`, and
six span lists, each `(open, body end)`: `subst_host()`'s nested spans, `end_of()`, `resets()`,
`downstream()` and `handed_to_kill()` in `feeds_kill()`, and the eval scan of `analyse()`. Every one asks `opening()` (the record's
"dollar", else its "open") or `extent()` (`opening()` through its last `)`). In `hooks/quote_mask.py` the record is made in `_scan()` (`_dollar()`) and moved
in `_mapped()`, its two writers, and `_arith_walk()` records the continuations in an arithmetic
as `_scan()` does, so a backtick's `(( \\$\\\\<NL>(L) ))` is joined before it is read. Two readers in
`hooks/bash_parse.py` still read the character before the `(`: `unquote()` (`raw[s["open"] - 1]
== "$"`) and `arith_commands()` (`t[s["open"] - 1] == "$"`).

## `mh-a-backtick-body-is-masked-as-the-code-bash-runs`

**Invariant.** Wherever `hooks/quote_mask.py` `mask_quoted()` shows a backtick body as scanned
code, it shows the mask of the code bash runs there (`backtick_code()`, its continuations joined),
read by itself with the same `quotes`, `keep`, `fill` and `live`, each character at the offset it
was written at, and `fill` at every character the de-escaping or the join removes.

**Site derivation (mechanical).** A backtick body is masked only in `_sub()`, so the sites are the
contexts that hand a backtick to it: every function of `hooks/quote_mask.py` that calls `_sub()`,
found by an AST walk (`_scan()` for unquoted code, `_span_double()` for "...", `_body_live()` for
an unquoted heredoc body, `_arith_walk()` for an arithmetic expression). The mask shows the body
as scanned everywhere except inside a "..." or heredoc body it masks without `live`, and an
unmasked unquoted heredoc body, which it shows as written. Every caller of `mask_quoted()`
(`grep -n 'mask_quoted(' hooks/*.sh hooks/*.py`) reads that mask; block-unsafe-kill's
`subst_host()` finds a substitution's host by the separators in it.

## `mh-a-name-kill-filter-held-in-an-expansion-is-counted`

**Invariant.** Where a name-keyed kill that `hooks/block-unsafe-kill.sh` counts gives a selection
option a value the shell only knows when it runs (`pkill -u $(id -u) NAME`, `kill $(pgrep -P $X
NAME)`, `kill $(pidof -o $$ NAME)`), the hook still counts it: an owner value that spells the
session's own user in the call's own shell is counted as that user, and any other such value is
counted with its option left out, so the count is never smaller than what the kill can reach.

**Site derivation (mechanical).** The options bound are every option the hook's own tables
say takes a value and reaches the count — `PG_ARG_SHORT & PG_COUNT_SHORT` and `PG_ARG_LONG &
PG_COUNT_LONG`, read by an AST walk of the hook's python (`-F -G -O -P -U -g -r -s -t
-u --cgroup --env --euid --group --ns --nslist --older --parent --pgroup --pidfile --runstates
--session --terminal --uid`) — and every value-taking option of pidof's SYNOPSIS (`man pidof`:
`-d`, `-o`). The check derives both sets at run time and is red for a derived option it has no row
for. The counts that read these values are `shared_name()` (pkill, and pgrep into a kill) and
`pidof_argv()` (pidof into a kill): `grep -n 'pg_options(\|pidof_argv(' hooks/block-unsafe-kill.sh`
lists them beside the three callers that read only pg_options()'s `full` flag. Not bound: a NAME
or pattern that is itself an expansion (`pkill -x "$NAME"`), the stated limit in the hook's header.

## `mh-a-pattern-less-kill-is-counted`

**Invariant.** A kill that `hooks/block-unsafe-kill.sh` reads whose selection names no process —
`pkill` or a `pgrep` into a kill with an owner filter (`-u`/`-U`/`--euid`/`--uid`, separate, glued
or `=`, a literal or an expansion of the session's own user or uid) or any other selection filter
and no pattern — is counted like a name kill with the same filters, by the same matcher, owner
reading and dropped-filter widening, with every name in place of the pattern, and refused when it
reaches more than one process; a pattern-less selection is never read as "no count, pass". An
owner filter naming ANOTHER user is counted and refused the same way: for a non-root sender the
kernel refuses each of those signals, so that refusal is of a no-op, and it stands because the
same text under sudo or as root reaches every one of them. A command with no criterion at all
(`pkill`, `pkill -x`, `pkill -v`) is pkill's own usage error, selects nothing and stays silent.

**Site derivation.** The one count of a pkill/pgrep selection is `pg_options()`, read by
`shared_name()` (pkill, and pgrep whose pids reach a kill); `grep -n 'pg_options(' hooks/block-unsafe-kill.sh`
lists it beside the three callers that read only its `full` flag. Which flags are criteria
without a pattern is read off procps (`pgrep -n`, `-o`, `-r S`, `-O 1` answer; `-v`, `-i`, `-A`,
`-x` alone exit 2), and is the hook's `NOT_A_CRITERION`. killall is refused
structurally whatever its options, so `killall -u "$USER"` is outside this count.

**Amended 2026-11-02.** The clause "a pattern-less selection is never read as 'no count, pass'"
no longer covers a selection whose only dropped filters are kinship filters and which is not
inverted. That case is now `mh-a-pattern-less-kinship-kill-is-not-the-host`, below. Every other
pattern-less selection is still counted as this sentence says.

**Amended again 2026-11-02 (later).** A selection whose only criterion is `-n`/`-o` (`--newest`,
`--oldest`, any abbreviation) is no longer counted: it is refused before any count, as
`mh-a-whole-account-kill-is-refused` says, below. "Any spelling of its options" here includes
every abbreviation procps accepts (`--eu`, `--ui`).

**Pinned by.** `hooks/tests/test-block-unsafe-kill-owner-only.py`.

## `mh-a-whole-account-kill-is-refused`

**Invariant.** `hooks/block-unsafe-kill.sh` refuses a kill whose target set is the whole account
or the caller's process group — a `kill` whose literal target is PID -1 or PID 0 in any grammar
bash's kill or `/bin/kill` reads a target in, with the signal that kill actually sends (a later
`-s`/`-n`, glued or separate, or `/bin/kill`'s `-s`/`--signal` anywhere before `--`, re-sets the
signal an earlier word named), after bash's brace expansion of a literal word and past a blank
before the number, a `ps` listing that selects by owner, every process or nothing whose pids
reach a kill, or a pkill/pgrep owner filter in any spelling procps accepts, abbreviated long
options included — as it refuses `pkill -u "$USER"`; and it refuses pkill, or pgrep into a kill,
whose only criteria are `-n`/`-o` and host-wide filters (`--ns`, `--nslist`, `-t`, `--cgroup`,
`-r`, `-O`, any spelling), which selects the newest or oldest process on the whole host whoever
owns it. A kill that both bash's kill and `/bin/kill` read as sending signal 0, or as listing
signals, is never refused by this rule.

**Stated limits (amended 2026-11-04).** Not read: a target, signal or command word the shell
computes when it runs — `$((-1))`, `$[-1]`, `$P` and `${P:--1}`, `$(echo -1)`, backticks, `k=kill;
$k -9 -1` — and a brace in a word that also holds a quote, an escape or an expansion; each passes
as a kill by PID does. Refused though one
of the two kills would send nothing: a spelling bash's builtin reads as signal 0 and `/bin/kill`
as a signal, or the reverse (`kill -0 --signal=KILL -1`, `kill -- -0 -1`), because the hook does
not tell which kill runs (`env`, sudo and xargs run `/bin/kill`); none is an ordinary probe. And `/bin/kill --signal KILL -1` (procps
takes `-1` as its signal word, then `--signal` replaces it: a usage error) is refused, as
`kill -1` alone is.

**On `-n`/`-o`.** Refused, not disclosed. A count of one is allowed
for a name kill because the writer named the process; `pkill -n` names nothing, so the one it
reaches is whatever started last on the host, usually the caller's own pipeline. With
a pattern or a filter (`pkill -n NAME`, `pkill -n -P $$`) it is read as before. Not covered:
`pkill -n -u "$USER"` (or `-G GID`), a count of one under an owner filter, which reaches the
account's newest process and passes as any one-process selection does. *Amended 2026-11-04:* `--ns` of one's own pid is the whole host, so -n/-o beside host-wide
filters alone (`NEWEST_WIDE`: --ns, --nslist, -t, --cgroup, -r, -O) is refused as -n/-o alone is.

**`kill -1` alone.** bash's builtin and `/bin/kill` read it as SIGHUP with no target, a usage error
that sends nothing. It is refused anyway, as the spelling of this kill missing its signal; a
refused no-op costs a rewrite. `kill -1 PID` (SIGHUP to a pid) is not refused.

**Site derivation.** Every kill passes `analyse()`'s structural loop over the call's
simple commands, past wrappers, paths and handed code (`grep -n 'kill_target(\|ps_whole_account('
hooks/block-unsafe-kill.sh`). Every pkill/pgrep long option is read through `pg_long()` in
`pg_options()`, the one parse of a pkill/pgrep argv. Its table `PG_LONG_ALL` is not a hand list:
the check derives procps's table from `/usr/bin/pgrep` (its `--help`, and the possibilities getopt
prints for every ambiguous one-letter prefix; pkill is the same program and table) and fails when
the hook's set differs, then asks the real pgrep how each prefix of each name reads.
*Amended 2026-11-04:* the one reading of a kill's argv is `kill_readings()` (`kill_argv()`'s brace
expansion, then `bash_kill_reads()` and `procps_kill_reads()`), asked by `kill_target()` and by the
two sites that decide whether a kill is a probe that pids feed nothing (`grep -n 'kill_readings('
hooks/block-unsafe-kill.sh`: `analyse()`'s `kills` and `synthetic_feeds()`'s `ks`). The option grammar is not a hand list: the check runs every
sequence of up to two signal words of each kind both kills read, and `--`, on both kills in
bash_oracle and holds the hook to what they send. `NEWEST_WIDE` is derived by the check from
`pgrep --help`: every option taking a value whose description matches or selects, less the kinship
(parent, session, process group) and owner (IDs) ones, plus the one that modifies `--ns`.

**Amended 2026-11-04.** An earlier `-N` signal word that a later `-s`/`--signal` re-sets is not a
target when the kill has a target of its own: `kill -0 -s TERM "$SRV"`, `/bin/kill -0 --signal KILL
-- 12345` and `/bin/kill --signal TERM -1 12345` signal the pid alone in both kills, and pass.
`procps_kill_reads()`, the only site that turns a signal word into a target, does so only when the
kill has no other target (`/bin/kill --signal KILL -1`, the refused no-op).

**Pinned by.** `hooks/tests/test-block-unsafe-kill-signal-reread.py`, `hooks/tests/test-block-unsafe-kill-whole-account-amended-cert.py`, `hooks/tests/test-block-unsafe-kill-whole-account-cert.py`, `hooks/tests/test-block-unsafe-kill-whole-account.py`.

## `mh-a-pattern-less-kinship-kill-is-not-the-host`

**Invariant.** `hooks/block-unsafe-kill.sh` does not count, and does not refuse on a count, a kill whose selection has no pattern, is not inverted, and leaves out of its count only kinship filters (`-P`/`--parent`, `-s`/`--session`, `-g`/`--pgroup`) whose values are known only when the shell runs; every other pattern-less selection is counted as `mh-a-pattern-less-kill-is-counted` says.

**Site derivation.** The one place a pkill/pgrep selection is counted is `pg_options()`,
read by `shared_name()`. `grep -n 'pg_options(' hooks/block-unsafe-kill.sh` lists it with its
callers. The kinship options are not a hand-list: they are the options that `pgrep --help`
(procps-ng) describes as matching by a process relation ("parent", "session", "process
group"). The check reads that help text from the installed pgrep and runs every option it finds. The hook's set is `KINSHIP_OPTS`.

**Not covered (stated limit).** The hook does not read what the value names. So `pkill -P $X` with
X=1 passes, where `pkill -P 1` would be counted. A NAME kill with a dropped kinship filter is still
counted without that filter (`mh-a-name-kill-filter-held-in-an-expansion-is-counted`), so
`pkill -P $P NAME` can be refused while the wider `pkill -P $P` passes.

**Pinned by.** `hooks/tests/test-block-unsafe-kill-kinship-runtime-value.py`.

## `mh-a-matcher-that-does-not-answer-selects-nothing-only-when-it-says-so`

**Invariant.** When the matcher the kill guard runs to count a name-keyed kill does not answer
(an exit status above 1, a timeout, or it does not start), the guard does not read that as
"nothing selected". It counts again with the option the matcher rejected left out, the same way
pg_options() already leaves out an option whose value is unknown, so the count is still the most
the kill can reach. If no count can be taken at all, it refuses and says the count could not be
taken. An exit status of 1 (no match) still reads as zero.

**Site derivation (mechanical).** The call sites are every `live_count(` call in the
hook's python, found by an AST walk. There are two: `shared_name()` (pkill, and pgrep
into a kill) and the pidof-into-a-kill path in `analyse()`. The options bound are every count
option of the hook's own tables (`PG_COUNT_SHORT`, `PG_COUNT_LONG`) that `/usr/bin/pgrep`, asked
at run time, exits above 1 on with an "unrecognized/invalid option" message (on a recent
procps-ng, `--env` alone). The table's `-q`, `--signal` and `--queue` never reach the count, and
every other count option is accepted. pidof (procps) exits 1, never above 1, for an option it
does not know, and it prints nothing, so a rejected pidof option is not reachable. Its rows use a stub.

**Read as zero, by design.** Some pgrep errors (exit 2) name the PATTERN or a VALUE pgrep
validated. `VALUE_ERROR` in the hook matches pgrep's own strings for these: "regex error",
"invalid user name", "invalid group name", "invalid session id", "invalid process group" and "not
a number". pkill parses both with the same code and exits on them, so the kill selects nothing
either way. Refusing them would turn two silent cases into false refusals: data the hook misreads as a
kill (`find -exec grep -l pkill {} +`, read as `pkill {}`), and the single-quoted literal
`pkill -u '$USER' NAME`.
This is narrower than a literal reading of the sentence's "an exit status above 1", and it is
stated here for that reason. An error that names no option and no value (`--nslist foo` exits 2
silently) takes the leave-out route.

**Not bound.** An exit status of 1 that carries an error: pgrep's `-F <not a pidfile>` prints
"pidfile not valid" and exits 1, and pidof exits 1 for any error. Both read as zero, as the
sentence says. Also not bound: the hook's python raising, which still fails open through the
heredoc's `|| exit 0`.

**Pinned by.** `hooks/tests/test-block-unsafe-kill-matcher-error.py`.

## `mh-every-hook-hands-its-whole-payload-to-its-reader`

**Invariant.** Every python-backed hook in `hooks/` hands its whole payload to its reader whatever
its size, so a call is judged on its content and never passed because the payload could not be
handed over.

**Mechanism.** The payload goes to python on fd 3, `3< <(printf '%s' "$payload" 2>/dev/null)`,
and the program reads it there (`open(3, "rb")`, decoded with `os.fsdecode`, which is how
`os.environ` decoded it before, so a payload with invalid UTF-8 parses as it did). Not the
environment: Linux caps one argv/envp string at `MAX_ARG_STRLEN` (128 KiB), so a bigger call
would make `execve` fail E2BIG and the hook exit 0. Why this route: stdin is taken by the program heredoc (`python3 -I - <<'PY'`), `-c "$prog"` would put
the program under the same 128 KiB cap (the kill guard's program is past it), and a here-string
past the pipe size is written to a temp file, which would add a TMPDIR the hook never needed. The
process substitution's writer is bash's builtin `printf`, which execs nothing and has no size limit.

**Site derivation.** By the check itself, never a list: every top-level `hooks/*.sh` that reads
stdin into a variable (`NAME=$(cat`) and names that variable on a `python3` launch line
(continuations joined). In this kit that is `block-unsafe-kill.sh`. The static row covers
every top-level script: no stdin variable is carried in a command-prefix assignment or an
`export`. `inject-gauges.sh` and `pretool-clock.sh` read stdin but hand python only fields jq took
from it (a model id, a transcript path), never the payload, so they are not in the set.

**Not covered.** `inject-gauges.sh` still passes jq-extracted fields in the environment. A field over 128 KiB
there would fail its (informational) python, which is not a guard. A payload bash cannot hold (memory) is not bounded here.

## `mh-a-hooks-tests-session-child-is-tied-to-its-test`

**Invariant.** Every child a hooks test starts in a session or process group of its own is tied
to the test, so that when a suite runner times a check out and signals its section's process group,
no child of that check outlives it. The one route is `_proc_names.tied()` (or `sleeper()`, built
on it), whose child the kernel SIGKILLs when the test dies (`PR_SET_PDEATHSIG`); a
`bash_oracle.run(...)` / `bash_oracle.argv(...)` argv counts as tied, since its PREFIX starts
`setpriv --pdeathsig KILL` (`mh-a-hooks-tests-oracle-line-dies-with-its-caller`).

**Site derivation (mechanical).** An AST walk of every .py file of hooks/tests and the helper
modules (the walk itself is original only). A call is a session child when it has a keyword
`start_new_session=`, `process_group=`, `setsid=` or `setpgroup=` that is not False/None, or a
`preexec_fn=` that calls (or is) os.setsid/os.setpgrp/os.setpgid; a `start_new_session` key in a
dict display also counts, and so does a spawning call whose argv display starts `setsid`. Such a
call passes when it is `tied(...)`/`sleeper(...)`, `bash_oracle.run(...)`, or has a
`bash_oracle.argv(...)` argv. An exemption is one fixed comment form on a line of the call or the
line just above it, `# untied-session-child: <reason>`.

**Not covered (one-sided).** A child spawned by code held in a string (a python fixture run with
`-c`) is not read. Neither is `os.fork()` followed by `os.setsid()`, nor a wrapper that receives
`start_new_session` in a variable. The tie follows the THREAD that forked.

**Pinned by.** `hooks/tests/test-bash-oracle-line-dies-with-its-caller-cert.py`, `hooks/tests/test-bash-oracle-own-process-group-cert.py`.
