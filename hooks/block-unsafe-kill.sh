#!/usr/bin/env bash
# PreToolUse(Bash) guard — block a process kill or a wait gate that is keyed on a process
# PATTERN or a process NAME, either of which can reach a process that is not yours.
#
# `pkill -f <pat>` and `for p in $(pgrep -f <pat>); do kill "$p"; done` kill the very shell
# running them, because the pattern is present in that shell's own cmdline. Agents are told
# this, remember it, and do it anyway — repeatedly, including with the "safe" bracket trick
# (`foo[-]bar`), which fails whenever the plain string also appears elsewhere in the same
# command. A structural guard, not a reminder.
#
# Blocks: pkill -f · killall · (pgrep -f … + kill) in one command ·
#         a wait gate (until/while) on ANY pgrep · a kill by exact NAME that would reach more
#         than one process on this host · any lister beside a kill a run-time guard cannot see
#         (sh -c, ssh, sudo, env -i, a path, an interpreter; unseen_route()) · a selection with
#         NO pattern (an owner or other filter alone: `pkill -u "$USER"`, `kill $(pgrep -U $UID)`)
#         that would reach more than one process · pkill/pgrep-into-a-kill whose only criterion
#         is -n/-o (the host's newest/oldest) · a kill of PID -1 (the whole account) or PID 0
#         (this shell's process group), and `kill -1` alone · a ps listing by owner, every
#         process or no selection into a kill. pkill/pgrep long options are read in every
#         abbreviation procps accepts (`--eu`).
# Allows: kill by PID (not -1 or 0) · kill -0 and kill -l (as both kills read them) · a safe
#         helper of your own (a function that filters out its own ancestry) · pgrep on its own ·
#         a kill by exact NAME, or a selection by filters alone, that resolves to at most one
#         process · a pattern-less kill of a process tree whose -P/-s/-g root is a run-time value
#         (KINSHIP_OPTS).
#
# Only real SHELL CODE is inspected, so a commit message or a docstring that merely MENTIONS these
# commands is not blocked; a guard that fires on prose is a guard people learn to override.
#
# HOW IT READS A COMMAND. Quotes are masked by the shared bash-aware, length-preserving quote mask
# (hooks/quote_mask.py), never by regexes: a naive strip reads the apostrophe in "it's fine" as an
# opening quote and eats everything up to the next quote, `pkill -f`'s own argument included. The
# command is then PARSED (hooks/bash_parse.py) into simple commands:
#   - the mask runs with live=True, so a substitution inside "…" stays in place as the code it is,
#     and with a non-space fill, so a quoted argument stays a WORD whose raw text can be read back
#     at the same offset; a data heredoc body is blanked length-preserving;
#   - each simple command's COMMAND WORD is resolved past wrappers (sudo, timeout, env, nice,
#     xargs, …), redirections and assignments, and by basename, so `/usr/bin/pkill`, `\pkill` and
#     `xargs /bin/kill` are pkill and kill;
#   - pkill/pgrep options are PARSED, arguments included, so -f is found wherever it sits;
#   - EVERY name-keyed kill is counted — pkill without -f, pgrep without -f into a kill, pidof
#     into a kill — at hook time, with the command's own matcher and selection options (`pgrep -x
#     <name>` is the matcher `pkill -x` uses), and refused only when it would reach more than one
#     process, naming each pid and its cmdline: `-x` is exact in the NAME, not in the OWNER;
#   - a loop's CONDITION is the text between its until/while and its `do`, wherever the pgrep or
#     pidof in it sits, and a loop body that breaks on one is a gate too: a gate on a process NAME
#     hangs if the pattern matches the caller, or if an unrelated long-lived service holds the name;
#   - code handed on is code: the argument of `bash|sh -c`, `eval`, `env -S`, a herestring or
#     heredoc fed to a shell, `echo|printf … | bash`, and the string of every program that hands
#     one to a shell (`flock FILE -c`, `su`/`runuser -c`, `watch`, `script -c`, `trap`, tmux's
#     shell-command arguments and send-keys, an `at`/`batch` job, `parallel --`/`:::`, sg/newgrp,
#     `git rebase -x`, submodule foreach, bisect run, filter-branch, `ssh` to THIS host; the table
#     is bash_parse.handed_code());
#   - a program whose SYNOPSIS ends `COMMAND [ARG]...` is a wrapper (bash_parse.WRAPPERS,
#     `docker|podman exec`, moreutils `parallel CMD --`), and find's -exec/-execdir/-ok/-okdir
#     clauses are argv; a lister the outer shell expands INTO such a string (`bash -c "kill
#     $(pgrep -f X)"`) reaches the kill there (handed_to_kill());
#   - a lister's pids fed to GNU parallel on STDIN reach the kill of its command template
#     (bash_parse.parallel_stdin() says where the input lands; parallel_feeds() writes it there);
#   - a safe helper is allowed because it is not a kill this guard matches, not by a substring
#     test that would let the rest of the command through.
#
# STATED LIMITS:
#   - a name held in a shell variable (`pkill -x "$NAME"`) is unresolvable here and passes;
#   - a count of exactly one is allowed, and this guard cannot tell whether that one is yours
#     (except -n/-o with no other criterion, which names nothing and is refused; `pkill -n -u
#     "$USER"` still passes as a count of one);
#   - the count is read at hook time, so a process that starts between the check and the kill is
#     not seen;
#   - a kill TARGET the shell computes when it runs -- `kill -9 $((-1))`, `$[-1]`, `$P`,
#     `${P:--1}`, `$(echo -1)`, backticks, `k=kill; $k -9 -1` -- is not read and passes as a kill
#     by PID does; literal braces and a blank-led quoted number are read (kill_argv(), below);
#   - code a shell assembles at run time (a variable, unless it was assigned a literal string in
#     the same call; a file it sources; a script path it runs) is not seen; a pid read from a
#     file and then killed is a kill by PID;
#   - out of purpose, the processes of ANOTHER host: ssh, mosh and `systemd-run -H` to another
#     host, a remote docker daemon. Not read: a fresh container (`docker run`, systemd-nspawn);
#     bwrap, pasta and perf, whose option grammars the table does not carry; options a parallel
#     profile, ~/.parallel/config or $PARALLEL adds, which the command text lacks.
set -uo pipefail

payload=$(cat)

# NB: the payload goes in on FD 3, not stdin -- `python3 - <<'PY'` makes the heredoc python's
# stdin, which silently discards a piped payload and makes this guard fail OPEN. Nor the
# environment: one envp string is capped at 128 KiB, so a `pkill -f` padded past it would fail
# execve with E2BIG and pass (hooks/tests/INVARIANTS.md
# mh-every-hook-hands-its-whole-payload-to-its-reader).
#
# The MESSAGE is built in python, inside a QUOTED heredoc, not in a bash heredoc downstream: an
# unquoted bash heredoc expands `$!`, `$$` and backticks in the advice itself, so the guidance
# would render as empty strings or as command output.
verdict=$(3< <(printf '%s' "$payload" 2>/dev/null) HOOK_SELF="${BASH_SOURCE[0]}" python3 -I - <<'PY'
import json, os, re, shlex, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.realpath(os.environ.get("HOOK_SELF", ""))))
from quote_mask import mask_quoted, substitutions, heredocs, MaskMismatch

try:
    with open(3, "rb") as fd3:        # the payload, whole, on fd 3 (never the environment)
        cmd = json.loads(os.fsdecode(fd3.read())).get("tool_input", {}).get("command", "")
except Exception:
    sys.exit(0)
if not cmd:
    sys.exit(0)

WAIT_ADVICE = """
If you are WAITING on something, gate on the RESOURCE, not on a process:
  [ "$(free -m | awk '/^Mem:/{print $7}')" -gt 4096 ]   # the resource is free
  [ -f "$done_marker" ]                             # the job said so
  wait "$PID"                                       # you started it, wait for it
  curl -sf localhost:8080/health                    # it is up and answering
A gate on a process NAME or PATTERN hangs two ways, and neither is visible from the command:
your own gate can match the calling shell, and an unrelated long-lived service can hold that
name for as long as the host is up, so `until ! pgrep -x myserver` may never exit at all.
"""

KILL_ADVICE = """
If you are KILLING, in order of preference:
  1. by PID:          SRV=$!   ...   kill "$SRV"
  2. a safe helper: one that resolves the pattern's matches, then filters out $$, $PPID,
     every ancestor, and harness wrapper shells before killing — it solves the SELF-match;
     choosing a pattern narrow enough to reach only your own is still yours
`pkill -x <name>` is exact in the NAME, not in the OWNER: it stops EVERY process with that
name, whoever started it. It is safe only where the name is unique on this host, so count
before you trust it —
      pgrep -x <name> | wc -l
and it is not unique for python3, node, bash or sleep.
"""

# The command reader is hooks/bash_parse.py, shared with other Bash guards.
from bash_parse import (FILL, SHELLS, RESERVED, WRAPPERS, REDIR, SEP, Cmd,  # noqa: F401
                        unresolved, unquote, split_words, resolve, herestrings, shell_code,
                        code_heredocs, join_lines, name_of, parallel_stdin, command_word,
                        handed_script, reads_code_on_stdin, _io_redirs, word_chars, eval_code,
                        command_codes)
from bash_parse import parse as parse_commands

# A PROGRAM THIS CANNOT READ, CARRYING A KILL OR A LISTER AMONG ITS OPERANDS, RUNS IT. The wrapper
# table in bash_parse.py names the programs whose man page runs their operands as a command, and
# a table cannot be complete for that class (`valgrind pkill -f X`, `bwrap --bind / / pkill -f X`,
# `ip netns exec NS pkill -f X`, numactl, ltrace, cgexec, firejail, xvfb-run, pkexec, `kubectl
# exec POD --`). So the rule is structural, not a longer list: a simple command whose own program
# is none of the ones this guard reads, and which carries a word naming a kill or a lister
# (CARRIED) after its command word, is read from that word on, as the wrapper it most likely is --
# which also reads `pgrep -f X | xargs -I{} find /proc/{} -exec kill {} \;` as the pipeline into
# a kill it is. Out: a program whose page reads its operands as DATA (TEXT_TOOLS -- `grep kill
# log`, `echo pkill -f X`, `man pkill` run nothing), a subcommand dispatcher bash_parse.py already
# reads where it runs a command (git, docker/podman: `exec` is read, a fresh `run` is stated out),
# and a command whose prefix sends it to another host (ssh, mosh, `systemd-run -H`, a remote
# docker daemon). Pinned by hooks/tests/test-pattern-keyed-kill-carried-kill.py.
# The words read past to are every kill and lister this guard reads (CARRIED: killall and ps
# included), derived from the names analyse() refuses on. A word from which the rest, read as a
# command, runs CODE is read past to as well (runs_code(): a shell's -c, eval, sudo -s, env -S,
# find -exec sh -c, ..., whatever bash_parse.command_codes() reads at a command's first word), so
# `valgrind -q sh -c 'pkill -f X'` and `kubectl exec POD -- bash -c '...'` have their -c read.
# Pinned by hooks/tests/test-pattern-keyed-kill-code-behind-unlisted-wrapper.py.
KILL_WORDS = {"pkill", "pgrep", "kill"}
CARRIED = KILL_WORDS | {"killall", "pidof", "ps"}
READ_HERE = KILL_WORDS | {"pidof", "ps", "killall", "eval", "parallel", "sem", "xargs"} | SHELLS
REMOTE = {"ssh", "mosh", "autossh", "slogin", "rsh", "dbclient"}
TEXT_TOOLS = {"echo", "printf", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack", "awk",
              "gawk", "mawk", "sed", "cat", "tac", "head", "tail", "sort", "uniq", "wc", "tr",
              "cut", "tee", "less", "more", "most", "man", "info", "whatis", "apropos", "which",
              "whereis", "type", "hash", "help", "alias", "unalias", "compgen", "complete",
              "logger", "notify-send", "jq", "yq", "git", "journalctl", "systemctl", "docker",
              "podman", "tmux", "test", "[", "[[", "true", "false", ":", "export",
              "declare", "typeset", "local", "readonly", "unset", "read", "set", "shift",
              "source", ".", "dpkg", "apt", "apt-get", "apt-cache", "pip", "npm", "file", "stat",
              "ls", "readlink", "realpath", "basename", "dirname", "diff", "cmp", "comm", "join",
              "paste", "column", "fold", "fmt", "nl", "od", "xxd", "hexdump", "strings", "tldr"}


def runs_code(words):
    """(index in words of the command they run, or None; the code strings they run): words read
    as a command, through the wrappers resolve() reads, by the one reading bash_parse.parse()
    gives a command it starts at its first word (command_codes())."""
    idx, codes, _ = resolve(words)
    return idx, codes + (command_codes(words[idx:]) if idx is not None else [])


def carried_kill(words, prefix=()):
    """(index in words of the word a program this cannot read runs, the words from there on as
    their command reads, the code strings that command runs), or None (the block above). The word
    is a kill or lister (CARRIED), or any word from which the rest, read as a command, runs code
    (`valgrind sh -c '...'`, `kubectl exec POD -- bash -c '...'`, `xvfb-run sudo -s '...'`).
    prefix is what precedes words in their segment, asked with them whether the command goes to
    another host."""
    if not words or command_word(words[0][0])[0] in READ_HERE | TEXT_TOOLS:
        return None
    for k in range(1, len(words)):
        raw = words[k][0]
        if REDIR.match(raw):
            continue
        if command_word(raw)[0] in CARRIED:
            got = (words[k:], [])
        else:
            idx, codes = runs_code(words[k:])
            if not codes:
                continue
            got = (words[k:][idx:] if idx is not None else [], codes)
        before = list(prefix) + list(words[:k])
        if any(command_word(r)[0] in REMOTE for r, _ in before):
            return None
        if resolve(before + [("true", "true")])[0] is None:
            return None                        # another host's daemon, or code it hands on
        return (k,) + got
    return None


def parse(text):
    """bash_parse.parse, with each simple command read past a program carrying a kill word, or a
    command that runs code, from that word on."""
    items = parse_commands(text)
    for c in items:
        c.carrier = None                       # the program read past, when one was (unseen_route)
        got = carried_kill(c.words, c.seg_words[:len(c.seg_words) - len(c.words)])
        if got:
            c.carrier = c.name
            c.words = got[1]
            c.name = name_of(c.words)
            c.codes += [code for code in got[2] if code not in c.codes]
    return items

# pkill / pgrep: options that take an ARGUMENT, and those passed to the counting pgrep.
PG_ARG_SHORT = set("dgGPstuUFqrO")
PG_ARG_LONG = {"--delimiter", "--pgroup", "--group", "--parent", "--session", "--terminal",
               "--euid", "--uid", "--pidfile", "--signal", "--queue", "--runstates", "--ns",
               "--nslist", "--cgroup", "--older", "--env"}
PG_COUNT_SHORT = set("xinovAgGPstuUFrO")
PG_COUNT_LONG = {"--exact", "--ignore-case", "--newest", "--oldest", "--inverse",
                 "--ignore-ancestors", "--pgroup", "--group", "--parent", "--session",
                 "--terminal", "--euid", "--uid", "--pidfile", "--runstates", "--ns", "--nslist",
                 "--cgroup", "--older", "--env"}

# A LONG OPTION IS READ AS PROCPS'S GETOPT READS IT. pgrep and pkill (one program, pgrep.c, one
# getopt_long table) take any exact name or UNIQUE PREFIX of a long option: `--eu` is --euid,
# `--ui` is --uid, `--fu` is --full, so `pkill --eu "$USER"` is a whole-account kill and `pkill
# --fu srv` a pattern kill. PG_LONG_ALL is the table procps-ng carries -- not a hand list: the
# check derives it from /usr/bin/pgrep (its --help and the possibilities getopt prints for each
# ambiguous one-letter prefix) and fails when this set differs, and it asks the real pgrep how
# every prefix of every name reads. An ambiguous or unknown prefix is left as written: procps
# refuses it, exit 2. Pinned by hooks/tests/test-block-unsafe-kill-whole-account.py, rows P and U.
PG_LONG_ALL = {"--cgroup", "--count", "--delimiter", "--echo", "--euid", "--exact", "--full",
               "--group", "--help", "--ignore-ancestors", "--ignore-case", "--inverse",
               "--lightweight", "--list-full", "--list-name", "--logpidfile", "--newest", "--ns",
               "--nslist", "--older", "--oldest", "--parent", "--pgroup", "--pidfile", "--queue",
               "--require-handler", "--runstates", "--session", "--signal", "--terminal",
               "--uid", "--version"}


def pg_long(name):
    """The pgrep/pkill long option name (no `=`) is, by getopt_long: itself when exact, else the
    one option it is a prefix of; as written when it is a prefix of none or several."""
    if name in PG_LONG_ALL:
        return name
    hits = [o for o in PG_LONG_ALL if o.startswith(name)]
    return hits[0] if len(hits) == 1 else name

# PKILL'S SIGNAL WORD IS WHAT PKILL READS AS ONE, so `-U USER`, `-G GID`, `-P PPID` and `-F FILE`
# keep their option (a capital letter after `-` is not a signal) and `pkill -term NAME` is a
# signal to pkill, not `-t erm`. procps-ng removes, before its option parse, the FIRST argument
# `-WORD` whose WORD names a signal: case-blind, with or without SIG, the aliases CLD IO IOT,
# RTMIN and RTMIN+n, EXIT and NULL, or a number 0-93 (`-94` and `-RTMAX` are options, and errors).
# That grammar was measured of the tool with --signal 0 against a probe's own children, not read
# off its page. pgrep reads no signal word at all. -O (older than) reaches the count with its
# value, as every other selection option of pkill(1) does.
# Pinned by hooks/tests/test-name-kill-uid-gid-filters.py.
SIGNAL_NAMES = {"HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1",
                "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP",
                "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "POLL",
                "PWR", "SYS", "CLD", "IO", "IOT", "RTMIN", "EXIT", "NULL"}


def pkill_signal_word(v):
    """True iff pkill reads the argument v as its signal (the block above)."""
    if not v.startswith("-"):
        return False
    s = v[1:].upper()
    if s.startswith("SIG"):
        s = s[3:]
    if s in SIGNAL_NAMES:
        return True
    if s.startswith("RTMIN+"):
        s = s[6:]
    return bool(re.fullmatch(r"\+?\d+", s)) and int(s) <= 93


# A SELECTION VALUE THE SHELL ONLY KNOWS WHEN IT RUNS -- `pkill -u $(id -u) python3`, `pkill -u
# "$USER" NAME`, `pkill -U $UID NAME`, `kill $(pgrep -u "$(whoami)" NAME)`, `kill $(pidof -o $$
# NAME)` -- is still counted. The owner filter is the idiom a session writes believing it limits
# the kill to its own processes; it does not, every process of that name the account owns is
# stopped. So:
#   - an owner value (-u/-U/--euid/--uid) that SPELLS the session's own user -- $UID, $EUID, $USER,
#     $LOGNAME, braced or double-quoted, or $(id -u), $(id -un), $(whoami) and their backtick forms
#     -- is counted as that user, where the shell that expands it is this session's (the call's
#     own text, not code handed to another shell), nothing in the call assigns the variable and
#     it defines no `id` or `whoami` of its own;
#   - any other unresolved selection value is counted WITHOUT its option: dropping a filter only
#     widens what pgrep selects, so the count is an upper bound, the refusing direction (so for
#     --nslist too: `--ns PID` alone selects at least what `--ns PID --nslist user` does).
#     Under --inverse a dropped filter widens to every process;
#   - pidof's `-o PID` is read the same way, and its `-d SEP` (an output separator, which would
#     make the count read no pid at all) is not passed to the count.
# A refusal on a count taken without a filter says so, naming the option.
# Pinned by hooks/tests/test-name-kill-filter-held-in-an-expansion-cert.py.
OWNER_OPTS = {"-u", "-U", "--euid", "--uid"}
OWN_VARS = {"UID", "EUID", "USER", "LOGNAME"}


# A SELECTION WITH NO PATTERN IS COUNTED LIKE ANY OTHER. `pkill -u "$USER"`, `pkill -U $UID`,
# `pkill --euid=$(id -u)`, `kill $(pgrep -u "$USER")` and `pgrep -u alice | xargs kill` each
# select EVERY process of the account, every other agent session and background job of that user
# included, and are the one-line command that stops them all. pkill and pgrep select by their
# filters alone when no pattern is given (`pgrep -u UID`, `-n`, `-o`, `-r S` and `-O 1` answer;
# `-v`, `-i`, `-A` and `-x` alone are "no matching criteria", exit 2). So a pattern-less selection
# is counted with its filters and the pattern `.` (every name; -x is dropped, since it is exact in
# a pattern there is none of), by the same matcher, the same owner reading and the same
# dropped-filter widening as a name kill, and refused when it reaches more than one process. A
# command with no criterion at all is pkill's own usage error and selects nothing. AN OWNER FILTER
# NAMING ANOTHER USER (`pkill -u root`, `pkill -u postgres`) is counted the same: for a non-root
# sender the kernel refuses each signal (EPERM), so the refusal there is of a command that would
# stop nothing, but the guard does not discount it, because the same text under sudo or as root
# reaches every one of them, and a refused no-op costs a rewrite.
# Pinned by hooks/tests/test-block-unsafe-kill-owner-only.py.
NOT_A_CRITERION = {"-v", "--inverse", "-i", "--ignore-case", "-A", "--ignore-ancestors"}

# -n / -o WITH NO OTHER CRITERION IS REFUSED, NOT COUNTED. Counted, `pkill -n` is `pgrep -n .`,
# which always answers ONE process and would pass under "a count of exactly one is allowed". But
# that one is the newest (or oldest) process on the whole HOST, whoever owns it: usually this
# command's own shell or pipeline, else another session's or user's latest process, and with -o
# the oldest the sender may signal. It names nothing the writer chose, so a count of one says
# nothing about whose it is. Such a selection (only -n/-o, beside NOT_A_CRITERION flags and the
# dropped -x, no filter dropped as unresolved) is refused before any count. With a pattern
# (`pkill -n NAME`) or a filter (`pkill -n -P $$`, `pkill -n -u "$USER"`) it is read as before.
NEWEST_OLDEST = {"-n", "--newest", "-o", "--oldest"}
# -n/-o BESIDE A HOST-WIDE FILTER ALONE IS REFUSED THE SAME WAY. --ns of one's own pid is every
# process in the host's namespaces, so `pkill -n --ns $$` picks the host's newest as surely as
# `pkill -n` alone. The same holds for each filter that selects by a property every process
# shares with the host rather than by name, owner, kinship or pidfile: --ns (and its --nslist),
# -t/--terminal, --cgroup, -r/--runstates and -O/--older. A selection whose only criteria are
# -n/-o and these (literal or dropped as unresolved) is refused before any count. Not a hand
# list: the check derives the set from `pgrep --help` (every option taking a value whose
# description matches or selects, less the kinship and owner ones, and the one that modifies
# --ns). Not covered: -n/-o beside an owner filter (`pkill -n -u "$USER"`, `-G GID`), a kinship
# filter or a pidfile, each read as a selection of one.
NEWEST_WIDE = {"--ns", "--nslist", "-t", "--terminal", "--cgroup", "-r", "--runstates", "-O",
               "--older"}


def newest_alone(argv, dropped):
    """Whether pgrep argv (options, then the name `.`) selects by -n/-o and, beside them, only by
    host-wide filters and flags that are no criterion (the blocks above)."""
    opts, i = [], 0
    while i < len(argv) - 1:
        o = argv[i]
        opts.append(o)
        i += 2 if o in PG_ARG_LONG or (len(o) == 2 and o[1] in PG_ARG_SHORT) else 1
    return argv[-1] == "." and any(o in NEWEST_OLDEST for o in opts) and \
        all(o in NOT_A_CRITERION | NEWEST_OLDEST | NEWEST_WIDE for o in opts) and \
        set(dropped) <= NEWEST_WIDE

# A PATTERN-LESS KILL OF A PROCESS TREE WHOSE ROOT IS A RUN-TIME VALUE IS NOT COUNTED AS THE HOST.
# With the dropped-filter widening, `pkill -P $P`, `pkill -P $!`, `pkill -KILL -s $P`, `kill
# $(pgrep -P $$)` and `trap 'pkill -P $$' EXIT` would count as `pgrep .` -- every process on the
# host -- and be refused with /sbin/init and kernel threads in the list, though the kill reaches
# only P's children, session or group: the ordinary way an agent stops a sweep, server or
# background job of its own. So a selection with NO pattern whose every dropped filter is a
# kinship filter (the names below: parent, session, process group) and which is not inverted is
# not counted: the guard cannot name the children of a value only the shell knows, and a count of
# the whole host names processes the kill does not reach. Stated limit: the guard does not read
# what the value names, so `pkill -P $X` with X=1 passes as `pkill -P 1` would not. Owner filters
# are unchanged (an unresolved one is still dropped and the count widened), a literal kinship
# value is still counted with its value, and a NAME kill with a dropped kinship filter is still
# counted without it (`mh-a-name-kill-filter-held-in-an-expansion-is-counted`). Under -v a
# dropped filter is still every process. Pinned by
# hooks/tests/test-block-unsafe-kill-kinship-runtime-value.py.
KINSHIP_OPTS = {"-P", "--parent", "-s", "--session", "-g", "--pgroup"}


def own_user(raw, text):
    """The session's own user, as pkill reads it, if raw spells it and text (the call) neither
    assigns the variable it reads nor defines the id/whoami it runs; else None (the block above)."""
    s = raw[1:-1] if len(raw) > 1 and raw[0] == raw[-1] == '"' else raw
    m = re.fullmatch(r"\$(?:\{(\w+)\}|(\w+))", s)
    if m:
        var = m.group(1) or m.group(2)
        if var not in OWN_VARS or re.search(r"(?<![\w$])(?<!\$\{)%s\b" % var, text):
            return None
        return str(os.geteuid() if var == "EUID" else os.getuid()) if "UID" in var else \
            __import__("pwd").getpwuid(os.getuid()).pw_name
    m = re.fullmatch(r"\$\((.*)\)|`(.*)`", s, re.S)
    if not m:
        return None
    try:
        argv = shlex.split(m.group(1) if m.group(1) is not None else m.group(2))
    except ValueError:
        return None
    if not argv or os.path.basename(argv[0]) not in ("id", "whoami"):
        return None
    if re.search(r"(?<![\w-])(?:function\s+)?%s\s*\(\s*\)|function\s+%s\b"
                 % ((re.escape(argv[0]),) * 2), text):
        return None                            # the call defines its own id or whoami
    if os.path.basename(argv[0]) == "whoami":
        return __import__("pwd").getpwuid(os.geteuid()).pw_name if len(argv) == 1 else None
    flags = set()
    for a in argv[1:]:
        if a in ("--user", "--name", "--real"):
            flags.add(a[2])
        elif re.fullmatch(r"-[unr]+", a):
            flags.update(a[1:])
        else:
            return None                        # an operand (another user) or another option
    if "u" not in flags:
        return None
    return str(os.getuid()) if "n" not in flags else __import__("pwd").getpwuid(os.getuid()).pw_name


def pg_options(words, own=None, dropped=None):
    """Parse pkill/pgrep/pidof argv: (full, exact, count_argv or None if unresolvable, pattern).
    own is the call's text where its shell is this session's (owner values that spell the session's
    user are counted as it), else None; an unresolved selection value is left out of count_argv
    and its option appended to dropped (the block above)."""
    full = exact = inverse = False
    count, pattern, gone = [], None, []
    if name_of(words) == "pkill":
        sig = next((k for k in range(1, len(words)) if not REDIR.match(words[k][0])
                    and pkill_signal_word(words[k][1])), None)
        if sig is not None:
            words = words[:sig] + words[sig + 1:]

    def valued(opt, arg_raw, arg):
        if not unresolved(arg_raw):
            return [opt, arg]
        who = own_user(arg_raw, own) if own is not None and opt in OWNER_OPTS else None
        if who is None:
            gone.append(opt)
            return []
        return [opt, who]
    i = 1
    while i < len(words):
        raw, v = words[i]
        if REDIR.match(raw):
            i += 1 if REDIR.match(raw).group(2) else 2; continue
        if v == "--":
            if i + 1 < len(words):
                pattern = words[i + 1]
            break
        if v.startswith("--"):
            name, eq, arg = v.partition("=")
            name = pg_long(name)                   # an abbreviation, as procps reads it
            takes = name in PG_ARG_LONG
            if not eq and takes and i + 1 < len(words):
                arg_raw = words[i + 1][0]; arg = words[i + 1][1]; i += 1
            else:
                arg_raw = raw.partition("=")[2] if eq else arg
            if name == "--full":
                full = True
            if name == "--exact":
                exact = True
            if name == "--inverse":
                inverse = True
            if name in PG_COUNT_LONG:
                count += valued(name, arg_raw, arg) if takes else [name]
            i += 1; continue
        if v.startswith("-") and len(v) > 1:
            j = 1
            while j < len(v):
                ch = v[j]
                if ch == "f":
                    full = True
                if ch == "x":
                    exact = True
                if ch == "v":
                    inverse = True
                if ch in PG_ARG_SHORT:
                    arg = v[j + 1:]
                    arg_raw = arg
                    if not arg and i + 1 < len(words):
                        arg_raw, arg = words[i + 1]; i += 1
                    if ch in PG_COUNT_SHORT:
                        count += valued("-" + ch, arg_raw, arg)
                    break
                if ch in PG_COUNT_SHORT:
                    count.append("-" + ch)
                j += 1
            i += 1; continue
        if pattern is None:
            pattern = words[i]
        i += 1
    if pattern is None:                        # a selection with no pattern (the block above)
        count = [o for o in count if o not in ("-x", "--exact")]
        if not gone and all(o in NOT_A_CRITERION for o in count):
            return full, exact, None, pattern  # no criterion at all: pkill's own usage error
        if gone and not inverse and set(gone) <= KINSHIP_OPTS:
            return full, exact, None, pattern  # a run-time tree root, not the host (KINSHIP_OPTS)
        name = "."                             # every name: the selection is the filters alone
    elif unresolved(pattern[0]):
        return full, exact, None, pattern
    else:
        name = pattern[1]
    if gone:
        if dropped is not None:
            dropped += gone
        if inverse:                            # NOT(a AND b) with b unknown: every process
            return full, exact, ["-v", "^$"], pattern
    return full, exact, count + [name], pattern


# A MATCHER THAT DOES NOT ANSWER HAS SELECTED NOTHING ONLY WHEN IT SAYS SO. live_count() reads the
# matcher's exit status, not only its stdout: `pkill --env FOO=1 NAME` (a procps that rejects
# --env exits 2, though the tables above carry it), `-u nosuchuser` (exit 2), a pgrep that hangs
# or is not on PATH must not read as "fewer than two" and let the kill pass uncounted. pgrep exits
# 0 (selected), 1 (none), 2 (usage) and 3 (fatal); pidof 0 and 1. An exit status above 1 is no
# answer: the count is taken again with the options the matcher named as rejected left out, and
# failing that, with every narrowing option left out (the pattern or names kept, and
# -i/--ignore-case, pidof's -x and -z, which widen): leaving a filter out only widens, so the
# count is still the most the kill can reach, and under -v/--inverse it is every process (as
# pg_options() reads a dropped filter). A matcher that times out, does not start, or still answers
# nothing raises Uncounted, and the kill is refused saying the count could not be taken. Exit 1
# still reads as zero, and so does a pgrep error that names the PATTERN or a VALUE it validated
# (VALUE_ERROR: "regex error", "invalid user name", "not a number", ... -- pgrep's own strings):
# pkill parses both with the same code and exits on them, so the kill selects nothing either way.
# `find -exec grep -l pkill {} +` (read as `pkill {}`) and `pkill -u '$USER' NAME` (a literal, no
# such user) stay silent. Pinned by hooks/tests/test-block-unsafe-kill-matcher-error.py.
REJECTED_OPT = re.compile(r"(?:unrecognized|unknown|ambiguous) option '(--[^'=\s]+)"
                          r"|option '(--[^'=\s]+)' (?:requires|doesn't allow) an argument"
                          r"|(?:invalid|unknown) option -- '?(\w)'?"
                          r"|option requires an argument -- '?(\w)'?")
VALUE_ERROR = re.compile(r"\S*pgrep: (?:regex error|invalid (?:session id|process group|user name|"
                         r"group name)|not a number)")
MATCHER_TIMEOUT = 5


class Uncounted(Exception):
    """The command's own matcher gave no count (the block above)."""


def run_matcher(argv):
    """(pids, None) when argv answers (exit 0 or 1), (None, (why, stderr, retry)) when it does not."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=MATCHER_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, ("timed out after %d s" % MATCHER_TIMEOUT, "", False)
    except Exception as e:
        return None, ("did not start (%s)" % (getattr(e, "strerror", None) or type(e).__name__),
                      "", False)
    if r.returncode not in (0, 1) and os.path.basename(argv[0]) == "pgrep" \
            and VALUE_ERROR.match(r.stderr):
        return [], None                         # the pattern or a value: pkill reads it the same
    if r.returncode not in (0, 1):
        first = next((l.strip() for l in r.stderr.splitlines() if l.strip()), "")
        return None, ("exited %d%s" % (r.returncode, ": " + first[:120] if first else ""),
                      r.stderr, True)
    return [p for p in r.stdout.split() if p.isdigit()], None


def matcher_opts(argv):
    """[(index, option, takes_value)] of a count argv (pgrep or pidof, as pg_options() and
    pidof_argv() build it: one option per word, a value in the next word)."""
    pidof = os.path.basename(argv[0]) == "pidof"
    out, i = [], 1
    last = len(argv) if pidof else len(argv) - 1     # pgrep's pattern is the last word
    while i < last:
        a = argv[i]
        if not a.startswith("-") or a == "-":
            i += 1; continue
        takes = (a == "-o") if pidof else (a in PG_ARG_LONG or (len(a) == 2 and a[1] in PG_ARG_SHORT))
        out.append((i, a, takes))
        i += 2 if takes else 1
    return out


WIDENING = {"-i", "--ignore-case"}
PIDOF_WIDENING = {"-x", "-z"}


def leave_out(argv, names):
    """argv with the options in names (and their values) left out; under -v/--inverse, a count of
    every process (the block above)."""
    opts = matcher_opts(argv)
    gone = set()
    for i, a, takes in opts:
        if a in names:
            gone.add(i)
            if takes:
                gone.add(i + 1)
    if not gone:
        return None
    if os.path.basename(argv[0]) != "pidof" and any(a in ("-v", "--inverse") for _, a, _ in opts):
        return [argv[0], "-v", "^$"]
    return [a for k, a in enumerate(argv) if k not in gone]


def live_count(argv, rejected=None):
    """The processes argv (pgrep/pidof, the command's own matcher) selects now, if more than one.
    A matcher that does not answer is asked again without what it rejected, and each option left
    out is appended to rejected; Uncounted when no count can be taken (the block above)."""
    tried = set()
    while True:
        tried.add(tuple(argv))
        pids, err = run_matcher(argv)
        if err is None:
            break
        why, stderr, retry = err
        if not retry:
            raise Uncounted("`%s` %s" % (" ".join(argv), why))
        named = {a or b or ("-" + c if c else "") or ("-" + d if d else "")
                 for a, b, c, d in REJECTED_OPT.findall(stderr)}
        nxt = leave_out(argv, named)
        if nxt is None or tuple(nxt) in tried:  # nothing named, or naming it changed nothing
            keep = WIDENING if os.path.basename(argv[0]) != "pidof" else PIDOF_WIDENING
            named = {a for _, a, _ in matcher_opts(argv) if a not in keep}
            nxt = leave_out(argv, named)
        if nxt is None or tuple(nxt) in tried:
            raise Uncounted("`%s` %s" % (" ".join(argv), why))
        if rejected is not None:
            rejected += [a for _, a, _ in matcher_opts(argv) if a in named]
        argv = nxt
    if len(pids) < 2:
        return None
    rows = []
    for p in pids[:8]:
        try:
            with open("/proc/%s/cmdline" % p, "rb") as fh:
                line = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except Exception:
            line = "(gone)"
        rows.append("  pid %-8s %s" % (p, line[:110]))
    if len(pids) > 8:
        rows.append("  ... and %d more" % (len(pids) - 8))
    return len(pids), "\n".join(rows)


def spelled(c):
    return " ".join(w[1] for w in c.words)


def without(dropped, rejected=()):
    """The clause a refusal adds when its count was taken without filters (pg_options(), and
    live_count() for options the matcher rejected)."""
    out = ""
    if dropped:
        out += (" (counted without %s, whose value is only known when the shell runs it: the count "
                "is the most the kill can reach)" % ", ".join(dict.fromkeys(dropped)))
    if rejected:
        out += (" (counted without %s, which the matcher on this host would not run with: the "
                "count is the most the kill can reach)" % ", ".join(dict.fromkeys(rejected)))
    return out


def uncounted(c, e):
    """The refusal of a name kill whose count could not be taken (live_count()'s block)."""
    return (("`%s` is a kill keyed on a process NAME and the count of what it reaches could not "
             "be taken: %s — a kill the guard cannot count is not let through as one that reaches "
             "nothing" % (spelled(c), e)), KILL_ADVICE, None)


def shared_name(c, verb, own=None):
    dropped, rejected = [], []
    _, _, argv, pattern = pg_options(c.words, own, dropped)
    if argv is None:
        return None
    if pattern is None and newest_alone(argv, dropped):
        return (("`%s` names no process: -n/-o with no other criterion (or only a host-wide "
                 "filter: --ns, -t, --cgroup, -r, -O) selects the newest or oldest process on the "
                 "whole host, whoever owns it -- usually this command's own shell -- so a count of "
                 "one says nothing about whose it is" % spelled(c)), KILL_ADVICE, None)
    try:
        hit = live_count(["pidof"] + argv if verb == "pidof" else ["pgrep"] + argv, rejected)
    except Uncounted as e:
        return uncounted(c, e)
    if not hit:
        return None
    n, rows = hit
    if pattern is None:                        # a selection by its filters alone (NOT_A_CRITERION)
        return (("`%s` names no process: it selects by its filters alone, every process they "
                 "match whatever its name, and reaches %d on this host, not one — an owner filter "
                 "is every process of that user, this session's siblings and any background job "
                 "included%s" % (spelled(c), n, without(dropped, rejected))),
                KILL_ADVICE, "The processes it would stop right now:\n" + rows)
    return (("`%s` reaches %d processes on this host, not one — a process NAME is not an owner, "
             "and `-x` is exact in the NAME, not in the OWNER%s" % (spelled(c), n,
                                                                  without(dropped, rejected))),
            KILL_ADVICE, "The processes it would stop right now:\n" + rows)


def pidof_argv(c, dropped=None):
    """pidof's argv for the count: an unresolved `-o` value is left out (the count is the upper
    bound) and appended to dropped, `-d SEP` is not passed (the count reads pids by whitespace),
    and a NAME that is an expansion makes it None (the stated limit) (pg_options()'s block)."""
    argv, names, w, i = [], 0, c.words, 1
    while i < len(w):
        raw, v = w[i]
        if REDIR.match(raw):
            break
        if v.startswith("-") and len(v) > 1:
            j = 1
            while j < len(v):
                ch = v[j]
                if ch in "od":
                    arg = v[j + 1:]
                    if not arg and i + 1 < len(w):
                        arg = w[i + 1][1]; i += 1
                    if ch == "o" and not unresolved(arg):
                        argv += ["-o", arg]
                    elif ch == "o" and dropped is not None:
                        dropped.append("-o")
                    break
                argv.append("-" + ch)
                j += 1
            i += 1; continue
        if unresolved(raw):
            return None
        argv.append(v); names += 1
        i += 1
    return argv if names else None


def gate_reason(loop):
    cond = [c for c in loop["cond"] if c.name in ("pgrep", "pidof")]
    body = [c for c in loop["body"] if c.name in ("pgrep", "pidof")]
    if any(c.name == "pgrep" and pg_options(c.words)[0] for c in cond + body):
        # The NON-destructive half of the same bug: `until ... pgrep -f <pat>` never exits when
        # <pat> appears in the caller's own cmdline -- the loop waits on itself.
        return ("pgrep -f inside an until/while gate (the pattern matches THIS shell, "
                "so the wait never exits)", WAIT_ADVICE, None)
    breaks = any(c.name in ("break", "exit", "return") for c in loop["body"])
    if cond or (body and breaks):
        # The same gate keyed on a NAME rather than a pattern: it does not match the caller, and
        # it hangs anyway when the name is shared.
        return ("a %s wait gate keyed on a process NAME (a name this host shares between "
                "services makes the gate true for ever)" % (cond or body)[0].name,
                WAIT_ADVICE, None)
    return None


# A LISTER'S PIDS MUST REACH THE KILL. A pgrep or pidof is not counted merely because a kill
# appears somewhere in the command: `pgrep -a NAME; kill "$SRV"` -- list, then kill by the PID you
# captured, this file's own advice 1 -- is a kill by PID. The pids reach a kill when the lister
#   - is in the kill's own pipeline, before it (`pgrep X | xargs kill`), or feeds a `read`
#     there whose variable the kill expands (`pgrep X | while read p; do kill $p; done`);
#   - sits in a substitution the kill expands, through any number of commands that pass its
#     output on (`kill $(pgrep X)`, `kill $(echo $(pidof X))`, `kill \`pidof X\``);
#   - sits in a substitution assigned to a variable, or iterated by a `for`, that the kill --
#     or a member of the kill's pipeline before it -- expands, directly or through another
#     assignment or `for` (`P=$(pgrep X); kill $P`, `echo "$P" | xargs kill`);
#   - sits in a process substitution or a herestring, and the command reading it is the kill
#     (`xargs kill <<< "$(pgrep X)"`, `xargs kill < <(pgrep X)`), a `read`/`mapfile` whose
#     own variable the kill expands, or a command passing it on (`kill $(cat <(pgrep X))`);
#   - sits in arithmetic whose value is a word of the kill (`kill $(( $(pgrep X) ))`) or is
#     assigned to a variable the kill expands (`(( p = $(pgrep X) ))`, `p=$(( ... ))`);
#   - is in, or is the substitution of, a command whose pipeline runs on into the kill
#     (`echo $(pgrep X) | xargs kill`).
# WHERE A LISTER SITS IS READ FROM THE SCANNER'S SUBSTITUTION SPANS, not from the character before
# its pipeline, so a lister after `$(<NL>`, after a `;` inside the substitution or after an earlier
# `$(cat f)` in the same word is found, and an array literal `v=( ... $(pgrep X) ... )` binds v.
# A herestring `<<< "$(pgrep X)"` or process substitution is read by its host like any other word:
# a kill is reached, a `read` binds only its own variables (or a compound's reads, for `done
# <<<`), a command passing it on is climbed out of; an arithmetic span is followed to what its
# value reaches (a word of its host for `$((...))`, the variables it assigns, nothing else); and a
# substitution whose host is no command this can read COUNTS the lister.
# THROUGH EVERY BINDING SITE BASH HAS. The pids are followed wherever bash puts them:
#   - out of a compound command (a `{ }` group, a `( )` subshell, a loop, an if, a case): what
#     its commands write is what it writes, so its own pipeline is the lister's (compounds());
#   - into an output process substitution `>(...)`, from the lister or a `tee` after it;
#   - into every builtin that binds a name: `printf -v`, `set` (the positional parameters, read
#     back by any of $@ "$*" $1 ${2}), a function call (its arguments), `${P:=...}`, `eval`
#     (read again with the eval spelled as its code, since it runs in this shell), a bare
#     `for p;`, and a compound's `read`s from `done <<< "$P"`;
#   - into `sh -c CODE NAME ARGS` and `xargs [-I R] sh -c CODE`, whose CODE is asked where its
#     arguments or R go (synthetic_feeds());
#   - on through any command that expands a bound name and writes it on (`kill $(echo $P)`), and
#     through a bound name as through the lister itself (`P=$(pgrep X); f $P` where f kills $1,
#     `sh -c 'kill "$@"' _ $P`, `set -- $P`, `read Q <<< "$P"`: through_words());
#   - code a call hands to `eval` or a shell through a variable assigned a LITERAL string earlier
#     in the call (`X="P=\$(pgrep X)"; eval "$X"`) is read as that string (with_literals());
#   - into GNU parallel's stdin (parallel_feeds()), as xargs' in `sh -c`.
# A BINDING HAS AN ORDER AND A SCOPE (Bound, live(), resets()): a use sees it only after it -- or
# in a later pass of a loop that holds both, or from a function body, which runs when called --
# only inside the subshell, substitution, pipeline member or function (`local`) that made it, and
# not past an assignment, `set`, `printf -v`, `unset` or `for` that bash always runs (standing
# alone, in no compound, substitution or pipeline, not behind `&&`/`||` or `&`), so `P=$(pgrep X);
# P=$SRV; kill $P` kills the pid you started. A call's arguments are the function's own positional
# parameters ("@fn"), not the caller's; `P=$(L) cmd` binds P for nothing but a function or shell
# cmd runs. A use in a function body is asked at each call of the function (calls_of(), holds();
# where a call cannot be placed -- `trap f EXIT`, `xargs f` -- the body sees every binding), a
# `read` bash always runs assigns its names anew (read_targets(); not `-t`, which may assign
# nothing), and pids given to `sh -c CODE` from $N on reach nothing when CODE reads only numbered
# positionals below N and no other route to them (first_positional(), reads_only_below()).
# STATED LIMIT: a pid carried through a file, a named pipe, a coprocess or an fd opened by
# `exec`, or a function's stdin, is not followed; the kill is then a kill by PID.
VAR_REF = re.compile(r"\$\{?[#!]?([A-Za-z_][A-Za-z0-9_]*)")
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^]]*\])?\+?=")
FOR_HEAD = re.compile(r"(?:^|[\s;&|(])(?:for|select)\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;\n]*)")
READERS = ("read", "mapfile", "readarray")


# A positional parameter ($@, "$*", $1, ${2}, ${@:2}; not the count $#): every one reads what `set --`, a
# function call or `sh -c CODE NAME ARGS` bound, so all of them are the one name "@".
POS_REF = re.compile(r"\$\{?!?[@*1-9]")
FOR_BARE = re.compile(r"(?:^|[\s;&|(])for\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:;|\n|\s+do\b)")
FUNC_DEF = re.compile(r"(?:^|[\s;&|(])(?:function\s+([A-Za-z_][\w.:-]*)|([A-Za-z_][\w.:-]*)\s*\(\s*\))")
PARAM_ASSIGN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?=")


def refs(words):
    out = {m.group(1) for raw, _ in words for m in VAR_REF.finditer(raw)}
    if any(POS_REF.search(raw) for raw, _ in words):
        out.add("@")
    return out


def expanded(raw):
    """(names, any): the variables a raw word expands, and whether it expands anything at all
    (a `$` or a backtick), read as bash reads it -- nothing inside '...' or $'...', nothing
    escaped by a backslash."""
    names, anything, i, dq = set(), False, 0, False
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            i += 2; continue
        if not dq and (ch == "'" or raw.startswith("$'", i)):
            j = i + (2 if ch == "$" else 1)
            while j < len(raw) and raw[j] != "'":
                j += 2 if ch == "$" and raw[j] == "\\" else 1
            i = j + 1; continue
        if ch == '"':
            dq = not dq
        elif ch in "$`":
            anything = True
            m = VAR_REF.match(raw, i)
            if m:
                names.add(m.group(1))
        i += 1
    return names, anything


# `$X` or `${X}` alone: the forms whose value is the variable's whole value.
PLAIN_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def parses(code):
    """Whether bash parses code whole (`bash -n`, extglob on so a pattern never counts as an
    error); None when bash could not be asked."""
    try:
        return subprocess.run(["bash", "-O", "extglob", "-n"], input=code, capture_output=True,
                              text=True, timeout=5).returncode == 0
    except Exception:
        return None


def eval_runs(code):
    """The codes to read for what `eval code` runs. bash's eval parses and runs its string a line
    at a time and stops at the first syntax error, so what runs is the longest prefix of whole
    lines that parses: `eval $'P=$(pgrep X)\\n"'` binds P, fails on the open quote, and the call
    goes on to what follows the eval; read whole, that quote would swallow what follows
    (hooks/tests/test-eval-re-read-is-the-code-bash-runs.py). Where bash cannot be asked, every
    whole-line prefix is read, so the guard reads too much rather than too little."""
    cuts = [k for k, ch in enumerate(code) if ch == "\n"]
    ok = parses(code)
    if ok:
        return [code]
    for k in reversed(cuts):
        if ok is None:
            break
        ok = parses(code[:k])
        if ok:
            return [code[:k]]
    if ok is None:
        return [code] + [code[:k] for k in reversed(cuts)]
    return [""]


def heredocs_closed(code):
    """code with each here-document it leaves open closed at its end, as bash's eval closes one at
    the end of its string (`bash -n` only warns of it, so eval_runs() keeps such a code whole). A
    here-document is the one construct bash accepts left open at the end of its input; read where
    the eval's code is spliced into the call, an open one would take the rest of the call for its
    body, and `eval 'P=$(pgrep -f X) <<E'; kill $P` would pass
    (mh-an-eval-is-read-as-the-code-bash-runs). Open is read by the same reader the call is
    (quote_mask.heredocs()): after a final newline, a closed body's terminator line ends before
    the text does and an open one runs to its end."""
    t = code + "\n"
    open_ = [hd["delim"] for hd in heredocs(t) if hd["end"] >= len(t)]
    return code + "".join("\n" + d for d in open_) if open_ else code


def with_literals(code, items, pos):
    """code with every plain `$X` replaced by the literal string X was last assigned before pos
    in this call (`X="P=\\$(pgrep X)"; eval "$X"` hands eval `P=$(pgrep X)`). A value that
    expands anything is no literal and is left as the reference it is."""
    lit = {}
    for x in sorted(items, key=lambda x: x.pos):
        if x.pos >= pos:
            break
        for raw, val in x.seg_words:
            m = ASSIGN.match(raw)
            if m and "+=" not in raw[:m.end()] and "[" not in raw[:m.end()] and "=" in val:
                lit[m.group(1)] = None if expanded(raw[m.end():])[1] else val.split("=", 1)[1]
    def sub(m):
        got = lit.get(m.group(1) or m.group(2))
        return m.group(0) if got is None else got
    return PLAIN_REF.sub(sub, code)


def printf_targets(ops):
    """The names `printf -v NAME` (or `-vNAME`) among a printf's operands assigns."""
    pv = [ops[k + 1] for k, w in enumerate(ops[:-1]) if w == "-v"] + \
         [w[2:] for w in ops if w.startswith("-v") and len(w) > 2]
    return {re.match(r"[A-Za-z_][A-Za-z0-9_]*", w).group(0) for w in pv if re.match(r"[A-Za-z_]", w)}


READ_ARG_OPTS = set("adinNpu")              # read's options that take an argument (-t: see below)


def read_targets(words):
    """The names a `read` with these operands always assigns anew: its NAME operands, or the array
    of `-a NAME`. bash assigns them even at end of input (empty), so the read ends what they held.
    None for `-t`, which with 0 reads nothing and assigns nothing, nor for anything it cannot read."""
    out, k = set(), 0
    while k < len(words):
        raw, w = words[k]
        r = REDIR.match(raw)
        if r:
            k += 1 if r.group(2) else 2; continue
        if w.startswith("-") and len(w) > 1:
            if w == "--":
                k += 1; break
            for j, ch in enumerate(w[1:], 1):
                if ch == "t" or not ch.isalpha():
                    return set()
                if ch in READ_ARG_OPTS:
                    arg = w[j + 1:] or (words[k + 1][1] if k + 1 < len(words) else "")
                    if ch == "a":
                        out.add(arg)
                    k += 0 if w[j + 1:] else 1
                    break
            k += 1; continue
        break
    names = []
    while k < len(words):
        r = REDIR.match(words[k][0])
        if r:                                  # a redirection, and its target when apart
            k += 1 if r.group(2) else 2; continue
        names.append(words[k][1]); k += 1
    out |= set(names) or ({"REPLY"} if not out else set())
    return out if all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", n) for n in out) else set()


# Whether a word bash expands to exactly one argument: nothing outside quotes is expanded, split or
# globbed, and nothing inside "..." is an array or "$@" (both expand to any number of words).
def one_word(raw):
    q, k = None, 0
    while k < len(raw):
        ch = raw[k]
        if q == "'":
            q = None if ch == "'" else q
        elif ch == "\\":
            k += 2; continue
        elif q == '"':
            if ch == '"':
                q = None
            elif raw.startswith(("$@", "${@", "@]"), k):
                return False
        elif ch in "'\"":
            q = ch
        elif ch in "$`*?[{~":
            return False
        k += 1
    return q is None


# A route by which code reads the positional parameters other than as a numbered `$N` / `${N...}`.
POS_OTHER = re.compile(r"\$(?:\{[#!]?)?[@*#]|\$\{!|\b(?:shift|set|getopts|eval|source|for)\b"
                       r"|(?:^|[\s;&|(])\.\s|BASH_ARGV|/proc")
POS_NUM = re.compile(r"\$(?:(\d)|\{(\d+))")


def first_positional(words, code, j):
    """The positional parameter word j of a `sh -c CODE NAME ARGS` argv lands at (NAME is $0), or
    None where that is not certain: every operand after CODE and before j must be one word."""
    k = next((k for k in range(1, len(words)) if words[k][1] == code), None)
    if k is None or j <= k:
        return None
    n = -1
    for raw, _ in words[k + 1:j]:
        if REDIR.match(raw) or not one_word(raw):
            return None
        n += 1
    return n + 1


def reads_only_below(code, m):
    """Whether code reads no positional parameter from $m on: each it expands is a numbered one
    below m, and it reads none of them by any other route ($@, $*, ${!N}, shift, set, a bare
    `for`, getopts, eval, BASH_ARGV)."""
    return not POS_OTHER.search(code) and all(int(a or b) < m for a, b in POS_NUM.findall(code))


DECLARERS = ("declare", "typeset", "export", "readonly", "local")


class Bound(dict):
    """The names a lister's pids are bound to, each with the set of its bindings: (offset, scope).
    The binder sets `at` to where bash makes the binding and `where` to the command that makes it;
    the scope is the span of the shell the binding lives in (a subshell, a substitution, a function
    for `local`), or None for the whole call, and is read off `where` unless the binder names it.
    A use sees a binding only from inside its scope, after it in the order bash runs them, and
    before any reassignment of the name that bash always runs (live() in feeds_kill)."""
    at = where = -1
    scope_of = staticmethod(lambda where, local: None)

    def add(self, n, local=False, scope=False):
        sc = self.scope_of(self.where, local) if scope is False else scope
        self[n] = self.get(n, frozenset()) | {(self.at, sc)}

    def update(self, ns, **kw):
        for n in ns:
            self.add(n, **kw)


def reader_vars(c):
    return {v for raw, v in c.words[1:] if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", v)}


def enclosing(pos, subs):
    """The innermost span (a substitution or an arithmetic `((...))`) whose body holds offset
    pos, or None at the top level."""
    inner = [s for s in subs if s["body"][0] <= pos <= s["body"][1]]
    return max(inner, key=lambda s: s["body"][0]) if inner else None


def held(v, subs):
    """v with every `${...}`, `$[...]` and arithmetic `$((...))` FILL, read level by level as
    bash_parse.word_chars() reads a segment: at the top level and in each command or process
    substitution's body, with the substitutions nested in it filled first, so an expansion is
    one run of word characters at its own level while a substitution inside it keeps its own
    separators for the scans that read that body. Every scan here that ends a pipeline, a
    substitution's host or a command at a separator reads this view, never v: read over v, the
    `|` of `pgrep -f X ${y:-|}; kill 1` would be a pipe into the kill (where bash's pgrep prints to
    the terminal), and `P=$(pgrep -f X); P=x${y:-;} | true; kill $P` would read the piped
    assignment as one that ends what P held (where bash's kill gets the pids).
    Pinned by hooks/tests/test-unsafe-kill-sep-scan-holds-expansions-whole.py."""
    levels = [(0, len(v))] + [(s["body"][0], s["body"][1]) for s in subs
                              if s["kind"] in ("cmd", "proc")]
    out = list(v)
    for a, b in levels:
        seg = list(v[a:b])
        for s in subs:
            if s["kind"] in ("cmd", "proc") and a <= s["open"] and s["body"][1] < b:
                seg[s["open"] - a:s["body"][1] + 1 - a] = FILL * (s["body"][1] + 1 - s["open"])
        seg = "".join(seg)
        for k, ch in enumerate(word_chars(seg)):
            if ch != seg[k]:
                out[a + k] = FILL
    return "".join(out)


def opening(sub):
    """The offset a span opens its word at: a `$((` expansion at its `$` (the arith record's
    "dollar", quote_mask.substitutions()), every other span at its "open". Never t0[open - 1]:
    in a backtick body the `$` may be written a de-escaped `\\\\<NL>` before the `((`, and
    x=`kill $\\\\<NL>(( $(pgrep -f X) ))` would read as an arithmetic command, a status and no
    word of the kill (hooks/tests/INVARIANTS.md
    `mh-an-arithmetic-expansion-is-known-by-its-record`)."""
    return sub["dollar"] if sub.get("dollar") is not None else sub["open"]


def extent(sub):
    """(first, last) offset of the span sub as a word holds it: from opening() through its closing
    character, an arithmetic's second `)` included. (open, body end) would leave an arithmetic's
    `$` and last `)` outside it; where held() does not fill the expansion (a written `\\$((` in a
    backtick body), that `)` would end the pipeline, and x=`echo \\$(( \\$(pgrep -f X) )) | xargs
    kill` would pass (hooks/tests/INVARIANTS.md
    `mh-an-arithmetic-expansion-is-known-by-its-record`)."""
    return opening(sub), sub["body"][1] + (sub["kind"] == "arith")


def subst_host(sub, v, t0, subs):
    """(kind, host words, host start, arith) for the span sub. kind is "cmd" for $(...) and
    backticks, "proc" for <(...) and >(...), "arith" for an arithmetic `((...))` or `$((...))`.
    The substitutions are the shared scanner's (quote_mask.substitutions), so a `$(` followed by
    a newline, a `;` inside the body and a backtick inside "..." are all read as bash reads them.
    The host is the simple command the span is a word of: from the last separator before its
    opening that lies in no other substitution, and is not the `(` of an array literal `v=(`, up
    to the opening. When sub sits directly in an arithmetic expression, arith is that span and
    there is no host: the value is the arithmetic's, which the caller follows instead."""
    o = opening(sub)                           # `$((`: the expansion opens at its `$`
    outer = [s for s in subs if s["body"][0] <= o < s["body"][1] and s is not sub]
    up = max(outer, key=lambda s: s["body"][0]) if outer else None
    if up is not None and up["kind"] == "arith":
        return sub["kind"], [], o, up
    lo = max([s["body"][0] for s in outer] or [0])
    nested = [extent(s) for s in subs if lo <= opening(s) < o]
    hs, hv = lo, held(v, subs)
    for m in SEP.finditer(hv, lo, o):
        if any(x <= m.start() <= y for x, y in nested):
            continue
        if m.group(0) == "(" and ARRAY_OPEN.search(v[lo:m.end()]):
            continue
        hs = m.end()
    # An earlier substitution of the same command is part of the word it sits in: its blanks do
    # not split the host, so `P="$(echo 1) $(pgrep X)"` and `P=$(cat f)$(pidof X)` stay the one
    # assignment word they are.
    w = list(v[hs:o])
    for x, y in nested:
        for k in range(max(x, hs), min(y + 1, o)):
            if w[k - hs] in " \t\n":
                w[k - hs] = FILL
    return sub["kind"], split_words("".join(w), t0[hs:o]), hs, None


# An assignment inside arithmetic: `(( p = ... ))`, `(( p += ... ))`, `x[i] = ...`; not `==`,
# `<=`, `>=` or `!=`.
ARITH_ASSIGN = re.compile(r"(?<![A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^]]*\])?\s*"
                          r"(?:[-+*/%&|^]|<<|>>)?=(?!=)")


def arith_targets(arith, t0, subs):
    """The variables an arithmetic span assigns, read with the substitutions in it blanked."""
    a, b = arith["body"]
    w = list(t0[a:b])
    for s in subs:
        if s is not arith and a <= s["open"] < b:
            for k in range(s["open"], min(s["body"][1] + 1, b)):
                w[k - a] = " "
    return {m.group(1) for m in ARITH_ASSIGN.finditer("".join(w))}


def here_word(raw):
    r = REDIR.match(raw)
    return bool(r) and r.group(1) == "<<<"


def takes_input(kind, hw, v, o):
    """Whether the span opening at o is read by its host on an input: a process substitution
    (`< <(...)`, or a file operand `cat <(...)`), or the word of a herestring `<<< "$(...)"`."""
    if kind == "proc":
        return True
    if not hw:
        return False
    if o and v[o - 1] not in " \t\n":          # glued to the last word: that is its word
        return here_word(hw[-1][0]) or (len(hw) > 1 and hw[-2][1] == "<<<")
    return hw[-1][1] == "<<<"


# A compound command's closing word, and the words that open one.
OPENERS, CLOSERS = ("while", "until", "for", "select", "{", "if", "case"), ("done", "}", "fi", "esac")


# `v=(` / `v+=(`: the `(` opens an array literal, and the words in it are the array's elements.
ARRAY_OPEN = re.compile(r"(?:^|(?<=[\s;&|(]))[A-Za-z_][A-Za-z0-9_]*\+?=\($")


CLOSES = {"{": "}", "if": "fi", "case": "esac", "while": "done", "until": "done", "for": "done",
          "select": "done"}


def compounds(items, v, t0, subs):
    """(start, after, kind) of every compound command: a `{ ...; }` group, a `( ... )` subshell, a
    loop, an `if` or a `case`. start is where it opens, after the offset just past its closing
    word or `)`, where its own pipeline goes on: the output of every command in it is its output.
    kind is its opening word, or "(" for a subshell.
    A subshell's `(` is one no substitution, arithmetic, array literal or `name()` owns; a `)`
    with nothing open, or a `case` pattern's, closes none."""
    out, stack = [], []
    for it in items:
        if it.kw in CLOSES:
            stack.append(it)
        elif it.kw in CLOSERS and stack and CLOSES[stack[-1].kw] == it.kw:
            o = stack.pop()
            k = v.find(it.kw, it.pos)
            out.append((o.pos, (k if k >= 0 else it.pos) + len(it.kw), o.kw))
    owned = set()
    for s in subs:
        if s["kind"] == "arith":
            owned |= {s["open"], s["open"] + 1, s["body"][1], s["body"][1] + 1}
        elif t0[s["open"]] != "`":
            owned |= {s["open"] + 1, s["body"][1]}
    cases = [(a, b) for a, b, kind in out if kind == "case"]
    opens = []
    for k, ch in enumerate(v):
        if k in owned:
            continue
        if ch == "(":
            if ARRAY_OPEN.search(v[max(0, k - 64):k + 1]) or re.match(r"\(\s*\)", v[k:]):
                continue
            opens.append(k)
        elif ch == ")" and opens:
            if any(opens[-1] < a <= k < b for a, b in cases):
                continue                       # `case x in a) ...`: a pattern, not a close
            out.append((opens.pop(), k + 1, "("))
    return out


def synthetic_feeds(code, depth):
    """Whether a lister written into code where its pids land (`set -- $(L); CODE` for the
    arguments of `sh -c CODE NAME ARGS`, CODE with xargs' replace string replaced by `$(L)`)
    reaches a kill of that code. Every place it was written is asked, not the first: in
    `echo {}; kill {}` the first one reaches only an echo."""
    if depth > 3:
        return True
    try:
        t = join_lines(code)
        its = parse(t)
        bodies = code_heredocs(t)
        vv = mask_quoted(t, fill=FILL, live=True, code_bodies=bodies)
        ss = substitutions(t, code_bodies=bodies)
    except MaskMismatch:
        return True
    cs = [x for x in its if x.kw is None and x.words]
    ks = [x for x in cs if x.name == "kill"
          and any(signals(sig) for sig, _ in kill_readings(x.words))]
    lst = [x for x in cs if x.name == "pgrep" and any(w[1] == LISTER_MARK for w in x.words)]
    return any(feeds_kill(x, its, ks, vv, t, ss, depth + 1) for x in lst)


LISTER_MARK = "__lister__"
LISTER_SUB = "$(pgrep -f %s)" % LISTER_MARK
HANDED_MARK = "__handed__"


def via_parallel(words):
    """words from the `parallel` the command words resolve to (past wrappers), or None."""
    for k, (_, w) in enumerate(words):
        if os.path.basename(w) == "parallel":
            return words[k:] if resolve(words[:k] + [("true", "true")])[0] == k else None
    return None


def parallel_feeds(words, depth):
    """Whether pids written to the stdin of the GNU `parallel` that words run reach a kill of its
    command template (bash_parse.parallel_stdin): the lister is written where each replacement
    string stands (closing and reopening a '...' it sits in), after the template when it holds
    none, and piped into it under `--pipe`."""
    words = via_parallel(words)
    got = parallel_stdin(words) if words else None
    if not got:
        return False
    line, spans, piped = got
    if piped:
        code = "pgrep -f %s | { %s\n}" % (LISTER_MARK, line)
    elif not spans:
        code = line + " " + LISTER_SUB
    else:
        out, p = [], 0
        for a, b, sq in spans:
            out += [line[p:a], "'%s'" % LISTER_SUB if sq else LISTER_SUB]
            p = b
        code = "".join(out + [line[p:]])
    return synthetic_feeds(code, depth)


def xargs_replace(words):
    """The replace string an `xargs` before the command word substitutes, or None."""
    for k, (_, w) in enumerate(words):
        if w == "-I" and k + 1 < len(words):
            return words[k + 1][1]
        if w in ("-i", "--replace"):
            return "{}"
        if w.startswith("--replace="):
            return w.split("=", 1)[1]
        if w.startswith(("-I", "-i")) and len(w) > 2:
            return w[2:]
    return None


def shell_takes_pids(x, depth, replace=None, at=None):
    """Whether x is a shell running `-c CODE` whose kill expands the pids it is given: as its
    arguments ($@, $1, ...) or, behind `xargs -I R`, as the text R stands for in CODE. at, where
    known, is the index in x.words of the word the pids are in: from the positional it lands at
    on (first_positional()), and code that reads only positionals below it takes none of them
    (`sh -c 'kill "$1"' _ "$SRV" $(L)` kills $SRV alone)."""
    if x.name not in SHELLS:
        return False
    kind, code = shell_code(x.words)
    if kind != "code" or not code:
        return False
    m = first_positional(x.words, code, at) if at is not None else None
    if not (m and reads_only_below(code, m)) and synthetic_feeds("set -- %s; %s" % (LISTER_SUB, code), depth):
        return True
    return bool(replace) and replace in code and synthetic_feeds(code.replace(replace, LISTER_SUB),
                                                                 depth)


def feeds_kill(c, items, kills, v, t0, subs, depth=0):
    """Whether the pids lister c (pgrep/pidof) prints reach one of kills (the block above).
    A path this cannot follow to its end -- a substitution whose host is no command it can
    read -- counts the lister: going silent is the fail-open direction."""
    cmds = [x for x in items if x.kw is None]
    if not kills and not any(x.name in SHELLS or x.codes for x in cmds):
        return False                           # nothing here kills, and nothing is handed code
    bound = Bound()
    groups = compounds(items, v, t0, subs)
    hv = held(v, subs)                         # what every separator scan reads (held())
    funcs = {m.group(1) or m.group(2) for m in FUNC_DEF.finditer(v)}
    loops = [(a, b) for a, b, kind in groups if kind in ("while", "until", "for", "select")]

    def body_of(m):
        """The span of the function body FUNC_DEF match m opens: the `{ }` or `( )` compound whose
        opening is the first thing after the name. Up to the end of the call when none is found,
        which is the side that keeps a use inside it seeing every binding."""
        p = m.end() + len(v[m.end():]) - len(v[m.end():].lstrip())
        got = [(a, b) for a, b, kind in groups if kind in ("{", "(") and b > p
               and (a if kind == "(" else v.find("{", a)) == p]
        return min(got, key=lambda s: s[1] - s[0]) if got else (m.end(), len(v))

    fdefs = [(m.group(1) or m.group(2), body_of(m)) for m in FUNC_DEF.finditer(v)]
    fbodies = [b for _, b in fdefs]
    named_at = [m.start(1) if m.group(1) else m.start(2) for m in FUNC_DEF.finditer(v)]
    in_func = lambda u: any(a <= u < b for a, b in fbodies)

    def end_of(x):
        """The offset where the simple command x ends: the body runs after its words, prefix
        assignments included (`P=$(L) f`), are expanded."""
        spans = [extent(s) for s in subs if opening(s) >= x.pos]
        return next((m.start() for m in SEP.finditer(hv, x.pos)
                     if not any(a <= m.start() <= b for a, b in spans)), len(v))

    def calls_of(body):
        """The offsets at which the function whose body is body runs, for each call outside it (the
        end of the call, end_of()); None where its name is defined twice or is said anywhere that is
        neither its definition nor the command word of a call (`trap f EXIT`, `xargs f`, `bash -c
        f`, in a string): a call this cannot place."""
        names = [n for n, b in fdefs if b == body]
        if len(names) != 1 or sum(n == names[0] for n, _ in fdefs) != 1:
            return None
        at = [x for x in cmds if x.words and x.name == names[0]   # not the `f()` defining it
              and not any(x.pos <= d and not v[x.pos:d].strip() for d in named_at)]
        said = len(re.findall(r"(?<![\w.:/-])%s(?![\w.:/-])" % re.escape(names[0]), t0))
        if said != 1 + len(at):
            return None
        return [end_of(x) for x in at if not body[0] <= x.pos < body[1]]

    def scope_of(where, local=False):
        """The span of the shell a binding made by the command at where lives in: the innermost
        `( )` subshell or command/process substitution holding it, or, for `local` and a
        `declare` in a function, that function's body. None: the whole call."""
        spans = [(a, b) for a, b, kind in groups if kind == "(" and a <= where < b]
        s = enclosing(where, subs)
        if s is not None and s["kind"] in ("cmd", "proc"):
            spans.append((s["body"][0], s["body"][1] + 1))
        if local:
            spans += [(a, b) for a, b in fbodies if a <= where < b]
        return min(spans, key=lambda s: s[1] - s[0]) if spans else None

    bound.scope_of = scope_of

    def is_local(x):
        """Whether the declarer x binds in its function's scope: `local`, or `declare`/`typeset`
        without -g, in a function body."""
        ws = [w for _, w in x.words[1:]]
        return (x.name == "local" or (x.name in ("declare", "typeset")
                                      and not any(w.startswith("-") and "g" in w for w in ws))) \
            and in_func(x.pos)

    def pipe_scope(x, w):
        """The scope of what the `read` x binds when it is fed by a pipe from the command at w:
        bash runs each member of a pipeline in a subshell (unless `lastpipe` is set), so it is the
        compound command x is the member of, or x alone."""
        if "lastpipe" in v:
            return scope_of(x.pos)
        got = [(a, b) for a, b, _ in groups if a <= x.pos < b and not a <= w < b]
        return max(got, key=lambda s: s[1] - s[0]) if got else (x.pos, x.pos + 1)

    def refs_at(words, u):
        """refs(words), where a positional parameter inside a function body is also the
        function's own arguments ("@fn", which a call binds), and outside one is not."""
        out = refs(words)
        if "@" in out and in_func(u):
            out.add("@fn")
        return out

    def resets():
        """name -> [(offset, scope)] at which bash always assigns it anew, ending what it held: an
        assignment standing alone (or a `declare`-family one), a `set` of the positional
        parameters, a `printf -v`, an `unset`, a `read`, in no compound command, no substitution and no
        pipeline, not run in the background, and not behind `&&` or `||`; and a `for` variable
        within its own loop (scope: the loop). `+=` and an element `P[i]=` keep the rest of the
        value, so they end nothing."""
        out = {}
        for x in cmds:
            if x.words and x.name not in DECLARERS + ("set", "printf", "unset", "read"):
                continue
            if enclosing(x.pos, subs) is not None or any(a <= x.pos < b for a, b, _ in groups):
                continue
            if x.sep in ("&&", "||", "|", "|&"):
                continue
            spans = [extent(s) for s in subs if opening(s) >= x.pos]
            nxt = next((m.group(0) for m in SEP.finditer(hv, x.pos)
                        if not any(a <= m.start() <= b for a, b in spans)), None)
            if nxt in ("|", "|&", "&", "&&", "||"):
                continue
            ws = [w for _, w in x.words[1:]]
            if x.name == "set":
                if ws and (ws[0] == "--" or not ws[0].startswith(("-", "+"))):
                    out.setdefault("@", []).append((x.pos, None))
                continue
            if x.name == "printf":
                for n in printf_targets(ws):
                    out.setdefault(n, []).append((x.pos, None))
                continue
            if x.name == "unset":
                if not any(w.startswith("-") and set(w[1:]) & set("fn") for w in ws):
                    for w in ws:
                        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", w):
                            out.setdefault(w, []).append((x.pos, None))
                continue
            if x.name == "read":
                for n in read_targets(x.words[1:]):
                    out.setdefault(n, []).append((x.pos, None))
                continue
            for raw, _ in (x.seg_words if not x.words else x.words[1:]):
                m = ASSIGN.match(raw)
                if m and "+=" not in raw[:m.end()] and "[" not in raw[:m.end()]:
                    out.setdefault(m.group(1), []).append((x.pos, None))
        for m in FOR_HEAD.finditer(v):
            loop = [(a, b) for a, b, kind in groups if kind in ("for", "select") and a <= m.end() < b]
            if loop:
                out.setdefault(m.group(1), []).append((m.start(), max(loop)))
        return out

    reset_at = resets()

    def ran_before(b, u):
        """Whether bash has made a binding at b when it runs the use at u: b comes first, or both
        are in one loop (a later pass), or u is in a function body (run when it is called)."""
        return b < u or in_func(u) or any(a <= b < e and a <= u < e for a, e in loops)

    def holds(n, b, sc, u, d=0):
        """Whether the binding of n made at b, living in sc, is what n holds when bash expands it at
        u: u is in sc, after b, and n is not assigned anew between the two. A use in a function body
        the binding is outside of is asked at each call of the function instead (calls_of()), since
        that is when it runs: `f() { kill $P; }; P=$SRV; f; P=$(L)` calls f before P holds the
        pids. Where a call cannot be placed, the body sees every binding."""
        body = [(a, e) for a, e in fbodies if a <= u < e and not a <= b < e]
        if body and n != "@fn" and d < 4:      # "@fn": a call's own arguments, bound at the call
            calls = calls_of(min(body, key=lambda s: s[1] - s[0]))
            if calls is not None:
                return any(holds(n, b, sc, p, d + 1) for p in calls)
        return (sc is None or sc[0] <= u < sc[1]) and ran_before(b, u) and not any(
            b < r < u and (rs is None or rs[0] <= u < rs[1]) for r, rs in reset_at.get(n, ()))

    def live(names, u):
        """The names among names that hold a lister's pids where they are expanded, at u: bound
        in a scope u is in, before u, and not assigned anew between the two (holds())."""
        return {n for n in names if any(holds(n, b, sc, u) for b, sc in bound.get(n, ()))}

    def downstream(hs):
        """Whether the command starting at hs pipes into a kill; binds the `read`s it pipes into.
        Its pipeline is read off the separators at its own level, not from Cmd.pipe."""
        lvl = enclosing(hs, subs)
        end = lvl["body"][1] if lvl else len(v)
        spans = [extent(s) for s in subs if opening(s) >= hs]
        p = hs
        while True:
            m = next((m for m in SEP.finditer(hv, p, end)
                      if not any(x <= m.start() <= y for x, y in spans)), None)
            if not m or m.group(0) not in ("|", "|&"):
                return False
            nxt = [x for x in cmds if x.pos >= m.end() and enclosing(x.pos, subs) is lvl]
            if not nxt:
                return False
            x = min(nxt, key=lambda x: x.pos)
            if x in kills:
                return True
            if x.name in READERS:
                bound.update(reader_vars(x), scope=pipe_scope(x, hs))
            if shell_takes_pids(x, depth, xargs_replace(x.seg_words)
                                if any(w[1] == "xargs" for w in x.seg_words) else None):
                return True
            if parallel_feeds(x.seg_words, depth):   # `L | parallel 'kill {}'`
                return True
            # Code x runs reads the pipe on its stdin: `L | bash -c 'read p; kill $p'`, `L | env -S
            # 'xargs kill'`. Not a shell whose stdin IS its code, nor one redirected, nor parallel,
            # whose stdin is its arguments (parallel_feeds() above).
            if x.codes and not getattr(x, "stdin_shell", False) and not _io_redirs(x.seg_words)[0] \
                    and via_parallel(x.seg_words) is None \
                    and any(synthetic_feeds("pgrep -f %s | { %s\n}" % (LISTER_MARK, code), depth)
                            for code in x.codes):
                return True
            p = x.pos

    def compound_readers(pos, closer):
        """Binds what the `read`s inside the compound command whose closing word starts at pos
        (`done <<<`, `} < <(...)`) take: its input is theirs. Every `read` in the call when it
        cannot be found."""
        end = next((k for k, x in enumerate(items) if x.kw == closer and x.pos == pos), None)
        nest, start = 0, None
        for k in range(end - 1, -1, -1) if end is not None else ():
            kw = items[k].kw
            if kw in CLOSERS:
                nest += 1
            elif kw in OPENERS:
                if nest == 0:
                    start = items[k].pos; break
                nest -= 1
        rs = [x for x in cmds if x.name in READERS and (start is None or start <= x.pos < pos)]
        for x in rs:                           # bound where each `read` runs, before its loop's kill
            bound.at = bound.where = x.pos
            bound.update(reader_vars(x))

    def handed_to_kill(sub, hs):
        """Whether the span sub, a word of the command starting at hs, lands in a string that
        command hands on to be run -- `bash -c "kill $(L)"`, `find . -exec kill $(L) \\;`, `ssh
        localhost kill $(L)` -- where a kill takes it. The host is read again with each of its
        spans spelled as a placeholder word, and the string it hands on is asked with the lister
        written where the placeholder lands."""
        spans = [extent(s) for s in subs if opening(s) >= hs]
        end = next((m.start() for m in SEP.finditer(hv, hs)
                    if not any(x <= m.start() <= y for x, y in spans)), len(v))
        out, p = [], hs
        for s in sorted((s for s in subs if hs <= s["open"] < end), key=lambda s: s["open"]):
            if s["open"] < p:
                continue                       # nested in a span already replaced
            out += [t0[p:s["open"]], HANDED_MARK if s is sub else "__span__"]
            p = s["body"][1] + 1
        out.append(t0[p:end])
        try:
            host = parse("".join(out))
        except MaskMismatch:
            return True
        return any(HANDED_MARK in code and synthetic_feeds(code.replace(HANDED_MARK, LISTER_SUB), depth)
                   for x in host for code in x.codes)

    def climb(c):
        """Whether what c writes reaches a kill by structure; binds the variables it reaches."""
        bound.at = bound.where = c.pos
        same = [x for x in cmds if x.pipe == c.pipe]
        if any(k in same and k.pos > c.pos for k in kills) or downstream(c.pos):
            return True
        for x in same:
            if x.pos > c.pos and x.name in READERS:
                bound.update(reader_vars(x), scope=pipe_scope(x, c.pos))
        lvl = enclosing(c.pos, subs)
        mine = [(a, after) for a, after, _ in groups if a <= c.pos < after and enclosing(a, subs) is lvl]
        # What it writes into an output process substitution `>(...)` -- its own redirection, a
        # `tee` after it, or the redirection of a compound command it sits in (`{ L; } > >(...)`)
        # -- is read by the first command of that body.
        for s in subs:
            if s["kind"] != "proc" or t0[s["open"]] != ">":
                continue
            _, _, hs, up = subst_host(s, v, t0, subs)
            host = next((x for x in cmds if x.pos == hs), None)
            if up is not None:
                continue
            ours = host is not None and (host is c or (host in same and host.pos > c.pos))
            if not ours and not any(after <= s["open"] and not SEP.search(hv[after:s["open"]])
                                    and v[after:s["open"]].rstrip().endswith(">") for _, after in mine):
                continue
            inner = [x for x in cmds if s["body"][0] <= x.pos <= s["body"][1]
                     and enclosing(x.pos, subs) is s]
            if inner:
                y = min(inner, key=lambda x: x.pos)
                if y in kills or downstream(y.pos):
                    return True
                if y.name in READERS:
                    bound.where = y.pos
                    bound.update(reader_vars(y))
        # A compound command it sits in writes what it writes: `{ L; } | xargs kill`,
        # `( L ) | xargs kill`, `for ...; do L; done | while read p; ...`.
        for a, after in mine:
            if downstream(after):
                return True
        sub = enclosing(min(x.pos for x in same), subs)
        for _ in range(12):
            if sub is None:
                break
            if sub["kind"] == "arith":             # the lister's value is the arithmetic's
                bound.where = sub["open"]
                bound.update(arith_targets(sub, t0, subs))
                if sub.get("dollar") is None:
                    break                          # `((...))`: a status, no word of any command
            kind, hw, hs, up = subst_host(sub, v, t0, subs)
            if up is not None:
                sub = up; continue                 # directly in arithmetic: follow its value
            bound.where = hs                       # what it binds lives in the host's shell
            host = next((x for x in cmds if x.pos == hs), None)
            lead = hw[0][0] if hw else None
            while hw and hw[0][0] in RESERVED and hw[0][0] not in ("for", "select"):
                hw = hw[1:]
            if takes_input(kind, hw, v, opening(sub)):
                if lead in CLOSERS:                # `done <<< "$(L)"`: what the compound's reads take
                    compound_readers(hs, lead); break
                if (kind != "proc" or (hw and hw[-1][0] == "<")) and parallel_feeds(hw, depth):
                    return True                    # `parallel 'kill {}' <<< "$(L)"`, `< <(L)`
            else:
                if len(hw) > 1 and hw[0][0] in ("for", "select"):
                    bound.add(hw[1][1]); break
                arr = [ASSIGN.match(r) for r, _ in hw if re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=\(", r)]
                if arr:                            # an element of an array literal: the array
                    bound.add(arr[-1].group(1)); break
                if hw and ASSIGN.match(hw[-1][0]):
                    n = ASSIGN.match(hw[-1][0]).group(1)
                    if host is not None and host.words and resolve(hw)[0] is None:
                        # `P=$(L) cmd ...`: an assignment in cmd's own environment, made after
                        # cmd's words are expanded and gone when it returns. A function or a shell
                        # it runs can read it; a kill or any other command binds nothing here.
                        if host.name in funcs:
                            bound.add(n); break
                        if host.name in SHELLS or host.codes:
                            return True
                        break
                    bound.add(n, local=host is not None and host.name in DECLARERS and is_local(host))
                    break
                if hw and PARAM_ASSIGN.search(hw[-1][0]):  # `${P:=$(L)}` assigns P, and is a word
                    bound.add(PARAM_ASSIGN.search(hw[-1][0]).group(1))
            idx, handed, _ = resolve(hw) if hw else (None, [], [])
            got = carried_kill(hw[idx:], hw[:idx]) if idx is not None else None
            if got:                                # `numactl -N 0 kill $(L)`: the kill it carries,
                idx = len(hw) - len(got[1]) if got[1] else None  # or the command running code
                handed = handed + got[2]           # (`valgrind sh -c "kill $(L)"`)
            if idx is None:
                if handed and kind == "cmd":       # `flock F -c "...$(L)..."`: the code it hands on
                    return handed_to_kill(sub, hs) or downstream(hs)
                return True                        # no command to read: count, never go silent
            name = name_of(hw[idx:])
            if name == "kill":
                return True
            if name in READERS and takes_input(kind, hw, v, opening(sub)):
                bound.update({w for r, w in hw[idx + 1:]  # a read binds only its own variables
                              if not REDIR.match(r) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", w)})
                break
            # The builtins that bind a name from their operands: `printf -v P FMT "$(L)"`, and
            # `set -- $(L)`, which binds the positional parameters, as a function call does its own.
            if name == "printf":
                pv = printf_targets([w for r, w in hw[idx + 1:] if not REDIR.match(r)])
                if pv:
                    bound.update(pv)
                    break
            if name == "set":
                bound.add("@"); break
            if name == "eval":                     # `eval "P=$(L)"` assigns P in this shell
                bound.update(ASSIGN.match(w).group(1) for _, w in hw[idx + 1:] if ASSIGN.match(w))
            if name in funcs:                      # a call binds the function's own arguments
                bound.add("@fn")
            glued = opening(sub) and v[opening(sub) - 1] not in " \t\n"
            if name in SHELLS and shell_takes_pids(Cmd(words=hw[idx:]), depth,
                                                   at=len(hw) - idx - glued):
                return True                        # `bash -c 'kill "$@"' _ $(L)`
            if kind == "cmd" and handed_to_kill(sub, hs):
                return True                        # `bash -c "kill $(L)"`, `find -exec kill $(L) \;`
            if downstream(hs):                     # a command passing the output on: its pipeline,
                return True
            sub = enclosing(hs, subs)              # then the span it sits in
        return False

    def through_words(x, names):
        """Whether names, bound to a lister's pids and expanded in x's own words, reach a kill
        through what x does with its words -- read as climb() reads a lister's substitution in
        that word; binds what x binds from them. A function call (`f $P`) and `set -- $P` bind the
        positional parameters, `printf -v Q ... "$P"` binds Q, a `read` from `<<< "$P"` its own
        names; a shell given them after its `-c CODE` (`sh -c 'kill "$@"' _ $P`) is asked where
        its arguments go, and code the outer shell expands them into (`sh -c "kill $P"`, `flock F
        -c "kill $P"`) is asked with the lister written where they land."""
        words = x.words[1:]
        mine = lambda raw: expanded(raw)[0] & names
        if x.name in funcs:
            bound.add("@fn")
        if x.name == "set":
            bound.add("@")
        if x.name == "printf":
            bound.update(printf_targets([w for r, w in words if not REDIR.match(r)]))
        if x.name in READERS and any(here_word(r) or r == "<<<" for r, _ in words):
            bound.update(reader_vars(x))
        sw = x.seg_words                       # `parallel 'kill {}' <<< "$P"`: its stdin
        here = [sw[k][0] if REDIR.match(sw[k][0]).group(2) else (sw[k + 1][0] if k + 1 < len(sw) else "")
                for k in range(len(sw)) if here_word(sw[k][0])]
        if any(mine(r) for r in here) and parallel_feeds(sw, depth):
            return True
        if x.name in SHELLS:
            kind, code = shell_code(x.words)
            k = next((k for k, (_, w) in enumerate(x.words) if kind == "code" and w == code), None)
            j = next((j for j in range(k + 1, len(x.words)) if mine(x.words[j][0])), None) \
                if k is not None else None
            if j is not None and shell_takes_pids(x, depth, at=j):
                return True
        for code in x.codes:
            ns = set().union(*[mine(r) for r, w in x.words if w and w in code])
            if ns and synthetic_feeds(PLAIN_REF.sub(lambda m: LISTER_SUB if (m.group(1) or m.group(2))
                                                     in ns else m.group(0), code), depth):
                return True
        return False

    if climb(c):
        return True
    fors = [(m.start(), m.group(1), refs([(t0[m.start(2):m.end(2)], "")])) for m in FOR_HEAD.finditer(v)]
    fors += [(m.start(), m.group(1), {"@"}) for m in FOR_BARE.finditer(v)]   # `for p; do`: over "$@"
    fors = [(at, var, rs | ({"@fn"} if "@" in rs and in_func(at) else set())) for at, var, rs in fors]
    seen = {(id(c), frozenset())}
    for _ in range(6):                         # carried on through assignments and for loops,
        before = dict(bound)
        for x in cmds:
            for raw, _ in x.seg_words:
                m = ASSIGN.match(raw)
                if m and live(refs_at([(raw, "")], x.pos), x.pos):
                    bound.at = bound.where = x.pos
                    bound.add(m.group(1), local=x.name in DECLARERS and is_local(x))
                for m in PARAM_ASSIGN.finditer(raw):   # `: ${Q:=$P}` assigns Q what P holds
                    if live(refs_at([(raw[m.end():], "")], x.pos), x.pos):
                        bound.at = bound.where = x.pos
                        bound.add(m.group(1))
        for at, var, rs in fors:
            if live(rs, at):
                bound.at = bound.where = at
                bound.add(var)
        for k in kills:
            upstream = [w for x in cmds if x.pipe == k.pipe and x.pos < k.pos for w in x.seg_words]
            if live(refs_at(k.words + upstream, k.pos), k.pos):
                return True
        # and through any command that expands one and writes it on (`kill $(echo $P)`,
        # `printf '%s\n' "$@" | xargs kill`), or binds or hands on what it expands (through_words).
        for x in cmds:
            names = live(refs_at(x.seg_words, x.pos), x.pos)
            if x not in kills and names and (id(x), frozenset(names)) not in seen:
                seen.add((id(x), frozenset(names)))
                if x.words and climb(x):
                    return True
                bound.at = bound.where = x.pos
                if x.words and through_words(x, names):
                    return True
                closer = next((it.kw for it in items if it.kw in CLOSERS and it.pos == x.pos), None)
                if not x.words and closer and any(here_word(r) for r, _ in x.seg_words):
                    compound_readers(x.pos, closer)   # `done <<< "$P"`
        if bound == before:
            break
    return False


def lists_by_pattern(code, depth=0):
    """Whether code runs a lister keyed on a full command line -- pgrep -f, or ps -- itself or in
    code it hands on."""
    if depth > 3:
        return True
    try:
        its = parse(join_lines(code))
    except MaskMismatch:
        return True
    return any((x.name == "pgrep" and pg_options(x.words)[0]) or x.name == "ps"
               or any(lists_by_pattern(k, depth + 1) for k in x.codes)
               for x in its if x.kw is None)


# A KILL WHOSE TARGET IS THE WHOLE ACCOUNT OR THE CALLER'S PROCESS GROUP IS REFUSED BY ITS WORDS.
# `kill -9 -1` sends the signal to every process the sender may signal -- every process of the
# account, every other agent session and background job of this user included -- and `kill 0`
# (or `-0`) to every process in the sender's process group. A literal PID is otherwise "a kill by
# PID", so these are read by their target. So is the same harm spelled as a ps listing with no
# pipe, `kill $(ps -u "$USER" -o pid=)`, whose listing is every process of the account, and `kill
# $(ps -o pid=)`: with no tty, plain ps is every process of the account. So:
#   - kill_target() reads kill's argv as bash's builtin and /bin/kill read it -- one signal word
#     (`-SIG`, `-s SIG`, `-n NUM`) and `--`, the first other word ending the options, after which
#     `-1` is a PID -- and the kill is refused when a target is -1 or 0. Signal 0 sends nothing and
#     `-l`/`-L` list signals, so those are never refused. `kill -1` alone is refused too: bash and
#     /bin/kill read it as SIGHUP with no target, a usage error that sends nothing, but it is the
#     spelling of the whole-account kill and a refused no-op costs a rewrite.
#   - ps_whole_account() reads a ps listing's selection; one that selects by owner or every
#     process (-e, -A, -a, -d, -N, -u, -U, --user, --User, --deselect, BSD a, x, g, U), or has no
#     selection at all, and whose pids reach a kill, is refused. A listing by pid, parent, session,
#     tty, group or command name alone is not this rule's.
# Pinned by hooks/tests/test-block-unsafe-kill-whole-account.py, rows A, S and R.
NO_SIGNAL = {"0", "EXIT", "NULL", "SIGEXIT", "SIGNULL"}

# EVERY SIGNAL WORD EITHER KILL RE-READS, AND THE TARGETS BASH EXPANDS. The first signal word is
# not final: bash's builtin re-reads `-s SIG`, `-n NUM`, `-sNAME` and `-nNUM` all through its
# option run (only a bare `-SIG` is taken once), and procps /bin/kill takes its first `-SIG` word
# from ANYWHERE in argv (after `--` included) and then lets every `-s`/`--signal` (getopt
# permutes, so after a target too) override it. So `kill -0 -s KILL -1`, `kill -0 -n 9 -1`, `kill
# -s 0 -s 9 -1`, `kill -EXIT -s KILL -1` and `/bin/kill -0 -s KILL -- -1` signal the whole
# account; so do `kill -9 {-1,99999}` (bash expands the braces before kill reads a word) and
# `kill -9 ' -1'` (both parse a number past a leading blank). Each argv is brace-expanded where
# its words are literal, read by BOTH grammars, and refused if EITHER sends a signal other than 0
# to -1 or 0: the hook does not tell which kill runs (`env`, sudo and xargs run /bin/kill;
# `command` and a bare word, the builtin), so a spelling one of them reads as signal 0 and the
# other as a signal is refused -- no ordinary probe is spelled that way. A kill that both read as
# signal 0, or as a listing, still passes. Derived of the tools, not their pages:
# hooks/tests/test-block-unsafe-kill-signal-reread.py runs every sequence of up to two signal
# words of each kind (and `--`) on both kills in bash_oracle and holds the hook to it.
# NOT READ (stated, hooks/tests/INVARIANTS.md mh-a-whole-account-kill-is-refused): a target or
# signal the shell computes when it runs -- `$((-1))`, `$[-1]`, `$P`, `${P:--1}`, `$(echo -1)`,
# backticks, `k=kill; $k -9 -1` -- and a brace in a word that also holds a quote or an expansion.
def brace_expand(s, limit=256):
    """Bash's brace expansion of the unquoted literal word s (comma lists and integer ranges,
    nested), capped at `limit` words; [s] where there is none."""
    for i, ch in enumerate(s):
        if ch != "{":
            continue
        depth, parts, start = 0, [], i + 1
        for j in range(i, len(s)):
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif s[j] == "," and depth == 1:
                parts.append(s[start:j]); start = j + 1
        else:
            return [s]                         # no closing brace: no expansion from here on
        inner = s[i + 1:j]
        if parts:
            alts = parts + [s[start:j]]
        else:
            m = re.fullmatch(r"([+-]?\d+)\.\.([+-]?\d+)(?:\.\.([+-]?\d+))?", inner)
            if not m:
                continue
            a, b = int(m.group(1)), int(m.group(2))
            step = abs(int(m.group(3) or 1)) or 1
            alts = [str(n) for n in range(a, b + (1 if b >= a else -1), step if b >= a else -step)]
        out = []
        for alt in alts[:limit]:
            out += brace_expand(s[:i] + alt + s[j + 1:], limit)
            if len(out) >= limit:
                break
        return out[:limit]
    return [s]


def kill_argv(words):
    """kill's operands as the program reads them: redirections dropped, and a word with no quote,
    escape or expansion brace-expanded (the block above)."""
    out, i = [], 1
    while i < len(words):
        raw, v = words[i]
        if REDIR.match(raw):
            i += 1 if REDIR.match(raw).group(2) else 2; continue
        out += brace_expand(v) if "{" in raw and not re.search(r"['\"\\$`]", raw) else [v]
        i += 1
    return out


def bash_sigspec(s):
    """Whether bash's decode_signal could accept s. Anything but an empty spec or one that starts
    with `-` (`--signal=9` read as `-SIG`: bash's 'invalid signal specification', nothing sent)
    counts as accepted -- an unknown name, and a spec the shell or a wrapper fills in when it runs
    (`-$(echo 9)`, parallel's `-{1}`), are the refusing direction."""
    return bool(s) and not s.startswith("-")


def bash_kill_reads(args):
    """(signal, targets) as bash's kill builtin reads operands `args` (builtins/kill.def):
    -l/-L list; -s SIG, -n NUM, -sNAME, -nNUM set the signal wherever they sit in the option run;
    a bare -SIG only when no signal was seen yet; `--` or any other word ends the options.
    signal None: nothing is sent."""
    sig, saw, i = "TERM", False, 0
    while i < len(args):
        w = args[i]
        if w in ("-l", "-L"):
            return None, []
        if w in ("-s", "-n"):
            if i + 1 == len(args):
                return None, []
            sig, saw, i = args[i + 1], True, i + 2; continue
        if (w[:2] == "-s" and w[2:3].isalpha()) or (w[:2] == "-n" and w[2:3].isdigit()):
            sig, saw, i = w[2:], True, i + 1; continue
        if w == "--":
            i += 1; break
        if w[:1] == "-" and not saw:
            sig, saw, i = w[1:], True, i + 1; continue
        break
    return (sig if bash_sigspec(sig) else None), args[i:]


def procps_kill_reads(args):
    """(signal, targets) as procps /bin/kill reads operands `args`: the first `-SIG` word
    anywhere that names a signal (pkill_signal_word, the same library) is taken out; then getopt
    permutes, so every -s/--signal (any unique prefix, `=` or separate, glued -sSIG) overrides it
    wherever it sits before `--`; -l/-L/--list/--table list; another option letter is a usage
    error, except a digit, whose word reaches kill() (counted as a target here). A `-N` word taken
    as the signal and then replaced by a -s/--signal is counted as the target it spells ONLY when
    the kill has no other target (`/bin/kill --signal KILL -1`, a usage error that sends nothing),
    as `kill -1` alone is refused: a refused no-op costs a rewrite. Beside a target it is the
    signal word the later -s re-set and nothing more (`/bin/kill -0 -s TERM P` signals P alone).
    None: no signal."""
    args = list(args)
    sig, taken = "TERM", None
    for j, w in enumerate(args):
        if pkill_signal_word(w):
            sig, taken = w[1:], w; del args[j]; break
    replaced = False
    targets, i = [], 0
    while i < len(args):
        w = args[i]
        if w == "--":
            targets += args[i + 1:]; break
        if w.startswith("--"):
            name, eq, val = w.partition("=")
            if any(o.startswith(name) for o in ("--list", "--table")) and len(name) > 2:
                return None, []
            if "--signal".startswith(name) and len(name) > 2 or "--queue".startswith(name) and len(name) > 2:
                if not eq:
                    val = args[i + 1] if i + 1 < len(args) else None; i += 1
                if val is None:
                    return None, []
                if name.startswith("--s"):
                    sig, replaced = val, True
                i += 1; continue
            return None, []                    # an option getopt does not know: usage
        if w[:1] == "-" and len(w) > 1:
            if w[1] in "lL":
                return None, []
            if w[1] in "sq":
                val = w[2:] or (args[i + 1] if i + 1 < len(args) else None)
                if val is None:
                    return None, []
                if w[1] == "s":
                    sig, replaced = val, True
                i += 1 if w[2:] else 2; continue
            if not w[1].isdigit():
                return None, []
        targets.append(w)
        i += 1
    if taken is not None and replaced and re.fullmatch(r"-\d+", taken) and not targets:
        targets.append(taken)                  # replaced, and no target: the no-op `kill -1` spells
    return sig, targets


def signals(sig):
    """Whether a kill reading's signal sends one: not None (nothing sent) and not signal 0."""
    return sig is not None and sig.upper() not in NO_SIGNAL and not (sig.isdigit() and int(sig) == 0)


def kill_readings(words):
    """[(signal, targets)] of kill argv `words`, by bash's builtin and by /bin/kill."""
    args = kill_argv(words)
    return [bash_kill_reads(args), procps_kill_reads(args)]


def kill_target(words):
    """The target of kill argv `words` that is the whole account (-1) or the process group (0)
    under a signal other than 0, by bash's builtin or by /bin/kill, or None (the blocks above)."""
    args = kill_argv(words)
    for sig, targets in kill_readings(words):
        if not signals(sig):
            continue
        hit = next((t.strip() for t in targets if re.fullmatch(r"\s*[+-]?\d+\s*", t)
                    and int(t) in (0, -1)), None)
        if hit is not None:
            return hit
    if args == ["-1"]:
        return "-1"                            # `kill -1` alone: SIGHUP and no target, refused
    return None


PS_WHOLE = set("eAadNx")                   # every process, or every one of the account
PS_OWNER_ARG = set("uU")                   # by owner, takes a list
PS_NARROW_ARG = set("pqstCgG")             # by pid, session, tty, command, group: takes a list
PS_FORMAT_ARG = set("oOkD")                # output format or sort: takes an argument
PS_LONG_WHOLE = {"--user", "--User", "--deselect"}
PS_LONG_NARROW = {"--pid", "--ppid", "--sid", "--tty", "--quick-pid", "--group", "--Group"}
PS_LONG_ARG = PS_LONG_WHOLE - {"--deselect"} | PS_LONG_NARROW | {
    "--format", "--sort", "--cols", "--columns", "--rows", "--lines", "--width", "--context"}


def ps_whole_account(words):
    """Whether the ps argv `words` lists every process of the account, or every process: an owner
    or every-process selection, or no selection at all (the block above)."""
    whole = narrow = False
    i = 1
    while i < len(words):
        raw, v = words[i]
        if REDIR.match(raw):
            i += 1 if REDIR.match(raw).group(2) else 2; continue
        if v.startswith("--"):
            name, eq, _ = v.partition("=")
            whole |= name in PS_LONG_WHOLE
            narrow |= name in PS_LONG_NARROW
            i += 2 if name in PS_LONG_ARG and not eq else 1; continue
        if not v.startswith("-") and (unresolved(raw) or re.fullmatch(r"[\d,\s]+", v)):
            narrow = True; i += 1; continue        # a pid list operand
        bsd = not v.startswith("-")
        s = v if bsd else v[1:]
        j = 0
        while j < len(s):
            ch = s[j]
            if ch in (set("axg") if bsd else PS_WHOLE):
                whole = True
            elif ch in (set("U") if bsd else PS_OWNER_ARG) or \
                    ch in (set("pqt") if bsd else PS_NARROW_ARG) or ch in PS_FORMAT_ARG:
                whole |= ch in (set("U") if bsd else PS_OWNER_ARG)
                narrow |= ch in (set("pqt") if bsd else PS_NARROW_ARG)
                if j + 1 == len(s):
                    i += 1                         # its argument is the next word
                break
            j += 1
        i += 1
    return whole or not narrow


def analyse(text, depth=0):
    if depth > 4:
        return None
    text = join_lines(text)                    # parse() reads the joined text; so must v
    items = parse(text)
    cmds = [c for c in items if c.kw is None and c.words]
    # a kill that neither kill reads as sending a signal (`kill -0 $(pgrep -f X)`, a probe) is fed
    # nothing; one that re-reads a later -s/-n (`kill -0 -s KILL $(pgrep -f X)`) is
    kills = [c for c in cmds if c.name == "kill"
             and any(signals(sig) for sig, _ in kill_readings(c.words))]
    pipes = {}
    for c in cmds:
        pipes.setdefault(c.pipe, []).append(c)
    bodies = code_heredocs(text)
    v = mask_quoted(text, fill=FILL, live=True, code_bodies=bodies)
    subs = substitutions(text, code_bodies=bodies)
    hv = held(v, subs)

    def feeds(c):
        return feeds_kill(c, items, kills, v, text, subs)

    # --- structural reasons: no process table needed ------------------------------------------
    for c in cmds:
        t = kill_target(c.words) if c.name == "kill" else None
        if t is not None:
            return (("`%s` signals every process %s (PID %s), not a process you started"
                     % (spelled(c), "this user may signal: every process of the account, this "
                        "session's siblings and any background job included" if
                        int(t) == -1 else "in this shell's process group", t)), KILL_ADVICE, None)
        if c.name == "ps" and ps_whole_account(c.words) and len(pipes[c.pipe]) == 1 and feeds(c):
            return (("`%s` into a kill lists every process of the account (an owner or "
                     "every-process selection, or none: with no tty plain ps is the account), not "
                     "one you started" % spelled(c)), KILL_ADVICE, None)
        if c.name == "pkill" and pg_options(c.words)[0]:
            return "pkill -f (a pattern on the full cmdline matches this shell)", KILL_ADVICE, None
        if c.name == "killall":
            return "killall", KILL_ADVICE, None
        if c.name == "pgrep" and pg_options(c.words)[0] and feeds(c):
            return ("pgrep -f + kill (resolves PIDs by cmdline pattern — matches this shell)",
                    KILL_ADVICE, None)
        # A ps listing piped on (to grep/awk) and then into a kill: in the same pipeline
        # (`| xargs kill`), from inside a substitution a kill expands, or wherever bash carries
        # what it prints, as pgrep -f's pids are carried (`ps aux | ... | while read p; do kill
        # $p; done`, `| { read p; kill $p; }`).
        if c.name == "ps" and len(pipes[c.pipe]) > 1 and (
                any(k.name == "kill" for k in pipes[c.pipe])
                or (pipes[c.pipe][0].sep in ("(", "`")
                    and any(any(unresolved(r) for r, _ in k.words[1:]) for k in kills))
                or feeds(c)):
            return ("a kill of PIDs read off a ps listing (the listing carries every cmdline, "
                    "this shell's included)", KILL_ADVICE, None)
    # Code a command runs prints what a pattern lister in it prints: `kill $(bash -c 'pgrep -f
    # X')`, `kill $(env -i -S pgrep -f X)`, `bash -c 'ps aux' | ... | xargs kill`.
    for c in items:
        if c.kw is None and c.codes and any(lists_by_pattern(code) for code in c.codes) \
                and feeds(c):
            return ("a kill of PIDs a pattern lister prints from code a command runs (pgrep -f or "
                    "a ps listing match this shell's own cmdline)", KILL_ADVICE, None)

    stack, loops = [], []
    for it in items:
        if it.kw in ("while", "until"):
            stack.append({"part": "cond", "cond": [], "body": [], "gate": True})
        elif it.kw in ("for", "select"):
            stack.append({"part": "head", "cond": [], "body": [], "gate": False})
        elif it.kw == "do" and stack:
            stack[-1]["part"] = "body"
        elif it.kw == "done" and stack:
            loops.append(stack.pop())
        elif it.kw is None:
            for lp in stack:
                if lp["part"] in ("cond", "body"):
                    lp[lp["part"]].append(it)
    for lp in loops + stack:
        if lp["gate"]:
            r = gate_reason(lp)
            if r:
                return r

    for c in items:
        for code in c.codes:
            r = analyse(with_literals(code, items, c.pos), depth + 1)
            if r:
                return r
    # `eval CODE` runs CODE in this shell, so what CODE binds is the rest of the call's to expand
    # (`eval "P=$(pgrep X)"; kill $P`): the call is read again with the eval spelled as its code.
    # That code is bash's (eval_code(): every word joined, no redirection), and it stands as a
    # group of lines of its own, so it ends where bash's string ends: a `#` in it comments out
    # nothing after the eval. Of a string bash cannot parse whole it is the lines bash runs before
    # the error (eval_runs()), so a quote left open there reaches nothing after the eval either,
    # and a here-document it leaves open is closed at its end (heredocs_closed()). An eval that is
    # a member of a pipeline runs in a subshell (unless `lastpipe` holds and it is the last), so
    # its code stands as `( CODE` newline `)` and binds nothing after the pipeline
    # (hooks/tests/test-eval-re-read-is-the-code-bash-runs.py).
    for c in cmds:
        if c.name == "eval" and c.codes:
            inner = [extent(s) for s in subs if opening(s) >= c.pos]
            m = next((m for m in SEP.finditer(hv, c.pos)
                      if not any(x <= m.start() <= y for x, y in inner)), None)
            end = m.start() if m else len(v)
            piped_on = bool(m) and m.group(0) in ("|", "|&")
            sub = (piped_on or c.sep in ("|", "|&")) and not ("lastpipe" in v and not piped_on)
            op, cl = (" ( ", "\n) ") if sub else (" { ", "\n} ")
            for code in eval_runs(with_literals(eval_code(c.words), items, c.pos)):
                code = heredocs_closed(code)
                r = analyse(text[:c.pos] + (op + code + cl if code.strip() else " ")
                            + text[end:], depth + 1)
                if r:
                    return r

    # --- a kill keyed on a NAME: counted with the command's own matcher -----------------------
    for c in cmds:
        if c.name == "pkill" or (c.name == "pgrep" and feeds(c)):
            r = shared_name(c, "pgrep", text if depth == 0 else None)
            if r:
                return r
        if c.name == "pidof" and feeds(c):
            dropped, rejected = [], []
            argv = pidof_argv(c, dropped)
            try:
                hit = live_count(["pidof"] + argv, rejected) if argv else None
            except Uncounted as e:
                return uncounted(c, e)
            if hit:
                n, rows = hit
                return (("`%s` into a kill reaches %d processes on this host, not one — a process "
                         "NAME is not an owner%s" % (spelled(c), n, without(dropped, rejected))),
                        KILL_ADVICE, "The processes it would stop right now:\n" + rows)
    return None


# A KILL A RUN-TIME GUARD COULD NOT SEE, IN A COMMAND THAT HOLDS A LISTER, IS REFUSED BY ITS WORDS
# (mh-a-kill-the-runtime-guard-cannot-see-is-refused). Everything above asks where bash carries a
# lister's pids, and no reader of the text can decide that exactly both ways. A run-time guard (a
# `kill` function read through BASH_ENV plus PATH shims; a prototype of the original, not shipped
# in this kit) can ask at kill time instead, for every kill a bash of the session runs through
# that function or a PATH lookup of kill, pkill or killall. What such a guard cannot see is
# decided here by WORDS ALONE, never by dataflow or the process table: a lister (pgrep, pidof, a
# ps listing piped on) anywhere in the text, together with a kill sent by
#   - a shell other than bash (dash reads no BASH_ENV and its kill is a builtin): the code of a
#     shell in SHELLS that is not bash, piped, herestring'd or heredoc'd into one, or handed to a
#     program that runs its string with /bin/sh (SH_RUNNERS);
#   - another login: ssh, mosh and kin, to any host;
#   - a program that resets the environment: sudo, doas, su, runuser, pkexec, run0, `env -i`;
#   - a spelling that skips the function or PATH: an absolute or relative path to kill, pkill or
#     killall; `builtin kill`; `command kill`; `unset -f kill`; a kill beside an assignment to,
#     or unset of, a variable such a guard keys on (GUARD_VARS);
#   - an INTERPRETER, which signals by kill(2) with no shell at all. There is no list of them:
#     any program this guard does not otherwise read (not a shell, wrapper, kill word or data
#     tool), handed code on its argv, a herestring, a heredoc, or an echo/printf piped into it,
#     counts when that code names a signal sender (INTERP_KILL). awk and sed are interpreters
#     here, not data tools: awk's system() and sed's `e` run a shell. The interpreters on the
#     host and each one's own signal senders are derived from the interpreters by the test,
#     hooks/tests/test-kill-the-runtime-guard-cannot-see.py, which fails if INTERP_KILL misses one.
# The promise is one-sided: these are refused; what passes is not promised safe. Over-refusing is
# cheap, because the fix is to write the kill as a plain `kill PID` in this bash.
UNSEEN_KILLERS = {"kill", "pkill", "killall"}
PRIVILEGE = {"sudo", "doas", "su", "runuser", "pkexec", "run0"}
SH_RUNNERS = {"watch", "at", "batch", "git", "sg", "newgrp"}
GUARD_VARS = ("KILL_GUARD_RUNTIME", "CLAUDE_PID", "BASH_ENV")
GUARD_VAR = re.compile(r"^(?:%s)(?:=|$)" % "|".join(GUARD_VARS))
INTERP_KILL = re.compile(r"(?<![A-Za-z])p?kill|send_signal")
# A file name, an option or a number is no program text: `python3 test-block-unsafe-kill.py`
# hands python a path, and `--kill-after` is an option. Code holds a blank or punctuation.
PLAIN_OPERAND = re.compile(r"[\w./@%+:,=~-]*")
SHELL_TOKEN = re.compile(r"[\s;&|()`'\"<>{}]+")
NOT_INTERPRETERS = ((TEXT_TOOLS - {"awk", "gawk", "mawk", "nawk", "busybox", "sed"}) | READ_HERE
                    | REMOTE | PRIVILEGE | set(WRAPPERS) | SH_RUNNERS
                    | {"find", "flock", "script", "tmux", "trap", "pidof", "killall"})


def env_clears(words):
    """Whether an `env` among words runs its command with an empty environment (-i, -, or
    --ignore-environment, alone or in a cluster of its options)."""
    for k, (_, v) in enumerate(words):
        if command_word(v)[0] != "env":
            continue
        for _, o in words[k + 1:]:
            if not o.startswith("-") or o == "--":
                break
            if o in ("-", "--ignore-environment") or (not o.startswith("--") and "i" in o[1:]):
                return True
    return False


def unseen_route(text):
    """The refusal of mh-a-kill-the-runtime-guard-cannot-see-is-refused, or None (the block above)."""
    found = {"lister": False, "route": None, "tamper": False, "kill": False}

    def note(route):
        found["route"] = found["route"] or route

    def walk(text, ctx, depth):
        if depth > 6:
            return
        t0 = join_lines(text)
        items = parse(t0)
        cmds = [c for c in items if c.kw is None and c.words]
        pipes = {}
        for c in cmds:
            pipes.setdefault(c.pipe, []).append(c)
        for c in items:                    # an assignment, alone or before a command word
            if c.kw is None and any(GUARD_VAR.match(v) for _, v in
                                    c.seg_words[:len(c.seg_words) - len(c.words)]):
                found["tamper"] = True
        owned = {}
        for hd in heredocs(t0):
            owner = [c for c in cmds if c.pos <= hd["op"]]
            if owner:
                a, b = hd["body"]
                owned.setdefault(id(max(owner, key=lambda c: c.pos)), []).append(t0[a:b])
        for c in cmds:
            prefix = c.seg_words[:len(c.seg_words) - len(c.words)]
            pnames = {command_word(v)[0] for _, v in prefix}
            here = set(ctx)
            if pnames & PRIVILEGE:
                here.add("a program that resets the environment (%s)" % sorted(pnames & PRIVILEGE)[0])
            if env_clears(prefix):
                here.add("env -i")
            # A program parse() read past to its kill word still runs that kill its own way:
            # `watch -n 1 kill N` joins its words and hands them to sh -c, as `watch 'kill N'` does.
            carrier = getattr(c, "carrier", None)
            if (carrier in SHELLS and carrier != "bash") or carrier in SH_RUNNERS:
                here.add("a shell other than bash (%s)" % carrier)
            if carrier in PRIVILEGE:
                here.add("a program that resets the environment (%s)" % carrier)
            if c.name in ("unset", "export", "declare", "typeset", "local", "readonly") and any(
                    GUARD_VAR.match(v) or (c.name == "unset" and v in UNSEEN_KILLERS)
                    for _, v in c.words[1:]):
                found["tamper"] = True
            if c.name in ("pgrep", "pidof") or (c.name == "ps" and len(pipes[c.pipe]) > 1):
                found["lister"] = True
            if c.name in UNSEEN_KILLERS:
                found["kill"] = True
                if here:
                    note(sorted(here)[0])
                elif "/" in unquote(c.words[0][0], drop=True):
                    note("%s named by its path" % c.words[0][1])
                elif pnames & {"builtin", "command"}:
                    note("`%s %s`, which skips the guard's function" % (
                        sorted(pnames & {"builtin", "command"})[0], c.name))
            # Code this command hands on, and the route it takes there.
            own = set(here)
            if (c.name in SHELLS and c.name != "bash") or c.name in SH_RUNNERS:
                own.add("a shell other than bash (%s)" % c.name)
            if c.name in PRIVILEGE:
                own.add("a program that resets the environment (%s)" % c.name)
            stdin_code = owned.get(id(c), []) if reads_code_on_stdin(c.words) else []
            for code in c.codes + (stdin_code if own - set(ctx) else []):
                walk(with_literals(code, items, c.pos), own, depth + 1)
            # Another login runs its words wherever it lands, so they are read as words: a kill
            # among them, after the ssh or mosh, on any host.
            k = next((i for i, (_, v) in enumerate(c.seg_words) if command_word(v)[0] in REMOTE), None)
            if k is not None:
                if any(os.path.basename(t) in UNSEEN_KILLERS
                       for _, v in c.seg_words[k + 1:] for t in SHELL_TOKEN.split(v)):
                    note("another login (%s)" % command_word(c.seg_words[k][1])[0])
            # An interpreter: any program read nowhere above, and the code it is handed.
            if c.name in NOT_INTERPRETERS or c.name in UNSEEN_KILLERS or c.name in SHELLS:
                continue
            code = [v for r, v in c.words[1:] if not REDIR.match(r) and not PLAIN_OPERAND.fullmatch(v)]
            code += herestrings(c.seg_words) + owned.get(id(c), [])
            mates = pipes[c.pipe]
            k = mates.index(c)
            if k and mates[k - 1].name in ("echo", "printf"):
                code.append(handed_script(mates[k - 1]) or "")
            code = "\n".join(code)
            if INTERP_KILL.search(code):
                note("an interpreter's own signal (%s)" % c.name)

    walk(text, frozenset(), 0)
    if found["tamper"] and found["kill"]:
        note("a kill beside a change to the run-time guard's own switches (%s)" % ", ".join(GUARD_VARS))
    if not (found["lister"] and found["route"]):
        return None
    return (("a process lister (pgrep, pidof or a ps listing) in the same command as a kill sent "
             "through %s, which a run-time kill guard could not see" % found["route"]),
            UNSEEN_ADVICE, None)


UNSEEN_ADVICE = """
Send the kill as a plain `kill PID` in this bash, from a pid you started (SRV=$! ... kill "$SRV"),
or as `xargs kill`, `pkill` or `killall` by name with no path in front, so the kill can be read
for what it reaches. A kill in `sh -c`, over ssh, under sudo or env -i, by an absolute path, or
from python, perl or another interpreter cannot be, so it is refused whenever the command also
lists processes by name or pattern.
"""


def cannot_read(e):
    return ("this guard could not read the command (%s), so it cannot tell whether it kills by "
            "name or pattern. It is refused because it could not be parsed, not because it was "
            "found unsafe. Split it into simpler calls, or put a heredoc body in a file" % e,
            "", None)


try:
    hit = analyse(cmd) or unseen_route(cmd)
except MaskMismatch as e:              # never allow what could not be read (mh-the-mask-is-its-inputs-length-or-the-call-is-refused)
    hit = cannot_read(e)
if hit:
    reason, advice, detail = hit
    print("BLOCKED: " + reason + ".")
    if detail:
        print("")
        print(detail)
    if advice:
        print(advice.rstrip())
PY
) || exit 0

[ -n "$verdict" ] || exit 0

printf '%s\n' "$verdict" >&2
exit 2
