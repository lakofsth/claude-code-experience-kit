"""Shared bash command reader for the hooks that judge SHELL CODE by its commands.

One reader of a Bash command -- which simple commands it runs and what each one's words,
redirections and handed-on shell code are -- so the guards that use it cannot disagree about
what a command is; a second regex over the same text is the defect this module exists to remove.

parse(text) -> [Cmd]: the simple commands and loop keywords of text, in textual order, read
from the shared quote mask (hooks/quote_mask.py, live=True and a word-keeping fill), which also
reads heredoc bodies (a body fed to a bare shell is named to it as code). Each Cmd carries
  words      [(raw, value)] from its command word on, wrappers (sudo, timeout, env, ...),
             leading assignments and leading redirections resolved away;
  seg_words  every word of its segment, leading redirections included (`> s.sh cat` and a
             bare `> s.sh` name their target BEFORE any command word);
  name       basename of the command word;
  codes      strings it hands a shell to run (`bash -c`, `eval`, `env -S`, herestrings and
             heredocs fed to a bare shell, `echo|printf ... | bash`, a heredoc or herestring a
             stdin copier such as `cat` pipes to one, and the programs of handed_code():
             `flock -c`, `su -c`, `watch`, `script -c`, `trap`, `tmux`, an `at`/`batch` job,
             find's -exec clauses, `parallel`, sg/newgrp, git's -x/foreach/run/filters, ssh to
             this host, the keys `screen -X stuff` types (screen_x_codes()) and fish's
             -C/--init-command code; where GNU parallel puts what it reads on stdin is
             parallel_stdin());
  pipe, pos, sep, kw as block-unsafe-kill.sh reads them.

A text the shared mask cannot read at its own length raises quote_mask.MaskMismatch (re-exported
here) out of parse(), join_lines() and code_heredocs(); every caller refuses the call it was
judging, saying it could not read it, rather than reading "no commands" and allowing it
(hooks/tests/INVARIANTS.md `mh-the-mask-is-its-inputs-length-or-the-call-is-refused`).
"""
import fnmatch, os, re, shlex, socket
from quote_mask import mask_quoted, heredocs, continuations, substitutions, MaskMismatch  # noqa: F401
from quote_mask import backtick_code, joined


FILL = "\x01"          # a masked character that is still part of a word (quote_mask `fill`)
# EVERY PROGRAM THAT IS A SHELL, not only the common five: `fish -c 'pkill -f X'`, tcsh, csh,
# rbash, yash and posh run code too. The registries are the host's /etc/shells and the Debian
# archive's `shells` section; hooks/tests/test-pattern-keyed-kill-every-shell-and-consumer.py
# derives both and fails on a member that is neither here nor stated out there. A shell's -c
# operand is read as shell code (a lister and a kill in a shell that is not bash are refused by
# words, unseen_route()).
SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "mksh", "ash", "rbash", "rzsh", "bash-static",
          "zsh-static", "mksh-static", "lksh", "ksh93", "pdksh", "oksh", "loksh", "posh", "yash",
          "fish", "fizsh", "tcsh", "csh", "bsd-csh", "rc", "es", "sash", "elvish", "xonsh",
          "rush", "osh", "ysh"}
# Options of a shell that take an argument, where they differ from bash's (`fish -p FILE`; bash's
# -p takes none).
SHELL_ARG = {"fish": {"-C", "--init-command", "-d", "--debug", "-o", "--debug-output", "-p",
                      "--profile", "--profile-startup", "-f", "--features", "-D",
                      "--debug-stack-frames"}}
# The short options of a shell that take an argument, read in a cluster as the shell reads them,
# so `bash -euo pipefail -c 'pkill -f X'` and `bash -O extglob -c '...'` have their -c found. bash,
# dash and the ksh family take one word per such letter, in order, wherever it stands in the group
# (`-euo pipefail`, `-oO pipefail extglob`, `-co pipefail CODE`; checked against bash and dash),
# with +o/+O alike. fish parses with getopt: its letter takes the rest of the word when there is
# one (`-c'CODE'`), else the next word. bash's -O is its shopt (bash(1)); mksh's -T takes a tty
# (mksh(1)); bash's -T is a flag, so the default is bash's own set.
SHELL_ARG_LETTERS = {"fish": "cCdDfop", "mksh": "oT", "mksh-static": "oT", "lksh": "oT"}
GETOPT_SHELLS = {"fish"}
RESERVED = {"!", "{", "}", "if", "then", "elif", "else", "fi", "while", "until", "do", "done",
            "for", "select", "case", "esac", "time", "function"}

# Wrappers that run their operand as a command: (options taking an argument, operands to skip).
WRAPPERS = {
    "sudo": ({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "timeout": ({"-s", "-k"}, 1),
    "env": ({"-u", "-C"}, 0),
    "nice": ({"-n"}, 0),
    "ionice": ({"-c", "-n"}, 0),
    "nohup": (set(), 0), "setsid": (set(), 0), "builtin": (set(), 0), "time": ({"-f"}, 0),
    "exec": ({"-a"}, 0), "command": (set(), 0), "unbuffer": (set(), 0), "chronic": (set(), 0),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "xargs": ({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"}, 0),
    "taskset": ({"-p"}, 1), "flock": ({"-w", "-E"}, 1),
}
WRAPPERS["env"][0].update({"-a"})

# EVERY PROGRAM THAT RUNS ITS OPERANDS AS A COMMAND, not a list of names somebody had met
# (`chroot / pkill -f X`, `systemd-run pkill -f X`, `docker exec C pkill -f X`). The rule is the man
# page's SYNOPSIS: a program whose synopsis ends `COMMAND [ARG]...` (or `program [arguments]`)
# execs its trailing operands, and is a wrapper here, with the options its page says take an
# argument. Derived by scanning installed man1/man8 SYNOPSIS lines and reading each hit's page
# (the scanning script is original only); a hit that is a subcommand dispatcher (docker, gpg, go,
# virsh) is not a wrapper, save `docker|podman exec` (resolve()). Stated out, with the reason in
# hooks/tests/INVARIANTS.md mh-code-handed-to-a-shell-is-code: a fresh container (`docker run`,
# systemd-nspawn), whose pid namespace holds only what it starts; bwrap, pasta and perf, whose
# option grammars this table does not carry.
WRAPPERS.update({
    "chroot": (set(), 1),
    "chrt": ({"-T", "-P", "-D"}, 1),
    "nsenter": ({"-t", "-N", "-W"}, 0),
    "unshare": ({"-l", "-R", "-w", "-S", "-G"}, 0),
    "setpriv": (set(), 0),
    "prlimit": ({"-p", "-o"}, 0),
    "setarch": (set(), 0), "linux32": (set(), 0), "linux64": (set(), 0), "i386": (set(), 0),
    "x86_64": (set(), 0),
    "choom": ({"-n", "-p"}, 0),
    "uclampset": ({"-m", "-M", "-p"}, 0),
    "runcon": ({"-u", "-r", "-t", "-l"}, 0),
    "systemd-run": ({"-u", "-p", "-E", "-M", "-H"}, 0),
    "run0": ({"-u", "-g", "-D"}, 0),
    "systemd-inhibit": (set(), 0),
    "systemd-cat": ({"-t", "-p"}, 0),
    "dbus-run-session": ({"--config-file", "--dbus-daemon"}, 0),
    "nocache": ({"-n"}, 0), "fstab-decode": (set(), 0), "busybox": (set(), 0),
    "fakeroot": ({"-l", "-i", "-s", "-b"}, 0),
    "trickle": ({"-d", "-u", "-w", "-t", "-l", "-n", "-L", "-P"}, 0),
    "sshpass": ({"-f", "-d", "-p", "-P"}, 0),
    "strace": ({"-a", "-b", "-e", "-E", "-I", "-o", "-O", "-p", "-P", "-s", "-S", "-u", "-U",
                "-X"}, 0),
    # `screen [-opts] [cmd [args]]`: `screen -dm pkill -f X` runs its command. An option letter
    # takes its argument from the rest of its word or the next one (`-dmS NAME`), as every
    # wrapper's cluster does; `-X CMD` sends CMD to a session, read as the command it names (`-X
    # exec pkill -f X`).
    "screen": ({"-c", "-e", "-h", "-p", "-S", "-T", "-t", "-s", "-Logfile"}, 0),
})


def _cluster_words(v, argopts):
    """The words a short-option cluster v (`-dmS`, `-iu`) spans: 2 when its last option letter
    takes an argument and nothing of v follows it, else 1 -- as getopt reads `-dmS NAME`."""
    for k, ch in enumerate(v[1:]):
        if "-" + ch in argopts:
            return 1 if k + 2 < len(v) else 2
    return 1


# EVERY WRAPPER'S LONG OPTIONS, AS ITS getopt_long READS THEM. getopt_long takes any unambiguous
# prefix of a long option, `--opt ARG` as well as `--opt=ARG`, and an optional argument only
# after `=`, so `timeout --sig KILL 5 pkill -f X` runs pkill (KILL is the signal, not the
# duration) and `xargs --replace pkill -f X` runs it too (--replace, like --max-lines and --eof,
# takes an OPTIONAL argument). Each name below is followed by `=` when it takes an argument, `?`
# when it takes an optional one, nothing when it takes none; the full set is kept, flags
# included, because a prefix is ambiguous over all of them.
# MEASURED, NOT COPIED (the PROBE of hooks/tests/test-wrapper-long-option-abbreviations.py, which
# measures again and fails on any difference): each installed wrapper was asked inside
# hooks/tests/bash_oracle.py's namespace, by its own diagnostics, what each name in its --help takes
# (`--NAME=x`: "doesn't allow an argument"; `--NAME`: "requires an argument"); `--c` for every
# letter c named what its help leaves out (flock --wait and --nonblocking, strace --signals, time
# --output-file, unshare --map-subids, ...); and a shared prefix it took without "ambiguous" marks
# an alias group, `a|b`, one option to glibc (setpriv --nnp|--no-new-privs). sudo, run0, systemd-run
# and systemd-inhibit are --help rows: running them starts units or asks for authentication. Not
# here, read in full only: the wrappers that parse no long option by getopt_long (dbus-run-session's
# own parser takes no prefix; doas, screen, unbuffer, chronic, nocache, sshpass, trickle, busybox
# and the builtins take no long option at all).
WRAPPER_LONG = {
    "choom": "adjust= help pid= version",
    "chroot": "groups= help skip-chdir userspec= version",
    "chrt": "all-tasks batch deadline fifo help idle max other pid reset-on-fork rr"
            " sched-deadline= sched-period= sched-runtime= verbose version",
    "env": "argv0= block-signal? chdir= debug default-signal? help ignore-environment"
           " ignore-signal? list-signal-handling null split-string= unset= version",
    "fakeroot": "faked= fd-base= help lib= unknown-is-real version",
    "flock": "close conflict-exit-code= exclusive fcntl help no-fork nonblock|nonblocking shared"
             " timeout= unlock verbose version wait=",
    "i386": "addr-compat-layout addr-no-randomize fdpic-funcptrs help mmap-page-zero"
            " read-implies-exec short-inode show? sticky-timeouts uname-2.6 verbose version"
            " whole-seconds",
    "ionice": "class= classdata= help ignore pgid= pid= uid= version",
    "linux32": "addr-compat-layout addr-no-randomize fdpic-funcptrs help mmap-page-zero"
               " read-implies-exec short-inode show? sticky-timeouts uname-2.6 verbose version"
               " whole-seconds",
    "linux64": "addr-compat-layout addr-no-randomize fdpic-funcptrs help mmap-page-zero"
               " read-implies-exec short-inode show? sticky-timeouts uname-2.6 verbose version"
               " whole-seconds",
    "nice": "adjustment= help version",
    "nohup": "help version",
    "nsenter": "all cgroup? env follow-context help ipc? join-cgroup keep-caps mount? net?"
               " net-socket= no-fork pid? preserve-credentials root? setgid= setuid= target= time?"
               " user? user-parent uts? version wd? wdns?",
    "prlimit": "as? core? cpu? data? fsize? help locks? memlock? msgqueue? nice? nofile?"
               " noheadings nproc? output= pid= raw rss? rtprio? rttime? sigpending? stack?"
               " verbose version",
    "run0": "background= chdir= description= group= help machine= nice= no-ask-password pipe"
            " property= pty setenv= shell-prompt-prefix= slice= slice-inherit unit= user= version",
    "runcon": "compute help range= role= type= user= version",
    "setarch": "addr-compat-layout addr-no-randomize fdpic-funcptrs help list mmap-page-zero"
               " read-implies-exec short-inode show? sticky-timeouts uname-2.6 verbose version"
               " whole-seconds",
    "setpriv": "ambient-caps= apparmor-profile= bounding-set= clear-groups dump egid= euid="
               " groups= help inh-caps= init-groups keep-groups landlock-access= landlock-rule="
               " list-caps nnp|no-new-privs pdeathsig= ptracer= regid= reset-env reuid= rgid="
               " ruid= seccomp-filter= securebits= selinux-label= version",
    "setsid": "ctty fork help version wait",
    "stdbuf": "error= help input= output= version",
    "strace": "abbrev= absolute-timestamps? always-show-pid argv0= attach= columns="
              " const-print-style= daemonised|daemonize|daemonized? debug decode-fds? decode-pids="
              " detach-on= env= failed-only|failing-only fault= follow-forks help inject="
              " instruction-pointer interruptible= kill-on-exit kvm= no-abbrev output="
              " output-append-mode output-separately pidns-translation quiet? raw= read="
              " relative-timestamps? seccomp-bpf secontext? signal|signals= silence|silent?"
              " stack-trace? stack-trace-frame-limit= stack-traces? status= string-limit="
              " strings-in-hex? successful-only summary summary-columns= summary-only"
              " summary-sort-by= summary-syscall-overhead= summary-wall-clock syscall-limit="
              " syscall-number syscall-times? timestamps? tips? trace= trace-fds= trace-path="
              " user= verbose= version write=",
    "sudo": "askpass background bell chdir= chroot= close-from= command-timeout= edit group= help"
            " host= list login non-interactive other-user= preserve-env? preserve-groups prompt="
            " remove-timestamp reset-timestamp role= set-home shell stdin type= user= validate"
            " version",
    "systemd-cat": "help identifier= level-prefix= namespace= priority= stderr-priority= version",
    "systemd-inhibit": "help list mode= no-ask-password no-legend no-pager version what= who="
                       " why=",
    "systemd-run": "background= collect description= expand-environment= gid= help host="
                   " ignore-failure json= machine= nice= no-ask-password no-block on-active="
                   " on-boot= on-calendar= on-clock-change on-startup= on-timezone-change"
                   " on-unit-active= on-unit-inactive= path-property= pipe property= pty quiet"
                   " remain-after-exit same-dir scope send-sighup service-type= setenv= shell"
                   " slice= slice-inherit socket-property= timer-property= uid= unit= user version"
                   " wait working-directory=",
    "taskset": "all-tasks cpu-list help pid version",
    "time": "append format= help output|output-file= portability quiet verbose version",
    "timeout": "foreground help kill-after= preserve-status signal= verbose version",
    "uclampset": "all-tasks help pid= reset-on-fork system verbose version",
    "unshare": "boottime= cgroup? fork help ipc? keep-caps kill-child? load-interp= map-auto"
               " map-current-user map-group= map-groups= map-root-user map-subids map-user="
               " map-users= monotonic= mount? mount-binfmt? mount-proc? net? pid? propagation="
               " root= setgid= setgroups= setuid= time? user? uts? version wd=",
    "x86_64": "addr-compat-layout addr-no-randomize fdpic-funcptrs help mmap-page-zero"
              " read-implies-exec short-inode show? sticky-timeouts uname-2.6 verbose version"
              " whole-seconds",
    "xargs": "arg-file= delimiter= eof? exit help interactive max-args= max-chars= max-lines?"
             " max-procs= no-run-if-empty null open-tty process-slot-var= replace? show-limits"
             " verbose version",
}


def _long_table(spec):
    """{"--name": (kind, the name of its option)} from a WRAPPER_LONG string."""
    out = {}
    for tok in spec.split():
        names = tok.rstrip("=?")
        group = ["--" + n for n in names.split("|")]
        out.update((n, (tok[len(names):], group[0])) for n in group)
    return out


# THE LONG OPTIONS OF THE PROGRAMS THAT HAND A STRING TO A SHELL, read by handed_code() and
# _shell_read() through long_option(), in the same notation, so `su --comm 'pkill -f X'`, `script
# --comm '...'`, `sg adm --comm '...'` and `git rebase --exe '...'` have their code read.
# MEASURED where it can be run unprivileged (hooks/tests/test-handed-code-long-option-prefixes.py
# measures again, with the PROBE of test-wrapper-long-option-abbreviations.py, and fails on any
# difference): script, sg, newgrp, watch, and runuser (whose getopt diagnostics come before its
# root check). su is the same util-linux binary as runuser (su-common.c, one getopt_long table;
# su refuses --user after parsing it) and is setuid, so its row is runuser's and was not run.
# git-rebase is `git rebase --git-completion-helper-all` (parse-options, which takes a unique
# prefix: `--ex` is --exec, `--e` is ambiguous). fish's row is fish's own documented getopt_long
# table (fish.rs LONG_OPTS, wgetopt a port of GNU getopt_long), not run.
# Not here, read in full because the program reads them in full: bash's long options (`bash --rcf`
# is an invalid option), flock's `FILE -c|--command` (a strcmp of the word after FILE; `flock F
# --comm` executes `--comm`), git's global options and `submodule`/`filter-branch` (shell `case`).
_SU_LONG = ("command= fast group= help login no-pty preserve-environment pty session-command="
            " shell= supp-group= user= version whitelist-environment=")
HANDED_LONG = {
    "su": _SU_LONG, "runuser": _SU_LONG,
    "script": "append command= echo= flush force help log-in= log-io= log-out= log-timing="
              " logging-format= output-limit= quiet return timing? version",
    "sg": "command= help version", "newgrp": "command= help version",
    "watch": "beep chgexit color differences? equexit= errexit exec help interval= no-color"
             " no-rerun no-title no-wrap precise version",
    "fish": "command= debug= debug-output= debug-stack-frames= features= help init-command="
            " interactive login no-config no-execute print-debug-categories print-rusage-self"
            " private profile= profile-startup= version",
    "git-rebase": "abort allow-empty-message apply autosquash autostash committer-date-is-author-date"
                  " continue edit-todo empty= exec= ff force-rebase fork-point gpg-sign ignore-date"
                  " ignore-whitespace interactive keep-base keep-empty merge no-allow-empty-message"
                  " no-autosquash no-autostash no-committer-date-is-author-date no-exec no-ff"
                  " no-force-rebase no-fork-point no-gpg-sign no-ignore-date no-ignore-whitespace"
                  " no-keep-base no-keep-empty no-onto no-preserve-merges no-quiet"
                  " no-reapply-cherry-picks no-rebase-merges no-reschedule-failed-exec"
                  " no-rerere-autoupdate no-reset-author-date no-root no-signoff no-stat"
                  " no-strategy no-strategy-option no-update-refs no-verbose no-verify no-whitespace"
                  " onto= preserve-merges quiet quit reapply-cherry-picks rebase-merges"
                  " reschedule-failed-exec rerere-autoupdate reset-author-date root"
                  " show-current-patch signoff skip stat strategy= strategy-option= update-refs"
                  " verbose verify whitespace=",
}

LONG_OPTS = {w: _long_table(spec) for w, spec in {**WRAPPER_LONG, **HANDED_LONG}.items()}


def long_option(v, prog):
    """(name, kind) for the long-option word v as prog's getopt_long reads it (LONG_OPTS): name
    is the full name of the option v is (an exact name wins) or is the only prefix of, an alias
    group's first name for any of the group; kind is '' when it takes no argument, '=' when it
    takes one (the next word unless v holds `=`), '?' when it takes an optional one (after `=`
    only). (None, None) when v names no option or is a prefix of several: prog refuses it and
    runs nothing. A prefix of an alias group's names (`setpriv --n`: --nnp, --no-new-privs;
    measured, as glibc takes them as one) is no ambiguity."""
    table, name = LONG_OPTS.get(prog, {}), v.partition("=")[0]
    hits = {table[name]} if name in table else {table[o] for o in table if o.startswith(name)}
    return hits.pop()[::-1] if len(hits) == 1 else (None, None)


def long_code(words, i, prog, names):
    """For the long-option word words[i] of prog, read by long_option(): (the code it hands a shell
    when it is one of `names`, the full names of prog's code-taking options, else None; the index
    after it and its argument). An unknown or ambiguous name is one word: prog refuses it."""
    v = words[i][1]
    opt, kind = long_option(v, prog)
    if "=" in v:
        return (v.split("=", 1)[1] if opt in names else None), i + 1
    if opt in names:
        return (words[i + 1][1] if i + 1 < len(words) else ""), i + 2
    return None, i + (2 if kind == "=" else 1)


def env_long(v):
    """v with its long-option name spelled in full, as env's getopt_long reads it; None when the
    name is no option or an ambiguous prefix (env refuses it and runs nothing)."""
    name, _ = long_option(v, "env")
    return name and name + v[len(v.partition("=")[0]):]


def opt_words(base, words, i):
    """How many words the option word words[i] of wrapper `base` spans, 1 or 2, as `base` reads
    it: a long option by its getopt_long grammar (LONG_OPTS), else by the WRAPPERS row -- an option
    taking an argument and no `=`, or a short cluster whose last letter takes one (`-dmS NAME`).
    An unknown or ambiguous long option is read as one word: the wrapper refuses it."""
    v, argopts = words[i][1], WRAPPERS[base][0]
    if v.startswith("--") and base in LONG_OPTS:
        _, kind = long_option(v, base)
        return 2 if kind == "=" and "=" not in v else 1
    if v in argopts and "=" not in v:
        return 2
    if not v.startswith("--") and len(v) > 2:
        return _cluster_words(v, argopts)
    return 1


def _env_split(v, argopts):
    """The string env's -S takes from the word v ('' when it is the next word), or None when v
    is no -S: `-S`, `-SSTR`, `--split-string[=STR]`, and -S inside a cluster (`-vS`, `-iS`).
    A long option is spelled in full first (env_long())."""
    if v == "--split-string":
        return ""
    if v.startswith("--split-string="):
        return v.split("=", 1)[1]
    if v.startswith("-") and not v.startswith("--"):
        for k, ch in enumerate(v[1:]):
            if ch == "S":
                return v[k + 2:]
            if "-" + ch in argopts:          # `-uS`: S is the name -u unsets
                return None
    return None


def _sudo_shell(v, argopts):
    """Whether the sudo option word v runs its command through a shell: -s/--shell or -i/--login,
    alone or in a cluster before any letter that takes an argument (`-Es`, `-si`, not `-us`)."""
    if v in ("--shell", "--login"):
        return True
    if v.startswith("-") and not v.startswith("--"):
        for ch in v[1:]:
            if ch in "si":
                return True
            if "-" + ch in argopts:
                return False
    return False


# An option that sends the command to ANOTHER host: out of this guard's purpose (the processes of
# this host), so the program runs nothing here that it can read.
REMOTE_OPTS = {"systemd-run": ("-H", "--host")}

# `docker|podman [GLOBAL] exec|container exec [OPTS] CONTAINER COMMAND [ARG...]` runs argv in a
# container that is already running on this host -- processes of this host, and a pattern kill there
# can match the container's own shell as it matches ours. A daemon reached at a remote -H/--url is
# another host's.
CTR_GLOBAL_ARG = {"--config", "-c", "--context", "-H", "--host", "-l", "--log-level", "--tlscacert",
                  "--tlscert", "--tlskey", "--connection", "--url", "--identity", "--root",
                  "--runroot", "--runtime", "--runtime-flag", "--storage-driver", "--storage-opt",
                  "--tmpdir", "--cgroup-manager", "--conmon", "--events-backend", "--hooks-dir",
                  "--module", "--network-cmd-path", "--network-config-dir", "--imagestore",
                  "--volumepath", "--out", "--ssh"}
CTR_EXEC_ARG = {"-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys",
                "--preserve-fd", "--preserve-fds"}

# moreutils `parallel [OPTS] COMMAND -- ARGS` runs COMMAND as argv (Debian's default `parallel`);
# GNU `parallel [OPTS] COMMAND ::: ARGS` (and with no separator, reading its arguments on stdin)
# hands the command line to a shell. With no COMMAND, each operand after `--` (moreutils) or
# `:::` (GNU) is itself run by `sh -c`, and GNU reads one command per line of stdin.
PAR_SEPS = {":::", "::::", ":::+", "::::+"}
PAR_ARG = {"-j", "-l", "-n", "-a", "-d", "-E", "-I", "-L", "-N", "-P", "-S", "-C", "--jobs",
           "--arg-file", "--delimiter", "--max-args", "--max-lines", "--sshlogin", "--colsep",
           "--joblog", "--results", "--tmpdir", "--timeout", "--delay", "--tagstring", "--workdir",
           "--basefile", "--return", "--transferfile", "--env", "--memfree", "--load", "--retries",
           "--nice", "--block", "--rpl", "--termseq", "--sshloginfile", "--slf", "--limit",
           "--arg-sep", "--arg-file-sep", "--header", "--semaphorename", "--id",
           "--er", "--extensionreplace", "--bnr", "--basenamereplace", "--dnr", "--dirnamereplace",
           "--bner", "--basenameextensionreplace", "--seqreplace", "--slotreplace"}


def _parallel(words, i):
    """For a `parallel` at words[i]: (start, end, sep) of its COMMAND words [start, end) and the
    separator word that ends them (None at the end of the command)."""
    j = i + 1
    while j < len(words):
        r = REDIR.match(words[j][0])
        if r:                                # `parallel <<< CMDS`: a redirection is no command
            j += 1 if r.group(2) else 2; continue
        v = words[j][1]
        if v in PAR_SEPS or v == "--" or not v.startswith("-") or v == "-":
            break
        j += 2 if (v in PAR_ARG and "=" not in v) else 1
    end = next((k for k in range(j, len(words)) if words[k][1] in PAR_SEPS | {"--"}), len(words))
    return j, end, (words[end][1] if end < len(words) else None)


# WHERE GNU PARALLEL PUTS WHAT IT READS ON STDIN. With a COMMAND and no `:::`/`::::` source and no
# `-a FILE` (or with one of them `-`), GNU parallel(1) reads its arguments on stdin and puts each
# where the command template holds a replacement string, or APPENDS it when the template holds
# none; with `--pipe` the input goes to each job's stdin instead, so `pgrep -f X | parallel 'kill
# {}'` is a kill of the lister's pids.
# Replacement strings: `{= perl =}`, any `{...}` with no blank in it (`{}`, `{.}`, `{/}`, `{1/.}`,
# --plus's forms) save the counters `{#}`, `{%}`, `{##}`, and the strings -I/-i/--replace, --er,
# --bnr, --dnr, --bner and --rpl's tag define. Read wide on purpose: a `{//}` (a pid's dirname is
# `.`) or a brace word in the template is taken for one, which can only refuse more.
PAR_DEFINES = {"-I", "--er", "--extensionreplace", "--bnr", "--basenamereplace", "--dnr",
               "--dirnamereplace", "--bner", "--basenameextensionreplace"}
PAR_REPL = re.compile(r"\{=.*?=\}|(?<!\$)\{(?!#\}|%\}|##\})[^\s{}]*\}", re.S)


def _squoted(s):
    """For each offset of s, whether it lies inside '...' (or $'...') as bash quotes it."""
    out, q, i = [False] * len(s), None, 0
    while i < len(s):
        ch = s[i]
        if q == "'":
            out[i] = ch != "'"
            q = None if ch == "'" else q
        elif ch == "\\":
            i += 2; continue
        elif q is None and ch == "'":
            q = "'"
        elif ch == '"':
            q = None if q == '"' else '"'
        i += 1
    return out


def parallel_stdin(words):
    """For a GNU `parallel` at words[0] with a COMMAND that reads stdin (the block above): (its
    command line, [(start, end, in '...')] of each replacement string in it, piped) -- piped when
    `--pipe` sends the input to each job's stdin. None when stdin is not its input."""
    if not words or os.path.basename(words[0][1]) != "parallel":
        return None
    j, end, sep = _parallel(words, 0)
    if j >= end or sep == "--":              # no command, or moreutils' `CMD -- ARGS`
        return None
    opts = [v for _, v in words[1:j]]
    stdin, defined, piped = sep is None, [], False
    for k, v in enumerate(opts):
        name, eq, arg = v.partition("=")
        nxt = opts[k + 1] if k + 1 < len(opts) else ""
        if name in ("-a", "--arg-file"):
            stdin = (arg if eq else nxt) == "-"
        elif v.startswith("-a") and len(v) > 2:
            stdin = v[2:] == "-"
        elif v in ("--pipe", "--spreadstdin"):
            piped = True
        elif name in PAR_DEFINES:
            defined.append(arg if eq else nxt)
        elif v.startswith("-I") and len(v) > 2:
            defined.append(v[2:])
        elif name in ("--replace", "-i"):
            defined.append(arg if eq else "{}")
        elif v.startswith("-i") and len(v) > 2:
            defined.append(v[2:])
        elif v == "--rpl" and nxt.split():
            defined.append(nxt.split()[0])
    k, src = end, None                       # `:::: -` (or `::::+ -`) reads stdin as a source
    while k < len(words):
        v = words[k][1]
        if v in PAR_SEPS:
            src = v
        elif v == "-" and src in ("::::", "::::+"):
            stdin = True
        k += 1
    if not stdin:
        return None
    parts, k = [], j
    while k < end:                           # its command words, redirections left out
        r = REDIR.match(words[k][0])
        if r:
            k += 1 if r.group(2) else 2; continue
        parts.append(words[k][1]); k += 1
    line = " ".join(parts)
    spans = [m.span() for m in PAR_REPL.finditer(line)]
    for s in filter(None, defined):
        spans += [(m.start(), m.start() + len(s)) for m in re.finditer(re.escape(s), line)]
    sq, kept, last = _squoted(line), [], -1
    for a, b in sorted(spans):
        if a >= last:
            kept.append((a, b, sq[a])); last = b
    return line, kept, piped


def _container_exec(words, i):
    """For a `docker`/`podman` at words[i]: the index of the command an `exec` runs, -1 when the
    daemon is another host's, None when it is not an exec."""
    j, n = i + 1, len(words)
    while j < n and words[j][1].startswith("-") and words[j][1] != "-":
        v = words[j][1]
        name, eq, arg = v.partition("=")
        if name in ("-H", "--host", "--url", "--connection") or v in ("-r", "--remote") or (
                name == "-c" and os.path.basename(words[i][1]) == "podman"):
            arg = arg if eq else (words[j + 1][1] if j + 1 < n else "")
            if not arg.startswith(("unix://", "fd://")):
                return -1
        j += 2 if (name in CTR_GLOBAL_ARG and not eq) else 1
    if j < n and words[j][1] == "container":
        j += 1
    if j >= n or words[j][1] != "exec":
        return None
    j, latest = j + 1, False
    while j < n and words[j][1].startswith("-") and words[j][1] != "-":
        v = words[j][1]
        if v == "--":
            j += 1; break
        latest |= v in ("-l", "--latest")
        j += 2 if (v in CTR_EXEC_ARG and "=" not in v) else 1
    return j + (0 if latest else 1)

# `<(...)` and `>(...)` are process substitutions, words of their own (parse() keeps one whole):
# a redirection is `<` or `>` followed by anything but that `(`. Its fd is a word of digits or a
# `{NAME}` (bash allocates the fd and binds NAME to it); `&>` takes none.
REDIR = re.compile(r"^(?:(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})(?!&))?(<<<|<<-?|<>|>>|>\||<&|>&|&>>|&>|<(?!\()|>(?!\())(.*)$",
                   re.S)
# The `|` of `>|` is the operator's, not a pipe.
SEP = re.compile(r"\|\||&&|\|&|;;|(?<![<>])&(?!>)|[;()\n`]|(?<!>)\|")
# A redirection operator as it starts inside a word of the mask (longest first).
REDIR_OP = re.compile(r"&>>|&>|<<<|<<-|<<|<>|<&|<|>>|>\||>&|>")
FD_WORD = re.compile(r"\d+|\{[A-Za-z_][A-Za-z0-9_]*\}")

# A producer's own option word, which is NOT part of what it writes to stdout: bash's `echo`
# accepts -n/-e/-E and any combination of those letters before its first operand.
ECHO_OPT = re.compile(r"^[-+]([nEe]*)$")
# A printf conversion spec: %[flags][width][.precision][length]conv. group(1) is the precision
# digits (for a `%.Ns` truncation), group(2) the conversion letter.
PRINTF_CONV = re.compile(r"%[-+ #0*]*(?:[0-9]+|\*)?(?:\.(\d+)|\.\*)?(?:hh|h|ll|l|j|z|t|L)?"
                         r"([diuoxXefgGaAcsbq%])")


def unresolved(raw):
    """A word whose value is only known when the shell runs it."""
    if raw.startswith("'") and raw.endswith("'") and len(raw) > 1:
        return False
    return "$" in raw or "`" in raw


ANSI_ESC = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
            "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


# $'...' numeric escapes, by bash(1) QUOTING: \nnn (one to three octal digits), \xHH (one or two
# hex digits), \uHHHH and \UHHHHHHHH (one to four and one to eight), \cx, control-x, and
# \x{H...} (every hex digit up to a `}`, the low byte kept).
ANSI_NUM = re.compile(r"([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|c([^'])|x\{([0-9A-Fa-f]*)\}?", re.S)


def u32_to_utf8(cp):
    """The text a `\\u`/`\\U` escape with code point cp decodes to in a UTF-8 locale: bash's
    u32toutf8() (lib/sh/unicode.c), which encodes every value below 0x80000000 in the original
    UTF-8 scheme -- a surrogate in 3 bytes, 0x110000..0x1FFFFF in 4, then 5 and 6 bytes -- and
    gives nothing at all from 0x80000000 up. Bytes that are not UTF-8 are held as surrogate
    escapes, as a byte escape's are: so `$'\\UFFFFFFFF'pkill -f X`, which bash runs as `pkill -f
    X`, is read as pkill (mh-a-words-value-is-bash-quote-removal)."""
    for top, lead, n in ((0x80, 0x00, 0), (0x800, 0xC0, 1), (0x10000, 0xE0, 2),
                         (0x200000, 0xF0, 3), (0x4000000, 0xF8, 4), (0x80000000, 0xFC, 5)):
        if cp < top:
            tail = [0x80 | (cp >> 6 * k) & 0x3F for k in range(n - 1, -1, -1)]
            return bytes([lead | cp >> 6 * n] + tail).decode("utf-8", "surrogateescape")
    return ""


def ansi_escape(raw, i):
    """(the text the $'...' escape at raw[i] (a backslash) decodes to, the index after it). A
    byte escape (octal, \\x) runs on into the bytes after it, so `\\xc3\\xa9` is one character, as
    bash prints it; an escape bash does not know is kept, backslash and all, so `eval $'kill
    \\x24(pgrep -f X)'` hands on `kill $(pgrep -f X)`. The braced `\\x{HH}` takes every hex digit
    up to a `}` and keeps the low byte, as bash does (`\\x{24}` is `$`, `\\x{263a}` is `:`)."""
    e = raw[i + 1]
    if e in ANSI_ESC:
        return ANSI_ESC[e], i + 2
    if e == "c" and raw[i + 2:i + 3] == "\\":
        # \c then a backslash is control-backslash, and bash's decoder (strtrans.c) takes the
        # backslash that follows it as well when there is one: `\c\\` is one character, 0x1c,
        # and `\c\x41` is 0x1c then `x41`. The scanner paired `\'` before decoding, so after a
        # lone `\c\` a quote is text.
        nxt = raw[i + 3:i + 4]
        if nxt in ("\\", "'"):
            return "\x1c" + ("'" if nxt == "'" else ""), i + 4
        return "\x1c", i + 3
    m = ANSI_NUM.match(raw, i + 1)
    if not m:
        return "\\" + e, i + 2
    if m.group(5) is not None:
        # \cx works on the BYTE after \c (strtrans.c, TOCTRL): a character of more than one byte
        # gives the control character of its first byte, and its other bytes follow as they are,
        # so under a UTF-8 locale `\cé` is 0x03 then the lone byte 0xa9.
        ch = m.group(5)
        if ch == "?":
            return "\x7f", m.end()
        b = ch.encode("utf-8", "surrogateescape")
        lead = b[:1].upper()[0] & 0x1f
        return chr(lead) + b[1:].decode("utf-8", "surrogateescape"), m.end()
    if m.group(3) or m.group(4):
        return u32_to_utf8(int(m.group(3) or m.group(4), 16)), m.end()
    out, j = bytearray(), i
    while True:
        out.append(int(m.group(1), 8) & 0xFF if m.group(1) else int(m.group(2), 16)
                   if m.group(2) else int(m.group(6) or "0", 16) & 0xFF)
        j = m.end()
        if raw[j:j + 1] != "\\":
            break
        m = ANSI_NUM.match(raw, j + 1)
        if not m or m.group(1) is None and m.group(2) is None and m.group(6) is None:
            break
    return out.decode("utf-8", "surrogateescape"), j


def unquote(raw, drop=False, seen=None):
    """The value of the word raw after bash's quote removal: '...' is literal, a backslash
    unquoted escapes any character, inside "..." (and $"...") only $ ` " \\ and a newline, and
    $'...' decodes its escapes. A `$(...)`, `<(...)`, `>(...)` or backtick substitution is kept as
    written, being code the shell runs, not quoted text. Not shlex.split(), which keeps the
    backslash of `\\$` inside "...", so that `eval "P=\\$(pgrep X)"` would hand on the literal
    string `P=\\$(pgrep X)` where bash runs a substitution. An unclosed quote runs to the end of
    the word.

    With drop, every substitution and parameter expansion is left out instead (what the word is
    when each expands to nothing), and seen, a list, is given a True for anything else the word
    holds -- a literal character or a quote, either of which keeps it a word (command_word())."""
    found = substitutions(raw)
    subs = {s["open"]: s["body"][1] for s in found if s["kind"] in ("cmd", "proc")}
    # A backtick substitution inside "..." is kept as the code it is OUTSIDE them: bash removes
    # the backslash of a `\"` in its body there (backtick_code()), and nowhere else, so the kept
    # text drops it: `eval "`printf %s \"pkill -f X\"`"` hands on code that runs pkill -f X.
    dq_ticks = {s["open"] for s in found if s.get("dq")}
    if drop:                                   # `$((...))`, from its `$` through its `))`
        subs.update({s["open"] - 1: s["body"][1] + 1 for s in found
                     if s["kind"] == "arith" and s["open"] and raw[s["open"] - 1] == "$"})
    out, i, n, quote = [], 0, len(raw), None
    while i < n:
        c = raw[i]
        if i in subs and quote in (None, '"'):
            end = min(subs[i] + 1, n)          # through its closing `)` or backtick
            if not drop:
                out.append(re.sub(r'\\(["\\$`])', lambda m: m.group(1) if m.group(1) == '"'
                                  else m.group(0), raw[i:end]) if i in dq_ticks else raw[i:end])
            i = end
            continue
        if drop and c == "$" and quote in (None, '"'):
            m = PARAM.match(raw, i)
            if m:
                i = m.end(); continue
        if seen is not None and quote is None:
            seen.append(True)
        if quote == "'":
            if c == "'":
                quote = None
            else:
                out.append(c)
            i += 1
        elif quote in ("$'", "$'nul"):
            # An escape that decodes to NUL (`\0`, `\x00`, `\c@`, `\x{}`...) ends the span's value,
            # as bash's C string ends there: `$'\0'"kill X"` is `kill X`. The rest of the span is
            # still read, escapes and all, to find its closing quote, so `eval $'\0'"kill \$(pgrep
            # -f X)"` hands on `kill $(pgrep -f X)`.
            if c == "'":
                quote = None; i += 1
            elif c == "\\" and i + 1 < n:
                got, i = ansi_escape(raw, i)
                if quote == "$'":
                    if "\x00" in got:
                        got, quote = got[:got.index("\x00")], "$'nul"
                    out.append(got)
            else:
                if quote == "$'":
                    out.append(c)
                i += 1
        elif quote == '"':
            if c == '"':
                quote = None; i += 1
            elif c == "\\" and i + 1 < n and raw[i + 1] in '$`"\\\n':
                out.append(raw[i + 1] if raw[i + 1] != "\n" else ""); i += 2
            else:
                out.append(c); i += 1
        elif c == "\\" and i + 1 == n:       # nothing to escape: bash keeps it, `a\` is a\
            out.append(c); i += 1
        elif c == "\\":
            out.append(raw[i + 1:i + 2] if raw[i + 1:i + 2] != "\n" else ""); i += 2
        elif c == "'":
            quote = "'"; i += 1
        elif c == '"':
            quote = '"'; i += 1
        elif c == "$" and raw[i + 1:i + 2] in ("'", '"'):
            quote = "$'" if raw[i + 1] == "'" else '"'; i += 2
        else:
            out.append(c); i += 1
    return "".join(out)


PARAM = re.compile(r"\$(?:\{[^}]*\}?|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])")


def command_word(raw):
    """(the name a command word runs when each expansion in it expands to nothing, whether the
    word can vanish). bash removes an unquoted word that expands to nothing and runs the next
    one: `$(true) kill $(pgrep -f X)` runs kill, and so does `$(true)kill`. A word whose value
    keeps a substitution's text (parse()) names no program by that text, so the name is read
    with the expansions left out, and a word of nothing but unquoted expansions is skipped by
    resolve() as bash may skip it."""
    seen = []
    return os.path.basename(unquote(raw, drop=True, seen=seen)), not seen


def name_of(words):
    return command_word(words[0][0])[0] if words else ""


class Cmd:
    def __init__(self, kw=None, words=(), pipe=0, pos=0):
        self.kw, self.pipe, self.pos = kw, pipe, pos
        self.words = list(words)            # [(raw, value)] from the command word on
        self.name = name_of(self.words)
        self.codes = []                     # strings this command runs as shell code
        self.sep = None                     # the separator before this simple command
        self.seg_words = list(words)        # every word of the segment (parse() sets it)
        self.at = None                      # the offset of its command word (parse() sets it)


def join_lines(text):
    """text with every line continuation removed, as bash removes it before it reads a word or an
    operator: `pk\\<NL>ill`, `sudo \\<NL>pkill`, a continuation standing alone, and one inside
    `&&`, `||`, `>>` or `;;` all read as their one-line form. Which pairs are continuations is the
    shared scanner's call (hooks/quote_mask.py, continuations()): one inside '...', a comment or
    a data heredoc body, or after an escaped backslash, stays literal.
    The pair is removed from the whole text BEFORE the separator scan, so `a &\\<NL>& b` reads as
    `a && b` and `ps aux |\\<NL>| kill 1` as `ps aux || kill 1`. Repeated because the first pass
    can misread what a pair joins (`bash \\<NL>-s <<EOF` names its body as code only once the two
    lines are one); a pass removes no pair it does not see (hooks/tests/INVARIANTS.md
    `mh-a-line-continuation-is-no-word`)."""
    return _joined(text, list(range(len(text))))[0]


def _joined(text, src):
    """(join_lines(text), the offsets src gives text's characters, kept for those it keeps): the
    shared join (quote_mask.joined()), its code bodies read from each pass's joined text."""
    return joined(text, src, lambda c, s: _code_bodies(c))


def tick_code(t, rec):
    """(the code bash runs for the backtick substitution rec of t, [the offset in t of each of its
    characters]): backtick_code() with every line continuation of that code removed, as bash
    removes it when it reads the code. De-escaping turns a written `\\\\<NL>` into `\\<NL>`, a
    continuation of the code that the text around the backtick reads as a literal backslash, so
    join_lines() over the whole text leaves it; so x=`bash \\\\<NL><<EOF<NL>kill \\\\\\$(pgrep -f
    X)<NL>EOF<NL>` names its code body and hands on the kill. Every caller of backtick_code() in
    this file reads it through here."""
    code, src = backtick_code(t, rec)
    return _joined(code, src)


def word_chars(seg):
    """seg (a mask, its substitutions already FILL) with every `${...}`, `$[...]` and arithmetic
    `$((...))` made FILL too: each is part of the word it sits in, whatever it holds, so no blank,
    separator or redirection operator inside one ends that word. A `$((` left in a mask whose
    closed command substitutions are filled is arithmetic once it closes; one that does not close
    is left to the separator scan, since a caller that fills only closed substitutions (the line
    prefix code_heredocs() reads) leaves `$(bash ` open there. A `${` or `$[` left open runs to the
    end of seg (bash reads on for its close and runs nothing without one). An arithmetic `$((...))`
    is not cut at its `(`, so `echo $((1)) pkill -f X` is one echo, not a command `pkill`."""
    out, i, n = list(seg), 0, len(seg)
    while i < n:
        if seg.startswith("$$", i):
            i += 2
            continue
        if seg.startswith(("${", "$[", "$(("), i):
            o = seg[i + 1]
            c = {"{": "}", "[": "]", "(": ")"}[o]
            depth, j = 0, i + 1
            while j < n:
                depth += (seg[j] == o) - (seg[j] == c)
                if depth == 0:
                    break
                j += 1
            if j >= n and o == "(":
                i += 1
                continue
            end = min(j + 1, n)
            out[i:end] = FILL * (end - i)
            i = end
            continue
        i += 1
    return "".join(out)


def arith_commands(t, subs):
    """(start, end) of each closed arithmetic COMMAND `((...))` among subs (substitutions(t)): an
    arith record with no `$` before it, `(( a > 1 ))` or the head of `for (( ;; ))`. Which `((`
    is arithmetic is the shared scanner's call (quote_mask._arith): `((cmd) )` stays two subshells."""
    return [(s["open"], s["body"][1] + 2) for s in subs if s["kind"] == "arith"
            and not (s["open"] and t[s["open"] - 1] == "$") and t[s["body"][1]:s["body"][1] + 2] == "))"]


def blank_arith(seg, lo, spans):
    """seg (the mask of t[lo:lo+len(seg)], as a list) with each arithmetic command of spans blanked
    and its last character a newline: bash reads `(( a > 1 ))` as one compound command that runs
    nothing, so none of its words is a command name, and what follows it starts a command (or is
    the `do` of `for (( ;; )) do`), so `(( pkill -f ))` runs no pkill."""
    for a, b in spans:
        x, y = a - lo, min(b, lo + len(seg)) - lo
        if 0 <= x < y:
            seg[x:y] = " " * (y - x - 1) + "\n"
    return seg


def _redir_cuts(v, a, b):
    """The words of the blank-free span v[a:b] of a mask, as (start, end) spans: bash ends a word
    at an unquoted `<` or `>` (and the `&` of `&>`), and a redirection operator's word runs from
    it to the next one. Digits or a `{NAME}` just before the operator, and nothing else since the
    word began, are its fd and stay in its word: `2>f` is one word, `a2>f` the word `a2` and `>f`.
    So `echo "new">s.sh` is a word `echo`, a word `"new"` and a redirection `>s.sh`."""
    out, s, p, led = [], a, a, False
    while p < b:
        m = REDIR_OP.match(v, p, b) if v[p] in "<>&" else None
        if m is None:
            p += 1
            continue
        if s < p and (led or v[p] == "&" or not FD_WORD.fullmatch(v, s, p)):
            out.append((s, p))
            s = p
        led = True
        p = m.end()
    out.append((s, b))
    return out


def word_spans(seg_v):
    """(start, end) of each word of a segment's mask, as bash ends them: at a blank, and at a
    redirection operator (_redir_cuts())."""
    return [c for m in re.finditer(r"[^ \t\n]+", seg_v) for c in _redir_cuts(seg_v, *m.span())]


def split_words(seg_v, seg_raw):
    words = []
    for a, b in word_spans(seg_v):
        raw = seg_raw[a:b]
        if raw:
            words.append((raw, unquote(raw)))
    return words


def resolve(words):
    """(index of the command word, code strings an `env -S` hands over), skipping assignments,
    redirections and wrappers. A redirection's target is skipped with it; a herestring's is kept
    in `herestrings` for a shell that reads it as a script."""
    i, codes, here = 0, [], []
    while i < len(words):
        raw, val = words[i]
        r = REDIR.match(raw)
        if r:
            tgt = r.group(2)
            if not tgt and i + 1 < len(words):
                i += 1; tgt = words[i][0]
            if r.group(1) == "<<<":
                here.append(unquote(tgt))
            i += 1; continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", raw):
            i += 1; continue
        base, vanishes = command_word(raw)
        if vanishes and i + 1 < len(words):  # `$(true) kill ...`: it may expand to no word
            i += 1; continue
        if base == "flock":                  # `flock [opts] FILE -c CODE`: code, not a command
            j = i + 1
            while j < len(words) and words[j][1].startswith("-") and words[j][1] != "-":
                j += opt_words("flock", words, j)
            if j + 1 < len(words) and words[j + 1][1] in ("-c", "--command"):
                codes.append(words[j + 2][1] if j + 2 < len(words) else "")
                return None, codes, here
        if base in ("docker", "podman"):
            j = _container_exec(words, i)
            if j is None:
                return i, codes, here
            if j < 0:
                return None, codes, here
            i = j
            continue
        if base in ("parallel", "sem"):
            j, end, sep = _parallel(words, i)
            if j >= end:                     # no command: its operands or stdin are the code
                return i, codes, here
            if sep != "--":                  # GNU: the command line goes to a shell
                codes.append(" ".join(v for _, v in words[j:end]))
            i = j
            continue
        if base == "screen":                 # `screen [opts] -X stuff KEYS`: keys, not a command
            keys = screen_x_codes(words, i)
            if keys is not None:
                return None, codes + keys, here
        if base in WRAPPERS:
            argopts, operands = WRAPPERS[base]
            i += 1
            as_shell = False
            if base in ("setarch", "runcon") and i < len(words) and not words[i][1].startswith("-"):
                i += 1                       # `setarch ARCH [opts] CMD`, `runcon CONTEXT CMD`
            # A lone `-` is an operand (stdin, a command name) to every wrapper but env, whose
            # `-` is POSIX's spelling of -i: `env - kill N` runs kill, not a program named `-`.
            while i < len(words) and words[i][1].startswith("-") and (
                    words[i][1] != "-" or base == "env"):
                v = words[i][1]
                if v == "--":
                    i += 1; break
                if base == "env" and v.startswith("--"):
                    v = env_long(v)
                    if v is None:            # env refuses the option and runs nothing
                        return None, codes, here
                if base == "command" and v in ("-v", "-V"):
                    return None, codes, here
                if base in LONG_OPTS and v.startswith("--"):
                    name, _ = long_option(v, base)
                    if name:                 # `systemd-run --ho H`: --host, spelled in full
                        v = name + v[len(v.partition("=")[0]):]
                if v.partition("=")[0] in REMOTE_OPTS.get(base, ()) or any(
                        v.startswith(o) and not o.startswith("--") and len(v) > 2
                        for o in REMOTE_OPTS.get(base, ())):
                    return None, codes, here
                # env -S STRING ARGS...: STRING split into words, ARGS appended to them, run. In
                # any spelling (`-S pkill -f X`, `-vS '...'`, `-i -S ...`).
                s = _env_split(v, argopts) if base == "env" else None
                if s is not None:
                    rest = i + 1 if s else i + 2
                    if not s:
                        s = words[i + 1][1] if i + 1 < len(words) else ""
                    codes.append(" ".join([s] + [r for r, _ in words[rest:]]))
                    return None, codes, here
                if base == "sudo" and _sudo_shell(v, argopts):
                    as_shell = True
                i += opt_words(base, words, i)
            # `sudo -s|-i CMD ARGS`: sudo(8) hands CMD and ARGS to the shell's -c as one command
            # line, each ARG escaped first, which is the words as the shell wrote them. Their
            # values joined are read too: `sudo -s 'pkill -f X'` names a program `pkill -f X` to
            # sudo and finds none, but it is the code its writer quoted, and refusing it costs a
            # plain `kill PID`.
            if as_shell and i < len(words):
                ws = [(r, v) for r, v in words[i:] if not REDIR.match(r)]
                codes.append(" ".join(r for r, _ in ws))
                codes.append(" ".join(v for _, v in ws))
                return None, codes, here
            i += operands
            continue
        return i, codes, here
    return None, codes, here


def herestrings(words):
    """The words a `<<<` hands a command on its stdin."""
    out = []
    for k, (raw, _) in enumerate(words):
        r = REDIR.match(raw)
        if r and r.group(1) == "<<<":
            if r.group(2):
                out.append(unquote(r.group(2)))
            elif k + 1 < len(words):
                out.append(words[k + 1][1])
    return out


# SHELLS WHOSE -c WINS OVER -s: `bash -cs CODE` runs CODE and leaves its stdin unread; dash runs
# CODE and then reads its stdin as code (`dash -sc CODE x` prints both). A shell not checked is
# read as dash is, the direction that refuses.
C_SKIPS_STDIN = {"bash", "rbash", "bash-static"}
# SHELLS WHERE +s UNDOES -s: in dash the last of -s/+s wins (`dash -s +s x` runs the script x);
# bash reads stdin on an `s` in either spelling (`bash +s x`, `bash -s +s x` run stdin). `sh` is
# read as dash (Debian's /bin/sh). A shell not checked is read as bash is: any s, stdin.
LAST_S_WINS = {"dash", "sh"}
# SHELLS THAT RUN NOTHING (checked against bash and dash with `echo RAN` on stdin and as the -c
# string). `-n` and `-o noexec` (noexec) read the commands and run none of them, -c string, script
# and stdin alike; the last of -n/+n and -o/+o noexec before the operands wins, and one after `-c
# CODE` is $0, not an option. In bash, -D, --dump-strings and --dump-po-strings dump the strings
# and run nothing (+n does not undo them), and --help and --version print and exit; dash rejects
# all five as invalid options and so runs nothing either. A shell not checked is read as running
# its code, the direction that refuses (zsh, ksh and fish have their own -n, not verified).
NOEXEC_SHELLS = {"bash", "rbash", "bash-static", "dash", "sh"}
BASH_RUNS_NOTHING = {"--help", "--version", "--dump-strings", "--dump-po-strings"}


def shell_code(words):
    """The code a bare shell runs from its argv: the -c string, or None (a script path, or
    stdin, which the caller reads from a heredoc, herestring or pipe)."""
    kind, code, _ = _shell_read(words)
    return kind, code


def _shell_read(words):
    """shell_code()'s (kind, code), and whether -s is in force (LAST_S_WINS says how +s reads).

    With -s the shell reads its commands from stdin and every operand is a positional
    parameter, never a script path: `bash -s x`, `bash -s -- x`, `bash -s - x` and `dash -is x`
    all run stdin (bash(1), dash(1)).

    A lone `-` operand is the stdin marker, not a script path: `bash -` runs what it reads
    (bash and dash), so it names a stdin shell exactly like `-s`
    and a bare shell does. What follows it behaves like what follows `--` — the next plain
    operand is the script path (`bash - FILE` opens FILE; `-` alone reads stdin), while a
    redirection word never is one.

    ("none", None, False) where the shell runs nothing at all: noexec, or bash printing its help,
    version or strings (NOEXEC_SHELLS above)."""
    i, cflag, sflag, noexec = 1, False, False, False
    name = name_of(words)
    argopts = SHELL_ARG.get(name, set())
    letters = SHELL_ARG_LETTERS.get(name, "oO")
    while i < len(words):
        raw, v = words[i]
        r = REDIR.match(raw)
        if r:                                # a redirection is not an operand; nor its target
            i += 1 if r.group(2) else 2; continue
        if v == "--":
            i += 1; break
        if name in LONG_OPTS and v.startswith("--"):   # fish: every spelling getopt_long takes
            code, j = long_code(words, i, name, {"--command"})
            if code is None:
                i = j; continue
            if "=" in v:
                return ("code", code, False)
            cflag = True; i += 1; continue
        if v.startswith("--command="):       # fish
            return ("code", v.split("=", 1)[1], False)
        if v == "--command":
            cflag = True; i += 1; continue
        if v in argopts and "=" not in v:
            i += 2; continue
        if v == "-" and not cflag:           # after -c a `-` is the code string, not the marker
            if noexec:                       # options end here, and -n is in force
                return ("none", None, False)
            if sflag:                        # `bash -s - x`: x is $1, stdin is the code
                return ("stdin", None, True)
            i += 1
            while i < len(words):
                rr = REDIR.match(words[i][0])
                if rr:
                    i += 1 if rr.group(2) else 2; continue
                return ("script", None, False)  # `bash - FILE` runs FILE
            return ("stdin", None, False)
        if v in ("--rcfile", "--init-file"):
            i += 2; continue
        if name in NOEXEC_SHELLS and v in BASH_RUNS_NOTHING:
            return ("none", None, False)
        if v.startswith("--") and len(v) > 2:
            i += 1; continue
        if (v.startswith("-") or v.startswith("+")) and len(v) > 1:
            taken = 0                        # words this cluster's letters take after it
            for k, ch in enumerate(v[1:], 1):
                if name in GETOPT_SHELLS and ch in letters:
                    rest = v[k + 1:]
                    if ch == "c":
                        if rest:
                            return ("code", rest, False)  # `fish -c'CODE'`
                        cflag = True
                        break
                    taken += 0 if rest else 1
                    break
                if ch == "c":
                    cflag = True
                elif ch == "s":
                    sflag = v[0] == "-" or name not in LAST_S_WINS
                elif ch == "n" and name in NOEXEC_SHELLS:
                    noexec = v[0] == "-"
                elif ch == "D" and name in NOEXEC_SHELLS and v[0] == "-":
                    return ("none", None, False)
                elif ch in letters:
                    taken += 1
                    if ch == "o" and name in NOEXEC_SHELLS and i + taken < len(words) \
                            and words[i + taken][1] == "noexec":
                        noexec = v[0] == "-"
            i += 1 + taken; continue
        break
    if noexec:
        return ("none", None, False)
    # a redirection is no operand, after `--` too (`bash -- <<< CODE` runs CODE)
    while i < len(words) and REDIR.match(words[i][0]):
        i += 1 if REDIR.match(words[i][0]).group(2) else 2
    if cflag:
        return ("code", words[i][1] if i < len(words) else "", sflag)
    if sflag:
        return ("stdin", None, True)
    return ("script", words[i][1], False) if i < len(words) else ("stdin", None, False)


# PROGRAMS THAT RUN A STRING AS SHELL CODE. Besides `bash -c`, `eval`, `env -S` and a bare shell's
# stdin, a program that hands its argument to `sh -c` itself runs code: `flock F -c '...'`, `su -c
# '...'` and `watch '...'` carrying a `pkill -f`. The rule is the program's own man page: where it
# says the string goes to a shell, it is code here. Each was checked with a harmless `echo RAN
# >file` where it can be run without root, a unit, a container or a login (su from its man page:
# it needs a password):
#   flock FILE -c|--command CODE    (resolve() above: flock is also an argv wrapper)
#   su / runuser  -c|--command|--session-command CODE, in any position, `-lc CODE` included;
#                 `runuser -u USER [--] CMD ARGS` runs argv
#   watch [opts] ARGS...            ARGS joined with spaces and given to `sh -c`; with -x/--exec
#                                   they are argv
#   script -c|--command CODE        (`script -qec CODE /dev/null`)
#   tmux [-c CODE] / new-session, new-window, split-window, respawn-pane|window, run-shell,
#                 display-popup, pipe-pane: the trailing shell-command; if-shell: its first
#                 operand; send-keys: the keys typed into the pane's shell, Enter as a newline
#   trap CODE SIGNAL...             the action bash runs when the signal arrives
#   at / batch                      read their job from stdin and run it with /bin/sh
# and, by the same reading:
#   find ... -exec|-execdir|-ok|-okdir ARGV ; | {} +    argv, joined as the shell wrote it
#   parallel [opts] -- CMD...       (moreutils) each CMD to `sh -c`; GNU: each after `:::`, a
#                                   command line per stdin line, and a COMMAND before `:::`
#   sg|newgrp GROUP [-c] CMD        the one string, to the shell (`sg -c CMD GROUP` too)
#   git rebase -x|--exec CMD, submodule foreach CMD, bisect run CMD ARGS, filter-branch
#                 --*-filter CMD    a shell command each, by git's own pages
#   ssh [opts] DEST CMD ARGS        its words joined and run by the login shell -- read only when
#                                   DEST is this host (another host's processes are not this guard's)
#   sudo -s|-i CMD ARGS             to the shell's -c, each ARG escaped (resolve() above)
#   nix-shell --run|--command CMD   to bash
#   fish -C|--init-command CODE     run before the -c code, the script or stdin (fish(1))
# and screen -X's typed keys (SCREEN_KEYS below, read from resolve()).
SU_ARG = set("cgGsw")
SCRIPT_ARG = set("IOBTmcEo")
WATCH_ARG = set("nq")
TMUX_SUBS = {   # subcommand -> option letters taking an argument
    "new-session": "cefFnstxy", "new": "cefFnstxy", "new-window": "ceFnt", "neww": "ceFnt",
    "split-window": "ceFlpt", "splitw": "ceFlpt", "respawn-pane": "cet", "respawnp": "cet",
    "respawn-window": "cet", "respawnw": "cet", "run-shell": "cdt", "run": "cdt",
    "display-popup": "bcdehsStTwxy", "popup": "bcdehsStTwxy", "pipe-pane": "t", "pipep": "t",
    "if-shell": "t", "if": "t", "send-keys": "Nt", "send": "Nt"}
TMUX_KEYS_NL = {"Enter", "C-m", "C-j", "KPEnter"}
# The subcommands whose shell-command, given as more than one argument, tmux(1) runs directly
# (without `sh -c`): its words are argv, joined as the shell wrote them, so `tmux new-session -d
# sh -c 'pkill -f X'` runs `sh -c 'pkill -f X'`, not a bare pkill.
TMUX_ARGV = {"new-session", "new", "new-window", "neww", "split-window", "splitw",
             "respawn-pane", "respawnp", "respawn-window", "respawnw"}

# KEYS TYPED INTO A SCREEN SESSION, the screen sibling of tmux send-keys. `screen [opts] -X CMD
# ARGS` runs the screen command CMD in a session; these type their string into a window, whose
# shell runs it (checked against screen, a detached session and a stand-in pkill):
#   stuff STRING             the keys themselves
#   at WINDOW CMD ARGS       CMD in that window
#   eval LINE...             each LINE a screen command, split and decoded once more
#   register [-e ENC] K STR  the keys `paste K` types
# screen decodes each -X argument (`\n`, `\r`, `\NNN`, `\\`, `^X`; `\t` read as a tab; a CR or LF ends a line),
# and an eval line again. `screen`/`exec` reached through `at`/`eval` start a window running argv,
# as `-X screen CMD` (read by the WRAPPERS row) does. A command that types nothing (`title`) and
# a string kept for later (`-X readreg`/`bufferfile`, a screenrc) are not read.
SCREEN_KEYS = {"stuff", "at", "eval", "register"}


def screen_unescape(s, split=False):
    """s as screen decodes a command argument; with split, an eval LINE as screen splits it
    into its words (blanks outside "..." and '...', both of which screen still decodes in)."""
    out, cur, q, i, have = [], [], None, 0, False
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            m = re.match(r"[0-7]{1,3}", s[i + 1:])
            if m:
                cur.append(chr(int(m.group(0), 8))); i += 1 + len(m.group(0))
            else:
                cur.append({"n": "\n", "r": "\r", "t": "\t"}.get(s[i + 1], s[i + 1])); i += 2
            have = True; continue
        if ch == "^" and i + 1 < len(s):
            cur.append("\x7f" if s[i + 1] == "?" else chr(ord(s[i + 1]) & 0x1f)); i += 2
            have = True; continue
        if split and ch in "\"'" and q in (None, ch):
            q = None if q else ch; have = True; i += 1; continue
        if split and q is None and ch in " \t":
            if have:
                out.append("".join(cur))
            cur, have = [], False; i += 1; continue
        cur.append(ch); have = True; i += 1
    if not split:
        return "".join(cur)
    return out + (["".join(cur)] if have else [])


def screen_codes(args, depth=0):
    """The code the screen command args (decoded words) types into a window or starts in one."""
    if not args or depth > 8:
        return []
    cmd, rest = args[0], args[1:]
    if cmd == "stuff":
        return [" ".join(rest).replace("\r", "\n")]
    if cmd == "at":
        return screen_codes(rest[1:], depth + 1)
    if cmd == "eval":
        return [c for line in rest for c in screen_codes(screen_unescape(line, True), depth + 1)]
    if cmd == "register":
        if rest[:1] == ["-e"]:
            rest = rest[2:]
        return [rest[1].replace("\r", "\n")] if len(rest) > 1 else []
    if cmd in ("screen", "exec") and depth:
        return [" ".join(shlex.quote(a) for a in args)]
    return []


def screen_x_codes(words, i):
    """For `screen [opts] -X CMD ARGS` at words[i]: the code CMD types or starts, when CMD is
    one of SCREEN_KEYS; else None (the WRAPPERS row reads the rest, `-X exec CMD` included)."""
    argopts, xflag, j = WRAPPERS["screen"][0], False, i + 1
    while j < len(words):
        raw, v = words[j]
        if REDIR.match(raw):
            j += 1 if REDIR.match(raw).group(2) else 2; continue
        if not v.startswith("-") or v == "-":
            break
        if v in argopts or v in ("-ls", "-list", "-wipe"):
            j += 1 if v in ("-ls", "-list", "-wipe") else 2; continue
        for k, ch in enumerate(v[1:]):       # a cluster, as screen reads `-dmS NAME`
            if "-" + ch in argopts:
                break
            xflag = xflag or ch == "X"
        j += _cluster_words(v, argopts)
    if not xflag or j >= len(words) or words[j][1] not in SCREEN_KEYS:
        return None
    return screen_codes([screen_unescape(v) for r, v in words[j:] if not REDIR.match(r)])


def _cluster_arg(words, i, argset):
    """For a short-option word words[i] (`-lc`, `-cCODE`): (letter taking an argument or None,
    its argument or None, index after it)."""
    v = words[i][1]
    for j, ch in enumerate(v[1:], 1):
        if ch in argset:
            if j + 1 < len(v):
                return ch, v[j + 1:], i + 1
            return ch, (words[i + 1][1] if i + 1 < len(words) else ""), i + 2
    return None, None, i + 1


def _operands(words, i, argset, longargs=(), stop=True, prog=None):
    """Skip options from words[i]; (index of the first operand, {letter: argument}). A long option
    is read in full against longargs, or, with prog, in every spelling prog's getopt_long takes
    (long_option())."""
    got = {}
    while i < len(words):
        raw, v = words[i]
        if REDIR.match(raw):
            i += 1 if REDIR.match(raw).group(2) else 2; continue
        if v == "--":
            return i + 1, got
        if v.startswith("--") and prog:
            i = long_code(words, i, prog, ())[1]; continue
        if v.startswith("--"):
            name = v.partition("=")[0]
            i += 2 if (name in longargs and "=" not in v) else 1; continue
        if v.startswith("-") and len(v) > 1:
            ch, arg, i = _cluster_arg(words, i, argset)
            if ch:
                got[ch] = arg
            for f in v[1:]:
                got.setdefault(f, None)
                if f == ch:
                    break
            continue
        if stop:
            return i, got
        i += 1
    return i, got


def builtin_operands(words):
    """The operand words of the builtin words[0] (eval, trap) as bash's own option parser leaves
    them, redirections dropped: a first `--` ends the options and is no operand, and any other
    first word of `-` and more is an option, on which neither builtin runs code (an invalid one
    is refused, `-l`/`-p`/`--help` print), so None. So `eval -- 'CODE'` is the code CODE, not a
    command named `--`, and `eval 2>/dev/null CODE` is CODE without the redirection."""
    ops, i = [], 1
    while i < len(words):
        m = REDIR.match(words[i][0])
        if m:
            i += 1 if m.group(2) else 2; continue
        ops.append(words[i]); i += 1
    if ops and ops[0][1] == "--":
        return ops[1:]
    if ops and ops[0][1].startswith("-") and len(ops[0][1]) > 1:
        return None
    return ops


def eval_code(words):
    """The code `eval` (words[0]) runs: its operand words' values (builtin_operands) joined by
    single spaces, as bash's eval joins them, or None where bash's option parsing leaves it no
    code to run. A redirection and its target are the eval command's own and never among them:
    joined in, `eval 'P=$(pgrep -f X)' >"it's"` would hand on `P=$(pgrep -f X) >it's`, whose
    apostrophe opens a quote (hooks/tests/test-eval-re-read-is-the-code-bash-runs.py)."""
    ops = builtin_operands(words)
    return None if ops is None else " ".join(w[1] for w in ops)


def handed_code(words):
    """The strings a command whose word is words[0] gives a shell to run (the table above)."""
    name = name_of(words)
    vals = [v for r, v in words if not REDIR.match(r)]
    if name == "fish":                       # -C/--init-command CODE: run before the -c code,
        out, i = [], 1                       # the script or stdin, which shell_code() reads (fish(1))
        while i < len(words):
            raw, v = words[i]
            if REDIR.match(raw):
                i += 1 if REDIR.match(raw).group(2) else 2; continue
            if v == "--" or not v.startswith("-") or v == "-":
                break                        # the script path: options end there
            if v.startswith("--"):           # any spelling getopt_long takes (long_code())
                code, i = long_code(words, i, "fish", {"--init-command"})
                out += [code] if code is not None else []
                continue
            else:     # getopt: a letter taking an argument takes the
                for k, ch in enumerate(v[1:], 1):  # rest of the word, else the next word
                    if ch in SHELL_ARG_LETTERS["fish"]:
                        arg = v[k + 1:] or (words[i + 1][1] if i + 1 < len(words) else "")
                        if ch == "C":
                            out.append(arg)
                        i += 0 if v[k + 1:] else 1
                        break
            i += 1
        return out
    if name in ("su", "runuser"):
        out, i, user = [], 1, "-u" in vals
        while i < len(words):
            v = words[i][1]
            if v.startswith("--") and len(v) > 2:   # any spelling getopt_long takes (long_code())
                user = user or long_option(v, name)[0] == "--user"
                code, i = long_code(words, i, name, {"--command", "--session-command"})
                out += [code] if code is not None else []
                continue
            if v.startswith("-") and not v.startswith("--") and len(v) > 1:
                ch, arg, i = _cluster_arg(words, i, SU_ARG | ({"u"} if name == "runuser" else set()))
                if ch == "c":
                    out.append(arg)
                continue
            i += 1
        if not out and name == "runuser" and user:
            k, _ = _operands(words, 1, set("cgGsuw"), prog=name)
            if k < len(words):                  # argv: its words as the shell wrote them
                out.append(" ".join(r for r, _ in words[k:]))
        return out
    if name == "watch":
        k, got = _operands(words, 1, WATCH_ARG, prog=name)
        if k >= len(words):
            return []
        exe = "x" in got or any(v.startswith("--") and long_option(v, name)[0] == "--exec"
                                for _, v in words[1:k])
        # Without -x watch joins the VALUES and gives the line to `sh -c`, so `watch sh -c
        # 'pkill -f X'` runs `sh -c pkill -f X`, a bare pkill. The words as written are read too:
        # they are the command the writer meant, and refusing it costs a plain `kill PID`.
        joined = [" ".join(r for r, _ in words[k:])]
        return joined if exe else [" ".join(v for _, v in words[k:])] + joined
    if name == "script":
        out, i = [], 1
        while i < len(words):
            v = words[i][1]
            if v.startswith("--") and len(v) > 2:   # any spelling getopt_long takes (long_code())
                code, i = long_code(words, i, name, {"--command"})
                out += [code] if code is not None else []
                continue
            if v.startswith("-") and not v.startswith("--") and len(v) > 1:
                ch, arg, i = _cluster_arg(words, i, SCRIPT_ARG)
                if ch == "c":
                    out.append(arg)
                continue
            i += 1
        return out
    if name == "trap":
        ops = builtin_operands(words)
        return [ops[0][1]] if ops and ops[0][1] != "-" else []
    if name == "tmux":
        k, got = _operands(words, 1, set("cfLST"))
        out = [got["c"]] if got.get("c") else []
        if k < len(words) and words[k][1] in TMUX_SUBS:
            sub = words[k][1]
            j, _ = _operands(words, k + 1, set(TMUX_SUBS[sub]))
            rest = [v for r, v in words[j:] if not REDIR.match(r) and v != ";"]
            if sub in ("send-keys", "send"):
                out.append("".join("\n" if v in TMUX_KEYS_NL else v + " " for v in rest))
            elif sub in ("if-shell", "if"):
                out += rest[:1]
            elif len(rest) > 1 and sub in TMUX_ARGV:
                out.append(" ".join(r for r, v in words[j:] if not REDIR.match(r) and v != ";"))
            elif rest:
                out.append(" ".join(rest))
        return out
    if name == "find":
        out, k = [], 1
        while k < len(words):
            if words[k][1] in FIND_EXEC:
                j = k + 1
                while j < len(words) and words[j][1] != ";" and not (
                        words[j][1] == "+" and words[j - 1][1] == "{}"):
                    j += 1
                if j > k + 1:
                    out.append(" ".join(r for r, _ in words[k + 1:j]))
                k = j
            k += 1
        return out
    if name in ("sg", "newgrp"):
        out, ops, i = [], [], 1
        while i < len(words):
            raw, v = words[i]
            if REDIR.match(raw):
                i += 1 if REDIR.match(raw).group(2) else 2; continue
            if v.startswith("--") and len(v) > 2:   # any spelling getopt_long takes (long_code())
                code, i = long_code(words, i, name, {"--command"})
                out += [code] if code is not None else []
                continue
            if v.startswith("-") and len(v) > 1:
                ch, arg, i = _cluster_arg(words, i, {"c"})
                if ch:
                    out.append(arg)
                continue
            if v != "-":
                ops.append(v)
            i += 1
        return out or ops[1:2]               # `sg GROUP CMD`: the one operand after the group
    if name in ("parallel", "sem"):          # no command (resolve() stopped here): each operand
        j, end, sep = _parallel(words, 0)    # after `--` or `:::` is a command line
        if j < end or sep in (None, "::::", "::::+"):
            return []
        return [v for r, v in words[end + 1:] if not REDIR.match(r) and v not in PAR_SEPS]
    if name == "git":
        k, _ = _operands(words, 1, set("Cc"), ("--git-dir", "--work-tree", "--namespace",
                                               "--super-prefix", "--config-env"))
        sub, out = (words[k][1] if k < len(words) else ""), []
        out += git_sh_values(words, k)
        if sub == "rebase":
            i = k + 1
            while i < len(words):
                v = words[i][1]
                if v.startswith("--") and long_option(v, "git-rebase")[0] == "--exec":
                    code, i = long_code(words, i, "git-rebase", {"--exec"})   # `--ex`, `--exe=`
                    out.append(code); continue
                if v.startswith("-") and not v.startswith("--") and len(v) > 1:
                    ch, arg, i = _cluster_arg(words, i, set("xsXC"))
                    if ch == "x":
                        out.append(arg)
                    continue
                i += 1
        elif sub == "filter-branch":
            for i in range(k + 1, len(words) - 1):
                if words[i][1] in GIT_FILTERS:
                    out.append(words[i + 1][1])
        else:
            run = None
            if sub == "submodule":
                j = k + 1
                while j < len(words) and words[j][1] in ("-q", "--quiet", "--cached"):
                    j += 1
                if j < len(words) and words[j][1] == "foreach":
                    j += 1
                    while j < len(words) and words[j][1] in ("-q", "--quiet", "--recursive"):
                        j += 1
                    run = words[j:]
            elif sub == "bisect" and k + 1 < len(words) and words[k + 1][1] == "run":
                run = words[k + 2:]
            if run:                          # argv[0] goes to a shell, its arguments after it
                out.append(" ".join([run[0][1]] + [r for r, _ in run[1:]]))
        return out
    if name == "nix-shell":                  # nix-shell(1): --run CMD and --command CMD, to bash
        out = []
        for i, (_, v) in enumerate(words[1:], 1):
            if v in ("--run", "--command"):
                out.append(words[i + 1][1] if i + 1 < len(words) else "")
            elif v.startswith(("--run=", "--command=")):
                out.append(v.split("=", 1)[1])
        return out
    if name == "ssh":
        k, _ = _operands(words, 1, SSH_ARG)
        if k + 1 >= len(words) or not this_host(words[k][1]):
            return []                        # another host's processes, or a login with no command
        return [" ".join(v if re.search(r"['\"\\]", r) else r for r, v in words[k + 1:]
                         if not REDIR.match(r))]
    return []


def command_codes(words, stdin=True):
    """The code strings the simple command whose command word is words[0] runs as shell code:
    eval's operands, a shell's -c string or herestring (stdin False leaves the herestring to the
    caller), and what handed_code() reads. One function, so that a reader starting a command at
    another word (block-unsafe-kill.sh's carried_kill(), past a program it cannot read) asks the
    same question parse() asks."""
    out = []
    name = name_of(words)
    if name == "eval":
        code = eval_code(words)
        if code is not None:
            out.append(code)
    if name in SHELLS:
        kind, code = shell_code(words)
        if kind == "code":
            out.append(code)
    if stdin and reads_code_on_stdin(words):
        out += herestrings(words)
    return out + handed_code(words)


# GIT'S CONFIGURATION NAMES A SHELL COMMAND TOO (`git -c alias.k='!kill N' k` runs kill). git
# runs with /bin/sh the value of an alias that begins with `!`, and the value of each key below,
# by git-config(1) (credential.helper with `!` or a path, the rest as they stand).
# Such a value is code wherever this command sets it: `-c NAME=VALUE` before the subcommand,
# `git config [set] NAME VALUE`, and the environment variables git reads in their place
# (git_env_code(), for the assignments in front of a git). A leading `!` is git's, not the shell's.
GIT_SH_KEYS = re.compile(r"(?i)^(?:core\.(?:editor|pager|sshcommand|askpass|fsmonitor)|sequence\.editor"
                         r"|diff\.external|credential\.(?:.+\.)?helper|sendemail\.sendmailcmd"
                         r"|uploadpack\.packobjectshook|pager\..+|diff\..+\.(?:command|textconv)"
                         r"|merge\..+\.driver|filter\..+\.(?:clean|smudge|process)"
                         r"|(?:merge|diff)tool\..+\.cmd|(?:browser|man)\..+\.cmd"
                         r"|remote\..+\.(?:uploadpack|receivepack))$")
GIT_SH_ENV = {"GIT_EDITOR", "GIT_PAGER", "GIT_SSH_COMMAND", "GIT_SEQUENCE_EDITOR", "GIT_ASKPASS",
              "GIT_EXTERNAL_DIFF", "EDITOR", "VISUAL", "PAGER", "SSH_ASKPASS"}
GIT_CONFIG_ARG = {"-f", "--file", "--blob", "--type", "--default", "--comment", "--value"}


def git_sh_value(name, value):
    """The code a git config NAME=VALUE hands /bin/sh, or None."""
    if name.lower().startswith("alias."):
        return value[1:] if value.startswith("!") else None
    if GIT_SH_KEYS.match(name):
        return value[1:] if value.startswith("!") else value
    return None


def git_sh_values(words, k):
    """The shell code a git command line sets in its configuration: each `-c NAME=VALUE` before
    the subcommand at words[k], and the VALUE of `git config [set] NAME VALUE` (the block above)."""
    out, i = [], 1
    while i < k:
        v = words[i][1]
        arg = None
        if v == "-c" and i + 1 < k:
            arg = words[i + 1][1]; i += 1
        elif v.startswith("-c") and len(v) > 2:
            arg = v[2:]
        if arg and "=" in arg:
            code = git_sh_value(*arg.split("=", 1))
            if code is not None:
                out.append(code)
        i += 1
    if k < len(words) and words[k][1] == "config":
        ops, i = [], k + 1
        while i < len(words):
            raw, v = words[i]
            if REDIR.match(raw):
                i += 1 if REDIR.match(raw).group(2) else 2; continue
            if v.startswith("-"):
                i += 2 if v in GIT_CONFIG_ARG else 1; continue
            ops.append(v); i += 1
        if ops[:1] == ["set"]:
            ops = ops[1:]
        if len(ops) >= 2:
            code = git_sh_value(ops[0], ops[1])
            if code is not None:
                out.append(code)
    return out


def git_env_code(prefix):
    """The shell code the assignments in front of a git hand it in GIT_SH_ENV (the block above)."""
    out = []
    for raw, v in prefix:
        name, eq, value = v.partition("=")
        if eq and name in GIT_SH_ENV:
            out.append(value)
    return out


FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
GIT_FILTERS = {"--env-filter", "--tree-filter", "--index-filter", "--parent-filter", "--msg-filter",
               "--commit-filter", "--tag-name-filter"}
SSH_ARG = set("BbcDEeFIiJLlmOoPpQRSWw")
LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "::1", "0.0.0.0"}


def this_host(dest):
    """Whether an ssh destination ([user@]host, ssh://[user@]host[:port]) names this host."""
    if dest.startswith("ssh://"):
        dest = dest[6:]
        dest = re.sub(r":\d+$", "", dest)
    host = dest.rsplit("@", 1)[-1].strip("[]").lower()
    me = socket.gethostname().lower()
    return host in LOCAL_NAMES | {me, me.split(".")[0]} or host.startswith("127.")


def reads_code_on_stdin(words):
    """Whether the command words[0] runs what it reads on stdin as shell code: a bare shell
    (shell_code() says "stdin", or -c with -s in a shell that runs both), `source`/`.` whose file
    is a name of stdin (`. /dev/stdin`, `source -- /dev/fd/0 ARGS`), or `at`/`batch` without
    `-f FILE` and not listing (-l/-r/-c)."""
    name = name_of(words)
    if name in SHELLS:
        kind, code, sflag = _shell_read(words)
        if kind == "script":                 # `bash /dev/stdin`: the script it opens is its stdin
            return code in _STDIN_PATHS
        if kind == "code" and not (sflag and name not in C_SKIPS_STDIN):
            return _code_reads_stdin(code or "")
        return kind == "stdin" or (sflag and name not in C_SKIPS_STDIN)
    if name in ("source", "."):              # the file it runs is its stdin: `. /dev/stdin`
        ops = [v for r, v in words[1:] if not REDIR.match(r)]
        ops = ops[1:] if ops[:1] == ["--"] else ops
        return bool(ops) and ops[0] in _STDIN_PATHS
    if name in ("at", "batch"):
        _, got = _operands(words, 1, set("qft"), stop=False)
        return not ({"f", "l", "r", "d", "c"} & set(got))
    if name in ("parallel", "sem"):          # GNU, no command and no operands: a command per line
        j, end, sep = _parallel(words, 0)
        return j >= end and sep is None and not any(
            v in ("-a", "--arg-file") or v.startswith("--arg-file=") for _, v in words[1:])
    return False


def printf_escape(s):
    """printf interprets backslash escapes in its format string and in a `%b` argument. For command
    boundaries the ones that matter are `\\n` (a new command line) and `\\t` (a word break); `\\\\`
    is a literal backslash; every other escape yields a single non-whitespace character, collapsed
    to a word-continuation placeholder so it neither splits a word nor drops a payload token.
    Without this a payload after `%s\\n` on a later line stays glued to the line above and reads as
    that line's argument, not as its own command."""
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            e = s[i + 1]
            if e == "n":
                out.append("\n")
            elif e == "t":
                out.append("\t")
            elif e == "\\":
                out.append("\\")
            elif e in "abfrve0x":
                out.append(FILL)
            else:
                out.append(e)
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def handed_script(prod):
    """The text an `echo`/`printf` producer WRITES to stdout — which is what a bare shell reading
    the pipe actually runs. The guard must analyse that, not the producer's argv joined with
    spaces: the format string is a template and an option word is not output, so joining them
    with the operands makes the format string (or `-e`) the command word and the payload an
    argument to it.

      echo:    its operands joined by spaces, leading -n/-e/-E options dropped (bash stops
               recognising echo options at the first operand, and does not treat `--` specially).
      printf:  the format string with each conversion filled by an argument — a string conversion
               (s, b, with any `%.N` truncation) emits its argument, `%c` its first character, a
               numeric/float/`%q` conversion something that is NOT the argument verbatim — and the
               format string reused while arguments remain. This reproduces what printf emits, so
               command boundaries the format string draws (a space, a newline) still bind: `printf
               '%s %s' 'echo a' 'pkill -f x'` emits `echo a pkill -f x` (a command named echo,
               silent), while `printf '%s' 'pkill -f x'` emits the payload on its own (a command,
               blocked). Falls back to joining every word when the format string itself is
               unresolved (`printf "$FMT" …`), so an unknown template behaves as before rather
               than being silently truncated.

    A redirection among the words, and its target, is bash's and not an operand, wherever it is
    written: `echo "echo 'P'" > >(bash)` writes `echo 'P'`."""
    argv, i = [], 1
    while i < len(prod.words):
        r = REDIR.match(prod.words[i][0])
        if r:
            i += 1 if r.group(2) else 2
            continue
        argv.append(prod.words[i])
        i += 1
    vals = [v for _, v in argv]
    if prod.name == "echo":
        i = 0
        while i < len(vals) and len(vals[i]) > 1 and ECHO_OPT.match(vals[i]):
            i += 1
        return " ".join(vals[i:])
    # printf: skip its options, which are not output. `-v VAR` sends the result to a variable, so
    # nothing reaches the shell on stdout; `--` only ends the option list
    # (`printf -- '%s' … | bash`). An unmodelled option means fall back to joining, never truncate.
    i = 0
    while i < len(argv):
        v = vals[i]
        if v == "--":
            i += 1
            break
        if v == "-v":
            return ""
        if v.startswith("-") and v != "-":
            return " ".join(vals)
        break
    if i >= len(argv) or unresolved(argv[i][0]):
        return " ".join(vals)
    fmt = vals[i]
    args, n = vals[i + 1:], len(vals) - i - 1
    convs = list(PRINTF_CONV.finditer(fmt))
    if not convs:
        return printf_escape(fmt)
    ai, out = 0, []
    while True:
        started, pos = ai, 0
        for m in convs:
            out.append(printf_escape(fmt[pos:m.start()]))
            pos = m.end()
            conv = m.group(2)
            if conv == "%":
                out.append("%")
                continue
            a = args[ai] if ai < n else ""
            ai += 1
            prec = m.group(1)
            if conv == "s":
                out.append(a[:int(prec)] if prec else a)
            elif conv == "b":
                a = printf_escape(a)
                out.append(a[:int(prec)] if prec else a)
            elif conv == "c":
                out.append(a[:1])
            # numeric / float / q: the argument is not written to the stream verbatim -> nothing
        out.append(printf_escape(fmt[pos:]))
        if ai == started or ai >= n:      # a pass that consumed no argument never repeats
            break
    return "".join(out)


# PROGRAMS WHOSE STDOUT IS THEIR STDIN'S TEXT. A heredoc or
# herestring read by one of these and piped to a shell reaches the shell unchanged, so it is the
# code the shell runs: `cat <<'EOF' | bash`, `cat <<< '...' | sh`, `tee log <<EOF | sudo bash`.
# The population is every installed program that, by its own page, copies standard input to
# standard output byte for byte when given no input file (coreutils cat, tee and dd, pv, and
# moreutils sponge), and only in the spellings that keep it so: an option that rewrites the
# text (`cat -n`, `cat -A`, `pv -X`, `dd conv=`), stops it short (`pv -S`, `dd count=`) or sends
# it elsewhere (`pv -o`, `dd of=`, `sponge FILE`), or an input file other than `-`, takes the
# program out (`cat FILE <<EOF | bash` runs FILE, not the body). An unlisted option takes it out
# too. Each entry: (options taking no argument, options taking one, whether a file operand other
# than `-` is allowed, dd-style operand keys allowed).
COPIES_STDIN = {
    "cat": ({"-u"}, set(), False, None),
    "tee": ({"-a", "--append", "-i", "--ignore-interrupts", "-p", "--output-error"}, set(),
            True, None),
    "pv": ({"-p", "--progress", "-t", "--timer", "-e", "--eta", "-I", "--fineta", "-r", "--rate",
            "-a", "--average-rate", "-b", "--bytes", "-T", "--buffer-percent", "-n",
            "--numeric", "-q", "--quiet", "-8", "--bits", "-k", "--si", "-W", "--wait", "-g",
            "--gauge", "-l", "--line-mode", "-0", "--null", "-v", "--stats", "-f", "--force",
            "-c", "--cursor", "-C", "--no-splice", "-E", "--skip-errors", "-Y", "--sync", "-K",
            "--direct-io"},
           {"-A", "--last-written", "-F", "--format", "-D", "--delay-start", "-s", "--size",
            "-i", "--interval", "-m", "--average-rate-window", "-w", "--width", "-H", "--height",
            "-N", "--name", "-u", "--bar-style", "-x", "--extra-display", "-L", "--rate-limit",
            "-B", "--buffer-size", "-Z", "--error-skip-block", "-U", "--store-and-forward",
            "-P", "--pidfile"}, False, None),
    "sponge": (set(), set(), False, None),
    "dd": (set(), set(), False, {"bs", "ibs", "obs", "status"}),
}


def _io_redirs(words):
    """(the stdin redirections of words in order, as their operators, and whether stdout is
    redirected away from the pipe). A redirection's fd is its leading digits, 0 or 1 when none."""
    ins, out = [], False
    for raw, _ in words:
        r = REDIR.match(raw)
        if not r:
            continue
        op, fd = r.group(1), raw[:r.start(1)]
        if op in ("<<<", "<<", "<<-", "<", "<>") and fd in ("", "0"):
            ins.append(op)
        elif op in ("&>", "&>>") or (op in (">", ">>", ">|", ">&") and fd in ("", "1")):
            out = True
    return ins, out


def fd1_to_pipe(words):
    """Whether what words' command writes on fd 1 still goes to the pipe its stdout was given,
    once bash has applied its redirections left to right: `> FILE`, `>/dev/null`,
    `&>`, `>&-` and `>&2 2>&1` send it elsewhere; `2>&1 >&2` and `3>&1 >&3` bring it back. An fd
    the line does not name is not the pipe. `|&` changes nothing here: bash applies its `2>&1`
    after these, and fd 1 is what the command writes."""
    tab, i = {1: "pipe"}, 0
    while i < len(words):
        raw = words[i][0]
        r = REDIR.match(raw)
        i += 1
        if not r:
            continue
        op, fdw, glued = r.group(1), raw[:r.start(1)], r.group(2)
        tgt = glued if glued else (unquote(words[i][0]) if i < len(words) else "")
        if not glued:
            i += 1
        if fdw.startswith("{"):                      # `{name}>`: a new fd, not 1
            continue
        n = int(fdw) if fdw else (0 if op[0] == "<" else 1)
        if op in ("&>", "&>>"):
            tab[1] = tab[2] = "away"
        elif op in (">&", "<&"):
            m = re.fullmatch(r"(\d+)(-?)", tgt)
            if m:
                tab[n] = tab.get(int(m.group(1)), "away")
                if m.group(2):
                    tab[int(m.group(1))] = "away"
            else:
                tab[n] = "away"
                if op == ">&" and not fdw and tgt != "-":
                    tab[2] = "away"
        elif op not in ("<<<", "<<", "<<-"):
            tab[n] = "away"
    return tab.get(1) == "pipe"


# PROGRAMS THAT PASS THEIR STDIN'S LINES ON. A line filter between a writer and a
# shell hands the shell whichever lines it keeps: `echo '...' | sort | bash`, `| grep pkill |
# bash`, `| sed 's/a/a/' | bash` and `| head -1 | bash` run the text, `| grep -v pkill | bash`
# and `| head -0 | bash` run none of it. The population is the installed programs whose output
# is lines of their input, kept, reordered or edited in place: coreutils sort, uniq, tac, head
# and tail, GNU grep (egrep, fgrep), sed, and awk (gawk, mawk, nawk). Read exactly: head and tail
# with a line count (`-n N`, `-N`, `--lines=N`, tail's `+N`) and nothing else; grep with fixed
# patterns (-F, or a pattern with no regex metacharacter), -v, -i, -x, -w, -e, -s, -h, -E, -G and
# -q, -c, -l, -L, which write no line of it. Every other spelling, and sort, uniq, tac, sed and
# awk always, is read as passing every line on unchanged: the refusing direction, wrong for
# `grep -v 'p.ill'`, `sed d`, `uniq -d` or `awk 0`, and for a filter given a file operand. So is
# a text that still holds an expansion (`$X`, `$1`, a backtick), which bash fills in before the
# filter reads it; only a filter that surely writes nothing (`head -0`, `grep -q`) ends it.
LINE_FILTERS = {"sort", "uniq", "tac", "sed", "awk", "gawk", "mawk", "nawk", "grep", "egrep",
                "fgrep", "head", "tail"}
_GREP_FLAGS = set("vixwshFEGqclL")
_BRE_META = set(".[]*^$\\")
_ERE_META = _BRE_META | set("+?(){}|")


def _lines_of(text, keep):
    """text with only the lines keep(list of lines) returns, its final newline kept."""
    end = "\n" if text.endswith("\n") else ""
    lines = keep(text[:-1].split("\n") if end else text.split("\n")) if text else []
    return "\n".join(lines) + (end if lines else "")


def _line_count(v):
    return int(v) if re.fullmatch(r"\d+", v) else None


def _head_tail(name, words):
    """What head or tail keeps, as a function of the lines; None where it keeps none, False where
    this reader does not read the spelling."""
    n, i = 10, 1
    while i < len(words):
        raw, v = words[i]
        r = REDIR.match(raw)
        if r:
            i += 1 if r.group(2) else 2; continue
        i += 1
        if v in ("-n", "--lines"):
            v = "-n" + (words[i][1] if i < len(words) else "")
            i += 1
        if v.startswith("--lines="):
            v = "-n" + v[8:]
        if name == "tail" and v.startswith("-n+") and _line_count(v[3:]) is not None:
            k = max(_line_count(v[3:]), 1)
            return lambda ls: ls[k - 1:]
        if v.startswith("-n") and _line_count(v[2:]) is not None:
            n = _line_count(v[2:])
        elif v.startswith("-") and _line_count(v[1:]) is not None:
            n = _line_count(v[1:])
        else:
            return False                             # an option, a file: not read
    if n == 0:
        return None
    return (lambda ls: ls[:n]) if name == "head" else (lambda ls: ls[len(ls) - n:])


def _grep(name, words):
    """What grep keeps, as a function of the lines; None where it writes none of them, False
    where this reader does not read the spelling."""
    opts = set("F" if name == "fgrep" else "E" if name == "egrep" else "")
    pats, operands, i, done = [], [], 1, False
    while i < len(words):
        raw, v = words[i]
        r = REDIR.match(raw)
        if r:
            i += 1 if r.group(2) else 2; continue
        i += 1
        if done or not v.startswith("-") or v == "-":
            operands.append(v); continue
        if v == "--":
            done = True; continue
        for k, ch in enumerate(v[1:]):
            if ch == "e":
                pats.append(v[k + 2:] if v[k + 2:] else (words[i][1] if i < len(words) else ""))
                i += 0 if v[k + 2:] else 1
                break
            if ch not in _GREP_FLAGS:
                return False
            opts.add(ch)
    if not pats:
        if not operands:
            return False
        pats, operands = [operands[0]], operands[1:]
    if operands and operands != ["-"]:
        return False                                 # it reads a file
    if opts & set("qclL"):
        return None
    pats = [p for pat in pats for p in pat.split("\n")]
    meta = _ERE_META if "E" in opts else _BRE_META
    if "F" not in opts and any(set(p) & meta for p in pats):
        return False
    fold = (lambda s: s.lower()) if "i" in opts else (lambda s: s)  # noqa: E731

    def hit(line):
        s = fold(line)
        for p in map(fold, pats):
            if "x" in opts:
                ok = s == p
            elif "w" in opts:
                ok = bool(re.search(r"(?<!\w)%s(?!\w)" % re.escape(p), s))
            else:
                ok = p in s
            if ok:
                return True
        return False
    return lambda ls: [ln for ln in ls if hit(ln) != ("v" in opts)]


def line_filter(words):
    """None where words[0] is no LINE_FILTERS program; else a function from the text it reads on
    its stdin to the text it writes, which given None (a text not known here) returns "" where the
    program surely writes none of it and None where it may write some."""
    name = name_of(words)
    if name not in LINE_FILTERS:
        return None
    keep = _head_tail(name, words) if name in ("head", "tail") else \
        _grep(name, words) if name.endswith("grep") else False
    if keep is None:
        return lambda text: ""
    if keep is False:
        return lambda text: text
    # A text still holding an expansion (`$X`, `$1`, a backtick) is not yet the text the filter
    # reads: bash fills it in first (`X='pkill ...'; echo "$X" | grep pkill | bash`), so it is
    # passed on whole, as the refusing direction reads it.
    return lambda text: None if text is None else text if re.search(r"[$`]", text) \
        else _lines_of(text, keep)


def copies_stdin(words):
    """Whether the command words[0] writes its stdin to its stdout unchanged (COPIES_STDIN)."""
    name = name_of(words)
    if name not in COPIES_STDIN:
        return False
    flags, argopts, files, ddkeys = COPIES_STDIN[name]
    i, opts_done = 1, False
    while i < len(words):
        raw, v = words[i]
        r = REDIR.match(raw)
        if r:                                # a redirection is not an operand; nor its target
            i += 1 if r.group(2) else 2; continue
        i += 1
        if ddkeys is not None:
            if v.partition("=")[0] not in ddkeys or "=" not in v:
                return False
            continue
        if not opts_done and v == "--":
            opts_done = True
        elif not opts_done and v.startswith("--"):
            key = v.partition("=")[0]
            if key in argopts:
                i += 0 if "=" in v else 1
            elif key not in flags or ("=" in v and key != "--output-error"):
                return False
        elif not opts_done and v.startswith("-") and v != "-":
            for k, ch in enumerate(v[1:]):   # a cluster: flags, an argument option last
                if "-" + ch in argopts:
                    i += 0 if k + 2 < len(v) else 1
                    break
                if "-" + ch not in flags:
                    return False
        elif v != "-" and not files:
            return False
    return True


def _line_words(line):
    """The segments of one command line as [(separator before it, words, start offset, word
    offsets)], read as parse() reads them: masked live, a closed substitution part of its word."""
    pv = list(mask_quoted(line, fill=FILL, live=True))
    for s in substitutions(line):            # a closed one is part of its word, as in parse()
        if s["kind"] in ("cmd", "proc") and s["body"][1] < len(line):
            pv[s["open"]:s["body"][1] + 1] = FILL * (s["body"][1] + 1 - s["open"])
    pv = word_chars("".join(pv))
    out, sep = [], None
    bounds = [(m.start(), m.end(), m.group(0)) for m in SEP.finditer(pv)] + [(len(pv),) * 2 + ("",)]
    start = 0
    for a, b, nxt in bounds:
        offs = [start + w[0] for w in word_spans(pv[start:a])]
        out.append((sep, split_words(pv[start:a], line[start:a]), start, offs))
        start, sep = b, nxt
    return out


def piped_to_stdin_shell(segs, k, shadowed=(), text=None):
    """Whether what segment k writes on stdout reaches a shell that runs its stdin, through any
    number of stdin copiers (`cat <<EOF | tee log | bash`) and line filters (LINE_FILTERS), text
    being what segment k writes where it is known: a filter that keeps none of it ends the route.
    A command word whose offset is in shadowed is a function's call (compound_flow()), neither a
    shell nor a copier."""
    if not fd1_to_pipe(segs[k][1]):
        return False
    for sep, words, _, offs in segs[k + 1:]:
        if sep not in ("|", "|&"):
            return False
        idx, _, _ = resolve(words)
        if idx is None or offs[idx] in shadowed:
            return False
        ins, out = _io_redirs(words)
        if ins:                              # its stdin is a file or a body, not the pipe
            return False
        if reads_code_on_stdin(words[idx:]):
            return True
        keep = line_filter(words[idx:])
        if keep is not None:
            text = keep(text)
            if text == "" or (text is not None and not text.strip()):
                return False
        elif not copies_stdin(words[idx:]):
            return False
        if not fd1_to_pipe(words):
            return False
    return False


def _body_at(p, src, end):
    """The offset in t at which a heredoc body starting at p of a backtick's code (backtick_code():
    the code, src its offset map) was written; end, the backtick body's end in t, past the code.
    src[p] is the body's first KEPT character, past its written start whenever the body opens
    with an escape the de-escaping removes (`\\``, `\\$`, `\\\\`, `\\"` inside "..."). A body starts
    just past the newline ending its operator line, and de-escaping keeps every newline, so the
    body was written just past that newline: mapped by src[p], x=`bash <<'EOF'` over `\\`true\\`;
    kill \\$(pgrep -f zz)` would name no code body
    (mh-a-heredoc-in-a-backtick-is-read-where-bash-reads-it)."""
    return src[p - 1] + 1 if 0 < p <= len(src) else end


def code_heredocs(text):
    """The start offsets in text of the heredoc bodies fed to a bare shell, read as _code_bodies()
    reads them over text with its line continuations removed (_joined()), as bash removes them
    before it reads an operator line, so `cat <<EOF \\<NL>| bash` names its code body whether or not
    the caller joined the text first, and a backtick's code, which de-escaping can give a
    continuation the whole text's join_lines() leaves, is joined too."""
    joined, src = _joined(text, list(range(len(text))))
    return {src[p] if p < len(src) else len(text) for p in _code_bodies(joined)}


def _code_bodies(text):
    """The start offsets of the heredoc bodies fed to a bare shell: CODE, not data. Every other
    body is data, and the shared mask reads it as bash does (hooks/quote_mask.py, heredocs():
    every delimiter form, a quoted body literal, an unquoted body's substitutions live), by the
    same scan parse() masks with, never by a regex of its own: so the apostrophe in a
    `<<'END-NOTE'` body opens no span, and a body inside `"$(bash <<'EOF' ...)"` is found and named
    as code here.
    A body read by a stdin copier (COPIES_STDIN) whose stdout is piped to such a shell is code
    too: `cat <<'EOF' | bash` runs the body exactly as `bash <<'EOF'` does. The copier's stdin must
    be this body (no later stdin redirection) and its stdout the pipe. A body that reaches such a
    shell through a compound
    command is code as well, read over the whole text by compound_flow(): a copier inside a
    group, subshell, if, loop or case piped on (`(cat <<EOF) | bash`, `{ cat <<EOF; } | bash`),
    the compound's own heredoc (`(cat) <<EOF | bash`), a shell inside the compound that is piped
    to (`cat <<EOF | (bash)`), and a pipe that ends the operator's line (`cat <<EOF |`, the shell
    after the body). What that reader leaves unread, and why, is stated above compound_flow().
    A heredoc inside a backtick body is read by this same function over the code bash runs there
    (backtick_code(), as compound_flow() and _backtick_region() read it), and what it names is put
    back at the offset it was written at, so two backticks deep the `\\`` before `bash` does not
    glue into the command word, and x=`: \\`bash <<EOF $A` names its code body."""
    code, flow = set(), compound_flow(text)
    shadowed = flow[2]
    subs = substitutions(text)
    ticks = [s for s in subs if s["kind"] == "cmd" and text[s["open"]] == "`"]
    spans = [s["body"] for s in ticks]
    for s in ticks:
        if any(lo <= s["open"] < hi for lo, hi in spans if (lo, hi) != s["body"]):
            continue                         # read by the backtick it sits in
        got, src = tick_code(text, s)
        code |= {_body_at(p, src, s["body"][1]) for p in code_heredocs(got)}
    for hd in heredocs(text):
        if any(lo <= hd["op"] < hi for lo, hi in spans):
            continue
        line_start = text.rfind("\n", 0, hd["op"]) + 1
        prefix = text[line_start:hd["op"]]
        pv = list(mask_quoted(prefix, fill=FILL, live=True))
        for s in substitutions(prefix):          # a closed one is part of its word, as in parse()
            if s["kind"] in ("cmd", "proc") and s["body"][1] < len(prefix):
                pv[s["open"]:s["body"][1] + 1] = FILL * (s["body"][1] + 1 - s["open"])
        pv = word_chars("".join(pv))
        cut = max([pm.end() for pm in SEP.finditer(pv)] or [0])
        words = split_words(pv[cut:], prefix[cut:])
        offs = [line_start + cut + w[0] for w in word_spans(pv[cut:])]
        idx, _, _ = resolve(words)
        if idx is not None and offs[idx] in shadowed:   # a function's call (a shell's name, a
            continue                                     # copier's): compound_flow() reads it
        if idx is not None and reads_code_on_stdin(words[idx:]):
            code.add(hd["body"][0])
            continue
        line_end = text.find("\n", hd["op"])
        line = text[line_start:len(text) if line_end < 0 else line_end]
        try:
            segs = _line_words(line)
        except MaskMismatch:
            continue
        rel = hd["op"] - line_start
        k = max(j for j, s in enumerate(segs) if s[2] <= rel)
        _, words, _, offs = segs[k]
        idx, _, _ = resolve(words)
        keep = line_filter(words[idx:]) if idx is not None else None
        if idx is None or not (keep or copies_stdin(words[idx:])):
            continue
        own = max(j for j, o in enumerate(offs) if o <= rel)   # the `<<WORD` word itself
        if words[own][0][:rel - offs[own]] not in ("", "0"):   # `3<<EOF` is not its stdin
            continue
        if _io_redirs(words[own + 1:])[0]:
            continue
        body = text[hd["body"][0]:hd["body"][1]]
        body = keep(body) if keep else body
        if not body.strip():
            continue
        if piped_to_stdin_shell(segs, k, {o - line_start for o in shadowed}, text=body):
            code.add(hd["body"][0])
    return code | flow[0]


# A COMPOUND COMMAND IN A PIPELINE. bash pipes a compound as it pipes a simple command, and
# inside one the streams are the compound's own: every command in it writes to the compound's
# stdout unless it redirects its
# own, and the first command in it that reads stdin reads the compound's. So `(cat <<EOF) | bash`,
# `{ cat <<EOF; } | bash`, `(cat) <<EOF | bash`, `{ cat <<< '...'; } | bash`, `(echo '...') | bash`
# and `cat <<EOF | (bash)` all hand the shell the text, as do the same forms with if/then/fi,
# for/while/until/select ... done and case ... esac in place of the group, nested to any depth,
# written over several lines, or inside a substitution. Which forms bash pipes this way was taken
# from bash itself, every form run by bash with stand-ins first, not from the grammar as
# remembered. compound_flow() reads the structure of the
# whole text (heredoc bodies blanked, quotes, comments, substitutions and arithmetic masked), and
# follows a stream out of and into compounds:
#   out_reaches(N)  N's stdout reaches a shell that runs its stdin (_sinks()): where N's fd 1 goes
#                   once N's own redirections are
#                   applied, left to right, over the fds it inherits -- the pipe to a next stage
#                   that is fed (in_reaches), a `>(...)` whose first reader is fed, or, through a
#                   dup (`>&2`, `3>&1`, `>&3-`), whatever that other fd is there; an fd N does not
#                   name is what it is where N's compound, or the call N's body runs for, runs;
#   in_reaches(N)   what N reads on stdin from the pipe reaches such a shell: N has no stdin
#                   redirection of its own, and it IS that shell (reads_code_on_stdin), or a copier
#                   (COPIES_STDIN) whose stdout reaches one, or a compound whose first stdin reader
#                   is fed;
#   first reader    of a compound: the first command at the head of one of its pipelines that is a
#                   shell reading stdin or a copier, with no stdin redirection of its own; a command
#                   that is neither is taken not to read stdin. That is wrong for one that does read
#                   it (`{ grep x; bash; }` is read as feeding bash), the refusing direction.
#   a call      of a function defined in the text is its body, run there (_walk_node()):
#               `f() { cat <<EOF; }; f | bash`, `function f { echo '...'; }; g() { f;
#               }; g | bash` and `f() { bash; }; echo '...' | f` hand the shell the text; the
#               body is the definition in force where bash runs the call, and a body no call runs
#               is not read here (`f() { ...; } | true; f`, `( f() ...; ); f`, `unset -f f; f`,
#               `f; f() ...` and `g() { f() ...; }; f` run no body);
#   <(...)      a stdin whose last redirection is from a `<(...)`, written as its own word, reads
#               what the substitution's top writes: `bash < <(echo '...')`, `f < <(echo '...')`
#               with f a shell;
#   >(...)      a stdout whose last redirection is into a `>(...)`, written as its own word, reaches
#               a shell when the substitution's first stdin reader is fed:
#               `cat <<EOF > >(bash)`, `{ echo '...'; } > >(sh)`, `f > >(cat | bash)`;
#   exec        an `exec` with only redirections redirects stdout for every later command of its
#               shell (_execs_back()): `exec > >(bash); echo '...'`, and `{ exec
#               > >(sh); }; f` with f writing the text; not past the end of a subshell, a pipeline
#               element, or a group whose own stdout redirection bash undoes at its end.
# WHICH COMMANDS BASH RUNS, AND ON WHICH FD. `&&`, `||` and every branch are not read as taken, a
# loop body is not run twice, a bare `unset NAME` may remove a function, an stdout dup onto a
# redirected fd is followed, a `>(...)` opened while fd 1 is another one writes there, and a shell
# reads its stdin in more spellings than shell_code() names; so `f() { echo; } >&2; f 2>&1 |
# bash`, `echo '...' > >(bash) > >(cat)`, `>(bash /dev/stdin)`, `>(bash -c bash)` and a call in a
# backtick hand the shell the text, and `false && f | bash`, `case y in x) f;; esac | bash`, `f()
# { return; echo; }; f | bash` and `unset f; f | bash` do not. So:
#   a walk      (_walk_list()) runs each list in bash's order: the right side of `&&` after a
#               status known nonzero, and of `||` after one known zero, does not run (a status is
#               known for `true`, `:`, `false` and `!` of one); an if/elif condition, a while or
#               until condition and a case word with its patterns decide their bodies where the
#               words alone say (else either may run); a for over words it can count runs its
#               body that many times, up to two, the second pass a copy of the first's text; what
#               follows a `return` in a body, or an `exit`, does not run; a command in the
#               background, a subshell or a pipeline element changes nothing after it. A command
#               bash does not run is not read here, nor what it defines, unsets or writes.
#   in force    a definition that may run is added beside the one in force (a call runs either);
#               `unset -f`, and a bare `unset NAME` where no variable may have the name, remove a
#               function only where they surely run, through `builtin`, `command` and `eval` too.
#   a stdin shell  also `bash /dev/stdin` (or /dev/fd/0), and a `-c` whose code hands its stdin to
#               such a shell (`bash -c bash`, `sh -c 'cat | sh'`, `bash -c 'exec bash'`), read by
#               this same reader over the code (reads_code_on_stdin()).
#   a read      before the shell inside a `>(...)` an echo or printf opens itself takes the first
#               line of what it writes (`echo '...' > >(read l; bash)` hands the shell nothing).
# THE CALL'S WORDS ARE THE BODY'S PARAMETERS, so `f() { echo "$1"; }; f '...' | bash`, `f() { bash
# <<< "$1"; }; f '...'` and an unquoted heredoc expanding `$1` hand the shell the caller's text.
# A call's body runs with the call's words, each expanded with the
# caller's own, as its positional parameters (_call_args(); a `"$@"` is each of the caller's), a
# `shift` or `set --` that surely runs changes them (_set_args()), and every word of a body node
# compound_flow() reads -- what an echo or printf writes, a herestring, the command a stdin is fed
# to -- is read with `$N`, `${N}`, `$*` and `$@` expanded (_node_wv()), as is an unquoted heredoc
# (_heredoc_with_args()). Not read: `${N:-...}` and other operators on a parameter, `$#`, an
# unquoted `$*` split into several words of a further call, a shift behind a condition (the
# parameters then unknown, read as written), a parameter that names the function a body calls or
# is an `eval`'s code, and the text's own parameters, read as written.
# WHERE THE TEXT IS HELD ON ITS WAY. A substitution's output, a `$g` command word, a shell's name
# shadowed by a function, and a `read` before the shell are followed, so `f() { echo '...'; };
# bash <<< "$(f)"`, `echo "$(f)" | bash` and `g=f; $g | bash` hand the shell the text, and
# `bash() { cat; }; echo '...' | bash` and `f() { read x; bash; }; echo '...' | f` do not. So:
#   held        a `$(...)` or backtick writes, at its top, the value of the word it is in, and of
#               every word that expands a variable an assignment of that word gave it (`x=$(f);
#               bash <<< "$x"`): where the word is the command's last stdin redirection's
#               herestring, it feeds that command; where the command is an echo or printf that
#               writes it, it is what that writes (_word_role(), ("word", ...) in _up());
#   a variable  a plain `NAME=WORD` that surely runs, WORD a literal, gives NAME that value, one
#               that may run adds it beside the one before (_var_maybe()); a command word that is
#               the variable alone calls each function its values name (`g=f; $g`), and with one
#               value is that value wherever the command's words are read (`s=bash; f | $s`);
#   shadowed    a command word every walk found a call of a function surely in force is no shell
#               and no copier on the line readers outside this walk either: parse()'s pipe and
#               herestring, code_heredocs()'s heredoc and copier (compound_flow()'s third value);
#   a read      at the head of the compound or call an echo or printf alone pipes into takes the
#               first line of what it writes (_own_drop(): `echo '...' | f`, f `read x; bash`).
# TEE, A DUPLICATED STDOUT, A LINE FILTER, A STDOUT SENT AWAY. `echo '...' | tee >(bash)`, `| sort
# | bash`, `| grep pkill | bash` and `| head -1 | bash` hand the shell the text, and `echo '...'
# >/dev/null | bash`, `> FILE | bash`, `>&- | bash`, `>&2 2>&1 | bash` and `>&2 |& bash` do not.
# So:
#   tee         a copier's FILE operand that is a `>(...)` written as its own word is a sink of its
#               stdin, as its stdout is (_tee_readers());
#   a filter    a LINE_FILTERS program is a reader of its stdin and writes the lines it keeps:
#               _onward() and _through() carry the text down every route a sink takes, so `| grep
#               -v pkill | bash` and `| head -0 | bash` hand the shell nothing, here as on the
#               per-line readers (parse()'s pipe walk, piped_to_stdin_shell(), code_heredocs());
#   fd 1        the per-line readers ask where fd 1 ends once the writer's redirections are
#               applied (fd1_to_pipe()), as _table() does here; and `|&`'s 2>&1 is applied after an
#               element's own redirections, as bash applies it (_sinks()), not before them.
# Not read here, stated: a substitution in any other word (a `-c` string, an `eval`'s code, a
# file name, an operand of another program); a variable set by `read`, `declare`, a `for` or any
# assignment that is neither a literal nor a substitution, whose value is read as none; a value
# split into several words of a call; a shell's name shadowed on its `-c` or wrapper path, read as
# the shell (the refusing direction).
# Not read: a text whose structure this reader cannot match (an unbalanced or unmodelled token,
# such as a `(` inside `${...}`, `coproc`, or a pattern with extglob parentheses), which keeps the
# per-line reading above and nothing more, as does a text with more function calls than
# _CALLS_MAX expands; a call inside its own body, not expanded a second time; a status known only
# when the shell runs (`test`, `[[ ]]`, any program), read as either, so a call behind one is read
# as run, and an unset behind one as not run (the refusing direction); `break` and `continue`,
# read as ending nothing; a loop run more than twice, read as twice; a variable a bare `unset`
# may find that the text names nowhere, other than in an all-capitals name; a `<(...)` that is a
# FILE operand (`bash <(...)`), and a `>(bash)` that is one of any program but a copier (`sort -o
# >(bash)`, `sed 'w >(bash)'`); a line filter that writes kill text it did not read (`sed
# 's/x/pkill .../'`), and one LINE_FILTERS does not read exactly, read as passing every line
# (`grep -v 'p.ill'`, `sed d`, `awk 0`: the refusing direction); a function
# defined in a backtick and called outside it; a heredoc, and a `>(...)`, written in a definition
# made outside a backtick and called inside it, and in an `eval`'s code; a shell handed the text
# by a command written directly, in a body no call runs or in a branch bash does not take
# (`false && echo ... | bash`), which the per-line reading still reads where it is written.
class _Unread(Exception):
    pass


class _Node:
    def __init__(self, kind, words=(), body=None):
        self.kind, self.words = kind, list(words)
        self.seq = [["body", body or []]]
        self.redirs, self.parent, self.pipeline, self.index = [], None, None, 0
        self.name, self.sub, self.top, self.region = None, False, None, None
        self.loop, self.call, self.into, self.streams = False, None, None, None
        self.ctype, self.items, self.var, self.word = None, None, None, None
        self.conn, self.bg, self.neg, self.errpipe = None, False, False, False
        self.live, self.origin, self.tab, self.args = 2, None, None, None
        self.holders, self.cmdvar, self.varheld = [], None, []
        self.callvals = []                  # vals in force at each walk of it inside a call
        self.lift = 0                       # backticks its words' text is above (compound_flow())
        self.relay = None                   # a read's: what runs after it in its shell (_relays())

    # A compound's parts in the order bash may run them: ("body", pipes) for a group, a subshell or
    # a call; ("cond", c), ("then", b) ... ("else", e) for if; ("cond", c), ("do", b) for while and
    # until; ("do", b) for for and select; ("arm", b, patterns, terminator) for case. A loop walked
    # a second time has its second pass appended as parts of their own.
    @property
    def body(self):
        return [p for part in self.seq for p in part[1]]

    @body.setter
    def body(self, pipes):
        self.seq = [["body", pipes]]


_CLOSERS = {"}", "fi", "done", "esac", "then", "elif", "else", "do"}
# The reserved words after which a list starts, on the same line or the next one.
_LIST_OPENERS = ("then", "do", "else", "elif")


def _tokens(s, t, lo):
    """Operators and words of the masked region s (t[lo:lo+len(s)] unmasked): ("op", text, off) or
    ("w", raw, off). A `&` after `<`/`>` or before `>`, and a `|` after `>`, are part of a word."""
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            i += 1
            continue
        if c in "\n()":
            out.append(("op", c, lo + i)); i += 1
            continue
        if c == ";":
            for op in (";;&", ";;", ";&", ";"):
                if s.startswith(op, i):
                    out.append(("op", op, lo + i)); i += len(op)
                    break
            continue
        if c == "|" or (c == "&" and not s.startswith("&>", i)):
            op = s[i:i + 2] if s[i:i + 2] in ("||", "|&", "&&") else c
            out.append(("op", op, lo + i)); i += len(op)
            continue
        if c == "`":
            raise _Unread("an unclosed backtick")
        j = i
        while j < n and s[j] not in " \t\n;()`":
            if s[j] == "|" and not (j > i and s[j - 1] == ">"):
                break
            if s[j] == "&" and not (j > i and s[j - 1] in "<>") and not s.startswith("&>", j):
                break
            j += 1
        out += [("w", t[lo + x:lo + y], lo + x) for x, y in _redir_cuts(s, i, j)]
        i = j
    return out


def _until(*ws):
    return lambda tok: tok[0] == "w" and tok[1] in ws


class _Reader:
    def __init__(self, toks):
        self.toks, self.k = toks, 0

    def peek(self, d=0):
        return self.toks[self.k + d] if self.k + d < len(self.toks) else None

    def take(self):
        tok = self.peek()
        if tok is None:
            raise _Unread("the text ends inside a command")
        self.k += 1
        return tok

    def is_op(self, *ops, d=0):
        tok = self.peek(d)
        return tok is not None and tok[0] == "op" and tok[1] in ops

    def is_word(self, *ws):
        tok = self.peek()
        return tok is not None and tok[0] == "w" and tok[1] in ws

    def skip_newlines(self):
        while self.is_op("\n"):
            self.k += 1

    def lst(self, stop, parent):
        """The pipelines of a list, until stop(token) holds at command position (or the end). The
        head of each pipeline carries how it is joined to the one before it (conn: `&&`, `||` or
        None) and whether its and-or list runs in the background (bg, a `&` after it)."""
        pipes, conn = [], None
        while True:
            while self.is_op(";", "\n", "&", "&&", "||"):
                op = self.take()[1]
                if op in ("&&", "||"):
                    conn = op
                elif op == "&":
                    for q in reversed(pipes):
                        q[0].bg = True
                        if q[0].conn is None:
                            break
                    conn = None
                elif op == ";":
                    conn = None
            tok = self.peek()
            if tok is None:
                if stop is not None:
                    raise _Unread("a compound is not closed")
                return pipes
            if stop is not None and stop(tok):
                return pipes
            p = self.pipeline(parent)
            p[0].conn, conn = conn, None
            pipes.append(p)

    def pipeline(self, parent):
        p = [self.element(parent)]
        while self.is_op("|", "|&"):
            p[-1].errpipe = self.take()[1] == "|&"
            self.skip_newlines()
            p.append(self.element(parent))
        for i, node in enumerate(p):
            node.pipeline, node.index = p, i
        return p

    def compound(self, kind, closer, parent):
        node = _Node(kind)
        node.parent = parent
        node.body = self.lst(lambda tok: tok[0] == "w" and tok[1] == closer, node)
        self.take()
        return node

    def part(self, node, role, *closers):
        """Read a list of node's into node.seq as role, up to one of closers; the closer taken."""
        node.seq.append([role, self.lst(_until(*closers), node)])
        return self.take()[1]

    def element(self, parent):
        neg = False
        while True:
            if self.is_word(*_LIST_OPENERS):          # a list may start on the next line
                self.k += 1
                self.skip_newlines()
            elif self.is_word("!"):
                neg = not neg
                self.k += 1
            elif self.is_word("time", "-p"):
                self.k += 1
            else:
                break
        node = self._element(parent)
        node.neg = neg
        return node

    def _element(self, parent):
        tok = self.take()
        kind, val = tok[0], tok[1]
        if kind == "op" and val == "(":
            if self.is_op("(") and self.peek()[2] == tok[2] + 1:
                raise _Unread("an arithmetic command the mask did not fill")
            node = _Node("compound")
            node.parent, node.sub = parent, True
            node.body = self.lst(lambda t_: t_[0] == "op" and t_[1] == ")", node)
            self.take()
        elif kind == "op":
            raise _Unread("an operator where a command was due")
        elif val == "{":
            node = self.compound("compound", "}", parent)
        elif val == "if":
            node = _Node("compound")
            node.parent, node.ctype, node.seq = parent, "if", []
            while True:
                self.part(node, "cond", "then")
                end = self.part(node, "then", "elif", "else", "fi")
                if end == "else":
                    self.part(node, "else", "fi")
                if end != "elif":
                    break
        elif val in ("while", "until"):
            node = _Node("compound")
            node.parent, node.ctype, node.seq, node.loop = parent, val, [], True
            self.part(node, "cond", "do")
            self.part(node, "do", "done")
        elif val in ("for", "select"):
            node = _Node("compound")
            node.parent, node.ctype, node.seq, node.loop = parent, val, [], True
            items = None
            if self.peek() is not None and self.peek()[0] == "w":
                node.var = self.take()[1]
                self.skip_newlines()
                if self.is_word("in"):
                    self.take()
                    items = []
                    while self.peek() is not None and self.peek()[0] == "w":
                        items.append(self.take())
            while not self.is_op(";", "\n") and not self.is_word("do"):   # `for ((...))`
                self.take()
                items = None
            while self.is_op(";", "\n"):
                self.take()
            if not self.is_word("do"):
                raise _Unread("a loop body that is not `do ... done`")
            self.take()
            node.items = items
            self.part(node, "do", "done")
        elif val == "case":
            node = _Node("compound")
            node.parent, node.ctype, node.seq = parent, "case", []
            ws = []
            while not self.is_word("in"):
                ws.append(self.take())
            self.take()
            node.word = ws[0] if len(ws) == 1 and ws[0][0] == "w" else None
            while True:
                self.skip_newlines()
                if self.is_word("esac"):
                    self.take()
                    break
                if self.is_op("("):
                    self.take()
                pats = []
                while not self.is_op(")"):
                    tok = self.take()
                    if tok[0] == "op" and tok[1] != "|":
                        raise _Unread("a case pattern this reader does not model")
                    if tok[0] == "w":
                        pats.append(tok)
                self.take()
                arm = self.lst(lambda t_: (t_[0] == "op" and t_[1] in (";;", ";&", ";;&"))
                               or (t_[0] == "w" and t_[1] == "esac"), node)
                term = self.take()[1] if self.is_op(";;", ";&", ";;&") else None
                node.seq.append(["arm", arm, pats, term])
        elif val == "function" and self.peek() is not None and self.peek()[0] == "w":
            name = self.take()
            if self.is_op("(") and self.is_op(")", d=1):
                self.k += 2
            return self.definition(name, parent)
        elif val in ("function", "coproc") or val in _CLOSERS:
            raise _Unread("%r where a command was due" % val)
        elif val == "[[":
            node = _Node("test")
            while not self.is_word("]]"):
                self.take()
            self.take()
            return node
        else:
            words = [tok]
            while self.peek() is not None and self.peek()[0] == "w":
                words.append(self.take())
            if self.is_op("("):
                if len(words) != 1 or not self.is_op(")", d=1):
                    raise _Unread("a word before `(`")
                self.k += 2
                return self.definition(tok, parent)
            node = _Node("simple", words)
            node.parent = parent
            return node
        while self.peek() is not None and self.peek()[0] == "w":
            node.redirs.append(self.take())
        return node

    def definition(self, name, parent):
        """A function definition `NAME () BODY` or `function NAME [()] BODY`: a node of kind "def"
        whose body is the compound BODY, with BODY's own redirections, as written."""
        node = _Node("def", [name])
        node.parent, node.name = parent, unquote(name[1])
        self.skip_newlines()
        body = self.element(node)
        if body.kind != "compound":
            raise _Unread("a function body that is not a compound command")
        body.pipeline, body.index = [body], 0
        node.body = [[body]]
        return node


_COPIED = ("name", "sub", "loop", "ctype", "items", "var", "word", "conn", "bg", "neg", "errpipe",
           "call", "lift")


def _copy(node, parent, origin=None):
    """A copy of node and everything under it, its parent parent; origin, where given, marks every
    copied node as text written elsewhere (see _walk_node())."""
    new = _Node(node.kind, node.words)
    for a in _COPIED:
        setattr(new, a, getattr(node, a))
    new.redirs, new.parent = list(node.redirs), parent
    new.origin = origin if origin is not None else node.origin
    new.seq = [[part[0], _copies(part[1], new, origin)] + list(part[2:]) for part in node.seq]
    return new


def _lifted(d):
    """A copy of definition d carried into a backtick (text written elsewhere, origin -1), each node
    of it one backtick further below the text its words' offsets are of: 1 for one written in the
    text above, one more for one carried into that text already, 0 (none) for the code of an eval."""
    new = _copy(d, None, -1)

    def pair(a, b):
        b.lift = 1 if a.origin is None else (a.lift + 1 if a.lift else 0)
        for pa, pb in zip(a.seq, b.seq):
            for xa, xb in zip(pa[1], pb[1]):
                for na, nb in zip(xa, xb):
                    pair(na, nb)
    pair(d, new)
    return new


def _copies(pipes, parent, origin=None):
    out = [[_copy(n, parent, origin) for n in p] for p in pipes]
    for p in out:
        for i, n in enumerate(p):
            n.pipeline, n.index = p, i
    return out


_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")


def _cmd_words(node):
    """[(raw, value)] of a simple node from its command word on, as bash looks it up: assignments
    before it, and every redirection and its target, left out."""
    w, i, out, cmd = _wv(node.words), 0, [], False
    while i < len(w):
        raw, v = w[i]
        r = REDIR.match(raw)
        if r:
            i += 1 if r.group(2) else 2
            continue
        i += 1
        if not cmd and _ASSIGN.match(raw):
            continue
        cmd = True
        out.append((raw, v))
    return out


# A word that is one variable's value and nothing else: `$g`, `${g}`, `"$g"`, `"${g}"`.
_VAR_WORD = re.compile(r'\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})|"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})"')


def _call_names(node, vals=None):
    """The names bash may look the command word of a simple node up by, its quotes removed: one,
    or none for a node with no command word. A word that is one variable a plain `NAME=WORD` may
    have given a literal (vals) is each literal it may hold, as bash expands it: quoted, the whole
    value; unquoted, its first field (`g=f; $g | bash` calls f); None among them where the value
    may be one the text does not give."""
    w = _cmd_words(node)
    if not w:
        return []
    got = _var_values(w[0][0], vals)
    if got is None:
        return [w[0][1]]
    return [None if not isinstance(v, str) else
            v if w[0][0].startswith('"') or not v.split() else v.split()[0] for v in got]


_VAR_REF = re.compile(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})")


def _var_refs(raw, pat=None):
    """The names of the variables the word raw expands: each `$NAME` or `${NAME}` outside '...'
    and $'...', and not escaped (pat: another pattern of a reference, its name in group 1 or 2)."""
    pat = pat or _VAR_REF
    out, i, n, quote = [], 0, len(raw), None
    while i < n:
        c = raw[i]
        if quote == "'":
            quote = None if c == "'" else quote
        elif c == "\\":
            i += 1
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "'" and quote is None:
            quote = "'"
        elif c == "$":
            m = pat.match(raw, i)
            if m:
                out.append(m.group(1) or m.group(2))
            elif raw[i + 1:i + 2] == "'" and quote is None:
                j = i + 2
                while j < n and raw[j] != "'":
                    j += 2 if raw[j] == "\\" else 1
                i = j
        i += 1
    return out


def _var_values(raw, vals):
    """The values vals says the variable the word raw is (and nothing else) may hold, or None."""
    m = _VAR_WORD.fullmatch(raw)
    name = m and next(g for g in m.groups() if g)
    return vals.get(name) if name and vals else None


def _var_maybe(st, name, value, live):
    """st.vals after an act that gives name the literal value (None: a value the text does not
    give), surely where live is 2, else beside what it may hold already."""
    if live == 2:
        if value is None:
            st.vals.pop(name, None)
        else:
            st.vals[name] = [value]
    elif name in st.vals:
        st.vals[name] = st.vals[name] + [value]
    elif value is not None:
        st.vals[name] = [None, value]


def _prefix_assigns(node):
    """[(name, value)] of the assignments written before a simple node's command word: the
    literal value of a plain `NAME=WORD`, None for any other (_var_maybe())."""
    out = []
    for raw, _ in _wv(node.words):
        if REDIR.match(raw):
            continue
        m = _ASSIGN.match(raw)
        if not m:
            break
        name = re.match(r"[A-Za-z_]\w*", raw).group(0)
        val = raw[m.end():]
        plain = m.group(0) == name + "=" and _literal(val)
        out.append((name, unquote(val) if plain else None))
    return out


# A variable as block-unsafe-kill.sh's with_literals() fills it in: `$NAME` or `${NAME}`.
_PLAIN_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_AT_CALL_MAX = 64


def _at_call(code, valsets):
    """The codes bash hands on where code was read from a function body: for each vals in force
    at a call that ran it, each `$NAME` and `${NAME}` replaced by each literal NAME may hold there,
    and by `${NAME-}` where NAME holds a value the text does not give, or none (unset). That
    spelling is the same expansion and is one the caller's reader of literals assigned before the
    body was WRITTEN does not fill in: what NAME held at the definition is not what bash expands at
    the call. code with no such reference, or valsets empty, is code as it is."""
    if not valsets or not _PLAIN_REF.search(code):
        return [code]
    out = []
    for vals in valsets:
        got = [""]
        pos = 0
        for m in _PLAIN_REF.finditer(code):
            name = m.group(1) or m.group(2)
            lits = vals.get(name) or [None]
            opts = []
            for v in lits:
                o = v if isinstance(v, str) else "${%s-}" % name
                if o not in opts:
                    opts.append(o)
            lead = code[pos:m.start()]
            got = [g + lead + o for g in got for o in opts][:_AT_CALL_MAX]
            pos = m.end()
        for g in got:
            if g + code[pos:] not in out:
                out.append(g + code[pos:])
        if len(out) >= _AT_CALL_MAX:
            break
    return out


def _cmd_offset(node):
    """The offset of a simple node's command word as _cmd_words() finds it, or None."""
    i, ws = 0, node.words
    while i < len(ws):
        raw = ws[i][1]
        r = REDIR.match(raw)
        if r:
            i += 1 if r.group(2) else 2
            continue
        if _ASSIGN.match(raw):
            i += 1
            continue
        return ws[i][2]
    return None


_CALLS_MAX = 256


def _spend(budget):
    budget[0] -= 1
    if budget[0] < 0:
        raise _Unread("more function calls than this reader expands")


class _State:
    """What is in force where a command runs: env ({name: [compound or None]}, the definitions one
    of which a call of name runs, None where the name may still be no function at all), vs (the
    names a command run so far may have made variables), vals ({name: [each value an assignment
    that may have run last gave it]}), stack (the functions being run), args (the positional
    parameters, a list, or None where they are not known from the text: the text's own), and the
    walk's shared budget, seen, assigned and shadow ({offset of a command word: True while every
    walk of it found a call of a function surely in force, see _walk_simple()})."""
    def __init__(self, env, vs, stack, budget, seen, assigned, args=None, vals=None, shadow=None,
                 callvals=None):
        # A value in vals is a literal string, None (one the text does not give), or ("held", a, b):
        # what the `$(...)`s and backticks written in text[a:b] write (_assign(), compound_flow()).
        # callvals ({offset of a command word: [vals at each walk of it inside a call]}) is shared;
        # scoped is the names a `local` (or `declare`) of this call made its own (_walk_simple()).
        self.env, self.vs, self.stack, self.args = env, vs, stack, args
        self.budget, self.seen, self.assigned = budget, seen, assigned
        self.vals = {} if vals is None else vals
        self.shadow = {} if shadow is None else shadow
        self.callvals = {} if callvals is None else callvals
        self.scoped = set()

    def fork(self):
        """The copy a subshell runs with: what it changes is not seen after it."""
        new = _State(dict(self.env), set(self.vs), self.stack, self.budget, self.seen,
                     self.assigned, self.args, dict(self.vals), self.shadow, self.callvals)
        new.scoped = self.scoped
        return new

    def inner(self, name, args):
        """The state a call of name runs its body with: the caller's shell, one function deeper,
        the call's words its positional parameters."""
        return _State(self.env, self.vs, self.stack + (name,), self.budget, self.seen,
                      self.assigned, args, self.vals, self.shadow, self.callvals)


# A positional parameter as a word expands it: `$N`, `${N}`, `$*`, `$@`, `${*}`, `${@}`. `$0`, `$#`
# and every `${N...}` with an operator are left as written.
_POSITIONAL = re.compile(r"\$(?:([0-9])|\{([0-9]+|[*@])\}|([*@]))")


def _param_value(m, args):
    n = m.group(1) or m.group(2) or m.group(3)
    if n in ("*", "@"):
        return " ".join(args)
    k = int(n)
    if k == 0:
        return None
    return args[k - 1] if k <= len(args) else ""


def _with_args(raw, args):
    """The word raw with each positional parameter bash expands in it replaced by its value from
    args, quoted so that unquote() gives that value: inside "..." with `$`, a backtick, `"` and a
    backslash escaped, outside quotes as a '...' word. Inside '...' and $'...' nothing expands; a
    substitution's body is left as written. args None leaves raw as it is."""
    if args is None or "$" not in raw:
        return raw
    subs = {s["open"]: s["body"][1] for s in substitutions(raw) if s["kind"] in ("cmd", "proc")}
    out, i, n, quote = [], 0, len(raw), None
    while i < n:
        c = raw[i]
        if i in subs and quote in (None, '"'):
            end = min(subs[i] + 1, n)
            out.append(raw[i:end])
            i = end
            continue
        m = _POSITIONAL.match(raw, i) if c == "$" and quote in (None, '"') else None
        if m and _param_value(m, args) is not None:
            v = _param_value(m, args)
            out.append(re.sub(r'(["\\$`])', r"\\\1", v) if quote == '"'
                       else "'" + v.replace("'", "'\\''") + "'")
            i = m.end()
        elif quote == "'":
            quote = None if c == "'" else quote
            out.append(c); i += 1
        elif quote == "$'":
            if c == "\\":
                out.append(raw[i:i + 2]); i += 2
                continue
            quote = None if c == "'" else quote
            out.append(c); i += 1
        elif c == "\\":
            out.append(raw[i:i + 2]); i += 2
        elif quote == '"':
            quote = None if c == '"' else quote
            out.append(c); i += 1
        elif c == "$" and raw[i + 1:i + 2] == "'":
            quote = "$'"; out.append("$'"); i += 2
        else:
            quote = c if c in "'\"" else None
            out.append(c); i += 1
    return "".join(out)


def _heredoc_with_args(body, args):
    """An unquoted heredoc body as the shell reading it expands it: each positional parameter
    replaced by its value, and the backslash before `$`, a backtick or a backslash removed."""
    def one(m):
        if m.group(0).startswith("\\"):
            return m.group(0)[1:]
        v = _param_value(m, args)
        return m.group(0) if v is None else v
    return re.sub(r"\\[$`\\]|" + _POSITIONAL.pattern, one, body)


def _node_wv(node):
    """[(raw, value)] of node's words (a compound's, its redirections) as bash expands them where
    node runs: a body's positional parameters are the words of the call that runs it."""
    ws = _wv(node.words if node.kind == "simple" else node.redirs)
    if node.cmdvar is not None:                      # `$g`, g a literal (_walk_simple())
        k = [i for i, t in enumerate(node.words) if t[2] == node.cmdvar[0]]
        if k:
            v = node.cmdvar[1]
            ws[k[0]] = ("'" + v.replace("'", "'\\''") + "'", v)
    if node.args is None:
        return ws
    out = []
    for raw, v in ws:
        new = _with_args(raw, node.args)
        out.append((new, v) if new == raw else (new, unquote(new)))
    return out


def _call_args(node, st):
    """The positional parameters a call's body runs with: the call's words after its name, each as
    bash expands it with the caller's own; a `"$@"` (or bare `$@`) is each of the caller's."""
    out = []
    for raw, v in _cmd_words(node)[1:]:
        if st.args is not None and raw in ('"$@"', "$@", '"${@}"', "${@}"):
            out += st.args
        else:
            new = _with_args(raw, st.args)
            out.append(v if new == raw else unquote(new))
    return out


def _set_args(node, st, live):
    """What a `shift [N]` or `set -- WORDS` that may run does to the positional parameters: where
    it surely runs, the list it leaves; where it only may, they are no longer known."""
    w = _cmd_words(node)
    if not w or w[0][1] not in ("shift", "set"):
        return
    if w[0][1] == "set" and (len(w) < 2 or w[1][1] != "--"):
        return
    if live != 2:
        st.args = None
    elif w[0][1] == "set":
        st.args = [v if _with_args(raw, st.args) == raw else unquote(_with_args(raw, st.args))
                   for raw, v in w[2:]]
    elif st.args is not None:
        k = w[1][1] if len(w) > 1 else "1"
        if not k.isdigit():
            st.args = None
        elif int(k) <= len(st.args):
            st.args = st.args[int(k):]


# A name a bare `unset NAME` may find as a variable, from the text alone: written before `=`,
# `+=`, `:=` or an arithmetic assignment operator anywhere in it (`f=1`, `${f:=1}`, `(( f += 1 ))`).
_ASSIGNED = re.compile(r"(?<![\w$])([A-Za-z_]\w*)\s*(?:\[[^]]*\])?\s*(?::|[-+*/%&|^])?=(?!=)")
# Builtins that make a variable of an operand named NAME or NAME=VALUE (`read f`, `declare f`).
_DECLARERS = {"declare", "typeset", "local", "export", "readonly", "read", "mapfile", "readarray",
              "getopts", "let", "printf"}


def _assigned_names(text):
    return {m.group(1) for m in _ASSIGNED.finditer(text)}


def _dead(pipes):
    """Mark pipes as commands bash does not run."""
    for p in pipes:
        for n in p:
            n.live = 0


def _flow_join(flow, f, sure):
    """flow, after a part that ended with f (a `return` or `exit`: ("certain"|"maybe", kind));
    a part that ran only maybe ends at most maybe."""
    if f is None:
        return flow
    f = f if sure else ("maybe", f[1])
    return f if flow is None or f[0] == "certain" else flow


def _status_of(node):
    """The exit status a simple node has from its words alone: 0 for `true` and `:`, 1 for `false`,
    written with no redirection; None for every other command."""
    w = _wv(node.words)
    if not w or any(REDIR.match(raw) for raw, _ in w) or _ASSIGN.match(w[0][0]):
        return None
    return {"true": 0, ":": 0, "false": 1}.get(w[0][1])


def _walk_list(pipes, st, live):
    """Walk the pipelines of a list in the order bash runs them; (the list's exit status where it
    is known from the words alone, else None; how it ended, see _flow_join()). live is 2 where
    the list runs, 1 where it may run; each node gets the live it is walked with, and 0 where bash
    does not run it: the right side of `&&` after a status known nonzero and of `||` after one
    known zero, and what follows a `return` or `exit` that runs."""
    status, flow, bgst = 0, None, None
    for k, p in enumerate(pipes):
        head = p[0]
        if live == 0:
            _dead(pipes[k:])
            break
        cond = False
        if head.conn in ("&&", "||"):
            if status is None:
                cond = True
            elif (status == 0) != (head.conn == "&&"):
                _dead([p])
                continue
        else:
            bgst = None
        if head.bg:                                  # a background and-or list runs in a subshell
            bgst = bgst or st.fork()
            s, f = _walk_pipe(p, bgst, 1 if cond else live)
            f = None
        else:
            s, f = _walk_pipe(p, st, 1 if cond else live)
        status = s if not cond or s == status else None
        if head.bg and (k + 1 == len(pipes) or pipes[k + 1][0].conn is None):
            status = 0
        if f is not None:
            flow = _flow_join(flow, f, not cond)
            if flow[0] == "certain":
                _dead(pipes[k + 1:])
                return status, flow
            live = min(live, 1)
    return status, flow


def _walk_pipe(p, st, live):
    s, f = None, None
    for node in p:
        s, f = _walk_node(node, st.fork() if len(p) > 1 else st, live)
    if len(p) > 1:
        f = None                                     # each element is a subshell
    if p[0].neg and s is not None:
        s = int(s == 0)
    return s, f


def _walk_node(node, st, live):
    """Walk node where bash runs it with st in force. A definition is in force from where it runs,
    in the shell it ran in, until `unset -f` names it or it is redefined; one that runs only maybe
    is added beside the one it may replace. A call of a function in force is replaced, in place, by
    the body bash runs there: a copy of each definition that may be in force, its parent the call,
    so the call's own pipe and redirections are its streams. A node whose origin is set is text
    written elsewhere (the code of an `eval`, a definition carried into a backtick): its words'
    offsets are not this text's, so no span of it is recorded."""
    node.live, node.args = live, st.args
    ws = node.words if node.kind == "simple" else node.redirs
    # Inside a call, a word's variables are what they hold HERE, at the call, not where the body
    # was written (_at_call()): the vals in force are kept for each walk of it.
    if st.stack:
        node.callvals.append(dict(st.vals))
        at = _cmd_offset(node) if node.kind == "simple" and (node.origin is None or node.lift) \
            else None
        if at is not None:                           # a definition carried into a backtick keeps
            st.callvals.setdefault(at if node.origin is None else ("lift", node.lift, at),
                                   []).append(dict(st.vals))   # its words' offsets in the text above
    # Each word that expands a variable holding what a substitution writes holds that text too.
    if node.origin is None:
        node.varheld = [(j, [v for name in _var_refs(raw) for v in st.vals.get(name, ())
                             if isinstance(v, tuple)]) for j, (_, raw, _) in enumerate(ws)]
    if ws and node.origin is None:
        st.seen.append(([(off, off + len(raw)) for _, raw, off in ws], dict(st.env), set(st.vs),
                        live, dict(st.vals)))
    if node.kind == "def":
        body = node.body[0][0]
        st.env[node.name] = [body] if live == 2 else st.env.get(node.name, [None]) + [body]
        return 0, None
    if node.kind == "test":
        return None, None
    if node.kind == "simple":
        return _walk_simple(node, st, live)
    if node.sub:
        st = st.fork()
    if node.ctype == "if":
        s, f = _walk_if(node, st, live)
    elif node.ctype == "case":
        s, f = _walk_case(node, st, live)
    elif node.loop:
        s, f = _walk_loop(node, st, live)
    else:
        s, f = _walk_list(node.body, st, live)
    return s, (None if node.sub else f)


def _walk_simple(node, st, live):
    _assign(node, st, live)
    _unset(node, st, live)
    _eval(node, st, live)
    _set_args(node, st, live)
    names = _call_names(node, st.vals)
    name = names[0] if len(names) == 1 else None
    if name == "exit":
        return None, ("certain", "exit")
    if name == "return" and st.stack:
        return None, ("certain", "return")
    # The definitions the call may run, each with the name it is called by; None where it may run
    # no function (a name not defined, or defined only maybe, or a value the text does not give).
    defs = [(n, d) for n in names for d in (st.env.get(n) or [None])]
    real = [(n, d) for n, d in defs if d is not None and n not in st.stack]
    # Whether every walk of this command word found it a call of a function surely in force: the
    # program of that name does not run there, so a shell's name is no shell (parse()). A call
    # inside its own body is left a command.
    at = _cmd_offset(node) if node.origin is None else None
    if at is not None:
        st.shadow[at] = st.shadow.get(at, True) and bool(real) and len(real) == len(defs)
    # A command word that is a variable with one literal value is that value wherever its words
    # are read (_node_wv()), where it stays one word: quoted, or one field.
    cw = _cmd_words(node)
    vs = _var_values(cw[0][0], st.vals) if cw else None
    if vs is not None and len(vs) == 1 and isinstance(vs[0], str) \
            and (cw[0][0].startswith('"') or len(vs[0].split()) == 1):
        node.cmdvar = (at if at is not None else _cmd_offset(node), vs[0])
    if real:
        _spend(st.budget)
        one = len(defs) == 1
        node.kind, node.redirs, node.call = "compound", list(node.words), real[0][0]
        node.body = [[_copy(d, node, node.origin)] for _, d in real]
        flow, args = None, _call_args(node, st)
        # `X=v f`: the body runs with X holding v, and X holds what it held before once f returns;
        # so does a name the body made its own with `local` (bash(1), FUNCTIONS).
        before, prefix = dict(st.vals), _prefix_assigns(node)
        for name, value in prefix:
            _var_maybe(st, name, value, live if one else min(live, 1))
        for (n, _), p in zip(real, node.body):
            p[0].pipeline, p[0].index = p, 0
            inner = st.inner(n, args)
            _, f = _walk_node(p[0], inner, live if one else min(live, 1))
            for name in inner.scoped | {name for name, _ in prefix}:
                if name in before:
                    st.vals[name] = before[name]
                else:
                    st.vals.pop(name, None)
            if f is not None and f[1] == "exit":     # a `return` ends the call, an `exit` the shell
                flow = _flow_join(flow, f, one)
        return None, flow
    return _status_of(node), None


def _literal(raw):
    """Whether the word raw has a value known from the text alone, with no expansion in it."""
    return not unresolved(raw) and not raw.startswith("~") and FILL not in raw


def _assign(node, st, live):
    """Add to st.vs the names node may make variables: its words when they are all assignments,
    and the operands of a builtin that declares or reads into them. A plain `NAME=WORD` that surely
    runs, WORD a literal, sets st.vals[NAME]; one that may run adds its value beside those NAME may
    hold, and any other way node may set NAME adds a value the text does not give (_var_maybe())."""
    w = _cmd_words(node)
    if not w:
        for raw, _ in _wv(node.words):
            m = _ASSIGN.match(raw)
            if not m:
                continue
            name = re.match(r"[A-Za-z_][A-Za-z0-9_]*", raw).group(0)
            st.vs.add(name)
            val = raw[m.end():]
            plain = m.group(0) == name + "=" and _literal(val)
            off = [t[2] for t in node.words if t[1] == raw]
            held = (("held", off[0] + m.end(), off[0] + len(raw)) if node.origin is None and off
                    and not plain and ("$(" in val or "`" in val) else None)
            _var_maybe(st, name, unquote(val) if plain else held, live)
    elif w[0][1] in _DECLARERS:
        names = [m.group(0) for m in (re.match(r"[A-Za-z_]\w*", v) for _, v in w[1:]) if m]
        st.vs.update(names)
        opts = "".join(v[1:] for _, v in w[1:] if v.startswith("-"))
        if st.stack and w[0][1] in ("local", "declare", "typeset") and "g" not in opts:
            st.scoped.update(names)                  # gone when the call returns (_walk_simple())
        for name in names:
            _var_maybe(st, name, None, live)
        # `local X=WORD` (declare, typeset, export, readonly), WORD a literal, gives X that value.
        if w[0][1] in ("local", "declare", "typeset", "export", "readonly") \
                and not set(opts) & set("aAinlu"):
            for raw, _ in w[1:]:
                m = re.match(r"([A-Za-z_]\w*)=", raw)
                if m and _literal(raw[m.end():]):
                    _var_maybe(st, m.group(1), unquote(raw[m.end():]), live)


def _unset(node, st, live):
    """What an `unset` that runs removes, through `builtin` or `command` too: `-f NAME` the
    function, `-v NAME` the variable, and a bare NAME the variable where one may have the name
    (st.vs, or the text assigns it, or it is spelled as an environment variable is), else the
    function. `-f` beside `-v` removes nothing (bash refuses it). Every name it lists may lose its
    value (st.vals, _var_maybe()); one that may run removes nothing else."""
    w = [v for _, v in _cmd_words(node)]
    while w and w[0] in ("builtin", "command"):
        if w[0] == "command" and len(w) > 1 and w[1] in ("-v", "-V"):
            return
        w = w[1:]
        while w and w[0] in ("-p", "--"):
            w = w[1:]
    if not w or w[0] != "unset":
        return
    i, opts = 1, ""
    while i < len(w) and w[i].startswith("-") and len(w[i]) > 1:
        i += 1
        if w[i - 1] == "--":
            break
        opts += w[i - 1][1:]
    for name in w[i:] if "f" not in opts else ():
        _var_maybe(st, name, None, live)             # a variable it may unset: its value unknown
    if live != 2 or ("f" in opts and "v" in opts):
        return
    for name in w[i:]:
        if "f" in opts:
            st.env.pop(name, None)
        elif "v" in opts or name in st.vs or name in st.assigned:
            st.vs.discard(name)
        elif not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            st.env.pop(name, None)


def _eval(node, st, live):
    """An `eval` runs its code in this shell: its definitions and unsets are walked here, its
    nodes marked as text written elsewhere (their origin the eval's own offset)."""
    w = _cmd_words(node)
    if not w or w[0][1] != "eval":
        return
    code = eval_code(w)
    pipes = _parse_code(code) if code else None
    if pipes is None:
        return
    origin = node.origin if node.origin is not None else node.words[0][2]
    for n in _every(pipes):
        n.origin = origin
    _walk_list(pipes, st, live)


def _every(pipes):
    for p in pipes:
        for n in p:
            yield n
            yield from _every(n.body)


def _walk_if(node, st, live):
    """Each `if`/`elif` condition runs until one has status 0, whose body runs, else the `else`
    body; a condition whose status is not known from its words alone may go either way."""
    sure, cur, flow, status, taken = True, live, None, 0, False
    parts, i = node.seq, 0
    while i < len(parts):
        role, pipes = parts[i][0], parts[i][1]
        if taken:
            _dead(pipes)
            i += 1
            continue
        if role == "else":
            s, f = _walk_list(pipes, st, cur)
            flow, status = _flow_join(flow, f, sure), (s if sure else None)
            i += 1
            continue
        sc, f = _walk_list(pipes, st, cur)
        flow = _flow_join(flow, f, sure)
        body = parts[i + 1][1]
        if flow is not None and flow[0] == "certain":
            for part in parts[i + 1:]:
                _dead(part[1])
            return None, flow
        if sc is None or sc == 0:
            s, f = _walk_list(body, st, cur if sc == 0 else min(cur, 1))
            flow = _flow_join(flow, f, sure and sc == 0)
            if sc == 0:
                taken, status = True, (s if sure else None)
            else:
                sure, cur, status = False, min(cur, 1), None
        else:
            _dead(body)
        i += 2
    return status, flow


def _case_word(word):
    if word is None or unresolved(word[1]) or any(c in word[1] for c in "~\\" + FILL):
        return None
    return unquote(word[1])


def _case_match(wv, pats):
    """Whether a case word of value wv matches one of pats: True, False, or None where the words
    alone do not say (an expansion, a bracket, a glob character inside quotes)."""
    if wv is None:
        return None
    got = False
    for _, raw, _ in pats:
        if unresolved(raw) or "[" in raw or FILL in raw:
            got = None
        elif any(q in raw for q in "'\"\\"):
            v = unquote(raw)
            if any(c in v for c in "*?"):
                got = None
            elif v == wv:
                return True
        elif fnmatch.fnmatchcase(wv, raw):
            return True
    return got


def _walk_case(node, st, live):
    """The first arm whose pattern matches runs; `;&` runs the next arm's body too, and `;;&`
    goes on testing."""
    wv = _case_word(node.word)
    sure, cur, flow, fall, done = True, live, None, None, False
    for part in node.seq:
        pipes, pats, term = part[1], part[2], part[3]
        if done:
            _dead(pipes)
            continue
        m = True if fall is not None else _case_match(wv, pats)
        if m is False:
            _dead(pipes)
            continue
        al = fall if fall is not None else (cur if m else min(cur, 1))
        _, f = _walk_list(pipes, st, al)
        flow = _flow_join(flow, f, sure and m is True)
        fall = al if term == ";&" else None
        if m is True and term in (";;", None):
            done = True
        if m is None:
            sure, cur = False, min(cur, 1)
    return None, flow


def _count(items):
    """How many times a `for` runs its body from its words alone, or None (no `in`, or a word an
    expansion may make more or fewer)."""
    if items is None:
        return None
    if any(c in raw for _, raw, _ in items for c in "$`*?[{~" + FILL):
        return None
    return len(items)


def _walk_loop(node, st, live):
    """A loop body runs as many times as bash runs it, up to twice: a `for` over words it can
    count, once per word; a `while`/`until` whose condition's status is known, never or every time;
    any other loop maybe, twice. The second pass is a copy of the loop's parts taken before the
    first ran, appended to them, so a call there reads what the first pass defined."""
    _spend(st.budget)
    spare = [[part[0], _copies(part[1], node)] for part in node.seq]
    if node.ctype in ("while", "until"):
        def once(parts, lv):
            sc, fc = _walk_list(parts[0][1], st, lv)
            runs = None if sc is None else (sc == 0) == (node.ctype == "while")
            if runs is False:
                _dead(parts[1][1])
                return False, fc
            _, f = _walk_list(parts[1][1], st, lv if runs else min(lv, 1))
            return runs, _flow_join(fc, f, bool(runs))
        runs, f = once(node.seq, live)
        if runs is False:
            return 0, _flow_join(None, f, False)
        lv = live if runs else min(live, 1)
    else:
        n = None if node.ctype == "select" else _count(node.items)
        if node.var:
            st.vs.add(node.var)
            # Each word the loop runs over is a value its variable may hold in the body, and after.
            words = [unquote(raw) for _, raw, _ in node.items] if n else None
            _var_maybe(st, node.var, None, live)
            for v in words or ():
                _var_maybe(st, node.var, v, 1)
        if n == 0:
            _dead(node.seq[0][1])
            return 0, None
        lv = live if n is not None else min(live, 1)
        _, f = _walk_list(node.seq[0][1], st, lv)
        if n == 1:
            return None, _flow_join(None, f, False)
        once = lambda parts, lv: (True, _walk_list(parts[0][1], st, lv)[1])  # noqa: E731
    node.seq += spare
    _, f2 = once(spare, lv)
    return None, _flow_join(_flow_join(None, f, False), f2, False)


_VALUES = {}


def _wv(ws):
    """[(raw, value)] of word tokens, as split_words() gives them (each value read once)."""
    if len(_VALUES) > 65536:
        _VALUES.clear()
    out = []
    for _, raw, _ in ws:
        if raw not in _VALUES:
            _VALUES[raw] = unquote(raw)
        out.append((raw, _VALUES[raw]))
    return out


def _stdins(node):
    return _io_redirs(_wv(node.words if node.kind == "simple" else node.redirs))[0]


def _reads_a_line(w):
    """Whether the command w is a `read` that takes exactly one line of its stdin."""
    if name_of(w) != "read":
        return False
    i = 1
    while i < len(w) and w[i][1].startswith("-") and w[i][1] != "--":
        for k, ch in enumerate(w[i][1][1:]):
            if ch in "pta":
                i += 0 if k + 2 < len(w[i][1]) else 1
                break
            if ch not in "rse":
                return False
        i += 1
    return True


# A READ THAT HANDS ITS LINE ON IS A RELAY (`echo T | while read l; do echo "$l"; done | bash` runs
# T). `read` and `mapfile`/`readarray` take stdin into variables; a later command of
# the same shell that writes one of them to a stdin shell (echo/printf), runs it (eval, a shell's -c)
# or feeds it as a herestring to a stdin shell hands the text on as code, as a copier would. Any
# expansion of the name counts (`$l`, `${l}`, `${a[@]}`, `${l:-x}`; not `${#l}`), an assignment of
# the name that surely runs ends it, and so does the end of the subshell the read is in.
_ANY_REF = re.compile(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*))")
_READ_ARG = {"read": set("adinNptu"), "mapfile": set("dnOsuCc"), "readarray": set("dnOsuCc")}


def _read_names(w):
    """The variables a `read`/`mapfile` taking its stdin (no -u FD) sets, or ()."""
    name = name_of(w)
    if name not in _READ_ARG:
        return ()
    argset, names, i = _READ_ARG[name], [], 1
    while i < len(w):
        raw, v = w[i]
        r = REDIR.match(raw)
        if r:
            i += 1 if r.group(2) else 2; continue
        if v == "--":
            names += [x for _, x in w[i + 1:]]; break
        if v.startswith("-") and len(v) > 1 and not names:
            for k, ch in enumerate(v[1:]):
                if ch in argset:
                    arg = v[k + 2:] or (w[i + 1][1] if i + 1 < len(w) else "")
                    if ch == "u":
                        return ()
                    if ch == "a":
                        names.append(arg)
                    i += 0 if v[k + 2:] else 1
                    break
            i += 1; continue
        names.append(v); i += 1
    return set(names) or {"REPLY" if name == "read" else "MAPFILE"}


def _hands_on(n, names, guard):
    """Whether the simple node n hands the text of a variable in names to a shell as code."""
    w = _node_wv(n)
    idx, _, _ = resolve(w)
    if idx is None:
        return False
    w = w[idx:]
    refs = lambda s: bool(names & set(_var_refs(s, _ANY_REF)))  # noqa: E731
    ins = _stdins(n)
    if name_of(w) in ("echo", "printf") and not ins \
            and any(refs(r) for r, _ in w[1:] if not REDIR.match(r)) \
            and _reaches(_sinks(n, 1, guard), guard):
        return True
    if ins and ins[-1] == "<<<" and any(refs(h) for h in herestrings([(r, r) for r, _ in w])) \
            and _fed(n, guard):
        return True
    return any(refs(c) for c in command_codes(w, stdin=False))


def _relays(node, guard):
    """Whether the read node (_first_readers() gave it node.relay, what runs after it in its shell)
    hands what it takes on to a shell as code."""
    names = set(_read_names(_node_wv(node)[resolve(_node_wv(node))[0] or 0:]))
    ends = []                                # (assignment, the names it gives a value)
    for n in node.relay or ():
        if n.live == 0 or n.kind != "simple":
            continue
        # An assignment before n ends a name where it surely runs, or where it is a pipeline of its
        # own, unjoined by && or ||, earlier in the same part of the same compound and as live as n
        # (`while read l; do l=x; echo "$l"; done`), which runs it whenever n runs.
        left = names - {k for a, ks in ends if a.live == 2 or (
            a.live >= n.live and a.conn is None and _part(a) == _part(n)) for k in ks}
        if left and _hands_on(n, left, guard):
            return True
        if resolve(_node_wv(n))[0] is None and n.pipeline is not None and len(n.pipeline) == 1:
            ends.append((n, {k for k, _ in _prefix_assigns(n)}))
    return False


def _part(n):
    """The list n's pipeline is in: (its compound, which part of it), or its region's top."""
    if n.parent is None:
        return id(n.top)
    return next(((id(n.parent), j) for j, part in enumerate(n.parent.seq)
                 if any(q is n.pipeline for q in part[1])), None)


def _first_readers(pipes, drop=0, tail=()):
    """The commands at the head of pipes that may be the first to read the stdin they share, each
    with how many lines a `read` before it takes ([(node, lines)], and whether the last one surely
    runs): a shell reading stdin or a copier, with no stdin redirection of its own and not in the
    background (whose stdin is /dev/null); a command that is neither is taken not to read stdin.
    That is wrong for one that does read it (`{ grep x; bash; }` is read as feeding bash), the
    refusing direction. A reader that may not run is not the last asked."""
    out = []
    for k, p in enumerate(pipes):
        head = p[0]
        if head.live == 0 or head.bg or head.kind in ("test", "def") or _stdins(head):
            continue
        # what runs after head in head's own shell: the rest of this list and, outside a subshell,
        # what tail says runs after it (a read's variables reach no further, _relays())
        after = () if len(p) > 1 else list(_nodes(pipes[k + 1:])) + list(tail)
        if head.kind == "compound":
            got, sure = _first_readers(head.body, drop, () if head.sub else after)
            out += got
            if sure:
                return out, True
            continue
        w = _node_wv(head)
        idx, _, _ = resolve(w)
        if idx is None:
            continue
        if line_filter(w[idx:]) is not None:
            # a line filter reads its stdin, but may leave some of it to a later reader (`head
            # -1; bash`, `grep -m1 x; bash`): asked, and not the last asked (the refusing direction)
            out.append((head, drop))
            continue
        if reads_code_on_stdin(w[idx:]) or copies_stdin(w[idx:]):
            out.append((head, drop))
            if head.live == 2:
                return out, True
            continue
        if _read_names(w[idx:]):
            head.relay = after
            out.append((head, drop))
        if head.live == 2 and _reads_a_line(w[idx:]):
            drop += 1
    return out, False


def _exec_only(node):
    """Whether node is an `exec` with no command, only redirections: they stay in force for every
    later command of its shell."""
    if node.kind != "simple":
        return False
    w, i = _wv(node.words), 0
    while i < len(w) and _ASSIGN.match(w[i][0]):
        i += 1
    if i >= len(w) or w[i][1] != "exec":
        return False
    i += 1
    while i < len(w):
        r = REDIR.match(w[i][0])
        if not r:
            return False
        i += 1 if r.group(2) else 2
    return True


def _table(node):
    """(what node's own redirections leave each fd they name, the `>(...)`s they open). bash
    applies them left to right, over the fds node inherits, so each is one of ("up", k): the fd k
    node inherits; ("proc", offset, node, fds): a `>(...)` written as its own word, opened with the
    fds node had at that point (its stdout is their fd 1); or ("none",): a file, a close, an input.
    A dup `N>&M` copies what M is at that point; `N>&M-` moves it."""
    if node.tab is not None:
        return node.tab
    ws = node.words if node.kind == "simple" else node.redirs
    procs = node.streams.procs if node.streams is not None and node.origin is None else {}
    tab, opened, i = {}, [], 0
    while i < len(ws):
        raw = ws[i][1]
        r = REDIR.match(raw)
        i += 1
        if not r:
            continue
        op, fdw, glued = r.group(1), raw[:r.start(1)], r.group(2)
        tgt = ("w", glued, None) if glued else (ws[i] if i < len(ws) else None)
        if not glued:
            i += 1
        if fdw.startswith("{"):                      # `{name}>`: the fd is chosen when it runs
            continue
        n = int(fdw) if fdw else (0 if op[0] == "<" else 1)

        def dest():
            if tgt is not None and tgt[2] in procs and tgt[1].endswith(")") \
                    and len(tgt[1]) == procs[tgt[2]][0]:
                fds = dict(tab)
                opened.append((tgt[2], fds))
                return ("proc", tgt[2], node, fds)
            return ("none",)
        if op in (">", ">>", ">|"):
            tab[n] = dest()
        elif op in ("&>", "&>>"):
            tab[1] = tab[2] = dest()
        elif op in (">&", "<&"):
            tv = unquote(tgt[1]) if tgt is not None else ""
            m = re.fullmatch(r"(\d+)(-?)", tv)
            if m:
                tab[n] = tab.get(int(m.group(1)), ("up", int(m.group(1))))
                if m.group(2):
                    tab[int(m.group(1))] = ("none",)
            elif op == ">&" and tv != "-":
                d = dest()
                tab[n] = d
                if not fdw:
                    tab[2] = d
            else:
                tab[n] = ("none",)
        else:
            tab[n] = ("none",)
    node.tab = (tab, opened)
    return node.tab


def _execs_back(pipes, k):
    """The stdout-holding `exec`s of pipes that set fd k for what follows them, last first: not one
    in a subshell, a pipeline element, the background, or a group (or call) whose own redirections
    name k, which bash undoes at its end."""
    for p in reversed(pipes):
        e = p[0]
        if len(p) > 1 or e.live == 0 or e.bg or e.kind in ("test", "def"):
            continue
        if _exec_only(e):
            if k in _table(e)[0]:
                yield e
        elif e.kind == "compound" and not e.sub and k not in _table(e)[0]:
            yield from _execs_back(e.body, k)


def _follow(node, s, guard):
    if s[0] == "up":
        return _up(node, s[1], guard)
    return [s] if s[0] == "proc" else []


def _sinks(node, k, guard):
    """Where what node writes on fd k goes, as bash runs it: [("pipe", next element), ("proc",
    offset, opener, fds), ("into", the command a `<(...)` region's top feeds), ("word", the command
    a `$(...)` or backtick region's top writes a word of, its role there: _word_role())]."""
    if k == 2 and node.errpipe and node.pipeline is not None \
            and node.index + 1 < len(node.pipeline):
        return _sinks(node, 1, guard)          # `|&`: a 2>&1 after node's own redirections
    return _follow(node, _table(node)[0].get(k, ("up", k)), guard)


def _up(node, k, guard):
    """Where fd k goes where node runs, before node's own redirections: the pipe to the next
    element (fd 1, and fd 2 after `|&`); else the last `exec` before node at its level that sets k
    and is still in force; else what k is where node's parent runs; and at the top of a region,
    the command a `<(...)` feeds, the command whose word a `$(...)` or backtick is, or what k was
    where each `>(...)` of this region was opened."""
    if (id(node), k) in guard:
        return []
    guard.add((id(node), k))
    p, out = node.pipeline, []
    if p is not None and node.index + 1 < len(p) and k == 1:
        return [("pipe", p[node.index + 1])]
    level = node.parent.body if node.parent is not None else (node.top or [])
    at = [i for i, q in enumerate(level) if q is p]
    if at:
        for e in _execs_back(level[:at[0]], k):
            out += _follow(e, _table(e)[0][k], guard)
            if e.live == 2:
                return out
    if node.parent is not None:
        return out + _sinks(node.parent, k, guard)
    if node.into is not None and k == 1:
        out.append(("into", node.into))
    if k == 1:
        out += [("word", h, role) for h, role in node.holders]
    if node.region is not None and node.streams is not None:
        for opener, fds in node.streams.openings.get(node.region, []):
            out += _follow(opener, fds.get(k, ("up", k)), guard)
    return out


def _reaches(sinks, guard):
    """Whether one of sinks reaches a shell that runs its stdin."""
    for s in sinks:
        if s[0] == "pipe" and _in_reaches(s[1], guard):
            return True
        if s[0] == "into" and _fed(s[1], guard):
            return True
        if s[0] == "word" and (_fed(s[1], guard) if s[2] == "here"
                               else _reaches(_sinks(s[1], 1, guard), guard)):
            return True
        if s[0] == "proc" and s[2].streams is not None:
            got = s[2].streams.procs.get(s[1])
            if got and any(_in_reaches(r, guard) for r, _ in _first_readers(got[1])[0]):
                return True
    return False


def _fed(node, guard):
    """What node reads on stdin, whatever it is, reaches a shell that runs its stdin."""
    if node.live == 0:
        return False
    if node.kind == "compound":
        return any(_in_reaches(r, guard) for r, _ in _first_readers(node.body)[0])
    if node.kind != "simple":
        return False
    w = _node_wv(node)
    idx, _, _ = resolve(w)
    if idx is None:
        return False
    if reads_code_on_stdin(w[idx:]):
        return True
    if node.relay is not None and _read_names(w[idx:]):
        return _relays(node, guard)
    keep = line_filter(w[idx:])
    if keep is not None:
        return keep(None) != "" and _reaches(_sinks(node, 1, guard), guard)
    return copies_stdin(w[idx:]) and (_reaches(_sinks(node, 1, guard), guard)
                                      or _tee_procs_fed(node, guard))


def _tee_readers(node):
    """The first stdin readers of each `>(...)` that is a FILE operand of the copier node, written
    as its own word: tee writes its stdin into each file it names, so `echo '...' | tee >(bash)`
    and `tee -a /dev/null >(sh)` hand the shell the text."""
    procs = node.streams.procs if node.streams is not None and node.origin is None else {}
    if node.kind != "simple" or not procs:
        return []
    ws, i, out = node.words, 0, []
    while i < len(ws):
        raw, off = ws[i][1], ws[i][2]
        r = REDIR.match(raw)
        i += 1
        if r:
            i += 0 if r.group(2) else 1
            continue
        got = procs.get(off)
        if got and raw.endswith(")") and len(raw) == got[0]:
            out += [rd for rd, _ in _first_readers(got[1])[0]]
    return out


def _tee_procs_fed(node, guard):
    return any(_in_reaches(rd, guard) for rd in _tee_readers(node))


def _onward(node, code, guard=frozenset()):
    """The texts a shell reads of code written on node's stdout, by every route _sinks() gives it:
    down a pipe, into a `>(...)`, through copiers (a tee's `>(...)` operands too) and line filters,
    each filter keeping the lines LINE_FILTERS says it keeps; [] where no route reaches a shell.
    A route through anything else (a compound, a relay, a `$(...)`) carries code as it is."""
    if id(node) in guard:
        return [code]
    guard, out = guard | {id(node)}, []
    for s in _sinks(node, 1, set()):
        if s[0] == "pipe":
            out += _through(s[1], code, guard)
        elif s[0] == "proc" and s[2].streams is not None and s[2].streams.procs.get(s[1]):
            for rd, _ in _first_readers(s[2].streams.procs[s[1]][1])[0]:
                out += _through(rd, code, guard)
        elif _reaches([s], set()):
            out.append(code)
    return out


def _through(n, code, guard=frozenset(), own=False):
    """The texts a shell reads of code read on n's stdin (own: n's stdin is its own redirection)."""
    if n.live == 0 or not own and _stdins(n) or not _fed(n, set()):
        return []
    if n.kind == "simple":
        w = _node_wv(n)
        idx = resolve(w)[0]
        if idx is not None and not reads_code_on_stdin(w[idx:]) and n.relay is None:
            keep = line_filter(w[idx:])
            if keep is not None:
                return _onward(n, keep(code), guard)
            if copies_stdin(w[idx:]):
                return _onward(n, code, guard) + [
                    t for rd in _tee_readers(n) for t in _through(rd, code, guard)]
    if n.kind == "compound" and id(n) not in guard:
        return [t for rd, _ in _first_readers(n.body)[0] for t in _through(rd, code, guard | {id(n)})]
    return [code]


def _in_reaches(node, guard):
    return node.live != 0 and not _stdins(node) and _fed(node, guard)


def _own_drop(node):
    """The lines a `read` takes, before a shell reads the rest, of what node alone writes into a
    stdin: inside the `>(...)` node's own stdout redirection opens, or in the compound (or call)
    its own pipe feeds (`echo ... | f`, f's body `read x; bash`); 0 everywhere else."""
    s = _table(node)[0].get(1)
    if s is None:
        p = node.pipeline
        if p is None or node.index + 1 >= len(p):
            return 0
        nxt = p[node.index + 1]
        if nxt.kind != "compound" or nxt.live == 0 or _stdins(nxt):
            return 0
        got = (None, nxt.body)
    elif s[0] != "proc" or s[2] is not node:
        return 0
    else:
        got = node.streams.procs.get(s[1])
    ds = [d for r, d in _first_readers(got[1])[0] if _in_reaches(r, set())] if got else []
    return min(ds) if ds else 0


def _word_role(node, j):
    """What bash does with the value of node's word j (a `$(...)` or backtick in it): "here" where
    it is the herestring of node's last stdin redirection, node's stdin; "out" where node is an
    echo or printf and j a word it writes; None where it is anything else (a file, a name)."""
    ws = node.words if node.kind == "simple" else node.redirs
    w, i, here, redir = _wv(ws), 0, None, set()
    while i < len(w):
        raw = w[i][0]
        r = REDIR.match(raw)
        if not r:
            i += 1
            continue
        tgt = i if r.group(2) else i + 1
        redir |= {i, tgt}
        if r.group(1) in ("<<<", "<<", "<<-", "<", "<>") and raw[:r.start(1)] in ("", "0"):
            here = tgt if r.group(1) == "<<<" else None
        i = tgt + 1
    if here == j:
        return "here"
    if node.kind != "simple" or j in redir:
        return None
    idx, _, _ = resolve(w)
    if idx is not None and j > idx and name_of(w[idx:]) in ("echo", "printf"):
        return "out"
    return None


def _nodes(pipes):
    """Every node of pipes bash may run, but not inside a definition: a body runs as the copy a
    call makes."""
    for p in pipes:
        for node in p:
            if node.live == 0:
                continue
            yield node
            if node.kind != "def":
                yield from _nodes(node.body)


def _proc_word(ws, kind, procs):
    """The offset of the `<(...)` (kind "<") or `>(...)` (">") that ws's last redirection of
    stdin or stdout reads from or writes into, written as its own word, or None."""
    w, target, i = _wv(ws), None, 0
    while i < len(w):
        raw = w[i][0]
        r = REDIR.match(raw)
        i += 1
        if not r:
            continue
        op, fd = r.group(1), raw[:r.start(1)]
        if kind == "<" and op in ("<<<", "<<", "<<-", "<", "<>") and fd in ("", "0"):
            target = None if r.group(2) or op != "<" or i >= len(ws) else ws[i]
        if kind == ">" and (op in ("&>", "&>>") or (op in (">", ">>", ">|", ">&")
                                                   and fd in ("", "1"))):
            target = None if r.group(2) or i >= len(ws) else ws[i]
        if not r.group(2):
            i += 1
    if target is None or target[2] not in procs or not target[1].endswith(")") \
            or len(target[1]) != procs[target[2]][0]:
        return None
    return target[2]


class _Streams:
    """The process substitutions of one text: procs and inprocs ({offset of `>(`/`<(`: (length,
    the parsed region of its body)}), and openings ({offset of `>(`: [(the command whose
    redirection opened it, its fds then)]})."""
    def __init__(self):
        self.procs, self.inprocs, self.openings = {}, {}, {}


def _prep(text):
    """(heredocs, the live mask with heredoc bodies blanked, the substitutions outside them)."""
    hds = heredocs(text)
    pv = list(mask_quoted(text, fill=FILL, live=True))
    for hd in hds:
        for k in range(hd["body"][0], hd["end"]):
            if pv[k] != "\n":
                pv[k] = " "
    spans = [(hd["body"][0], hd["end"]) for hd in hds]
    subs = [s for s in substitutions(text) if not any(a <= s["open"] < b for a, b in spans)]
    return hds, pv, subs


def _read_region(text, pv, subs, lo, hi):
    """The parsed list of text[lo:hi], each substitution in it one span of word characters, or None
    where this reader cannot match its structure."""
    seg = pv[lo:hi]
    for s in subs:                           # a closed one is part of its word, as in parse()
        if lo <= s["open"] < hi:
            end = s["body"][1] + (2 if s["kind"] == "arith" else 1)
            seg[s["open"] - lo:min(end, hi) - lo] = FILL * (min(end, hi) - s["open"])
    try:
        return _Reader(_tokens(word_chars("".join(seg)), text, lo)).lst(None, None)
    except (_Unread, IndexError, RecursionError):
        return None


def _parse_code(code):
    """The parsed list of a code string (an `eval`'s, a `-c`'s), its substitutions unread, or None."""
    try:
        _, pv, subs = _prep(code)
    except Exception:                        # a mask the code does not close: not read
        return None
    return _read_region(code, pv, subs, 0, len(code))


_STDIN_PATHS = {"/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
_CODE_READS_STDIN = {}


def _code_reads_stdin(code):
    """Whether shell code run with `-c`, given a stdin, hands what it reads to a shell that runs
    it: its first stdin reader is such a shell, or a copier whose stdout reaches one (`bash -c
    bash`, `sh -c 'cat | bash'`, `bash -c 'exec bash'`), as compound_flow() reads a compound."""
    if code not in _CODE_READS_STDIN:
        _CODE_READS_STDIN[code] = False      # the code inside itself reads as not
        pipes, got = _parse_code(code), False
        if pipes is not None:
            try:
                _walk_list(pipes, _State({}, set(), (), [_CALLS_MAX], [], _assigned_names(code)), 2)
                for p in pipes:
                    for n in p:
                        n.top = pipes
                got = _fed(_Node("compound", body=pipes), set())
            except (_Unread, RecursionError):
                got = False
        _CODE_READS_STDIN[code] = got
    return _CODE_READS_STDIN[code]


def compound_flow(text, env0=None, vs0=None, live0=2, assigned0=(), vals0=None, holders0=()):
    """(start offsets of the heredoc bodies, [(offset, code)] of the herestrings and echo/printf
    output) that reach a shell running its stdin through a compound command, read as above, and
    the offsets of the command words every walk found a call of a function surely in force. Each
    region is read on its own: the text, and the body of each `$(...)`, backtick and `<(...)`.
    env0, vs0, vals0 and live0 are what is in force where the text runs (a backtick's, from the
    command whose word holds it), assigned0 the names the text around it assigns, and holders0
    the commands (with _word_role()) whose word its output is."""
    hds, pv, subs = _prep(text)
    # A backtick body is read from the code bash runs (backtick_code(), as in _backtick_region()),
    # by this same reader over that code, and what it finds is put back at the offsets it was
    # written at; a substitution inside one is that reader's.
    ticks = [s for s in subs if s["kind"] == "cmd" and text[s["open"]] == "`"]
    inner = [s for s in subs if any(k is not s and k["body"][0] <= s["open"] <= k["body"][1]
                                    for k in ticks)]
    regions = [(0, len(text))] + [s["body"] for s in subs if s["kind"] in ("cmd", "proc")
                                  and s not in ticks and s not in inner]
    bodies, codes, parsed = set(), [], []
    for lo, hi in regions:
        pipes = _read_region(text, pv, subs, lo, hi)
        if pipes is not None:
            parsed.append((lo, pipes))
    # A function body runs where the function is called (_walk_node()), and a `>(...)` an output
    # is redirected into is read by the region of its body; both are known only once every region
    # is. A `<(...)` a stdin is redirected from writes, at its top, to the command reading it.
    streams, region_of = _Streams(), {}
    for s in subs:
        if s["kind"] == "proc" and text[s["open"]] in "<>":
            got = [p for lo, p in parsed if lo == s["body"][0]]
            if got:
                (streams.procs if text[s["open"]] == ">" else streams.inprocs)[s["open"]] = (
                    s["body"][1] + 1 - s["open"], got[0])
                if text[s["open"]] == ">":
                    region_of[s["body"][0]] = s["open"]
    # Each region is walked in the order bash runs it, the text first: a region of a substitution
    # starts from what is in force at the command whose word holds it (a subshell's copy of it),
    # runs only where that command may, and one inside a body no call ran starts from nothing.
    budget, readable, seen, shadow, callvals = [_CALLS_MAX], [], [], {}, {}
    assigned = set(assigned0) | _assigned_names(text)

    def in_force(at):
        found = [x for x in seen if any(a <= at < b for a, b in x[0])]
        if found:
            return (dict(found[-1][1]), set(found[-1][2]), max(x[3] for x in found),
                    dict(found[-1][4]))
        return None
    for lo, pipes in sorted(parsed, key=lambda r: r[0]):
        env, vs, live, vals = in_force(lo) or (
            (dict(env0 or {}), set(vs0 or ()), live0, dict(vals0 or {})) if lo == 0
            else ({}, set(), 2, {}))
        if live == 0:
            continue
        try:
            _walk_list(pipes, _State(env, vs, (), budget, seen, assigned, vals=vals,
                                     shadow=shadow, callvals=callvals), live)
            for p in pipes:
                for node in p:
                    node.top, node.region = pipes, region_of.get(lo)
                    if lo == 0:
                        node.holders = list(holders0)
            readable.append(list(_nodes(pipes)))
        except (_Unread, RecursionError):
            continue
    every = [n for nodes in readable for n in nodes]
    tick_holders = {}
    for node in every:
        node.streams = streams
    for node in every:
        if node.origin is not None:
            continue
        ws = node.words if node.kind == "simple" else node.redirs
        at = _proc_word(ws, "<", streams.inprocs)
        if at is not None:
            for p in streams.inprocs[at][1]:
                for top in p:
                    top.into = node
        for off, fds in _table(node)[1]:
            streams.openings.setdefault(off, []).append((node, fds))
        # A `$(...)` or backtick writes, at its top, the value of the word it sits in, and of each
        # word that expands a variable an assignment of that word gave it (node.varheld).
        spans = [(j, off, off + len(raw)) for j, (_, raw, off) in enumerate(ws)]
        spans += [(j, h[1], h[2]) for j, held in node.varheld for h in held]
        for j, a, b in spans:
            for s in subs:
                if s["kind"] != "cmd" or s in inner or not a <= s["open"] < b:
                    continue
                role = _word_role(node, j)
                if role is None:
                    continue
                if s in ticks:
                    tick_holders.setdefault(s["open"], []).append((node, role))
                    continue
                for lo, pipes in parsed:
                    if lo == s["body"][0]:
                        for p in pipes:
                            for top in p:
                                top.holders.append((node, role))
    for node in every:
        ws = node.words if node.kind == "simple" else node.redirs
        w = _node_wv(node)
        ins = _stdins(node)
        at_ = node.origin if node.origin is not None else (ws[0][2] if ws else 0)
        for hd in hds if node.origin is None else ():
            at = [j for j, (_, raw, off) in enumerate(ws) if off <= hd["op"] < off + len(raw)]
            if not at:
                continue
            j = at[0]
            raw, off = ws[j][1], ws[j][2]
            body = text[hd["body"][0]:hd["body"][1]]
            idx = resolve(w)[0]
            if not reads_code_on_stdin(w[idx:] if idx is not None else w) \
                    and not any(t.strip() for t in _through(node, body, own=True)):
                continue                     # a filter keeps none of it on its way
            if raw[:hd["op"] - off] in ("", "0") and not _io_redirs(w[j + 1:])[0] \
                    and _fed(node, set()):
                bodies.add(hd["body"][0])
                # In a body a call runs, the text is the body with the call's words in it.
                if node.args is not None and not hd["quoted"] \
                        and (_POSITIONAL.search(body) or _PLAIN_REF.search(body)):
                    codes += [(at_, c) for c in _at_call(_heredoc_with_args(body, node.args),
                                                         node.callvals)]
        if ins and ins[-1] == "<<<" and _fed(node, set()):
            got = herestrings(w)
            idx = resolve(w)[0]
            texts = got[-1:]
            if got and isinstance(got[-1], str) \
                    and not reads_code_on_stdin(w[idx:] if idx is not None else w):
                texts = [t for t in _through(node, got[-1], own=True) if t.strip()]
            for t in texts:
                codes += [(at_, c) for c in _at_call(t, node.callvals)]
        if node.kind == "simple" and not ins:
            idx, _, _ = resolve(w)
            if idx is not None and name_of(w[idx:]) in ("echo", "printf") \
                    and _reaches(_sinks(node, 1, set()), set()):
                code = handed_script(Cmd(words=w[idx:]))
                drop = _own_drop(node) if isinstance(code, str) else 0
                if drop:
                    code = "\n".join(code.split("\n")[drop:])
                texts = [t for t in _onward(node, code) if t.strip()] if isinstance(code, str) \
                    else [code]
                for code in texts:
                    codes += [(at_, c) for c in (_at_call(code, node.callvals)
                                                 if isinstance(code, str) else [code])]
    shadows = {o for o, sure in shadow.items() if sure}
    # A backtick runs where the command whose word holds it runs, with what is in force there; a
    # definition carried in is text written outside it, put back at the backtick.
    for s in ticks:
        if s in inner:
            continue
        env, vs, live, vals = in_force(s["open"]) or ({}, set(), 2, {})
        if live == 0:
            continue
        code, src = tick_code(text, s)
        env = {k: [d if d is None else _lifted(d) for d in v] for k, v in env.items()}
        got = compound_flow(code, env, vs, live, assigned, vals, tick_holders.get(s["open"], ()))
        for o, v in got[3].items():
            if isinstance(o, tuple):                 # a node of a definition carried in (_lifted())
                callvals.setdefault(o[2] if o[1] == 1 else ("lift", o[1] - 1, o[2]), []).extend(v)
            elif o < len(src):
                callvals.setdefault(src[o], []).extend(v)
        at = (lambda p, src=src, s=s: s["open"] if p < 0 else
              (src[p] if p < len(src) else s["body"][1]))
        bodies |= {_body_at(p, src, s["body"][1]) for p in got[0]}
        codes += [(at(o), c) for o, c in got[1]]
        shadows |= {src[o] for o in got[2] if o < len(src)}
    return bodies, codes, shadows, callvals


def parse(text):
    """Simple commands and loop keywords of text, in textual order.

    A WORD HOLDING A SUBSTITUTION IS ONE WORD. A `$(...)`, backtick, `<(...)` or `>(...)` is read as
    part of the word it sits in, its text kept in the word's value, and its body is read as
    commands of its own (a region, first separator `(` or the backtick, a pipe number of its own)
    listed beside the command it is a word of: so `printf %s x$(echo a)y` is one printf, not a
    printf of `x$` and a command `y`, and `bash -c "x=$(true); kill \\$(pgrep -f X)"` hands on the
    whole assignment. An arithmetic `$((...))`, a `${...}` and a `$[...]` are not substitutions
    here, and are part of the word they sit in (word_chars()); a word also ends at a redirection
    operator glued to it (word_spans())."""
    t0 = join_lines(text)
    flow = compound_flow(t0)
    bodies = code_heredocs(t0)
    v = mask_quoted(t0, fill=FILL, live=True, code_bodies=bodies)
    if len(v) != len(t0):              # mask_quoted raises first; kept so no return path is []
        raise MaskMismatch("mask is %d characters, input %d" % (len(v), len(t0)))
    subs = sorted(substitutions(t0, code_bodies=bodies), key=lambda s: s["open"])
    items, st = [], {"pipe": 0}
    _region(t0, v, 0, len(v), None, subs, items, st)
    items.sort(key=lambda x: x.pos)    # stable: a segment's keywords stay before its command
    # A command word every walk found a call of a function surely in force (compound_flow()) runs
    # that function, not the program of its name: a shell's name there reads no stdin as code, and
    # a copier's passes nothing on (`bash() { cat; }; echo '...' | bash`). Its body is read where
    # the call runs it (compound_flow()).
    for c in items:
        if c.kw is not None:
            continue
        c.shadowed = c.at in flow[2]
        if getattr(c, "stdin_shell", False) and c.shadowed:
            c.stdin_shell = False
        elif getattr(c, "stdin_shell", False) and _io_redirs(c.words)[0][-1:] == ["<<<"]:
            c.codes += herestrings(c.words)[-1:]     # the last stdin redirection is what it reads
    # `echo … | bash` / `printf … | bash`: what a bare shell reads from the pipe is the producer's
    # stdout, so it is analysed as the code handed_script reconstructs (not argv joined — that
    # reads printf's format string or echo's option word as the command, and misses a payload in
    # a format argument). The producer is the command before it in its own pipeline, which a
    # substitution between them (`echo $(date) | bash`) does not interrupt.
    # A stdin copier (COPIES_STDIN) passes on what it reads: the herestring it is given (`cat <<<
    # '...' | bash`), or what the stage before it wrote (`echo … | cat | bash`). A heredoc it reads
    # is named code by code_heredocs() instead, and read inline like `bash <<EOF`'s.
    # What a stage wrote reaches the next only where its fd 1 is still the pipe once its
    # redirections are applied (fd1_to_pipe(): `echo ... >/dev/null | bash` hands the shell
    # nothing), and a line filter (LINE_FILTERS) passes on the lines it keeps.
    last, wrote = {}, {}
    for c in (c for c in items if c.kw is None):
        prev = last.get(c.pipe)
        fed = wrote.get(id(prev)) if prev is not None and fd1_to_pipe(prev.seg_words) else None
        if getattr(c, "stdin_shell", False) and fed and not _io_redirs(c.seg_words)[0]:
            c.codes.append(fed)                      # `| bash < F` reads F, not the pipe
        keep = None if c.shadowed else line_filter(c.words)
        if c.name in ("echo", "printf"):
            wrote[id(c)] = handed_script(c)
        elif (keep is not None or copies_stdin(c.words)) and not c.shadowed:
            keep = keep or (lambda text: text)
            ins, _ = _io_redirs(c.seg_words)
            if ins and ins[-1] == "<<<":
                got = (herestrings(c.seg_words) or [None])[-1]
                wrote[id(c)] = keep(got) if isinstance(got, str) else got
            elif not ins:
                wrote[id(c)] = keep(fed) if isinstance(fed, str) else fed
        last[c.pipe] = c
    # A herestring or echo/printf output a compound command carries to such a shell
    # (compound_flow()) is code too, handed on by the command whose word it is.
    cmds = [c for c in items if c.kw is None]
    seen = {code for c in cmds for code in c.codes}
    for off, code in flow[1]:
        owner = [c for c in cmds if c.pos <= off]
        if owner and code not in seen:
            max(owner, key=lambda c: c.pos).codes.append(code)
            seen.add(code)
    ticks = [s["body"] for s in subs if t0[s["open"]] == "`"]
    _expanded_bodies(t0, bodies, cmds, skip=ticks)
    # A command in a function body runs where a call runs it, so a variable in what it hands on
    # (every code attached above) is what that variable holds at the call (_at_call(), flow[3]),
    # not the literal assigned last before the body was WRITTEN.
    for c in items:
        if c.kw is None and c.codes and flow[3].get(c.at):
            c.codes = [n for code in c.codes for n in (
                _at_call(code, flow[3][c.at]) if isinstance(code, str) else [code])]
    return items


def _expanded_bodies(text, bodies, cmds, skip=()):
    """Hand on, by the command whose heredoc it is, the expansion of each UNQUOTED code body of
    text. That body is expanded by the shell that reads the heredoc before the shell it feeds
    runs it, and in that expansion a backslash before `$`, a backtick or a backslash is removed
    (bash(1), Here Documents): `bash <<EOF` (or `cat <<EOF | bash`) over `kill \\$(pgrep -f X)`
    runs `kill $(pgrep -f X)` in the inner shell. Read inline the body keeps its backslash and
    the substitution is not one.
    A heredoc inside a backtick body (its operator inside a span of skip) is expanded by
    _backtick_region() from the code bash runs there, never here: expanded from the text as
    written, the backtick's own escapes still in it, `` x=`bash <<EOF `` over `kill
    \\\\\\$(pgrep -f X)` would hand on `kill \\$(pgrep -f X)`, not the `kill $(pgrep -f X)` bash
    runs."""
    for hd in heredocs(text):
        a, b = hd["body"]
        if a not in bodies or hd["quoted"] or any(lo <= hd["op"] < hi for lo, hi in skip):
            continue
        body = text[a:b]
        expanded = re.sub(r"\\([$`\\])", r"\1", body)
        owner = [c for c in cmds if c.pos <= hd["op"]]
        if expanded != body and owner:
            max(owner, key=lambda c: c.pos).codes.append(expanded)


def _region(t0, v, a, b, first_sep, subs, items, st):
    """Read the commands of t0[a:b] into items: each substitution directly inside it is one span
    of word characters here, and a region of its own (read after this one). subs holds the
    arithmetic records too; an arithmetic command directly inside the region names no command
    (blank_arith()), and its substitutions are regions as any others."""
    direct, upto = [], a
    for s in subs:
        if s["kind"] in ("cmd", "proc") and a <= s["open"] < b and s["open"] >= upto:
            direct.append(s)
            upto = s["body"][1] + 1
    seg = list(v[a:b])
    for s in direct:
        for k in range(s["open"], min(s["body"][1] + 1, b)):
            seg[k - a] = FILL
    inside = [(s["open"], s["body"][1]) for s in direct]
    blank_arith(seg, a, [(x, y) for x, y in arith_commands(t0, subs)
                         if not any(o <= x <= c for o, c in inside)])
    seg = word_chars("".join(seg))
    bounds, start, prev_sep = [], 0, first_sep
    for m in SEP.finditer(seg):
        bounds.append((start, m.start(), prev_sep)); start, prev_sep = m.end(), m.group(0)
    bounds.append((start, len(seg), prev_sep))
    for x, y, sep in bounds:
        words = split_words(seg[x:y], t0[a + x:a + y])
        offs = [a + x + w[0] for w in word_spans(seg[x:y])]
        if sep not in ("|", "|&"):
            st["pipe"] += 1
        pipe, pos = st["pipe"], a + x
        while words and words[0][0] in RESERVED:
            kw = words.pop(0)[0]
            offs.pop(0)
            items.append(Cmd(kw=kw, pipe=pipe, pos=pos))
            if kw == "function":       # `function NAME { BODY`: the body's first command is here
                words, offs = words[1:], offs[1:]
            elif kw in ("for", "select", "case"):
                words = []
        if not words:
            continue
        idx, codes, _ = resolve(words)
        c = Cmd(words=words[idx:] if idx is not None else [], pipe=pipe, pos=pos)
        c.seg_words = words
        c.sep = sep
        c.at = offs[idx] if idx is not None and idx < len(offs) else None
        c.codes += codes
        c.codes += command_codes(c.words, stdin=False)
        if reads_code_on_stdin(c.words):
            c.stdin_shell = True
        if c.name == "git":
            c.codes += git_env_code(words[:idx])
        items.append(c)
    for s in direct:
        lo, hi = s["body"]
        if t0[s["open"]] == "`":
            _backtick_region(t0, s, items, st)
        else:
            _region(t0, v, lo, min(hi, b), "(", subs, items, st)


def _backtick_region(t0, s, items, st):
    """Read the commands of the backtick substitution s of t0 into items, from the code bash runs
    (backtick_code()), each at the offset in t0 it was written at, so `kill `echo \\`pgrep -f
    X\\``` reads the substitution bash runs, not a word `\\`pgrep`, and a body word `\\"b 1\\"`
    inside "..." is the one word bash gives."""
    code, src = tick_code(t0, s)
    bodies = code_heredocs(code)
    v = mask_quoted(code, fill=FILL, live=True, code_bodies=bodies)
    subs = sorted(substitutions(code, code_bodies=bodies), key=lambda x: x["open"])
    got = []
    _region(code, v, 0, len(code), "`", subs, got, st)
    ticks = [x["body"] for x in subs if code[x["open"]] == "`"]
    _expanded_bodies(code, bodies, [c for c in got if c.kw is None], skip=ticks)
    for c in got:
        c.pos = src[c.pos] if c.pos < len(src) else s["body"][1]
        c.at = src[c.at] if c.at is not None and c.at < len(src) else None
    items.extend(got)
