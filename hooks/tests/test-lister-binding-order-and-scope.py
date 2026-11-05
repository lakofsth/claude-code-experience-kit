"""Check of the ORDER and SCOPE of a lister's binding in hooks/block-unsafe-kill.sh -- the edges of
mh-a-lister-reaches-a-kill-through-every-binding-site that
test-lister-bound-name-and-order-cert.py does not pin.

A binding counts only where bash has it when the kill runs: after the
binding, in the shell that made it, and before a reassignment bash always runs. Each of those
rules has a side where getting it wrong goes SILENT, and that side is pinned here:

  - a kill textually before the binding still sees it in a later pass of a loop that holds both,
    and inside a function body (`function f { ... }` too), which runs when it is called;
  - a binding in a subshell, a substitution or a `local` is seen by a kill inside it, a
    `declare -g` in a function by the whole call, and a pipeline's `read` by its own compound
    and, under `shopt -s lastpipe`, by what follows;
  - `set -e`, `unset -f` and `set -- "$@" x` end nothing, and a later `for` over the bound name
    carries it on;
  - a prefix assignment `P=$(L) cmd` binds P for a function cmd runs (refused), and for nothing
    else (silent, as an `echo` or a kill with it in its environment).

The labels are bash's, as in test-lister-bound-name-and-order-cert.py: its harness (stand-in listers above pid_max, logging
kills) runs every template first, and a template bash disagrees with exits 2.
"""
import importlib.util, os, shutil, signal, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "cert", os.path.join(HERE, "test-lister-bound-name-and-order-cert.py"))
cert = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert)

REACH = [
    ("kill before =, in a later pass", "for i in 1 2; do kill \"$SRV\" $P; P=$({L}); done"),
    ("function keyword body",         "function f { kill $P; }; P=$({L}); f"),
    ("function body before =",        "f() { kill $P; }; P=$({L}); f"),
    ("kill inside the subshell",      "( P=$({L}); kill $P )"),
    ("kill inside the substitution",  "echo $(P=$({L}); kill $P)"),
    ("local seen in its function",    "f() { local P=$({L}); kill $P; }; f"),
    ("declare -g in a function",      "f() { declare -g P=$({L}); }; f; kill $P"),
    ("read in its pipe's compound",   "{L} | { read p; kill $p; }"),
    ("lastpipe read",                 "shopt -s lastpipe; {L} | read p; kill $p"),
    ("set -e ends nothing",           "set -- $({L}); set -e; kill \"$@\""),
    ("set -- \"$@\" carries on",      "set -- $({L}); set -- \"$@\" 4194409; kill \"$@\""),
    ("unset -f ends nothing",         "P=$({L}); unset -f P; kill $P"),
    ("printf -v from itself",         "printf -v P '%s' \"$({L})\"; printf -v P '%s' \"$P\"; kill $P"),
    ("later for over the name",       "for p in $({L}); do :; done; for p in $p; do kill $p; done"),
    ("prefix to a function",          "f() { kill $P; }; P=$({L}) f"),
    ("chain then function args",      "P=$({L}); f() { kill $1; }; f $P"),
]

SILENT = [
    ("prefix to an echo",             "P=$({L}) echo hi; kill \"$SRV\" $P"),
    ("binding inside a substitution", "echo $(P=$({L})); kill \"$SRV\" $P"),
    ("read in a pipe, kill outside",  "{L} | { read p; }; kill \"$SRV\" $p"),
    ("kill after the loop that binds", "kill \"$SRV\" $P; for i in 1; do P=$({L}); done"),
    ("set -- rebound, loop after",    "set -- $({L}); set -- \"$SRV\"; for q in \"$@\"; do kill $q; done"),
    ("chain into function args, top-level $1",
                                      "P=$({L}); f() { echo \"$@\"; }; f $P; kill \"$SRV\" $1"),
]


def main():
    d = tempfile.mkdtemp(prefix="mh-order-scope-")
    sd = os.path.join(d, "bin")
    os.mkdir(sd)
    log = os.path.join(d, "kill.log")
    rc = cert.stand_ins(sd, log)
    exe = os.path.join(d, cert.A)
    shutil.copy2("/bin/sleep", exe)
    procs = [cert.sleeper(exe) for _ in range(2)]
    failures, broken, total = [], [], 0
    try:
        for _ in range(50):
            if cert.count(cert.A) >= 2:
                break
            time.sleep(0.05)
        if cert.count(cert.A) != 2:
            print("SETUP FAILED: want 2 x %s, have %d" % (cert.A, cert.count(cert.A)))
            return 2
        for want, rows in ((True, REACH), (False, SILENT)):
            for label, tpl in rows:
                truth = cert.bash_carries(tpl.replace("{L}", "pgrep -f x"), sd, log, rc)
                if truth != want:
                    broken.append("[%s] written as %s, bash says otherwise: %s"
                                  % (label, "carried" if want else "not carried", tpl))
                    continue
                for ln, lister in cert.LISTERS:
                    cmd = tpl.replace("{L}", lister)
                    total += 1
                    fired, err = cert.verdict(cmd)
                    if want and not fired:
                        failures.append("NOT REFUSED [%s, %s]: %s" % (label, ln, cmd))
                    elif not want and fired:
                        failures.append("FALSE REFUSAL [%s, %s]: %s\n    said: %s"
                                        % (label, ln, cmd, err.splitlines()[0] if err else ""))
    finally:
        for p in procs:             # by PID
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)

    if broken:
        print("CHECK DEFECT: %d template(s) disagree with bash" % len(broken))
        for b in broken:
            print("  " + b)
        return 2
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d cases (%d reach x %d listers refused, %d silent x %d listers silent), "
          "each template's label confirmed by bash"
          % (total, len(REACH), len(cert.LISTERS), len(SILENT), len(cert.LISTERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
