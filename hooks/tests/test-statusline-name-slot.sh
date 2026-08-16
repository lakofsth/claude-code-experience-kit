#!/usr/bin/env bash
# Branch proof for the one slot in hooks/statusline.sh that holds either the session NAME
# (from the presence registry, §11) or the burndown meter (§2).
#
# Every case drives the real script across the real boundary — crafted status-line JSON on
# stdin — under a throwaway HOME, so it can neither read nor write any live state: the script
# resolves ~/.local/state/claude-sessions/names.tsv, ~/.claude/.burndown-status.<sid> and the
# gauges file it writes all through $HOME.
#
# Run from anywhere:  bash hooks/tests/test-statusline-name-slot.sh
# Exit status is the gate: 0 all pass, 1 one or more failed.
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
SL="$HERE/../statusline.sh"
SID="test-session-0001"
bad=0

run() {           # run <fakehome> -> the rendered line with ANSI stripped
  HOME="$1" bash "$SL" <<JSON | sed 's/\x1b\[[0-9;]*m//g'
{"session_id":"$SID","model":{"display_name":"Test Model"},
 "workspace":{"current_dir":"/tmp"},"context_window":{"used_percentage":34}}
JSON
}

fresh_home() {    # a HOME with ~/.claude present (the script writes its gauges file there)
  local h; h=$(mktemp -d)
  mkdir -p "$h/.claude"
  printf '%s\n' "$h"
}

check() {         # check <label> <line> <must-contain|-> <must-not-contain|->
  local label="$1" line="$2" want="$3" nowant="$4" ok=1
  [ "$want"   = "-" ] || case "$line" in *"$want"*)   ;; *) ok=0 ;; esac
  [ "$nowant" = "-" ] || case "$line" in *"$nowant"*) ok=0 ;; esac
  if [ "$ok" = 1 ]; then echo "  PASS  $label"; else
    bad=$((bad+1)); echo "  FAIL  $label"
    echo "        want=[$want] not=[$nowant] got=[$line]"
  fi
}

# 1. No names.tsv at all — presence is not installed. The burn readout must survive untouched.
H=$(fresh_home); echo '210k/% ~14t' > "$H/.claude/.burndown-status.$SID"
check "no names.tsv        -> burn readout" "$(run "$H")" "210k/% ~14t" "-"

# 2. names.tsv exists but does NOT hold this session — registered peers, not us yet.
#    Discriminates a real lookup from "any names.tsv means a name": a bare -f test would pass
#    here and print the peer's name.
H=$(fresh_home); echo '210k/% ~14t' > "$H/.claude/.burndown-status.$SID"
mkdir -p "$H/.local/state/claude-sessions"
printf 'other-heron\tsome-other-session\t123\t/tmp\n' > "$H/.local/state/claude-sessions/names.tsv"
check "names.tsv, not ours -> burn readout" "$(run "$H")" "210k/% ~14t" "other-heron"

# 3. names.tsv holds this session — the name takes the slot and the burn is not also printed.
H=$(fresh_home); echo '210k/% ~14t' > "$H/.claude/.burndown-status.$SID"
mkdir -p "$H/.local/state/claude-sessions"
printf 'other-heron\tsome-other-session\t123\t/tmp\nautumn-wren\t%s\t124\t/tmp\n' "$SID" \
  > "$H/.local/state/claude-sessions/names.tsv"
check "names.tsv, ours     -> name, no burn" "$(run "$H")" "autumn-wren" "210k/% ~14t"

# 4. Neither — the slot is simply empty and the rest of the line still renders.
H=$(fresh_home)
line=$(run "$H")
check "neither             -> rest of line intact" "$line" "Test Model" "210k/% ~14t"
check "neither             -> context gauge intact" "$line" "34%c" "-"

echo
if [ "$bad" = 0 ]; then echo "  Ran 5 checks — ALL PASS"; else echo "  Ran 5 checks — $bad FAILED"; fi
exit $(( bad ? 1 : 0 ))
