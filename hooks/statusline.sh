#!/usr/bin/env bash
# Claude Code status line — model, dir/branch, and a CONTEXT-WINDOW gauge.
# The gauge runs green (<70%), yellow (>=70%), bold-red + "WATCH/⚠90%+" (>=90%).
# Rationale: the model has NO introspective access to its own context fill, so this
# bar is the externalized dial a human watches to wrap up / checkpoint BEFORE the
# squeeze. Input = JSON on stdin. Fields: https://code.claude.com/docs/en/statusline
set -euo pipefail
input=$(cat)

j() { jq -r "$1 // empty" <<<"$input" 2>/dev/null; }

model=$(j '.model.display_name'); model=${model:-?}
model=${model% (*}                                # drop trailing "(1M context)" etc.
fulldir=$(j '.workspace.current_dir'); [ -n "$fulldir" ] || fulldir=$(j '.cwd')
dir=${fulldir##*/}
branch=$(git -C "${fulldir:-.}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
pct=$(j '.context_window.used_percentage')
fivehr=$(j '.rate_limits.five_hour.used_percentage')
fivereset=$(j '.rate_limits.five_hour.resets_at')
sid=$(j '.session_id'); sid=${sid:-default}         # per-session key: .gauges is read by inject-gauges
                                                    # in the MATCHING session — a shared file clobbers
                                                    # across concurrent sessions (fixed 2026-07-10).

# Persist gauges for the UserPromptSubmit inject-gauges hook (model context awareness).
# Sentinel '-' for an EMPTY field, never a bare gap: an empty middle field (fivehr unset early
# in a session) would otherwise collapse under the reader's `read -r ctx fh rs`, shifting the
# reset EPOCH into the 5h-usage slot ("5h-usage 1783984200% used"). Reproduced + fixed 2026-07-13.
printf '%s %s %s\n' "${pct:--}" "${fivehr:--}" "${fivereset:--}" 2>/dev/null > ~/.claude/.gauges."$sid" || true

# ANSI
R=$'\033[0m'; DIM=$'\033[2m'; GRN=$'\033[32m'; YLW=$'\033[33m'; RED=$'\033[1;31m'; CYN=$'\033[36m'
PTH=$'\033[38;5;109m'; SES=$'\033[38;5;180m'    # path(branch)=light blue-grey, session=light gold

# Context % (compact — 10-char bar dropped for mobile width; the model now sees ctx-fill itself
# via the inject-gauges hook, so the human only needs the number + a colour cue).
if [ -z "$pct" ]; then
  gauge="${DIM}--c${R}"                           # null early in session / right after /compact
else
  p=${pct%.*}; [ -n "$p" ] || p=0
  if   [ "$p" -ge 90 ]; then col=$RED
  elif [ "$p" -ge 70 ]; then col=$YLW
  else                       col=$GRN
  fi
  gauge="${col}${p}%c${R}"
fi

# Burndown meter (written by ~/.claude/inject-gauges.sh each user turn): tokens/% + turns-to-cap.
BRN=$'\033[38;5;175m'                              # light mauve
brd=$(cat ~/.claude/.burndown-status."$sid" 2>/dev/null || true)
burn=""; [ -n "$brd" ] && burn="  ${BRN}${brd}${R}"

# 5-hour usage window (only when present) --------------------------------------
# Show TIME LEFT until the window resets (from resets_at epoch), plus % consumed.
# refreshInterval in settings.json keeps the countdown ticking between messages.
five=""
if [ -n "$fivehr" ]; then
  left=""
  if [ -n "$fivereset" ]; then
    rem=$(( ${fivereset%.*} - $(date +%s) )); [ "$rem" -lt 0 ] && rem=0
    h=$(( rem / 3600 )); m=$(( (rem % 3600) / 60 ))
    if [ "$h" -gt 0 ]; then left="${h}h${m}m "; else left="${m}m "; fi
  fi
  five="  ${SES}${left}${fivehr%.*}%${R}"
fi

printf '%s%s%s%s%s' \
  "$gauge" \
  "$five" \
  "$burn" \
  "${dir:+  ${PTH}${dir}${R}}${branch:+ ${PTH}(${branch})${R}}" \
  "  ${CYN}${model}${R}"
