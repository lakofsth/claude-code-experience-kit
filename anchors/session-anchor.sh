#!/usr/bin/env bash
# Claude Code usage-window ANCHOR. Spends a few tokens (Haiku, '.' prompt) purely to OPEN a 5h
# usage window at a predictable time, so the window RESETS at a predictable time (reset =
# fire time + 5h). NOT meant to do work — minimal tokens by design.
#
# Use an ABSOLUTE path to the claude binary: under systemd/cron there is no login PATH.
# Find yours with `command -v claude` in a login shell and substitute it below.
echo "[$(date '+%F %T %Z')] anchor fire ($1) -> window resets ~$(date -d '+5 hours' '+%H:%M %Z')"
timeout 180 "$HOME/.npm-global/bin/claude" --dangerously-skip-permissions \
  --model claude-haiku-4-5-20251001 -p '.' 2>&1 | tail -2
echo "[$(date '+%F %T %Z')] anchor done ($1) rc=${PIPESTATUS[0]}"
