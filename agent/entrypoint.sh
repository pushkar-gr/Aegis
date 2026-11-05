#!/bin/sh
# Runs the trap-server alongside the agent in one container.

(
  while true; do
    ./aegis-trap-server
    echo "trap-server exited with status $?, restarting in 1s" >&2
    sleep 1
  done
) &

exec ./aegis-agent
