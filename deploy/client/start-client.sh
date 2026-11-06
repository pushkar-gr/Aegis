#!/bin/sh
set -eu

export DISPLAY=:99

ip route replace 172.21.0.0/24 via 172.20.0.10

Xvfb "$DISPLAY" \
  -screen 0 1920x1080x24 \
  -ac \
  >/tmp/xvfb.log 2>&1 &

sleep 2

openbox \
  >/tmp/openbox.log 2>&1 &

x11vnc \
  -display "$DISPLAY" \
  -rfbport 5900 \
  -listen 127.0.0.1 \
  -forever \
  -shared \
  -nopw \
  >/tmp/x11vnc.log 2>&1 &

i=0
while ! ss -lnt | grep -q ':5900 '; do
  i=$((i + 1))

  if [ "$i" -ge 20 ]; then
    echo "x11vnc did not start"
    cat /tmp/x11vnc.log
    exit 1
  fi

  sleep 1
done

websockify \
  --web=/usr/share/novnc \
  --heartbeat=30 \
  0.0.0.0:6080 \
  127.0.0.1:5900 \
  >/tmp/websockify.log 2>&1 &

sleep 1

chromium \
  --no-sandbox \
  --disable-dev-shm-usage \
  --disable-gpu \
  --start-maximized \
  about:blank \
  >/tmp/chromium.log 2>&1 &

wait
