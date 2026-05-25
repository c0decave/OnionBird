#!/bin/bash
set -e

# Phase 1 (running as root): override DNS resolver so TB's queries go to dns-trap.
# This makes dns-trap the leak detector: if SOCKS5+remoteDNS is configured
# correctly, .onion lookups must NEVER hit dns-trap. Container-name lookups
# bypass DNS entirely via /etc/hosts (populated by extra_hosts in compose).
if [[ "$EUID" -eq 0 ]]; then
    if [[ -n "${T0_DNS_TRAP_IP:-}" ]]; then
        echo "nameserver ${T0_DNS_TRAP_IP}" > /etc/resolv.conf
    fi
    # Clean stale X lock files (volume may persist /tmp)
    rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
    # Drop to tbuser for the rest of the entrypoint
    exec gosu tbuser "$0" "$@"
fi

# Phase 2 (running as tbuser): X server, dbus, marionette bridge, TB

Xvfb :99 -screen 0 1280x720x24 -nolisten tcp &
export DISPLAY=:99

for _ in $(seq 1 30); do
    if xdpyinfo -display :99 >/dev/null 2>&1; then break; fi
    sleep 0.2
done

eval "$(dbus-launch --sh-syntax)"

# Marionette binds 127.0.0.1 only. socat forwards 0.0.0.0:2828 -> 127.0.0.1:2829.
socat TCP-LISTEN:2828,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:2829 &
SOCAT_PID=$!

cleanup() {
    kill "$SOCAT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

exec thunderbird --profile /home/tbuser/.thunderbird/test --marionette --remote-allow-system-access --no-remote
