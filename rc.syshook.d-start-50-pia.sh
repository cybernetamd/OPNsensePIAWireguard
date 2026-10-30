#!/bin/sh
# 50-pia - bring the PIA WireGuard tunnel up at boot (OPNsense)
#
# OPNsense's rc.syshook "start" stage runs AFTER system network startup
# (i.e. once your WAN has an IP), so this is the right place to launch the
# PIA tunnel at boot without waiting for the every-5-minutes cron.
#
# Without this hook the gateway (e.g. PIAGW_GW) sits in an "Undefined"/red
# state for up to ~4 minutes after a reboot, because the tunnel's endpoint
# pointer file /tmp/wg0_router is wiped on reboot and only gets re-written
# the first time the monitor runs. This hook runs the SAME proven configd
# action the cron uses, once, so the pointer is written fast and the
# gateway flips to "Online" within a couple of seconds of boot.
#
# Install location on the router:   /usr/local/etc/rc.syshook.d/start/50-pia
# The "50-" prefix = plugin ordering (core scripts use "20-", plugins "50-").
# Make it executable:               chmod +x /usr/local/etc/rc.syshook.d/start/50-pia
#
# It is idempotent: the monitor is safe to re-run, so a stray extra call
# (or a later cron tick) never undoes the work.

set -u

# Find a WAN interface that actually has an IP, giving it up to 30 seconds.
# The syshook "start" stage normally runs after WAN is up, so this is a belt
# and braces wait rather than a long one.
WANIF=$(ifconfig -L 2>/dev/null | tr ' ' '\n' | grep -vE '^lo[0-9]?$' | head -1)
WANIF=${WANIF:-vtnet0}
i=0
while [ $i -lt 30 ]; do
    if ifconfig ${WANIF} 2>/dev/null | grep -q 'inet '; then break; fi
    i=$((i+1)); sleep 1
done

logger -t rc_pia "rc_pia[syshook]: launching PIA (wan=${WANIF}, waited ${i}s)"

# Run the exact action the every-5-minutes cron uses. configctl is OPNsense's
# configd action helper (lives in /usr/local/sbin). Fallback to PATH if the
# absolute path isn't present on an unusual install.
CFG=/usr/local/sbin/configctl
[ -x $CFG ] || CFG=configctl
$CFG piawireguard monitor >/dev/null 2>&1 &

# Give the monitor a moment to write the endpoint pointer, then log the result.
sleep 5
if [ -f /tmp/wg0_router ]; then
    logger -t rc_pia "rc_pia[syshook]: SUCCESS /tmp/wg0_router=$(cat /tmp/wg0_router)"
else
    logger -t rc_pia "rc_pia[syshook]: monitor ran; /tmp/wg0_router not set yet (cron will finish it)"
fi
