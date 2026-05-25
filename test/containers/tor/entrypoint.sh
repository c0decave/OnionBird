#!/bin/bash
set -e
chown -R tor:tor /var/lib/tor
exec su-exec tor tor -f /etc/tor/torrc
