#!/bin/bash
# start_services.sh
# Purpose: Start rtrouted and obuspa with NotifyDML vendor plugin automatically.

set -e

# Cleanup any stale locks or sockets
rm -f /tmp/rtrouted /tmp/usp_cli /usr/local/var/obuspa/usp.db

# Clear stale DM discovery conf files from previous session.
# Without this, obuspa would register DM paths from a previous run's rbus
# providers into its in-memory schema at startup. If those providers are not
# yet running, every GET on those paths returns error 7003 until the async
# deregistration completes. Clearing on startup ensures a clean slate.
truncate -s 0 /etc/usp-pa/usp_dm_objs.conf 2>/dev/null || true
truncate -s 0 /etc/usp-pa/usp_dm_params.conf 2>/dev/null || true

# Ensure rtrouted is running
export LD_LIBRARY_PATH=/usr/local/lib
mkdir -p /usr/local/var/obuspa
echo "Starting rtrouted..."
/usr/local/bin/rtrouted > /var/log/rtrouted.log 2>&1 &
sleep 2

# Start obuspa with the plugin
echo "Starting obuspa (UspPA) with vendor plugin..."
export LD_LIBRARY_PATH=/usr/local/lib
/usr/local/bin/obuspa -x /usr/local/libexec/usp-pa-vendor-rdk.so -v 3 -l /var/log/obuspa.log -i lo -s /tmp/usp_cli &

echo "Services started. Container is ready."
# Keep container alive by tailing logs
tail -f /var/log/rtrouted.log /var/log/obuspa.log
