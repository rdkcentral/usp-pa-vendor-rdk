#!/bin/bash
export LD_LIBRARY_PATH=/usr/local/lib
LOG_DIR=/var/log
STRESS_LOG=/tmp/stress_test.log
rm -f $STRESS_LOG

echo "--- STRESS TEST REPORT ---" > $STRESS_LOG
echo "Timestamp: $(date)" >> $STRESS_LOG

# 1. Functional Test: Rapid Row Addition/Removal
echo "=== 1. Functional: High Frequency Discovery/Cleanup ===" | tee -a $STRESS_LOG
# Spawn a dynamic provider that iterates 50 times
/usr/local/bin/rbusStressProvider dynamic 50 > /dev/null 2>&1 &
DYN_PID=$!
sleep 2
echo "Monitoring Table changes..." | tee -a $STRESS_LOG
for i in {1..10}; do
    count=$(obuspa -s /tmp/usp_cli -c get Device.Stress.Table. 2>/dev/null | grep -c "Param")
    echo "Snapshot $i: Found $count parameters" | tee -a $STRESS_LOG
    sleep 1
done
wait $DYN_PID

# 2. Performance: Mass Discovery
echo "=== 2. Performance: Mass Discovery (50 static providers) ===" | tee -a $STRESS_LOG
START_TIME=$(date +%s%N)
PIDS=()
for i in {1..50}; do
    /usr/local/bin/rbusStressProvider "Device.Perf.Table.$i.Name" "val$i" > /dev/null 2>&1 &
    PIDS+=($!)
done
# Wait for discovery
sleep 15
END_TIME=$(date +%s%N)
ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Elapsed discovery time for 50 providers: $ELAPSED ms" | tee -a $STRESS_LOG
count=$(obuspa -s /tmp/usp_cli -c get Device.Perf.Table. 2>/dev/null | grep -c "Name")
echo "Total discovered parameters: $count / 50" | tee -a $STRESS_LOG

# 3. Multi-operations Stress: Kill all mass providers at once
echo "=== 3. Stress: Bulk Deregistration (simultaneous kill) ===" | tee -a $STRESS_LOG
# Start monitoring log for "DML Task: Notifying instance deletion"
BEFORE_DELETE_LINES=$(grep -c "Notifying instance deletion" /var/log/obuspa.log)
kill ${PIDS[@]}
sleep 10
AFTER_DELETE_LINES=$(grep -c "Notifying instance deletion" /var/log/obuspa.log)
DEL_COUNT=$((AFTER_DELETE_LINES - BEFORE_DELETE_LINES))
echo "Deregistration notifications detected: $DEL_COUNT" | tee -a $STRESS_LOG
# Final check - should be empty
final_count=$(obuspa -s /tmp/usp_cli -c get Device.Perf.Table. 2>&1 | grep -c "Param")
if [[ $final_count -eq 0 ]]; then
    echo "Cleanup SUCCESSFUL" | tee -a $STRESS_LOG
else
    echo "Cleanup FAILED: $final_count entries remain" | tee -a $STRESS_LOG
fi

# 4. Multi-Operation Concurrency Stress
echo "=== 4. Stress: Multi-Operation Concurrency (Add/Del/Change) ===" | tee -a $STRESS_LOG
/usr/local/bin/rbusStressProvider multi 100 > /dev/null 2>&1 &
MULTI_PID=$!

echo "Simulating 100 random operations while monitoring USP DM..." | tee -a $STRESS_LOG
for i in {1..20}; do
    # Try to get all entries in the stress table
    count=$(obuspa -s /tmp/usp_cli -c get Device.Stress.Multi. 2>/dev/null | grep -c "Param")
    echo "Concurrent check $i: $count entries active" | tee -a $STRESS_LOG
    sleep 0.5
done

wait $MULTI_PID
echo "Multi-op phase FINISHED. Waiting 10s for notifications to settle..." | tee -a $STRESS_LOG
sleep 10
echo "Performing final cleanup check..." | tee -a $STRESS_LOG
final_count=$(obuspa -s /tmp/usp_cli -c get Device.Stress.Multi. 2>/dev/null | grep -c "Param")
echo "Final stale entries: $final_count" | tee -a $STRESS_LOG

echo "--- ALL TESTS FINISHED ---" | tee -a $STRESS_LOG
cat $STRESS_LOG
