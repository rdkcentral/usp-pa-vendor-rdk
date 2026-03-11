#!/bin/bash

# Configuration
USP_CLI="obuspa -s /tmp/usp_cli"
LOG_FILE="/var/log/obuspa.log"
PROVIDER_LOG="/work/provider.log"
REPORT_FILE="/work/test_report.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RESET='\033[0m'

# Summary tracking
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Helper Functions
log_header() {
    echo -e "\n${MAGENTA}======================================================================${RESET}"
    echo -e "${MAGENTA} $1 ${RESET}"
    echo -e "${MAGENTA}======================================================================${RESET}"
}

log_step() { echo -e "${CYAN}[STEP]${RESET} $1"; }
log_verify() { echo -e "${YELLOW}[VERIFY]${RESET} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${RESET} $1"; PASSED_CHECKS=$((PASSED_CHECKS+1)); }
log_fail() { echo -e "${RED}[FAIL]${RESET} $1"; FAILED_CHECKS=$((FAILED_CHECKS+1)); }

# Environment Setup
setup_env() {
    log_header "ENVIRONMENT SETUP"
    log_step "Cleaning processes and clearing data..."
    killall -9 obuspa rtrouted rbusTestProvider 2>/dev/null || true
    rm -f /tmp/rtrouted /tmp/usp_cli /usr/local/var/obuspa/usp.db
    > $LOG_FILE
    > $PROVIDER_LOG
    > $REPORT_FILE

    log_step "Starting rtrouted..."
    /usr/local/bin/rtrouted > /var/log/rtrouted.log 2>&1 &
    sleep 2

    log_step "Starting obuspa..."
    LD_LIBRARY_PATH=/usr/local/lib /usr/local/bin/obuspa -x /usr/local/libexec/usp-pa-vendor-rdk.so -v 4 -l $LOG_FILE -i eth0 -s /tmp/usp_cli -p -t -f /usr/local/var/obuspa/usp.db &

    log_step "Waiting for steady state..."
    TRIES=0
    while ! grep -qa "Subscribing to NotifyDML" $LOG_FILE && [ $TRIES -lt 30 ]; do
        sleep 1
        TRIES=$((TRIES+1))
    done

    if [ $TRIES -eq 30 ]; then
        log_fail "Environment failed to initialize (continuing anyway)"
    else
        log_pass "Environment Ready"
    fi
}

# Verification Logic
verify_path() {
    local path=$1
    local expected_val=$2
    local check_type=$3 # "exists" or "missing"
    
    log_verify "Verifying $path ($check_type)..."
    
    for attempt in {1..10}; do
        local fail_reason=""
        
        # 1. RBUS Check
        local rbus_ok=false
        local rbus_out=$(rbuscli get "$path" 2>&1)
        if [[ "$check_type" == "exists" ]]; then
            if [[ "$rbus_out" == *"$path"* ]] && [[ "$rbus_out" != *"Error"* ]] && [[ "$rbus_out" != *"not found"* ]]; then
                rbus_ok=true
            else
                fail_reason="RBUS check failed"
            fi
        else
            if [[ "$rbus_out" == *"Error"* ]] || [[ "$rbus_out" == *"not found"* ]] || [[ "$rbus_out" != *"$path"* ]]; then
                rbus_ok=true
            else
                fail_reason="RBUS should be missing"
            fi
        fi

        # 2. USP GET Check (trigger lazy cleanup if needed)
        local get_ok=false
        local get_out=$( $USP_CLI -c get "$path" 2>&1 )
        if [[ "$check_type" == "exists" ]]; then
            if [[ "$get_out" == *"$expected_val"* ]]; then
                get_ok=true
            else
                fail_reason="USP GET failed"
            fi
        else
            if echo "$get_out" | grep -qiE "Path is invalid|7016|not found|DESTINATION_NOT_FOUND|Destination.not.found" || [ -z "$get_out" ]; then
                get_ok=true
            else
                fail_reason="USP GET reachable"
            fi
        fi

        # 3. Schema Check
        local schema_ok=false
        local search_path=$(echo "$path" | sed 's/\.[0-9]\+/\.{i}/g')
        local dump_out=$( $USP_CLI -c dump datamodel 2>/dev/null | grep "$search_path" )
        if [[ "$check_type" == "exists" ]]; then
            if [ ! -z "$dump_out" ]; then schema_ok=true; else fail_reason="Schema missing"; fi
        else
            if [[ "$path" == *".1."* || "$path" == *".2."* ]]; then
                schema_ok=true; # Table instances template remains
            else
                if [ -z "$dump_out" ]; then schema_ok=true; else fail_reason="Schema present"; fi
            fi
        fi

        if [ "$rbus_ok" = true ] && [ "$get_ok" = true ] && [ "$schema_ok" = true ]; then
            log_pass "Verified: $path"
            return 0
        fi

        if [ $attempt -eq 3 ]; then
            log_step "Triggering manual discovery sync..."
            $USP_CLI -c set Device.X_RDK_Test.Sync true > /dev/null 2>&1
        fi

        if [ $attempt -lt 10 ]; then
            log_step "Attempt $attempt failed ($fail_reason), retrying in 5s..."
            sleep 5
        fi
    done

    log_fail "Verification failed for $path after 10 attempts"
    return 1
}

# --- TEST CATEGORIES ---

test_functional() {
    log_header "FUNCTIONAL TESTS"
    
    # 1. Basic Single Parameter
    log_step "Case 1: Single Parameter Lifecycle"
    /usr/bin/rbusTestProvider Device.X_RDK_Test.Func.Param1 ValFunc >> $PROVIDER_LOG 2>&1 &
    PID=$!
    verify_path "Device.X_RDK_Test.Func.Param1" "ValFunc" "exists"
    kill $PID
    verify_path "Device.X_RDK_Test.Func.Param1" "" "missing"

    # 2. Re-registration Stability
    log_step "Case 2: Re-registration Bug Fix Verification"
    /usr/bin/rbusTestProvider Device.X_RDK_Test.Func.Repeat Val1 >> $PROVIDER_LOG 2>&1 &
    PID=$!
    verify_path "Device.X_RDK_Test.Func.Repeat" "Val1" "exists"
    kill $PID
    sleep 5
    /usr/bin/rbusTestProvider Device.X_RDK_Test.Func.Repeat Val2 >> $PROVIDER_LOG 2>&1 &
    PID2=$!
    verify_path "Device.X_RDK_Test.Func.Repeat" "Val2" "exists"
    kill $PID2

    # 3. Table Instances
    log_step "Case 3: Dynamic Table Instances"
    /usr/bin/rbusTestProvider Device.X_RDK_Test.Func.Table.1.Name T1 >> $PROVIDER_LOG 2>&1 &
    PIDT1=$!
    /usr/bin/rbusTestProvider Device.X_RDK_Test.Func.Table.2.Name T2 >> $PROVIDER_LOG 2>&1 &
    PIDT2=$!
    verify_path "Device.X_RDK_Test.Func.Table.1.Name" "T1" "exists"
    verify_path "Device.X_RDK_Test.Func.Table.2.Name" "T2" "exists"
    kill $PIDT1
    verify_path "Device.X_RDK_Test.Func.Table.1.Name" "" "missing"
    verify_path "Device.X_RDK_Test.Func.Table.2.Name" "T2" "exists"
    kill $PIDT2
}

test_performance() {
    log_header "PERFORMANCE TESTS"
    
    log_step "Measuring Discovery Latency..."
    START_TIME=$(date +%s%N)
    /usr/bin/rbusTestProvider Device.X_RDK_Test.Perf.Latency LatencyVal >> $PROVIDER_LOG 2>&1 &
    PID=$!
    
    FOUND=false
    while [ $(($(date +%s%N) - START_TIME)) -lt 10000000000 ]; do # 10s limit
        if $USP_CLI -c get Device.X_RDK_Test.Perf.Latency | grep -q "LatencyVal"; then
            END_TIME=$(date +%s%N)
            FOUND=true
            break
        fi
        sleep 0.2
    done
    
    if [ "$FOUND" = true ]; then
        LATENCY=$(( (END_TIME - START_TIME) / 1000000 ))
        log_pass "Discovery Latency: ${LATENCY}ms"
    else
        log_fail "Performance: Discovery took too long (>10s)"
    fi
    kill $PID
}

test_stress() {
    log_header "STRESS TESTS"
    
    log_step "Rapid Registration (10 parameters)..."
    PIDS=()
    for i in {1..10}; do
        /usr/bin/rbusTestProvider Device.X_RDK_Test.Stress.P$i "Val$i" >> $PROVIDER_LOG 2>&1 &
        PIDS+=($!)
    done
    
    sleep 5
    FAIL_COUNT=0
    for i in {1..10}; do
        if $USP_CLI -c get Device.X_RDK_Test.Stress.P$i | grep -q "Val$i"; then
            log_pass "P$i: OK"
        else
            log_fail "P$i: FAILED"
            FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    done
    
    if [ $FAIL_COUNT -eq 0 ]; then
        log_pass "Stress: Batch Registration Successful"
    else
        log_fail "Stress: $FAIL_COUNT parameters failed to register"
    fi
    
    for pid in "${PIDS[@]}"; do kill $pid 2>/dev/null; done
}

test_nonfunctional() {
    log_header "NON-FUNCTIONAL TESTS"
    
    log_step "Agent Stability during Provider Crash"
    /usr/bin/rbusTestProvider Device.X_RDK_Test.NonFunc.Crash Surprise >> $PROVIDER_LOG 2>&1 &
    PID=$!
    sleep 3
    kill -9 $PID # Simulated crash
    sleep 5
    verify_path "Device.X_RDK_Test.NonFunc.Crash" "" "missing"
}

# --- MAIN MENU ---

show_menu() {
    echo -e "\n${CYAN}======================================================================${RESET}"
    echo -e "${CYAN} USP-RBUS UNIFIED TEST SUITE ${RESET}"
    echo -e "${CYAN}======================================================================${RESET}"
    echo "1) Run Functional Tests"
    echo "2) Run Performance Tests"
    echo "3) Run Stress Tests"
    echo "4) Run Non-Functional Tests"
    echo "5) Run ALL Tests"
    echo "q) Quit"
    echo -n "Select option: "
}

run_all() {
    setup_env
    test_functional
    test_performance
    test_stress
    test_nonfunctional
}

print_summary() {
    echo -e "\n${CYAN}======================================================================${RESET}"
    echo -e " FINAL TEST SUMMARY"
    echo -e "======================================================================${RESET}"
    echo -e " Checks Passed: ${GREEN}$PASSED_CHECKS${RESET}"
    echo -e " Checks Failed: ${RED}$FAILED_CHECKS${RESET}"
    if [ $((PASSED_CHECKS + FAILED_CHECKS)) -gt 0 ]; then
        echo -e " Success Rate:  $(( 100 * PASSED_CHECKS / (PASSED_CHECKS + FAILED_CHECKS) ))%"
    fi
    echo -e "${CYAN}======================================================================${RESET}\n"
}

# Execution CLI
if [[ -n "$1" ]]; then
    case $1 in
        "functional") setup_env; test_functional ;;
        "performance") setup_env; test_performance ;;
        "stress") setup_env; test_stress ;;
        "nonfunctional") setup_env; test_nonfunctional ;;
        "all") run_all ;;
        *) echo "Usage: $0 {functional|performance|stress|nonfunctional|all}" ;;
    esac
    print_summary
    [ $FAILED_CHECKS -eq 0 ] && exit 0 || exit 1
else
    while true; do
        show_menu
        read opt
        case $opt in
            1) setup_env; test_functional ;;
            2) setup_env; test_performance ;;
            3) setup_env; test_stress ;;
            4) setup_env; test_nonfunctional ;;
            5) run_all ;;
            q) exit 0 ;;
            *) echo "Invalid option" ;;
        esac
        print_summary
    done
fi
