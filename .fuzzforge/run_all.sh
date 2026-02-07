#!/usr/bin/env bash
# FuzzForge AI — Master Execution Script for systemd
# Run: ./run_all.sh [category] [--dry-run]
#
# Categories: all, ossfuzz, newtargets, protocols, configs, serialize,
#             security, llm, secrets, sanitizers, corpus, diff, ci
#
# Example:
#   ./run_all.sh ossfuzz          # Run all OSS-Fuzz campaigns
#   ./run_all.sh llm --dry-run    # Preview LLM analysis commands
#   ./run_all.sh all              # Run everything (250+ CPU-hours)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SARIF_DIR="${SCRIPT_DIR}/sarif"
PARAMS_DIR="${SCRIPT_DIR}/params"
LOG_DIR="${SCRIPT_DIR}/logs"
CATEGORY="${1:-all}"
DRY_RUN="${2:-}"

mkdir -p "$SARIF_DIR" "$LOG_DIR"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }

run_cmd() {
    local desc="$1"
    shift
    local cmd="$*"

    log "Task: $desc"
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        echo "  $cmd"
        return 0
    fi

    local logfile="${LOG_DIR}/$(echo "$desc" | tr ' /' '_-' | tr '[:upper:]' '[:lower:]').log"
    if eval "$cmd" > "$logfile" 2>&1; then
        ok "$desc completed. Log: $logfile"
    else
        err "$desc FAILED (exit $?). Log: $logfile"
    fi
}

# ============================================================
# A. OSS-FUZZ CAMPAIGNS — Existing Targets
# ============================================================
run_ossfuzz() {
    log "========== A. OSS-FUZZ CAMPAIGNS =========="

    run_cmd "A1: DNS Packet - ASAN 8h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=8 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a01-dns-packet-asan.sarif"

    run_cmd "A2: DNS Resource Record - MSAN 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=libfuzzer override_sanitizer=memory \
        --wait --export-sarif "${SARIF_DIR}/a02-dns-rr-msan.sarif"

    run_cmd "A3: DHCP Client - AFL 6h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=6 \
        override_engine=afl override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a03-dhcp-client-afl.sarif"

    run_cmd "A4: DHCPv6 Client - UBSAN 6h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=6 \
        override_engine=libfuzzer override_sanitizer=undefined \
        --wait --export-sarif "${SARIF_DIR}/a04-dhcp6-ubsan.sarif"

    run_cmd "A5: D-Bus Message - Honggfuzz 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=honggfuzz override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a05-bus-message-honggfuzz.sarif"

    for san in address memory undefined; do
        run_cmd "A6: Journal Native - ${san^^} 2h" \
            ff workflow run ossfuzz_campaign . \
            project_name=systemd campaign_duration_hours=2 \
            override_sanitizer=$san \
            --wait --export-sarif "${SARIF_DIR}/a06-journald-native-${san}.sarif"
    done

    run_cmd "A7: Journal Syslog - ASAN 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a07-journald-syslog.sarif"

    run_cmd "A8: LLDP Frame - AFL 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=afl override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a08-lldp-afl.sarif"

    run_cmd "A9: NDisc Router - ASAN 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a09-ndisc-rs.sarif"

    run_cmd "A10: Unit File - MSAN 6h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=6 \
        override_engine=libfuzzer override_sanitizer=memory \
        --wait --export-sarif "${SARIF_DIR}/a10-unit-file-msan.sarif"

    run_cmd "A11: JSON Parser - ASAN 12h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=12 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a11-json-extended.sarif"

    run_cmd "A12: Varlink Protocol - ASAN 6h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=6 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a12-varlink.sarif"

    run_cmd "A13: udev Rules - AFL 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=afl override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a13-udev-rules-afl.sarif"

    run_cmd "A14: Boot BCD - ASAN 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a14-bcd.sarif"

    run_cmd "A15: nspawn OCI - ASAN 4h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=4 \
        override_engine=libfuzzer override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/a15-nspawn-oci.sarif"
}

# ============================================================
# F. STATIC SECURITY ASSESSMENT
# ============================================================
run_security() {
    log "========== F. STATIC SECURITY ASSESSMENT =========="

    run_cmd "F1: Shared Library Security" \
        ff workflow run security_assessment src/shared/ \
        --param-file "${PARAMS_DIR}/security-shared.json" \
        --wait --export-sarif "${SARIF_DIR}/f01-security-shared.sarif"

    run_cmd "F2: Core Execution Security" \
        ff workflow run security_assessment src/core/ \
        --param-file "${PARAMS_DIR}/security-core.json" \
        --wait --export-sarif "${SARIF_DIR}/f02-security-core.sarif"

    run_cmd "F3: Network Stack Security" \
        ff workflow run security_assessment src/network/ \
        --param-file "${PARAMS_DIR}/security-network.json" \
        --wait --export-sarif "${SARIF_DIR}/f03-security-network.sarif"

    run_cmd "F4: Login/Home Security" \
        ff workflow run security_assessment src/login/ \
        --param-file "${PARAMS_DIR}/security-login.json" \
        --wait --export-sarif "${SARIF_DIR}/f04-security-login.sarif"

    run_cmd "F5: Full Codebase Dangerous Functions" \
        ff workflow run security_assessment . \
        --param-file "${PARAMS_DIR}/security-full.json" \
        --wait --export-sarif "${SARIF_DIR}/f05-security-full.sarif"
}

# ============================================================
# G. LLM-POWERED CODE ANALYSIS
# ============================================================
run_llm() {
    log "========== G. LLM-POWERED CODE ANALYSIS =========="

    run_cmd "G1: DNS Protocol Review" \
        ff workflow run llm_analysis src/shared/ \
        llm_model=gpt-5-mini max_files=5 \
        "file_patterns=dns-*.c" \
        --wait --export-sarif "${SARIF_DIR}/g01-llm-dns.sarif"

    run_cmd "G2: DHCP/DHCPv6 Protocol Review" \
        ff workflow run llm_analysis src/libsystemd-network/ \
        llm_model=gpt-5-mini max_files=10 \
        "file_patterns=dhcp*.c,sd-dhcp*.c" \
        --wait --export-sarif "${SARIF_DIR}/g02-llm-dhcp.sarif"

    run_cmd "G3: D-Bus Message Review" \
        ff workflow run llm_analysis src/libsystemd/sd-bus/ \
        llm_model=gpt-5-mini max_files=8 \
        "file_patterns=bus-*.c" \
        --wait --export-sarif "${SARIF_DIR}/g03-llm-dbus.sarif"

    run_cmd "G4: Journal File Format Review" \
        ff workflow run llm_analysis src/libsystemd/sd-journal/ \
        llm_model=gpt-5-mini max_files=8 \
        "file_patterns=journal-*.c" \
        --wait --export-sarif "${SARIF_DIR}/g04-llm-journal.sarif"

    run_cmd "G5: Execution Context Review" \
        ff workflow run llm_analysis src/core/ \
        llm_model=gpt-5-mini max_files=8 \
        "file_patterns=execute*.c,namespace.c,cgroup.c" \
        --wait --export-sarif "${SARIF_DIR}/g05-llm-exec.sarif"

    run_cmd "G6: Credential System Review" \
        ff workflow run llm_analysis src/shared/ \
        llm_model=gpt-5-mini max_files=5 \
        "file_patterns=creds-util.c,recovery-key.c,machine-credential.c" \
        --wait --export-sarif "${SARIF_DIR}/g06-llm-creds.sarif"

    run_cmd "G7: Image Dissection Review" \
        ff workflow run llm_analysis src/shared/ \
        llm_model=gpt-5-mini max_files=5 \
        "file_patterns=dissect-image.c,discover-image.c,loop-util.c" \
        --wait --export-sarif "${SARIF_DIR}/g07-llm-image.sarif"

    run_cmd "G8: BPF Security Programs Review" \
        ff workflow run llm_analysis src/core/ \
        llm_model=gpt-5-mini max_files=6 \
        "file_patterns=bpf-*.c" \
        --wait --export-sarif "${SARIF_DIR}/g08-llm-bpf.sarif"
}

# ============================================================
# H. SECRET DETECTION
# ============================================================
run_secrets() {
    log "========== H. SECRET DETECTION =========="

    run_cmd "H1: LLM Secret Detection - Full" \
        ff workflow run llm_secret_detection . \
        llm_model=gpt-5-mini max_files=50 \
        --wait --export-sarif "${SARIF_DIR}/h01-secrets-llm.sarif"

    run_cmd "H2: Gitleaks Pattern Detection" \
        ff workflow run gitleaks_detection . \
        --wait --export-sarif "${SARIF_DIR}/h02-secrets-gitleaks.sarif"

    run_cmd "H3: Test Data Credential Audit" \
        ff workflow run llm_secret_detection test/ \
        llm_model=gpt-5-mini max_files=30 \
        --wait --export-sarif "${SARIF_DIR}/h03-secrets-test.sarif"

    run_cmd "H4: Config Template Review" \
        ff workflow run llm_secret_detection . \
        llm_model=gpt-5-mini max_files=20 \
        "file_patterns=*.conf.in,*.conf,*.xml" \
        --wait --export-sarif "${SARIF_DIR}/h04-secrets-config.sarif"
}

# ============================================================
# I. SANITIZER MATRIX
# ============================================================
run_sanitizers() {
    log "========== I. SANITIZER MATRIX =========="

    run_cmd "I1: Full Suite ASAN 24h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=24 \
        override_sanitizer=address \
        --wait --export-sarif "${SARIF_DIR}/i01-full-asan.sarif"

    run_cmd "I2: Full Suite MSAN 24h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=24 \
        override_sanitizer=memory \
        --wait --export-sarif "${SARIF_DIR}/i02-full-msan.sarif"

    run_cmd "I3: Full Suite UBSAN 24h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=24 \
        override_sanitizer=undefined \
        --wait --export-sarif "${SARIF_DIR}/i03-full-ubsan.sarif"

    run_cmd "I4: Full Suite DFSan 12h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=12 \
        override_sanitizer=dataflow \
        --wait --export-sarif "${SARIF_DIR}/i04-full-dfsan.sarif"
}

# ============================================================
# K. CROSS-ENGINE DIFFERENTIAL
# ============================================================
run_diff() {
    log "========== K. CROSS-ENGINE DIFFERENTIAL =========="

    for engine in libfuzzer afl honggfuzz; do
        run_cmd "K1: Cross-engine ${engine} 4h" \
            ff workflow run ossfuzz_campaign . \
            project_name=systemd campaign_duration_hours=4 \
            override_engine=$engine override_sanitizer=address \
            --wait --export-sarif "${SARIF_DIR}/k01-cross-${engine}.sarif"
    done
}

# ============================================================
# L. CI/CD INTEGRATION
# ============================================================
run_ci() {
    log "========== L. CI/CD INTEGRATION =========="

    run_cmd "L1: PR Gate Fuzz Check 1h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=1 \
        override_sanitizer=address \
        --wait --fail-on error --export-sarif "${SARIF_DIR}/l01-ci-fuzz.sarif"

    run_cmd "L2: Nightly Extended 8h" \
        ff workflow run ossfuzz_campaign . \
        project_name=systemd campaign_duration_hours=8 \
        --wait --fail-on error --export-sarif "${SARIF_DIR}/l02-nightly-fuzz.sarif"
}

# ============================================================
# MAIN DISPATCH
# ============================================================
case "$CATEGORY" in
    ossfuzz)    run_ossfuzz ;;
    security)   run_security ;;
    llm)        run_llm ;;
    secrets)    run_secrets ;;
    sanitizers) run_sanitizers ;;
    diff)       run_diff ;;
    ci)         run_ci ;;
    all)
        run_security
        run_llm
        run_secrets
        run_ossfuzz
        run_sanitizers
        run_diff
        run_ci
        ;;
    *)
        echo "Usage: $0 {all|ossfuzz|security|llm|secrets|sanitizers|diff|ci} [--dry-run]"
        echo ""
        echo "Categories:"
        echo "  ossfuzz     - OSS-Fuzz campaigns (15 tasks, ~80h)"
        echo "  security    - Static security assessment (5 tasks)"
        echo "  llm         - LLM code analysis (8 tasks)"
        echo "  secrets     - Secret detection (4 tasks)"
        echo "  sanitizers  - Sanitizer matrix expansion (4 tasks, ~84h)"
        echo "  diff        - Cross-engine differential (3 runs, ~12h)"
        echo "  ci          - CI/CD integration tests (2 tasks)"
        echo "  all         - Run everything (~250+ hours)"
        exit 1
        ;;
esac

log "Done. SARIF results in: ${SARIF_DIR}/"
log "Logs in: ${LOG_DIR}/"
