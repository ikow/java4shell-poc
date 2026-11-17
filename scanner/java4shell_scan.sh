#!/usr/bin/env bash
# Java4Shell (CVE-2026-114938) Host Scanner
# Checks all Java installations on the host for vulnerability
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Java4Shell (CVE-2026-114938) Host Scanner    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
echo

VULN_COUNT=0
SAFE_COUNT=0
SKIP_COUNT=0

check_cpu() {
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        echo -e "${GREEN}[+] CPU: $arch — NOT AFFECTED (AVX-512 VBMI is x86-64 only)${NC}"
        exit 0
    fi

    if [[ -f /proc/cpuinfo ]]; then
        local has_vbmi=false
        if grep -qm1 'avx512vbmi' /proc/cpuinfo; then
            has_vbmi=true
        fi
        local cpu_name
        cpu_name=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
        if $has_vbmi; then
            echo -e "${YELLOW}[!] CPU: $cpu_name — HAS AVX-512 VBMI${NC}"
            return 0
        else
            echo -e "${GREEN}[+] CPU: $cpu_name — no AVX-512 VBMI, NOT AFFECTED${NC}"
            exit 0
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        if sysctl -n machdep.cpu.leaf7_features 2>/dev/null | grep -qi 'avx512vbmi'; then
            echo -e "${YELLOW}[!] CPU has AVX-512 VBMI${NC}"
            return 0
        else
            echo -e "${GREEN}[+] CPU: no AVX-512 VBMI, NOT AFFECTED${NC}"
            exit 0
        fi
    fi
}

check_java() {
    local java_bin="$1"
    local version_output
    version_output=$("$java_bin" -version 2>&1) || return 1

    local version
    version=$(echo "$version_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local major minor patch
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)
    patch=$(echo "$version" | cut -d. -f3)

    local vm_name
    vm_name=$(echo "$version_output" | grep -i 'vm' | head -1 | xargs)

    local vulnerable=false

    case "$major" in
        17)
            if [[ "$minor" -eq 0 && "$patch" -ge 6 && "$patch" -le 21 ]]; then
                vulnerable=true
            fi
            ;;
        21)
            if [[ "$minor" -eq 0 && "$patch" -le 13 ]]; then
                vulnerable=true
            fi
            ;;
        25)
            if [[ "$minor" -eq 0 && "$patch" -le 5 ]]; then
                vulnerable=true
            fi
            ;;
        27)
            if [[ "$minor" -eq 0 && "$patch" -le 1 ]]; then
                vulnerable=true
            fi
            ;;
    esac

    # Check for OpenJ9 (not affected)
    if echo "$vm_name" | grep -qi 'openj9\|j9'; then
        echo -e "    ${GREEN}SAFE${NC}  $java_bin"
        echo -e "          $version — OpenJ9 (different runtime, not affected)"
        ((SAFE_COUNT++)) || true
        return
    fi

    if $vulnerable; then
        echo -e "    ${RED}VULN${NC}  $java_bin"
        echo -e "          $version — $vm_name"
        ((VULN_COUNT++)) || true
    else
        echo -e "    ${GREEN}SAFE${NC}  $java_bin"
        echo -e "          $version — $vm_name"
        ((SAFE_COUNT++)) || true
    fi
}

check_jvm_flags() {
    local pid="$1"
    local name
    name=$(ps -p "$pid" -o args= 2>/dev/null | head -c 80)
    if echo "$name" | grep -q 'UseBASE64Intrinsics\|UseAVX=2'; then
        echo -e "    ${GREEN}MITIGATED${NC}  PID $pid — $name"
    else
        echo -e "    ${YELLOW}DEFAULT${NC}    PID $pid — $name"
    fi
}

# 1. CPU check
echo -e "${BLUE}[1/3] CPU Check${NC}"
check_cpu
echo

# 2. Find all Java binaries
echo -e "${BLUE}[2/3] Java Installations${NC}"
JAVA_BINS=()

# Common paths
for path in \
    /usr/bin/java /usr/local/bin/java \
    /usr/lib/jvm/*/bin/java \
    /usr/java/*/bin/java \
    /opt/java/*/bin/java \
    /opt/jdk*/bin/java \
    /Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java; do
    [[ -x "$path" ]] && JAVA_BINS+=("$path")
done

# JAVA_HOME
[[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]] && JAVA_BINS+=("$JAVA_HOME/bin/java")

# which java
command -v java &>/dev/null && JAVA_BINS+=("$(command -v java)")

# Deduplicate
readarray -t JAVA_BINS < <(printf '%s\n' "${JAVA_BINS[@]}" | sort -u)

if [[ ${#JAVA_BINS[@]} -eq 0 ]]; then
    echo "    No Java installations found"
else
    for jbin in "${JAVA_BINS[@]}"; do
        check_java "$jbin" 2>/dev/null || true
    done
fi
echo

# 3. Running JVMs
echo -e "${BLUE}[3/3] Running JVM Processes${NC}"
JAVA_PIDS=$(pgrep -f 'java\b' 2>/dev/null || true)
if [[ -z "$JAVA_PIDS" ]]; then
    echo "    No running JVM processes found"
else
    while read -r pid; do
        [[ -n "$pid" ]] && check_jvm_flags "$pid"
    done <<< "$JAVA_PIDS"
fi
echo

# Summary
echo "═══════════════════════════════════════════════"
if [[ $VULN_COUNT -gt 0 ]]; then
    echo -e "${RED}RESULT: $VULN_COUNT vulnerable, $SAFE_COUNT safe${NC}"
    echo
    echo "Recommended actions:"
    echo "  1. Update to fixed JDK (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1)"
    echo "  2. Interim: add -XX:-UseBASE64Intrinsics to all JVM start flags"
    echo "  3. Restart all JVM processes after patching"
    exit 1
else
    echo -e "${GREEN}RESULT: No vulnerable Java installations found${NC}"
    exit 0
fi
