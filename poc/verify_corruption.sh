#!/usr/bin/env bash
# Verify Java4Shell (CVE-2026-114938) memory corruption
# Usage: ./verify_corruption.sh [java-binary]
set -euo pipefail

JAVA="${1:-java}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔═══════════════════════════════════════════════════╗"
echo "║  Java4Shell (CVE-2026-114938) Corruption Verifier ║"
echo "╚═══════════════════════════════════════════════════╝"
echo

echo "[*] Environment"
echo "    OS:   $(uname -srm)"
"$JAVA" -version 2>&1 | sed 's/^/    JDK:  /'
echo

ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    echo "[!] SKIP: Architecture is $ARCH — AVX-512 VBMI requires x86-64"
    exit 2
fi

if [[ -f /proc/cpuinfo ]]; then
    REQUIRED=(avx512f avx512bw avx512vbmi bmi2)
    MISSING=()
    for flag in "${REQUIRED[@]}"; do
        if ! grep -qm1 "$flag" /proc/cpuinfo; then
            MISSING+=("$flag")
        fi
    done
    if [[ ${#MISSING[@]} -gt 0 ]]; then
        echo "[!] SKIP: CPU missing: ${MISSING[*]}"
        exit 2
    fi
    CPU=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
    echo "[+] CPU:  $CPU"
    echo "[+] Flags: ${REQUIRED[*]} ✓"
fi
echo

echo "[*] Compiling..."
"$JAVA"c "$DIR/Base64Trigger.java" -d /tmp/java4shell-poc 2>&1
echo

echo "[*] Running trigger (default JVM)..."
echo "────────────────────────────────────"
"$JAVA" -cp /tmp/java4shell-poc Base64Trigger 2>&1 && VULN=true || VULN=false
echo "────────────────────────────────────"
echo

if $VULN; then
    echo "[!] VULNERABLE — 62-byte heap overflow confirmed"
    echo
    echo "[*] Testing mitigation: -XX:-UseBASE64Intrinsics"
    echo "────────────────────────────────────"
    "$JAVA" -XX:-UseBASE64Intrinsics -cp /tmp/java4shell-poc Base64Trigger 2>&1 || true
    echo "────────────────────────────────────"
    echo
    echo "[*] Testing mitigation: -XX:UseAVX=2"
    echo "────────────────────────────────────"
    "$JAVA" -XX:UseAVX=2 -cp /tmp/java4shell-poc Base64Trigger 2>&1 || true
    echo "────────────────────────────────────"
else
    echo "[+] NOT VULNERABLE"
fi

rm -rf /tmp/java4shell-poc
