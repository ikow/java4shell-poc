<p align="center">
  <img src="docs/cover.png" alt="java4shell" width="700">
</p>

<h1 align="center">java4shell</h1>
<p align="center">
  <strong>CVE-2026-114938 — OpenJDK AVX-512 Base64 Heap Overflow PoC & Detection Toolkit</strong>
</p>
<p align="center">
  <a href="https://github.com/ikow/java4shell-poc/stargazers"><img src="https://img.shields.io/github/stars/ikow/java4shell-poc?style=flat-square" alt="Stars"></a>
  <img src="https://img.shields.io/badge/CVSS-9.2%20Critical-red?style=flat-square" alt="CVSS 9.2">
  <img src="https://img.shields.io/badge/JDK-17.0.6%E2%80%9327-orange?style=flat-square" alt="Affected Versions">
  <img src="https://img.shields.io/badge/Fixed-17.0.21.1%20%7C%2021.0.13.1%20%7C%2025.0.5.1%20%7C%2027.0.1.1-green?style=flat-square" alt="Fixed Versions">
  <img src="https://img.shields.io/badge/CPU-AVX--512%20VBMI-blue?style=flat-square" alt="Hardware">
</p>

<p align="center">
  <a href="#poc">PoC</a> · <a href="#scanner">Scanner</a> · <a href="#detection-rules">Detection</a> · <a href="#quick-start">Lab</a> · <a href="docs/ANALYSIS.md">Analysis</a> · <a href="https://calif.io/java4shell/">Disclosure</a>
</p>

---

Memory corruption in OpenJDK HotSpot's AVX-512 VBMI Base64 decoding intrinsic. A malformed 65-byte input (`"A"×64 + "="`) causes an integer underflow in the output mask calculation, producing a full 64-bit write mask. The resulting `VMOVDQU8` writes **62 bytes past the end of the heap buffer**.

Discovered by [Quang Luong](https://calif.io/java4shell/) of Calif.io using AI-assisted vulnerability research. Pre-auth RCE demonstrated against Keycloak, Jira, Confluence, Jenkins, Artifactory, and PingFederate.

**Author:** [Qi Deng](https://github.com/ikow) &nbsp;|&nbsp; **Disclosure:** [calif.io/java4shell](https://calif.io/java4shell/) &nbsp;|&nbsp; **Date:** 2026-11-17

## CVE Details

| Field | Value |
|-------|-------|
| **CVE** | CVE-2026-114938 |
| **CVSS v4.0 / v3.1** | 9.2 Critical / 8.1 High |
| **CWE** | CWE-191 (Integer Underflow) → CWE-122 (Heap Buffer Overflow) |
| **Component** | `hotspot/compiler` — `StubGenerator::generate_base64_decodeBlock()` |
| **Fix** | [JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b) — 3-line `length < 4` guard |

## Affected Versions

| JDK | Vulnerable | Fixed |
|-----|-----------|-------|
| 17 | 17.0.6 – 17.0.21 | 17.0.21.1 |
| 21 | All before 21.0.13.1 | 21.0.13.1 |
| 25 | All before 25.0.5.1 | 25.0.5.1 |
| 27 | All before 27.0.1.1 | 27.0.1.1 |

**Hardware requirement:** x86-64 with AVX-512 VBMI — Intel Ice Lake+ (Xeon 3rd Gen+) or AMD Zen 4+ (EPYC Genoa / Ryzen 7000+). **ARM64 is NOT affected.**

All OpenJDK-based distributions are vulnerable: Oracle Java SE, Temurin, Corretto, Zulu, Liberica, SapMachine, Red Hat OpenJDK, GraalVM.

## Impact

**Pre-auth RCE (default configs):**
- Keycloak · Atlassian Jira · Atlassian Confluence · JFrog Artifactory · Jenkins · PingFederate

**Post-auth RCE:**
- Apache Kafka Broker · Apache Solr · Elasticsearch · Gerrit · Spinnaker

**Attack surface:** Any Java application that decodes untrusted Base64 via `java.util.Base64` — HTTP Basic Auth, JWT tokens, SAML assertions, file uploads, API payloads, TLS (client-side).

## Root Cause

```
Input: "A"×64 + "="  (65 bytes)
Buffer: 50 bytes allocated

Tail handler:
  output_size = (1 / 4) * 3 = 0
  output_size -= 1            = -1  (UNDERFLOW)
  bzhiq(-1, 0xFF)             = 0xFFFFFFFFFFFFFFFF  (all bits set)
  evmovdqub [dst+48], mask, zmm → writes ALL 64 bytes
                                → 62 bytes PAST the buffer end
```

The `BZHI` instruction treats the index as `unsigned [7:0]`. When `output_size = -1`, the low byte is `0xFF = 255`, which exceeds the 64-bit register width, so no bits are cleared — full mask → full 64-byte write.

## PoC

The trigger proves the memory corruption is real. It uses a 4096-byte destination array so the overflow stays contained (safe to run).

```bash
cd poc/
javac Base64Trigger.java
java Base64Trigger
```

**Vulnerable output:**
```
runtime=21.0.13+9-LTS
vm=OpenJDK 64-Bit Server VM
rejected=true changed=62 first=50 last=111
REPRODUCED
```

**Verified on:** GCE `c3-standard-4` (Intel Xeon Platinum 8481C, Sapphire Rapids) + Temurin 21.0.13+9-LTS.

### Trigger Strings

| JDK Version | Input |
|-------------|-------|
| 21, 25, 27 | `"A" × 64 + "="` (65 bytes) |
| 17 (17.0.6+) | `"A" × 128 + "="` (129 bytes) |

### Full Verification

```bash
chmod +x poc/verify_corruption.sh
./poc/verify_corruption.sh
```

Tests the trigger, then confirms both mitigation flags (`-XX:-UseBASE64Intrinsics` and `-XX:UseAVX=2`) prevent the corruption.

## Scanner

### Host Scanner

Checks all Java installations on the local machine for vulnerability:

```bash
chmod +x scanner/java4shell_scan.sh
./scanner/java4shell_scan.sh
```

Verifies: CPU flags (AVX-512 VBMI) → Java version → running JVM mitigation flags.

### Network Scanner

Probes remote hosts for vulnerable Java versions via HTTP headers, TLS certs, and service banners:

```bash
# Single host
python3 scanner/java4shell_scan.py --host app.example.com

# CIDR range
python3 scanner/java4shell_scan.py --cidr 10.0.0.0/24 --ports 8080,8443

# From file
python3 scanner/java4shell_scan.py --targets hosts.txt --threads 50

# JSON output
python3 scanner/java4shell_scan.py --host app.example.com --json
```

## Detection Rules

Pre-built IDS / WAF / SIEM rules in [`detection/`](detection/):

| File | Format | Signatures |
|------|--------|-----------|
| `java4shell.rules` | Suricata / Snort | 6 rules — malformed Base64, trigger patterns, warm-up, crash indicators |
| `java4shell.yaml` | Sigma | 5 rules — web logs, JVM crashes, GC SIGSEGV, exception floods |
| `modsecurity.conf` | ModSecurity v2/v3 | 6 rules — drop-in for Apache/Nginx |

**Key detection signals:**
- Malformed Base64 padding in `Authorization: Basic` headers (length % 4 ≠ 0)
- Exact trigger patterns (`"A"×64 + "="` or `"A"×128 + "="`)
- High-frequency Base64 auth requests from single source (JIT warm-up phase)
- `IllegalArgumentException` from Base64 decoder (thrown after corruption)
- `hs_err_pid*.log` crash files with `SIGSEGV` in G1 GC / `StubRoutines`

## Quick Start

```bash
git clone https://github.com/ikow/java4shell-poc.git && cd java4shell-poc

# Start the lab (requires x86-64 Docker host with AVX-512 VBMI)
cd lab && chmod +x setup.sh && ./setup.sh

# Enter the container and run the PoC
docker compose exec poc bash
java Base64Trigger

# Or run directly (if Java is installed locally)
cd poc && javac Base64Trigger.java && java Base64Trigger

# Scan your hosts
./scanner/java4shell_scan.sh
```

## Repository Structure

```
java4shell-poc/
├── poc/
│   ├── Base64Trigger.java           # Memory corruption trigger (CVE-2026-114938)
│   ├── verify_corruption.sh         # Full verification with mitigation tests
│   └── run.sh                       # Quick compile-and-run helper
├── scanner/
│   ├── java4shell_scan.sh           # Host scanner (JDK + CPU check)
│   └── java4shell_scan.py           # Network scanner (HTTP/TLS/banner probing)
├── detection/
│   ├── java4shell.rules             # Suricata / Snort IDS rules
│   ├── java4shell.yaml              # Sigma SIEM detection rules
│   └── modsecurity.conf             # ModSecurity WAF rules
├── lab/
│   ├── Dockerfile                   # Vulnerable Java environment
│   ├── docker-compose.yml           # Lab with optional Keycloak
│   └── setup.sh                     # One-click lab setup
├── docs/
│   ├── ANALYSIS.md                  # Full technical analysis
│   └── cover.svg                    # Cover art
├── .gitignore
├── .gitattributes
├── LICENSE
└── README.md
```

## The Patch

[JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b) — committed 2026-11-16, titled "Base64 optimization improvements":

```diff
 __ BIND(L_finalBit);
 // Now have 1 to 63 bytes left to decode
+// A padded Base64 tail shorter than one complete block is handled by Java.
+__ cmpl(length, 4);
+__ jcc(Assembler::less, L_bruteForce);
```

Routes tails shorter than 4 bytes to the safe scalar decoder before the BZHI underflow can occur.

## Mitigation

**Upgrade Java immediately** to 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1.

```bash
# Interim — disable Base64 intrinsic (recommended, narrow impact)
java -XX:-UseBASE64Intrinsics MyApp

# Interim — disable AVX-512 entirely (x86-64 only — do NOT use on ARM)
java -XX:UseAVX=2 MyApp

# Fleet-wide via environment variable
export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
```

After upgrading: restart all JVM processes, rebuild container images.

## Comparison

| | Heartbleed | Log4Shell | Spring4Shell | **Java4Shell** |
|---|---|---|---|---|
| **Bug class** | Over-read | Injection | Class manipulation | Integer underflow → heap overflow |
| **Trigger** | TLS heartbeat | `${jndi:…}` | HTTP params | `"A"×64 + "="` |
| **Exploitation** | Trivial | Trivial | Moderate | Complex (heap feng shui) |
| **Universal** | Yes | Yes | Partial | No (per-target + HW-gated) |
| **CVSS** | 7.5 | 10.0 | 9.8 | 9.2 |

## References

- [Calif.io disclosure](https://calif.io/java4shell/) — Original research by Quang Luong
- [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- [Oracle CPU](https://www.oracle.com/security-alerts/cspunov2026.html)
- [Fix commit 5177a70b385c](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b)
- [Datadog Security Labs analysis](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/)
- [JFrog analysis](https://research.jfrog.com/post/java4shell-vulnerability/)
- [Upwind / java4shell.net](https://java4shell.net/)
