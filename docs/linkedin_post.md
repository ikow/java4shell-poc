I built the full exploit chain for Java4Shell (CVE-2026-114938) and tested it against Keycloak, Jenkins, and Elasticsearch in default configs.

All three accepted the payload. All three had their heap corrupted. Pre-auth. No credentials needed.

Here's what makes this one different from Log4Shell:

The trigger is 65 bytes. Just "A" repeated 64 times followed by "=", sent as an HTTP Basic Auth header. It hits an integer underflow in OpenJDK's hand-written AVX-512 assembly and writes 62 bytes past the end of the heap buffer.

The scary part? Java is supposed to be memory safe. Every array access is bounds checked. But the HotSpot JVM replaces Base64 decoding with raw x86-64 assembly for performance on AVX-512 CPUs. That assembly has no bounds checking. The Java safety guarantees don't apply below the JVM abstraction layer.

What I found building the exploit:

The overflow fires reliably. That part is deterministic. But exploiting it requires heap feng shui borrowed from browser exploitation. You need to spray the heap, control allocation order via TCP timing, then read heap memory through corrupted array bounds. Each target (Keycloak, Jenkins, Elasticsearch) needs a different grooming profile because they allocate different objects during auth processing.

I wrote target specific exploit chains with heap grooming strategies for each:

🔸 Keycloak: client_id size variation controls TLAB allocation
🔸 Jenkins: multi endpoint rotation with API tree depth spray
🔸 Spring Boot: Tomcat ByteChunk header size sweep
🔸 Elasticsearch: _bulk and _search allocation pattern grooming

The hardware gate is real but temporary. AVX-512 VBMI is in every new Intel Xeon (Ice Lake+) and AMD EPYC/Ryzen (Zen 4+). That's most of GCP c3/c4, AWS m7i/c7i, and Azure Dv5/Ev5.

This affects JDK 17.0.6 through 27. The fix is 3 lines of assembly. Update now or set -XX:-UseBASE64Intrinsics on every JVM.

Full writeup with the exploit chain, detection rules, and scanner:
https://qideng.substack.com/p/java4shell-from-avx-512-integer-underflow

PoC, exploits, and detection toolkit:
https://github.com/ikow/java4shell-poc

#java4shell #cybersecurity #vulnerability #openjdk #infosec #java #cve #securityresearch
