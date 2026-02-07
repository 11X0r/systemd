# FuzzForge AI Comprehensive Security Task List for systemd

> Generated against systemd repository using [FuzzForge AI v0.7.3](https://github.com/FuzzingLabs/fuzzforge_ai)
> 84 tasks across 12 categories leveraging all FuzzForge workflow types

---

## Quick Reference

| Category | Tasks | FuzzForge Workflow | Priority |
|----------|-------|--------------------|----------|
| A. OSS-Fuzz Campaigns (Existing Targets) | 15 | `ossfuzz_campaign` | P0 |
| B. New Fuzz Harness Targets | 16 | `ossfuzz_campaign` + manual | P0 |
| C. Protocol Fuzzing (Network Attack Surface) | 10 | `ossfuzz_campaign` | P0 |
| D. Configuration Parser Fuzzing | 8 | `ossfuzz_campaign` | P1 |
| E. Serialization/Deserialization Fuzzing | 6 | `ossfuzz_campaign` | P1 |
| F. Static Security Assessment | 5 | `security_assessment` | P1 |
| G. LLM-Powered Code Analysis | 8 | `llm_analysis` | P1 |
| H. Secret Detection | 4 | `llm_secret_detection` / `gitleaks_detection` | P2 |
| I. Sanitizer Matrix Expansion | 4 | `ossfuzz_campaign` | P1 |
| J. Corpus Engineering | 4 | manual + `ossfuzz_campaign` | P2 |
| K. Differential / Cross-Validation | 2 | `ossfuzz_campaign` | P2 |
| L. CI/CD Integration | 2 | `workflow run --fail-on` | P2 |

---

## A. OSS-Fuzz Campaign — Existing Targets (15 tasks)

systemd is an existing OSS-Fuzz project. These tasks exercise the 49 existing fuzz
harnesses through FuzzForge's orchestration, applying different engines, sanitizers,
and durations systematically.

### A1. DNS Packet Parsing — Extended Campaign
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=8 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif dns-packet-asan.sarif
```
**Target:** `fuzz-dns-packet` — Parses raw DNS wire-format packets
**File:** `src/fuzz/fuzz-dns-packet.c` → `dns_packet_new()` / `dns_packet_append_blob()`
**Rationale:** DNS is the #1 network attack surface in systemd-resolved. 8-hour campaign
discovers deep state-machine bugs that short runs miss.

### A2. DNS Resource Record — Memory Sanitizer
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=libfuzzer override_sanitizer=memory \
  --wait --export-sarif dns-rr-msan.sarif
```
**Target:** `fuzz-resource-record` — Tests DNS RR type parsing (A, AAAA, MX, SRV, etc.)
**File:** `src/fuzz/fuzz-resource-record.c`
**Rationale:** MSAN catches uninitialized memory reads in RR deserialization that ASAN misses.

### A3. DHCP Client — AFL++ Engine
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=6 \
  override_engine=afl override_sanitizer=address \
  --wait --export-sarif dhcp-client-afl.sarif
```
**Target:** `fuzz-dhcp-client` — DHCP packet processing from network
**File:** `src/libsystemd-network/fuzz-dhcp-client.c`
**Rationale:** AFL++ finds different bug classes than libFuzzer due to different mutation
strategies. DHCP packets from untrusted networks are a critical attack vector.

### A4. DHCPv6 Client — Extended + UBSAN
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=6 \
  override_engine=libfuzzer override_sanitizer=undefined \
  --wait --export-sarif dhcp6-ubsan.sarif
```
**Target:** `fuzz-dhcp6-client` — DHCPv6 option parsing
**File:** `src/libsystemd-network/fuzz-dhcp6-client.c`
**Rationale:** DHCPv6 has complex option nesting (IA_NA/IA_PD with sub-options). UBSAN
catches integer overflow and shift UB in option length calculations.

### A5. D-Bus Message Parsing — Honggfuzz Engine
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=honggfuzz override_sanitizer=address \
  --wait --export-sarif bus-message-honggfuzz.sarif
```
**Target:** `fuzz-bus-message` — sd-bus binary protocol parsing
**File:** `src/libsystemd/sd-bus/fuzz-bus-message.c`
**Rationale:** Honggfuzz's hardware-assisted feedback (Intel PT) finds coverage paths that
pure software instrumentation misses. D-Bus IPC is reachable from unprivileged processes.

### A6. Journal Native Protocol — All Sanitizers
```bash
for san in address memory undefined; do
  ff workflow run ossfuzz_campaign . \
    project_name=systemd campaign_duration_hours=2 \
    override_sanitizer=$san \
    --wait --export-sarif journald-native-${san}.sarif
done
```
**Targets:** `fuzz-journald-native`, `fuzz-journald-native-fd`
**Files:** `src/journal/fuzz-journald-native.c`, `fuzz-journald-native-fd.c`
**Rationale:** journald accepts data from any process via `/run/systemd/journal/socket`.
Testing all sanitizers catches different bug classes in this always-exposed surface.

### A7. Journal Syslog Parsing
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif journald-syslog.sarif
```
**Target:** `fuzz-journald-syslog` — Parses legacy syslog format
**File:** `src/journal/fuzz-journald-syslog.c`
**Rationale:** Syslog parsing handles arbitrary strings from network-facing daemons with
complex timestamp, priority, and structured data parsing.

### A8. LLDP Frame Parsing
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=afl override_sanitizer=address \
  --wait --export-sarif lldp-afl.sarif
```
**Target:** `fuzz-lldp-rx` — LLDP Ethernet frame parsing
**File:** `src/libsystemd-network/fuzz-lldp-rx.c`
**Rationale:** LLDP frames come directly from the network layer (L2), attacker-controlled
from adjacent network. AFL excels at binary protocol fuzzing.

### A9. NDisc Router Solicitation
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif ndisc-rs.sarif
```
**Target:** `fuzz-ndisc-rs` — IPv6 Router Advertisement/Solicitation parsing
**File:** `src/libsystemd-network/fuzz-ndisc-rs.c`
**Rationale:** Router advertisements control IPv6 address assignment and routing. Malicious
RAs can compromise network configuration of every host on a LAN segment.

### A10. Unit File Parsing — Memory Sanitizer
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=6 \
  override_engine=libfuzzer override_sanitizer=memory \
  --wait --export-sarif unit-file-msan.sarif
```
**Target:** `fuzz-unit-file` — systemd unit file (`.service`, `.socket`, etc.) parsing
**File:** `src/core/fuzz-unit-file.c` → `load-fragment.c` parser
**Rationale:** Unit files have 200+ directives parsed through gperf hash tables. MSAN
catches info leaks where uninitialized config values propagate to runtime decisions.

### A11. JSON Parser — Extended Duration
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=12 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif json-extended.sarif
```
**Target:** `fuzz-json` — sd-json parser (used by Varlink, user records, credentials)
**File:** `src/fuzz/fuzz-json.c`
**Rationale:** JSON parsing is foundational — used by varlink IPC, homed user records,
credential system. 12-hour campaign reaches deep nesting/recursion paths.

### A12. Varlink Protocol Fuzzing
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=6 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif varlink.sarif
```
**Target:** `fuzz-varlink` — Varlink JSON-RPC-like IPC protocol
**File:** `src/fuzz/fuzz-varlink.c`
**Rationale:** Varlink is replacing D-Bus in many systemd interfaces. It's exposed as
an IPC socket accessible to unprivileged users.

### A13. udev Rules Parsing — AFL++
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=afl override_sanitizer=address \
  --wait --export-sarif udev-rules-afl.sarif
```
**Target:** `fuzz-udev-rules` — udev rule file parsing
**File:** `src/udev/fuzz-udev-rules.c`
**Rationale:** udev rules are text-based with complex pattern matching. AFL's
deterministic mutations are effective at finding edge cases in grammar parsing.

### A14. Boot Configuration Data (BCD) — Extended
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif bcd.sarif
```
**Target:** `fuzz-bcd` — Windows BCD registry hive parsing
**File:** `src/boot/efi/fuzz-bcd.c`
**Rationale:** BCD parsing handles potentially attacker-controlled data on dual-boot
systems via the EFI System Partition.

### A15. nspawn OCI Spec Parsing
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=4 \
  override_engine=libfuzzer override_sanitizer=address \
  --wait --export-sarif nspawn-oci.sarif
```
**Target:** `fuzz-nspawn-oci` — OCI container specification JSON parsing
**File:** `src/nspawn/fuzz-nspawn-oci.c`
**Rationale:** OCI specs from container registries are untrusted input that controls
namespace/cgroup/mount configuration — a container escape vector.

---

## B. New Fuzz Harness Targets — Gap Coverage (16 tasks)

These are high-value parsing functions that currently lack fuzz coverage.
Each task requires writing a new `LLVMFuzzerTestOneInput` harness.

### B1. DNSSEC Signature Verification
**File:** `src/resolve/resolved-dns-dnssec.c`
**Functions:** `dnssec_verify_rrset()`, `dnssec_verify_dnskey_by_ds()`, `dnssec_nsec3_hash()`
**Harness location:** `src/fuzz/fuzz-dnssec-verify.c`
**Input format:** Crafted DNS packets with RRSIG/DNSKEY/DS records
**Priority:** CRITICAL — DNSSEC validation bugs can poison DNS for entire networks

### B2. User Record JSON Deserialization
**File:** `src/shared/user-record.c`
**Functions:** `user_record_load()`, JSON dispatch for identity fields
**Harness location:** `src/fuzz/fuzz-user-record.c`
**Input format:** JSON blobs representing user identity records
**Priority:** CRITICAL — User records control authentication, home directories, credentials

### B3. Group Record JSON Deserialization
**File:** `src/shared/group-record.c`
**Functions:** `group_record_load()`
**Harness location:** `src/fuzz/fuzz-group-record.c`
**Input format:** JSON blobs representing group records
**Priority:** HIGH — Group membership controls authorization

### B4. Credential Encryption/Decryption
**File:** `src/shared/creds-util.c`
**Functions:** `decrypt_credential_and_warn()`, `ipc_decrypt_credential()`
**Harness location:** `src/fuzz/fuzz-credential.c`
**Input format:** Raw credential blobs (header + encrypted payload)
**Priority:** CRITICAL — Credential system handles secrets for services

### B5. Disk Image Dissection (GPT Parsing)
**File:** `src/shared/dissect-image.c`
**Functions:** `dissect_image_file()`, `dissected_image_decrypt()`
**Harness location:** `src/fuzz/fuzz-dissect-image.c`
**Input format:** Raw disk image bytes (GPT header + partition entries)
**Priority:** HIGH — Portable services and systemd-homed parse untrusted images

### B6. Configuration File Generic Parser
**File:** `src/shared/conf-parser.c`
**Functions:** `config_parse()`, `config_parse_many()`
**Harness location:** `src/fuzz/fuzz-conf-parser.c`
**Input format:** INI-style config files with section headers and key=value pairs
**Priority:** HIGH — Backbone parser used by journald, resolved, networkd, logind, etc.

### B7. Seccomp Syscall Filter Parsing
**File:** `src/shared/seccomp-util.c`
**Functions:** `seccomp_parse_syscall_filter()`, `parse_syscall_and_errno()`
**Harness location:** `src/fuzz/fuzz-seccomp-parse.c`
**Input format:** Syscall filter specification strings
**Priority:** HIGH — Incorrect parsing can weaken sandbox security

### B8. C String Escape/Unescape
**File:** `src/basic/escape.c`
**Functions:** `cunescape_length()`, `cunescape_one()`, `shell_escape()`, `shell_maybe_quote()`
**Harness location:** `src/fuzz/fuzz-escape.c`
**Input format:** Raw byte sequences with escape characters
**Priority:** MEDIUM — Used throughout for handling user-supplied strings

### B9. Hardware Address Parsing
**File:** `src/basic/ether-addr-util.c`
**Functions:** `parse_hw_addr()`, `parse_hw_addr_full()`, `parse_ether_addr()`
**Harness location:** `src/fuzz/fuzz-hw-addr.c`
**Input format:** MAC address strings in various formats
**Priority:** MEDIUM — Used in networkd for interface matching

### B10. Socket Address Parsing
**File:** `src/basic/socket-util.c`
**Functions:** `socket_address_parse()`, `socket_address_parse_unix()`, `socket_address_parse_vsock()`
**Harness location:** `src/fuzz/fuzz-socket-addr.c`
**Input format:** Socket address specification strings (IPv4, IPv6, Unix, vsock)
**Priority:** MEDIUM — Socket units use these parsers for user-specified addresses

### B11. Device Database Deserialization
**File:** `src/libsystemd/sd-device/device-private.c`
**Functions:** `device_read_db_internal_filename()`, `device_read_uevent_file()`
**Harness location:** `src/fuzz/fuzz-device-db.c`
**Input format:** udev database files (key=value lines)
**Priority:** MEDIUM — udev DB can be corrupted or manipulated

### B12. Netlink Message Parsing
**File:** `src/libsystemd/sd-netlink/netlink-message.c`
**Functions:** `socket_read_message()`, netlink attribute parsing
**Harness location:** `src/fuzz/fuzz-netlink-message.c`
**Input format:** Raw netlink message bytes with nested attributes
**Priority:** MEDIUM — Netlink messages from kernel, but format bugs affect stability

### B13. QCOW2 Image Format Parsing
**File:** `src/import/qcow2-util.c`
**Functions:** QCOW2 header and L1/L2 table parsing
**Harness location:** `src/fuzz/fuzz-qcow2.c`
**Input format:** QCOW2 image headers
**Priority:** HIGH — systemd-importd processes untrusted VM images

### B14. tmpfiles.d Configuration Parsing
**File:** `src/tmpfiles/tmpfiles.c`
**Functions:** tmpfiles.d line parsing (type, path, mode, ownership, age)
**Harness location:** `src/fuzz/fuzz-tmpfiles.c`
**Input format:** tmpfiles.d configuration lines
**Priority:** MEDIUM — tmpfiles runs at boot with root privileges

### B15. sysusers.d Configuration Parsing
**File:** `src/sysusers/sysusers.c`
**Functions:** sysusers.d line parsing (user/group creation directives)
**Harness location:** `src/fuzz/fuzz-sysusers.c`
**Input format:** sysusers.d configuration lines
**Priority:** MEDIUM — sysusers creates users/groups at install time with root

### B16. Recovery Key Normalization
**File:** `src/shared/recovery-key.c`
**Functions:** `normalize_recovery_key()`
**Harness location:** `src/fuzz/fuzz-recovery-key.c`
**Input format:** Recovery key strings with dashes and varied encoding
**Priority:** MEDIUM — Used in systemd-homed for disk encryption recovery

---

## C. Protocol Fuzzing — Network Attack Surface (10 tasks)

These target protocol implementations reachable from the network.

### C1. DHCP Server Relay — Spoofed Agent
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=6 \
  override_engine=afl override_sanitizer=address \
  --wait --export-sarif dhcp-relay.sarif
```
**Target:** `fuzz-dhcp-server-relay` — DHCP relay agent packet handling
**File:** `src/libsystemd-network/fuzz-dhcp-server-relay.c`
**Rationale:** Relay packets traverse network boundaries; a bug here is remotely exploitable.

### C2. DHCPv6 Domain Name List Parsing
**Function:** `dhcp6_option_parse_domainname_list()` in `src/libsystemd-network/dhcp6-option.c`
**Attack vector:** Malicious DHCPv6 server sends crafted domain search list
**Coverage needed:** DNS name compression pointers, label length bounds, NUL termination

### C3. DHCP Lease Search Domain Parsing
**Function:** `dhcp_lease_parse_search_domains()` in `src/libsystemd-network/dhcp-lease-internal.c`
**Attack vector:** Rogue DHCP server on local network
**Coverage needed:** Domain name encoding with length-prefixed labels

### C4. DNR Service Parameters
**Function:** `dnr_parse_svc_params()` in `src/libsystemd-network/dns-resolver-internal.c`
**Attack vector:** DNS-over-HTTPS/TLS resolver discovery parameters
**Coverage needed:** Service parameter TLV parsing

### C5. NDisc Neighbor Advertisement Parsing
**Function:** `ndisc_neighbor_parse()` in `src/libsystemd-network/ndisc-neighbor-internal.c`
**Attack vector:** Spoofed IPv6 neighbor advertisements on LAN
**Coverage needed:** Option TLV parsing, target link-layer address

### C6. NDisc Router Redirect Parsing
**Function:** `ndisc_redirect_parse()` in `src/libsystemd-network/ndisc-redirect-internal.c`
**Attack vector:** Malicious router redirect messages
**Coverage needed:** Redirect header + embedded original packet parsing

### C7. NDisc Router Advertisement Full Parse
**Function:** `ndisc_router_parse()` in `src/libsystemd-network/ndisc-router-internal.c`
**Attack vector:** Rogue router advertisements controlling IPv6 configuration
**Coverage needed:** Prefix info, route info, RDNSS, DNSSL options

### C8. mDNS Service Discovery Answer Processing
**Function:** `mdns_manage_services_answer()` in `src/resolve/resolved-dns-browse-services.c`
**Attack vector:** Malicious mDNS responder on local network
**Coverage needed:** Service instance name parsing, TXT record handling

### C9. /etc/hosts Extended Parsing
**Target:** `fuzz-etc-hosts` — Already exists but needs extended corpus
**Function:** `etc_hosts_parse()` in `src/resolve/resolved-etc-hosts.c`
**Enhancement:** Generate corpus from real-world /etc/hosts files (containers, k8s)

### C10. Journal Remote HTTP Parsing
**Target:** `fuzz-journal-remote` — Journal-over-HTTP protocol
**File:** `src/journal-remote/fuzz-journal-remote.c`
**Enhancement:** Extended campaign with malformed HTTP chunked encoding + journal export format

---

## D. Configuration Parser Fuzzing (8 tasks)

### D1. journald.conf Parsing
**Parser:** `src/journal/journald-gperf.gperf` → `conf-parser.c`
**Input:** `[Journal]` section with `Storage=`, `Compress=`, `RateLimitIntervalSec=`, etc.
**Risk:** journald runs as root, config affects security logging

### D2. resolved.conf Parsing
**Parser:** `src/resolve/resolved-gperf.gperf`
**Input:** `[Resolve]` section with `DNS=`, `DNSSEC=`, `DNSOverTLS=`, etc.
**Risk:** Incorrect DNS configuration can redirect all name resolution

### D3. logind.conf Parsing
**Parser:** `src/login/logind-gperf.gperf`
**Input:** `[Login]` section with `InhibitDelayMaxSec=`, `HandlePowerKey=`, etc.
**Risk:** logind manages power keys, session limits, idle actions

### D4. timesyncd.conf Parsing
**Parser:** `src/timesync/timesyncd-gperf.gperf`
**Input:** `[Time]` section with `NTP=`, `FallbackNTP=`, `PollIntervalMinSec=`, etc.
**Risk:** Incorrect NTP config affects time-dependent security (TLS certs, Kerberos)

### D5. coredump.conf Parsing
**Parser:** `src/coredump/coredump-gperf.gperf`
**Input:** `[Coredump]` section with `Storage=`, `ProcessSizeMax=`, etc.
**Risk:** Coredumps contain sensitive memory; misconfiguration leaks secrets

### D6. nspawn Settings Parsing (Extended)
**Target:** `fuzz-nspawn-settings` (exists, needs extended campaign)
**File:** `src/nspawn/nspawn-gperf.gperf`
**Risk:** nspawn settings control container isolation boundaries

### D7. .link File Parsing (Extended)
**Target:** `fuzz-link-parser` (exists, needs extended campaign)
**File:** `src/udev/net/link-config-gperf.gperf`
**Risk:** Link configuration affects network interface naming and properties

### D8. system.conf / user.conf Manager Parsing
**Parser:** `src/core/system.conf` parsed via conf-parser
**Input:** `[Manager]` section with `DefaultLimitNOFILE=`, `DefaultEnvironment=`, etc.
**Risk:** Manager defaults affect all service execution security

---

## E. Serialization/Deserialization Fuzzing (6 tasks)

### E1. Manager State Serialization
**Target:** `fuzz-manager-serialize` (exists)
**Enhancement:** Extended 8-hour campaign with structure-aware mutations
**File:** `src/core/fuzz-manager-serialize.c`
**Risk:** Manager reload deserializes state; corruption can crash PID 1

### E2. Execute Context Serialization
**Target:** `fuzz-execute-serialize` (exists)
**Enhancement:** MSAN campaign to catch uninitialized memory in deserialized exec params
**File:** `src/core/fuzz-execute-serialize.c`
**Risk:** ExecContext controls capabilities, namespaces, security settings

### E3. Varlink IDL (Interface Definition Language)
**Target:** `fuzz-varlink-idl` (exists)
**Enhancement:** AFL++ engine for grammar-based IDL parsing
**File:** `src/fuzz/fuzz-varlink-idl.c`
**Risk:** IDL parsing controls API surface validation

### E4. Logind Session State Deserialization
**Function:** `session_load()` in `src/login/logind-session.c`
**New harness needed:** Parse serialized session state
**Risk:** Session state controls user session properties and access control

### E5. Logind Seat State Deserialization
**Function:** `seat_load()` in `src/login/logind-seat.c`
**New harness needed:** Parse serialized seat state
**Risk:** Seat assignment affects device access permissions

### E6. Logind Inhibitor State Deserialization
**Function:** `inhibitor_load()` in `src/login/logind-inhibit.c`
**New harness needed:** Parse serialized inhibitor state
**Risk:** Inhibitors control power management (prevent sleep/shutdown)

---

## F. Static Security Assessment (5 tasks)

Using FuzzForge's `security_assessment` workflow for pattern-based static analysis.

### F1. Shared Library — Secret/Credential Patterns
```bash
ff workflow run security_assessment src/shared/ \
  --param-file params/security-shared.json \
  --wait --export-sarif security-shared.sarif
```
**Scope:** `src/shared/` (credential handling, crypto, authentication)
**Checks:** Hardcoded secrets, dangerous function usage, crypto patterns

### F2. Core Execution — Privilege Escalation Patterns
```bash
ff workflow run security_assessment src/core/ \
  --param-file params/security-core.json \
  --wait --export-sarif security-core.sarif
```
**Scope:** `src/core/` (PID 1 code, execution context, namespace setup)
**Checks:** setuid/setgid patterns, capability handling, namespace escapes

### F3. Network Stack — Injection Patterns
```bash
ff workflow run security_assessment src/network/ \
  --param-file params/security-network.json \
  --wait --export-sarif security-network.sarif
```
**Scope:** `src/network/`, `src/libsystemd-network/`, `src/resolve/`
**Checks:** Buffer overflow patterns, integer overflow in packet parsing

### F4. Login/Home — Authentication Patterns
```bash
ff workflow run security_assessment src/login/ \
  --param-file params/security-login.json \
  --wait --export-sarif security-login.sarif
```
**Scope:** `src/login/`, `src/home/`
**Checks:** Authentication bypass, TOCTOU, credential handling

### F5. Full Codebase — Dangerous C Functions
```bash
ff workflow run security_assessment . \
  --param-file params/security-full.json \
  --wait --export-sarif security-full.sarif
```
**Scope:** Entire C codebase
**Checks:** `gets()`, `sprintf()`, `strcpy()`, `strcat()` (banned functions),
format string vulnerabilities, missing bounds checks

---

## G. LLM-Powered Code Analysis (8 tasks)

Using FuzzForge's `llm_analysis` workflow for AI-driven vulnerability detection.

### G1. DNS Protocol Implementation Review
```bash
ff workflow run llm_analysis src/shared/dns-packet.c \
  llm_model=gpt-5-mini max_files=5 \
  --wait --export-sarif llm-dns.sarif
```
**Scope:** `dns-packet.c`, `dns-domain.c`, `dns-rr.c`, `dns-question.c`, `dns-answer.c`
**Analysis:** Buffer management, DNS compression pointer loops, label length validation

### G2. DHCP/DHCPv6 Protocol Review
```bash
ff workflow run llm_analysis src/libsystemd-network/ \
  llm_model=gpt-5-mini max_files=10 \
  --wait --export-sarif llm-dhcp.sarif
```
**Scope:** `dhcp-packet.c`, `dhcp-option.c`, `dhcp6-option.c`, `sd-dhcp-client.c`
**Analysis:** Option length validation, buffer overflows, integer wraparound

### G3. D-Bus Message Marshalling Review
```bash
ff workflow run llm_analysis src/libsystemd/sd-bus/ \
  llm_model=gpt-5-mini max_files=8 \
  --wait --export-sarif llm-dbus.sarif
```
**Scope:** `bus-message.c`, `bus-signature.c`, `bus-type.c`, `bus-match.c`
**Analysis:** Type confusion, recursive container depth, alignment bugs

### G4. Journal File Format Security
```bash
ff workflow run llm_analysis src/libsystemd/sd-journal/ \
  llm_model=gpt-5-mini max_files=8 \
  --wait --export-sarif llm-journal.sarif
```
**Scope:** `journal-file.c`, `journal-verify.c`, `journal-authenticate.c`
**Analysis:** HMAC verification, hash chain integrity, mmap safety

### G5. Execution Context & Namespace Review
```bash
ff workflow run llm_analysis src/core/ \
  llm_model=gpt-5-mini max_files=8 \
  --wait --export-sarif llm-exec.sarif
```
**Scope:** `execute.c`, `namespace.c`, `cgroup.c`, `execute-serialize.c`
**Analysis:** Privilege drop ordering, namespace escape, resource limit bypass

### G6. Credential System Review
```bash
ff workflow run llm_analysis src/shared/ \
  llm_model=gpt-5-mini max_files=5 file_patterns=*.c \
  --wait --export-sarif llm-creds.sarif
```
**Scope:** `creds-util.c`, `recovery-key.c`, `machine-credential.c`
**Analysis:** Crypto misuse, timing side channels, key material handling

### G7. Image Dissection & Mount Review
```bash
ff workflow run llm_analysis src/shared/ \
  llm_model=gpt-5-mini max_files=5 \
  --wait --export-sarif llm-image.sarif
```
**Scope:** `dissect-image.c`, `discover-image.c`, `loop-util.c`
**Analysis:** GPT partition table parsing, TOCTOU between dissect and mount, symlink attacks

### G8. BPF Security Program Review
```bash
ff workflow run llm_analysis src/core/ \
  llm_model=gpt-5-mini max_files=6 file_patterns=bpf*.c \
  --wait --export-sarif llm-bpf.sarif
```
**Scope:** `bpf-firewall.c`, `bpf-devices.c`, `bpf-restrict-fs.c`, `bpf-restrict-ifaces.c`
**Analysis:** BPF map size limits, race conditions between attach and enforcement

---

## H. Secret Detection (4 tasks)

### H1. LLM-Powered Secret Detection — Full Repo
```bash
ff workflow run llm_secret_detection . \
  llm_model=gpt-5-mini max_files=50 \
  --wait --export-sarif secrets-llm.sarif
```
**Scope:** All source files, configs, scripts
**Goal:** Detect semantically-hidden secrets (test credentials, default passwords)

### H2. Gitleaks Pattern Detection
```bash
ff workflow run gitleaks_detection . \
  --wait --export-sarif secrets-gitleaks.sarif
```
**Scope:** Full git history
**Goal:** Find secrets accidentally committed and later removed

### H3. Test Data Credential Audit
```bash
ff workflow run llm_secret_detection test/ \
  llm_model=gpt-5-mini max_files=30 \
  file_patterns=*.c,*.h,*.conf,*.json \
  --wait --export-sarif secrets-test.sarif
```
**Scope:** Test fixtures and corpus data
**Goal:** Ensure test credentials aren't real/reusable

### H4. Configuration Template Review
```bash
ff workflow run llm_secret_detection . \
  llm_model=gpt-5-mini max_files=20 \
  file_patterns=*.conf.in,*.conf,*.xml \
  --wait --export-sarif secrets-config.sarif
```
**Scope:** Default configuration templates
**Goal:** Audit default credentials in shipped configs

---

## I. Sanitizer Matrix Expansion (4 tasks)

Run the full fuzz target suite under different sanitizer configurations.

### I1. Full Suite — AddressSanitizer (Baseline)
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=24 \
  override_sanitizer=address \
  --wait --export-sarif full-asan.sarif
```
**All 49 targets**, ASAN catches: heap/stack buffer overflow, use-after-free, double-free

### I2. Full Suite — MemorySanitizer
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=24 \
  override_sanitizer=memory \
  --wait --export-sarif full-msan.sarif
```
**All 49 targets**, MSAN catches: uninitialized memory reads (information disclosure)

### I3. Full Suite — UndefinedBehaviorSanitizer
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=24 \
  override_sanitizer=undefined \
  --wait --export-sarif full-ubsan.sarif
```
**All 49 targets**, UBSAN catches: signed overflow, shift UB, null deref, alignment

### I4. Full Suite — DataFlow Sanitizer
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=12 \
  override_sanitizer=dataflow \
  --wait --export-sarif full-dfsan.sarif
```
**All 49 targets**, DFSan: taint tracking to find data flows from input to sensitive sinks

---

## J. Corpus Engineering (4 tasks)

### J1. Seed Corpus from Real-World DNS Traffic
**Action:** Capture DNS packet corpus from public resolvers, convert to raw bytes
**Files:** `test/fuzz/fuzz-dns-packet/`
**Method:** Use `tcpdump -w` → extract DNS payloads → add to corpus directory
**Impact:** Real-world DNS packets exercise protocol paths that random bytes don't reach

### J2. Seed Corpus from systemd-networkd Configs
**Action:** Collect .network/.netdev/.link files from all major distributions
**Files:** `test/fuzz/fuzz-network-parser/`, `test/fuzz/fuzz-netdev-parser/`
**Sources:** Fedora, Ubuntu, Arch, RHEL default network configurations
**Impact:** Real configs exercise config parser paths with valid key combinations

### J3. Seed Corpus from Real Journal Files
**Action:** Extract structured journal entries from production systems
**Files:** `test/fuzz/fuzz-journald-*/`
**Method:** `journalctl --output=export` → extract native protocol format entries
**Impact:** Real journal data exercises field combinations not reached by random input

### J4. Unit File Corpus from Package Ecosystems
**Action:** Harvest all .service/.socket/.timer files from Fedora/Debian package repos
**Files:** `test/fuzz/fuzz-unit-file/`
**Scale:** 10,000+ unit files from 50,000+ packages
**Impact:** Exercises directive combinations and ordering not covered by test files

---

## K. Differential / Cross-Validation (2 tasks)

### K1. Cross-Engine Differential: libFuzzer vs AFL++ vs Honggfuzz
**Method:** Run same targets with all 3 engines, compare coverage and crash dedup
```bash
for engine in libfuzzer afl honggfuzz; do
  ff workflow run ossfuzz_campaign . \
    project_name=systemd campaign_duration_hours=4 \
    override_engine=$engine override_sanitizer=address \
    --wait --export-sarif cross-${engine}.sarif
done
```
**Goal:** Identify which engine finds unique bugs per target class

### K2. Regression Verification Against Previous Releases
**Method:** Run full fuzz suite against systemd v255 and v256 with shared corpus
**Goal:** Verify old bugs stay fixed, detect regressions in parser changes

---

## L. CI/CD Integration (2 tasks)

### L1. PR Gate — Fuzz Regression in CI
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=1 \
  override_sanitizer=address \
  --wait --fail-on error --export-sarif ci-fuzz.sarif
```
**Integration:** GitHub Actions / GitLab CI
**Trigger:** On every PR that modifies `src/fuzz/`, `src/shared/dns-*`, `src/libsystemd-network/`
**Exit code:** Non-zero if any crash found (blocks merge)

### L2. Nightly Extended Fuzz Campaign
```bash
ff workflow run ossfuzz_campaign . \
  project_name=systemd campaign_duration_hours=8 \
  --wait --fail-on error --export-sarif nightly-fuzz.sarif
```
**Integration:** Cron-triggered nightly CI job
**Reporting:** SARIF upload to GitHub Security tab
**Duration:** 8 hours covering all targets with rotating engines

---

## Execution Summary

| Metric | Count |
|--------|-------|
| Total tasks | **84** |
| Requires new harness code | 16 (Section B) + 3 (Section E) |
| Uses existing harnesses | 65 |
| OSS-Fuzz campaign tasks | 36 |
| Static analysis tasks | 5 |
| LLM analysis tasks | 8 |
| Secret detection tasks | 4 |
| Corpus engineering tasks | 4 |
| CI/CD integration tasks | 2 |
| Estimated total fuzzing hours | ~250+ hours |
| Unique C functions targeted | ~150+ |
| Attack surface categories | Network, IPC, Config, Disk, Crypto, Auth |

---

## Prerequisites

1. **Docker Compose** running with FuzzForge services:
   ```bash
   cd /path/to/fuzzforge_ai && docker compose up -d
   ```

2. **OSS-Fuzz worker** started:
   ```bash
   docker compose up -d worker-ossfuzz
   ```

3. **FuzzForge initialized** in systemd:
   ```bash
   cd /path/to/systemd && ff init --name systemd
   ```

4. **API keys** configured for LLM workflows:
   ```bash
   # In fuzzforge_ai/volumes/env/.env
   LITELLM_OPENAI_API_KEY=sk-...
   LITELLM_ANTHROPIC_API_KEY=sk-ant-...
   ```
