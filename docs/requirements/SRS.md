# Software Requirements Specification — pcapgrammar

**Version:** 1.0  
**Date:** 2026-07-25  
**Status:** Draft — ready for System Architect review

---

## 1. Purpose & Scope

### 1.1 Purpose

This document specifies the functional and non-functional requirements for **pcapgrammar**, a command-line tool that reads captured network traffic (`.pcap` files), reassembles TCP byte streams, and validates each stream against a user-supplied protocol grammar defined in YAML.

### 1.2 Scope

`pcapgrammar` is a standalone CLI binary targeting the Linux platform (primary) with no GUI. It is a C++17 portfolio project demonstrating:

- Packet-capture file parsing (libpcap / PcapPlusPlus).
- Stateful TCP stream reassembly.
- Grammar-driven protocol validation with finite-state machine (FSM) semantics.
- Clean CLI UX with machine-readable exit codes.

The tool is read-only with respect to network traffic; it never captures live traffic, modifies packets, or writes `.pcap` files.

---

## 2. Definitions

| Term | Definition |
|------|------------|
| **Flow** | A unique TCP connection identified by the 4-tuple (src-ip, dst-ip, src-port, dst-port). Directionality is tracked separately per side. |
| **Reassembled stream** | The ordered, de-duplicated byte sequence reconstructed from TCP segments for one direction of a flow. |
| **Grammar file** | A YAML file that declares a framing strategy and an FSM of allowed message transitions for a protocol. |
| **Framing strategy** | The rule used to split the reassembled byte stream into discrete messages. |
| **FSM** | Finite-State Machine; a set of named states, each specifying accepted message patterns and allowable next states. |
| **Violation** | Any message that does not match the allowed patterns for the current FSM state, or any illegal state transition. |
| **TLV** | Type-Length-Value encoding: a fixed-width type field, a fixed-width length field, followed by a variable-length value. |
| **RESP** | Redis Serialization Protocol — Redis's line-oriented text protocol. |
| **libpcap** | The portable C library for network traffic capture (`libpcap-dev` package on Ubuntu). |
| **PcapPlusPlus** | A C++ wrapper library over libpcap/WinPcap providing higher-level packet parsing. |
| **yaml-cpp** | A YAML 1.2 parser and emitter library for C++. |

---

## 3. Functional Requirements

### 3.1 Pcap File Reading

**FR-01** The tool shall accept a `.pcap` file path via the `--pcap` CLI argument and open it for reading using libpcap or PcapPlusPlus.

**FR-02** The tool shall read the pcap file packet-by-packet (streaming), never loading the entire file into memory at once.

**FR-03** The tool shall process only packets with an Ethernet + IPv4 + TCP layer stack. Packets with other layer combinations shall be silently skipped.

**FR-04** The tool shall report a usage/parse error (exit code 2) if the specified pcap file does not exist, cannot be opened, or is not a valid pcap format.

### 3.2 TCP Flow Identification

**FR-05** The tool shall identify TCP flows using the canonical 4-tuple: source IP address, destination IP address, source TCP port, and destination TCP port.

**FR-06** Each direction of a TCP connection (client→server, server→client) shall be treated as a separate reassembled byte stream.

**FR-07** When `--port <port>` is specified, the tool shall process only flows where the source port **or** destination port equals `<port>`. All other flows shall be skipped silently.

### 3.3 TCP Stream Reassembly

**FR-08** The tool shall reassemble TCP segments into a contiguous, ordered byte stream per flow direction, handling out-of-order delivery by buffering and reordering segments by TCP sequence number.

**FR-09** The tool shall discard duplicate TCP payload bytes (retransmissions) during reassembly.

**FR-10** The tool shall support reassembled stream sizes of up to 64 MB per flow direction.

**FR-11** If a reassembled flow direction exceeds 64 MB, the tool shall emit a warning and cease validating that direction; it shall not terminate for other flows.

### 3.4 Grammar File Parsing

**FR-12** The tool shall accept a grammar file path via the `--grammar` CLI argument and parse it as a YAML document using yaml-cpp.

**FR-13** The tool shall report a usage/parse error (exit code 2) if the grammar file does not exist, cannot be opened, or contains invalid YAML or an unrecognised schema.

**FR-14** A grammar file shall declare exactly one framing strategy under the top-level key `framing`. The valid strategies are:
- `line` — messages are delimited by a newline character (`\n`; `\r\n` also accepted).
- `length_prefixed` — each message is preceded by a 2-byte or 4-byte big-endian unsigned integer indicating the payload byte count. The grammar file shall additionally specify `prefix_bytes: 2` or `prefix_bytes: 4`.
- `tlv` — each message consists of a type field (1–4 bytes), a length field (1–4 bytes), and a variable-length value. The grammar file shall additionally specify `type_bytes` and `length_bytes` (each 1–4).

**FR-15** A grammar file shall declare a list of named states under the top-level key `states`. Each state shall have:
- A unique string name (`name`).
- A list of one or more message patterns (`patterns`), each containing:
  - A match criterion (`match`): either a literal byte string or a regular expression (ERE syntax).
  - A list of next-state names (`next_states`) the FSM may transition to after a successful match.

**FR-16** The grammar file shall designate exactly one state as the initial FSM state via the top-level key `initial_state`.

**FR-17** A terminal state (one that allows the stream to end without violation) shall be expressed by including the sentinel value `"__end__"` in its `next_states` list.

**FR-18** The tool shall validate the grammar file's internal consistency at load time: all state names referenced in `next_states` must be declared states; the `initial_state` must be a declared state.

### 3.5 Stream Validation

**FR-19** For each flow direction that passes the port filter (FR-07), the tool shall apply the framing strategy (FR-14) to segment the reassembled byte stream into messages.

**FR-20** For each segmented message, the tool shall attempt to match it against the patterns of the current FSM state (FR-15). Pattern matching shall use the order defined in the grammar file; the first matching pattern wins.

**FR-21** If a message matches a pattern, the FSM shall transition to one of the listed `next_states`. When multiple transitions are possible, the tool shall greedily select the first listed `next_state`.

**FR-22** If a message does not match any pattern in the current FSM state, the tool shall record a **violation** containing:
- The flow 4-tuple (src-ip, dst-ip, src-port, dst-port).
- The byte offset within the reassembled stream at which the violating message begins.
- The current FSM state name.
- The raw bytes of the non-matching message (printable representation, up to 128 bytes displayed).

**FR-23** If the reassembled stream ends while the FSM is in a state that does not include `"__end__"` in its `next_states`, the tool shall record a violation indicating premature stream termination.

**FR-24** Validation shall continue past a violation to report as many violations as possible; the FSM shall reset to its `initial_state` after each violation and resume from the next message boundary.

### 3.6 Reporting

**FR-25** Upon completion, the tool shall print a summary to `stdout` listing:
- Total flows processed.
- Total violations found.
- Per-violation detail (flow 4-tuple, byte offset, state, message excerpt).

**FR-26** When `--verbose` is specified, the tool shall additionally print to `stdout` each successfully matched message with its flow 4-tuple, byte offset, matched state, and matched pattern.

**FR-27** The tool shall exit with code **0** if all validated flows produced zero violations.

**FR-28** The tool shall exit with code **1** if one or more violations were found.

**FR-29** The tool shall exit with code **2** on any usage error (missing required argument, unreadable file, malformed grammar, unrecognised CLI flag).

### 3.7 Demo Grammar Files

**FR-30** The repository shall include the following demo grammar files under `grammars/`:

| File | Protocol | Framing | FSM states |
|------|----------|---------|------------|
| `http1.yaml` | HTTP/1.1 | `line` | request-line, header, blank-line (end of headers) |
| `smtp.yaml` | SMTP control channel | `line` | greeting, auth, mail-from, rcpt-to, data, quit |
| `ftp.yaml` | FTP control channel | `line` | greeting, logged-out, logged-in, transfer |
| `irc.yaml` | IRC (RFC 1459) | `line` | connected, registered, channel-joined |
| `redis.yaml` | Redis RESP | `line` | idle (inline commands and bulk-string command prefix) |

---

## 4. Non-Functional Requirements

**NFR-01 Memory efficiency:** The tool shall process pcap files with millions of packets without holding all packets in memory simultaneously. Peak resident memory usage for a single flow shall not exceed twice the 64 MB stream size limit.

**NFR-02 Stream size limit:** The tool shall support TCP flow directions of up to 64 MB of reassembled data without error, per FR-10.

**NFR-03 Language standard:** All production source code shall be written in C++17 (`-std=c++17`); no C++20 features or compiler extensions shall be required to build.

**NFR-04 Test coverage:** Unit tests shall achieve ≥ 80% line coverage of the grammar-parsing and stream-validation logic, measured by a coverage tool (e.g., `gcov`/`lcov`).

**NFR-05 Test framework:** Tests shall use GoogleTest. All tests shall pass in the CI environment.

**NFR-06 Build system:** The project shall use CMake ≥ 3.20 as the sole build system. The top-level `CMakeLists.txt` shall produce the `pcapgrammar` binary and a test target.

**NFR-07 CI:** A GitHub Actions workflow shall build the project and run all tests on `ubuntu-latest` with `libpcap-dev` and `yaml-cpp` (and optionally PcapPlusPlus) installed from the default Ubuntu package repository or built from source.

**NFR-08 Portability:** The primary target is Linux (x86-64). Windows and macOS are out of scope but the code shall not deliberately preclude future porting.

**NFR-09 Dependencies:** Third-party dependencies are limited to: libpcap or PcapPlusPlus (packet reading), yaml-cpp (grammar parsing), GoogleTest (testing). No other third-party libraries shall be introduced without updating this SRS.

**NFR-10 Licensing:** The project shall be released under an OSI-approved open-source licence (MIT or Apache 2.0) consistent with the existing `LICENSE` file.

---

## 5. External Interface Requirements

### 5.1 CLI Interface

```
pcapgrammar --pcap <file.pcap> --grammar <grammar.yaml> [--port <port>] [--verbose]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--pcap <file.pcap>` | Yes | Path to the input pcap file. |
| `--grammar <grammar.yaml>` | Yes | Path to the protocol grammar YAML file. |
| `--port <port>` | No | Integer TCP port (1–65535). Filters to flows involving this port in either direction. |
| `--verbose` | No | Enables per-message trace output on `stdout`. |

Unrecognised arguments shall cause exit code 2 with a usage message on `stderr`.

### 5.2 Grammar YAML File Format

Top-level keys:

```yaml
framing: line                  # "line" | "length_prefixed" | "tlv"
prefix_bytes: 2                # required when framing == length_prefixed; 2 or 4
type_bytes: 1                  # required when framing == tlv; 1-4
length_bytes: 2                # required when framing == tlv; 1-4
initial_state: <state-name>
states:
  - name: <state-name>
    patterns:
      - match: "<literal or ERE regex>"
        next_states:
          - <state-name>        # or "__end__"
```

### 5.3 Standard Output Format

Violation output (one line per violation, plus summary):

```
VIOLATION flow=<src-ip>:<src-port>-><dst-ip>:<dst-port> offset=<bytes> state=<state> msg=<excerpt>
...
Summary: flows=<N> violations=<M>
```

Verbose match output (when `--verbose`):

```
MATCH    flow=<src-ip>:<src-port>-><dst-ip>:<dst-port> offset=<bytes> state=<state> pattern=<pattern>
```

### 5.4 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All validated flows are violation-free. |
| 1 | At least one violation was found. |
| 2 | Usage error, missing argument, unreadable file, or malformed grammar. |

---

## 6. Constraints & Assumptions

**CA-01** The tool processes only offline pcap files; live capture (e.g., sniffing a network interface) is not required.

**CA-02** Only IPv4 is in scope. IPv6 flow reassembly is out of scope for this version.

**CA-03** TCP handshake (SYN/FIN/RST) packets are used only to identify stream boundaries; their flags are not independently validated by the grammar.

**CA-04** The grammar FSM is deterministic: when multiple patterns could match, the first pattern in declaration order wins (FR-20). The grammar author is responsible for ordering patterns to avoid ambiguity.

**CA-05** Pattern matching is performed on the raw bytes of each framed message. Multi-byte character encoding issues are the grammar author's responsibility.

**CA-06** The tool is single-threaded. Parallel processing of flows is out of scope for this version.

**CA-07** The build environment is Ubuntu (LTS). The CI workflow targets `ubuntu-latest` in GitHub Actions.

**CA-08** yaml-cpp and libpcap (or PcapPlusPlus) must be available either as system packages or buildable from source within the CI job; no proprietary or access-restricted libraries are used.

---

## 7. Out of Scope

**OOS-01** Live packet capture from a network interface.

**OOS-02** IPv6 flow reassembly and validation.

**OOS-03** UDP or ICMP stream reassembly.

**OOS-04** Automatic protocol detection (the grammar file is always user-supplied).

**OOS-05** Writing or modifying `.pcap` files.

**OOS-06** Graphical or web-based user interface.

**OOS-07** Windows or macOS native builds (portability is a nice-to-have, not a requirement).

**OOS-08** Non-deterministic (backtracking) FSM: the tool implements a greedy, first-match-wins FSM only.

**OOS-09** TLS/SSL decryption; encrypted payloads are passed to the grammar as opaque bytes.

**OOS-10** Grammar hot-reload; the grammar file is parsed once at startup.

---

## 8. Acceptance Criteria

The following conditions must all be satisfied before this project is considered complete:

| ID | Criterion |
|----|-----------|
| AC-01 | `pcapgrammar --pcap sample.pcap --grammar grammars/http1.yaml` exits 0 on a well-formed HTTP/1.1 pcap. |
| AC-02 | `pcapgrammar --pcap bad.pcap --grammar grammars/smtp.yaml` exits 1 and prints at least one `VIOLATION` line when the pcap contains an SMTP protocol error. |
| AC-03 | `pcapgrammar --pcap large.pcap --grammar grammars/redis.yaml --port 6379` correctly filters to port 6379 flows only. |
| AC-04 | `pcapgrammar` exits 2 with a message on `stderr` when `--pcap` is omitted. |
| AC-05 | All five demo grammar files (`http1.yaml`, `smtp.yaml`, `ftp.yaml`, `irc.yaml`, `redis.yaml`) parse without error. |
| AC-06 | GoogleTest suite passes with ≥ 80% line coverage on grammar-validation code, verified by CI. |
| AC-07 | GitHub Actions workflow completes (build + test) successfully on `ubuntu-latest`. |
| AC-08 | A pcap file containing a flow with 64 MB of reassembled data is processed without out-of-memory termination. |

---

*Handoff to System Architect.*
