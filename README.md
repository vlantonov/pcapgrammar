# pcapgrammar

**pcapgrammar** is a C++17 command-line tool that reads a PCAP capture file and validates TCP application-layer streams against user-defined protocol grammars described in YAML. It helps network engineers and security analysts verify that recorded traffic conforms to expected protocol state machines.

## Prerequisites

Install the following packages (Debian/Ubuntu):

```sh
sudo apt install -y cmake g++ libpcap-dev libyaml-cpp-dev libgtest-dev pkg-config
```

## Build

```sh
cmake -B build -DPCAPGRAMMAR_USE_CONAN=OFF
cmake --build build -- -j$(nproc)
```

### With Conan 2

```sh
conan install . --build=missing
cmake -B build -DPCAPGRAMMAR_USE_CONAN=ON -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake
cmake --build build -- -j$(nproc)
```

## Run tests

```sh
cd build && ctest --output-on-failure
```

## Usage

```
pcapgrammar --pcap <file.pcap> --grammar <grammar.yaml> [--port <N>] [--verbose]
```

| Flag | Description |
|---|---|
| `--pcap <path>` | Path to the PCAP capture file (required) |
| `--grammar <path>` | Path to the protocol grammar YAML file (required) |
| `--port <N>` | Filter to a specific TCP destination port (optional) |
| `--verbose` | Print each matched pattern in addition to violations |

### Examples

```sh
# Validate HTTP/1.1 traffic
./build/src/pcapgrammar --pcap capture.pcap --grammar grammars/http1.yaml

# Check port 25 SMTP, show matched lines
./build/src/pcapgrammar --pcap capture.pcap --grammar grammars/smtp.yaml --port 25 --verbose

# FTP control channel, filter to port 21
./build/src/pcapgrammar --pcap capture.pcap --grammar grammars/ftp.yaml --port 21

# Redis on default port
./build/src/pcapgrammar --pcap capture.pcap --grammar grammars/redis.yaml --port 6379
```

## Grammar file format

Grammars are YAML files that describe:

- **framing** — how to extract individual messages from the byte stream (`line`, `length_prefixed`, or `tlv`).
- **initial_state** — the starting FSM state.
- **states** — a list of named states, each with one or more patterns. Patterns specify a `match` string, a `type` (`literal` or `regex`), and `next_states` to transition to on a match. The special state `__end__` marks a clean stream termination.

```yaml
name: "Example"
framing:
  type: line
initial_state: start
states:
  - name: start
    patterns:
      - match: "^HELLO .*$"
        type: regex
        next_states:
          - done
  - name: done
    patterns:
      - match: "^BYE$"
        type: literal
        next_states:
          - __end__
```

## Demo grammars

| File | Protocol | Framing | Port |
|---|---|---|---|
| `grammars/http1.yaml` | HTTP/1.1 | line | 80/443 |
| `grammars/smtp.yaml` | SMTP | line | 25/587 |
| `grammars/ftp.yaml` | FTP control | line | 21 |
| `grammars/irc.yaml` | IRC RFC 1459 | line | 6667 |
| `grammars/redis.yaml` | Redis RESP | line | 6379 |
