#include <gtest/gtest.h>
#include "TcpReassembler.hpp"

#include <string>
#include <vector>

static std::vector<uint8_t> makePayload(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

struct ReassemblerHarness {
    std::vector<uint8_t> received;
    TcpReassembler reassembler;

    explicit ReassemblerHarness(size_t max_bytes = TcpReassembler::kMaxStreamBytes)
        : reassembler([this](const uint8_t* d, size_t l){
                          received.insert(received.end(), d, d + l);
                      }, max_bytes)
    {}

    std::string receivedStr() const {
        return std::string(received.begin(), received.end());
    }
};

// -----------------------------------------------------------------------
// In-order delivery
// -----------------------------------------------------------------------
TEST(TcpReassembler, InOrderDelivery) {
    ReassemblerHarness h;
    // SYN at seq 100
    h.reassembler.push(100, {}, true, false, false);
    // Data at seq 101, 106
    h.reassembler.push(101, makePayload("HELLO"), false, false, false);
    h.reassembler.push(106, makePayload("WORLD"), false, true, false);

    EXPECT_EQ(h.receivedStr(), "HELLOWORLD");
}

// -----------------------------------------------------------------------
// Out-of-order: packet 2 arrives before packet 1
// -----------------------------------------------------------------------
TEST(TcpReassembler, OutOfOrderDelivery) {
    ReassemblerHarness h;
    h.reassembler.push(0, {}, true, false, false);  // SYN
    // seq 1 expected, but seq 6 arrives first
    h.reassembler.push(6, makePayload("WORLD"), false, false, false);
    EXPECT_EQ(h.receivedStr(), "");  // nothing yet

    h.reassembler.push(1, makePayload("HELLO"), false, false, false);
    EXPECT_EQ(h.receivedStr(), "HELLOWORLD");
}

// -----------------------------------------------------------------------
// Duplicate segment ignored (retransmit)
// -----------------------------------------------------------------------
TEST(TcpReassembler, DuplicateSegmentIgnored) {
    ReassemblerHarness h;
    h.reassembler.push(0, {}, true, false, false);  // SYN
    h.reassembler.push(1, makePayload("HELLO"), false, false, false);
    // Retransmit same segment
    h.reassembler.push(1, makePayload("HELLO"), false, false, false);
    h.reassembler.flush();

    EXPECT_EQ(h.receivedStr(), "HELLO");
}

// -----------------------------------------------------------------------
// Overlapping segment trimmed
// -----------------------------------------------------------------------
TEST(TcpReassembler, OverlappingSegmentTrimmed) {
    ReassemblerHarness h;
    h.reassembler.push(0, {}, true, false, false);  // SYN (next_expected = 1)
    h.reassembler.push(1, makePayload("HELLO"), false, false, false);  // delivers HELLO, next=6
    // Overlapping: starts at 4 (already partly delivered), only "LO!!" is new
    h.reassembler.push(4, makePayload("LO!!"), false, false, false);
    h.reassembler.flush();

    // After trimming overlap (first 2 bytes already delivered), delivers "!!"
    EXPECT_EQ(h.receivedStr(), "HELLO!!");
}

// -----------------------------------------------------------------------
// SYN sets initial seq
// -----------------------------------------------------------------------
TEST(TcpReassembler, SynSetsInitialSeq) {
    ReassemblerHarness h;
    // Without SYN, push at seq 500 should be ignored
    h.reassembler.push(500, makePayload("DATA"), false, false, false);
    EXPECT_EQ(h.receivedStr(), "");

    // SYN at seq 999
    h.reassembler.push(999, {}, true, false, false);
    // Data at 1000
    h.reassembler.push(1000, makePayload("DATA"), false, false, false);
    EXPECT_EQ(h.receivedStr(), "DATA");
}

// -----------------------------------------------------------------------
// FIN flushes buffer
// -----------------------------------------------------------------------
TEST(TcpReassembler, FinFlushesBuffer) {
    ReassemblerHarness h;
    h.reassembler.push(0, {}, true, false, false);
    h.reassembler.push(1, makePayload("HI"), false, true, false);
    EXPECT_EQ(h.receivedStr(), "HI");
}

// -----------------------------------------------------------------------
// Size limit enforced
// -----------------------------------------------------------------------
TEST(TcpReassembler, SizeLimitEnforced) {
    ReassemblerHarness h(10);  // max 10 bytes
    h.reassembler.push(0, {}, true, false, false);
    h.reassembler.push(1, makePayload("12345678901"), false, false, false);  // 11 bytes

    // Should have delivered nothing (limit exceeded before insertion)
    EXPECT_LE(h.received.size(), 10u);
}

// -----------------------------------------------------------------------
// Empty payload (pure ACK) — no bytes delivered
// -----------------------------------------------------------------------
TEST(TcpReassembler, EmptyPayloadNoDelivery) {
    ReassemblerHarness h;
    h.reassembler.push(0, {}, true, false, false);
    h.reassembler.push(1, {}, false, false, false);  // empty = pure ACK
    EXPECT_EQ(h.received.size(), 0u);
}
