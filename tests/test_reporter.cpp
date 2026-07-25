#include <gtest/gtest.h>
#include "Reporter.hpp"
#include "PcapReader.hpp"

#include <sstream>
#include <string>
#include <iostream>

// Portable stdout capture using streambuf redirect — no /tmp dependency.
struct StdoutCapture {
    std::ostringstream oss;
    std::streambuf*    old;
    StdoutCapture() : old(std::cout.rdbuf(oss.rdbuf())) {}
    ~StdoutCapture() { std::cout.rdbuf(old); }
    std::string str() const { return oss.str(); }
};

static FlowKey makeFlow(uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp) {
    FlowKey k;
    k.src_ip   = sip;
    k.src_port = sp;
    k.dst_ip   = dip;
    k.dst_port = dp;
    return k;
}

static Violation makeViolation(FlowKey fk, size_t off = 0,
                               const std::string& state = "s1",
                               const std::string& excerpt = "bad msg",
                               bool eof = false) {
    Violation v;
    v.flow            = fk;
    v.byte_offset     = off;
    v.state_name      = state;
    v.message_excerpt = excerpt;
    v.is_premature_eof = eof;
    return v;
}

static MatchInfo makeMatch(FlowKey fk, size_t off = 0,
                           const std::string& state = "s1",
                           const std::string& pat = "^OK$") {
    MatchInfo m;
    m.flow        = fk;
    m.byte_offset = off;
    m.state_name  = state;
    m.pattern_str = pat;
    return m;
}

// -----------------------------------------------------------------------
// Exit code 0 when no violations
// -----------------------------------------------------------------------
TEST(Reporter, ExitCode0NoViolations) {
    Reporter r(false);
    EXPECT_EQ(r.exitCode(), 0);
}

// -----------------------------------------------------------------------
// Exit code 1 when violations present
// -----------------------------------------------------------------------
TEST(Reporter, ExitCode1WithViolation) {
    Reporter r(false);
    FlowKey fk = makeFlow(0x7f000001, 1234, 0x7f000002, 80);
    r.recordViolation(makeViolation(fk));
    EXPECT_EQ(r.exitCode(), 1);
}

// -----------------------------------------------------------------------
// printSummary output format
// -----------------------------------------------------------------------
TEST(Reporter, PrintSummaryFormat) {
    Reporter r(false);
    FlowKey fk = makeFlow(0x7f000001, 1234, 0x7f000002, 80);
    r.registerFlow();
    r.registerFlow();
    r.recordViolation(makeViolation(fk));

    StdoutCapture cap;
    r.printSummary();
    std::string out = cap.str();

    EXPECT_NE(out.find("flows=2"), std::string::npos);
    EXPECT_NE(out.find("violations=1"), std::string::npos);
}

// -----------------------------------------------------------------------
// VIOLATION line format
// -----------------------------------------------------------------------
TEST(Reporter, ViolationLineFormat) {
    Reporter r(false);
    // src=127.0.0.1:1234 -> dst=192.168.1.1:80
    FlowKey fk = makeFlow(0x7f000001, 1234, 0xC0A80101, 80);

    StdoutCapture cap;
    r.recordViolation(makeViolation(fk, 42, "greet", "bad stuff"));
    std::string out = cap.str();

    EXPECT_NE(out.find("VIOLATION"), std::string::npos);
    EXPECT_NE(out.find("offset=42"), std::string::npos);
    EXPECT_NE(out.find("state=greet"), std::string::npos);
    EXPECT_NE(out.find("msg=bad stuff"), std::string::npos);
    // IP check
    EXPECT_NE(out.find("127.0.0.1"), std::string::npos);
    EXPECT_NE(out.find("1234"), std::string::npos);
}

// -----------------------------------------------------------------------
// Verbose mode includes MATCH lines
// -----------------------------------------------------------------------
TEST(Reporter, VerboseModeIncludesMatch) {
    Reporter r(true);
    FlowKey fk = makeFlow(0x7f000001, 1234, 0x7f000002, 80);

    StdoutCapture cap;
    r.recordMatch(makeMatch(fk, 10, "start", "^HELLO$"));
    std::string out = cap.str();

    EXPECT_NE(out.find("MATCH"), std::string::npos);
    EXPECT_NE(out.find("state=start"), std::string::npos);
    EXPECT_NE(out.find("pattern=^HELLO$"), std::string::npos);
}

// -----------------------------------------------------------------------
// Non-verbose mode omits MATCH lines
// -----------------------------------------------------------------------
TEST(Reporter, NonVerboseOmitsMatch) {
    Reporter r(false);
    FlowKey fk = makeFlow(0x7f000001, 1234, 0x7f000002, 80);

    StdoutCapture cap;
    r.recordMatch(makeMatch(fk));
    std::string out = cap.str();

    EXPECT_EQ(out.find("MATCH"), std::string::npos);
}

// -----------------------------------------------------------------------
// totalFlows and totalViolations
// -----------------------------------------------------------------------
TEST(Reporter, Counters) {
    Reporter r(false);
    FlowKey fk = makeFlow(0x7f000001, 1234, 0x7f000002, 80);
    r.registerFlow();
    r.registerFlow();
    r.registerFlow();
    r.recordViolation(makeViolation(fk));
    r.recordViolation(makeViolation(fk));

    EXPECT_EQ(r.totalFlows(), 3u);
    EXPECT_EQ(r.totalViolations(), 2u);
}
