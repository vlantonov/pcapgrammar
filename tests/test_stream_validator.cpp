#include <gtest/gtest.h>
#include "StreamValidator.hpp"
#include "Grammar.hpp"
#include "Reporter.hpp"
#include "PcapReader.hpp"

#include <string>
#include <vector>

// -----------------------------------------------------------------------
// Helper: build a simple line-framed grammar in memory
// -----------------------------------------------------------------------
struct SimpleGrammar {
    Grammar g;

    SimpleGrammar() {
        g.framing.type = FramingType::LINE;
        g.initial_state = "start";
    }

    // Adds a state with a single literal or regex pattern
    SimpleGrammar& addState(const std::string& name,
                            const std::string& match_str,
                            PatternType ptype,
                            const std::vector<std::string>& nexts,
                            bool is_extra_pattern = false) {
        if (!g.states.count(name)) {
            State s;
            s.name = name;
            g.states[name] = s;
        }
        Pattern p;
        p.match_str = match_str;
        p.ptype = ptype;
        if (ptype == PatternType::REGEX) {
            p.compiled = std::regex(match_str, std::regex::extended | std::regex::optimize);
        }
        p.next_states = nexts;
        for (const auto& n : nexts) {
            if (n == "__end__") {
                g.states[name].allow_eof = true;
            }
        }
        if (!is_extra_pattern) {
            (void)is_extra_pattern;
        }
        g.states[name].patterns.push_back(std::move(p));
        return *this;
    }
};

// -----------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------
struct Harness {
    Grammar grammar;
    FlowKey flow_key;
    std::vector<Violation> violations;
    std::vector<MatchInfo> matches;
    std::unique_ptr<StreamValidator> sv;

    explicit Harness(Grammar g) : grammar(std::move(g)) {
        flow_key.src_ip   = 0x7f000001;
        flow_key.dst_ip   = 0x7f000002;
        flow_key.src_port = 1234;
        flow_key.dst_port = 80;
        sv = std::make_unique<StreamValidator>(
            grammar, flow_key,
            [this](const Violation& v){ violations.push_back(v); },
            [this](const MatchInfo& m){ matches.push_back(m); }
        );
    }

    void feed(const std::string& line) {
        std::string data = line + "\n";
        sv->consume(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    void feedRaw(const uint8_t* data, size_t len) {
        sv->consume(data, len);
    }

    void flush() {
        sv->flush();
    }

    size_t violationCount() const { return violations.size(); }
    size_t matchCount()     const { return matches.size(); }
};

// Build a two-state line grammar: start -> "HELLO" -> end
static Grammar buildHelloGrammar() {
    SimpleGrammar sg;
    sg.addState("start", "HELLO", PatternType::LITERAL, {"__end__"});
    return sg.g;
}

// Build a multi-state grammar: request -> response -> __end__
// Uses literal "OK" (no anchors) so it matches the string exactly.
static Grammar buildRequestResponseGrammar() {
    SimpleGrammar sg;
    sg.addState("start",    "^REQ .*$", PatternType::REGEX,   {"response"});
    sg.addState("response", "OK",        PatternType::LITERAL, {"__end__"});
    return sg.g;
}

// Three-state grammar: start -> response -> done -> __end__
// "response" does NOT have __end__ in next_states so allow_eof=false,
// making it suitable for premature-EOF tests.
static Grammar buildThreeStateGrammar() {
    SimpleGrammar sg;
    sg.addState("start",    "^REQ .*$", PatternType::REGEX,   {"response"});
    sg.addState("response", "OK",        PatternType::LITERAL, {"done"});
    sg.addState("done",     "BYE",       PatternType::LITERAL, {"__end__"});
    return sg.g;
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

TEST(StreamValidator, ValidSingleMessageNoViolation) {
    Harness h(buildHelloGrammar());
    h.feed("HELLO");
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);
}

TEST(StreamValidator, ValidSequenceWithStateTransition) {
    Harness h(buildRequestResponseGrammar());
    h.feed("REQ foo");
    h.feed("OK");
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);
}

TEST(StreamValidator, ViolationOnMismatch) {
    Harness h(buildHelloGrammar());
    h.feed("GOODBYE");
    EXPECT_EQ(h.violationCount(), 1u);
}

TEST(StreamValidator, ContinuesAfterViolation) {
    // After violation, FSM resets to initial. A valid message then succeeds.
    Harness h(buildHelloGrammar());
    h.feed("GARBAGE");  // violation, reset to start
    h.feed("HELLO");    // should succeed from start
    h.flush();
    EXPECT_EQ(h.violationCount(), 1u);
}

TEST(StreamValidator, PrematureEofInNonTerminalState) {
    // Use three-state grammar: response -> done (not __end__), so allow_eof=false
    Harness h(buildThreeStateGrammar());
    h.feed("REQ bar");  // transitions to response state (allow_eof=false)
    h.flush();          // not in allow_eof state -> violation
    EXPECT_GE(h.violationCount(), 1u);
    EXPECT_TRUE(h.violations.back().is_premature_eof);
}

TEST(StreamValidator, CleanEofInTerminalState) {
    Harness h(buildHelloGrammar());
    h.feed("HELLO");  // transitions to __end__
    h.flush();        // done_ = true, no violation
    EXPECT_EQ(h.violationCount(), 0u);
}

TEST(StreamValidator, ByteOffsetTracking) {
    Harness h(buildRequestResponseGrammar());
    h.feed("REQ foo");  // 7 chars + \n = 8 bytes
    h.feed("OK");       // 2 chars + \n = 3 bytes
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);
    // Offset after second message: 8 + 3 = 11
    EXPECT_EQ(h.matchCount(), 2u);
    EXPECT_EQ(h.matches[0].byte_offset, 8u);
    EXPECT_EQ(h.matches[1].byte_offset, 11u);
}

TEST(StreamValidator, MessageExcerptTruncatedAt128) {
    SimpleGrammar sg;
    // No pattern matches -> violation
    sg.addState("start", "NOPE", PatternType::LITERAL, {"__end__"});
    Harness h(sg.g);

    std::string long_msg(200, 'A');
    h.feed(long_msg);
    ASSERT_EQ(h.violationCount(), 1u);
    EXPECT_LE(h.violations[0].message_excerpt.size(), 128u);
}

TEST(StreamValidator, LiteralPatternMatch) {
    SimpleGrammar sg;
    sg.addState("start", "EXACT", PatternType::LITERAL, {"__end__"});
    Harness h(sg.g);
    h.feed("EXACT");
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);
}

TEST(StreamValidator, RegexPatternMatch) {
    SimpleGrammar sg;
    sg.addState("start", "^[0-9]+$", PatternType::REGEX, {"__end__"});
    Harness h(sg.g);
    h.feed("12345");
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);
}

TEST(StreamValidator, LengthPrefixed2ByteFraming) {
    Grammar g;
    g.framing.type         = FramingType::LENGTH_PREFIXED;
    g.framing.prefix_bytes = 2;
    g.initial_state = "msg";

    State s;
    s.name = "msg";
    Pattern p;
    p.match_str   = ".*";
    p.ptype       = PatternType::REGEX;
    p.compiled    = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.allow_eof   = false;
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    std::vector<MatchInfo> matches;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); },
        [&](const MatchInfo& m){ matches.push_back(m); });

    // Build a LENGTH_PREFIXED message: 2-byte big-endian length + payload
    std::string payload = "HELLO";
    std::vector<uint8_t> msg;
    uint16_t len = static_cast<uint16_t>(payload.size());
    msg.push_back(static_cast<uint8_t>(len >> 8));
    msg.push_back(static_cast<uint8_t>(len & 0xFF));
    msg.insert(msg.end(), payload.begin(), payload.end());

    sv.consume(msg.data(), msg.size());
    EXPECT_EQ(viols.size(), 0u);
    EXPECT_EQ(matches.size(), 1u);
}

TEST(StreamValidator, LengthPrefixed4ByteFraming) {
    Grammar g;
    g.framing.type         = FramingType::LENGTH_PREFIXED;
    g.framing.prefix_bytes = 4;
    g.initial_state = "msg";

    State s;
    s.name = "msg";
    Pattern p;
    p.match_str   = ".*";
    p.ptype       = PatternType::REGEX;
    p.compiled    = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.allow_eof   = false;
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); }, nullptr);

    std::string payload = "WORLD";
    std::vector<uint8_t> msg;
    uint32_t len = static_cast<uint32_t>(payload.size());
    msg.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    msg.push_back(static_cast<uint8_t>((len >>  8) & 0xFF));
    msg.push_back(static_cast<uint8_t>( len        & 0xFF));
    msg.insert(msg.end(), payload.begin(), payload.end());

    sv.consume(msg.data(), msg.size());
    EXPECT_EQ(viols.size(), 0u);
}

TEST(StreamValidator, PartialBufferDeliverOneCompleteMessage) {
    Harness h(buildHelloGrammar());
    // Send partial data without newline
    std::string partial = "HEL";
    h.feedRaw(reinterpret_cast<const uint8_t*>(partial.data()), partial.size());
    EXPECT_EQ(h.violationCount(), 0u);
    // Now complete the message
    std::string rest = "LO\n";
    h.feedRaw(reinterpret_cast<const uint8_t*>(rest.data()), rest.size());
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);
}

TEST(StreamValidator, TlvFraming) {
    Grammar g;
    g.framing.type         = FramingType::TLV;
    g.framing.type_bytes   = 1;
    g.framing.length_bytes = 1;
    g.initial_state = "msg";

    State s;
    s.name = "msg";
    Pattern p;
    p.match_str   = ".*";
    p.ptype       = PatternType::REGEX;
    p.compiled    = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.allow_eof   = false;
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    std::vector<MatchInfo> matches;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); },
        [&](const MatchInfo& m){ matches.push_back(m); });

    // TLV: type(1) + length(1) + value
    std::string payload = "DATA";
    std::vector<uint8_t> tlv;
    tlv.push_back(0x01);  // type
    tlv.push_back(static_cast<uint8_t>(payload.size()));  // length
    tlv.insert(tlv.end(), payload.begin(), payload.end());

    sv.consume(tlv.data(), tlv.size());
    EXPECT_EQ(viols.size(), 0u);
    EXPECT_EQ(matches.size(), 1u);
}

TEST(StreamValidator, VerboseModeOnMatchFires) {
    Harness h(buildHelloGrammar());
    h.feed("HELLO");
    h.flush();
    EXPECT_EQ(h.matchCount(), 1u);
    EXPECT_EQ(h.matches[0].pattern_str, "HELLO");
}

// -----------------------------------------------------------------------
// Gap-closing tests — paths uncovered by the original suite
// -----------------------------------------------------------------------

// FR-14 (line framing): \r\n terminator — the \r must be stripped before matching
TEST(StreamValidator, CrlfLineTerminationStripped) {
    Harness h(buildHelloGrammar());
    std::string crlf = "HELLO\r\n";
    h.feedRaw(reinterpret_cast<const uint8_t*>(crlf.data()), crlf.size());
    h.flush();
    EXPECT_EQ(h.violationCount(), 0u);  // \r stripped, "HELLO" matches
}

// LENGTH_PREFIXED: only 1 byte arrives when 2-byte prefix expected → no message yet
TEST(StreamValidator, LengthPrefixedPartialPrefix) {
    Grammar g;
    g.framing.type         = FramingType::LENGTH_PREFIXED;
    g.framing.prefix_bytes = 2;
    g.initial_state = "msg";
    State s; s.name = "msg";
    Pattern p; p.match_str = ".*"; p.ptype = PatternType::REGEX;
    p.compiled = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    std::vector<MatchInfo> matches;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); },
        [&](const MatchInfo& m){ matches.push_back(m); });

    std::vector<uint8_t> partial{0x00};  // only 1 of 2 prefix bytes
    sv.consume(partial.data(), partial.size());
    EXPECT_EQ(viols.size(), 0u);
    EXPECT_EQ(matches.size(), 0u);  // message not yet extractable
}

// LENGTH_PREFIXED: prefix complete (claims 10 bytes) but only 3 body bytes arrive
TEST(StreamValidator, LengthPrefixedPartialBody) {
    Grammar g;
    g.framing.type         = FramingType::LENGTH_PREFIXED;
    g.framing.prefix_bytes = 2;
    g.initial_state = "msg";
    State s; s.name = "msg";
    Pattern p; p.match_str = ".*"; p.ptype = PatternType::REGEX;
    p.compiled = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    std::vector<MatchInfo> matches;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); },
        [&](const MatchInfo& m){ matches.push_back(m); });

    // prefix = 0x000A (10 bytes needed), but only 3 body bytes provided
    std::vector<uint8_t> partial{0x00, 0x0A, 'A', 'B', 'C'};
    sv.consume(partial.data(), partial.size());
    EXPECT_EQ(viols.size(), 0u);
    EXPECT_EQ(matches.size(), 0u);  // incomplete message stays in buffer
}

// FR-22: non-printable bytes in a violating message are shown as '.' in the excerpt
TEST(StreamValidator, NonPrintableBytesInExcerpt) {
    SimpleGrammar sg;
    sg.addState("start", "NOPE", PatternType::LITERAL, {"__end__"});
    Harness h(sg.g);

    // Line containing a NUL and a control byte; no pattern matches → violation
    std::vector<uint8_t> raw{'H', 0x00, 0x01, 'i', '\n'};
    h.feedRaw(raw.data(), raw.size());
    ASSERT_EQ(h.violationCount(), 1u);
    EXPECT_NE(h.violations[0].message_excerpt.find('.'), std::string::npos);
}

// FR-23: stream ending in an allow_eof state must NOT produce a premature-EOF violation
TEST(StreamValidator, FlushInAllowEofStateNoViolation) {
    // "loop" greedily stays in "loop" (first next_state), but allow_eof=true
    // so flush() should take the early-return branch without emitting a violation.
    SimpleGrammar sg;
    sg.addState("loop", ".*", PatternType::REGEX, {"loop"});
    sg.g.initial_state = "loop";        // override SimpleGrammar default "start"
    sg.g.states["loop"].allow_eof = true;
    Harness h(sg.g);

    h.feed("anything");   // stays in "loop", done_=false
    h.flush();            // buffer empty; done_=false; allow_eof=true → no violation
    EXPECT_EQ(h.violationCount(), 0u);
}

// TLV: only 2 bytes arrive when 3-byte header (type=1 + length=2) expected
TEST(StreamValidator, TlvPartialHeader) {
    Grammar g;
    g.framing.type         = FramingType::TLV;
    g.framing.type_bytes   = 1;
    g.framing.length_bytes = 2;  // header_size = 3
    g.initial_state = "msg";
    State s; s.name = "msg";
    Pattern p; p.match_str = ".*"; p.ptype = PatternType::REGEX;
    p.compiled = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    std::vector<MatchInfo> matches;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); },
        [&](const MatchInfo& m){ matches.push_back(m); });

    std::vector<uint8_t> partial{0x01, 0x00};  // 2 bytes < 3-byte header
    sv.consume(partial.data(), partial.size());
    EXPECT_EQ(viols.size(), 0u);
    EXPECT_EQ(matches.size(), 0u);
}

// TLV: header complete (claiming 10-byte body) but only 3 body bytes provided
TEST(StreamValidator, TlvPartialBody) {
    Grammar g;
    g.framing.type         = FramingType::TLV;
    g.framing.type_bytes   = 1;
    g.framing.length_bytes = 1;  // header_size = 2
    g.initial_state = "msg";
    State s; s.name = "msg";
    Pattern p; p.match_str = ".*"; p.ptype = PatternType::REGEX;
    p.compiled = std::regex(".*", std::regex::extended);
    p.next_states = {"msg"};
    s.patterns.push_back(std::move(p));
    g.states["msg"] = std::move(s);

    FlowKey fk{};
    std::vector<Violation> viols;
    std::vector<MatchInfo> matches;
    StreamValidator sv(g, fk,
        [&](const Violation& v){ viols.push_back(v); },
        [&](const MatchInfo& m){ matches.push_back(m); });

    // type=0x01, length=10, but only 3 body bytes follow
    std::vector<uint8_t> partial{0x01, 0x0A, 'A', 'B', 'C'};
    sv.consume(partial.data(), partial.size());
    EXPECT_EQ(viols.size(), 0u);
    EXPECT_EQ(matches.size(), 0u);
}
