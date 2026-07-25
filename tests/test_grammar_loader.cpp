#include <gtest/gtest.h>
#include "GrammarLoader.hpp"
#include "Grammar.hpp"

#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

static fs::path writeTmp(const std::string& content, const std::string& suffix = ".yaml") {
    fs::path tmp = fs::temp_directory_path() / (std::string("pcapgrammar_test_") +
                                                  std::to_string(std::rand()) + suffix);
    std::ofstream f(tmp);
    f << content;
    return tmp;
}

// Helper RAII to clean up temp files
struct TmpFile {
    fs::path path;
    explicit TmpFile(const std::string& content) : path(writeTmp(content)) {}
    ~TmpFile() { fs::remove(path); }
};

// -----------------------------------------------------------------------
// Happy path: minimal valid line grammar
// -----------------------------------------------------------------------
TEST(GrammarLoader, HappyPathLineGrammar) {
    TmpFile tmp(R"(
name: "Test Protocol"
framing:
  type: line
initial_state: start
states:
  - name: start
    patterns:
      - match: "^HELLO$"
        type: literal
        next_states:
          - __end__
)");
    Grammar g = GrammarLoader::load(tmp.path.string());
    EXPECT_EQ(g.display_name, "Test Protocol");
    EXPECT_EQ(g.framing.type, FramingType::LINE);
    EXPECT_EQ(g.initial_state, "start");
    ASSERT_EQ(g.states.size(), 1u);
    EXPECT_TRUE(g.states.at("start").allow_eof);
}

// -----------------------------------------------------------------------
// LENGTH_PREFIXED with prefix_bytes=2
// -----------------------------------------------------------------------
TEST(GrammarLoader, LengthPrefixed2) {
    TmpFile tmp(R"(
framing:
  type: length_prefixed
  prefix_bytes: 2
initial_state: msg
states:
  - name: msg
    patterns:
      - match: ".*"
        type: regex
        next_states:
          - msg
)");
    Grammar g = GrammarLoader::load(tmp.path.string());
    EXPECT_EQ(g.framing.type, FramingType::LENGTH_PREFIXED);
    EXPECT_EQ(g.framing.prefix_bytes, 2);
}

// -----------------------------------------------------------------------
// LENGTH_PREFIXED with prefix_bytes=4
// -----------------------------------------------------------------------
TEST(GrammarLoader, LengthPrefixed4) {
    TmpFile tmp(R"(
framing:
  type: length_prefixed
  prefix_bytes: 4
initial_state: msg
states:
  - name: msg
    patterns:
      - match: ".*"
        type: regex
        next_states:
          - msg
)");
    Grammar g = GrammarLoader::load(tmp.path.string());
    EXPECT_EQ(g.framing.prefix_bytes, 4);
}

// -----------------------------------------------------------------------
// TLV framing
// -----------------------------------------------------------------------
TEST(GrammarLoader, TlvFraming) {
    TmpFile tmp(R"(
framing:
  type: tlv
  type_bytes: 1
  length_bytes: 2
initial_state: msg
states:
  - name: msg
    patterns:
      - match: ".*"
        type: regex
        next_states:
          - msg
)");
    Grammar g = GrammarLoader::load(tmp.path.string());
    EXPECT_EQ(g.framing.type, FramingType::TLV);
    EXPECT_EQ(g.framing.type_bytes, 1);
    EXPECT_EQ(g.framing.length_bytes, 2);
}

// -----------------------------------------------------------------------
// allow_eof set when __end__ in next_states
// -----------------------------------------------------------------------
TEST(GrammarLoader, AllowEofSet) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "OK"
        type: literal
        next_states:
          - s1
          - __end__
)");
    Grammar g = GrammarLoader::load(tmp.path.string());
    EXPECT_TRUE(g.states.at("s1").allow_eof);
}

// -----------------------------------------------------------------------
// Error: missing initial_state
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorMissingInitialState) {
    TmpFile tmp(R"(
framing:
  type: line
states:
  - name: s1
    patterns:
      - match: "OK"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: unknown initial_state
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorUnknownInitialState) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: does_not_exist
states:
  - name: s1
    patterns:
      - match: "OK"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: undeclared next_state
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorUndeclaredNextState) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "OK"
        type: literal
        next_states: [nonexistent]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: invalid framing type
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorInvalidFramingType) {
    TmpFile tmp(R"(
framing:
  type: chunked
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: prefix_bytes=3 (invalid)
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorPrefixBytes3) {
    TmpFile tmp(R"(
framing:
  type: length_prefixed
  prefix_bytes: 3
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: length_prefixed missing prefix_bytes
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorLengthPrefixedMissingPrefixBytes) {
    TmpFile tmp(R"(
framing:
  type: length_prefixed
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: empty states list
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorEmptyStatesList) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states: []
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: empty pattern list in a state
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorEmptyPatternList) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns: []
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: invalid regex pattern
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorInvalidRegex) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "[invalid regex"
        type: regex
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Error: file not found
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorFileNotFound) {
    EXPECT_THROW(GrammarLoader::load("/tmp/definitely_does_not_exist_pcapgrammar.yaml"),
                 GrammarError);
}

// -----------------------------------------------------------------------
// Error: invalid YAML
// -----------------------------------------------------------------------
TEST(GrammarLoader, ErrorInvalidYaml) {
    TmpFile tmp("framing: {\nthis is not valid yaml: [[\n");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// -----------------------------------------------------------------------
// Gap-closing tests — paths uncovered by the original suite
// -----------------------------------------------------------------------

// Error: empty / null YAML root (file contains only YAML null "~")
TEST(GrammarLoader, ErrorEmptyYamlFile) {
    TmpFile tmp("~");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: 'framing' key absent entirely
TEST(GrammarLoader, ErrorMissingFramingKey) {
    TmpFile tmp(R"(
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: framing map present but 'type' sub-key missing
TEST(GrammarLoader, ErrorMissingFramingType) {
    TmpFile tmp(R"(
framing:
  prefix_bytes: 2
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Optional endian_big flag is loaded for length_prefixed framing
TEST(GrammarLoader, LengthPrefixedEndianBigOption) {
    TmpFile tmp(R"(
framing:
  type: length_prefixed
  prefix_bytes: 4
  endian_big: false
initial_state: msg
states:
  - name: msg
    patterns:
      - match: ".*"
        type: regex
        next_states:
          - msg
)");
    Grammar g = GrammarLoader::load(tmp.path.string());
    EXPECT_EQ(g.framing.type, FramingType::LENGTH_PREFIXED);
    EXPECT_EQ(g.framing.prefix_bytes, 4);
    EXPECT_FALSE(g.framing.endian_big);
}

// Error: TLV framing missing 'type_bytes'
TEST(GrammarLoader, ErrorTlvMissingTypeBytes) {
    TmpFile tmp(R"(
framing:
  type: tlv
  length_bytes: 2
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: TLV framing missing 'length_bytes'
TEST(GrammarLoader, ErrorTlvMissingLengthBytes) {
    TmpFile tmp(R"(
framing:
  type: tlv
  type_bytes: 1
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: TLV 'type_bytes' value > 4 (out of range)
TEST(GrammarLoader, ErrorTlvTypeBytesOutOfRange) {
    TmpFile tmp(R"(
framing:
  type: tlv
  type_bytes: 5
  length_bytes: 2
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: TLV 'length_bytes' value of 0 (out of range)
TEST(GrammarLoader, ErrorTlvLengthBytesOutOfRange) {
    TmpFile tmp(R"(
framing:
  type: tlv
  type_bytes: 1
  length_bytes: 0
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: 'states' key absent entirely
TEST(GrammarLoader, ErrorMissingStatesKey) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: state entry in the sequence has no 'name'
TEST(GrammarLoader, ErrorStateMissingName) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - patterns:
      - match: "x"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: two state entries share the same name
TEST(GrammarLoader, ErrorDuplicateStateName) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
        next_states: [s1]
  - name: s1
    patterns:
      - match: "y"
        type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: state entry has no 'patterns' key
TEST(GrammarLoader, ErrorStateMissingPatterns) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: pattern entry has no 'match' key
TEST(GrammarLoader, ErrorPatternMissingMatch) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - type: literal
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: pattern has an unrecognised type string
TEST(GrammarLoader, ErrorUnknownPatternType) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: glob
        next_states: [s1]
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}

// Error: pattern entry has no 'next_states' key
TEST(GrammarLoader, ErrorPatternMissingNextStates) {
    TmpFile tmp(R"(
framing:
  type: line
initial_state: s1
states:
  - name: s1
    patterns:
      - match: "x"
        type: literal
)");
    EXPECT_THROW(GrammarLoader::load(tmp.path.string()), GrammarError);
}
