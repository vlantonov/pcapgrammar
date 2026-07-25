#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <regex>
#include <cstdint>

enum class FramingType { LINE, LENGTH_PREFIXED, TLV };
enum class PatternType { LITERAL, REGEX };

struct FramingConfig {
    FramingType type{FramingType::LINE};
    uint8_t prefix_bytes{2};
    bool    endian_big{true};
    uint8_t type_bytes{1};
    uint8_t length_bytes{1};
};

struct Pattern {
    std::string              match_str;
    PatternType              ptype{PatternType::LITERAL};
    std::regex               compiled;
    std::vector<std::string> next_states;
};

struct State {
    std::string          name;
    std::vector<Pattern> patterns;
    bool                 allow_eof{false};
};

struct Grammar {
    std::string                            display_name;
    FramingConfig                          framing;
    std::string                            initial_state;
    std::unordered_map<std::string, State> states;
};
