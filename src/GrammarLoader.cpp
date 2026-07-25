#include "GrammarLoader.hpp"

#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>

Grammar GrammarLoader::load(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw GrammarError(std::string("YAML parse error in '") + path + "': " + e.what());
    }

    if (!root) {
        throw GrammarError("Empty or invalid YAML file: " + path);
    }

    Grammar grammar;

    // Optional display name
    if (root["name"]) {
        grammar.display_name = root["name"].as<std::string>();
    }

    // Required: framing
    if (!root["framing"]) {
        throw GrammarError("Missing required 'framing' key in: " + path);
    }
    const YAML::Node& framing_node = root["framing"];
    if (!framing_node["type"]) {
        throw GrammarError("Missing 'framing.type' in: " + path);
    }

    std::string ftype = framing_node["type"].as<std::string>();
    if (ftype == "line") {
        grammar.framing.type = FramingType::LINE;
    } else if (ftype == "length_prefixed") {
        grammar.framing.type = FramingType::LENGTH_PREFIXED;
        if (!framing_node["prefix_bytes"]) {
            throw GrammarError("'length_prefixed' framing requires 'prefix_bytes' in: " + path);
        }
        int pb = framing_node["prefix_bytes"].as<int>();
        if (pb != 2 && pb != 4) {
            throw GrammarError("'prefix_bytes' must be 2 or 4 for length_prefixed framing in: " + path);
        }
        grammar.framing.prefix_bytes = static_cast<uint8_t>(pb);
        if (framing_node["endian_big"]) {
            grammar.framing.endian_big = framing_node["endian_big"].as<bool>();
        }
    } else if (ftype == "tlv") {
        grammar.framing.type = FramingType::TLV;
        if (!framing_node["type_bytes"]) {
            throw GrammarError("'tlv' framing requires 'type_bytes' in: " + path);
        }
        if (!framing_node["length_bytes"]) {
            throw GrammarError("'tlv' framing requires 'length_bytes' in: " + path);
        }
        int tb = framing_node["type_bytes"].as<int>();
        int lb = framing_node["length_bytes"].as<int>();
        if (tb < 1 || tb > 4) {
            throw GrammarError("'type_bytes' must be between 1 and 4 for tlv framing in: " + path);
        }
        if (lb < 1 || lb > 4) {
            throw GrammarError("'length_bytes' must be between 1 and 4 for tlv framing in: " + path);
        }
        grammar.framing.type_bytes   = static_cast<uint8_t>(tb);
        grammar.framing.length_bytes = static_cast<uint8_t>(lb);
    } else {
        throw GrammarError("Unknown framing type '" + ftype + "' in: " + path);
    }

    // Required: initial_state
    if (!root["initial_state"]) {
        throw GrammarError("Missing required 'initial_state' in: " + path);
    }
    grammar.initial_state = root["initial_state"].as<std::string>();

    // Required: states
    if (!root["states"] || !root["states"].IsSequence()) {
        throw GrammarError("Missing or invalid 'states' sequence in: " + path);
    }
    const YAML::Node& states_node = root["states"];
    if (states_node.size() == 0) {
        throw GrammarError("'states' list must not be empty in: " + path);
    }

    // First pass: collect state names
    for (const auto& snode : states_node) {
        if (!snode["name"]) {
            throw GrammarError("State entry missing 'name' in: " + path);
        }
        std::string sname = snode["name"].as<std::string>();
        if (grammar.states.count(sname)) {
            throw GrammarError("Duplicate state name '" + sname + "' in: " + path);
        }
        grammar.states[sname].name = sname;
    }

    // Second pass: parse patterns (so next_state validation can check declared states)
    for (const auto& snode : states_node) {
        std::string sname = snode["name"].as<std::string>();
        State& state = grammar.states.at(sname);

        if (!snode["patterns"] || !snode["patterns"].IsSequence()) {
            throw GrammarError("State '" + sname + "' missing 'patterns' sequence in: " + path);
        }
        if (snode["patterns"].size() == 0) {
            throw GrammarError("State '" + sname + "' must have at least one pattern in: " + path);
        }

        for (const auto& pnode : snode["patterns"]) {
            Pattern pat;

            if (!pnode["match"]) {
                throw GrammarError("Pattern in state '" + sname + "' missing 'match' in: " + path);
            }
            pat.match_str = pnode["match"].as<std::string>();

            std::string ptype_str = "literal";
            if (pnode["type"]) {
                ptype_str = pnode["type"].as<std::string>();
            }

            if (ptype_str == "literal") {
                pat.ptype = PatternType::LITERAL;
            } else if (ptype_str == "regex") {
                pat.ptype = PatternType::REGEX;
                try {
                    pat.compiled = std::regex(pat.match_str,
                                              std::regex::extended | std::regex::optimize);
                } catch (const std::regex_error& e) {
                    throw GrammarError("Invalid regex '" + pat.match_str
                                       + "' in state '" + sname + "': " + e.what());
                }
            } else {
                throw GrammarError("Unknown pattern type '" + ptype_str
                                   + "' in state '" + sname + "' in: " + path);
            }

            if (!pnode["next_states"] || !pnode["next_states"].IsSequence()) {
                throw GrammarError("Pattern in state '" + sname
                                   + "' missing 'next_states' sequence in: " + path);
            }
            for (const auto& ns : pnode["next_states"]) {
                std::string ns_str = ns.as<std::string>();
                pat.next_states.push_back(ns_str);
                if (ns_str == "__end__") {
                    state.allow_eof = true;
                }
            }

            state.patterns.push_back(std::move(pat));
        }
    }

    // Validate initial_state is a declared state
    if (!grammar.states.count(grammar.initial_state)) {
        throw GrammarError("initial_state '" + grammar.initial_state
                           + "' is not a declared state in: " + path);
    }

    // Validate all next_states
    for (auto& [sname, state] : grammar.states) {
        for (auto& pat : state.patterns) {
            for (const auto& ns : pat.next_states) {
                if (ns != "__end__" && !grammar.states.count(ns)) {
                    throw GrammarError("next_state '" + ns + "' in state '"
                                       + sname + "' is not a declared state in: " + path);
                }
            }
        }
    }

    return grammar;
}
