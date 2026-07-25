#pragma once
#include "Grammar.hpp"
#include "PcapReader.hpp"

#include <string>

/// Loads a Grammar from a YAML file.
/// Throws GrammarError on parse or validation failure.
class GrammarLoader {
public:
    static Grammar load(const std::string& path);
};
