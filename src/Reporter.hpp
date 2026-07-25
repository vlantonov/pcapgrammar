#pragma once
#include "PcapReader.hpp"
#include <string>
#include <vector>
#include <cstddef>

struct Violation {
    FlowKey     flow;
    size_t      byte_offset{0};
    std::string state_name;
    std::string message_excerpt;  // <= 128 printable bytes
    bool        is_premature_eof{false};
};

struct MatchInfo {
    FlowKey     flow;
    size_t      byte_offset{0};
    std::string state_name;
    std::string pattern_str;
};

class Reporter {
public:
    explicit Reporter(bool verbose);

    void recordViolation(const Violation& v);
    void recordMatch(const MatchInfo& m);   // no-op if !verbose_
    void registerFlow();
    void printSummary() const;
    int  exitCode() const;
    size_t totalFlows()      const;
    size_t totalViolations() const;

private:
    bool verbose_;
    size_t flows_{0};
    std::vector<Violation> violations_;
    std::vector<MatchInfo> matches_;

    static std::string flowStr(const FlowKey& k);
};
