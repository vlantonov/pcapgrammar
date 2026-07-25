#pragma once
#include "Grammar.hpp"
#include "Reporter.hpp"
#include "PcapReader.hpp"
#include <functional>
#include <vector>
#include <optional>

using ViolationCallback = std::function<void(const Violation&)>;
using MatchCallback     = std::function<void(const MatchInfo&)>;

class StreamValidator {
public:
    StreamValidator(const Grammar& grammar,
                    FlowKey        flow_key,
                    ViolationCallback on_violation,
                    MatchCallback     on_match);

    void consume(const uint8_t* data, size_t len);
    void flush();

private:
    const Grammar&    grammar_;
    FlowKey           flow_key_;
    ViolationCallback on_violation_;
    MatchCallback     on_match_;
    std::string       current_state_;
    std::vector<uint8_t> buffer_;
    size_t            byte_offset_{0};
    bool              done_{false};   // set when FSM transitioned to __end__

    std::optional<std::vector<uint8_t>> extractMessage();
    void processMessage(const std::vector<uint8_t>& msg);
    bool matchPattern(const Pattern& pat, const std::vector<uint8_t>& msg) const;

    // Framing overhead for byte offset tracking
    size_t framingOverhead(size_t msg_len) const;

    // helper: read big-endian uint from bytes
    static uint32_t readBigEndian(const uint8_t* data, uint8_t nbytes);
};
