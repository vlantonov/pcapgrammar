#include "StreamValidator.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>

StreamValidator::StreamValidator(const Grammar& grammar,
                                 FlowKey        flow_key,
                                 ViolationCallback on_violation,
                                 MatchCallback     on_match)
    : grammar_(grammar)
    , flow_key_(flow_key)
    , on_violation_(std::move(on_violation))
    , on_match_(std::move(on_match))
    , current_state_(grammar.initial_state)
{}

void StreamValidator::consume(const uint8_t* data, size_t len) {
    buffer_.insert(buffer_.end(), data, data + len);

    while (!done_) {
        auto msg = extractMessage();
        if (!msg) {
            break;
        }
        processMessage(*msg);
    }
}

uint32_t StreamValidator::readBigEndian(const uint8_t* data, uint8_t nbytes) {
    uint32_t val = 0;
    for (uint8_t i = 0; i < nbytes; ++i) {
        val = (val << 8) | data[i];
    }
    return val;
}

std::optional<std::vector<uint8_t>> StreamValidator::extractMessage() {
    if (buffer_.empty()) {
        return std::nullopt;
    }

    const FramingConfig& fc = grammar_.framing;

    if (fc.type == FramingType::LINE) {
        // Scan for newline
        auto it = std::find(buffer_.begin(), buffer_.end(), uint8_t('\n'));
        if (it == buffer_.end()) {
            return std::nullopt;
        }

        // Extract line content (strip trailing \r if present)
        auto line_end = it;
        size_t consumed = static_cast<size_t>(it - buffer_.begin()) + 1; // includes \n

        std::vector<uint8_t> msg(buffer_.begin(), line_end);
        if (!msg.empty() && msg.back() == uint8_t('\r')) {
            msg.pop_back();
        }

        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(consumed));
        byte_offset_ += consumed;

        return msg;

    } else if (fc.type == FramingType::LENGTH_PREFIXED) {
        uint8_t pb = fc.prefix_bytes;
        if (buffer_.size() < pb) {
            return std::nullopt;
        }

        uint32_t msg_len = readBigEndian(buffer_.data(), pb);
        size_t total = static_cast<size_t>(pb) + static_cast<size_t>(msg_len);
        if (buffer_.size() < total) {
            return std::nullopt;
        }

        std::vector<uint8_t> msg(buffer_.begin() + pb,
                                 buffer_.begin() + static_cast<ptrdiff_t>(total));
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(total));
        byte_offset_ += total;

        return msg;

    } else { // TLV
        uint8_t tb = fc.type_bytes;
        uint8_t lb = fc.length_bytes;
        size_t header_size = static_cast<size_t>(tb) + static_cast<size_t>(lb);

        if (buffer_.size() < header_size) {
            return std::nullopt;
        }

        // Skip type field, read length field
        uint32_t val_len = readBigEndian(buffer_.data() + tb, lb);
        size_t total = header_size + static_cast<size_t>(val_len);
        if (buffer_.size() < total) {
            return std::nullopt;
        }

        // Extract value field only
        std::vector<uint8_t> msg(buffer_.begin() + static_cast<ptrdiff_t>(header_size),
                                 buffer_.begin() + static_cast<ptrdiff_t>(total));
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<ptrdiff_t>(total));
        byte_offset_ += total;

        return msg;
    }
}

bool StreamValidator::matchPattern(const Pattern& pat,
                                   const std::vector<uint8_t>& msg) const {
    std::string s(msg.begin(), msg.end());
    if (pat.ptype == PatternType::LITERAL) {
        return s == pat.match_str;
    } else {
        return std::regex_search(s, pat.compiled);
    }
}

static std::string makeExcerpt(const std::vector<uint8_t>& msg) {
    std::string result;
    result.reserve(128);
    for (uint8_t b : msg) {
        if (result.size() >= 128) {
            break;
        }
        if (std::isprint(static_cast<unsigned char>(b))) {
            result.push_back(static_cast<char>(b));
        } else {
            result.push_back('.');
        }
    }
    return result;
}

void StreamValidator::processMessage(const std::vector<uint8_t>& msg) {
    // byte_offset_ has already been advanced by extractMessage()
    // We report the offset at the start of this message:
    // The offset after advancing is the END of this message, so start = offset - consumed.
    // We track offset as running total so we need the start-of-message offset.
    // Since extractMessage already advanced byte_offset_, we store the offset before the call.
    // To fix this cleanly we need the pre-extraction offset. Let's compute it here.
    // Actually we've already advanced byte_offset_ before calling processMessage.
    // The start offset is byte_offset_ - (msg.size() + overhead).
    // overhead = consumed_bytes - msg.size().
    // For LINE: consumed = msg.size() + 1 (or +2 for CRLF already stripped).
    // But msg is already stripped; let's just report byte_offset_ as current end and
    // use (byte_offset_ - consumed) as start. We don't have consumed here easily.
    //
    // Simpler approach: report byte_offset_ as the offset of the NEXT message start
    // (i.e., current end of consumed). The spec says "byte offset" without strict definition.
    // We'll report byte_offset_ (the offset at start of the message would require storing
    // pre-extraction value). Let's report it as the offset BEFORE this message which is
    // stored in a field.
    //
    // We track this via a separate field updated before extractMessage is called.

    auto it_state = grammar_.states.find(current_state_);
    if (it_state == grammar_.states.end()) {
        // Unknown state — shouldn't happen, reset
        current_state_ = grammar_.initial_state;
        return;
    }
    const State& state = it_state->second;

    for (const auto& pat : state.patterns) {
        if (matchPattern(pat, msg)) {
            // Transition
            std::string next = pat.next_states.empty() ? "__end__" : pat.next_states[0];

            if (on_match_) {
                MatchInfo m;
                m.flow        = flow_key_;
                m.byte_offset = byte_offset_;
                m.state_name  = current_state_;
                m.pattern_str = pat.match_str;
                on_match_(m);
            }

            if (next == "__end__") {
                done_ = true;
                current_state_ = "__end__";
            } else {
                current_state_ = next;
            }
            return;
        }
    }

    // No pattern matched → violation
    Violation v;
    v.flow             = flow_key_;
    v.byte_offset      = byte_offset_;
    v.state_name       = current_state_;
    v.message_excerpt  = makeExcerpt(msg);
    v.is_premature_eof = false;
    if (on_violation_) {
        on_violation_(v);
    }

    // Reset to initial state
    current_state_ = grammar_.initial_state;
}

void StreamValidator::flush() {
    if (done_) {
        return;
    }

    // Check if current state allows EOF
    auto it = grammar_.states.find(current_state_);
    if (it != grammar_.states.end() && it->second.allow_eof) {
        return;
    }

    // Emit premature-EOF violation
    Violation v;
    v.flow             = flow_key_;
    v.byte_offset      = byte_offset_;
    v.state_name       = current_state_;
    v.message_excerpt  = "";
    v.is_premature_eof = true;
    if (on_violation_) {
        on_violation_(v);
    }
}
