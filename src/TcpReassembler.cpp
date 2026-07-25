#include "TcpReassembler.hpp"

#include <iostream>
#include <cstring>

TcpReassembler::TcpReassembler(ByteConsumer on_bytes, size_t max_bytes)
    : on_bytes_(std::move(on_bytes))
    , max_bytes_(max_bytes)
{}

void TcpReassembler::push(uint32_t seq,
                          const std::vector<uint8_t>& payload,
                          bool is_syn, bool is_fin, bool is_rst) {
    if (is_syn && !syn_seen_) {
        next_expected_seq_ = seq + 1;
        syn_seen_ = true;
        return;
    }

    if (!syn_seen_) {
        return;
    }

    if (payload.empty()) {
        if (is_fin || is_rst) {
            flush();
        }
        return;
    }

    // Check size limit before inserting
    if (size_exceeded_) {
        return;
    }
    if (total_bytes_delivered_ + payload.size() > max_bytes_) {
        std::cerr << "[TcpReassembler] stream size limit exceeded (" << max_bytes_
                  << " bytes); truncating\n";
        size_exceeded_ = true;
        flush();
        return;
    }

    // Detect if this segment is entirely before next_expected_seq_ (duplicate/retransmit)
    // Use wrapping arithmetic: if (int32_t)(seq - next_expected_seq_) < 0 the entire
    // segment might still have new data starting at next_expected_seq_.
    uint32_t seg_end = seq + static_cast<uint32_t>(payload.size());

    // If the entire segment is already delivered, skip
    // seg_end <= next_expected_seq_ in wrapping arithmetic
    if (static_cast<int32_t>(seg_end - next_expected_seq_) <= 0) {
        // entirely duplicate
        if (is_fin || is_rst) {
            flush();
        }
        return;
    }

    // Trim already-delivered prefix
    std::vector<uint8_t> trimmed;
    if (static_cast<int32_t>(seq - next_expected_seq_) < 0) {
        // Partial overlap: skip bytes already delivered
        uint32_t skip = next_expected_seq_ - seq;
        trimmed.assign(payload.begin() + skip, payload.end());
        seq = next_expected_seq_;
    } else {
        trimmed = payload;
    }

    if (trimmed.empty()) {
        if (is_fin || is_rst) {
            flush();
        }
        return;
    }

    // Insert (or merge) into out_of_order_ map
    auto it = out_of_order_.find(seq);
    if (it == out_of_order_.end()) {
        out_of_order_[seq] = std::move(trimmed);
    } else if (trimmed.size() > it->second.size()) {
        // Keep the longer segment
        it->second = std::move(trimmed);
    }
    // else: existing segment is same size or longer, keep it

    drain();

    if (is_fin || is_rst) {
        flush();
    }
}

void TcpReassembler::drain() {
    while (!out_of_order_.empty()) {
        auto it = out_of_order_.begin();
        if (it->first != next_expected_seq_) {
            break;
        }
        const std::vector<uint8_t>& seg = it->second;
        on_bytes_(seg.data(), seg.size());
        total_bytes_delivered_ += seg.size();
        next_expected_seq_ += static_cast<uint32_t>(seg.size());
        out_of_order_.erase(it);
    }
}

void TcpReassembler::flush() {
    if (flushed_) {
        return;
    }
    drain();
    flushed_ = true;
}
