#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <map>
#include <vector>

using ByteConsumer = std::function<void(const uint8_t* data, size_t len)>;

class TcpReassembler {
public:
    static constexpr size_t kMaxStreamBytes = 64ULL * 1024 * 1024;

    explicit TcpReassembler(ByteConsumer on_bytes,
                            size_t max_bytes = kMaxStreamBytes);
    void push(uint32_t seq, const std::vector<uint8_t>& payload,
              bool is_syn, bool is_fin, bool is_rst);
    void flush();

private:
    ByteConsumer on_bytes_;
    size_t       max_bytes_;
    uint32_t     next_expected_seq_{0};
    bool         syn_seen_{false};
    size_t       total_bytes_delivered_{0};
    bool         size_exceeded_{false};
    bool         flushed_{false};
    std::map<uint32_t, std::vector<uint8_t>> out_of_order_;

    void drain();
};
