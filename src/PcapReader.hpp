#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <stdexcept>
#include <pcap/pcap.h>

class PcapError : public std::runtime_error {
public:
    explicit PcapError(const std::string& msg) : std::runtime_error(msg) {}
};

class GrammarError : public std::runtime_error {
public:
    explicit GrammarError(const std::string& msg) : std::runtime_error(msg) {}
};

struct FlowKey {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};

    bool operator==(const FlowKey& o) const {
        return src_ip==o.src_ip && dst_ip==o.dst_ip
            && src_port==o.src_port && dst_port==o.dst_port;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        size_t h = 0;
        auto mix = [&](size_t v){ h ^= v + 0x9e3779b9 + (h<<6) + (h>>2); };
        mix(std::hash<uint32_t>{}(k.src_ip));
        mix(std::hash<uint32_t>{}(k.dst_ip));
        mix(std::hash<uint16_t>{}(k.src_port));
        mix(std::hash<uint16_t>{}(k.dst_port));
        return h;
    }
};

struct PacketInfo {
    FlowKey              flow;
    uint32_t             seq_num{0};
    std::vector<uint8_t> payload;
    bool                 is_syn{false};
    bool                 is_fin{false};
    bool                 is_rst{false};
};

class PcapReader {
public:
    explicit PcapReader(const std::string& path);
    ~PcapReader();
    PcapReader(const PcapReader&)            = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    std::optional<PacketInfo> nextPacket();

private:
    pcap_t* handle_{nullptr};
    int     datalink_{0};
};
