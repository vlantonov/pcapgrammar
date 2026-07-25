#pragma once
#include "Grammar.hpp"
#include "PcapReader.hpp"
#include "Reporter.hpp"
#include <optional>
#include <unordered_map>
#include <memory>

class Reporter;

class FlowTracker {
public:
    FlowTracker(const Grammar& grammar, Reporter& reporter,
                std::optional<uint16_t> port_filter);
    ~FlowTracker();
    void handlePacket(const PacketInfo& pkt);
    void flushAll();

private:
    struct FlowEntry;
    const Grammar&  grammar_;
    Reporter&       reporter_;
    std::optional<uint16_t> port_filter_;
    std::unordered_map<FlowKey, std::unique_ptr<FlowEntry>, FlowKeyHash> flows_;
};
