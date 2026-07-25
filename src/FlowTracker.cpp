#include "FlowTracker.hpp"
#include "StreamValidator.hpp"
#include "TcpReassembler.hpp"

struct FlowTracker::FlowEntry {
    StreamValidator validator;
    TcpReassembler  reassembler;

    FlowEntry(const Grammar& grammar, FlowKey key, Reporter& reporter)
        : validator(grammar, key,
                    [&reporter](const Violation& v){ reporter.recordViolation(v); },
                    [&reporter](const MatchInfo& m){ reporter.recordMatch(m); })
        , reassembler([this](const uint8_t* data, size_t len){
                          validator.consume(data, len);
                      })
    {}
};

FlowTracker::~FlowTracker() = default;

FlowTracker::FlowTracker(const Grammar& grammar, Reporter& reporter,
                         std::optional<uint16_t> port_filter)
    : grammar_(grammar)
    , reporter_(reporter)
    , port_filter_(port_filter)
{}

void FlowTracker::handlePacket(const PacketInfo& pkt) {
    if (port_filter_) {
        if (pkt.flow.dst_port != *port_filter_ &&
            pkt.flow.src_port != *port_filter_) {
            return;
        }
    }

    auto it = flows_.find(pkt.flow);
    if (it == flows_.end()) {
        reporter_.registerFlow();
        auto entry = std::make_unique<FlowEntry>(grammar_, pkt.flow, reporter_);
        it = flows_.emplace(pkt.flow, std::move(entry)).first;
    }

    it->second->reassembler.push(pkt.seq_num, pkt.payload,
                                  pkt.is_syn, pkt.is_fin, pkt.is_rst);
}

void FlowTracker::flushAll() {
    for (auto& [key, entry] : flows_) {
        entry->reassembler.flush();
        entry->validator.flush();
    }
}
