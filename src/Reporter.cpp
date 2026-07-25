#include "Reporter.hpp"

#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/in.h>

Reporter::Reporter(bool verbose)
    : verbose_(verbose)
{}

std::string Reporter::flowStr(const FlowKey& k) {
    // IP stored as host byte order uint32_t — convert to in_addr for inet_ntoa
    struct in_addr src_addr{}, dst_addr{};
    src_addr.s_addr = htonl(k.src_ip);
    dst_addr.s_addr = htonl(k.dst_ip);

    std::string src_str = inet_ntoa(src_addr);
    std::string dst_str = inet_ntoa(dst_addr);

    return src_str + ":" + std::to_string(k.src_port)
         + "->" + dst_str + ":" + std::to_string(k.dst_port);
}

void Reporter::recordViolation(const Violation& v) {
    violations_.push_back(v);
    std::cout << "VIOLATION flow=" << flowStr(v.flow)
              << " offset=" << v.byte_offset
              << " state=" << v.state_name
              << " msg=" << v.message_excerpt
              << "\n";
}

void Reporter::recordMatch(const MatchInfo& m) {
    if (!verbose_) {
        return;
    }
    matches_.push_back(m);
    std::cout << "MATCH     flow=" << flowStr(m.flow)
              << " offset=" << m.byte_offset
              << " state=" << m.state_name
              << " pattern=" << m.pattern_str
              << "\n";
}

void Reporter::registerFlow() {
    ++flows_;
}

void Reporter::printSummary() const {
    std::cout << "Summary: flows=" << flows_
              << " violations=" << violations_.size()
              << "\n";
}

int Reporter::exitCode() const {
    return violations_.empty() ? 0 : 1;
}

size_t Reporter::totalFlows() const {
    return flows_;
}

size_t Reporter::totalViolations() const {
    return violations_.size();
}
