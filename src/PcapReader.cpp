#include "PcapReader.hpp"

#include <cstring>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace {

constexpr int  kEtherHeaderLen = 14;
constexpr int  kEtherTypeIPv4  = 0x0800;
constexpr uint8_t kProtoTCP    = 6;
constexpr uint8_t kFlagFIN     = 0x01;
constexpr uint8_t kFlagSYN     = 0x02;
constexpr uint8_t kFlagRST     = 0x04;

} // namespace

PcapReader::PcapReader(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    handle_ = pcap_open_offline(path.c_str(), errbuf);
    if (!handle_) {
        throw PcapError(std::string("pcap_open_offline failed: ") + errbuf);
    }
    datalink_ = pcap_datalink(handle_);
    if (datalink_ != DLT_EN10MB) {
        pcap_close(handle_);
        handle_ = nullptr;
        throw PcapError("Unsupported link-layer type; only Ethernet (DLT_EN10MB) is supported");
    }
}

PcapReader::~PcapReader() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

std::optional<PacketInfo> PcapReader::nextPacket() {
    while (true) {
        struct pcap_pkthdr* header = nullptr;
        const uint8_t*      data   = nullptr;

        int ret = pcap_next_ex(handle_, &header, &data);
        if (ret == PCAP_ERROR_BREAK || ret == 0) {
            // EOF or timeout with no packet
            return std::nullopt;
        }
        if (ret < 0) {
            // Error reading
            return std::nullopt;
        }
        if (!data || header->caplen < static_cast<bpf_u_int32>(kEtherHeaderLen)) {
            continue; // too short
        }

        // Parse Ethernet header — check EtherType
        uint16_t ethertype = static_cast<uint16_t>(
            (data[12] << 8) | data[13]);
        if (ethertype != kEtherTypeIPv4) {
            continue;
        }

        const uint8_t* ip = data + kEtherHeaderLen;
        uint32_t remaining = header->caplen - kEtherHeaderLen;

        if (remaining < 20) {
            continue; // too short for minimum IPv4 header
        }

        uint8_t ihl_byte = ip[0];
        int ip_hdr_len = (ihl_byte & 0x0F) * 4;
        if (ip_hdr_len < 20 || static_cast<uint32_t>(ip_hdr_len) > remaining) {
            continue;
        }

        uint8_t proto = ip[9];
        if (proto != kProtoTCP) {
            continue;
        }

        uint16_t ip_total_len = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
        if (ip_total_len < static_cast<uint16_t>(ip_hdr_len)) {
            continue;
        }

        uint32_t src_ip = (static_cast<uint32_t>(ip[12]) << 24) |
                          (static_cast<uint32_t>(ip[13]) << 16) |
                          (static_cast<uint32_t>(ip[14]) <<  8) |
                           static_cast<uint32_t>(ip[15]);
        uint32_t dst_ip = (static_cast<uint32_t>(ip[16]) << 24) |
                          (static_cast<uint32_t>(ip[17]) << 16) |
                          (static_cast<uint32_t>(ip[18]) <<  8) |
                           static_cast<uint32_t>(ip[19]);

        const uint8_t* tcp = ip + ip_hdr_len;
        uint32_t tcp_remaining = remaining - static_cast<uint32_t>(ip_hdr_len);
        if (tcp_remaining < 20) {
            continue; // too short for minimum TCP header
        }

        uint16_t src_port = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
        uint16_t dst_port = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);

        uint32_t seq_num = (static_cast<uint32_t>(tcp[4]) << 24) |
                           (static_cast<uint32_t>(tcp[5]) << 16) |
                           (static_cast<uint32_t>(tcp[6]) <<  8) |
                            static_cast<uint32_t>(tcp[7]);

        uint8_t data_offset_byte = tcp[12];
        int tcp_hdr_len = ((data_offset_byte >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20 || static_cast<uint32_t>(tcp_hdr_len) > tcp_remaining) {
            continue;
        }

        uint8_t flags = tcp[13];
        bool is_syn = (flags & kFlagSYN) != 0;
        bool is_fin = (flags & kFlagFIN) != 0;
        bool is_rst = (flags & kFlagRST) != 0;

        // Payload length based on IP total length field (more reliable than caplen)
        int payload_len = static_cast<int>(ip_total_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len < 0) {
            payload_len = 0;
        }

        const uint8_t* payload_start = tcp + tcp_hdr_len;
        uint32_t available = tcp_remaining - static_cast<uint32_t>(tcp_hdr_len);
        size_t actual_len = std::min(static_cast<size_t>(payload_len),
                                     static_cast<size_t>(available));

        PacketInfo pkt;
        pkt.flow.src_ip   = src_ip;
        pkt.flow.dst_ip   = dst_ip;
        pkt.flow.src_port = src_port;
        pkt.flow.dst_port = dst_port;
        pkt.seq_num  = seq_num;
        pkt.is_syn   = is_syn;
        pkt.is_fin   = is_fin;
        pkt.is_rst   = is_rst;
        if (actual_len > 0) {
            pkt.payload.assign(payload_start, payload_start + actual_len);
        }

        return pkt;
    }
}
