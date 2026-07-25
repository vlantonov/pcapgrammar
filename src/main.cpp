#include "GrammarLoader.hpp"
#include "PcapReader.hpp"
#include "Reporter.hpp"
#include "FlowTracker.hpp"

#include <getopt.h>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

static void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog
              << " --pcap <file.pcap> --grammar <grammar.yaml>"
              << " [--port <N>] [--verbose]\n";
}

int main(int argc, char** argv) {
    std::string pcap_path;
    std::string grammar_path;
    std::optional<uint16_t> port_filter;
    bool verbose = false;

    static const struct option long_opts[] = {
        {"pcap",    required_argument, nullptr, 'p'},
        {"grammar", required_argument, nullptr, 'g'},
        {"port",    required_argument, nullptr, 'P'},
        {"verbose", no_argument,       nullptr, 'v'},
        {nullptr,   0,                 nullptr,  0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'p': pcap_path    = optarg; break;
            case 'g': grammar_path = optarg; break;
            case 'P': {
                int p = std::atoi(optarg);
                if (p <= 0 || p > 65535) {
                    std::cerr << "Error: --port must be in [1, 65535]\n";
                    return 2;
                }
                port_filter = static_cast<uint16_t>(p);
                break;
            }
            case 'v': verbose = true; break;
            default:
                printUsage(argv[0]);
                return 2;
        }
    }

    if (pcap_path.empty() || grammar_path.empty()) {
        printUsage(argv[0]);
        return 2;
    }

    Grammar grammar;
    try {
        grammar = GrammarLoader::load(grammar_path);
    } catch (const GrammarError& e) {
        std::cerr << "Grammar error: " << e.what() << "\n";
        return 2;
    }

    Reporter reporter(verbose);
    std::unique_ptr<PcapReader> reader;
    try {
        reader = std::make_unique<PcapReader>(pcap_path);
    } catch (const PcapError& e) {
        std::cerr << "PCAP error: " << e.what() << "\n";
        return 2;
    }

    FlowTracker tracker(grammar, reporter, port_filter);

    try {
        while (auto pkt = reader->nextPacket()) {
            tracker.handlePacket(*pkt);
        }
    } catch (const PcapError& e) {
        std::cerr << "PCAP read error: " << e.what() << "\n";
        return 2;
    }

    tracker.flushAll();
    reporter.printSummary();

    return reporter.exitCode();
}
