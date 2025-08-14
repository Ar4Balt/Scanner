#include <tins/tins.h>
#include <iostream>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <atomic>

using namespace Tins;
std::mutex print_mutex;
std::mutex queue_mutex;

struct Fingerprint {
    int ttl;
    int window;
    std::string os;
};

std::string detect_os(int ttl, int window) {
    static std::vector<Fingerprint> signatures = {
        {128, 64240, "Windows 10/11"},
        {128, 65535, "Windows Server 2016+"},
        {128, 8192,  "Windows XP/2003"},
        {64, 29200,  "Linux (Ubuntu/Debian)"},
        {64, 5840,   "Linux (старые ядра)"},
        {64, 65535,  "macOS"},
    };
    for (const auto& sig : signatures) {
        if (sig.ttl == ttl && sig.window == window) {
            return sig.os;
        }
    }
    return "Неизвестная ОС";
}

void scan_worker(std::queue<std::string>& targets, uint16_t port, std::atomic<bool>& done) {
    PacketSender sender;
    NetworkInterface iface = NetworkInterface::default_interface();

    while (true) {
        std::string ip;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (targets.empty()) break;
            ip = targets.front();
            targets.pop();
        }

        IP pkt = IP(ip) / TCP(port, TCP::SYN);
        sender.send(pkt);

        SnifferConfiguration config;
        config.set_filter("tcp and src host " + ip + " and src port " + std::to_string(port) + " and tcp[13] & 18 == 18");
        config.set_promisc_mode(true);
        config.set_timeout(1000); // 1 секунда

        try {
            Sniffer sniffer(iface.name(), config);
            auto packet = sniffer.next_packet();
            if (!packet) continue;

            const IP& ip_resp = packet.pdu()->rfind_pdu<IP>();
            const TCP& tcp_resp = packet.pdu()->rfind_pdu<TCP>();

            int ttl = ip_resp.ttl();
            int window = tcp_resp.window();
            std::string os = detect_os(ttl, window);

            {
                std::lock_guard<std::mutex> lock(print_mutex);
                std::cout << ip << " | TTL: " << ttl << " | Win: " << window << " | ОС: " << os << "\n";
            }
        } catch (...) {}
    }
    done = true;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cout << "Использование: " << argv[0] << " <start_ip> <end_ip> <порт> <потоки>\n";
        return 1;
    }

    std::string start_ip = argv[1];
    std::string end_ip = argv[2];
    uint16_t port = std::stoi(argv[3]);
    int threads_count = std::stoi(argv[4]);

    auto ip_to_int = [](const std::string& ip) {
        unsigned int b1, b2, b3, b4;
        sscanf(ip.c_str(), "%u.%u.%u.%u", &b1, &b2, &b3, &b4);
        return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    };
    auto int_to_ip = [](unsigned int ip) {
        return std::to_string((ip >> 24) & 0xFF) + "." +
               std::to_string((ip >> 16) & 0xFF) + "." +
               std::to_string((ip >> 8) & 0xFF) + "." +
               std::to_string(ip & 0xFF);
    };

    unsigned int start = ip_to_int(start_ip);
    unsigned int end = ip_to_int(end_ip);

    std::queue<std::string> targets;
    for (unsigned int ip = start; ip <= end; ++ip) {
        targets.push(int_to_ip(ip));
    }

    std::vector<std::thread> threads;
    std::atomic<bool> done(false);

    for (int i = 0; i < threads_count; ++i) {
        threads.emplace_back(scan_worker, std::ref(targets), port, std::ref(done));
    }
    for (auto& t : threads) t.join();

    return 0;
}
