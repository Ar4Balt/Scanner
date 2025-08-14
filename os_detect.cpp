#include <tins/tins.h>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>

using namespace Tins;
using namespace std;
mutex output_mutex;
atomic<int> active_threads(0);

string guess_os(const IP& ip_pkt, const TCP& tcp_pkt) {
    uint16_t window_size = tcp_pkt.window();
    if (window_size == 64240 || window_size == 65535) return "Windows (XP/7/10/Server)";
    if (window_size == 5840 || window_size == 29200) return "Linux (Ubuntu/Debian/Arch)";
    if (window_size == 8760) return "Oracle Solaris";
    return "Unknown";
}

void scan_host(const string& target_ip) {
    try {
        NetworkInterface iface = NetworkInterface::default_interface();
        IPv4Address src_ip = iface.addresses().ip_addr;
        PacketSender sender;

        TCP tcp = TCP(80, 40000);
        tcp.set_flag(TCP::SYN, 1);
        IP ip = IP(target_ip, src_ip) / tcp;

        PDU* response = sender.send_recv(ip, iface);
        if (response) {
            const IP& ip_resp = response->rfind_pdu<IP>();
            const TCP& tcp_resp = response->rfind_pdu<TCP>();
            string os = guess_os(ip_resp, tcp_resp);

            lock_guard<mutex> lock(output_mutex);
            cout << target_ip << " - " << os << endl;
        }
        delete response;
    } catch (...) {}
    active_threads--;
}

int main() {
    string base_ip = "192.168.0.";
    int start = 1, end = 20;
    int max_threads = 10;

    for (int i = start; i <= end; i++) {
        string ip = base_ip + to_string(i);
        while (active_threads >= max_threads) {
            this_thread::sleep_for(chrono::milliseconds(50));
        }
        active_threads++;
        thread(scan_host, ip).detach();
    }

    while (active_threads > 0) {
        this_thread::sleep_for(chrono::milliseconds(100));
    }
    return 0;
}
