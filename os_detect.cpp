#include <tins/tins.h>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>

using namespace std;
using namespace Tins;

// Мьютекс для синхронизации вывода в консоль (чтобы строки не перемешивались)
mutex output_mutex;

// Счетчик активных потоков
atomic<int> active_threads(0);

/**
 * Простейшее определение ОС по TCP Window Size.
 * Это лишь базовый метод, в реальности лучше использовать набор параметров TCP/IP.
 */
string guess_os(const IP& ip_pkt, const TCP& tcp_pkt) {
    uint16_t window_size = tcp_pkt.window();

    // Простая таблица соответствий
    if (window_size == 64240 || window_size == 65535) return "Windows (XP/7/10/Server)";
    if (window_size == 5840 || window_size == 29200) return "Linux (Ubuntu/Debian/Arch)";
    if (window_size == 8760) return "Oracle Solaris";

    return "Unknown";
}

/**
 * Сканирование одного IP-адреса
 */
void scan_host(const string& target_ip) {
    try {
        // Получаем интерфейс по умолчанию
        NetworkInterface iface = NetworkInterface::default_interface();
        IPv4Address src_ip = iface.addresses().ip_addr;

        PacketSender sender;

        // Создаем TCP SYN пакет
        TCP tcp = TCP(80, 40000); // порт 80, исходный порт 40000
        tcp.set_flag(TCP::SYN, 1);

        // Формируем IP+TCP пакет
        IP ip = IP(target_ip, src_ip) / tcp;

        // Отправляем пакет и ждем ответ
        PDU* response = sender.send_recv(ip, iface);

        if (response) {
            // Извлекаем IP и TCP заголовки из ответа
            const IP& ip_resp = response->rfind_pdu<IP>();
            const TCP& tcp_resp = response->rfind_pdu<TCP>();

            // Определяем ОС
            string os = guess_os(ip_resp, tcp_resp);

            // Вывод результата
            lock_guard<mutex> lock(output_mutex);
            cout << target_ip << " - " << os << endl;
        }

        delete response;
    } catch (...) {
        // Игнорируем ошибки
    }

    // Уменьшаем счетчик активных потоков
    active_threads--;
}

/**
 * Главная функция
 */
int main() {
    string base_ip = "192.168.0."; // базовый адрес сети
    int start = 1, end = 20;            // диапазон адресов
    int max_threads = 10;               // максимальное количество потоков

    for (int i = start; i <= end; i++) {
        string ip = base_ip + to_string(i);

        // Ждем, пока количество потоков уменьшится
        while (active_threads >= max_threads) {
            this_thread::sleep_for(chrono::milliseconds(50));
        }

        // Запускаем новый поток
        active_threads++;
        thread(scan_host, ip).detach();
    }

    // Ждем завершения всех потоков
    while (active_threads > 0) {
        this_thread::sleep_for(chrono::milliseconds(100));
    }

    return 0;
}
