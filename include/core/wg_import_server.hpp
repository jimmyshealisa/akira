#ifndef AKIRA_WG_IMPORT_SERVER_HPP
#define AKIRA_WG_IMPORT_SERVER_HPP

#include <atomic>
#include <functional>
#include <string>
#include <thread>

/*
 * LAN push of a WireGuard config, companion-app style but over plain HTTP: the
 * Switch shows an address, the user opens it in any browser on a phone / PC and
 * fills in a form. Two pages:
 *   /easytier   network name + secret + VPN portal node; keys derived on device
 *   /wireguard  individual wg-quick fields, or a pasted config
 * The result is validated, written to wg0.conf and reloaded.
 *
 * The code (embedded in the served form) gates the write so a random web page
 * cannot blind-POST a config through the user's browser. Bad-code attempts are
 * limited like the companion pairing.
 */
namespace akira::wg {

enum class ImportEvent {
    Listening,
    ClientConnected,
    Imported,
    BadCode,
    Error,
};

enum class ImportPage {
    EasyTier,
    WireGuard,
};

class WgImportServer {
public:
    using EventCallback = std::function<void(ImportEvent)>;

    WgImportServer() = default;
    ~WgImportServer();

    void start(int port, const std::string& code, ImportPage defaultPage, EventCallback onEvent);
    void stop();

    static constexpr int kMaxTries = 3;
    static constexpr const char* PROFILE_PATH = "sdmc:/switch/akira/easytier.conf";

private:
    void run(int port, std::string code, ImportPage defaultPage);

    std::thread thread_;
    std::atomic<bool> running_{false};
    EventCallback onEvent_;
};

} // namespace akira::wg

#endif // AKIRA_WG_IMPORT_SERVER_HPP
