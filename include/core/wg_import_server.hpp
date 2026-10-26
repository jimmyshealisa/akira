#ifndef AKIRA_WG_IMPORT_SERVER_HPP
#define AKIRA_WG_IMPORT_SERVER_HPP

#include <atomic>
#include <functional>
#include <string>
#include <thread>

/*
 * LAN push of a WireGuard config, companion-app style but over plain HTTP: the
 * Switch shows an address plus a short code, the user opens it in any browser on
 * a phone / PC, pastes the wg-quick config EasyTier generated and submits. The
 * config is validated lightly, written to wg0.conf and reloaded.
 *
 * The code gates the write because anyone on the LAN could otherwise replace the
 * tunnel config. Bad-code attempts are limited like the companion pairing.
 */
namespace akira::wg {

enum class ImportEvent {
    Listening,
    ClientConnected,
    Imported,
    BadCode,
    Error,
};

class WgImportServer {
public:
    using EventCallback = std::function<void(ImportEvent)>;

    WgImportServer() = default;
    ~WgImportServer();

    void start(int port, const std::string& code, EventCallback onEvent);
    void stop();

    static constexpr int kMaxTries = 3;

private:
    void run(int port, std::string code);

    std::thread thread_;
    std::atomic<bool> running_{false};
    EventCallback onEvent_;
};

} // namespace akira::wg

#endif // AKIRA_WG_IMPORT_SERVER_HPP
