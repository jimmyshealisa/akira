#ifndef AKIRA_WG_IMPORT_VIEW_HPP
#define AKIRA_WG_IMPORT_VIEW_HPP

#include <atomic>
#include <chrono>
#include <memory>

#include <borealis.hpp>

#include "core/wg_import_server.hpp"

/*
 * Shows the Switch address + one-time code for pushing a WireGuard config from a
 * phone / PC browser, and refreshes the WireGuard state once a config lands.
 */
class WgImportView : public brls::Box {
public:
    WgImportView();
    ~WgImportView() override;

    void draw(NVGcontext* vg, float x, float y, float width, float height,
              brls::Style style, brls::FrameContext* ctx) override;

    brls::View* getDefaultFocus() override { return this; }

private:
    static constexpr int kWindowSeconds = 120;

    void startListening();
    void onEvent(akira::wg::ImportEvent event);

    brls::Label* codeLabel = nullptr;
    brls::Label* addrIpLabel = nullptr;
    brls::Label* addrPortLabel = nullptr;
    brls::Label* timerLabel = nullptr;
    brls::Label* statusLabel = nullptr;
    brls::Button* closeBtn = nullptr;

    akira::wg::WgImportServer server;
    std::shared_ptr<std::atomic<bool>> alive = std::make_shared<std::atomic<bool>>(true);
    int listenPort = 18901;

    std::chrono::steady_clock::time_point windowStart;
    int lastShownSecond = -1;
    bool counting = false;
};

#endif // AKIRA_WG_IMPORT_VIEW_HPP
