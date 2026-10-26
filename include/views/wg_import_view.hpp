#ifndef AKIRA_WG_IMPORT_VIEW_HPP
#define AKIRA_WG_IMPORT_VIEW_HPP

#include <atomic>
#include <chrono>
#include <memory>

#include <borealis.hpp>

#include "core/wg_import_server.hpp"

/*
 * Shows the address of the on-Switch web form (EasyTier or WireGuard page) for a
 * phone / PC browser, and refreshes the WireGuard state once a config lands.
 */
class WgImportView : public brls::Box {
public:
    explicit WgImportView(akira::wg::ImportPage page = akira::wg::ImportPage::WireGuard);
    ~WgImportView() override;

    void draw(NVGcontext* vg, float x, float y, float width, float height,
              brls::Style style, brls::FrameContext* ctx) override;

    brls::View* getDefaultFocus() override { return this; }

private:
    static constexpr int kWindowSeconds = 120;

    void startListening();
    void onEvent(akira::wg::ImportEvent event);

    brls::Label* titleLabel = nullptr;
    brls::Label* instructionsLabel = nullptr;
    brls::Label* urlLabel = nullptr;
    brls::Label* codeLabel = nullptr;
    brls::Label* timerLabel = nullptr;
    brls::Label* statusLabel = nullptr;
    brls::Button* closeBtn = nullptr;

    akira::wg::ImportPage page;
    akira::wg::WgImportServer server;
    std::shared_ptr<std::atomic<bool>> alive = std::make_shared<std::atomic<bool>>(true);
    int listenPort = 18901;
    int badCodes = 0;

    std::chrono::steady_clock::time_point windowStart;
    int lastShownSecond = -1;
    bool counting = false;
};

#endif // AKIRA_WG_IMPORT_VIEW_HPP
