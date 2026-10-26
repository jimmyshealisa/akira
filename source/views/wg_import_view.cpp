#include "views/wg_import_view.hpp"

#include "core/pair_listener.hpp"
#include "core/wireguard_manager.hpp"
#include "ui/theme.hpp"

#include <borealis/core/i18n.hpp>
#include <cstdio>

using namespace brls::literals;

namespace {

std::string spaced(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); i++) {
        if (i > 0)
            out += "  ";
        out += s[i];
    }
    return out;
}

const char* statusKey(akira::wg::ImportEvent event) {
    switch (event) {
        case akira::wg::ImportEvent::Listening:
            return "akira/wg_import/status_waiting";
        case akira::wg::ImportEvent::ClientConnected:
            return "akira/wg_import/status_connecting";
        case akira::wg::ImportEvent::Imported:
            return "akira/wg_import/status_imported";
        case akira::wg::ImportEvent::BadCode:
            return "akira/wg_import/status_bad_code";
        case akira::wg::ImportEvent::Error:
        default:
            return "akira/wg_import/status_error";
    }
}

} // namespace

WgImportView::WgImportView() {
    this->inflateFromXMLRes("xml/views/wg_import.xml");

    codeLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/code"));
    addrIpLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/addrIp"));
    addrPortLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/addrPort"));
    timerLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/timer"));
    statusLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/status"));
    closeBtn = dynamic_cast<brls::Button*>(this->getView("wgimport/close"));

    if (closeBtn) {
        closeBtn->registerClickAction([](brls::View*) {
            brls::Application::popActivity();
            return true;
        });
    }

    this->registerAction("akira/common/back"_i18n, brls::ControllerButton::BUTTON_B,
        [](brls::View*) {
            brls::Application::popActivity();
            return true;
        });

    setFocusable(true);

    const auto& palette = akira::ui::active();
    std::string ip = akira::pair::PairListener::localIpv4();
    if (addrIpLabel) {
        addrIpLabel->setText(ip.empty() ? "-" : ip);
        addrIpLabel->setTextColor(palette.accent);
    }
    if (addrPortLabel) {
        addrPortLabel->setText(brls::getStr("akira/wg_import/port_fmt", listenPort));
        addrPortLabel->setTextColor(palette.warning);
    }

    startListening();
}

WgImportView::~WgImportView() {
    *alive = false;
    server.stop();
}

void WgImportView::startListening() {
    std::string code = akira::pair::PairListener::generateCode();
    if (codeLabel)
        codeLabel->setText(spaced(code));

    windowStart = std::chrono::steady_clock::now();
    lastShownSecond = -1;
    counting = true;

    auto guard = alive;
    server.start(listenPort, code, [this, guard](akira::wg::ImportEvent event) {
        brls::sync([this, guard, event]() {
            if (!*guard)
                return;
            this->onEvent(event);
        });
    });
}

void WgImportView::draw(NVGcontext* vg, float x, float y, float width, float height,
                        brls::Style style, brls::FrameContext* ctx) {
    if (counting && timerLabel) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now() - windowStart)
                           .count();
        int remaining = kWindowSeconds - static_cast<int>(elapsed);
        if (remaining < 0)
            remaining = 0;
        if (remaining != lastShownSecond) {
            lastShownSecond = remaining;
            char buf[8];
            std::snprintf(buf, sizeof(buf), "%d:%02d", remaining / 60, remaining % 60);
            timerLabel->setText(brls::getStr("akira/wg_import/timer_fmt", std::string(buf)));
        }
        if (remaining == 0) {
            // Rotate the code so a window left open does not stay valid forever.
            startListening();
            return;
        }
    }

    Box::draw(vg, x, y, width, height, style, ctx);
}

void WgImportView::onEvent(akira::wg::ImportEvent event) {
    if (event == akira::wg::ImportEvent::Imported) {
        counting = false;
        brls::Application::notify("akira/wg_import/imported"_i18n);
        brls::Application::popActivity();
        return;
    }

    if (event == akira::wg::ImportEvent::BadCode) {
        counting = false;
        if (timerLabel)
            timerLabel->setText("");
    }

    if (statusLabel)
        statusLabel->setText(brls::getStr(statusKey(event)));
}
