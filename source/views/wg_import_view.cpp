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
            out += " ";
        out += s[i];
    }
    return out;
}

} // namespace

WgImportView::WgImportView(akira::wg::ImportPage page) : page(page) {
    this->inflateFromXMLRes("xml/views/wg_import.xml");

    titleLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/title"));
    instructionsLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/instructions"));
    urlLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/url"));
    codeLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/code"));
    timerLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/timer"));
    statusLabel = dynamic_cast<brls::Label*>(this->getView("wgimport/status"));
    closeBtn = dynamic_cast<brls::Button*>(this->getView("wgimport/close"));

    bool easytier = page == akira::wg::ImportPage::EasyTier;
    if (titleLabel)
        titleLabel->setText(easytier ? "akira/wg_import/title_easytier"_i18n : "akira/wg_import/title"_i18n);
    if (instructionsLabel)
        instructionsLabel->setText(easytier ? "akira/wg_import/instructions_easytier"_i18n
                                            : "akira/wg_import/instructions"_i18n);

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
    if (urlLabel) {
        if (ip.empty()) {
            urlLabel->setText("akira/wg_import/no_network"_i18n);
            urlLabel->setTextColor(palette.danger);
        } else {
            urlLabel->setText("http://" + ip + ":" + std::to_string(listenPort) +
                              (easytier ? "/easytier" : "/wireguard"));
            urlLabel->setTextColor(palette.accent);
        }
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
        codeLabel->setText(brls::getStr("akira/wg_import/code_fmt", spaced(code)));

    windowStart = std::chrono::steady_clock::now();
    lastShownSecond = -1;
    counting = true;
    badCodes = 0;

    auto guard = alive;
    server.start(listenPort, code, page, [this, guard](akira::wg::ImportEvent event) {
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
            // Nobody opened the page: rotate the code so an idle screen does not
            // stay valid forever.
            startListening();
            return;
        }
    }

    Box::draw(vg, x, y, width, height, style, ctx);
}

void WgImportView::onEvent(akira::wg::ImportEvent event) {
    using akira::wg::ImportEvent;

    switch (event) {
        case ImportEvent::Imported:
            counting = false;
            brls::Application::notify("akira/wg_import/imported"_i18n);
            brls::Application::popActivity();
            return;

        case ImportEvent::ClientConnected:
            // The browser has the form (with this code); keep the code stable
            // while the user fills it in, however long that takes.
            counting = false;
            if (timerLabel)
                timerLabel->setText("");
            if (statusLabel)
                statusLabel->setText("akira/wg_import/status_connecting"_i18n);
            return;

        case ImportEvent::BadCode:
            badCodes++;
            if (statusLabel)
                statusLabel->setText(badCodes >= akira::wg::WgImportServer::kMaxTries
                                         ? "akira/wg_import/status_bad_code"_i18n
                                         : "akira/wg_import/status_bad_code_retry"_i18n);
            return;

        case ImportEvent::Listening:
            if (statusLabel)
                statusLabel->setText("akira/wg_import/status_waiting"_i18n);
            return;

        case ImportEvent::Error:
        default:
            if (statusLabel)
                statusLabel->setText("akira/wg_import/status_error"_i18n);
            return;
    }
}
