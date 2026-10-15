#include "views/psn_browser_login_view.hpp"

#include "core/profile.hpp"
#include "core/settings_manager.hpp"
#include "psn/auth_bootstrap.hpp"
#include "ui/theme.hpp"
#include "util/http_pool.hpp"
#include "views/pair_view.hpp"
#include "views/qr_code_view.hpp"

#include <borealis/core/i18n.hpp>

using namespace brls::literals;

namespace {

// Big enough for a pasted redirect URL; the bare code is only a handful of characters.
constexpr int kInputMaxLength = 256;
// The ~590-byte authorize URL lands on QR version 16-17 (81-85 modules + quiet zone),
// so 500 px keeps every module at 5 px.
constexpr float kQrSize = 500.0f;

} // namespace

PsnBrowserLoginView::PsnBrowserLoginView(bool createProfile) : createProfile(createProfile) {
    this->inflateFromXMLRes("xml/views/psn_browser_login.xml");

    SettingsManager* settings = SettingsManager::getInstance();
    const Profile* active = settings->getActiveProfile();

    // Mirrors PairView::applyCredentials: a legacy profile cannot be upgraded in place.
    if (!createProfile && active && active->legacy)
        blocked = true;

    // A new profile gets a new DUID; an existing one keeps its own so its console
    // registrations and holepunch identity stay valid.
    const bool reuseDuid = !createProfile && active;
    request = psn::browser_login::begin(reuseDuid ? settings->getGlobalDuid() : std::string());

    qrView = new QrCodeView(kQrSize);
    if (qrSlot)
        qrSlot->addView(qrView);

    if (blocked) {
        setStatus("akira/pair/mode_mismatch"_i18n, StatusTone::Error);
    } else if (request.authorizeUrl.empty() || !qrView->setContent(request.authorizeUrl)) {
        blocked = true;
        setStatus("akira/psn_login/status_qr_failed"_i18n, StatusTone::Error);
    }

    if (enterBtn) {
        enterBtn->registerClickAction([this](brls::View*) {
            askForCode();
            return true;
        });
    }

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
}

PsnBrowserLoginView::~PsnBrowserLoginView() {
    *alive = false;
}

brls::View* PsnBrowserLoginView::getDefaultFocus() {
    if (enterBtn && !blocked)
        return enterBtn;
    if (closeBtn)
        return closeBtn;
    return brls::Box::getDefaultFocus();
}

void PsnBrowserLoginView::setStatus(const std::string& text, StatusTone tone) {
    if (!statusLabel)
        return;

    const auto& palette = akira::ui::active();
    statusLabel->setText(text);
    switch (tone) {
        case StatusTone::Busy:
            statusLabel->setTextColor(palette.accent);
            break;
        case StatusTone::Error:
            statusLabel->setTextColor(palette.danger);
            break;
        case StatusTone::Muted:
        default:
            statusLabel->setTextColor(palette.textMuted);
            break;
    }
}

void PsnBrowserLoginView::askForCode() {
    if (blocked || busy)
        return;

    brls::Application::getImeManager()->openForText(
        [this](std::string text) {
            if (text.empty())
                return;
            submit(text);
        },
        "akira/psn_login/enter_code"_i18n, "akira/psn_login/enter_code_hint"_i18n,
        kInputMaxLength, lastInput, 0);
}

void PsnBrowserLoginView::submit(const std::string& input) {
    lastInput = input;

    // Reject typos locally instead of spending one of Sony's short-lived code redemptions.
    if (psn::bootstrap::extractAuthCodeFromInput(input).empty()) {
        setStatus("akira/psn_login/status_bad_input"_i18n, StatusTone::Error);
        return;
    }

    busy = true;
    setStatus("akira/psn_login/status_signing_in"_i18n, StatusTone::Busy);

    auto guard = alive;
    psn::browser_login::Request req = request;
    HttpPool::instance().submit([this, guard, req, input](HttpSession& session) {
        psn::browser_login::Result result = psn::browser_login::complete(session, req, input);
        brls::sync([this, guard, result]() {
            if (!*guard)
                return;
            onResult(result);
        });
    });
}

void PsnBrowserLoginView::onResult(const psn::browser_login::Result& result) {
    busy = false;

    if (!result.success) {
        // invalid_grant almost always means the code expired or was already used.
        const bool expired = result.message.find("invalid_grant") != std::string::npos;
        std::string text = expired
            ? "akira/psn_login/status_code_expired"_i18n
            : brls::getStr("akira/psn_login/status_failed_fmt", result.message);
        setStatus(text, StatusTone::Error);
        return;
    }

    PairView::applyCredentials(result.credentials, createProfile);

    const std::string& name = result.credentials.onlineId;
    brls::Application::notify(name.empty()
        ? "akira/psn_login/signed_in"_i18n
        : brls::getStr("akira/psn_login/signed_in_as_fmt", name));
    brls::Application::popActivity();
}
