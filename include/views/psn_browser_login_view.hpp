#ifndef AKIRA_PSN_BROWSER_LOGIN_VIEW_HPP
#define AKIRA_PSN_BROWSER_LOGIN_VIEW_HPP

#include <atomic>
#include <memory>
#include <string>

#include <borealis.hpp>

#include "psn/browser_login.hpp"

class QrCodeView;

/*
 * Signs in to PSN without the companion app: shows the Sony authorize URL as a QR
 * code, the user logs in on any other device and types back the code from the
 * redirect page. Tokens are then stored exactly like a companion push.
 */
class PsnBrowserLoginView : public brls::Box {
public:
    explicit PsnBrowserLoginView(bool createProfile = false);
    ~PsnBrowserLoginView() override;

    brls::View* getDefaultFocus() override;

private:
    enum class StatusTone { Muted, Busy, Error };

    void askForCode();
    void submit(const std::string& input);
    void onResult(const psn::browser_login::Result& result);
    void setStatus(const std::string& text, StatusTone tone);

    psn::browser_login::Request request;
    bool createProfile = false;
    bool blocked = false;
    bool busy = false;
    std::string lastInput;

    QrCodeView* qrView = nullptr;
    std::shared_ptr<std::atomic<bool>> alive = std::make_shared<std::atomic<bool>>(true);

    BRLS_BIND(brls::Box, qrSlot, "psnlogin/qrSlot");
    BRLS_BIND(brls::Label, statusLabel, "psnlogin/status");
    BRLS_BIND(brls::Button, enterBtn, "psnlogin/enter");
    BRLS_BIND(brls::Button, closeBtn, "psnlogin/close");
};

#endif // AKIRA_PSN_BROWSER_LOGIN_VIEW_HPP
