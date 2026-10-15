#ifndef AKIRA_PSN_BROWSER_LOGIN_HPP
#define AKIRA_PSN_BROWSER_LOGIN_HPP

#include <string>

#include "core/pair_listener.hpp"
#include "util/http.hpp"

/*
 * Companion-free PSN sign-in for the Switch.
 *
 *   1. begin()    picks a DUID and builds the Remote Play authorize URL (shown as a QR)
 *   2. the user signs in on a phone / PC; Sony redirects to
 *      https://remoteplay.dl.playstation.net/remoteplay/redirect?code=...
 *   3. complete() trades that code for tokens and resolves the account id
 *
 * The result is a PairedCredentials, so it lands in settings through the exact same
 * path a companion push uses.
 */
namespace psn::browser_login {

struct Request {
    std::string duid;
    std::string authorizeUrl;
};

struct Result {
    bool success = false;
    std::string message;
    akira::pair::PairedCredentials credentials;
};

// Reuses existingDuid when it is a valid Remote Play DUID, otherwise mints a new one.
// An empty authorizeUrl means the random source failed.
Request begin(const std::string& existingDuid);

// Blocking: run it off the UI thread (HttpPool).
Result complete(HttpSession& session, const Request& request, const std::string& userInput);

} // namespace psn::browser_login

#endif // AKIRA_PSN_BROWSER_LOGIN_HPP
