#ifndef AKIRA_PSN_AUTH_BOOTSTRAP_HPP
#define AKIRA_PSN_AUTH_BOOTSTRAP_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace psn::bootstrap {

enum class Credential {
    RemotePlay,
    MobileSso
};

struct NpssoState {
    bool hasNpsso = false;
    bool valid = false;
    int64_t lastCheckedAt = 0;
};

std::string urlEncode(std::string_view value);
std::string buildAuthorizeUrl(Credential credential, std::string_view duid, std::string_view cid);
std::string buildCodeExchangeBody(Credential credential, std::string_view code);
std::string extractAuthCode(std::string_view location);
bool shouldValidateNpsso(const NpssoState& state, int64_t now, int64_t intervalSeconds, bool force);

/*
 * Interactive browser login: the Switch shows the authorize URL as a QR code, the user
 * signs in on another device and types back what the redirect page shows.
 */

// Same Remote Play authorize URL as the NPSSO path, minus no_captcha: a human signs
// in here, so Sony is free to show its normal login and captcha pages.
std::string buildBrowserAuthorizeUrl(std::string_view duid, std::string_view cid);

// Accepts the full redirect URL, a "code=..." fragment or the bare code. Surrounding
// whitespace is ignored. Returns empty when nothing that looks like a code is found.
std::string extractAuthCodeFromInput(std::string_view input);

// PSN user_id (decimal uint64) -> Remote Play account id (base64 of 8 LE bytes).
std::string accountIdFromUserId(std::string_view userId);

// Remote Play DUIDs are a fixed 16-hex-char prefix plus 16 random bytes in hex.
std::string buildDuid(const std::array<uint8_t, 16>& randomBytes);
bool isValidDuid(std::string_view duid);

// RFC 4122 v4 UUID string from 16 random bytes (used as the authorize "cid").
std::string formatCid(std::array<uint8_t, 16> randomBytes);

} // namespace psn::bootstrap

#endif // AKIRA_PSN_AUTH_BOOTSTRAP_HPP
