#include "psn/auth_bootstrap.hpp"

#include <array>
#include <charconv>
#include <sstream>

namespace psn::bootstrap {

namespace {

constexpr const char* REMOTE_CLIENT_ID = "ba495a24-818c-472b-b12d-ff231c1b5745";
constexpr const char* REMOTE_CLIENT_SECRET = "mvaiZkRsAsI1IBkY";
constexpr const char* REMOTE_REDIRECT_URI = "https://remoteplay.dl.playstation.net/remoteplay/redirect";
constexpr const char* REMOTE_SCOPES =
    "psn:clientapp referenceDataService:countryConfig.read "
    "pushNotification:webSocket.desktop.connect "
    "sessionManager:remotePlaySession.system.update";

constexpr const char* MOBILE_CLIENT_ID = "09515159-7237-4370-9b40-3806e67c0891";
constexpr const char* MOBILE_REDIRECT_URI = "com.scee.psxandroid.scecompcall://redirect";
constexpr const char* MOBILE_SCOPES = "psn:mobile.v2.core psn:clientapp";

constexpr const char* AUTHORIZE_URL = "https://ca.account.sony.com/api/authz/v3/oauth/authorize";

bool isUnreserved(unsigned char ch)
{
    return (ch >= 'A' && ch <= 'Z') ||
        (ch >= 'a' && ch <= 'z') ||
        (ch >= '0' && ch <= '9') ||
        ch == '-' || ch == '_' || ch == '.' || ch == '~';
}

void appendParam(std::ostringstream& out, bool& first, std::string_view key, std::string_view value)
{
    out << (first ? '?' : '&') << key << '=' << urlEncode(value);
    first = false;
}

std::string buildRemotePlayAuthorizeUrl(std::string_view duid, std::string_view cid, bool noCaptcha)
{
    std::ostringstream out;
    out << AUTHORIZE_URL;

    bool first = true;
    appendParam(out, first, "client_id", REMOTE_CLIENT_ID);
    appendParam(out, first, "redirect_uri", REMOTE_REDIRECT_URI);
    appendParam(out, first, "scope", REMOTE_SCOPES);
    appendParam(out, first, "response_type", "code");
    appendParam(out, first, "service_entity", "urn:service-entity:psn");
    appendParam(out, first, "access_type", "offline");
    appendParam(out, first, "duid", duid);
    appendParam(out, first, "smcid", "remoteplay");
    appendParam(out, first, "layout_type", "popup");
    appendParam(out, first, "PlatformPrivacyWs1", "minimal");
    if (noCaptcha)
        appendParam(out, first, "no_captcha", "true");
    appendParam(out, first, "cid", cid);
    return out.str();
}

std::string_view trimView(std::string_view value)
{
    constexpr std::string_view WHITESPACE = " \t\r\n";
    size_t begin = value.find_first_not_of(WHITESPACE);
    if (begin == std::string_view::npos)
        return {};
    size_t end = value.find_last_not_of(WHITESPACE);
    return value.substr(begin, end - begin + 1);
}

bool isHex(unsigned char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

constexpr std::array<char, 16> HEX_LOWER = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

constexpr const char* DUID_PREFIX = "0000000700410080";

std::string base64Encode(const uint8_t* data, size_t size)
{
    static constexpr char TABLE[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((size + 2) / 3) * 4);
    for (size_t i = 0; i < size; i += 3)
    {
        uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < size)
            chunk |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < size)
            chunk |= static_cast<uint32_t>(data[i + 2]);

        out.push_back(TABLE[(chunk >> 18) & 0x3F]);
        out.push_back(TABLE[(chunk >> 12) & 0x3F]);
        out.push_back(i + 1 < size ? TABLE[(chunk >> 6) & 0x3F] : '=');
        out.push_back(i + 2 < size ? TABLE[chunk & 0x3F] : '=');
    }
    return out;
}

} // namespace

std::string urlEncode(std::string_view value)
{
    static constexpr std::array<char, 16> HEX = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    std::string encoded;
    encoded.reserve(value.size() * 3);

    for (unsigned char ch : value)
    {
        if (isUnreserved(ch))
        {
            encoded.push_back(static_cast<char>(ch));
            continue;
        }

        encoded.push_back('%');
        encoded.push_back(HEX[(ch >> 4) & 0x0F]);
        encoded.push_back(HEX[ch & 0x0F]);
    }

    return encoded;
}

std::string buildAuthorizeUrl(Credential credential, std::string_view duid, std::string_view cid)
{
    std::ostringstream out;
    out << AUTHORIZE_URL;

    bool first = true;
    if (credential == Credential::MobileSso)
    {
        appendParam(out, first, "access_type", "offline");
        appendParam(out, first, "client_id", MOBILE_CLIENT_ID);
        appendParam(out, first, "redirect_uri", MOBILE_REDIRECT_URI);
        appendParam(out, first, "response_type", "code");
        appendParam(out, first, "scope", MOBILE_SCOPES);
        return out.str();
    }

    return buildRemotePlayAuthorizeUrl(duid, cid, true);
}

std::string buildBrowserAuthorizeUrl(std::string_view duid, std::string_view cid)
{
    return buildRemotePlayAuthorizeUrl(duid, cid, false);
}

std::string buildCodeExchangeBody(Credential credential, std::string_view code)
{
    std::ostringstream out;
    out << "grant_type=authorization_code"
        << "&code=" << urlEncode(code);

    if (credential == Credential::MobileSso)
    {
        out << "&redirect_uri=" << urlEncode(MOBILE_REDIRECT_URI)
            << "&token_format=jwt";
        return out.str();
    }

    out << "&client_id=" << urlEncode(REMOTE_CLIENT_ID)
        << "&client_secret=" << urlEncode(REMOTE_CLIENT_SECRET)
        << "&redirect_uri=" << urlEncode(REMOTE_REDIRECT_URI)
        << "&scope=" << urlEncode(REMOTE_SCOPES);
    return out.str();
}

std::string extractAuthCode(std::string_view location)
{
    if (location.empty())
        return {};

    size_t query = location.find('?');
    if (query == std::string_view::npos)
        return {};

    std::string_view rest = location.substr(query + 1);
    while (!rest.empty())
    {
        size_t amp = rest.find('&');
        std::string_view part = rest.substr(0, amp);
        size_t eq = part.find('=');
        std::string_view key = part.substr(0, eq);
        std::string_view value = eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1);

        if (key == "code")
            return std::string(value);

        if (amp == std::string_view::npos)
            break;
        rest.remove_prefix(amp + 1);
    }

    return {};
}

bool shouldValidateNpsso(const NpssoState& state, int64_t now, int64_t intervalSeconds, bool force)
{
    if (!state.hasNpsso)
        return false;

    if (force || state.lastCheckedAt <= 0)
        return true;

    return (state.lastCheckedAt + intervalSeconds) <= now;
}

std::string extractAuthCodeFromInput(std::string_view input)
{
    input = trimView(input);
    if (input.empty())
        return {};

    std::string code;
    if (input.find('?') != std::string_view::npos)
    {
        code = extractAuthCode(input);
    }
    else
    {
        // "code=xyz", "cid=1&code=xyz" or just "xyz"
        std::string_view rest = input;
        size_t at = std::string_view::npos;
        if (rest.starts_with("code="))
            at = 0;
        else if (size_t amp = rest.find("&code="); amp != std::string_view::npos)
            at = amp + 1;

        if (at != std::string_view::npos)
        {
            rest = rest.substr(at + 5);
            rest = rest.substr(0, rest.find('&'));
        }
        else if (rest.find('=') != std::string_view::npos || rest.find('&') != std::string_view::npos)
        {
            return {};
        }
        code = std::string(rest);
    }

    if (code.empty())
        return {};
    for (unsigned char ch : code)
    {
        if (!isUnreserved(ch))
            return {};
    }
    return code;
}

std::string accountIdFromUserId(std::string_view userId)
{
    userId = trimView(userId);
    if (userId.empty())
        return {};

    uint64_t value = 0;
    auto [ptr, ec] = std::from_chars(userId.data(), userId.data() + userId.size(), value);
    if (ec != std::errc() || ptr != userId.data() + userId.size() || value == 0)
        return {};

    std::array<uint8_t, 8> bytes{};
    for (size_t i = 0; i < bytes.size(); i++)
        bytes[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);

    return base64Encode(bytes.data(), bytes.size());
}

std::string buildDuid(const std::array<uint8_t, 16>& randomBytes)
{
    std::string duid(DUID_PREFIX);
    duid.reserve(48);
    for (uint8_t byte : randomBytes)
    {
        duid.push_back(HEX_LOWER[byte >> 4]);
        duid.push_back(HEX_LOWER[byte & 0x0F]);
    }
    return duid;
}

bool isValidDuid(std::string_view duid)
{
    if (duid.size() != 48)
        return false;
    for (unsigned char ch : duid)
    {
        if (!isHex(ch))
            return false;
    }
    return true;
}

std::string formatCid(std::array<uint8_t, 16> bytes)
{
    bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);

    std::string out;
    out.reserve(36);
    for (size_t i = 0; i < bytes.size(); i++)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            out.push_back('-');
        out.push_back(HEX_LOWER[bytes[i] >> 4]);
        out.push_back(HEX_LOWER[bytes[i] & 0x0F]);
    }
    return out;
}

} // namespace psn::bootstrap
