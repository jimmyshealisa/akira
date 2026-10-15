#include "psn/browser_login.hpp"

#include "psn/auth_bootstrap.hpp"

#include <borealis.hpp>
#include <chiaki/random.h>
#include <json-c/json.h>

#include <array>
#include <ctime>
#include <format>

namespace psn::browser_login {

namespace {

constexpr const char* REMOTE_CLIENT_ID = "ba495a24-818c-472b-b12d-ff231c1b5745";
constexpr const char* REMOTE_CLIENT_SECRET = "mvaiZkRsAsI1IBkY";
// v3 authorize codes are redeemed on the v3 token endpoint (same as the NPSSO bootstrap).
constexpr const char* CODE_TOKEN_URL = "https://ca.account.sony.com/api/authz/v3/oauth/token";
// Token introspection lives on the legacy 2.0 endpoint: GET <url>/<access_token>.
constexpr const char* ACCOUNT_INFO_URL = "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token/";

bool randomBytes(std::array<uint8_t, 16>& out)
{
    return chiaki_random_bytes_crypt(out.data(), out.size()) == CHIAKI_ERR_SUCCESS;
}

std::string jsonString(json_object* root, const char* key)
{
    json_object* value = nullptr;
    if (!root || !json_object_object_get_ex(root, key, &value) || !value)
        return {};
    const char* str = json_object_get_string(value);
    return str ? std::string(str) : std::string();
}

int jsonInt(json_object* root, const char* key)
{
    json_object* value = nullptr;
    if (!root || !json_object_object_get_ex(root, key, &value) || !value)
        return 0;
    return json_object_get_int(value);
}

std::string describeError(const HttpResponse& response, json_object* parsed)
{
    std::string code = jsonString(parsed, "error");
    std::string description = jsonString(parsed, "error_description");
    if (!code.empty() && !description.empty())
        return code + ": " + description;
    if (!code.empty())
        return code;
    return std::format("HTTP {}", response.status);
}

} // namespace

Request begin(const std::string& existingDuid)
{
    Request request;

    if (bootstrap::isValidDuid(existingDuid))
    {
        request.duid = existingDuid;
    }
    else
    {
        std::array<uint8_t, 16> bytes{};
        if (!randomBytes(bytes))
        {
            brls::Logger::error("PSN browser login: failed to generate a DUID");
            return {};
        }
        request.duid = bootstrap::buildDuid(bytes);
    }

    std::array<uint8_t, 16> cidBytes{};
    if (!randomBytes(cidBytes))
    {
        brls::Logger::error("PSN browser login: failed to generate a cid");
        return {};
    }

    request.authorizeUrl = bootstrap::buildBrowserAuthorizeUrl(request.duid, bootstrap::formatCid(cidBytes));
    return request;
}

Result complete(HttpSession& session, const Request& request, const std::string& userInput)
{
    Result result;

    std::string code = bootstrap::extractAuthCodeFromInput(userInput);
    if (code.empty())
    {
        result.message = "No authorization code found in the input";
        return result;
    }

    /* 1. code -> access / refresh token */
    HttpRequest tokenRequest;
    tokenRequest.url = CODE_TOKEN_URL;
    tokenRequest.headers = {"Content-Type: application/x-www-form-urlencoded"};
    tokenRequest.postFields = bootstrap::buildCodeExchangeBody(bootstrap::Credential::RemotePlay, code);
    tokenRequest.post = true;
    tokenRequest.timeoutSec = 30;
    tokenRequest.bypassSonyGate = true;

    HttpResponse tokenResponse = session.perform(tokenRequest);
    if (tokenResponse.transportFailed())
    {
        brls::Logger::error("PSN browser login: token transport failure: {}", tokenResponse.error);
        result.message = tokenResponse.error;
        return result;
    }

    json_object* tokenJson = json_tokener_parse(tokenResponse.body.c_str());
    if (tokenResponse.status != 200 || !tokenJson || !jsonString(tokenJson, "error").empty())
    {
        result.message = describeError(tokenResponse, tokenJson);
        brls::Logger::error("PSN browser login: code exchange failed: {}", result.message);
        if (tokenJson)
            json_object_put(tokenJson);
        return result;
    }

    std::string accessToken = jsonString(tokenJson, "access_token");
    std::string refreshToken = jsonString(tokenJson, "refresh_token");
    int expiresIn = jsonInt(tokenJson, "expires_in");
    json_object_put(tokenJson);

    if (accessToken.empty() || refreshToken.empty())
    {
        result.message = "Missing tokens in response";
        return result;
    }

    /* 2. access token -> user_id / online_id */
    HttpRequest infoRequest;
    infoRequest.url = std::string(ACCOUNT_INFO_URL) + accessToken;
    infoRequest.basicUser = REMOTE_CLIENT_ID;
    infoRequest.basicPassword = REMOTE_CLIENT_SECRET;
    infoRequest.headers = {"Content-Type: application/json"};
    infoRequest.timeoutSec = 30;
    infoRequest.bypassSonyGate = true;

    HttpResponse infoResponse = session.perform(infoRequest);
    if (infoResponse.transportFailed())
    {
        brls::Logger::error("PSN browser login: account info transport failure: {}", infoResponse.error);
        result.message = infoResponse.error;
        return result;
    }

    json_object* infoJson = json_tokener_parse(infoResponse.body.c_str());
    if (infoResponse.status != 200 || !infoJson)
    {
        result.message = describeError(infoResponse, infoJson);
        brls::Logger::error("PSN browser login: account info failed: {}", result.message);
        if (infoJson)
            json_object_put(infoJson);
        return result;
    }

    std::string userId = jsonString(infoJson, "user_id");
    std::string onlineId = jsonString(infoJson, "online_id");
    json_object_put(infoJson);

    std::string accountId = bootstrap::accountIdFromUserId(userId);
    if (accountId.empty())
    {
        result.message = "PSN returned no usable user id";
        return result;
    }

    akira::pair::PairedCredentials& creds = result.credentials;
    creds.duid = request.duid;
    creds.accountId = accountId;
    creds.onlineId = onlineId;
    creds.accessToken = accessToken;
    creds.refreshToken = refreshToken;
    creds.expiresIn = expiresIn;
    creds.expiresAt = expiresIn > 0 ? static_cast<int64_t>(std::time(nullptr)) + expiresIn : 0;

    brls::Logger::info("PSN browser login: signed in as {}", onlineId.empty() ? "(unknown)" : onlineId);
    result.success = true;
    return result;
}

} // namespace psn::browser_login
