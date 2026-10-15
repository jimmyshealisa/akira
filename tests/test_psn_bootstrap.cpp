#include "test_util.hpp"

#include "psn/auth_bootstrap.hpp"

using namespace psn::bootstrap;

TEST(extract_auth_code_reads_the_code_query_param)
{
    CHECK_EQ(extractAuthCode("https://remoteplay.dl.playstation.net/remoteplay/redirect?code=abc123&cid=123"),
        std::string("abc123"));
    CHECK_EQ(extractAuthCode("https://example.com/callback?state=1&code=xyz"),
        std::string("xyz"));
}

TEST(extract_auth_code_returns_empty_when_missing)
{
    CHECK_EQ(extractAuthCode("https://example.com/callback?state=1"), std::string());
    CHECK_EQ(extractAuthCode(""), std::string());
}

TEST(build_authorize_url_uses_remote_play_fields)
{
    std::string url = buildAuthorizeUrl(Credential::RemotePlay, "deadbeef", "cid-123");
    CHECK(url.find("client_id=ba495a24-818c-472b-b12d-ff231c1b5745") != std::string::npos);
    CHECK(url.find("duid=deadbeef") != std::string::npos);
    CHECK(url.find("cid=cid-123") != std::string::npos);
    CHECK(url.find("smcid=remoteplay") != std::string::npos);
}

TEST(build_authorize_url_uses_mobile_fields)
{
    std::string url = buildAuthorizeUrl(Credential::MobileSso, "", "");
    CHECK(url.find("client_id=09515159-7237-4370-9b40-3806e67c0891") != std::string::npos);
    CHECK(url.find("redirect_uri=com.scee.psxandroid.scecompcall%3A%2F%2Fredirect") != std::string::npos);
    CHECK(url.find("scope=psn%3Amobile.v2.core%20psn%3Aclientapp") != std::string::npos);
}

TEST(build_code_exchange_body_uses_the_expected_remote_play_fields)
{
    std::string body = buildCodeExchangeBody(Credential::RemotePlay, "auth-code");
    CHECK(body.find("grant_type=authorization_code") != std::string::npos);
    CHECK(body.find("code=auth-code") != std::string::npos);
    CHECK(body.find("client_secret=mvaiZkRsAsI1IBkY") != std::string::npos);
    CHECK(body.find("redirect_uri=https%3A%2F%2Fremoteplay.dl.playstation.net%2Fremoteplay%2Fredirect") != std::string::npos);
}

TEST(should_validate_npsso_forces_first_time_and_stale_checks)
{
    NpssoState unknown{.hasNpsso = true, .valid = false, .lastCheckedAt = 0};
    CHECK(shouldValidateNpsso(unknown, 1000, 60, false));

    NpssoState fresh{.hasNpsso = true, .valid = true, .lastCheckedAt = 995};
    CHECK(!shouldValidateNpsso(fresh, 1000, 60, false));

    NpssoState stale{.hasNpsso = true, .valid = true, .lastCheckedAt = 900};
    CHECK(shouldValidateNpsso(stale, 1000, 60, false));
    CHECK(shouldValidateNpsso(fresh, 1000, 60, true));
}

TEST(browser_authorize_url_matches_npsso_url_without_no_captcha)
{
    std::string browser = buildBrowserAuthorizeUrl("deadbeef", "cid-123");
    std::string npsso = buildAuthorizeUrl(Credential::RemotePlay, "deadbeef", "cid-123");

    CHECK(browser.find("no_captcha") == std::string::npos);
    CHECK(npsso.find("no_captcha=true") != std::string::npos);
    CHECK(browser.find("client_id=ba495a24-818c-472b-b12d-ff231c1b5745") != std::string::npos);
    CHECK(browser.find("redirect_uri=https%3A%2F%2Fremoteplay.dl.playstation.net%2Fremoteplay%2Fredirect") != std::string::npos);
    CHECK(browser.find("duid=deadbeef") != std::string::npos);
    CHECK(browser.find("cid=cid-123") != std::string::npos);
    CHECK(browser.find("access_type=offline") != std::string::npos);
}

TEST(extract_auth_code_from_input_accepts_url_fragment_and_bare_code)
{
    CHECK_EQ(extractAuthCodeFromInput("https://remoteplay.dl.playstation.net/remoteplay/redirect?code=v3.AbC123&cid=x"),
        std::string("v3.AbC123"));
    CHECK_EQ(extractAuthCodeFromInput("remoteplay.dl.playstation.net/remoteplay/redirect?code=v3.AbC123"),
        std::string("v3.AbC123"));
    CHECK_EQ(extractAuthCodeFromInput("code=v3.AbC123&cid=x"), std::string("v3.AbC123"));
    CHECK_EQ(extractAuthCodeFromInput("cid=x&code=v3.AbC123"), std::string("v3.AbC123"));
    CHECK_EQ(extractAuthCodeFromInput("  v3.AbC123 \n"), std::string("v3.AbC123"));
}

TEST(extract_auth_code_from_input_rejects_garbage)
{
    CHECK_EQ(extractAuthCodeFromInput(""), std::string());
    CHECK_EQ(extractAuthCodeFromInput("   "), std::string());
    CHECK_EQ(extractAuthCodeFromInput("v3 AbC"), std::string());
    CHECK_EQ(extractAuthCodeFromInput("cid=x"), std::string());
    CHECK_EQ(extractAuthCodeFromInput("https://remoteplay.dl.playstation.net/remoteplay/redirect?error=access_denied"),
        std::string());
}

TEST(account_id_from_user_id_is_little_endian_base64)
{
    // 1 -> 01 00 00 00 00 00 00 00
    CHECK_EQ(accountIdFromUserId("1"), std::string("AQAAAAAAAAA="));
    // 0x0102030405060708 -> 08 07 06 05 04 03 02 01
    CHECK_EQ(accountIdFromUserId("72623859790382856"), std::string("CAcGBQQDAgE="));
    CHECK_EQ(accountIdFromUserId("18446744073709551615"), std::string("//////////8="));
    CHECK_EQ(accountIdFromUserId("").size(), size_t(0));
    CHECK_EQ(accountIdFromUserId("0").size(), size_t(0));
    CHECK_EQ(accountIdFromUserId("12ab").size(), size_t(0));
    CHECK_EQ(accountIdFromUserId("18446744073709551616").size(), size_t(0));
}

TEST(build_duid_has_remote_play_prefix_and_validates)
{
    std::array<uint8_t, 16> bytes{};
    for (size_t i = 0; i < bytes.size(); i++)
        bytes[i] = static_cast<uint8_t>(i * 17);

    std::string duid = buildDuid(bytes);
    CHECK_EQ(duid, std::string("000000070041008000112233445566778899aabbccddeeff"));
    CHECK(isValidDuid(duid));
    CHECK(!isValidDuid(""));
    CHECK(!isValidDuid("deadbeef"));
    CHECK(!isValidDuid(std::string(47, 'a') + "g"));
}

TEST(format_cid_is_a_v4_uuid)
{
    std::array<uint8_t, 16> bytes{};
    bytes.fill(0xFF);
    std::string cid = formatCid(bytes);
    CHECK_EQ(cid.size(), size_t(36));
    CHECK_EQ(cid, std::string("ffffffff-ffff-4fff-bfff-ffffffffffff"));
}
