#include "test_util.hpp"

#include "util/easytier_portal.hpp"

using namespace akira::easytier;

namespace {

std::string b64(const Key& key)
{
    return base64Encode(key.data(), key.size());
}

} // namespace

// Reference values printed by `easytier-cli vpn-portal` (easytier-core 2.6.4) for
// a node started with the given --network-name / --network-secret.
TEST(easytier_portal_keys_match_easytier_cli)
{
    CHECK_EQ(b64(portalClientPrivateKey("qilulu", "abc123")),
        std::string("tV5Z9/NPmLMCFfa6neZcQ3Vf2oaHtH1guYq4htJvEsk="));
    CHECK_EQ(b64(portalServerPublicKey("qilulu", "abc123")),
        std::string("5zitPw2PFdldLDvrkuzbHPgfc52thLrGKSZu9kaIPEw="));
}

TEST(easytier_portal_keys_handle_utf8_and_spaces)
{
    std::string name = "my net \xE6\xB5\x8B\xE8\xAF\x95";
    CHECK_EQ(b64(portalClientPrivateKey(name, "p@ss word!")),
        std::string("KoQgVn2xkMbQYyDlMIfeAw3FWQHw1EuSHb24OPF0KyY="));
    CHECK_EQ(b64(portalServerPublicKey(name, "p@ss word!")),
        std::string("Q9e/4bfLm9Y03fgjtW1ZfhkcuTrQ0VHuBbUQsjRozQg="));
}

TEST(easytier_base64_pads)
{
    const uint8_t data[] = {'f', 'o', 'o', 'b', 'a'};
    CHECK_EQ(base64Encode(data, 1), std::string("Zg=="));
    CHECK_EQ(base64Encode(data, 2), std::string("Zm8="));
    CHECK_EQ(base64Encode(data, 3), std::string("Zm9v"));
    CHECK_EQ(base64Encode(data, 5), std::string("Zm9vYmE="));
}

TEST(easytier_ipv4_check)
{
    CHECK(isIpv4("10.14.14.2"));
    CHECK(isIpv4("0.0.0.0"));
    CHECK(!isIpv4("10.14.14"));
    CHECK(!isIpv4("10.14.14.256"));
    CHECK(!isIpv4("10.14.14.2."));
    CHECK(!isIpv4("a.b.c.d"));
    CHECK(!isIpv4(""));
}

TEST(easytier_validate_and_build_config)
{
    PortalParams p;
    p.networkName = "qilulu";
    p.networkSecret = "abc123";
    p.host = "120.25.3.129";
    p.port = 22022;
    p.clientIp = "10.14.14.2";
    CHECK(validatePortalParams(p).empty());

    std::string conf = buildPortalWgConfig(p);
    CHECK(conf.find("PrivateKey = tV5Z9/NPmLMCFfa6neZcQ3Vf2oaHtH1guYq4htJvEsk=\n") != std::string::npos);
    CHECK(conf.find("PublicKey = 5zitPw2PFdldLDvrkuzbHPgfc52thLrGKSZu9kaIPEw=\n") != std::string::npos);
    CHECK(conf.find("Address = 10.14.14.2/32\n") != std::string::npos);
    CHECK(conf.find("Endpoint = 120.25.3.129:22022\n") != std::string::npos);
    CHECK(conf.find("MTU") == std::string::npos);

    PortalParams bad = p;
    bad.host = "120.25.3.129:22022";
    CHECK(!validatePortalParams(bad).empty());
    bad = p;
    bad.networkName = "  ";
    CHECK(!validatePortalParams(bad).empty());
    bad = p;
    bad.clientIp = "10.14.14";
    CHECK(!validatePortalParams(bad).empty());
    bad = p;
    bad.port = 0;
    CHECK(!validatePortalParams(bad).empty());
    bad = p;
    bad.mtu = 9000;
    CHECK(!validatePortalParams(bad).empty());
}

TEST(easytier_profile_round_trips_without_secret)
{
    PortalParams p;
    p.networkName = "qilulu";
    p.networkSecret = "abc123";
    p.host = "et.example.com";
    p.port = 11013;
    p.clientIp = "10.14.14.9";
    p.keepalive = 15;
    p.mtu = 1380;

    std::string text = serializeProfile(p);
    CHECK(text.find("abc123") == std::string::npos);

    PortalParams back = parseProfile(text);
    CHECK_EQ(back.networkName, p.networkName);
    CHECK_EQ(back.networkSecret, std::string());
    CHECK_EQ(back.host, p.host);
    CHECK_EQ(back.port, p.port);
    CHECK_EQ(back.clientIp, p.clientIp);
    CHECK_EQ(back.keepalive, p.keepalive);
    CHECK_EQ(back.mtu, p.mtu);
}
