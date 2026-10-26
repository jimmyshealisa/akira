#include "test_util.hpp"

#include "util/web_form.hpp"

using namespace akira::web;

TEST(url_decode_handles_escapes_and_plus)
{
    CHECK_EQ(urlDecode("a+b"), std::string("a b"));
    CHECK_EQ(urlDecode("%2B"), std::string("+"));
    CHECK_EQ(urlDecode("line1%0D%0Aline2"), std::string("line1\r\nline2"));
    CHECK_EQ(urlDecode("%E4%B8%AD"), std::string("\xE4\xB8\xAD"));
}

TEST(url_decode_passes_malformed_escapes_through)
{
    CHECK_EQ(urlDecode("100%"), std::string("100%"));
    CHECK_EQ(urlDecode("%ZZ"), std::string("%ZZ"));
    CHECK_EQ(urlDecode("%2"), std::string("%2"));
}

TEST(form_field_value_reads_keys_case_insensitively)
{
    std::string body = "code=1234&Config=%5BInterface%5D%0APrivateKey+%3D+abc";
    CHECK_EQ(formFieldValue(body, "code"), std::string("1234"));
    CHECK_EQ(formFieldValue(body, "config"), std::string("[Interface]\nPrivateKey = abc"));
    CHECK_EQ(formFieldValue(body, "missing"), std::string());
}

TEST(query_parameter_value_reads_the_request_target)
{
    CHECK_EQ(queryParameterValue("/import?code=1234", "code"), std::string("1234"));
    CHECK_EQ(queryParameterValue("/import?code=1234&x=1", "code"), std::string("1234"));
    CHECK_EQ(queryParameterValue("/import", "code"), std::string());
    CHECK_EQ(queryParameterValue("/import?config=a%3Db", "config"), std::string("a=b"));
}

TEST(request_target_returns_the_middle_token)
{
    CHECK_EQ(requestTarget("POST /import?code=1234 HTTP/1.1\r\nHost: x"),
        std::string("/import?code=1234"));
    CHECK_EQ(requestTarget("GET / HTTP/1.1"), std::string("/"));
    CHECK_EQ(requestTarget("nonsense"), std::string());
}

TEST(validate_wg_config_accepts_an_easytier_style_conf)
{
    std::string conf =
        "[Interface]\n"
        "PrivateKey = ABCdef1234567890ABCdef1234567890ABCdef12345=\n"
        "Address = 10.144.144.10/24\n"
        "MTU = 1420\n"
        "\n"
        "[Peer]\n"
        "PublicKey = XYZ9876543210XYZ9876543210XYZ9876543210XYZ=\n"
        "AllowedIPs = 10.144.144.0/24, 192.168.1.0/24\n"
        "Endpoint = 203.0.113.7:11013\n"
        "PersistentKeepalive = 25\n";
    CHECK(validateWgConfigText(conf).empty());
}

TEST(validate_wg_config_rejects_incomplete_configs)
{
    CHECK(!validateWgConfigText("").empty());
    CHECK(!validateWgConfigText("[Interface]\nPrivateKey = x\n").empty());
    CHECK(!validateWgConfigText(
        "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/24\n").empty());
    CHECK(!validateWgConfigText(
        "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/24\n\n[Peer]\nEndpoint = h:1\n").empty());
    CHECK(!validateWgConfigText(
        "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/24\n\n[Peer]\nPublicKey = b\n").empty());
}

TEST(validate_wg_config_rejects_wildcard_endpoint)
{
    std::string conf =
        "[Interface]\nPrivateKey = a\nAddress = 10.14.14.2/32\n\n"
        "[Peer]\nPublicKey = b\nEndpoint = 0.0.0.0:22022\n";
    CHECK(!validateWgConfigText(conf).empty());
    CHECK(!validateWgConfigText(
        "[Interface]\nPrivateKey = a\nAddress = 10.14.14.2/32\n\n[Peer]\nPublicKey = b\nEndpoint = host\n").empty());
}

TEST(strip_inline_comments_handles_easytier_cli_output)
{
    std::string cli =
        "\n[Interface]\r\n"
        "PrivateKey = tV5Z9/NPmLMCFfa6neZcQ3Vf2oaHtH1guYq4htJvEsk=\n"
        "Address = 10.14.14.0/32 # should assign an ip from this cidr manually\n"
        "# whole-line comment stays\n"
        "Endpoint = 1.2.3.4:22022 # should be the public ip(or domain) of the vpn server\n";
    std::string out = stripInlineComments(cli);
    CHECK(out.find("Address = 10.14.14.0/32\n") != std::string::npos);
    CHECK(out.find("Endpoint = 1.2.3.4:22022\n") != std::string::npos);
    CHECK(out.find("# whole-line comment stays\n") != std::string::npos);
    CHECK(out.find("should assign") == std::string::npos);
    CHECK(out.find('\r') == std::string::npos);
}

TEST(html_escape_and_field_builder)
{
    CHECK_EQ(htmlEscape("<a href=\"x\">&'"), std::string("&lt;a href=&quot;x&quot;&gt;&amp;&#39;"));

    WgFields f;
    f.privateKey = " priv= ";
    f.address = "10.14.14.2/32";
    f.publicKey = "pub=";
    f.endpoint = "1.2.3.4:22022";
    std::string conf = buildWgConfigText(f);
    CHECK(validateWgConfigText(conf).empty());
    CHECK(conf.find("PrivateKey = priv=\n") != std::string::npos);
    CHECK(conf.find("PersistentKeepalive = 25\n") != std::string::npos);
    CHECK(conf.find("PresharedKey") == std::string::npos);
    CHECK(conf.find("MTU") == std::string::npos);
}
