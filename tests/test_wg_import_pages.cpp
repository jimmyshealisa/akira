#include "test_util.hpp"

#include "core/wg_import_pages.hpp"

using namespace akira::wg;

TEST(easytier_page_embeds_code_and_escapes_profile)
{
    akira::easytier::PortalParams d;
    d.networkName = "a\"<b>";
    d.host = "1.2.3.4";
    d.port = 11013;
    d.clientIp = "10.14.14.7";

    std::string html = pages::easytierPage("4821", d, true);
    CHECK(html.find("action=\"/easytier?code=4821\"") != std::string::npos);
    CHECK(html.find("value=\"a&quot;&lt;b&gt;\"") != std::string::npos);
    CHECK(html.find("value=\"11013\"") != std::string::npos);
    CHECK(html.find("value=\"10.14.14.7\"") != std::string::npos);
    CHECK(html.find("name=\"network_secret\" value=\"\"") != std::string::npos);
    CHECK(html.find("网络名称") != std::string::npos);
    CHECK(pages::easytierPage("1", {}, false).find("Network name") != std::string::npos);
    CHECK(pages::easytierPage("1", {}, false).find("value=\"10.14.14.2\"") != std::string::npos);
}

TEST(wireguard_and_result_pages_render)
{
    std::string html = pages::wireguardPage("0007", false);
    CHECK(html.find("action=\"/wireguard?code=0007\"") != std::string::npos);
    CHECK(html.find("name=\"private_key\"") != std::string::npos);
    CHECK(html.find("name=\"config\"") != std::string::npos);

    std::string bad = pages::resultPage(false, "<script>", "/easytier", true);
    CHECK(bad.find("&lt;script&gt;") != std::string::npos);
    CHECK(bad.find("<script>") == std::string::npos);
}
