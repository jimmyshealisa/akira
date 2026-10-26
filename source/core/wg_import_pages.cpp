#include "core/wg_import_pages.hpp"

#include "util/web_form.hpp"

namespace akira::wg::pages {

namespace {

using akira::web::htmlEscape;

const char* kStyle = R"CSS(
:root{--bg:#f2f3f5;--card:#fff;--text:#1f2225;--muted:#6b7280;--line:#e2e5e9;--input:#fff;--accent:#18a058;--accent-d:#0c7a43;--warn:#b45309;--err:#d03050}
@media (prefers-color-scheme:dark){:root{--bg:#18191c;--card:#232428;--text:#e8e8ea;--muted:#9aa0a6;--line:#35373c;--input:#2b2d31;--warn:#f0a020;--err:#e88080}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:46rem;margin:0 auto;padding:1.2rem 1rem 3rem}
h1{font-size:1.25rem;margin:.2rem 0 1rem}
.tabs{display:flex;gap:.5rem;margin-bottom:1rem}
.tabs a{flex:1;text-align:center;padding:.55rem;border-radius:8px;border:1px solid var(--line);color:var(--text);text-decoration:none;background:var(--card)}
.tabs a.on{border-color:var(--accent);color:var(--accent);font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem 1.1rem;margin-bottom:1rem}
.card h2{font-size:1rem;margin:0 0 .8rem}
.intro{color:var(--muted);margin:0 0 1rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem 1rem}
.full{grid-column:1/-1}
@media (max-width:560px){.grid{grid-template-columns:1fr}}
label{display:block;font-size:.9rem;margin-bottom:.3rem}
label .req{color:var(--err)}
input,textarea{width:100%;padding:.55rem .7rem;border:1px solid var(--line);border-radius:6px;background:var(--input);color:var(--text);font:inherit}
textarea{font-family:ui-monospace,Consolas,monospace;font-size:.85rem}
input:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(24,160,88,.18)}
.hint{color:var(--muted);font-size:.8rem;margin-top:.25rem}
details{margin-top:.2rem}
summary{cursor:pointer;font-weight:600;padding:.2rem 0}
.btn{display:block;margin:1.2rem auto 0;padding:.65rem 2.4rem;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:1rem;font-weight:600;cursor:pointer}
.btn:hover{background:var(--accent-d)}
ol{padding-left:1.2rem;margin:.4rem 0}
li{margin:.35rem 0}
code{background:var(--input);border:1px solid var(--line);border-radius:4px;padding:0 .3rem;font-size:.85em;word-break:break-all}
.note{color:var(--warn);font-size:.85rem}
.ok{color:var(--accent);font-size:1.2rem;font-weight:600}
.bad{color:var(--err);font-size:1.2rem;font-weight:600}
)CSS";

const char* kIpv4Pattern = R"((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3})";
const char* kHostPattern = R"([A-Za-z0-9._\-]+)";

std::string T(bool zh, const char* cn, const char* en)
{
    return zh ? cn : en;
}

std::string head(bool zh, const std::string& title)
{
    return std::string("<!doctype html><html lang=\"") + (zh ? "zh-CN" : "en") +
        "\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>" + htmlEscape(title) + "</title><style>" + kStyle + "</style></head><body><div class=\"wrap\">";
}

std::string tabs(bool easytierActive)
{
    return std::string("<div class=\"tabs\">") +
        "<a href=\"/easytier\"" + (easytierActive ? " class=\"on\"" : "") + ">EasyTier</a>"
        "<a href=\"/wireguard\"" + (easytierActive ? "" : " class=\"on\"") + ">WireGuard</a></div>";
}

std::string field(const std::string& name, const std::string& label, const std::string& value,
                  const std::string& attrs, const std::string& hint, bool required, bool full = false)
{
    std::string out = std::string("<div") + (full ? " class=\"full\"" : "") + "><label for=\"" + name + "\">" +
        label + (required ? " <span class=\"req\">*</span>" : "") + "</label>"
        "<input id=\"" + name + "\" name=\"" + name + "\" value=\"" + htmlEscape(value) + "\" " + attrs +
        (required ? " required" : "") + ">";
    if (!hint.empty())
        out += "<div class=\"hint\">" + hint + "</div>";
    return out + "</div>";
}

} // namespace

std::string easytierPage(const std::string& code, const akira::easytier::PortalParams& d, bool zh)
{
    std::string port = std::to_string(d.port > 0 ? d.port : 22022);
    std::string clientIp = d.clientIp.empty() ? "10.14.14.2" : d.clientIp;
    std::string keepalive = std::to_string(d.keepalive);
    std::string mtu = d.mtu > 0 ? std::to_string(d.mtu) : "";

    std::string html = head(zh, T(zh, "Akira · EasyTier 接入", "Akira · EasyTier"));
    html += "<h1>" + T(zh, "Akira · EasyTier 接入", "Akira · Join an EasyTier network") + "</h1>";
    html += tabs(true);
    html += "<p class=\"intro\">" + T(zh,
        "Switch 无法直接运行 EasyTier，但可以通过网络中某个节点的「VPN 门户」以 WireGuard 方式加入同一个虚拟网络。"
        "填写与 EasyTier GUI 相同的网络名称和密码，密钥会在 Switch 上自动生成。",
        "The Switch cannot run EasyTier itself, but it can join the same virtual network through a node's "
        "\"VPN portal\" over WireGuard. Enter the same network name and secret as in the EasyTier GUI; the keys "
        "are derived on the Switch.") + "</p>";

    html += "<form method=\"POST\" action=\"/easytier?code=" + htmlEscape(code) + "\" autocomplete=\"off\">";

    html += "<div class=\"card\"><h2>" + T(zh, "基础设置", "Network") + "</h2><div class=\"grid\">";
    html += field("network_name", T(zh, "网络名称", "Network name"), d.networkName, "", "", true);
    html += field("network_secret", T(zh, "网络密码", "Network secret"), "", "type=\"password\"",
        T(zh, "不会被保存到 Switch 的表单记录中", "Not remembered by the form"), false);
    html += "</div></div>";

    html += "<div class=\"card\"><h2>" + T(zh, "VPN 门户节点", "VPN portal node") + "</h2><div class=\"grid\">";
    html += field("host", T(zh, "门户地址", "Portal address"), d.host,
        std::string("placeholder=\"120.25.3.129 / et.example.com\" pattern=\"") + kHostPattern + "\"",
        T(zh, "开启了 VPN 门户的节点的公网 IP 或域名，不带端口", "Public IP or domain of the node running the VPN portal, without port"),
        true, true);
    html += field("port", T(zh, "门户端口", "Portal port"), port, "type=\"number\" min=\"1\" max=\"65535\"",
        T(zh, "GUI：高级设置 → VPN 门户 → 监听端口（UDP）", "GUI: Advanced → VPN portal → listen port (UDP)"), true);
    html += field("client_ip", T(zh, "Switch 虚拟 IP", "Switch virtual IP"), clientIp,
        std::string("pattern=\"") + kIpv4Pattern + "\"",
        T(zh, "须在门户「客户端网段」内（默认 10.14.14.0/24），不要用 .0，每台设备不同",
          "Inside the portal client CIDR (default 10.14.14.0/24), not .0, unique per device"), true);
    html += "</div><details><summary>" + T(zh, "高级设置", "Advanced") + "</summary><div class=\"grid\" style=\"margin-top:.6rem\">";
    html += field("keepalive", T(zh, "保活间隔（秒）", "Keepalive (s)"), keepalive, "type=\"number\" min=\"0\" max=\"3600\"", "", false);
    html += field("mtu", "MTU", mtu, "type=\"number\" min=\"576\" max=\"1420\" placeholder=\"1420\"",
        T(zh, "留空使用默认值", "Leave empty for the default"), false);
    html += "</div></details></div>";

    html += "<button class=\"btn\" type=\"submit\">" + T(zh, "保存到 Switch", "Save to Switch") + "</button></form>";

    html += "<div class=\"card\" style=\"margin-top:1.4rem\"><details><summary>" +
        T(zh, "使用前需要在 EasyTier 里做什么？", "What to set up in EasyTier first?") + "</summary><ol>";
    html += "<li>" + T(zh,
        "<b>门户节点</b>（Switch 在外网能用 UDP 访问到的节点，例如云服务器）：GUI「高级设置 → VPN 门户」开启，记下监听端口和客户端网段；云服务器安全组/防火墙放行该 UDP 端口。命令行等价于 <code>--vpn-portal wg://0.0.0.0:22022/10.14.14.0/24</code>。",
        "<b>Portal node</b> (reachable over UDP from where the Switch is, e.g. a cloud server): enable \"VPN portal\" under Advanced, note the listen port and client CIDR, and open that UDP port in the firewall. CLI: <code>--vpn-portal wg://0.0.0.0:22022/10.14.14.0/24</code>.") + "</li>";
    html += "<li>" + T(zh,
        "<b>家里和 PS5 同一局域网的节点</b>：开启「子网代理」，填 PS5 所在网段，例如 <code>192.168.1.0/24</code>（命令行 <code>-n 192.168.1.0/24</code>）。",
        "<b>Home node on the PS5's LAN</b>: enable \"Subnet proxy\" for the PS5's subnet, e.g. <code>192.168.1.0/24</code> (CLI <code>-n 192.168.1.0/24</code>).") + "</li>";
    html += "<li>" + T(zh,
        "保存后回到 Switch「网络工具」点「连接」，再在 Akira 中用 PS5 的局域网 IP（如 192.168.1.x）手动添加主机。",
        "After saving, press Connect in the Switch's Network tab, then add the PS5 manually by its LAN IP (e.g. 192.168.1.x).") + "</li>";
    html += "</ol><p class=\"note\">" + T(zh,
        "门户的 WireGuard 密钥由「网络名称 + 网络密码」推导（EasyTier 2.x），所以门户节点必须属于你填写的这个网络。",
        "EasyTier 2.x derives the portal keys from network name + secret, so the portal node must belong to this network.") +
        "</p></details></div>";

    html += "</div></body></html>";
    return html;
}

std::string wireguardPage(const std::string& code, bool zh)
{
    std::string html = head(zh, T(zh, "Akira · WireGuard 配置", "Akira · WireGuard"));
    html += "<h1>" + T(zh, "Akira · WireGuard 配置", "Akira · WireGuard config") + "</h1>";
    html += tabs(false);
    html += "<p class=\"intro\">" + T(zh,
        "适用于任意 WireGuard 服务器（包括 easytier-cli vpn-portal 输出的配置）。逐项填写，或在下方粘贴完整配置。",
        "For any WireGuard server (including the output of easytier-cli vpn-portal). Fill in the fields, or paste a full config below.") + "</p>";

    html += "<form method=\"POST\" action=\"/wireguard?code=" + htmlEscape(code) + "\" autocomplete=\"off\">";

    html += "<div class=\"card\"><h2>[Interface]</h2><div class=\"grid\">";
    html += field("private_key", "PrivateKey", "", "placeholder=\"base64\"", "", false, true);
    html += field("address", "Address", "", "placeholder=\"10.14.14.2/32\"",
        T(zh, "只使用第一个 IPv4 地址", "Only the first IPv4 address is used"), false);
    html += field("mtu", "MTU", "", "type=\"number\" min=\"576\" max=\"1420\" placeholder=\"1420\"", "", false);
    html += "</div></div>";

    html += "<div class=\"card\"><h2>[Peer]</h2><div class=\"grid\">";
    html += field("public_key", "PublicKey", "", "placeholder=\"base64\"", "", false, true);
    html += field("endpoint", "Endpoint", "", "placeholder=\"1.2.3.4:22022\"",
        T(zh, "服务器公网地址:端口", "Server public address:port"), false);
    html += field("keepalive", "PersistentKeepalive", "25", "type=\"number\" min=\"0\" max=\"3600\"", "", false);
    html += field("preshared_key", "PresharedKey", "", "placeholder=\"" + T(zh, "可选", "optional") + "\"", "", false, true);
    html += "</div></div>";

    html += "<div class=\"card\"><details><summary>" + T(zh, "或粘贴完整配置（优先使用）", "Or paste a full config (takes precedence)") +
        "</summary><textarea name=\"config\" rows=\"12\" style=\"margin-top:.6rem\" placeholder=\"[Interface]\nPrivateKey = ...\nAddress = 10.14.14.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = host:port\"></textarea>"
        "<div class=\"hint\">" + T(zh, "行尾的 # 注释会被自动去掉。", "Trailing # comments are removed automatically.") +
        "</div></details></div>";

    html += "<button class=\"btn\" type=\"submit\">" + T(zh, "保存到 Switch", "Save to Switch") + "</button></form>";
    html += "</div></body></html>";
    return html;
}

std::string resultPage(bool ok, const std::string& detail, const std::string& backPath, bool zh)
{
    std::string html = head(zh, "Akira");
    html += "<div class=\"card\" style=\"margin-top:2rem;text-align:center\">";
    if (ok) {
        html += "<p class=\"ok\">" + T(zh, "已保存到 Switch", "Saved to the Switch") + "</p>";
        html += "<p>" + T(zh,
            "回到 Switch「网络工具」点击「连接」。连接成功后，用 PS5 的局域网 IP 手动添加主机即可远程游玩。",
            "Go back to the Switch's Network tab and press Connect. Once connected, add the PS5 manually by its LAN IP.") + "</p>";
    } else {
        html += "<p class=\"bad\">" + T(zh, "保存失败", "Not saved") + "</p>";
        html += "<p>" + htmlEscape(detail) + "</p>";
        html += "<p><a href=\"" + htmlEscape(backPath) + "\" onclick=\"history.back();return false\">" +
            T(zh, "返回修改", "Go back") + "</a></p>";
    }
    if (ok && !detail.empty())
        html += "<p class=\"hint\">" + htmlEscape(detail) + "</p>";
    html += "</div></div></body></html>";
    return html;
}

} // namespace akira::wg::pages
