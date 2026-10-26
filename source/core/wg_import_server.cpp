#include "core/wg_import_server.hpp"

#include "core/wg_import_pages.hpp"
#include "core/wireguard_manager.hpp"
#include "util/easytier_portal.hpp"
#include "util/net_wrappers.hpp"
#include "util/web_form.hpp"

#include <borealis.hpp>
#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

namespace akira::wg {

using akira::web::formFieldValue;
using akira::web::queryParameterValue;
using akira::web::requestTarget;
using akira::web::stripInlineComments;
using akira::web::validateWgConfigText;

namespace {

constexpr std::size_t kMaxHeadBytes = 16 * 1024;
constexpr std::size_t kMaxBodyBytes = 128 * 1024;
constexpr const char* kHtml = "text/html; charset=utf-8";

bool sameCode(const std::string& a, const std::string& b)
{
    // Still leaks length, but codes are fixed width anyway; timing is not the
    // real boundary here, the LAN is. This is just tidier than ==.
    bool same = a.size() == b.size();
    for (size_t i = 0; i < a.size() && i < b.size(); i++)
        same &= a[i] == b[i];
    return same;
}

std::string lowercased(std::string_view value)
{
    std::string out(value);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

std::string headerValue(const std::string& head, const std::string& name)
{
    size_t pos = 0;
    while (pos <= head.size()) {
        size_t eol = head.find("\r\n", pos);
        std::string line = head.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos &&
            lowercased(line.substr(0, colon)) == lowercased(name)) {
            size_t start = line.find_first_not_of(" \t", colon + 1);
            return start == std::string::npos ? "" : line.substr(start);
        }
        if (eol == std::string::npos)
            break;
        pos = eol + 2;
    }
    return {};
}

void sendResponse(int fd, int status, const char* reason, const std::string& body,
                  const char* contentType = "text/plain; charset=utf-8")
{
    std::string response = "HTTP/1.1 " + std::to_string(status) + " " + reason +
        "\r\nContent-Type: " + contentType +
        "\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < response.size()) {
        ssize_t r = send(fd, response.data() + sent, response.size() - sent, 0);
        if (r <= 0)
            return;
        sent += static_cast<std::size_t>(r);
    }
}

std::string pathOf(const std::string& target)
{
    std::string path = target.substr(0, target.find('?'));
    while (path.size() > 1 && path.back() == '/')
        path.pop_back();
    return path;
}

int toInt(const std::string& text, int fallback)
{
    std::string_view v(text);
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
        v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
        v.remove_suffix(1);
    if (v.empty())
        return fallback;
    int value = 0;
    auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), value);
    if (ec != std::errc{} || ptr != v.data() + v.size())
        return -1;
    return value;
}

akira::easytier::PortalParams loadProfile()
{
    std::ifstream file(WgImportServer::PROFILE_PATH, std::ios::binary);
    if (!file.is_open())
        return {};
    std::stringstream ss;
    ss << file.rdbuf();
    return akira::easytier::parseProfile(ss.str());
}

void saveProfile(const akira::easytier::PortalParams& params)
{
    std::ofstream file(WgImportServer::PROFILE_PATH, std::ios::binary | std::ios::trunc);
    if (file.is_open())
        file << akira::easytier::serializeProfile(params);
}

bool anyFieldSet(const akira::web::WgFields& f)
{
    for (const std::string* s : {&f.privateKey, &f.address, &f.publicKey, &f.endpoint, &f.presharedKey}) {
        if (s->find_first_not_of(" \t\r\n") != std::string::npos)
            return true;
    }
    return false;
}

} // namespace

WgImportServer::~WgImportServer() {
    stop();
}

void WgImportServer::start(int port, const std::string& code, ImportPage defaultPage, EventCallback onEvent) {
    stop();
    onEvent_ = std::move(onEvent);
    running_ = true;
    thread_ = std::thread(&WgImportServer::run, this, port, code, defaultPage);
}

void WgImportServer::stop() {
    running_ = false;
    if (thread_.joinable())
        thread_.join();
}

void WgImportServer::run(int port, std::string code, ImportPage defaultPage) {
    SocketGuard listenSock(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (listenSock < 0) {
        if (onEvent_) onEvent_(ImportEvent::Error);
        return;
    }

    int one = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(listenSock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(listenSock, 4) < 0) {
        if (onEvent_) onEvent_(ImportEvent::Error);
        return;
    }

    int listenFlags = fcntl(listenSock, F_GETFL, 0);
    fcntl(listenSock, F_SETFL, listenFlags | O_NONBLOCK);

    if (onEvent_) onEvent_(ImportEvent::Listening);

    int tries = 0;

    while (running_) {
        struct pollfd pfd = {};
        pfd.fd = listenSock;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 500);
        if (pr <= 0 || !(pfd.revents & POLLIN))
            continue;

        int client = accept(listenSock, nullptr, nullptr);
        if (client < 0)
            continue;

        SocketGuard clientSock(client);
        int clientFlags = fcntl(clientSock, F_GETFL, 0);
        fcntl(clientSock, F_SETFL, clientFlags & ~O_NONBLOCK);
        struct timeval ctv = {10, 0};
        setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));

        /* Read the head (request line + headers), then Content-Length bytes of body. */
        std::string head;
        std::string body;
        bool malformed = false;
        while (head.find("\r\n\r\n") == std::string::npos) {
            char chunk[1024];
            ssize_t r = recv(clientSock, chunk, sizeof(chunk), 0);
            if (r <= 0) {
                malformed = true;
                break;
            }
            head.append(chunk, static_cast<std::size_t>(r));
            if (head.size() > kMaxHeadBytes) {
                malformed = true;
                break;
            }
        }

        if (malformed) {
            // Browsers open speculative connections and drop them; not an error.
            continue;
        }

        size_t headEnd = head.find("\r\n\r\n");
        std::string headOnly = head.substr(0, headEnd);
        body = head.substr(headEnd + 4);

        std::string method = headOnly.substr(0, headOnly.find(' '));
        std::string target = requestTarget(headOnly);
        std::string path = pathOf(target);
        bool zh = lowercased(headerValue(headOnly, "Accept-Language")).find("zh") != std::string::npos;

        if (path == "/favicon.ico") {
            sendResponse(clientSock, 404, "Not Found", "");
            continue;
        }

        bool easytierPath = path == "/easytier";
        bool wireguardPath = path == "/wireguard" || path == "/import";
        if (!easytierPath && !wireguardPath) {
            easytierPath = defaultPage == ImportPage::EasyTier;
            wireguardPath = !easytierPath;
        }

        if (onEvent_) onEvent_(ImportEvent::ClientConnected);

        /* Browsing to the address serves the form (code embedded). */
        if (method != "POST") {
            std::string page = easytierPath
                ? pages::easytierPage(code, loadProfile(), zh)
                : pages::wireguardPage(code, zh);
            sendResponse(clientSock, 200, "OK", page, kHtml);
            continue;
        }

        std::string backPath = easytierPath ? "/easytier" : "/wireguard";

        std::string contentLengthStr = headerValue(headOnly, "Content-Length");
        size_t contentLength = 0;
        if (!contentLengthStr.empty()) {
            auto [ptr, ec] = std::from_chars(
                contentLengthStr.data(), contentLengthStr.data() + contentLengthStr.size(), contentLength);
            if (ec != std::errc{} || ptr != contentLengthStr.data() + contentLengthStr.size())
                contentLength = 0;
        }
        if (contentLength > kMaxBodyBytes) {
            sendResponse(clientSock, 413, "Payload Too Large",
                pages::resultPage(false, "config too large", backPath, zh), kHtml);
            continue;
        }
        while (body.size() < contentLength) {
            char chunk[4096];
            ssize_t r = recv(clientSock, chunk, std::min(sizeof(chunk), contentLength - body.size()), 0);
            if (r <= 0)
                break;
            body.append(chunk, static_cast<std::size_t>(r));
        }

        /* The code comes from the query string (form action / curl) or the form body. */
        std::string supplied = queryParameterValue(target, "code");
        std::string contentType = lowercased(headerValue(headOnly, "Content-Type"));
        bool isForm = contentType.find("application/x-www-form-urlencoded") != std::string::npos;
        if (isForm && supplied.empty())
            supplied = formFieldValue(body, "code");

        if (!sameCode(supplied, code)) {
            tries++;
            sendResponse(clientSock, 403, "Forbidden",
                pages::resultPage(false,
                    zh ? "验证码不匹配：页面可能已过期（Switch 上的导入界面被重新打开过）。请刷新页面后重新提交。"
                       : "Code mismatch: the page is probably stale (the import screen was reopened). Reload the page and submit again.",
                    backPath, zh),
                kHtml);
            if (onEvent_) onEvent_(ImportEvent::BadCode);
            if (tries >= kMaxTries) {
                running_ = false;
                break;
            }
            continue;
        }

        std::string config;
        std::string problem;
        akira::easytier::PortalParams portal;
        if (easytierPath) {
            portal.networkName = formFieldValue(body, "network_name");
            portal.networkSecret = formFieldValue(body, "network_secret");
            portal.host = formFieldValue(body, "host");
            portal.port = toInt(formFieldValue(body, "port"), 22022);
            portal.clientIp = formFieldValue(body, "client_ip");
            portal.keepalive = toInt(formFieldValue(body, "keepalive"), 25);
            portal.mtu = toInt(formFieldValue(body, "mtu"), 0);
            problem = akira::easytier::validatePortalParams(portal);
            if (problem.empty())
                config = akira::easytier::buildPortalWgConfig(portal);
        } else if (isForm) {
            config = formFieldValue(body, "config");
            if (config.find_first_not_of(" \t\r\n") == std::string::npos) {
                akira::web::WgFields fields;
                fields.privateKey = formFieldValue(body, "private_key");
                fields.address = formFieldValue(body, "address");
                fields.publicKey = formFieldValue(body, "public_key");
                fields.endpoint = formFieldValue(body, "endpoint");
                fields.presharedKey = formFieldValue(body, "preshared_key");
                fields.keepalive = formFieldValue(body, "keepalive");
                fields.mtu = formFieldValue(body, "mtu");
                config = anyFieldSet(fields) ? akira::web::buildWgConfigText(fields) : std::string();
            }
        } else {
            config = body;
        }

        if (problem.empty()) {
            config = stripInlineComments(config);
            problem = validateWgConfigText(config);
        }
        if (!problem.empty()) {
            sendResponse(clientSock, 400, "Bad Request",
                pages::resultPage(false, problem, backPath, zh), kHtml);
            if (onEvent_) onEvent_(ImportEvent::Error);
            continue;
        }

        if (!WireGuardManager::instance().saveConfigText(config)) {
            sendResponse(clientSock, 500, "Internal Server Error",
                pages::resultPage(false, WireGuardManager::instance().getLastError(), backPath, zh), kHtml);
            if (onEvent_) onEvent_(ImportEvent::Error);
            continue;
        }

        std::string detail;
        if (easytierPath) {
            saveProfile(portal);
            detail = (zh ? "Switch 虚拟 IP " : "Switch virtual IP ") + portal.clientIp +
                (zh ? "，门户 " : ", portal ") + portal.host + ":" + std::to_string(portal.port);
        }
        sendResponse(clientSock, 200, "OK", pages::resultPage(true, detail, backPath, zh), kHtml);
        if (onEvent_) onEvent_(ImportEvent::Imported);
        break;
    }

    running_ = false;
}

} // namespace akira::wg
