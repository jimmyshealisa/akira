#include "core/wg_import_server.hpp"

#include "core/wireguard_manager.hpp"
#include "util/net_wrappers.hpp"
#include "util/web_form.hpp"

#include <borealis.hpp>
#include <algorithm>
#include <charconv>
#include <cstring>
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
using akira::web::validateWgConfigText;

namespace {

constexpr std::size_t kMaxHeadBytes = 16 * 1024;
constexpr std::size_t kMaxBodyBytes = 128 * 1024;

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

void sendResponse(int fd, int status, const char* reason, const std::string& body)
{
    std::string response = "HTTP/1.1 " + std::to_string(status) + " " + reason +
        "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < response.size()) {
        ssize_t r = send(fd, response.data() + sent, response.size() - sent, 0);
        if (r <= 0)
            return;
        sent += static_cast<std::size_t>(r);
    }
}

std::string importPage(const std::string& code)
{
    return
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Akira WireGuard import</title></head>"
        "<body style=\"font-family:sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem\">"
        "<h2>Akira WireGuard import</h2>"
        "<p>Paste the wg-quick config (from EasyTier's WireGuard setup) and submit.</p>"
        "<form method=\"POST\" action=\"/import?code=" + code + "\">"
        "<textarea name=\"config\" rows=\"14\" style=\"width:100%\" "
        "placeholder=\"[Interface]\nPrivateKey = ...\nAddress = 10.x.x.x/24\n\n[Peer]\nPublicKey = ...\nEndpoint = host:port\"></textarea>"
        "<p><button style=\"padding:.6rem 2rem\">Import</button></p>"
        "</form></body></html>";
}

} // namespace

WgImportServer::~WgImportServer() {
    stop();
}

void WgImportServer::start(int port, const std::string& code, EventCallback onEvent) {
    stop();
    onEvent_ = std::move(onEvent);
    running_ = true;
    thread_ = std::thread(&WgImportServer::run, this, port, code);
}

void WgImportServer::stop() {
    running_ = false;
    if (thread_.joinable())
        thread_.join();
}

void WgImportServer::run(int port, std::string code) {
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
        listen(listenSock, 1) < 0) {
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

        if (onEvent_) onEvent_(ImportEvent::ClientConnected);

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
            sendResponse(clientSock, 400, "Bad Request", "malformed request");
            if (onEvent_) onEvent_(ImportEvent::Error);
            continue;
        }

        size_t headEnd = head.find("\r\n\r\n");
        std::string headOnly = head.substr(0, headEnd);
        body = head.substr(headEnd + 4);

        std::string target = requestTarget(headOnly);
        std::string contentLengthStr = headerValue(headOnly, "Content-Length");
        size_t contentLength = 0;
        if (!contentLengthStr.empty()) {
            auto [ptr, ec] = std::from_chars(
                contentLengthStr.data(), contentLengthStr.data() + contentLengthStr.size(), contentLength);
            if (ec != std::errc{} || ptr != contentLengthStr.data() + contentLengthStr.size())
                contentLength = 0;
        }
        if (contentLength > kMaxBodyBytes) {
            sendResponse(clientSock, 413, "Payload Too Large", "config too large");
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
        std::string config;
        if (contentType.find("application/x-www-form-urlencoded") != std::string::npos) {
            if (supplied.empty())
                supplied = formFieldValue(body, "code");
            config = formFieldValue(body, "config");
        } else {
            config = body;
        }

        if (!sameCode(supplied, code)) {
            sendResponse(clientSock, 403, "Forbidden", "wrong code");
            tries++;
            if (tries >= kMaxTries) {
                if (onEvent_) onEvent_(ImportEvent::BadCode);
                running_ = false;
                break;
            }
            if (onEvent_) onEvent_(ImportEvent::BadCode);
            continue;
        }

        std::string problem = validateWgConfigText(config);
        if (!problem.empty()) {
            sendResponse(clientSock, 400, "Bad Request", "invalid config: " + problem);
            if (onEvent_) onEvent_(ImportEvent::Error);
            continue;
        }

        if (!WireGuardManager::instance().saveConfigText(config)) {
            sendResponse(clientSock, 500, "Internal Server Error", "failed to save config");
            if (onEvent_) onEvent_(ImportEvent::Error);
            continue;
        }

        sendResponse(clientSock, 200, "OK", "imported");
        if (onEvent_) onEvent_(ImportEvent::Imported);
        break;
    }

    running_ = false;
}

} // namespace akira::wg
