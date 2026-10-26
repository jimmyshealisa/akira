#include "util/easytier_portal.hpp"

#include <charconv>
#include <string>
#include <vector>

// Monocypher, linked through libwireguard.a (clamps the scalar itself).
extern "C" void crypto_x25519_public_key(uint8_t public_key[32], const uint8_t secret_key[32]);

namespace akira::easytier {

namespace {

inline uint64_t rotl(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

inline void sipRound(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3)
{
    v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
    v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
}

std::string trimmed(std::string_view s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos)
        return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(start, end - start + 1));
}

bool isHostChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '-' || c == '_';
}

int parseInt(std::string_view text, int fallback)
{
    int value = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size())
        return fallback;
    return value;
}

} // namespace

uint64_t sipHash13(std::string_view data)
{
    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;

    const auto* in = reinterpret_cast<const uint8_t*>(data.data());
    const std::size_t len = data.size();
    const std::size_t full = len - (len % 8);

    for (std::size_t i = 0; i < full; i += 8) {
        uint64_t m = 0;
        for (int b = 0; b < 8; b++)
            m |= static_cast<uint64_t>(in[i + b]) << (8 * b);
        v3 ^= m;
        sipRound(v0, v1, v2, v3);
        v0 ^= m;
    }

    uint64_t last = static_cast<uint64_t>(len & 0xff) << 56;
    for (std::size_t b = 0; b < len - full; b++)
        last |= static_cast<uint64_t>(in[full + b]) << (8 * b);

    v3 ^= last;
    sipRound(v0, v1, v2, v3);
    v0 ^= last;
    v2 ^= 0xff;
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    sipRound(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

Key legacyDigest(std::string_view a, std::string_view b)
{
    // DefaultHasher is a stream: write(a); write(b); finish() == hash(a ++ b).
    // After each 8-byte shard the whole digest-so-far is written again.
    std::string stream;
    stream.reserve(a.size() + b.size() + 80);
    stream.append(a);
    stream.append(b);

    Key digest{};
    for (int i = 0; i < 4; i++) {
        uint64_t h = sipHash13(stream);
        for (int k = 0; k < 8; k++)
            digest[i * 8 + k] = static_cast<uint8_t>(h >> (56 - 8 * k));
        stream.append(reinterpret_cast<const char*>(digest.data()), static_cast<std::size_t>((i + 1) * 8));
    }
    return digest;
}

Key portalClientPrivateKey(std::string_view networkName, std::string_view networkSecret)
{
    std::string seed = std::string(networkName) + std::string(networkSecret);
    return legacyDigest("client", seed);
}

Key portalServerPublicKey(std::string_view networkName, std::string_view networkSecret)
{
    std::string seed = std::string(networkName) + std::string(networkSecret);
    Key serverPrivate = legacyDigest("server", seed);
    Key serverPublic{};
    crypto_x25519_public_key(serverPublic.data(), serverPrivate.data());
    return serverPublic;
}

std::string base64Encode(const uint8_t* data, std::size_t len)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len)
            n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len)
            n |= data[i + 2];
        out += table[(n >> 18) & 63];
        out += table[(n >> 12) & 63];
        out += i + 1 < len ? table[(n >> 6) & 63] : '=';
        out += i + 2 < len ? table[n & 63] : '=';
    }
    return out;
}

bool isIpv4(std::string_view text)
{
    int parts = 0;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t dot = text.find('.', pos);
        std::string_view part = text.substr(pos, dot == std::string_view::npos ? std::string_view::npos : dot - pos);
        if (part.empty() || part.size() > 3)
            return false;
        for (char c : part) {
            if (c < '0' || c > '9')
                return false;
        }
        if (parseInt(part, 256) > 255)
            return false;
        parts++;
        if (dot == std::string_view::npos)
            break;
        pos = dot + 1;
    }
    return parts == 4;
}

std::string validatePortalParams(const PortalParams& p)
{
    if (trimmed(p.networkName).empty())
        return "network name is required";
    std::string host = trimmed(p.host);
    if (host.empty())
        return "portal address is required";
    for (char c : host) {
        if (!isHostChar(c))
            return "portal address must be an IPv4 address or domain name, without port";
    }
    if (p.port < 1 || p.port > 65535)
        return "portal port must be 1-65535";
    if (!isIpv4(trimmed(p.clientIp)))
        return "Switch virtual IP must be an IPv4 address such as 10.14.14.2";
    if (p.keepalive < 0 || p.keepalive > 3600)
        return "keepalive must be 0-3600";
    if (p.mtu != 0 && (p.mtu < 576 || p.mtu > 1420))
        return "MTU must be 576-1420 (or empty)";
    return {};
}

std::string buildPortalWgConfig(const PortalParams& p)
{
    Key clientPrivate = portalClientPrivateKey(p.networkName, p.networkSecret);
    Key serverPublic = portalServerPublicKey(p.networkName, p.networkSecret);

    std::string conf;
    conf += "# Generated by Akira from an EasyTier network (VPN portal)\n";
    conf += "[Interface]\n";
    conf += "PrivateKey = " + base64Encode(clientPrivate.data(), clientPrivate.size()) + "\n";
    conf += "Address = " + trimmed(p.clientIp) + "/32\n";
    if (p.mtu != 0)
        conf += "MTU = " + std::to_string(p.mtu) + "\n";
    conf += "\n[Peer]\n";
    conf += "PublicKey = " + base64Encode(serverPublic.data(), serverPublic.size()) + "\n";
    conf += "AllowedIPs = 0.0.0.0/0\n";
    conf += "Endpoint = " + trimmed(p.host) + ":" + std::to_string(p.port) + "\n";
    conf += "PersistentKeepalive = " + std::to_string(p.keepalive) + "\n";
    return conf;
}

std::string serializeProfile(const PortalParams& p)
{
    std::string out;
    out += "network_name=" + p.networkName + "\n";
    out += "host=" + p.host + "\n";
    out += "port=" + std::to_string(p.port) + "\n";
    out += "client_ip=" + p.clientIp + "\n";
    out += "keepalive=" + std::to_string(p.keepalive) + "\n";
    out += "mtu=" + std::to_string(p.mtu) + "\n";
    return out;
}

PortalParams parseProfile(std::string_view text)
{
    PortalParams p;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        std::string_view line = text.substr(pos, eol == std::string_view::npos ? std::string_view::npos : eol - pos);
        pos = eol == std::string_view::npos ? text.size() : eol + 1;

        std::size_t eq = line.find('=');
        if (eq == std::string_view::npos)
            continue;
        std::string key = trimmed(line.substr(0, eq));
        std::string value = trimmed(line.substr(eq + 1));
        if (key == "network_name")
            p.networkName = value;
        else if (key == "host")
            p.host = value;
        else if (key == "port")
            p.port = parseInt(value, p.port);
        else if (key == "client_ip")
            p.clientIp = value;
        else if (key == "keepalive")
            p.keepalive = parseInt(value, p.keepalive);
        else if (key == "mtu")
            p.mtu = parseInt(value, p.mtu);
    }
    return p;
}

} // namespace akira::easytier
