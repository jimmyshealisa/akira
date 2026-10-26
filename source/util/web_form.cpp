#include "util/web_form.hpp"

#include <cctype>

namespace akira::web {

namespace {

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

std::string_view trim(std::string_view value)
{
    constexpr std::string_view WHITESPACE = " \t\r\n";
    size_t begin = value.find_first_not_of(WHITESPACE);
    if (begin == std::string_view::npos)
        return {};
    size_t end = value.find_last_not_of(WHITESPACE);
    return value.substr(begin, end - begin + 1);
}

bool iequals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

} // namespace

std::string urlDecode(std::string_view value)
{
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); i++) {
        if (value[i] == '+') {
            out.push_back(' ');
            continue;
        }
        if (value[i] == '%' && i + 2 < value.size()) {
            int hi = hexValue(value[i + 1]);
            int lo = hexValue(value[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(value[i]);
    }
    return out;
}

std::string formFieldValue(std::string_view body, std::string_view key)
{
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t amp = body.find('&', pos);
        std::string_view pair = body.substr(pos, amp == std::string_view::npos
            ? std::string_view::npos
            : amp - pos);
        size_t eq = pair.find('=');
        std::string_view name = eq == std::string_view::npos ? pair : pair.substr(0, eq);
        if (iequals(trim(name), key))
            return urlDecode(eq == std::string_view::npos ? std::string_view{} : pair.substr(eq + 1));
        if (amp == std::string_view::npos)
            break;
        pos = amp + 1;
    }
    return {};
}

std::string queryParameterValue(std::string_view target, std::string_view key)
{
    size_t query = target.find('?');
    if (query == std::string_view::npos)
        return {};
    return formFieldValue(target.substr(query + 1), key);
}

std::string requestTarget(std::string_view requestHead)
{
    size_t space = requestHead.find(' ');
    if (space == std::string_view::npos)
        return {};
    size_t end = requestHead.find(' ', space + 1);
    if (end == std::string_view::npos)
        end = requestHead.size();
    return std::string(requestHead.substr(space + 1, end - space - 1));
}

std::string validateWgConfigText(std::string_view text)
{
    if (trim(text).empty())
        return "config is empty";

    std::string_view section;
    bool hasPrivateKey = false;
    bool hasAddress = false;
    bool hasPeerSection = false;
    bool hasPublicKey = false;
    bool hasEndpoint = false;

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string_view line = text.substr(pos, nl == std::string_view::npos
            ? std::string_view::npos
            : nl - pos);
        pos = nl == std::string_view::npos ? text.size() + 1 : nl + 1;

        line = trim(line);
        if (line.empty() || line[0] == '#')
            continue;

        if (line.front() == '[') {
            size_t end = line.find(']');
            if (end != std::string_view::npos)
                section = line.substr(1, end - 1);
            if (iequals(section, "Peer"))
                hasPeerSection = true;
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string_view::npos)
            continue;
        std::string_view key = trim(line.substr(0, eq));
        std::string_view value = trim(line.substr(eq + 1));
        if (value.empty())
            continue;

        if (iequals(section, "Interface")) {
            if (iequals(key, "PrivateKey"))
                hasPrivateKey = true;
            else if (iequals(key, "Address"))
                hasAddress = true;
        } else if (iequals(section, "Peer")) {
            if (iequals(key, "PublicKey"))
                hasPublicKey = true;
            else if (iequals(key, "Endpoint"))
                hasEndpoint = true;
        }
    }

    if (!hasPrivateKey)
        return "missing [Interface] PrivateKey";
    if (!hasAddress)
        return "missing [Interface] Address";
    if (!hasPeerSection)
        return "missing [Peer] section";
    if (!hasPublicKey)
        return "missing [Peer] PublicKey";
    if (!hasEndpoint)
        return "missing [Peer] Endpoint";
    return {};
}

} // namespace akira::web
