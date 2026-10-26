#ifndef AKIRA_WEB_FORM_HPP
#define AKIRA_WEB_FORM_HPP

#include <string>
#include <string_view>

/*
 * Minimal helpers for talking to a plain-text browser form, used by the WireGuard
 * config import server. Kept free of Switch/borealis dependencies so it is unit
 * testable on the host.
 */
namespace akira::web {

// Percent-decoding with '+' as space. Invalid escapes are passed through verbatim.
std::string urlDecode(std::string_view value);

// Value of `key` in an application/x-www-form-urlencoded body ("a=1&b=2"), decoded.
// Empty when the key is absent.
std::string formFieldValue(std::string_view body, std::string_view key);

// Value of `key` in the request target's query string ("POST /import?code=1234 ...").
std::string queryParameterValue(std::string_view target, std::string_view key);

// The "POST /path?query HTTP/1.1" target from the start of a request head.
std::string requestTarget(std::string_view requestHead);

/*
 * Light sanity check for a wg-quick style config before it is written to the SD
 * card. WireGuardManager does the real parsing on load; this only rejects input
 * that cannot possibly parse, so the phone gets a useful error instead of the
 * Switch UI. Returns an error description, or empty when acceptable.
 */
std::string validateWgConfigText(std::string_view text);

} // namespace akira::web

#endif // AKIRA_WEB_FORM_HPP
