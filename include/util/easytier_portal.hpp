#ifndef AKIRA_EASYTIER_PORTAL_HPP
#define AKIRA_EASYTIER_PORTAL_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

/*
 * EasyTier "VPN portal" (wg://...) client support.
 *
 * A Switch homebrew cannot run an EasyTier node itself (no TUN, no tokio), but
 * any EasyTier node started with a VPN portal accepts plain WireGuard clients
 * and routes them into the virtual network, including subnet-proxied LANs.
 * EasyTier 2.x derives that portal's WireGuard keys deterministically from the
 * network name + secret (vpn_portal/wireguard.rs, WgConfig::new_for_portal,
 * tunnel::generate_digest_from_str), so the Switch can build the exact client
 * config `easytier-cli vpn-portal` would print from the same inputs a user types
 * into the EasyTier GUI. Free of Switch/borealis dependencies for host tests.
 */
namespace akira::easytier {

using Key = std::array<uint8_t, 32>;

struct PortalParams {
    std::string networkName;
    std::string networkSecret;
    std::string host;      // public IP / domain of the node running the VPN portal
    int port = 22022;      // the portal's WireGuard listen port
    std::string clientIp;  // this Switch's address inside the portal client CIDR
    int keepalive = 25;
    int mtu = 0;           // 0 = WireGuard default
};

// Rust std DefaultHasher (SipHash-1-3, zero keys) over `data`.
uint64_t sipHash13(std::string_view data);

// EasyTier tunnel::generate_digest_from_str(a, b) for a 32-byte digest.
Key legacyDigest(std::string_view a, std::string_view b);

// Client private key (raw, as EasyTier prints it) for the portal of this network.
Key portalClientPrivateKey(std::string_view networkName, std::string_view networkSecret);

// The portal's (server) public key for this network.
Key portalServerPublicKey(std::string_view networkName, std::string_view networkSecret);

std::string base64Encode(const uint8_t* data, std::size_t len);

// Strict dotted-quad IPv4 check ("10.14.14.2").
bool isIpv4(std::string_view text);

// Returns a description of the first problem, or empty when usable.
std::string validatePortalParams(const PortalParams& params);

// wg-quick text that WireGuardManager loads (wg0.conf).
std::string buildPortalWgConfig(const PortalParams& params);

// Persisted form defaults (everything except the secret), key=value lines.
std::string serializeProfile(const PortalParams& params);
PortalParams parseProfile(std::string_view text);

} // namespace akira::easytier

#endif // AKIRA_EASYTIER_PORTAL_HPP
