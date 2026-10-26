#ifndef AKIRA_WG_IMPORT_PAGES_HPP
#define AKIRA_WG_IMPORT_PAGES_HPP

#include <string>

#include "util/easytier_portal.hpp"

/*
 * HTML served by WgImportServer to the phone / PC browser. Plain strings, no
 * Switch dependencies; `zh` picks Simplified Chinese from Accept-Language.
 */
namespace akira::wg::pages {

std::string easytierPage(const std::string& code, const akira::easytier::PortalParams& defaults, bool zh);
std::string wireguardPage(const std::string& code, bool zh);
std::string resultPage(bool ok, const std::string& detail, const std::string& backPath, bool zh);

} // namespace akira::wg::pages

#endif // AKIRA_WG_IMPORT_PAGES_HPP
