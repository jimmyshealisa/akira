#ifndef AKIRA_QR_CODE_VIEW_HPP
#define AKIRA_QR_CODE_VIEW_HPP

#include <borealis.hpp>

#include <string>
#include <vector>

/*
 * Square QR code drawn with NanoVG rectangles. The matrix is encoded once in
 * setContent() and cached, so draw() only walks the module grid.
 */
class QrCodeView : public brls::View {
public:
    explicit QrCodeView(float size = 320.0f);

    // Returns false when the payload does not fit any QR version.
    bool setContent(const std::string& text);
    bool hasContent() const { return m_size > 0; }

    void draw(NVGcontext* vg, float x, float y, float width, float height,
              brls::Style style, brls::FrameContext* ctx) override;

private:
    static constexpr int kQuietZone = 4;

    int m_size = 0;
    std::vector<bool> m_modules;
};

#endif // AKIRA_QR_CODE_VIEW_HPP
