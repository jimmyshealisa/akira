#include "views/qr_code_view.hpp"

#include <qrcodegen.hpp>

#include <algorithm>
#include <cmath>
#include <exception>

QrCodeView::QrCodeView(float size) {
    this->setWidth(size);
    this->setHeight(size);
}

bool QrCodeView::setContent(const std::string& text) {
    m_size = 0;
    m_modules.clear();

    try {
        // A backlit screen never gets scratched or smudged like print, so LOW ECC is
        // enough and keeps a ~600-byte OAuth URL at a version with large modules.
        // encodeText still bumps the ECC level up when the chosen version has room.
        qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::LOW);
        const int size = qr.getSize();
        m_modules.resize(static_cast<size_t>(size) * size);
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
                m_modules[static_cast<size_t>(y) * size + x] = qr.getModule(x, y);
        m_size = size;
    } catch (const std::exception& e) {
        brls::Logger::error("QR encode failed ({} bytes): {}", text.size(), e.what());
        return false;
    }

    this->invalidate();
    return true;
}

void QrCodeView::draw(NVGcontext* vg, float x, float y, float width, float height,
                      brls::Style style, brls::FrameContext* ctx) {
    (void)style;
    (void)ctx;

    const float side = std::min(width, height);
    const float ox = x + (width - side) * 0.5f;
    const float oy = y + (height - side) * 0.5f;

    // White card behind the code: scanners need a light quiet zone even on dark themes.
    nvgBeginPath(vg);
    nvgRoundedRect(vg, ox, oy, side, side, 8.0f);
    nvgFillColor(vg, nvgRGB(255, 255, 255));
    nvgFill(vg);

    if (m_size <= 0)
        return;

    const int total = m_size + kQuietZone * 2;
    // Snap modules to whole pixels so neighbouring rects do not leave hairline seams.
    const float module = std::floor(side / static_cast<float>(total));
    if (module < 1.0f)
        return;

    const float codeSide = module * static_cast<float>(m_size);
    const float cx = std::round(ox + (side - codeSide) * 0.5f);
    const float cy = std::round(oy + (side - codeSide) * 0.5f);

    nvgBeginPath(vg);
    for (int row = 0; row < m_size; row++) {
        int col = 0;
        while (col < m_size) {
            if (!m_modules[static_cast<size_t>(row) * m_size + col]) {
                col++;
                continue;
            }
            // Merge horizontal runs into one rect to keep the path short.
            int run = 1;
            while (col + run < m_size && m_modules[static_cast<size_t>(row) * m_size + col + run])
                run++;
            nvgRect(vg, cx + col * module, cy + row * module, run * module, module);
            col += run;
        }
    }
    nvgFillColor(vg, nvgRGB(0, 0, 0));
    nvgFill(vg);
}
