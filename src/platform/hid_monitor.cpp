#include "platform/hid_monitor.h"

#include <Windows.h>

namespace hidshield {

HidMonitor::HidMonitor() = default;

bool HidMonitor::Start() {
    running_ = true;
    return true;
}

void HidMonitor::Stop() {
    running_ = false;
}

void HidMonitor::IngestRawInput(const RAWINPUT& rawInput, std::uint32_t processId, const std::string& activeWindow) {
    if (!running_ || rawInput.header.dwType != RIM_TYPEKEYBOARD) {
        return;
    }

    HidInputEvent event{};
    event.timestamp = std::chrono::steady_clock::now();
    event.scanCode = rawInput.data.keyboard.MakeCode;
    event.keyDown = (rawInput.data.keyboard.Flags & RI_KEY_BREAK) == 0U;
    event.processId = processId;
    event.activeWindow = activeWindow;
    (void)queue_.TryPush(event);
}

std::vector<HidInputEvent> HidMonitor::DrainBatch(std::size_t maxBatch) {
    std::vector<HidInputEvent> events;
    events.reserve(maxBatch);

    while (events.size() < maxBatch) {
        auto next = queue_.TryPop();
        if (!next.has_value()) {
            break;
        }
        events.push_back(next.value());
    }
    return events;
}

}  // namespace hidshield
