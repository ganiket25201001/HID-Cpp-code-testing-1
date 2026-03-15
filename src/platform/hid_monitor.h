#pragma once

#include <Windows.h>

#include <optional>
#include <vector>

#include "common/lock_free_queue.h"
#include "common/types.h"

namespace hidshield {

class HidMonitor final {
public:
    HidMonitor();

    bool Start();
    void Stop();
    void IngestRawInput(const RAWINPUT& rawInput, std::uint32_t processId, const std::string& activeWindow);
    [[nodiscard]] std::vector<HidInputEvent> DrainBatch(std::size_t maxBatch);

private:
    bool running_{false};
    LockFreeQueue<HidInputEvent, 1024> queue_{};
};

}  // namespace hidshield
