#pragma once

#include <vector>

#include "common/types.h"

namespace hidshield {

class UsbDeviceDetector final {
public:
    [[nodiscard]] std::vector<DeviceDescriptorSnapshot> EnumerateHidDevices() const;

private:
    [[nodiscard]] static bool IsHidClassGuid(const std::string& className);
    [[nodiscard]] static DeviceDescriptorSnapshot BuildSnapshotFromPath(const std::string& devicePath);
};

}  // namespace hidshield
