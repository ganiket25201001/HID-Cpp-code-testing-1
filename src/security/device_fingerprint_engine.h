#pragma once

#include "common/types.h"

namespace hidshield {

class DeviceFingerprintEngine final {
public:
    [[nodiscard]] DeviceFingerprint ComputeFingerprint(const DeviceDescriptorSnapshot& snapshot) const;

private:
    [[nodiscard]] static std::string Sha256Hex(const std::vector<std::uint8_t>& bytes);
    [[nodiscard]] static std::string BuildFuzzyIdentity(const DeviceDescriptorSnapshot& snapshot);
};

}  // namespace hidshield
