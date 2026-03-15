#pragma once

#include <set>
#include <string>

#include "common/types.h"

namespace hidshield {

class PolicyEngine final {
public:
    void AddAllowlistedFingerprint(const std::string& fingerprintSha256);
    void AddTombstonedFingerprint(const std::string& fingerprintSha256);

    [[nodiscard]] PolicyDecision Decide(const DeviceFingerprint& fingerprint,
                                        const ClassificationResult& classification,
                                        bool silentEnterpriseMode) const;

private:
    std::set<std::string> allowlist_{};
    std::set<std::string> tombstones_{};
};

}  // namespace hidshield
