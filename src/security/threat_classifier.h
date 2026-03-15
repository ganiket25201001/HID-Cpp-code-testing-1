#pragma once

#include "common/types.h"

namespace hidshield {

class ThreatClassifier final {
public:
    [[nodiscard]] ClassificationResult Classify(const DeviceFingerprint& fingerprint,
                                                const BehavioralFeatures& features) const;
};

}  // namespace hidshield
