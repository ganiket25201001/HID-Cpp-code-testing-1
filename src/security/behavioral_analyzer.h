#pragma once

#include <vector>

#include "common/types.h"

namespace hidshield {

class BehavioralAnalyzer final {
public:
    [[nodiscard]] BehavioralFeatures ExtractFeatures(const std::vector<HidInputEvent>& events) const;

private:
    [[nodiscard]] static double ComputeMeanIksMs(const std::vector<HidInputEvent>& events, std::chrono::milliseconds window);
    [[nodiscard]] static double ComputeVarianceIksMs(const std::vector<HidInputEvent>& events);
    [[nodiscard]] static bool DetectSyntheticPattern(const std::vector<HidInputEvent>& events);
};

}  // namespace hidshield
