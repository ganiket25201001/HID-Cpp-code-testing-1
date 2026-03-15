#pragma once

#include <optional>
#include <string>

#include "common/types.h"

namespace hidshield {

class OnnxPipeline final {
public:
    bool Initialize(const std::string& modelPath,
                    const std::string& expectedSha256Hex,
                    const std::string& signaturePath);

    [[nodiscard]] std::optional<ClassificationResult> Infer(const BehavioralFeatures& features) const;

private:
    bool ready_{false};
};

}  // namespace hidshield
