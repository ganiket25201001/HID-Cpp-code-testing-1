#pragma once

#include <functional>
#include <unordered_map>
#include <vector>

#include "common/types.h"

namespace hidshield {

enum class PlaybookTrigger {
    SafeAfterAnomaly,
    Suspicious,
    Malicious
};

class RemediationEngine final {
public:
    using ActionHandler = std::function<void(const RemediationContext&)>;

    void Register(PlaybookTrigger trigger, ActionHandler handler);
    void Execute(const RemediationContext& context) const;

private:
    std::unordered_map<PlaybookTrigger, std::vector<ActionHandler>> handlers_{};
};

}  // namespace hidshield
