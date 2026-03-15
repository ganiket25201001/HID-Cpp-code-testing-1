#include "security/remediation_engine.h"

namespace hidshield {

void RemediationEngine::Register(PlaybookTrigger trigger, ActionHandler handler) {
    handlers_[trigger].push_back(std::move(handler));
}

void RemediationEngine::Execute(const RemediationContext& context) const {
    PlaybookTrigger trigger = PlaybookTrigger::SafeAfterAnomaly;
    if (context.classification.level == ThreatLevel::Malicious) {
        trigger = PlaybookTrigger::Malicious;
    } else if (context.classification.level == ThreatLevel::Suspicious) {
        trigger = PlaybookTrigger::Suspicious;
    }

    const auto it = handlers_.find(trigger);
    if (it == handlers_.end()) {
        return;
    }

    for (const auto& handler : it->second) {
        handler(context);
    }
}

}  // namespace hidshield
