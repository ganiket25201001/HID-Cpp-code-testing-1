#include "core/orchestrator.h"

#include <iostream>

namespace hidshield {

bool Orchestrator::Initialize() {
    if (!etw_.Register()) {
        return false;
    }

    RegisterDefaultPlaybooks();
    return true;
}

void Orchestrator::RunSinglePass() {
    const auto devices = detector_.EnumerateHidDevices();
    for (const auto& device : devices) {
        const auto fingerprint = fingerprintEngine_.ComputeFingerprint(device);

        // Simulated event batch in bootstrap stage.
        std::vector<HidInputEvent> events;
        const auto now = std::chrono::steady_clock::now();
        for (int i = 0; i < 12; ++i) {
            events.push_back(HidInputEvent{now + std::chrono::milliseconds(i * 4), 30, true, 0, "powershell.exe"});
        }

        const auto features = behavioralAnalyzer_.ExtractFeatures(events);
        auto classification = classifier_.Classify(fingerprint, features);

        if (classification.level == ThreatLevel::Suspicious) {
            const auto stage2 = onnxPipeline_.Infer(features);
            if (stage2.has_value() && stage2->confidence > classification.confidence) {
                classification = stage2.value();
            }
        }

        const auto decision = policyEngine_.Decide(fingerprint, classification, true);
        etw_.EmitDeviceEvent(device, "HID device evaluated");
        etw_.EmitThreatEvent(classification, decision.reason);

        const RemediationContext ctx{device, classification, decision};
        remediationEngine_.Execute(ctx);

        std::cout << "Device " << device.vid << ":" << device.pid
                  << " threat=" << static_cast<int>(classification.level)
                  << " action=" << static_cast<int>(decision.action)
                  << " reason=" << decision.reason << "\n";
    }
}

void Orchestrator::RegisterDefaultPlaybooks() {
    remediationEngine_.Register(PlaybookTrigger::Malicious, [](const RemediationContext& context) {
        std::cout << "[PLAYBOOK] MALICIOUS: disable HID, terminate spawned process, create ticket for "
                  << context.device.vid << ":" << context.device.pid << "\n";
    });

    remediationEngine_.Register(PlaybookTrigger::Suspicious, [](const RemediationContext& context) {
        std::cout << "[PLAYBOOK] SUSPICIOUS: quarantine + rate-limit for "
                  << context.device.vid << ":" << context.device.pid << "\n";
    });

    remediationEngine_.Register(PlaybookTrigger::SafeAfterAnomaly, [](const RemediationContext& context) {
        std::cout << "[PLAYBOOK] SAFE AFTER ANOMALY: elevated monitoring for "
                  << context.device.vid << ":" << context.device.pid << "\n";
    });
}

}  // namespace hidshield
