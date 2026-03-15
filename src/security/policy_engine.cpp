#include "security/policy_engine.h"

namespace hidshield {

void PolicyEngine::AddAllowlistedFingerprint(const std::string& fingerprintSha256) {
    allowlist_.insert(fingerprintSha256);
}

void PolicyEngine::AddTombstonedFingerprint(const std::string& fingerprintSha256) {
    tombstones_.insert(fingerprintSha256);
}

PolicyDecision PolicyEngine::Decide(const DeviceFingerprint& fingerprint,
                                    const ClassificationResult& classification,
                                    bool silentEnterpriseMode) const {
    if (tombstones_.contains(fingerprint.canonicalSha256)) {
        return {PolicyAction::Block, "Device fingerprint tombstoned"};
    }

    if (classification.level == ThreatLevel::Malicious) {
        return {PolicyAction::Block, "Threat level malicious"};
    }

    if (classification.level == ThreatLevel::Suspicious) {
        return {silentEnterpriseMode ? PolicyAction::Quarantine : PolicyAction::Restrict,
                "Suspicious behavior requires containment"};
    }

    if (allowlist_.contains(fingerprint.canonicalSha256)) {
        return {PolicyAction::Allow, "Trusted fingerprint"};
    }

    return {PolicyAction::Restrict, "Zero Trust default for unknown device"};
}

}  // namespace hidshield
