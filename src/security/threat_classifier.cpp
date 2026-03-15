#include "security/threat_classifier.h"

namespace hidshield {

ClassificationResult ThreatClassifier::Classify(const DeviceFingerprint& fingerprint,
                                                const BehavioralFeatures& features) const {
    ClassificationResult result{};

    double score = 0.0;
    if (fingerprint.reputationScore < -30) {
        score += 0.5;
        result.topReasons[0] = "Historical device reputation degraded";
    }
    if (features.syntheticSequence) {
        score += 0.3;
        result.topReasons[1] = "Synthetic keystroke sequence detected";
    }
    if (features.ikdVariance < 1.0 && features.ikdMs200Window > 0.0 && features.ikdMs200Window < 15.0) {
        score += 0.2;
        result.topReasons[2] = "Near-constant inter-keystroke timing";
    }
    if (features.suspiciousProcessLaunch) {
        score += 0.3;
        if (result.topReasons[2].empty()) {
            result.topReasons[2] = "Suspicious shell process correlation";
        }
    }

    result.confidence = score > 1.0 ? 1.0 : score;
    if (score >= 0.8) {
        result.level = ThreatLevel::Malicious;
    } else if (score >= 0.4) {
        result.level = ThreatLevel::Suspicious;
    } else {
        result.level = ThreatLevel::Safe;
    }

    return result;
}

}  // namespace hidshield
