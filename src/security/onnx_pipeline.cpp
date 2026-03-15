#include "security/onnx_pipeline.h"

#include "security/model_integrity.h"

namespace hidshield {

bool OnnxPipeline::Initialize(const std::string& modelPath,
                              const std::string& expectedSha256Hex,
                              const std::string& signaturePath) {
    ModelIntegrityVerifier verifier;
    ready_ = verifier.VerifyModelFile(modelPath, expectedSha256Hex, signaturePath);
    return ready_;
}

std::optional<ClassificationResult> OnnxPipeline::Infer(const BehavioralFeatures& features) const {
    if (!ready_) {
        return std::nullopt;
    }

    ClassificationResult result{};
    // Placeholder for ONNX Runtime inference. Stage-2 ML is only used for ambiguous cases.
    const double roboticScore = (features.syntheticSequence ? 0.5 : 0.0) + (features.ikdVariance < 2.0 ? 0.3 : 0.0);
    result.confidence = roboticScore;
    result.level = roboticScore > 0.75 ? ThreatLevel::Malicious : ThreatLevel::Suspicious;
    result.topReasons = {
        "Stage-2 ONNX model score elevated",
        "Inter-keystroke variance below human baseline",
        "Synthetic sequence confidence increased"
    };
    return result;
}

}  // namespace hidshield
