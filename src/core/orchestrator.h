#pragma once

#include "platform/etw_provider.h"
#include "platform/usb_device_detector.h"
#include "security/behavioral_analyzer.h"
#include "security/device_fingerprint_engine.h"
#include "security/onnx_pipeline.h"
#include "security/policy_engine.h"
#include "security/remediation_engine.h"
#include "security/threat_classifier.h"

namespace hidshield {

class Orchestrator final {
public:
    bool Initialize();
    void RunSinglePass();

private:
    void RegisterDefaultPlaybooks();

    UsbDeviceDetector detector_{};
    DeviceFingerprintEngine fingerprintEngine_{};
    BehavioralAnalyzer behavioralAnalyzer_{};
    ThreatClassifier classifier_{};
    OnnxPipeline onnxPipeline_{};
    PolicyEngine policyEngine_{};
    RemediationEngine remediationEngine_{};
    EtwProvider etw_{};
};

}  // namespace hidshield
