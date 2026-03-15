#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hidshield {

enum class ThreatLevel {
    Safe,
    Suspicious,
    Malicious
};

enum class PolicyAction {
    Allow,
    Restrict,
    Quarantine,
    Block
};

enum class DeviceTrustState {
    Unknown,
    Restricted,
    Approved,
    Tombstoned
};

struct DeviceDescriptorSnapshot {
    std::string rawPath;
    std::string instanceId;
    std::string vid;
    std::string pid;
    std::string serial;
    std::string manufacturer;
    std::string product;
    std::vector<std::uint8_t> descriptorBytes;
};

struct DeviceFingerprint {
    std::string canonicalSha256;
    std::string fuzzyIdentity;
    double timingSkewScore{0.0};
    int reputationScore{0};
};

struct HidInputEvent {
    std::chrono::steady_clock::time_point timestamp;
    std::uint16_t scanCode{0};
    bool keyDown{false};
    std::uint32_t processId{0};
    std::string activeWindow;
};

struct BehavioralFeatures {
    double ikdMs50Window{0.0};
    double ikdMs200Window{0.0};
    double ikdMs1sWindow{0.0};
    double ikdVariance{0.0};
    bool syntheticSequence{false};
    bool suspiciousProcessLaunch{false};
};

struct ClassificationResult {
    ThreatLevel level{ThreatLevel::Safe};
    std::array<std::string, 3> topReasons{};
    double confidence{0.0};
};

struct PolicyDecision {
    PolicyAction action{PolicyAction::Restrict};
    std::string reason;
};

struct RemediationContext {
    DeviceDescriptorSnapshot device;
    ClassificationResult classification;
    PolicyDecision decision;
};

}  // namespace hidshield
