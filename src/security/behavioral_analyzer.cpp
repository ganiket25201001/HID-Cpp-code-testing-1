#include "security/behavioral_analyzer.h"

#include <algorithm>
#include <cmath>
#include <numeric>

namespace hidshield {

BehavioralFeatures BehavioralAnalyzer::ExtractFeatures(const std::vector<HidInputEvent>& events) const {
    BehavioralFeatures features{};
    if (events.size() < 2) {
        return features;
    }

    features.ikdMs50Window = ComputeMeanIksMs(events, std::chrono::milliseconds(50));
    features.ikdMs200Window = ComputeMeanIksMs(events, std::chrono::milliseconds(200));
    features.ikdMs1sWindow = ComputeMeanIksMs(events, std::chrono::seconds(1));
    features.ikdVariance = ComputeVarianceIksMs(events);
    features.syntheticSequence = DetectSyntheticPattern(events);
    features.suspiciousProcessLaunch = std::any_of(events.begin(), events.end(), [](const HidInputEvent& event) {
        return event.activeWindow.find("powershell") != std::string::npos ||
               event.activeWindow.find("cmd.exe") != std::string::npos;
    });

    return features;
}

double BehavioralAnalyzer::ComputeMeanIksMs(const std::vector<HidInputEvent>& events, std::chrono::milliseconds window) {
    const auto now = events.back().timestamp;
    std::vector<double> deltas;

    for (std::size_t i = 1; i < events.size(); ++i) {
        if (now - events[i].timestamp > window) {
            continue;
        }
        const auto delta = std::chrono::duration_cast<std::chrono::microseconds>(events[i].timestamp - events[i - 1].timestamp).count() / 1000.0;
        if (delta >= 0.0) {
            deltas.push_back(delta);
        }
    }

    if (deltas.empty()) {
        return 0.0;
    }
    const double sum = std::accumulate(deltas.begin(), deltas.end(), 0.0);
    return sum / static_cast<double>(deltas.size());
}

double BehavioralAnalyzer::ComputeVarianceIksMs(const std::vector<HidInputEvent>& events) {
    std::vector<double> deltas;
    deltas.reserve(events.size() - 1U);
    for (std::size_t i = 1; i < events.size(); ++i) {
        const auto delta = std::chrono::duration_cast<std::chrono::microseconds>(events[i].timestamp - events[i - 1].timestamp).count() / 1000.0;
        if (delta >= 0.0) {
            deltas.push_back(delta);
        }
    }

    if (deltas.empty()) {
        return 0.0;
    }

    const double mean = std::accumulate(deltas.begin(), deltas.end(), 0.0) / static_cast<double>(deltas.size());
    double acc = 0.0;
    for (const auto value : deltas) {
        const auto d = value - mean;
        acc += d * d;
    }
    return acc / static_cast<double>(deltas.size());
}

bool BehavioralAnalyzer::DetectSyntheticPattern(const std::vector<HidInputEvent>& events) {
    if (events.size() < 8) {
        return false;
    }

    std::size_t repeated = 0;
    for (std::size_t i = 2; i < events.size(); ++i) {
        if (events[i].scanCode == events[i - 1].scanCode && events[i - 1].scanCode == events[i - 2].scanCode) {
            ++repeated;
        }
    }

    const double ratio = static_cast<double>(repeated) / static_cast<double>(events.size());
    return ratio > 0.4;
}

}  // namespace hidshield
