#include "platform/etw_provider.h"

#include <Windows.h>

#include <string>

namespace hidshield {
namespace {

constexpr GUID kProviderGuid = {0x7c6a2892, 0x4db6, 0x4f37, {0x84, 0x80, 0xc9, 0x13, 0x31, 0x1b, 0x8f, 0x82}};

}  // namespace

EtwProvider::EtwProvider() = default;

EtwProvider::~EtwProvider() {
    Unregister();
}

bool EtwProvider::Register() {
    if (registrationHandle_ != 0) {
        return true;
    }
    return EventRegister(&kProviderGuid, nullptr, nullptr, &registrationHandle_) == ERROR_SUCCESS;
}

void EtwProvider::Unregister() {
    if (registrationHandle_ == 0) {
        return;
    }
    EventUnregister(registrationHandle_);
    registrationHandle_ = 0;
}

void EtwProvider::EmitDeviceEvent(const DeviceDescriptorSnapshot& device, const std::string& message) const {
    if (registrationHandle_ == 0) {
        return;
    }
    std::string payload = "device=" + device.vid + ":" + device.pid + " msg=" + message;
    EventWriteString(registrationHandle_, 0, 0, std::wstring(payload.begin(), payload.end()).c_str());
}

void EtwProvider::EmitThreatEvent(const ClassificationResult& result, const std::string& message) const {
    if (registrationHandle_ == 0) {
        return;
    }
    std::string payload = "threat=" + std::to_string(static_cast<int>(result.level)) + " conf=" + std::to_string(result.confidence) + " msg=" + message;
    EventWriteString(registrationHandle_, 0, 0, std::wstring(payload.begin(), payload.end()).c_str());
}

}  // namespace hidshield
