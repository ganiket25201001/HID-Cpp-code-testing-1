#pragma once

#include <Windows.h>
#include <evntprov.h>

#include <string>

#include "common/types.h"

namespace hidshield {

class EtwProvider final {
public:
    EtwProvider();
    ~EtwProvider();

    bool Register();
    void Unregister();
    void EmitDeviceEvent(const DeviceDescriptorSnapshot& device, const std::string& message) const;
    void EmitThreatEvent(const ClassificationResult& result, const std::string& message) const;

private:
    REGHANDLE registrationHandle_{0};
};

}  // namespace hidshield
