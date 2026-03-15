#include "platform/usb_device_detector.h"

#include <Windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>

#include <array>
#include <stdexcept>
#include <string>

#pragma comment(lib, "setupapi.lib")

namespace hidshield {
namespace {

std::string WideToUtf8(const std::wstring& input) {
    if (input.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring ExtractPropertyString(HDEVINFO infoSet, SP_DEVINFO_DATA& infoData, DWORD property) {
    std::array<wchar_t, 512> buffer{};
    DWORD requiredSize = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(infoSet,
                                           &infoData,
                                           property,
                                           nullptr,
                                           reinterpret_cast<PBYTE>(buffer.data()),
                                           static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                                           &requiredSize)) {
        return L"";
    }
    return std::wstring(buffer.data());
}

}  // namespace

std::vector<DeviceDescriptorSnapshot> UsbDeviceDetector::EnumerateHidDevices() const {
    std::vector<DeviceDescriptorSnapshot> devices;

    HDEVINFO infoSet = SetupDiGetClassDevsW(
        nullptr,
        L"USB",
        nullptr,
        DIGCF_PRESENT | DIGCF_ALLCLASSES);

    if (infoSet == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("SetupDiGetClassDevsW failed");
    }

    SP_DEVINFO_DATA infoData{};
    infoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD index = 0; SetupDiEnumDeviceInfo(infoSet, index, &infoData); ++index) {
        const auto className = WideToUtf8(ExtractPropertyString(infoSet, infoData, SPDRP_CLASS));
        if (!IsHidClassGuid(className)) {
            continue;
        }

        DeviceDescriptorSnapshot snapshot{};
        snapshot.rawPath = WideToUtf8(ExtractPropertyString(infoSet, infoData, SPDRP_HARDWAREID));
        snapshot.manufacturer = WideToUtf8(ExtractPropertyString(infoSet, infoData, SPDRP_MFG));
        snapshot.product = WideToUtf8(ExtractPropertyString(infoSet, infoData, SPDRP_FRIENDLYNAME));
        snapshot.instanceId = WideToUtf8(ExtractPropertyString(infoSet, infoData, SPDRP_LOCATION_INFORMATION));

        const auto posVid = snapshot.rawPath.find("VID_");
        const auto posPid = snapshot.rawPath.find("PID_");
        if (posVid != std::string::npos && snapshot.rawPath.size() >= posVid + 8U) {
            snapshot.vid = snapshot.rawPath.substr(posVid + 4U, 4U);
        }
        if (posPid != std::string::npos && snapshot.rawPath.size() >= posPid + 8U) {
            snapshot.pid = snapshot.rawPath.substr(posPid + 4U, 4U);
        }
        devices.push_back(std::move(snapshot));
    }

    SetupDiDestroyDeviceInfoList(infoSet);
    return devices;
}

bool UsbDeviceDetector::IsHidClassGuid(const std::string& className) {
    return className == "HIDClass" || className == "Keyboard" || className == "Mouse";
}

DeviceDescriptorSnapshot UsbDeviceDetector::BuildSnapshotFromPath(const std::string& devicePath) {
    DeviceDescriptorSnapshot snapshot{};
    snapshot.rawPath = devicePath;
    return snapshot;
}

}  // namespace hidshield
