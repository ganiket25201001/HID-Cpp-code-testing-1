#include "security/device_fingerprint_engine.h"

#include <Windows.h>
#include <bcrypt.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace hidshield {

DeviceFingerprint DeviceFingerprintEngine::ComputeFingerprint(const DeviceDescriptorSnapshot& snapshot) const {
    DeviceFingerprint out{};
    out.canonicalSha256 = Sha256Hex(snapshot.descriptorBytes);
    out.fuzzyIdentity = BuildFuzzyIdentity(snapshot);
    out.timingSkewScore = 0.0;
    out.reputationScore = 0;
    return out;
}

std::string DeviceFingerprintEngine::Sha256Hex(const std::vector<std::uint8_t>& bytes) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD dataLength = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &dataLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptGetProperty failed");
    }

    std::vector<UCHAR> hashObject(objectLength);
    if (BCryptCreateHash(alg, &hash, hashObject.data(), objectLength, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptCreateHash failed");
    }

    if (!bytes.empty() && BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptHashData failed");
    }

    std::vector<UCHAR> digest(32);
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptFinishHash failed");
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    std::ostringstream oss;
    for (const auto byte : digest) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::string DeviceFingerprintEngine::BuildFuzzyIdentity(const DeviceDescriptorSnapshot& snapshot) {
    return snapshot.vid + ":" + snapshot.pid + ":" + snapshot.manufacturer + ":" + snapshot.product;
}

}  // namespace hidshield
