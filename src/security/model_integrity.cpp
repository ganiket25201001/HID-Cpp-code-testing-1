#include "security/model_integrity.h"

#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace hidshield {

bool ModelIntegrityVerifier::VerifyModelFile(const std::string& modelPath,
                                             const std::string& expectedSha256Hex,
                                             const std::string& signaturePath) const {
    if (signaturePath.empty()) {
        return false;
    }

    const auto actual = HashFileSha256Hex(modelPath);
    return !actual.empty() && actual == expectedSha256Hex;
}

std::string ModelIntegrityVerifier::HashFileSha256Hex(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return {};
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD dataLength = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return {};
    }
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &dataLength, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    std::vector<UCHAR> hashObject(objectLength);
    if (BCryptCreateHash(alg, &hash, hashObject.data(), objectLength, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    std::array<char, 4096> buffer{};
    while (file.good()) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto bytesRead = static_cast<ULONG>(file.gcount());
        if (bytesRead == 0) {
            break;
        }
        if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), bytesRead, 0) != 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
    }

    std::vector<UCHAR> digest(32);
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    std::ostringstream oss;
    for (const auto byte : digest) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

}  // namespace hidshield
