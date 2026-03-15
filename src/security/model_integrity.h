#pragma once

#include <string>

namespace hidshield {

class ModelIntegrityVerifier final {
public:
    [[nodiscard]] bool VerifyModelFile(const std::string& modelPath,
                                       const std::string& expectedSha256Hex,
                                       const std::string& signaturePath) const;

private:
    [[nodiscard]] static std::string HashFileSha256Hex(const std::string& filePath);
};

}  // namespace hidshield
