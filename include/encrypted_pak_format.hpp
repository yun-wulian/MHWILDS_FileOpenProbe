#pragma once

#include <array>
#include <cstdint>

namespace encrypted_pak {
constexpr uintptr_t kVirtualFileHandleBase = 0x5A11000000000000ULL;
constexpr uintptr_t kVirtualMappingHandleBase = 0x5A12000000000000ULL;
constexpr uint32_t kLegacyVersion = 1;
constexpr uint32_t kVersion = 2;
constexpr uint32_t kLegacyAlgorithmAes256Cbc = 1;
constexpr uint32_t kLegacyAlgorithmXor32 = 2;
constexpr uint32_t kAlgorithmAes256CbcHmacSha256 = 3;
constexpr uint32_t kAlgorithmAes256CbcChunkedHmacSha256 = 4;
constexpr uint32_t kAlgorithmAes256Cbc = kLegacyAlgorithmAes256Cbc;
constexpr uint32_t kAlgorithmXor32 = kLegacyAlgorithmXor32;
constexpr uint32_t kPurposePak = 1;
constexpr uint32_t kPurposeIndex = 2;
constexpr uint32_t kPurposeMetadata = 3;
constexpr uint32_t kDefaultIoChunkSize = 8U * 1024U * 1024U;
constexpr uint32_t kDefaultPakChunkPlainSize = 64U * 1024U;
constexpr uint32_t kChunkAuthTagSize = 32U;
constexpr uint32_t kHeaderReservedFlagsIndex = 0;
constexpr uint32_t kHeaderReservedMetadataSizeIndex = 1;
constexpr uint32_t kHeaderReservedChunkPlainSizeIndex = 2;
constexpr uint32_t kHeaderReservedChunkAuthSizeIndex = 3;
constexpr uint32_t kHeaderReservedFlagChunkedLayout = 0x00000001U;
constexpr std::array<char, 8> kLegacyMagic{'M', 'H', 'W', 'S', 'E', 'P', '1', '\0'};
constexpr std::array<char, 8> kMagic{'M', 'H', 'W', 'S', 'E', 'P', '2', '\0'};
constexpr uint32_t kMetadataVersion = 1;
constexpr std::array<char, 8> kMetadataMagic{'M', 'H', 'W', 'S', 'M', 'D', '1', '\0'};

#pragma pack(push, 1)
struct LegacyHeader {
    char magic[8];
    uint32_t version;
    uint32_t algorithm;
    uint64_t plain_size;
    uint64_t cipher_size;
    uint8_t iv[16];
    uint8_t reserved[16];
};

struct HeaderV2 {
    char magic[8];
    uint32_t version;
    uint32_t header_size;
    uint32_t algorithm;
    uint32_t purpose;
    uint64_t plain_size;
    uint64_t cipher_size;
    uint8_t game_fingerprint[16];
    uint8_t iv[16];
    uint8_t auth_tag[32];
    uint8_t reserved[16];
};

struct MetadataHeaderV1 {
    char magic[8];
    uint32_t version;
    uint32_t json_size;
    uint8_t reserved[16];
};
#pragma pack(pop)

using Header = LegacyHeader;

static_assert(sizeof(LegacyHeader) == 64);
static_assert(sizeof(HeaderV2) == 120);
static_assert(sizeof(MetadataHeaderV1) == 32);
} // namespace encrypted_pak
