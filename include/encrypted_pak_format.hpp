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
constexpr uint32_t kAesBlockSize = 16;
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

struct PakChunkedHeaderV1 {
    uint8_t iv[16];
    uint8_t auth_tag[32];
    uint32_t plain_size;
    uint32_t cipher_size;
    uint8_t reserved[8];
};

struct PakChunkedConfigV1 {
    uint32_t chunk_plain_size;
    uint32_t chunk_header_size;
    uint32_t flags;
    uint32_t reserved;
};

struct MetadataHeaderV1 {
    char magic[8];
    uint32_t version;
    uint32_t json_size;
    uint8_t reserved[16];
};
#pragma pack(pop)

using Header = LegacyHeader;

constexpr uint64_t align_up_u64(uint64_t value, uint64_t alignment) {
    return alignment == 0 ? value : ((value + alignment - 1) / alignment) * alignment;
}

constexpr uint64_t padded_cipher_size_for_plain_size(uint64_t plain_size) {
    if (plain_size == 0) {
        return 0;
    }

    return align_up_u64(plain_size + 1, kAesBlockSize);
}

constexpr uint64_t chunk_count_for_plain_size(uint64_t plain_size, uint32_t chunk_plain_size) {
    return (plain_size == 0 || chunk_plain_size == 0)
        ? 0
        : ((plain_size + static_cast<uint64_t>(chunk_plain_size) - 1) / static_cast<uint64_t>(chunk_plain_size));
}

constexpr uint32_t plain_size_for_chunk_index(uint64_t plain_size, uint32_t chunk_plain_size, uint64_t chunk_index) {
    if (plain_size == 0 || chunk_plain_size == 0) {
        return 0;
    }

    const auto chunk_offset = static_cast<uint64_t>(chunk_plain_size) * chunk_index;
    if (chunk_offset >= plain_size) {
        return 0;
    }

    const auto remaining = plain_size - chunk_offset;
    return static_cast<uint32_t>(remaining < chunk_plain_size ? remaining : chunk_plain_size);
}

constexpr uint64_t full_chunk_cipher_size(uint32_t chunk_plain_size) {
    return padded_cipher_size_for_plain_size(chunk_plain_size);
}

constexpr uint64_t full_chunk_record_size(uint32_t chunk_plain_size) {
    return sizeof(PakChunkedHeaderV1) + full_chunk_cipher_size(chunk_plain_size);
}

constexpr uint64_t chunk_record_offset_from_payload_base(
    uint64_t plain_size,
    uint32_t chunk_plain_size,
    uint64_t chunk_index) {
    if (chunk_plain_size == 0) {
        return 0;
    }

    const auto full_record = full_chunk_record_size(chunk_plain_size);
    const auto chunk_count = chunk_count_for_plain_size(plain_size, chunk_plain_size);
    if (chunk_count == 0 || chunk_index >= chunk_count) {
        return 0;
    }

    return full_record * chunk_index;
}

constexpr uint64_t total_chunked_payload_size(uint64_t plain_size, uint32_t chunk_plain_size) {
    const auto chunk_count = chunk_count_for_plain_size(plain_size, chunk_plain_size);
    if (chunk_count == 0 || chunk_plain_size == 0) {
        return 0;
    }

    const auto full_record = full_chunk_record_size(chunk_plain_size);
    const auto full_chunk_count = chunk_count > 0 ? (chunk_count - 1) : 0;
    const auto last_plain_size = plain_size_for_chunk_index(plain_size, chunk_plain_size, chunk_count - 1);
    return full_record * full_chunk_count
        + sizeof(PakChunkedHeaderV1)
        + padded_cipher_size_for_plain_size(last_plain_size);
}

static_assert(sizeof(LegacyHeader) == 64);
static_assert(sizeof(HeaderV2) == 120);
static_assert(sizeof(PakChunkedHeaderV1) == 64);
static_assert(sizeof(PakChunkedConfigV1) == 16);
static_assert(sizeof(MetadataHeaderV1) == 32);
} // namespace encrypted_pak
