#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <json.hpp>

#include "encrypted_pak_format.hpp"

namespace {
struct ScopedBcryptAlgorithmHandle {
    BCRYPT_ALG_HANDLE handle{};

    ~ScopedBcryptAlgorithmHandle() {
        if (handle != nullptr) {
            BCryptCloseAlgorithmProvider(handle, 0);
        }
    }
};

struct ScopedBcryptHashHandle {
    BCRYPT_HASH_HANDLE handle{};

    ~ScopedBcryptHashHandle() {
        if (handle != nullptr) {
            BCryptDestroyHash(handle);
        }
    }
};

struct ScopedBcryptKeyHandle {
    BCRYPT_KEY_HANDLE handle{};

    ~ScopedBcryptKeyHandle() {
        if (handle != nullptr) {
            BCryptDestroyKey(handle);
        }
    }
};

struct DerivedKeyMaterial {
    std::array<uint8_t, 16> game_fingerprint{};
    std::array<uint8_t, 32> encryption_key{};
    std::array<uint8_t, 32> authentication_key{};
};

struct OptionalModMetadata {
    std::wstring mod_version{};
    std::wstring update_url{};
    std::wstring author{};

    [[nodiscard]] bool empty() const {
        return mod_version.empty() && update_url.empty() && author.empty();
    }
};

std::wstring trim_ascii_copy(std::wstring_view value) {
    size_t begin = 0;
    while (begin < value.size()) {
        const auto ch = value[begin];
        if (ch != L' ' && ch != L'\t' && ch != L'\r' && ch != L'\n') {
            break;
        }
        ++begin;
    }

    size_t end = value.size();
    while (end > begin) {
        const auto ch = value[end - 1];
        if (ch != L' ' && ch != L'\t' && ch != L'\r' && ch != L'\n') {
            break;
        }
        --end;
    }

    return std::wstring{value.substr(begin, end - begin)};
}

std::optional<std::string> narrow_utf8(std::wstring_view value) {
    if (value.empty()) {
        return std::string{};
    }

    const auto size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (size <= 0) {
        return std::nullopt;
    }

    std::string utf8(static_cast<size_t>(size), '\0');
    const auto written = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        utf8.data(),
        size,
        nullptr,
        nullptr);
    if (written != size) {
        return std::nullopt;
    }

    return utf8;
}

std::optional<std::string> build_metadata_json(const OptionalModMetadata& metadata) {
    const auto mod_version = trim_ascii_copy(metadata.mod_version);
    const auto update_url = trim_ascii_copy(metadata.update_url);
    const auto author = trim_ascii_copy(metadata.author);
    if (mod_version.empty() && update_url.empty() && author.empty()) {
        return std::nullopt;
    }

    nlohmann::json json = nlohmann::json::object();
    if (!mod_version.empty()) {
        const auto utf8 = narrow_utf8(mod_version);
        if (!utf8.has_value()) {
            return std::nullopt;
        }
        json["mod_version"] = *utf8;
    }
    if (!update_url.empty()) {
        const auto utf8 = narrow_utf8(update_url);
        if (!utf8.has_value()) {
            return std::nullopt;
        }
        json["update_url"] = *utf8;
    }
    if (!author.empty()) {
        const auto utf8 = narrow_utf8(author);
        if (!utf8.has_value()) {
            return std::nullopt;
        }
        json["author"] = *utf8;
    }

    return json.dump();
}

std::optional<std::vector<uint8_t>> build_plain_metadata_block(const OptionalModMetadata& metadata) {
    const auto json = build_metadata_json(metadata);
    if (!json.has_value() || json->empty()) {
        return std::vector<uint8_t>{};
    }

    encrypted_pak::MetadataHeaderV1 header{};
    std::memcpy(header.magic, encrypted_pak::kMetadataMagic.data(), encrypted_pak::kMetadataMagic.size());
    header.version = encrypted_pak::kMetadataVersion;
    header.json_size = static_cast<uint32_t>(json->size());

    std::vector<uint8_t> block(sizeof(header) + json->size(), 0);
    std::memcpy(block.data(), &header, sizeof(header));
    std::memcpy(block.data() + sizeof(header), json->data(), json->size());
    return block;
}

std::optional<std::array<uint8_t, 16>> compute_file_md5(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }

    ScopedBcryptAlgorithmHandle algorithm{};
    ScopedBcryptHashHandle hash{};
    DWORD object_size{};
    DWORD bytes_written{};
    DWORD hash_size{};
    std::vector<uint8_t> hash_object{};
    std::array<uint8_t, 16> digest{};
    std::vector<uint8_t> buffer(encrypted_pak::kDefaultIoChunkSize, 0);

    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_MD5_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    if (BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes_written, 0) != 0 ||
        BCryptGetProperty(algorithm.handle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &bytes_written, 0) != 0 ||
        hash_size != digest.size()) {
        return std::nullopt;
    }

    hash_object.resize(object_size);
    if (BCryptCreateHash(algorithm.handle, &hash.handle, hash_object.data(), static_cast<ULONG>(hash_object.size()), nullptr, 0, 0) != 0) {
        return std::nullopt;
    }

    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto bytes_read = input.gcount();
        if (bytes_read <= 0) {
            break;
        }

        if (BCryptHashData(hash.handle, buffer.data(), static_cast<ULONG>(bytes_read), 0) != 0) {
            return std::nullopt;
        }
    }

    if (input.bad()) {
        return std::nullopt;
    }

    if (BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        return std::nullopt;
    }

    return digest;
}

std::optional<std::array<uint8_t, 32>> compute_sha256_bytes(const uint8_t* bytes, size_t size) {
    ScopedBcryptAlgorithmHandle algorithm{};
    ScopedBcryptHashHandle hash{};
    DWORD object_size{};
    DWORD bytes_written{};
    DWORD hash_size{};
    std::vector<uint8_t> hash_object{};
    std::array<uint8_t, 32> digest{};

    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    if (BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes_written, 0) != 0 ||
        BCryptGetProperty(algorithm.handle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &bytes_written, 0) != 0 ||
        hash_size != digest.size()) {
        return std::nullopt;
    }

    hash_object.resize(object_size);
    if (BCryptCreateHash(algorithm.handle, &hash.handle, hash_object.data(), static_cast<ULONG>(hash_object.size()), nullptr, 0, 0) != 0) {
        return std::nullopt;
    }

    if (bytes != nullptr && size > 0 &&
        BCryptHashData(hash.handle, const_cast<PUCHAR>(bytes), static_cast<ULONG>(size), 0) != 0) {
        return std::nullopt;
    }

    if (BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        return std::nullopt;
    }

    return digest;
}

std::optional<std::array<uint8_t, 32>> compute_hmac_sha256_bytes(
    const uint8_t* bytes,
    size_t size,
    const std::array<uint8_t, 32>& key) {
    ScopedBcryptAlgorithmHandle algorithm{};
    ScopedBcryptHashHandle hash{};
    DWORD object_size{};
    DWORD bytes_written{};
    DWORD hash_size{};
    std::vector<uint8_t> hash_object{};
    std::array<uint8_t, 32> digest{};

    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return std::nullopt;
    }

    if (BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes_written, 0) != 0 ||
        BCryptGetProperty(algorithm.handle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &bytes_written, 0) != 0 ||
        hash_size != digest.size()) {
        return std::nullopt;
    }

    hash_object.resize(object_size);
    if (BCryptCreateHash(
            algorithm.handle,
            &hash.handle,
            hash_object.data(),
            static_cast<ULONG>(hash_object.size()),
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()),
            0) != 0) {
        return std::nullopt;
    }

    if (bytes != nullptr && size > 0 &&
        BCryptHashData(hash.handle, const_cast<PUCHAR>(bytes), static_cast<ULONG>(size), 0) != 0) {
        return std::nullopt;
    }

    if (BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        return std::nullopt;
    }

    return digest;
}

std::optional<std::array<uint8_t, 32>> derive_v2_key(
    const char* label,
    uint32_t purpose,
    const std::array<uint8_t, 16>& game_fingerprint) {
    std::vector<uint8_t> seed{};
    const auto label_size = std::strlen(label);
    seed.reserve(label_size + 1 + sizeof(purpose) + game_fingerprint.size());
    seed.insert(seed.end(), label, label + label_size);
    seed.push_back(0);
    for (size_t index = 0; index < sizeof(purpose); ++index) {
        seed.push_back(static_cast<uint8_t>((purpose >> (index * 8)) & 0xFF));
    }
    seed.insert(seed.end(), game_fingerprint.begin(), game_fingerprint.end());
    return compute_sha256_bytes(seed.data(), seed.size());
}

std::optional<DerivedKeyMaterial> derive_v2_key_material(
    const std::array<uint8_t, 16>& game_fingerprint,
    uint32_t purpose) {
    const auto encryption_key = derive_v2_key("mhwsmod-v2|enc", purpose, game_fingerprint);
    const auto authentication_key = derive_v2_key("mhwsmod-v2|mac", purpose, game_fingerprint);
    if (!encryption_key.has_value() || !authentication_key.has_value()) {
        return std::nullopt;
    }

    DerivedKeyMaterial material{};
    material.game_fingerprint = game_fingerprint;
    material.encryption_key = *encryption_key;
    material.authentication_key = *authentication_key;
    return material;
}

std::optional<DerivedKeyMaterial> derive_v2_key_material(const std::filesystem::path& game_exe, uint32_t purpose) {
    const auto game_fingerprint = compute_file_md5(game_exe);
    if (!game_fingerprint.has_value()) {
        return std::nullopt;
    }

    return derive_v2_key_material(*game_fingerprint, purpose);
}

uint64_t ceil_div_u64(uint64_t value, uint64_t divisor) {
    return divisor == 0 ? 0 : ((value + divisor - 1) / divisor);
}

uint64_t align_up_u64(uint64_t value, uint64_t alignment) {
    return alignment == 0 ? value : ceil_div_u64(value, alignment) * alignment;
}

void write_header_reserved_u32(encrypted_pak::HeaderV2& header, uint32_t index, uint32_t value) {
    if ((static_cast<size_t>(index) + 1) * sizeof(uint32_t) > sizeof(header.reserved)) {
        return;
    }

    std::memcpy(header.reserved + (static_cast<size_t>(index) * sizeof(uint32_t)), &value, sizeof(value));
}

uint64_t compute_chunk_count(uint64_t plain_size, uint32_t chunk_plain_size) {
    return chunk_plain_size == 0 ? 0 : ceil_div_u64(plain_size, chunk_plain_size);
}

uint64_t compute_chunk_plain_size(uint64_t plain_size, uint32_t chunk_plain_size, uint64_t chunk_index) {
    const auto chunk_start = chunk_index * static_cast<uint64_t>(chunk_plain_size);
    if (chunk_start >= plain_size) {
        return 0;
    }

    const auto remaining = plain_size - chunk_start;
    return remaining < chunk_plain_size ? remaining : chunk_plain_size;
}

uint64_t compute_chunk_cipher_size(uint64_t chunk_plain_size) {
    if (chunk_plain_size == 0) {
        return 0;
    }

    return align_up_u64(chunk_plain_size, 16);
}

uint64_t compute_total_chunk_cipher_size(uint64_t plain_size, uint32_t chunk_plain_size) {
    const auto chunk_count = compute_chunk_count(plain_size, chunk_plain_size);
    uint64_t total = 0;
    for (uint64_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
        total += compute_chunk_cipher_size(compute_chunk_plain_size(plain_size, chunk_plain_size, chunk_index));
    }

    return total;
}

std::array<uint8_t, 16> derive_chunk_iv(const uint8_t* base_iv, uint64_t chunk_index) {
    std::array<uint8_t, 16> iv{};
    std::memcpy(iv.data(), base_iv, iv.size());

    auto carry = chunk_index;
    for (size_t offset = 0; offset < sizeof(uint64_t); ++offset) {
        const auto byte_index = iv.size() - 1 - offset;
        const auto sum = static_cast<uint32_t>(iv[byte_index]) + static_cast<uint32_t>(carry & 0xFF);
        iv[byte_index] = static_cast<uint8_t>(sum & 0xFF);
        carry = (carry >> 8) + (sum >> 8);
    }

    return iv;
}

std::optional<std::array<uint8_t, 32>> compute_chunked_container_auth_tag(
    const encrypted_pak::HeaderV2& header,
    const std::vector<uint8_t>& auth_table,
    const std::array<uint8_t, 32>& authentication_key) {
    encrypted_pak::HeaderV2 header_copy = header;
    std::memset(header_copy.auth_tag, 0, sizeof(header_copy.auth_tag));

    std::vector<uint8_t> auth_input(sizeof(header_copy) + auth_table.size(), 0);
    std::memcpy(auth_input.data(), &header_copy, sizeof(header_copy));
    if (!auth_table.empty()) {
        std::memcpy(auth_input.data() + sizeof(header_copy), auth_table.data(), auth_table.size());
    }

    return compute_hmac_sha256_bytes(auth_input.data(), auth_input.size(), authentication_key);
}

std::optional<std::vector<uint8_t>> encrypt_v2_payload_bytes(
    const std::vector<uint8_t>& plain_bytes,
    const std::array<uint8_t, 16>& game_fingerprint,
    uint32_t purpose) {
    const auto key_material = derive_v2_key_material(game_fingerprint, purpose);
    if (!key_material.has_value()) {
        return std::nullopt;
    }

    ScopedBcryptAlgorithmHandle algorithm{};
    ScopedBcryptKeyHandle key_handle{};
    DWORD object_size{};
    DWORD bytes_written{};
    std::vector<uint8_t> key_object{};
    std::vector<uint8_t> cipher_bytes(plain_bytes.size() + 32, 0);
    ULONG cipher_size{};
    encrypted_pak::HeaderV2 header{};
    std::array<uint8_t, 16> iv{};

    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    const auto chaining_mode_bytes = static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t));
    if (BCryptSetProperty(algorithm.handle, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), chaining_mode_bytes, 0) != 0 ||
        BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes_written, 0) != 0) {
        return std::nullopt;
    }

    if (BCryptGenRandom(nullptr, iv.data(), static_cast<ULONG>(iv.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return std::nullopt;
    }

    key_object.resize(object_size);
    if (BCryptGenerateSymmetricKey(
            algorithm.handle,
            &key_handle.handle,
            key_object.data(),
            static_cast<ULONG>(key_object.size()),
            const_cast<PUCHAR>(key_material->encryption_key.data()),
            static_cast<ULONG>(key_material->encryption_key.size()),
            0) != 0) {
        return std::nullopt;
    }

    auto iv_copy = iv;
    const auto encrypt_status = BCryptEncrypt(
        key_handle.handle,
        const_cast<PUCHAR>(plain_bytes.data()),
        static_cast<ULONG>(plain_bytes.size()),
        nullptr,
        iv_copy.data(),
        static_cast<ULONG>(iv_copy.size()),
        cipher_bytes.data(),
        static_cast<ULONG>(cipher_bytes.size()),
        &cipher_size,
        BCRYPT_BLOCK_PADDING);
    if (encrypt_status != 0) {
        return std::nullopt;
    }

    cipher_bytes.resize(cipher_size);
    const auto auth_tag = compute_hmac_sha256_bytes(plain_bytes.data(), plain_bytes.size(), key_material->authentication_key);
    if (!auth_tag.has_value()) {
        return std::nullopt;
    }

    std::memcpy(header.magic, encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size());
    header.version = encrypted_pak::kVersion;
    header.header_size = sizeof(header);
    header.algorithm = encrypted_pak::kAlgorithmAes256CbcHmacSha256;
    header.purpose = purpose;
    header.plain_size = plain_bytes.size();
    header.cipher_size = cipher_bytes.size();
    std::memcpy(header.game_fingerprint, key_material->game_fingerprint.data(), key_material->game_fingerprint.size());
    std::memcpy(header.iv, iv.data(), iv.size());
    std::memcpy(header.auth_tag, auth_tag->data(), auth_tag->size());

    std::vector<uint8_t> output(sizeof(header) + cipher_bytes.size(), 0);
    std::memcpy(output.data(), &header, sizeof(header));
    if (!cipher_bytes.empty()) {
        std::memcpy(output.data() + sizeof(header), cipher_bytes.data(), cipher_bytes.size());
    }

    return output;
}

bool encrypt_pak_to_v2_container(
    const std::filesystem::path& input_pak,
    const std::filesystem::path& output_path,
    const DerivedKeyMaterial& key_material,
    const OptionalModMetadata& metadata) {
    std::ifstream input(input_pak, std::ios::binary);
    if (!input) {
        return false;
    }

    if (!output_path.parent_path().empty()) {
        std::filesystem::create_directories(output_path.parent_path());
    }

    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }

    std::error_code size_ec{};
    const auto source_size_raw = std::filesystem::file_size(input_pak, size_ec);
    if (size_ec || source_size_raw == 0) {
        return false;
    }

    const auto plain_size = static_cast<uint64_t>(source_size_raw);
    const auto chunk_plain_size = encrypted_pak::kDefaultPakChunkPlainSize;
    const auto chunk_count = compute_chunk_count(plain_size, chunk_plain_size);
    const auto auth_table_size_u64 = chunk_count * static_cast<uint64_t>(encrypted_pak::kChunkAuthTagSize);

    encrypted_pak::HeaderV2 header{};
    std::vector<uint8_t> metadata_block{};
    if (const auto plain_metadata_block = build_plain_metadata_block(metadata); !plain_metadata_block.has_value()) {
        return false;
    } else if (!plain_metadata_block->empty()) {
        const auto encrypted_metadata_block = encrypt_v2_payload_bytes(
            *plain_metadata_block,
            key_material.game_fingerprint,
            encrypted_pak::kPurposeMetadata);
        if (!encrypted_metadata_block.has_value()) {
            return false;
        }

        metadata_block = std::move(*encrypted_metadata_block);
    }

    const auto header_size_u64 = static_cast<uint64_t>(sizeof(encrypted_pak::HeaderV2)) +
        static_cast<uint64_t>(metadata_block.size()) +
        auth_table_size_u64;
    if (header_size_u64 > 0xFFFFFFFFULL) {
        return false;
    }

    std::vector<uint8_t> auth_table(static_cast<size_t>(auth_table_size_u64), 0);

    std::memcpy(header.magic, encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size());
    header.version = encrypted_pak::kVersion;
    header.header_size = static_cast<uint32_t>(header_size_u64);
    header.algorithm = encrypted_pak::kAlgorithmAes256CbcChunkedHmacSha256;
    header.purpose = encrypted_pak::kPurposePak;
    header.plain_size = plain_size;
    header.cipher_size = compute_total_chunk_cipher_size(plain_size, chunk_plain_size);
    std::memcpy(header.game_fingerprint, key_material.game_fingerprint.data(), key_material.game_fingerprint.size());
    write_header_reserved_u32(header, encrypted_pak::kHeaderReservedFlagsIndex, encrypted_pak::kHeaderReservedFlagChunkedLayout);
    write_header_reserved_u32(header, encrypted_pak::kHeaderReservedMetadataSizeIndex, static_cast<uint32_t>(metadata_block.size()));
    write_header_reserved_u32(header, encrypted_pak::kHeaderReservedChunkPlainSizeIndex, chunk_plain_size);
    write_header_reserved_u32(header, encrypted_pak::kHeaderReservedChunkAuthSizeIndex, encrypted_pak::kChunkAuthTagSize);

    if (BCryptGenRandom(nullptr, header.iv, sizeof(header.iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return false;
    }

    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!output.good()) {
        return false;
    }

    if (!metadata_block.empty()) {
        output.write(reinterpret_cast<const char*>(metadata_block.data()), static_cast<std::streamsize>(metadata_block.size()));
        if (!output.good()) {
            return false;
        }
    }

    if (!auth_table.empty()) {
        output.write(reinterpret_cast<const char*>(auth_table.data()), static_cast<std::streamsize>(auth_table.size()));
        if (!output.good()) {
            return false;
        }
    }

    ScopedBcryptAlgorithmHandle aes_algorithm{};
    ScopedBcryptKeyHandle aes_key{};
    DWORD aes_object_size{};
    DWORD bytes_written{};
    std::vector<uint8_t> aes_key_object{};
    std::vector<uint8_t> read_buffer(chunk_plain_size, 0);
    std::vector<uint8_t> cipher_buffer(static_cast<size_t>(chunk_plain_size) + 16U, 0);

    if (BCryptOpenAlgorithmProvider(&aes_algorithm.handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        return false;
    }

    const auto chaining_mode_bytes = static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t));
    if (BCryptSetProperty(aes_algorithm.handle, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), chaining_mode_bytes, 0) != 0 ||
        BCryptGetProperty(aes_algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&aes_object_size), sizeof(aes_object_size), &bytes_written, 0) != 0) {
        return false;
    }

    aes_key_object.resize(aes_object_size);
    if (BCryptGenerateSymmetricKey(
            aes_algorithm.handle,
            &aes_key.handle,
            aes_key_object.data(),
            static_cast<ULONG>(aes_key_object.size()),
            const_cast<PUCHAR>(key_material.encryption_key.data()),
            static_cast<ULONG>(key_material.encryption_key.size()),
            0) != 0) {
        return false;
    }

    for (uint64_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
        const auto current_chunk_plain_size = compute_chunk_plain_size(plain_size, chunk_plain_size, chunk_index);
        if (current_chunk_plain_size == 0 || current_chunk_plain_size > read_buffer.size()) {
            return false;
        }

        input.read(reinterpret_cast<char*>(read_buffer.data()), static_cast<std::streamsize>(current_chunk_plain_size));
        if (input.gcount() != static_cast<std::streamsize>(current_chunk_plain_size)) {
            return false;
        }

        const auto chunk_auth_tag = compute_hmac_sha256_bytes(
            read_buffer.data(),
            static_cast<size_t>(current_chunk_plain_size),
            key_material.authentication_key);
        if (!chunk_auth_tag.has_value()) {
            return false;
        }

        const auto auth_table_offset = static_cast<size_t>(chunk_index * encrypted_pak::kChunkAuthTagSize);
        std::memcpy(auth_table.data() + auth_table_offset, chunk_auth_tag->data(), chunk_auth_tag->size());

        auto chunk_iv = derive_chunk_iv(header.iv, chunk_index);
        const auto use_padding = (current_chunk_plain_size % 16) != 0;
        ULONG cipher_chunk_size{};
        const auto encrypt_status = BCryptEncrypt(
            aes_key.handle,
            read_buffer.data(),
            static_cast<ULONG>(current_chunk_plain_size),
            nullptr,
            chunk_iv.data(),
            static_cast<ULONG>(chunk_iv.size()),
            cipher_buffer.data(),
            static_cast<ULONG>(cipher_buffer.size()),
            &cipher_chunk_size,
            use_padding ? BCRYPT_BLOCK_PADDING : 0);

        if (encrypt_status != 0 ||
            cipher_chunk_size != compute_chunk_cipher_size(current_chunk_plain_size)) {
            return false;
        }

        output.write(reinterpret_cast<const char*>(cipher_buffer.data()), cipher_chunk_size);
        if (!output.good()) {
            return false;
        }
    }

    if (input.peek() != std::char_traits<char>::eof()) {
        return false;
    }

    const auto container_auth_tag = compute_chunked_container_auth_tag(header, auth_table, key_material.authentication_key);
    if (!container_auth_tag.has_value()) {
        return false;
    }
    std::memcpy(header.auth_tag, container_auth_tag->data(), container_auth_tag->size());

    output.flush();
    if (!output.good()) {
        return false;
    }

    output.seekp(0, std::ios::beg);
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!output.good()) {
        return false;
    }

    if (!auth_table.empty()) {
        output.seekp(static_cast<std::streamoff>(sizeof(header) + metadata_block.size()), std::ios::beg);
        output.write(reinterpret_cast<const char*>(auth_table.data()), static_cast<std::streamsize>(auth_table.size()));
    }
    output.flush();
    return output.good();
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 4) {
        std::wcerr << L"Usage: mhwilds_pak_packer <game_exe_path> <input_pak_path> <output_mhwsmod_path> [--mod-version <value>] [--update-url <value>] [--author <value>]\n";
        return 1;
    }

    const std::filesystem::path game_exe = argv[1];
    const std::filesystem::path input_pak = argv[2];
    const std::filesystem::path output_path = argv[3];
    OptionalModMetadata metadata{};

    for (int index = 4; index < argc; ++index) {
        const std::wstring_view arg = argv[index];
        auto require_value = [&](std::wstring_view option_name) -> wchar_t* {
            if (index + 1 >= argc) {
                std::wcerr << L"Missing value for option: " << option_name << L"\n";
                return nullptr;
            }
            ++index;
            return argv[index];
        };

        if (arg == L"--mod-version") {
            if (const auto value = require_value(arg); value == nullptr) {
                return 1;
            } else {
                metadata.mod_version = value;
            }
        } else if (arg == L"--update-url") {
            if (const auto value = require_value(arg); value == nullptr) {
                return 1;
            } else {
                metadata.update_url = value;
            }
        } else if (arg == L"--author") {
            if (const auto value = require_value(arg); value == nullptr) {
                return 1;
            } else {
                metadata.author = value;
            }
        } else {
            std::wcerr << L"Unknown option: " << arg << L"\n";
            return 1;
        }
    }

    const auto key_material = derive_v2_key_material(game_exe, encrypted_pak::kPurposePak);
    if (!key_material.has_value()) {
        std::wcerr << L"Failed to derive v2 key material from game exe: " << game_exe << L"\n";
        return 2;
    }

    if (!encrypt_pak_to_v2_container(input_pak, output_path, *key_material, metadata)) {
        std::wcerr << L"Failed to pack encrypted mod: " << input_pak << L"\n";
        return 3;
    }

    std::wcout << L"Encrypted pak written to: " << output_path << L"\n";
    std::wcout << L"Format: v2 chunked AES-256-CBC + per-chunk HMAC-SHA256\n";
    if (!metadata.empty()) {
        std::wcout << L"Metadata embedded: yes\n";
    }
    return 0;
}
