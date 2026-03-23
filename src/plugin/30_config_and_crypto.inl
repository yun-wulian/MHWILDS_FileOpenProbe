void ensure_stage_startup_cleanup(const VirtualPakLoaderConfig& config);
void persist_stage_session_index(const VirtualPakLoaderConfig& config, const std::filesystem::path& session_dir);
std::optional<std::vector<uint8_t>> decode_v2_encrypted_pak_bytes(const std::vector<uint8_t>& file_bytes, uint32_t expected_purpose);

bool normalized_path_matches_target(const std::wstring& normalized_path, const std::wstring& normalized_target) {
    if (normalized_target.empty()) {
        return false;
    }

    return normalized_path == normalized_target;
}

std::vector<std::wstring> scan_files_in_directory_by_extensions(
    const std::filesystem::path& directory,
    const std::vector<std::wstring>& accepted_extensions) {
    std::vector<std::wstring> file_paths{};
    std::error_code ec{};

    ScopedInternalBackendOpen internal_open_guard{};
    if (directory.empty() || !std::filesystem::exists(directory, ec) || ec) {
        return file_paths;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        if (!entry.is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        auto extension = entry.path().extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(ch));
        });

        if (std::find(accepted_extensions.begin(), accepted_extensions.end(), extension) != accepted_extensions.end()) {
            file_paths.emplace_back(entry.path().wstring());
        }
    }

    std::sort(file_paths.begin(), file_paths.end(), [](const std::wstring& a, const std::wstring& b) {
        auto left = normalize_path_for_match(a);
        auto right = normalize_path_for_match(b);
        return left < right;
    });

    return file_paths;
}

std::vector<std::wstring> scan_pak_files_in_directory(const std::filesystem::path& directory) {
    return scan_files_in_directory_by_extensions(directory, {L".pak"});
}

std::vector<std::wstring> scan_mhwsmod_files_in_directory(const std::filesystem::path& directory) {
    return scan_files_in_directory_by_extensions(directory, {to_lower_copy(kEncryptedModExtension)});
}

std::filesystem::path default_reframework_custom_pak_dir() {
    return std::filesystem::current_path() / L"pak_mods";
}

std::filesystem::path reframework_runtime_config_path() {
    return std::filesystem::current_path() / L"re2_fw_config.txt";
}

std::filesystem::path default_custom_test_pak_dir() {
    return std::filesystem::current_path() / L"test_pak";
}

bool load_reframework_pak_directory_enabled_from_disk() {
    const auto config_path = reframework_runtime_config_path();
    if (!std::filesystem::exists(config_path)) {
        return false;
    }

    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(config_path, std::ios::binary);
    if (!input) {
        return false;
    }

    std::string line{};
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const auto trimmed = trim_ascii_copy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        const auto delimiter = trimmed.find('=');
        if (delimiter == std::string::npos) {
            continue;
        }

        const auto key = trim_ascii_copy(trimmed.substr(0, delimiter));
        if (_stricmp(key.c_str(), "IntegrityCheckBypass_LoadPakDirectory") != 0) {
            continue;
        }

        const auto value = trim_ascii_copy(trimmed.substr(delimiter + 1));
        return parse_bool_value(value);
    }

    return false;
}

std::vector<std::wstring> resolve_reframework_custom_pak_paths(bool enabled) {
    if (!enabled) {
        return {};
    }

    return scan_pak_files_in_directory(default_reframework_custom_pak_dir());
}

std::vector<std::wstring> resolve_encrypted_custom_mod_paths() {
    return scan_mhwsmod_files_in_directory(default_reframework_custom_pak_dir());
}

std::vector<std::wstring> resolve_local_custom_pak_paths(const VirtualPakLoaderConfig& config) {
    auto filter_paths = [](std::vector<std::wstring> paths) {
        std::erase_if(paths, [](const std::wstring& path) {
            return normalize_path_for_match(path).find(L"\\mhwsmod_cache\\") != std::wstring::npos;
        });
        return paths;
    };

    if (!config.source_path.empty()) {
        const std::filesystem::path source_path{config.source_path};
        std::error_code ec{};
        if (std::filesystem::is_directory(source_path, ec) && !ec) {
            return filter_paths(scan_pak_files_in_directory(source_path));
        }

        if (!ec && std::filesystem::is_regular_file(source_path, ec) && !ec) {
            auto extension = source_path.extension().wstring();
            std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });

            if (extension == L".pak") {
                return {source_path.wstring()};
            }
        }
    }

    if (!config.custom_pak_dir.empty()) {
        return filter_paths(scan_pak_files_in_directory(std::filesystem::path{config.custom_pak_dir}));
    }

    return filter_paths(scan_pak_files_in_directory(default_custom_test_pak_dir()));
}

int count_effective_virtual_source_paths(const VirtualPakLoaderConfig& config) {
    if (config.rf_chain_mode) {
        return config.reframework_source_count + config.custom_source_count + config.encrypted_mod_staged_count;
    }

    return config.custom_source_count + config.encrypted_mod_staged_count;
}

std::vector<std::wstring> resolve_effective_rf_chain_pak_paths(const VirtualPakLoaderConfig& config) {
    std::vector<std::wstring> paths{};

    if (config.rf_chain_mode) {
        const auto reframework_paths = resolve_reframework_custom_pak_paths(config.reframework_pak_dir_enabled);
        paths.insert(paths.end(), reframework_paths.begin(), reframework_paths.end());
    }

    const auto local_paths = resolve_local_custom_pak_paths(config);
    paths.insert(paths.end(), local_paths.begin(), local_paths.end());
    {
        std::scoped_lock _{g_encrypted_mod_stage_mutex};
        paths.insert(paths.end(), g_encrypted_mod_stage_cache.staged_paths.begin(), g_encrypted_mod_stage_cache.staged_paths.end());
    }
    return paths;
}

VirtualPakLoaderConfig load_virtual_loader_config_from_disk() {
    VirtualPakLoaderConfig config{};
    const auto config_file = loader_config_path();

    if (!std::filesystem::exists(config_file)) {
        return config;
    }

    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(config_file, std::ios::binary);
    if (!input) {
        return config;
    }

    std::string line{};
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const auto trimmed = trim_ascii_copy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        const auto delimiter = trimmed.find('=');
        if (delimiter == std::string::npos) {
            continue;
        }

        const auto key = trim_ascii_copy(trimmed.substr(0, delimiter));
        const auto value = trim_ascii_copy(trimmed.substr(delimiter + 1));
        const auto wide_value = widen_utf8(value);
        if (!wide_value.has_value()) {
            continue;
        }

        if (_stricmp(key.c_str(), "enabled") == 0) {
            config.enabled = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "observer_only") == 0) {
            config.observer_only = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "backend_only") == 0) {
            config.backend_only = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "record_only") == 0) {
            config.record_only = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "plain_source") == 0) {
            config.plain_source = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "stage_source") == 0) {
            config.stage_source = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "keep_staged_file") == 0) {
            config.keep_staged_file = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "trace_enabled") == 0) {
            config.trace_enabled = parse_bool_value(value);
        } else if (_stricmp(key.c_str(), "trace_start_rva") == 0) {
            if (const auto parsed = parse_u64_value(value); parsed.has_value()) {
                config.trace_start_rva = static_cast<uintptr_t>(*parsed);
            }
        } else if (_stricmp(key.c_str(), "trace_max_instructions") == 0) {
            if (const auto parsed = parse_u64_value(value); parsed.has_value()) {
                config.trace_max_instructions = static_cast<uint32_t>(std::max<uint64_t>(1, *parsed));
            }
        } else if (_stricmp(key.c_str(), "mode") == 0) {
            config.observer_only = _stricmp(value.c_str(), "observer") == 0 || _stricmp(value.c_str(), "observe") == 0 || _stricmp(value.c_str(), "logonly") == 0;
            config.backend_only = _stricmp(value.c_str(), "backend") == 0 || _stricmp(value.c_str(), "backend_only") == 0 || _stricmp(value.c_str(), "minimal") == 0;
            config.record_only = _stricmp(value.c_str(), "record") == 0 || _stricmp(value.c_str(), "record_only") == 0 || _stricmp(value.c_str(), "trace") == 0 || _stricmp(value.c_str(), "monitor") == 0;
            config.rf_chain_mode = _stricmp(value.c_str(), "rf_chain") == 0 || _stricmp(value.c_str(), "reframework_chain") == 0 || _stricmp(value.c_str(), "extend") == 0;
            config.plain_source = _stricmp(value.c_str(), "backend_plaintext") == 0 || _stricmp(value.c_str(), "backend_raw") == 0;
            config.passthrough = _stricmp(value.c_str(), "passthrough") == 0 || _stricmp(value.c_str(), "real") == 0;
            config.stage_source =
                _stricmp(value.c_str(), "stage") == 0 ||
                _stricmp(value.c_str(), "staged") == 0 ||
                _stricmp(value.c_str(), "stage_encrypted") == 0 ||
                _stricmp(value.c_str(), "staged_encrypted") == 0 ||
                _stricmp(value.c_str(), "stage_plain") == 0 ||
                _stricmp(value.c_str(), "staged_plain") == 0 ||
                _stricmp(value.c_str(), "stage_plaintext") == 0 ||
                _stricmp(value.c_str(), "staged_plaintext") == 0;
            if (_stricmp(value.c_str(), "stage_plain") == 0 ||
                _stricmp(value.c_str(), "staged_plain") == 0 ||
                _stricmp(value.c_str(), "stage_plaintext") == 0 ||
                _stricmp(value.c_str(), "staged_plaintext") == 0) {
                config.plain_source = true;
            }
            config.redirect = false;
        } else if (_stricmp(key.c_str(), "target_path") == 0) {
            config.target_path = *wide_value;
        } else if (_stricmp(key.c_str(), "source_path") == 0) {
            config.source_path = *wide_value;
        } else if (_stricmp(key.c_str(), "custom_pak_dir") == 0) {
            config.custom_pak_dir = *wide_value;
        } else if (_stricmp(key.c_str(), "stage_root") == 0) {
            config.stage_root = *wide_value;
        }
    }

    if (config.stage_source) {
        config.passthrough = true;
    }

    ensure_stage_startup_cleanup(config);
    config.target_path_normalized = normalize_path_for_match(config.target_path);
    config.base_patch_num = scan_highest_native_patch_num();
    config.reframework_pak_dir_enabled = load_reframework_pak_directory_enabled_from_disk();
    const auto reframework_custom_paths = resolve_reframework_custom_pak_paths(config.reframework_pak_dir_enabled);
    const auto encrypted_custom_paths = resolve_encrypted_custom_mod_paths();
    const auto staged_encrypted_paths = stage_encrypted_custom_mods_into_local_dir(config);
    const auto local_custom_paths = resolve_local_custom_pak_paths(config);
    config.reframework_source_count = static_cast<int>(reframework_custom_paths.size());
    config.custom_source_count = static_cast<int>(local_custom_paths.size());
    config.encrypted_mod_source_count = static_cast<int>(encrypted_custom_paths.size());
    config.encrypted_mod_staged_count = static_cast<int>(staged_encrypted_paths.size());
    const auto effective_source_count = count_effective_virtual_source_paths(config);
    if (const auto patch_num = extract_patch_num_from_target_path(config.target_path); patch_num.has_value()) {
        config.target_patch_num = *patch_num;
    }

    if (config.base_patch_num >= 0 && effective_source_count > 0) {
        config.total_patch_num = config.base_patch_num + effective_source_count;
    }

    if (config.target_patch_num >= 0) {
        config.total_patch_num = std::max(config.total_patch_num, config.target_patch_num);
    } else if (config.total_patch_num >= 0) {
        config.target_patch_num = config.total_patch_num;
    }

    const auto exact_target_mode = !config.target_path_normalized.empty();
    if (config.record_only) {
        if (!exact_target_mode) {
            config.enabled = false;
        }
    } else if ((effective_source_count <= 0 && !exact_target_mode) || (!exact_target_mode && config.total_patch_num < 0)) {
        config.enabled = false;
    }

    return config;
}

void reload_virtual_loader_config() {
    const auto config = load_virtual_loader_config_from_disk();

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        g_virtual_loader_config = config;
        g_virtual_payload_cache = {};
        g_virtual_stage_cache = {};
        g_cached_game_key.reset();
        g_cached_game_key_source.clear();
        g_cached_game_fingerprint.reset();
        g_cached_game_fingerprint_source.clear();
    }

    std::ostringstream oss;
    oss << "virtual-loader-config"
        << " enabled=" << static_cast<int>(config.enabled)
        << " observer_only=" << static_cast<int>(config.observer_only)
        << " backend_only=" << static_cast<int>(config.backend_only)
        << " record_only=" << static_cast<int>(config.record_only)
        << " rf_chain_mode=" << static_cast<int>(config.rf_chain_mode)
        << " plain_source=" << static_cast<int>(config.plain_source)
        << " stage_source=" << static_cast<int>(config.stage_source)
        << " keep_staged_file=" << static_cast<int>(config.keep_staged_file)
        << " mode=" << virtual_loader_mode_to_string(config)
        << " route=" << (config.target_path_normalized.empty() ? "auto_patch_slots" : "exact_target")
        << " target=" << narrow_utf8(config.target_path)
        << " source=" << narrow_utf8(config.source_path)
        << " custom_pak_dir=" << narrow_utf8(config.custom_pak_dir)
        << " reframework_pak_dir_enabled=" << static_cast<int>(config.reframework_pak_dir_enabled)
        << " stage_root=" << narrow_utf8(config.stage_root)
        << " base_patch=" << config.base_patch_num
        << " reframework_count=" << config.reframework_source_count
        << " custom_count=" << config.custom_source_count
        << " encrypted_count=" << config.encrypted_mod_source_count
        << " encrypted_staged=" << config.encrypted_mod_staged_count
        << " target_patch=" << config.target_patch_num
        << " total_patch=" << config.total_patch_num
        << " trace_enabled=" << static_cast<int>(config.trace_enabled)
        << " trace_start_rva=0x" << std::hex << config.trace_start_rva
        << std::dec
        << " trace_max_instructions=" << config.trace_max_instructions
        << "\n";
    append_log_line(oss.str());
}

std::optional<std::vector<uint8_t>> read_binary_file(const std::filesystem::path& path) {
    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        return std::nullopt;
    }

    const auto end = input.tellg();
    if (end < 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(end), 0);
    input.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
            return std::nullopt;
        }
    }

    return bytes;
}

bool write_binary_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    ScopedInternalBackendOpen internal_open_guard{};
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }

    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!output.good()) {
            return false;
        }
    }

    output.flush();
    return output.good();
}

std::wstring sanitize_stage_file_name(std::wstring name) {
    for (auto& ch : name) {
        if ((ch >= L'0' && ch <= L'9') ||
            (ch >= L'a' && ch <= L'z') ||
            (ch >= L'A' && ch <= L'Z') ||
            ch == L'.' ||
            ch == L'_' ||
            ch == L'-') {
            continue;
        }

        ch = L'_';
    }

    return name;
}

std::wstring generate_random_hex_string(size_t byte_count) {
    std::vector<uint8_t> bytes(byte_count, 0);
    if (!bytes.empty() &&
        BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        const auto tick = static_cast<uint64_t>(GetTickCount64());
        const auto pid = static_cast<uint64_t>(GetCurrentProcessId());
        std::wostringstream fallback;
        fallback << std::hex << tick << pid;
        return fallback.str();
    }

    static constexpr wchar_t kHexDigits[] = L"0123456789abcdef";
    std::wstring text{};
    text.reserve(byte_count * 2);
    for (const auto byte : bytes) {
        text.push_back(kHexDigits[(byte >> 4) & 0x0F]);
        text.push_back(kHexDigits[byte & 0x0F]);
    }

    return text;
}

std::filesystem::path default_stage_root() {
    std::error_code ec{};
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec) {
        root = std::filesystem::current_path(ec);
        ec.clear();
    }

    return root;
}

std::filesystem::path resolve_stage_root(const VirtualPakLoaderConfig& config) {
    if (!config.stage_root.empty()) {
        return std::filesystem::path{config.stage_root};
    }

    return default_stage_root();
}

void ensure_stage_startup_cleanup(const VirtualPakLoaderConfig& config);
void persist_stage_session_index(const VirtualPakLoaderConfig& config, const std::filesystem::path& session_dir);

std::filesystem::path build_stage_session_dir(const VirtualPakLoaderConfig& config) {
    std::scoped_lock _{g_stage_session_mutex};
    if (!g_shared_stage_session_dir.empty()) {
        return std::filesystem::path{g_shared_stage_session_dir};
    }

    const auto session_dir = resolve_stage_root(config) / generate_random_hex_string(12) / generate_random_hex_string(12);
    g_shared_stage_session_dir = session_dir.wstring();
    persist_stage_session_index(config, session_dir);
    return session_dir;
}

std::filesystem::path build_random_stage_pak_path(const std::filesystem::path& session_dir) {
    return session_dir / (generate_random_hex_string(12) + kStagedRuntimePakExtension);
}

std::filesystem::path build_stage_output_path(const VirtualPakLoaderConfig& config) {
    return build_random_stage_pak_path(build_stage_session_dir(config));
}

void apply_hidden_system_attributes(const std::filesystem::path& path) {
    const auto attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    SetFileAttributesW(path.c_str(), attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

std::string hex_encode_bytes(const uint8_t* bytes, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        if (i != 0) {
            oss << ' ';
        }

        oss << std::hex << static_cast<unsigned>(bytes[i] >> 4);
        oss << std::hex << static_cast<unsigned>(bytes[i] & 0x0F);
    }

    return oss.str();
}

std::optional<std::array<uint8_t, 16>> compute_file_md5(const std::filesystem::path& path) {
    const auto file_bytes = read_binary_file(path);
    if (!file_bytes.has_value()) {
        return std::nullopt;
    }

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    DWORD object_size{};
    DWORD bytes_written{};
    DWORD hash_size{};
    std::vector<uint8_t> hash_object{};
    std::array<uint8_t, 16> digest{};

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes_written, 0) != 0 ||
        BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &bytes_written, 0) != 0 ||
        hash_size != digest.size()) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }

    hash_object.resize(object_size);
    if (BCryptCreateHash(algorithm, &hash, hash_object.data(), static_cast<ULONG>(hash_object.size()), nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }

    if (!file_bytes->empty() &&
        BCryptHashData(hash, const_cast<PUCHAR>(file_bytes->data()), static_cast<ULONG>(file_bytes->size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }

    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return digest;
}

std::optional<std::array<uint8_t, 32>> derive_game_key_once() {
    const auto exe_path = widen_module_path(GetModuleHandleW(nullptr));

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        if (g_cached_game_key.has_value() && g_cached_game_key_source == exe_path) {
            return g_cached_game_key;
        }
    }

    const auto digest = compute_file_md5(exe_path);
    if (!digest.has_value()) {
        append_log_line("virtual-loader-key-md5-failed\n");
        return std::nullopt;
    }

    std::array<uint8_t, 32> key{};
    std::memcpy(key.data(), digest->data(), digest->size());
    std::memcpy(key.data() + digest->size(), digest->data(), digest->size());

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        g_cached_game_key = key;
        g_cached_game_key_source = exe_path;
    }

    std::ostringstream oss;
    oss << "virtual-loader-key-ready exe=" << narrow_utf8(exe_path)
        << " md5=" << hex_encode_bytes(digest->data(), digest->size())
        << "\n";
    append_log_line(oss.str());

    return key;
}

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

std::optional<std::array<uint8_t, 16>> derive_game_fingerprint_once() {
    const auto exe_path = widen_module_path(GetModuleHandleW(nullptr));

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        if (g_cached_game_fingerprint.has_value() && g_cached_game_fingerprint_source == exe_path) {
            return g_cached_game_fingerprint;
        }
    }

    const auto digest = compute_file_md5(exe_path);
    if (!digest.has_value()) {
        append_log_line("virtual-loader-fingerprint-md5-failed\n");
        return std::nullopt;
    }

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        g_cached_game_fingerprint = digest;
        g_cached_game_fingerprint_source = exe_path;
    }

    std::ostringstream oss;
    oss << "virtual-loader-game-fingerprint-ready exe=" << narrow_utf8(exe_path)
        << " md5=" << hex_encode_bytes(digest->data(), digest->size())
        << "\n";
    append_log_line(oss.str());

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

std::optional<DerivedKeyMaterial> derive_v2_key_material(uint32_t purpose) {
    const auto game_fingerprint = derive_game_fingerprint_once();
    if (!game_fingerprint.has_value()) {
        return std::nullopt;
    }

    const auto encryption_key = derive_v2_key("mhwsmod-v2|enc", purpose, *game_fingerprint);
    const auto authentication_key = derive_v2_key("mhwsmod-v2|mac", purpose, *game_fingerprint);
    if (!encryption_key.has_value() || !authentication_key.has_value()) {
        return std::nullopt;
    }

    DerivedKeyMaterial material{};
    material.game_fingerprint = *game_fingerprint;
    material.encryption_key = *encryption_key;
    material.authentication_key = *authentication_key;
    return material;
}

std::filesystem::path stage_index_path(const VirtualPakLoaderConfig& config) {
    return resolve_stage_root(config) / kStageIndexFileName;
}

bool is_hex_component(const std::wstring& value) {
    if (value.size() != 24) {
        return false;
    }

    for (const auto ch : value) {
        const auto lowered = static_cast<wchar_t>(towlower(ch));
        const auto is_digit = lowered >= L'0' && lowered <= L'9';
        const auto is_hex_alpha = lowered >= L'a' && lowered <= L'f';
        if (!is_digit && !is_hex_alpha) {
            return false;
        }
    }

    return true;
}

bool is_valid_indexed_stage_session_dir(const VirtualPakLoaderConfig& config, const std::filesystem::path& candidate) {
    if (candidate.empty()) {
        return false;
    }

    std::error_code ec{};
    const auto stage_root = std::filesystem::absolute(resolve_stage_root(config), ec).lexically_normal();
    if (ec) {
        return false;
    }

    ec.clear();
    const auto session_dir = std::filesystem::absolute(candidate, ec).lexically_normal();
    if (ec) {
        return false;
    }

    const auto relative = session_dir.lexically_relative(stage_root);
    if (relative.empty()) {
        return false;
    }

    std::vector<std::wstring> components{};
    for (const auto& part : relative) {
        const auto text = part.wstring();
        if (text.empty() || text == L"." || text == L"..") {
            return false;
        }
        components.emplace_back(text);
    }

    return components.size() == 2 && is_hex_component(components[0]) && is_hex_component(components[1]);
}

std::optional<std::vector<uint8_t>> encrypt_v2_payload_bytes(const std::vector<uint8_t>& plain_bytes, uint32_t purpose) {
    const auto material = derive_v2_key_material(purpose);
    if (!material.has_value()) {
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
            const_cast<PUCHAR>(material->encryption_key.data()),
            static_cast<ULONG>(material->encryption_key.size()),
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
    const auto auth_tag = compute_hmac_sha256_bytes(plain_bytes.data(), plain_bytes.size(), material->authentication_key);
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
    std::memcpy(header.game_fingerprint, material->game_fingerprint.data(), material->game_fingerprint.size());
    std::memcpy(header.iv, iv.data(), iv.size());
    std::memcpy(header.auth_tag, auth_tag->data(), auth_tag->size());

    std::vector<uint8_t> output(sizeof(header) + cipher_bytes.size(), 0);
    std::memcpy(output.data(), &header, sizeof(header));
    if (!cipher_bytes.empty()) {
        std::memcpy(output.data() + sizeof(header), cipher_bytes.data(), cipher_bytes.size());
    }

    return output;
}

std::optional<std::wstring> load_indexed_stage_session_dir(const VirtualPakLoaderConfig& config) {
    const auto index_bytes = read_binary_file(stage_index_path(config));
    if (!index_bytes.has_value()) {
        return std::nullopt;
    }

    const auto plain_bytes = decode_v2_encrypted_pak_bytes(*index_bytes, encrypted_pak::kPurposeIndex);
    if (!plain_bytes.has_value()) {
        append_log_line("stage-index-decode-failed\n");
        return std::nullopt;
    }

    const std::string plain_text(reinterpret_cast<const char*>(plain_bytes->data()), plain_bytes->size());
    if (plain_text.rfind(kStageIndexPlainMagic, 0) != 0) {
        append_log_line("stage-index-magic-invalid\n");
        return std::nullopt;
    }

    const auto wide_path = widen_utf8(plain_text.substr(std::strlen(kStageIndexPlainMagic)));
    if (!wide_path.has_value()) {
        append_log_line("stage-index-path-invalid\n");
        return std::nullopt;
    }

    return *wide_path;
}

void persist_stage_session_index(const VirtualPakLoaderConfig& config, const std::filesystem::path& session_dir) {
    if (config.keep_staged_file) {
        return;
    }

    const auto indexed_session_dir = session_dir.lexically_normal().wstring();
    const std::string payload_text = std::string{kStageIndexPlainMagic} + narrow_utf8(indexed_session_dir);
    const std::vector<uint8_t> plain_bytes(payload_text.begin(), payload_text.end());
    const auto encrypted_bytes = encrypt_v2_payload_bytes(plain_bytes, encrypted_pak::kPurposeIndex);
    if (!encrypted_bytes.has_value()) {
        append_log_line("stage-index-encrypt-failed\n");
        return;
    }

    const auto index_file = stage_index_path(config);
    std::error_code ec{};
    {
        ScopedInternalBackendOpen internal_open_guard{};
        std::filesystem::create_directories(index_file.parent_path(), ec);
        if (!ec && !write_binary_file(index_file, *encrypted_bytes)) {
            ec = std::make_error_code(std::errc::io_error);
        }
    }

    if (ec) {
        std::ostringstream oss;
        oss << "stage-index-write-failed path=" << narrow_utf8(index_file.wstring())
            << " ec=" << ec.value()
            << "\n";
        append_log_line(oss.str());
        return;
    }

    apply_hidden_system_attributes(index_file);
    std::ostringstream oss;
    oss << "stage-index-written path=" << narrow_utf8(index_file.wstring())
        << " session_dir=" << narrow_utf8(indexed_session_dir)
        << "\n";
    append_log_line(oss.str());
}

void ensure_stage_startup_cleanup(const VirtualPakLoaderConfig& config) {
    std::scoped_lock _{g_stage_session_mutex};
    if (g_stage_startup_cleanup_done || config.keep_staged_file) {
        return;
    }

    g_stage_startup_cleanup_done = true;
    const auto index_file = stage_index_path(config);
    const auto indexed_session_dir = load_indexed_stage_session_dir(config);
    if (!indexed_session_dir.has_value()) {
        std::error_code cleanup_ec{};
        ScopedInternalBackendOpen internal_open_guard{};
        std::filesystem::remove(index_file, cleanup_ec);
        return;
    }

    const std::filesystem::path session_dir{*indexed_session_dir};
    if (!is_valid_indexed_stage_session_dir(config, session_dir)) {
        append_log_line("stage-startup-clean-invalid-path\n");
        std::error_code cleanup_ec{};
        ScopedInternalBackendOpen internal_open_guard{};
        std::filesystem::remove(index_file, cleanup_ec);
        return;
    }

    std::error_code ec{};
    {
        ScopedInternalBackendOpen internal_open_guard{};
        std::filesystem::remove_all(session_dir, ec);
        std::error_code index_ec{};
        std::filesystem::remove(index_file, index_ec);
    }

    std::ostringstream oss;
    oss << "stage-startup-cleanup dir=" << narrow_utf8(session_dir.wstring())
        << " ec=" << ec.value()
        << "\n";
    append_log_line(oss.str());
}

std::optional<std::vector<uint8_t>> decrypt_aes256_cbc(
    const std::vector<uint8_t>& cipher_text,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 16>& iv,
    uint64_t expected_plain_size) {
    if (cipher_text.empty()) {
        return std::vector<uint8_t>{};
    }

    if (cipher_text.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max()) ||
        expected_plain_size > static_cast<uint64_t>(std::numeric_limits<ULONG>::max())) {
        append_log_line("virtual-loader-decrypt-size-too-large\n");
        return std::nullopt;
    }

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_KEY_HANDLE key_handle{};
    DWORD object_size{};
    DWORD bytes_written{};
    std::vector<uint8_t> key_object{};
    std::vector<uint8_t> output(cipher_text.size() + 16, 0);
    auto iv_copy = iv;
    ULONG output_size{};

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    const auto chaining_mode_bytes = static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t));
    if (BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), chaining_mode_bytes, 0) != 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes_written, 0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }

    key_object.resize(object_size);
    if (BCryptGenerateSymmetricKey(
            algorithm,
            &key_handle,
            key_object.data(),
            static_cast<ULONG>(key_object.size()),
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()),
            0) != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }

    const auto decrypt_status = BCryptDecrypt(
        key_handle,
        const_cast<PUCHAR>(cipher_text.data()),
        static_cast<ULONG>(cipher_text.size()),
        nullptr,
        iv_copy.data(),
        static_cast<ULONG>(iv_copy.size()),
        output.data(),
        static_cast<ULONG>(output.size()),
        &output_size,
        BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    if (decrypt_status != 0) {
        return std::nullopt;
    }

    output.resize(output_size);
    if (output.size() != expected_plain_size) {
        return std::nullopt;
    }

    return output;
}

std::optional<std::vector<uint8_t>> decrypt_xor32(
    const std::vector<uint8_t>& cipher_text,
    const std::array<uint8_t, 32>& key,
    uint64_t expected_plain_size) {
    if (cipher_text.size() != expected_plain_size) {
        return std::nullopt;
    }

    std::vector<uint8_t> output(cipher_text.size(), 0);
    for (size_t i = 0; i < cipher_text.size(); ++i) {
        output[i] = static_cast<uint8_t>(cipher_text[i] ^ key[i % key.size()]);
    }

    return output;
}

std::optional<std::vector<uint8_t>> decode_v2_encrypted_pak_bytes(
    const std::vector<uint8_t>& file_bytes,
    uint32_t expected_purpose) {
    if (file_bytes.size() < sizeof(encrypted_pak::HeaderV2)) {
        append_log_line("virtual-loader-source-read-failed\n");
        return std::nullopt;
    }

    encrypted_pak::HeaderV2 header{};
    std::memcpy(&header, file_bytes.data(), sizeof(header));
    if (std::memcmp(header.magic, encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size()) != 0 ||
        header.version != encrypted_pak::kVersion) {
        append_log_line("virtual-loader-header-invalid\n");
        return std::nullopt;
    }

    if (header.header_size < sizeof(encrypted_pak::HeaderV2) ||
        header.header_size > file_bytes.size() ||
        header.algorithm != encrypted_pak::kAlgorithmAes256CbcHmacSha256) {
        append_log_line("virtual-loader-header-size-invalid\n");
        return std::nullopt;
    }

    if (header.purpose != expected_purpose) {
        std::ostringstream oss;
        oss << "virtual-loader-purpose-mismatch expected=" << expected_purpose
            << " actual=" << header.purpose
            << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    const auto payload_offset = static_cast<size_t>(header.header_size);
    if (header.cipher_size == 0 ||
        (header.cipher_size % 16) != 0 ||
        header.cipher_size > file_bytes.size() ||
        payload_offset + header.cipher_size > file_bytes.size()) {
        append_log_line("virtual-loader-header-size-invalid\n");
        return std::nullopt;
    }

    const auto material = derive_v2_key_material(header.purpose);
    if (!material.has_value()) {
        return std::nullopt;
    }

    if (std::memcmp(header.game_fingerprint, material->game_fingerprint.data(), material->game_fingerprint.size()) != 0) {
        std::ostringstream oss;
        oss << "virtual-loader-fingerprint-mismatch expected=" << hex_encode_bytes(material->game_fingerprint.data(), material->game_fingerprint.size())
            << " actual=" << hex_encode_bytes(header.game_fingerprint, material->game_fingerprint.size())
            << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    std::vector<uint8_t> cipher_text(static_cast<size_t>(header.cipher_size), 0);
    if (!cipher_text.empty()) {
        std::memcpy(cipher_text.data(), file_bytes.data() + payload_offset, cipher_text.size());
    }

    std::array<uint8_t, 16> iv{};
    std::memcpy(iv.data(), header.iv, iv.size());
    const auto plain_bytes = decrypt_aes256_cbc(cipher_text, material->encryption_key, iv, header.plain_size);
    if (!plain_bytes.has_value()) {
        append_log_line("virtual-loader-decrypt-failed\n");
        return std::nullopt;
    }

    const auto auth_tag = compute_hmac_sha256_bytes(plain_bytes->data(), plain_bytes->size(), material->authentication_key);
    if (!auth_tag.has_value() ||
        std::memcmp(auth_tag->data(), header.auth_tag, auth_tag->size()) != 0) {
        append_log_line("virtual-loader-auth-failed\n");
        return std::nullopt;
    }

    return plain_bytes;
}

std::optional<std::vector<uint8_t>> decode_encrypted_pak_bytes(const std::vector<uint8_t>& file_bytes) {
    if (file_bytes.size() < sizeof(uint32_t) + encrypted_pak::kLegacyMagic.size()) {
        append_log_line("virtual-loader-source-read-failed\n");
        return std::nullopt;
    }

    if (std::memcmp(file_bytes.data(), encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size()) == 0) {
        return decode_v2_encrypted_pak_bytes(file_bytes, encrypted_pak::kPurposePak);
    }

    encrypted_pak::LegacyHeader header{};
    std::memcpy(&header, file_bytes.data(), sizeof(header));
    if (std::memcmp(header.magic, encrypted_pak::kLegacyMagic.data(), encrypted_pak::kLegacyMagic.size()) != 0 ||
        header.version != encrypted_pak::kLegacyVersion) {
        append_log_line("virtual-loader-header-invalid\n");
        return std::nullopt;
    }

    const auto payload_offset = sizeof(encrypted_pak::LegacyHeader);
    if (header.cipher_size > file_bytes.size() || payload_offset + header.cipher_size > file_bytes.size()) {
        append_log_line("virtual-loader-header-size-invalid\n");
        return std::nullopt;
    }

    std::vector<uint8_t> cipher_text(static_cast<size_t>(header.cipher_size), 0);
    if (!cipher_text.empty()) {
        std::memcpy(cipher_text.data(), file_bytes.data() + payload_offset, cipher_text.size());
    }

    const auto key = derive_game_key_once();
    if (!key.has_value()) {
        return std::nullopt;
    }

    if (header.algorithm == encrypted_pak::kAlgorithmAes256Cbc) {
        std::array<uint8_t, 16> iv{};
        std::memcpy(iv.data(), header.iv, iv.size());
        const auto plain_bytes = decrypt_aes256_cbc(cipher_text, *key, iv, header.plain_size);
        if (!plain_bytes.has_value()) {
            append_log_line("virtual-loader-decrypt-failed\n");
        }
        return plain_bytes;
    }

    if (header.algorithm == encrypted_pak::kAlgorithmXor32) {
        const auto plain_bytes = decrypt_xor32(cipher_text, *key, header.plain_size);
        if (!plain_bytes.has_value()) {
            append_log_line("virtual-loader-decrypt-failed\n");
        }
        return plain_bytes;
    }

    append_log_line("virtual-loader-header-invalid\n");
    return std::nullopt;
}

bool parse_metadata_json_text(std::string_view json_text, ModMetadataRecord& record) {
    const auto root = nlohmann::json::parse(json_text.begin(), json_text.end(), nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        return false;
    }

    auto assign_string_field = [&](const char* key, std::wstring& destination) {
        const auto it = root.find(key);
        if (it == root.end() || !it->is_string()) {
            return true;
        }

        const auto wide = widen_utf8(it->get_ref<const std::string&>());
        if (!wide.has_value()) {
            return false;
        }

        destination = trim_ascii_copy(*wide);
        return true;
    };

    return assign_string_field("mod_version", record.mod_version) &&
        assign_string_field("update_url", record.update_url) &&
        assign_string_field("author", record.author);
}

bool parse_legacy_metadata_block_bytes(const std::vector<uint8_t>& metadata_bytes, ModMetadataRecord& record) {
    if (metadata_bytes.size() < sizeof(encrypted_pak::MetadataHeaderV1)) {
        return false;
    }

    encrypted_pak::MetadataHeaderV1 header{};
    std::memcpy(&header, metadata_bytes.data(), sizeof(header));
    if (std::memcmp(header.magic, encrypted_pak::kMetadataMagic.data(), encrypted_pak::kMetadataMagic.size()) != 0 ||
        header.version != encrypted_pak::kMetadataVersion ||
        sizeof(header) + static_cast<size_t>(header.json_size) > metadata_bytes.size()) {
        return false;
    }

    const std::string json_text(
        reinterpret_cast<const char*>(metadata_bytes.data() + sizeof(header)),
        static_cast<size_t>(header.json_size));
    if (!parse_metadata_json_text(json_text, record)) {
        return false;
    }

    record.metadata_present = true;
    return true;
}

std::optional<ModMetadataRecord> load_mod_metadata_record(const std::filesystem::path& source_path) {
    ModMetadataRecord record{};
    record.source_path = source_path.wstring();
    record.display_name = source_path.stem().wstring();

    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(source_path, std::ios::binary);
    if (!input) {
        std::ostringstream oss;
        oss << "mhwsmod-metadata-open-failed source=" << narrow_utf8(record.source_path) << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    std::array<uint8_t, sizeof(encrypted_pak::HeaderV2)> header_bytes{};
    input.read(reinterpret_cast<char*>(header_bytes.data()), static_cast<std::streamsize>(header_bytes.size()));
    const auto bytes_read = static_cast<size_t>(input.gcount());
    if (bytes_read < sizeof(encrypted_pak::LegacyHeader)) {
        std::ostringstream oss;
        oss << "mhwsmod-metadata-header-invalid source=" << narrow_utf8(record.source_path) << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    if (std::memcmp(header_bytes.data(), encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size()) != 0) {
        return record;
    }

    if (bytes_read < sizeof(encrypted_pak::HeaderV2)) {
        std::ostringstream oss;
        oss << "mhwsmod-metadata-header-invalid source=" << narrow_utf8(record.source_path) << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    encrypted_pak::HeaderV2 header{};
    std::memcpy(&header, header_bytes.data(), sizeof(header));
    if (header.version != encrypted_pak::kVersion ||
        header.header_size < sizeof(encrypted_pak::HeaderV2) ||
        header.header_size == sizeof(encrypted_pak::HeaderV2)) {
        return record;
    }

    const auto metadata_size = static_cast<size_t>(header.header_size - sizeof(encrypted_pak::HeaderV2));
    std::vector<uint8_t> metadata_bytes(metadata_size, 0);
    input.read(reinterpret_cast<char*>(metadata_bytes.data()), static_cast<std::streamsize>(metadata_bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(metadata_bytes.size())) {
        std::ostringstream oss;
        oss << "mhwsmod-metadata-read-failed source=" << narrow_utf8(record.source_path)
            << " size=" << metadata_bytes.size()
            << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    if (metadata_bytes.size() >= encrypted_pak::kMagic.size() &&
        std::memcmp(metadata_bytes.data(), encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size()) == 0) {
        const auto plain_metadata = decode_v2_encrypted_pak_bytes(metadata_bytes, encrypted_pak::kPurposeMetadata);
        if (!plain_metadata.has_value() || !parse_legacy_metadata_block_bytes(*plain_metadata, record)) {
            std::ostringstream oss;
            oss << "mhwsmod-metadata-decode-failed source=" << narrow_utf8(record.source_path) << "\n";
            append_log_line(oss.str());
            return record;
        }

        record.authenticated = true;
    } else if (metadata_bytes.size() >= encrypted_pak::kMetadataMagic.size() &&
        std::memcmp(metadata_bytes.data(), encrypted_pak::kMetadataMagic.data(), encrypted_pak::kMetadataMagic.size()) == 0) {
        if (!parse_legacy_metadata_block_bytes(metadata_bytes, record)) {
            std::ostringstream oss;
            oss << "mhwsmod-metadata-legacy-parse-failed source=" << narrow_utf8(record.source_path) << "\n";
            append_log_line(oss.str());
            return record;
        }

        record.authenticated = false;
    } else {
        return record;
    }

    std::ostringstream oss;
    oss << "mhwsmod-metadata-loaded source=" << narrow_utf8(record.source_path)
        << " authenticated=" << static_cast<int>(record.authenticated)
        << " version=" << narrow_utf8(record.mod_version)
        << " update_url=" << narrow_utf8(record.update_url)
        << " author=" << narrow_utf8(record.author)
        << "\n";
    append_log_line(oss.str());
    return record;
}

bool decrypt_v2_encrypted_pak_to_file(
    const std::filesystem::path& source_path,
    const std::filesystem::path& output_path,
    const encrypted_pak::HeaderV2& header,
    uint64_t* plain_size_out) {
    if (plain_size_out != nullptr) {
        *plain_size_out = 0;
    }

    const auto material = derive_v2_key_material(header.purpose);
    if (!material.has_value()) {
        return false;
    }

    if (std::memcmp(header.game_fingerprint, material->game_fingerprint.data(), material->game_fingerprint.size()) != 0) {
        std::ostringstream oss;
        oss << "mhwsmod-fingerprint-mismatch source=" << narrow_utf8(source_path.wstring())
            << " expected=" << hex_encode_bytes(material->game_fingerprint.data(), material->game_fingerprint.size())
            << " actual=" << hex_encode_bytes(header.game_fingerprint, material->game_fingerprint.size())
            << "\n";
        append_log_line(oss.str());
        return false;
    }

    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(source_path, std::ios::binary);
    if (!input) {
        append_log_line("mhwsmod-read-failed\n");
        return false;
    }

    input.seekg(static_cast<std::streamoff>(header.header_size), std::ios::beg);
    if (!input.good()) {
        append_log_line("mhwsmod-header-seek-failed\n");
        return false;
    }

    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        append_log_line("mhwsmod-stage-write-failed\n");
        return false;
    }

    auto cleanup_output = [&]() {
        output.close();
        std::error_code cleanup_ec{};
        std::filesystem::remove(output_path, cleanup_ec);
    };

    ScopedBcryptAlgorithmHandle aes_algorithm{};
    ScopedBcryptKeyHandle aes_key{};
    ScopedBcryptAlgorithmHandle hmac_algorithm{};
    ScopedBcryptHashHandle hmac_hash{};
    DWORD aes_object_size{};
    DWORD bytes_written{};
    DWORD hmac_object_size{};
    DWORD hmac_hash_size{};
    std::vector<uint8_t> aes_key_object{};
    std::vector<uint8_t> hmac_hash_object{};
    std::vector<uint8_t> read_buffer(encrypted_pak::kDefaultIoChunkSize, 0);
    std::vector<uint8_t> pending{};
    std::vector<uint8_t> plain_buffer(encrypted_pak::kDefaultIoChunkSize + 32, 0);
    std::array<uint8_t, 16> iv{};
    std::array<uint8_t, 32> computed_auth_tag{};
    uint64_t remaining_cipher = header.cipher_size;
    uint64_t plain_size = 0;

    if (BCryptOpenAlgorithmProvider(&aes_algorithm.handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        cleanup_output();
        return false;
    }

    const auto chaining_mode_bytes = static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t));
    if (BCryptSetProperty(aes_algorithm.handle, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), chaining_mode_bytes, 0) != 0 ||
        BCryptGetProperty(aes_algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&aes_object_size), sizeof(aes_object_size), &bytes_written, 0) != 0) {
        cleanup_output();
        return false;
    }

    aes_key_object.resize(aes_object_size);
    if (BCryptGenerateSymmetricKey(
            aes_algorithm.handle,
            &aes_key.handle,
            aes_key_object.data(),
            static_cast<ULONG>(aes_key_object.size()),
            const_cast<PUCHAR>(material->encryption_key.data()),
            static_cast<ULONG>(material->encryption_key.size()),
            0) != 0) {
        cleanup_output();
        return false;
    }

    if (BCryptOpenAlgorithmProvider(&hmac_algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        cleanup_output();
        return false;
    }

    if (BCryptGetProperty(hmac_algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hmac_object_size), sizeof(hmac_object_size), &bytes_written, 0) != 0 ||
        BCryptGetProperty(hmac_algorithm.handle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hmac_hash_size), sizeof(hmac_hash_size), &bytes_written, 0) != 0 ||
        hmac_hash_size != computed_auth_tag.size()) {
        cleanup_output();
        return false;
    }

    hmac_hash_object.resize(hmac_object_size);
    if (BCryptCreateHash(
            hmac_algorithm.handle,
            &hmac_hash.handle,
            hmac_hash_object.data(),
            static_cast<ULONG>(hmac_hash_object.size()),
            const_cast<PUCHAR>(material->authentication_key.data()),
            static_cast<ULONG>(material->authentication_key.size()),
            0) != 0) {
        cleanup_output();
        return false;
    }

    std::memcpy(iv.data(), header.iv, iv.size());
    pending.reserve(read_buffer.size() + iv.size());

    while (remaining_cipher > 0) {
        const auto bytes_to_read = static_cast<size_t>(std::min<uint64_t>(remaining_cipher, read_buffer.size()));
        input.read(reinterpret_cast<char*>(read_buffer.data()), static_cast<std::streamsize>(bytes_to_read));
        if (input.gcount() != static_cast<std::streamsize>(bytes_to_read)) {
            cleanup_output();
            append_log_line("mhwsmod-read-short\n");
            return false;
        }

        pending.insert(pending.end(), read_buffer.begin(), read_buffer.begin() + bytes_to_read);
        remaining_cipher -= bytes_to_read;

        const auto is_final = remaining_cipher == 0;
        size_t cipher_to_process = 0;
        if (is_final) {
            cipher_to_process = pending.size();
        } else if (pending.size() > iv.size()) {
            cipher_to_process = pending.size() - iv.size();
            cipher_to_process -= (cipher_to_process % iv.size());
        }

        if (cipher_to_process == 0) {
            continue;
        }

        if (plain_buffer.size() < cipher_to_process + iv.size()) {
            plain_buffer.resize(cipher_to_process + iv.size());
        }

        ULONG plain_chunk_size{};
        const auto decrypt_status = BCryptDecrypt(
            aes_key.handle,
            pending.data(),
            static_cast<ULONG>(cipher_to_process),
            nullptr,
            iv.data(),
            static_cast<ULONG>(iv.size()),
            plain_buffer.data(),
            static_cast<ULONG>(plain_buffer.size()),
            &plain_chunk_size,
            is_final ? BCRYPT_BLOCK_PADDING : 0);

        if (decrypt_status != 0) {
            cleanup_output();
            append_log_line("mhwsmod-decrypt-failed\n");
            return false;
        }

        if (plain_chunk_size > 0 &&
            BCryptHashData(hmac_hash.handle, plain_buffer.data(), plain_chunk_size, 0) != 0) {
            cleanup_output();
            return false;
        }

        if (plain_chunk_size > 0) {
            output.write(reinterpret_cast<const char*>(plain_buffer.data()), plain_chunk_size);
            if (!output.good()) {
                cleanup_output();
                append_log_line("mhwsmod-stage-write-failed\n");
                return false;
            }
        }

        plain_size += plain_chunk_size;
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(cipher_to_process));
    }

    if (!pending.empty() || plain_size != header.plain_size) {
        cleanup_output();
        append_log_line("mhwsmod-size-mismatch\n");
        return false;
    }

    if (BCryptFinishHash(hmac_hash.handle, computed_auth_tag.data(), static_cast<ULONG>(computed_auth_tag.size()), 0) != 0) {
        cleanup_output();
        return false;
    }

    if (std::memcmp(computed_auth_tag.data(), header.auth_tag, computed_auth_tag.size()) != 0) {
        cleanup_output();
        append_log_line("mhwsmod-auth-failed\n");
        return false;
    }

    output.flush();
    if (!output.good()) {
        cleanup_output();
        append_log_line("mhwsmod-stage-write-failed\n");
        return false;
    }

    output.close();
    if (plain_size_out != nullptr) {
        *plain_size_out = plain_size;
    }
    return true;
}

std::optional<uint64_t> stage_encrypted_container_to_file(
    const std::filesystem::path& source_path,
    const std::filesystem::path& output_path) {
    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(source_path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }

    std::array<uint8_t, sizeof(encrypted_pak::HeaderV2)> header_bytes{};
    input.read(reinterpret_cast<char*>(header_bytes.data()), static_cast<std::streamsize>(header_bytes.size()));
    const auto bytes_read = static_cast<size_t>(input.gcount());
    if (bytes_read < sizeof(encrypted_pak::LegacyHeader)) {
        append_log_line("mhwsmod-header-invalid\n");
        return std::nullopt;
    }

    if (std::memcmp(header_bytes.data(), encrypted_pak::kMagic.data(), encrypted_pak::kMagic.size()) == 0) {
        if (bytes_read < sizeof(encrypted_pak::HeaderV2)) {
            append_log_line("mhwsmod-header-invalid\n");
            return std::nullopt;
        }

        encrypted_pak::HeaderV2 header{};
        std::memcpy(&header, header_bytes.data(), sizeof(header));
        if (header.version != encrypted_pak::kVersion ||
            header.header_size < sizeof(encrypted_pak::HeaderV2) ||
            header.algorithm != encrypted_pak::kAlgorithmAes256CbcHmacSha256 ||
            header.purpose != encrypted_pak::kPurposePak ||
            header.cipher_size == 0 ||
            (header.cipher_size % 16) != 0) {
            append_log_line("mhwsmod-header-invalid\n");
            return std::nullopt;
        }

        std::error_code size_ec{};
        const auto source_size = std::filesystem::file_size(source_path, size_ec);
        if (size_ec || header.header_size > source_size || header.cipher_size > source_size - header.header_size) {
            append_log_line("mhwsmod-header-size-invalid\n");
            return std::nullopt;
        }

        uint64_t plain_size{};
        if (!decrypt_v2_encrypted_pak_to_file(source_path, output_path, header, &plain_size)) {
            return std::nullopt;
        }

        return plain_size;
    }

    const auto encrypted_bytes = read_binary_file(source_path);
    if (!encrypted_bytes.has_value()) {
        return std::nullopt;
    }

    const auto plain_bytes = decode_encrypted_pak_bytes(*encrypted_bytes);
    if (!plain_bytes.has_value() || !write_binary_file(output_path, *plain_bytes)) {
        return std::nullopt;
    }

    return static_cast<uint64_t>(plain_bytes->size());
}

std::vector<std::wstring> stage_encrypted_custom_mods_into_local_dir(const VirtualPakLoaderConfig& config) {
    const auto encrypted_source_paths = resolve_encrypted_custom_mod_paths();

    std::scoped_lock _{g_encrypted_mod_stage_mutex};
    if (g_encrypted_mod_stage_prepared.exchange(true)) {
        return g_encrypted_mod_stage_cache.staged_paths;
    }

    const auto stage_dir = build_stage_session_dir(config);
    std::error_code ec{};
    {
        ScopedInternalBackendOpen internal_open_guard{};
        std::filesystem::create_directories(stage_dir, ec);
    }

    std::vector<std::wstring> staged_paths{};
    if (ec) {
        std::ostringstream oss;
        oss << "mhwsmod-stage-dir-create-failed path=" << narrow_utf8(stage_dir.wstring())
            << " ec=" << ec.value()
            << "\n";
        append_log_line(oss.str());
        return staged_paths;
    }

    for (const auto& source_path : encrypted_source_paths) {
        const auto output_path = build_random_stage_pak_path(stage_dir);
        const auto plain_size = stage_encrypted_container_to_file(source_path, output_path);
        if (!plain_size.has_value()) {
            std::ostringstream oss;
            oss << "mhwsmod-decrypt-failed source=" << narrow_utf8(source_path) << "\n";
            append_log_line(oss.str());
            continue;
        }

        apply_hidden_system_attributes(output_path);
        staged_paths.emplace_back(output_path.wstring());

        std::ostringstream oss;
        oss << "mhwsmod-staged source=" << narrow_utf8(source_path)
            << " output=" << narrow_utf8(output_path.wstring())
            << " size=0x" << std::hex << *plain_size
            << "\n";
        append_log_line(oss.str());
    }

    g_encrypted_mod_stage_cache.staged_dir = stage_dir.wstring();
    g_encrypted_mod_stage_cache.staged_paths = staged_paths;

    apply_hidden_system_attributes(stage_dir.parent_path());
    apply_hidden_system_attributes(stage_dir);

    std::ostringstream oss;
    oss << "mhwsmod-stage-summary"
        << " source_count=" << encrypted_source_paths.size()
        << " staged_count=" << staged_paths.size()
        << " stage_dir=" << narrow_utf8(stage_dir.wstring())
        << "\n";
    append_log_line(oss.str());

    return staged_paths;
}

std::optional<std::shared_ptr<std::vector<uint8_t>>> load_virtual_pak_payload() {
    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock _{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }

    if (!config.enabled || config.source_path.empty()) {
        return std::nullopt;
    }

    const std::filesystem::path source_path{config.source_path};
    std::error_code ec{};
    const auto write_time = std::filesystem::last_write_time(source_path, ec);
    if (ec) {
        std::ostringstream oss;
        oss << "virtual-loader-source-missing path=" << narrow_utf8(config.source_path)
            << " ec=" << ec.value()
            << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        if (g_virtual_payload_cache.payload &&
            g_virtual_payload_cache.source_path == config.source_path &&
            g_virtual_payload_cache.write_time == write_time) {
            return g_virtual_payload_cache.payload;
        }
    }

    const auto file_bytes = read_binary_file(source_path);
    if (!file_bytes.has_value()) {
        append_log_line("virtual-loader-source-read-failed\n");
        return std::nullopt;
    }

    if (config.plain_source) {
        const auto payload = std::make_shared<std::vector<uint8_t>>(*file_bytes);

        {
            std::scoped_lock _{g_virtual_loader_mutex};
            g_virtual_payload_cache.source_path = config.source_path;
            g_virtual_payload_cache.write_time = write_time;
            g_virtual_payload_cache.payload = payload;
        }

        std::ostringstream oss;
        oss << "virtual-loader-plain-payload-ready source=" << narrow_utf8(config.source_path)
            << " size=0x" << std::hex << payload->size()
            << "\n";
        append_log_line(oss.str());

        return payload;
    }

    const auto plain_bytes = decode_encrypted_pak_bytes(*file_bytes);
    if (!plain_bytes.has_value()) {
        return std::nullopt;
    }

    const auto payload = std::make_shared<std::vector<uint8_t>>(*plain_bytes);

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        g_virtual_payload_cache.source_path = config.source_path;
        g_virtual_payload_cache.write_time = write_time;
        g_virtual_payload_cache.payload = payload;
    }

    std::ostringstream oss;
    oss << "virtual-loader-payload-ready source=" << narrow_utf8(config.source_path)
        << " plain_size=0x" << std::hex << payload->size()
        << "\n";
    append_log_line(oss.str());

    return payload;
}

std::optional<std::wstring> ensure_runtime_source_path_prepared() {
    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock _{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }

    if (!config.enabled || config.source_path.empty()) {
        return std::nullopt;
    }

    if (!config.stage_source) {
        return config.source_path;
    }

    const std::filesystem::path source_path{config.source_path};
    std::error_code ec{};
    const auto write_time = std::filesystem::last_write_time(source_path, ec);
    if (ec) {
        std::ostringstream oss;
        oss << "stage-source-missing path=" << narrow_utf8(config.source_path)
            << " ec=" << ec.value()
            << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        if (!g_virtual_stage_cache.staged_path.empty() &&
            g_virtual_stage_cache.source_path == config.source_path &&
            g_virtual_stage_cache.write_time == write_time &&
            std::filesystem::exists(g_virtual_stage_cache.staged_path, ec) &&
            !ec) {
            return g_virtual_stage_cache.staged_path;
        }
    }

    const auto session_dir = build_stage_session_dir(config);
    const auto staged_path = build_stage_output_path(config);
    std::filesystem::create_directories(session_dir, ec);
    if (ec) {
        std::ostringstream oss;
        oss << "stage-dir-create-failed path=" << narrow_utf8(session_dir.wstring())
            << " ec=" << ec.value()
            << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    bool stage_ok = false;
    if (config.plain_source) {
        ScopedInternalBackendOpen internal_open_guard{};
        std::filesystem::copy_file(source_path, staged_path, std::filesystem::copy_options::overwrite_existing, ec);
        stage_ok = !ec;
    } else {
        const auto payload = load_virtual_pak_payload();
        if (payload.has_value()) {
            stage_ok = write_binary_file(staged_path, **payload);
        }
    }

    if (!stage_ok) {
        std::ostringstream oss;
        oss << "stage-write-failed path=" << narrow_utf8(staged_path.wstring());
        if (ec) {
            oss << " ec=" << ec.value();
        }
        oss << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    apply_hidden_system_attributes(session_dir.parent_path());
    apply_hidden_system_attributes(session_dir);
    apply_hidden_system_attributes(staged_path);

    {
        std::scoped_lock _{g_virtual_loader_mutex};
        g_virtual_stage_cache.source_path = config.source_path;
        g_virtual_stage_cache.write_time = write_time;
        g_virtual_stage_cache.staged_path = staged_path.wstring();
        g_virtual_stage_cache.staged_dir = session_dir.wstring();
    }

    std::ostringstream oss;
    oss << "stage-ready input=" << narrow_utf8(config.source_path)
        << " staged=" << narrow_utf8(staged_path.wstring())
        << " plain_source=" << static_cast<int>(config.plain_source)
        << "\n";
    append_log_line(oss.str());
    return staged_path.wstring();
}

void cleanup_staged_runtime_source() {
    VirtualPakLoaderConfig config{};
    VirtualPakStageCache cache{};
    EncryptedModStageCache encrypted_cache{};
    std::wstring shared_stage_session_dir{};
    {
        std::scoped_lock _{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
        cache = g_virtual_stage_cache;
        g_virtual_stage_cache = {};
    }
    {
        std::scoped_lock _{g_encrypted_mod_stage_mutex};
        encrypted_cache = g_encrypted_mod_stage_cache;
        g_encrypted_mod_stage_cache = {};
        g_encrypted_mod_stage_prepared = false;
    }
    {
        std::scoped_lock _{g_stage_session_mutex};
        shared_stage_session_dir = g_shared_stage_session_dir;
        g_shared_stage_session_dir.clear();
    }

    const auto has_generic_stage = !cache.staged_dir.empty() || !cache.staged_path.empty();
    const auto has_encrypted_stage = !encrypted_cache.staged_dir.empty() || !encrypted_cache.staged_paths.empty();
    const auto session_dir_to_remove = !shared_stage_session_dir.empty()
        ? shared_stage_session_dir
        : (!cache.staged_dir.empty() ? cache.staged_dir : encrypted_cache.staged_dir);

    if (config.keep_staged_file || (!has_generic_stage && !has_encrypted_stage && session_dir_to_remove.empty())) {
        return;
    }

    std::error_code ec{};
    {
        ScopedInternalBackendOpen internal_open_guard{};
        if (!session_dir_to_remove.empty()) {
            std::filesystem::remove_all(session_dir_to_remove, ec);
        } else {
            if (!cache.staged_path.empty()) {
                std::filesystem::remove(cache.staged_path, ec);
                ec.clear();
            }
            if (!cache.staged_dir.empty()) {
                std::filesystem::remove_all(cache.staged_dir, ec);
            }
        }
    }

    std::ostringstream oss;
    oss << "stage-cleanup path=" << narrow_utf8(cache.staged_path)
        << " dir=" << narrow_utf8(session_dir_to_remove.empty() ? cache.staged_dir : session_dir_to_remove)
        << " encrypted_count=" << encrypted_cache.staged_paths.size()
        << "\n";
    append_log_line(oss.str());
}

bool path_matches_virtual_target_locked(const std::wstring& normalized_path, const VirtualPakLoaderConfig& config) {
    if (!config.enabled || config.record_only) {
        return false;
    }

    if (!config.target_path_normalized.empty()) {
        return normalized_path_matches_target(normalized_path, config.target_path_normalized);
    }

    const auto effective_source_count = count_effective_virtual_source_paths(config);
    if (config.base_patch_num < 0 || effective_source_count <= 0) {
        return false;
    }

    if (!looks_like_reframework_custom_slot_path(normalized_path)) {
        return false;
    }

    const auto patch_num = extract_patch_num_from_target_path(normalized_path);
    if (!patch_num.has_value() || *patch_num <= config.base_patch_num) {
        return false;
    }

    const auto first_custom_patch = config.base_patch_num + 1;
    if (*patch_num < first_custom_patch) {
        return false;
    }

    const auto custom_index = *patch_num - first_custom_patch;
    return custom_index >= 0 && custom_index < effective_source_count;
}

bool path_matches_record_target_locked(const std::wstring& normalized_path, const VirtualPakLoaderConfig& config) {
    if (!config.enabled || !config.record_only || config.target_path_normalized.empty()) {
        return false;
    }

    return normalized_path_matches_target(normalized_path, config.target_path_normalized);
}

