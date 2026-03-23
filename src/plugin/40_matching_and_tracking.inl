bool path_matches_virtual_target(const std::wstring& path) {
    const auto normalized = normalize_path_for_match(path);
    std::scoped_lock _{g_virtual_loader_mutex};
    return path_matches_virtual_target_locked(normalized, g_virtual_loader_config);
}

bool path_matches_virtual_target(LPCWSTR file_name) {
    if (file_name == nullptr) {
        return false;
    }

    return path_matches_virtual_target(std::wstring{file_name});
}

bool path_matches_record_target(const std::wstring& path) {
    const auto normalized = normalize_path_for_match(path);
    std::scoped_lock _{g_virtual_loader_mutex};
    return path_matches_record_target_locked(normalized, g_virtual_loader_config);
}

bool path_matches_record_target(LPCWSTR file_name) {
    if (file_name == nullptr) {
        return false;
    }

    return path_matches_record_target(std::wstring{file_name});
}

std::optional<VirtualPakLoaderConfig> current_virtual_loader_config() {
    std::scoped_lock _{g_virtual_loader_mutex};
    if (!g_virtual_loader_config.enabled || g_virtual_loader_config.record_only || g_virtual_loader_config.source_path.empty()) {
        return std::nullopt;
    }

    return g_virtual_loader_config;
}

std::optional<std::wstring> current_virtual_source_path() {
    return ensure_runtime_source_path_prepared();
}

HANDLE create_virtual_file_handle(
    const std::wstring& requested_path,
    const std::wstring& source_path,
    std::shared_ptr<std::vector<uint8_t>> payload,
    HANDLE backing_handle = nullptr) {
    auto handle = backing_handle;
    const auto synthetic_handle = handle == nullptr || handle == INVALID_HANDLE_VALUE;
    if (synthetic_handle) {
        const auto id = g_virtual_handle_counter.fetch_add(1);
        handle = reinterpret_cast<HANDLE>(encrypted_pak::kVirtualFileHandleBase + id);
    }

    const auto key = reinterpret_cast<uintptr_t>(handle);
    VirtualPakHandleState state{};
    state.requested_path = requested_path;
    state.source_path = source_path;
    state.payload = std::move(payload);
    state.position = 0;
    state.synthetic_handle = synthetic_handle;

    std::scoped_lock _{g_handle_mutex};
    g_virtual_pak_handles.emplace(key, std::move(state));

    return handle;
}

HANDLE create_virtual_mapping_handle(
    const std::wstring& path,
    std::shared_ptr<std::vector<uint8_t>> payload,
    HANDLE backing_handle = nullptr) {
    auto handle = backing_handle;
    const auto synthetic_handle = handle == nullptr || handle == INVALID_HANDLE_VALUE;
    if (synthetic_handle) {
        const auto id = g_virtual_handle_counter.fetch_add(1);
        handle = reinterpret_cast<HANDLE>(encrypted_pak::kVirtualMappingHandleBase + id);
    }

    const auto key = reinterpret_cast<uintptr_t>(handle);
    VirtualMappingHandleState state{};
    state.path = path;
    state.payload = std::move(payload);
    state.synthetic_handle = synthetic_handle;

    std::scoped_lock _{g_handle_mutex};
    g_virtual_mapping_handles.emplace(key, std::move(state));

    return handle;
}

bool path_looks_like_pak(LPCWSTR file_name) {
    if (file_name == nullptr) {
        return false;
    }

    const auto lowered = to_lower_copy(file_name);
    return lowered.find(L".pak") != std::wstring::npos;
}

bool path_matches_focus_target(const std::wstring& path) {
    if (path_matches_virtual_target(path)) {
        return true;
    }

    const auto lowered = normalize_path_for_match(path);
    return lowered.find(kFocusPakPathFragment) != std::wstring::npos;
}

bool path_matches_focus_target(LPCWSTR file_name) {
    if (file_name == nullptr) {
        return false;
    }

    return path_matches_focus_target(std::wstring{file_name});
}

std::optional<size_t> match_create_file_nearby_site(void* caller) {
    const auto caller_addr = reinterpret_cast<uintptr_t>(caller);

    for (size_t i = 0; i < g_create_file_callsite_addrs.size(); ++i) {
        const auto callsite = g_create_file_callsite_addrs[i];
        if (callsite != 0 && caller_addr > callsite && caller_addr <= (callsite + 0x20)) {
            return i;
        }
    }

    return std::nullopt;
}

std::string describe_caller(void* caller) {
    std::ostringstream oss;
    const auto caller_addr = reinterpret_cast<uintptr_t>(caller);

    HMODULE caller_module{};
    std::wstring module_path = L"<unknown>";
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(caller),
            &caller_module) != 0 &&
        caller_module != nullptr) {
        module_path = widen_module_path(caller_module);
    }

    oss << " caller_return=0x" << std::hex << caller_addr
        << " module=" << narrow_utf8(module_path);

    if (caller_module != nullptr && reinterpret_cast<uintptr_t>(caller_module) == g_game_module_base) {
        oss << " game_rva=0x" << (caller_addr - g_game_module_base);
    }

    const auto nearby_site = match_create_file_nearby_site(caller);
    if (nearby_site.has_value()) {
        oss << " near_site_index=" << *nearby_site
            << " expected_callsite=0x" << g_create_file_callsite_addrs[*nearby_site];
    }

    return oss.str();
}

CallerContext resolve_caller_context(void* caller) {
    CallerContext context{};
    context.return_address = reinterpret_cast<uintptr_t>(caller);
    context.near_createfile_site = match_create_file_nearby_site(caller).has_value();

    if (caller == nullptr) {
        return context;
    }

    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(caller),
            &context.module) != 0 &&
        context.module != nullptr) {
        context.module_path = widen_module_path(context.module);
        context.module_name = to_lower_copy(std::filesystem::path(context.module_path).filename().wstring());
    }

    return context;
}

const char* evaluate_virtual_backend_caller(const CallerContext& caller) {
    if (caller.near_createfile_site) {
        return "allow_near_game_callsite";
    }

    if (caller.module != nullptr && reinterpret_cast<uintptr_t>(caller.module) == g_game_module_base) {
        return "allow_game_module";
    }

    if (caller.module_name == L"dinput8.dll") {
        return "allow_reframework_module";
    }

    if (caller.module_name == L"dstorage.dll" || caller.module_name == L"dstoragecore.dll") {
        return "allow_directstorage_module";
    }

    if (caller.module == nullptr) {
        return "allow_unknown_module";
    }

    return nullptr;
}

uintptr_t handle_key(HANDLE handle) {
    return reinterpret_cast<uintptr_t>(handle);
}

void track_pak_handle(HANDLE handle, const std::wstring& path) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto key = handle_key(handle);
    g_pak_handle_paths[key] = path;
    g_pak_handle_positions[key] = 0;
    g_pak_handle_sizes.erase(key);
}

std::optional<std::wstring> lookup_pak_handle_path(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto virtual_it = g_virtual_pak_handles.find(handle_key(handle));
    if (virtual_it != g_virtual_pak_handles.end()) {
        return virtual_it->second.requested_path;
    }

    const auto it = g_pak_handle_paths.find(handle_key(handle));
    if (it == g_pak_handle_paths.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::optional<uint64_t> lookup_pak_handle_position(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto virtual_it = g_virtual_pak_handles.find(handle_key(handle));
    if (virtual_it != g_virtual_pak_handles.end()) {
        return virtual_it->second.position;
    }

    const auto it = g_pak_handle_positions.find(handle_key(handle));
    if (it == g_pak_handle_positions.end()) {
        return std::nullopt;
    }

    return it->second;
}

void set_pak_handle_position(HANDLE handle, uint64_t position) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto virtual_it = g_virtual_pak_handles.find(handle_key(handle));
    if (virtual_it != g_virtual_pak_handles.end()) {
        virtual_it->second.position = position;
        return;
    }

    g_pak_handle_positions[handle_key(handle)] = position;
}

std::optional<uint64_t> lookup_pak_handle_size(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto virtual_it = g_virtual_pak_handles.find(handle_key(handle));
    if (virtual_it != g_virtual_pak_handles.end()) {
        return virtual_it->second.payload != nullptr ? virtual_it->second.payload->size() : 0ULL;
    }

    const auto it = g_pak_handle_sizes.find(handle_key(handle));
    if (it == g_pak_handle_sizes.end()) {
        return std::nullopt;
    }

    return it->second;
}

void set_pak_handle_size(HANDLE handle, uint64_t size) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto virtual_it = g_virtual_pak_handles.find(handle_key(handle));
    if (virtual_it != g_virtual_pak_handles.end()) {
        return;
    }

    g_pak_handle_sizes[handle_key(handle)] = size;
}

std::optional<uint64_t> apply_signed_offset(uint64_t base, int64_t delta) {
    if (delta >= 0) {
        return base + static_cast<uint64_t>(delta);
    }

    const auto magnitude = static_cast<uint64_t>(-delta);
    if (magnitude > base) {
        return std::nullopt;
    }

    return base - magnitude;
}

void track_mapping_handle(HANDLE mapping_handle, const std::wstring& path) {
    if (mapping_handle == nullptr || mapping_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    std::scoped_lock _{g_handle_mutex};
    g_mapping_handle_paths[handle_key(mapping_handle)] = path;
}

std::optional<std::wstring> lookup_mapping_handle_path(HANDLE mapping_handle) {
    if (mapping_handle == nullptr || mapping_handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto virtual_it = g_virtual_mapping_handles.find(handle_key(mapping_handle));
    if (virtual_it != g_virtual_mapping_handles.end()) {
        return virtual_it->second.path;
    }

    const auto it = g_mapping_handle_paths.find(handle_key(mapping_handle));
    if (it == g_mapping_handle_paths.end()) {
        return std::nullopt;
    }

    return it->second;
}

void untrack_close_handle(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto key = handle_key(handle);
    g_pak_handle_paths.erase(key);
    g_pak_handle_positions.erase(key);
    g_pak_handle_sizes.erase(key);
    g_mapping_handle_paths.erase(key);
    g_virtual_pak_handles.erase(key);
    g_virtual_mapping_handles.erase(key);
}

bool ensure_minhook_initialized() {
    const auto status = MH_Initialize();
    if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED) {
        return true;
    }

    std::ostringstream oss;
    oss << "minhook-init-failed status=" << static_cast<int>(status) << "\n";
    append_log_line(oss.str());
    return false;
}

bool install_named_hook(void* target, void* detour, void** original, const char* label) {
    if (target == nullptr) {
        std::ostringstream oss;
        oss << "install-hook-missing-target label=" << label << "\n";
        append_log_line(oss.str());
        return false;
    }

    const auto create_status = MH_CreateHook(target, detour, original);
    if (create_status != MH_OK && create_status != MH_ERROR_ALREADY_CREATED) {
        std::ostringstream oss;
        oss << "install-hook-create-failed label=" << label << " status=" << static_cast<int>(create_status)
            << " target=0x" << std::hex << reinterpret_cast<uintptr_t>(target) << "\n";
        append_log_line(oss.str());
        return false;
    }

    const auto enable_status = MH_EnableHook(target);
    if (enable_status != MH_OK && enable_status != MH_ERROR_ENABLED) {
        std::ostringstream oss;
        oss << "install-hook-enable-failed label=" << label << " status=" << static_cast<int>(enable_status)
            << " target=0x" << std::hex << reinterpret_cast<uintptr_t>(target) << "\n";
        append_log_line(oss.str());
        return false;
    }

    return true;
}

void initialize_fixed_addresses() {
    if (g_game_module_base != 0) {
        return;
    }

    g_game_module_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (g_game_module_base == 0) {
        append_log_line("game-module-null\n");
        return;
    }

    for (size_t i = 0; i < kCreateFileCallsiteRvas.size(); ++i) {
        g_create_file_callsite_addrs[i] = g_game_module_base + kCreateFileCallsiteRvas[i];
    }

    std::ostringstream oss;
    oss << "fixed-targets"
        << " module_base=0x" << std::hex << g_game_module_base
        << " open_stream=0x" << (g_game_module_base + kOpenStreamRva)
        << " createfile_callsite_0=0x" << g_create_file_callsite_addrs[0]
        << " callsite_0_bytes=" << dump_bytes(reinterpret_cast<const void*>(g_create_file_callsite_addrs[0]), 8)
        << " createfile_callsite_1=0x" << g_create_file_callsite_addrs[1]
        << " callsite_1_bytes=" << dump_bytes(reinterpret_cast<const void*>(g_create_file_callsite_addrs[1]), 8)
        << " directstorage_callsite=0x" << (g_game_module_base + kDirectStorageCallsiteRva)
        << "\n";
    append_log_line(oss.str());
}

bool install_redirect_breakpoint_site(RedirectPathBreakpointSite& site, uintptr_t address, const char* label) {
    if (site.addr == address && site.addr != 0) {
        return true;
    }

    uint8_t original_byte{};
    if (!read_memory_block_safe(reinterpret_cast<const void*>(address), &original_byte, sizeof(original_byte))) {
        std::ostringstream oss;
        oss << "redirect-breakpoint-byte-read-failed"
            << " label=" << label
            << " addr=0x" << std::hex << address
            << "\n";
        append_log_line(oss.str());
        return false;
    }

    if (!write_breakpoint_byte(address, 0xCC)) {
        std::ostringstream oss;
        oss << "redirect-breakpoint-install-failed"
            << " label=" << label
            << " addr=0x" << std::hex << address
            << "\n";
        append_log_line(oss.str());
        return false;
    }

    site.addr = address;
    site.original_byte = original_byte;
    site.label = label;
    return true;
}

bool install_redirect_path_breakpoints() {
    initialize_fixed_addresses();

    if (g_redirect_path_veh_handle == nullptr) {
        g_redirect_path_veh_handle = AddVectoredExceptionHandler(1, &redirect_path_veh_handler);
        if (g_redirect_path_veh_handle == nullptr) {
            append_log_line("redirect-breakpoint-veh-install-failed\n");
            return false;
        }
    }

    bool ok = true;
    for (size_t i = 0; i < g_create_file_callsite_addrs.size(); ++i) {
        if (!install_redirect_breakpoint_site(g_redirect_createfile_sites[i], g_create_file_callsite_addrs[i], "createfile_callsite")) {
            ok = false;
        }
    }

    std::ostringstream oss;
    oss << "redirect-breakpoints-installed"
        << " createfile_sites=" << std::dec << g_create_file_callsite_addrs.size()
        << " directstorage_site=0"
        << " ok=" << static_cast<int>(ok)
        << "\n";
    append_log_line(oss.str());
    return ok;
}

void uninstall_redirect_path_breakpoints() {
    for (auto& site : g_redirect_createfile_sites) {
        if (site.addr != 0) {
            write_breakpoint_byte(site.addr, site.original_byte);
            site.addr = 0;
            site.original_byte = 0;
            site.label = nullptr;
        }
    }

    if (g_redirect_directstorage_site.addr != 0) {
        write_breakpoint_byte(g_redirect_directstorage_site.addr, g_redirect_directstorage_site.original_byte);
        g_redirect_directstorage_site.addr = 0;
        g_redirect_directstorage_site.original_byte = 0;
        g_redirect_directstorage_site.label = nullptr;
    }

    if (g_redirect_path_veh_handle != nullptr) {
        RemoveVectoredExceptionHandler(g_redirect_path_veh_handle);
        g_redirect_path_veh_handle = nullptr;
    }
}

bool resolve_directstorage_target_once() {
    initialize_fixed_addresses();
    if (g_game_module_base == 0) {
        return false;
    }

    if (g_directstorage_target != nullptr) {
        return true;
    }

    const auto callsite = g_game_module_base + kDirectStorageCallsiteRva;
    const auto search_begin = callsite - 0x30;

    for (size_t offset = 0; offset < 0x30; ++offset) {
        const auto addr = search_begin + offset;
        uint8_t insn[7]{};
        if (!read_memory_block_safe(reinterpret_cast<const void*>(addr), insn, sizeof(insn))) {
            continue;
        }

        if (insn[0] == 0x48 && insn[1] == 0x8B && insn[2] == 0x0D) {
            const auto global_ptr_addr = resolve_rel32_target(addr, 3, 7);
            if (!global_ptr_addr) {
                continue;
            }

            g_directstorage_global_ptr_addr = *global_ptr_addr;

            uint64_t object_ptr{};
            if (!read_u64_safe(reinterpret_cast<const void*>(g_directstorage_global_ptr_addr), &object_ptr) || object_ptr == 0) {
                continue;
            }

            uint64_t vtable{};
            if (!read_u64_safe(reinterpret_cast<const void*>(object_ptr), &vtable) || vtable == 0) {
                continue;
            }

            uint64_t target{};
            if (!read_u64_safe(reinterpret_cast<const void*>(vtable + 0x20), &target) || target == 0) {
                continue;
            }

            g_directstorage_target = reinterpret_cast<void*>(static_cast<uintptr_t>(target));

            std::ostringstream oss;
            oss << "directstorage-resolved"
                << " global_ptr_addr=0x" << std::hex << g_directstorage_global_ptr_addr
                << " object=0x" << object_ptr
                << " vtable=0x" << vtable
                << " target=0x" << target
                << "\n";
            append_log_line(oss.str());
            return true;
        }
    }

    append_log_line("directstorage-target-unavailable\n");
    return false;
}

std::optional<std::shared_ptr<std::vector<uint8_t>>> lookup_virtual_payload(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto it = g_virtual_pak_handles.find(handle_key(handle));
    if (it == g_virtual_pak_handles.end()) {
        return std::nullopt;
    }

    return it->second.payload;
}

std::optional<VirtualPakHandleState> lookup_virtual_pak_state(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto it = g_virtual_pak_handles.find(handle_key(handle));
    if (it == g_virtual_pak_handles.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::optional<std::wstring> lookup_virtual_source_path(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto it = g_virtual_pak_handles.find(handle_key(handle));
    if (it == g_virtual_pak_handles.end()) {
        return std::nullopt;
    }

    return it->second.source_path;
}

std::optional<VirtualMappingHandleState> lookup_virtual_mapping(HANDLE handle) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    std::scoped_lock _{g_handle_mutex};
    const auto it = g_virtual_mapping_handles.find(handle_key(handle));
    if (it == g_virtual_mapping_handles.end()) {
        return std::nullopt;
    }

    return it->second;
}

FILETIME virtual_filetime_now() {
    FILETIME filetime{};
    GetSystemTimeAsFileTime(&filetime);
    return filetime;
}

LONGLONG filetime_to_large_integer(const FILETIME& filetime) {
    return (static_cast<LONGLONG>(filetime.dwHighDateTime) << 32) | filetime.dwLowDateTime;
}

uint64_t virtual_file_id(HANDLE handle) {
    return 0x4D48575000000000ULL | (handle_key(handle) & 0x00000000FFFFFFFFULL);
}

bool fill_virtual_by_handle_file_information(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION file_information) {
    if (file_information == nullptr) {
        return false;
    }

    const auto size = lookup_pak_handle_size(handle).value_or(0);
    const auto filetime = virtual_filetime_now();
    std::memset(file_information, 0, sizeof(*file_information));
    file_information->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
    file_information->ftCreationTime = filetime;
    file_information->ftLastAccessTime = filetime;
    file_information->ftLastWriteTime = filetime;
    file_information->dwVolumeSerialNumber = 0x4D485750;
    file_information->nFileSizeHigh = static_cast<DWORD>(size >> 32);
    file_information->nFileSizeLow = static_cast<DWORD>(size & 0xFFFFFFFFULL);
    file_information->nNumberOfLinks = 1;
    const auto file_id = virtual_file_id(handle);
    file_information->nFileIndexHigh = static_cast<DWORD>(file_id >> 32);
    file_information->nFileIndexLow = static_cast<DWORD>(file_id & 0xFFFFFFFFULL);
    return true;
}

bool patch_virtual_by_handle_file_information(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION file_information) {
    if (file_information == nullptr) {
        return false;
    }

    const auto size = lookup_pak_handle_size(handle).value_or(0);
    file_information->nFileSizeHigh = static_cast<DWORD>(size >> 32);
    file_information->nFileSizeLow = static_cast<DWORD>(size & 0xFFFFFFFFULL);
    return true;
}

bool fill_virtual_file_information_by_handle_ex(
    HANDLE handle,
    FILE_INFO_BY_HANDLE_CLASS file_information_class,
    LPVOID file_information,
    DWORD buffer_size,
    DWORD* last_error) {
    if (file_information == nullptr) {
        if (last_error != nullptr) {
            *last_error = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    const auto size = lookup_pak_handle_size(handle).value_or(0);
    const auto position = lookup_pak_handle_position(handle).value_or(0);
    const auto filetime = virtual_filetime_now();
    const auto requested_path = lookup_pak_handle_path(handle).value_or(L"");

    auto require_size = [&](size_t required) {
        if (buffer_size < required) {
            if (last_error != nullptr) {
                *last_error = ERROR_MORE_DATA;
            }
            return false;
        }
        return true;
    };

    switch (file_information_class) {
    case FileBasicInfo: {
        if (!require_size(sizeof(FILE_BASIC_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_BASIC_INFO*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->CreationTime.QuadPart = filetime_to_large_integer(filetime);
        info->LastAccessTime = info->CreationTime;
        info->LastWriteTime = info->CreationTime;
        info->ChangeTime = info->CreationTime;
        info->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
        return true;
    }
    case FileStandardInfo: {
        if (!require_size(sizeof(FILE_STANDARD_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_STANDARD_INFO*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->AllocationSize.QuadPart = static_cast<LONGLONG>(size);
        info->EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        info->NumberOfLinks = 1;
        return true;
    }
    case FileAttributeTagInfo: {
        if (!require_size(sizeof(FILE_ATTRIBUTE_TAG_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_ATTRIBUTE_TAG_INFO*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
        return true;
    }
    case FileCompressionInfo: {
        if (!require_size(sizeof(FILE_COMPRESSION_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_COMPRESSION_INFO*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->CompressedFileSize.QuadPart = static_cast<LONGLONG>(size);
        return true;
    }
    case FileAlignmentInfo: {
        if (!require_size(sizeof(FILE_ALIGNMENT_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_ALIGNMENT_INFO*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->AlignmentRequirement = 0;
        return true;
    }
    case FileIdInfo: {
        if (!require_size(sizeof(FILE_ID_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_ID_INFO*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->VolumeSerialNumber = 0x4D485750;
        const auto file_id = virtual_file_id(handle);
        std::memcpy(info->FileId.Identifier, &file_id, sizeof(file_id));
        return true;
    }
    case FileNameInfo: {
        const auto bytes_needed = sizeof(FILE_NAME_INFO) + (requested_path.size() * sizeof(wchar_t));
        if (!require_size(bytes_needed)) {
            return false;
        }
        auto* info = static_cast<FILE_NAME_INFO*>(file_information);
        std::memset(info, 0, buffer_size);
        info->FileNameLength = static_cast<DWORD>(requested_path.size() * sizeof(wchar_t));
        if (!requested_path.empty()) {
            std::memcpy(info->FileName, requested_path.data(), requested_path.size() * sizeof(wchar_t));
        }
        return true;
    }
    default:
        if (last_error != nullptr) {
            *last_error = ERROR_CALL_NOT_IMPLEMENTED;
        }
        return false;
    }
}

bool patch_virtual_file_information_by_handle_ex(
    HANDLE handle,
    FILE_INFO_BY_HANDLE_CLASS file_information_class,
    LPVOID file_information,
    DWORD buffer_size,
    DWORD* last_error) {
    if (file_information == nullptr) {
        if (last_error != nullptr) {
            *last_error = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    const auto size = lookup_pak_handle_size(handle).value_or(0);

    auto require_size = [&](size_t required) {
        if (buffer_size < required) {
            if (last_error != nullptr) {
                *last_error = ERROR_MORE_DATA;
            }
            return false;
        }
        return true;
    };

    switch (file_information_class) {
    case FileStandardInfo: {
        if (!require_size(sizeof(FILE_STANDARD_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_STANDARD_INFO*>(file_information);
        info->AllocationSize.QuadPart = static_cast<LONGLONG>(size);
        info->EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        return true;
    }
    case FileCompressionInfo: {
        if (!require_size(sizeof(FILE_COMPRESSION_INFO))) {
            return false;
        }
        auto* info = static_cast<FILE_COMPRESSION_INFO*>(file_information);
        info->CompressedFileSize.QuadPart = static_cast<LONGLONG>(size);
        return true;
    }
    default:
        if (last_error != nullptr) {
            *last_error = ERROR_SUCCESS;
        }
        return true;
    }
}

struct VirtualNtFileStandardInformation {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
    USHORT Reserved;
};

struct VirtualNtFilePositionInformation {
    LARGE_INTEGER CurrentByteOffset;
};

struct VirtualNtFileNetworkOpenInformation {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG Reserved;
};

NTSTATUS fill_virtual_nt_query_information_file(
    HANDLE handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    FILE_INFORMATION_CLASS file_information_class) {
    if (io_status_block == nullptr || file_information == nullptr) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    const auto size = lookup_pak_handle_size(handle).value_or(0);
    const auto position = lookup_pak_handle_position(handle).value_or(0);
    const auto filetime = virtual_filetime_now();

    auto fail = [&](NTSTATUS status) {
        io_status_block->Status = status;
        io_status_block->Information = 0;
        return status;
    };

    auto succeed = [&](ULONG bytes_written) {
        io_status_block->Status = 0;
        io_status_block->Information = bytes_written;
        return static_cast<NTSTATUS>(0);
    };

    constexpr FILE_INFORMATION_CLASS kNtFileStandardInformation = static_cast<FILE_INFORMATION_CLASS>(5);
    constexpr FILE_INFORMATION_CLASS kNtFilePositionInformation = static_cast<FILE_INFORMATION_CLASS>(14);
    constexpr FILE_INFORMATION_CLASS kNtFileNetworkOpenInformation = static_cast<FILE_INFORMATION_CLASS>(34);

    switch (file_information_class) {
    case kNtFileStandardInformation: {
        if (length < sizeof(VirtualNtFileStandardInformation)) {
            return fail(static_cast<NTSTATUS>(0xC0000004));
        }
        auto* info = static_cast<VirtualNtFileStandardInformation*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->AllocationSize.QuadPart = static_cast<LONGLONG>(size);
        info->EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        info->NumberOfLinks = 1;
        return succeed(sizeof(*info));
    }
    case kNtFilePositionInformation: {
        if (length < sizeof(VirtualNtFilePositionInformation)) {
            return fail(static_cast<NTSTATUS>(0xC0000004));
        }
        auto* info = static_cast<VirtualNtFilePositionInformation*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->CurrentByteOffset.QuadPart = static_cast<LONGLONG>(position);
        return succeed(sizeof(*info));
    }
    case kNtFileNetworkOpenInformation: {
        if (length < sizeof(VirtualNtFileNetworkOpenInformation)) {
            return fail(static_cast<NTSTATUS>(0xC0000004));
        }
        auto* info = static_cast<VirtualNtFileNetworkOpenInformation*>(file_information);
        std::memset(info, 0, sizeof(*info));
        info->CreationTime.QuadPart = filetime_to_large_integer(filetime);
        info->LastAccessTime = info->CreationTime;
        info->LastWriteTime = info->CreationTime;
        info->ChangeTime = info->CreationTime;
        info->AllocationSize.QuadPart = static_cast<LONGLONG>(size);
        info->EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        info->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
        return succeed(sizeof(*info));
    }
    default:
        return fail(static_cast<NTSTATUS>(0xC0000002));
    }
}

NTSTATUS patch_virtual_nt_query_information_file(
    HANDLE handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    FILE_INFORMATION_CLASS file_information_class) {
    if (io_status_block == nullptr || file_information == nullptr) {
        return static_cast<NTSTATUS>(0xC000000D);
    }

    const auto size = lookup_pak_handle_size(handle).value_or(0);
    const auto position = lookup_pak_handle_position(handle).value_or(0);

    constexpr FILE_INFORMATION_CLASS kNtFileStandardInformation = static_cast<FILE_INFORMATION_CLASS>(5);
    constexpr FILE_INFORMATION_CLASS kNtFilePositionInformation = static_cast<FILE_INFORMATION_CLASS>(14);
    constexpr FILE_INFORMATION_CLASS kNtFileNetworkOpenInformation = static_cast<FILE_INFORMATION_CLASS>(34);

    switch (file_information_class) {
    case kNtFileStandardInformation: {
        if (length < sizeof(VirtualNtFileStandardInformation)) {
            return static_cast<NTSTATUS>(0xC0000004);
        }
        auto* info = static_cast<VirtualNtFileStandardInformation*>(file_information);
        info->AllocationSize.QuadPart = static_cast<LONGLONG>(size);
        info->EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        io_status_block->Information = sizeof(*info);
        return static_cast<NTSTATUS>(0);
    }
    case kNtFilePositionInformation: {
        if (length < sizeof(VirtualNtFilePositionInformation)) {
            return static_cast<NTSTATUS>(0xC0000004);
        }
        auto* info = static_cast<VirtualNtFilePositionInformation*>(file_information);
        info->CurrentByteOffset.QuadPart = static_cast<LONGLONG>(position);
        io_status_block->Information = sizeof(*info);
        return static_cast<NTSTATUS>(0);
    }
    case kNtFileNetworkOpenInformation: {
        if (length < sizeof(VirtualNtFileNetworkOpenInformation)) {
            return static_cast<NTSTATUS>(0xC0000004);
        }
        auto* info = static_cast<VirtualNtFileNetworkOpenInformation*>(file_information);
        info->AllocationSize.QuadPart = static_cast<LONGLONG>(size);
        info->EndOfFile.QuadPart = static_cast<LONGLONG>(size);
        io_status_block->Information = sizeof(*info);
        return static_cast<NTSTATUS>(0);
    }
    default:
        return static_cast<NTSTATUS>(0);
    }
}

