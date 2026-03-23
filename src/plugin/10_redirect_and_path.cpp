#include "plugin_internal.hpp"

namespace mhwilds::probe {

bool read_memory_block_safe(const void* src, void* dst, size_t size) {
    __try {
        std::memcpy(dst, src, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool read_u64_safe(const void* src, uint64_t* value) {
    return read_memory_block_safe(src, value, sizeof(uint64_t));
}

std::string dump_bytes(const void* address, size_t count) {
    std::vector<uint8_t> bytes(count, 0);
    if (!read_memory_block_safe(address, bytes.data(), count)) {
        return "<byte-read-failed>";
    }

    std::ostringstream oss;
    for (size_t i = 0; i < count; ++i) {
        if (i != 0) {
            oss << ' ';
        }

        oss << std::hex << static_cast<unsigned>(bytes[i] >> 4);
        oss << std::hex << static_cast<unsigned>(bytes[i] & 0x0F);
    }

    return oss.str();
}

#if defined(MHWILDS_VERSION_PROXY)
struct PatternByte {
    bool wildcard{};
    uint8_t value{};
};

std::optional<std::vector<PatternByte>> parse_ida_pattern(std::string_view pattern) {
    std::vector<PatternByte> parsed{};
    size_t index = 0;

    while (index < pattern.size()) {
        const auto ch = pattern[index];
        if (std::isspace(static_cast<unsigned char>(ch))) {
            ++index;
            continue;
        }

        if (ch == '?') {
            parsed.push_back(PatternByte{true, 0});
            ++index;
            if (index < pattern.size() && pattern[index] == '?') {
                ++index;
            }
            continue;
        }

        if (index + 1 >= pattern.size()) {
            return std::nullopt;
        }

        const auto hex_digit = [](char value) -> int {
            if (value >= '0' && value <= '9') {
                return value - '0';
            }
            if (value >= 'a' && value <= 'f') {
                return value - 'a' + 10;
            }
            if (value >= 'A' && value <= 'F') {
                return value - 'A' + 10;
            }
            return -1;
        };

        const auto hi = hex_digit(pattern[index]);
        const auto lo = hex_digit(pattern[index + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }

        parsed.push_back(PatternByte{false, static_cast<uint8_t>((hi << 4) | lo)});
        index += 2;
    }

    return parsed;
}

size_t main_module_size() {
    if (g_game_module_base == 0) {
        return 0;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_game_module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_game_module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return nt->OptionalHeader.SizeOfImage;
}

std::optional<uintptr_t> scan_main_module_pattern(std::string_view pattern) {
    const auto parsed = parse_ida_pattern(pattern);
    if (!parsed.has_value() || parsed->empty()) {
        return std::nullopt;
    }

    const auto image_size = main_module_size();
    if (g_game_module_base == 0 || image_size < parsed->size()) {
        return std::nullopt;
    }

    const auto* image = reinterpret_cast<const uint8_t*>(g_game_module_base);
    const auto last_start = image_size - parsed->size();

    for (size_t offset = 0; offset <= last_start; ++offset) {
        bool matched = true;
        for (size_t i = 0; i < parsed->size(); ++i) {
            if (!(*parsed)[i].wildcard && image[offset + i] != (*parsed)[i].value) {
                matched = false;
                break;
            }
        }

        if (matched) {
            return g_game_module_base + offset;
        }
    }

    return std::nullopt;
}
#endif

std::optional<int> extract_patch_num_from_target_path(std::wstring_view path) {
    const auto patch_pos = path.rfind(L".patch_");
    if (patch_pos == std::wstring_view::npos) {
        return std::nullopt;
    }

    const auto digits_begin = patch_pos + 7;
    const auto pak_pos = path.find(L".pak", digits_begin);
    if (pak_pos == std::wstring_view::npos || pak_pos <= digits_begin) {
        return std::nullopt;
    }

    int value = 0;
    for (size_t i = digits_begin; i < pak_pos; ++i) {
        const auto ch = path[i];
        if (ch < L'0' || ch > L'9') {
            return std::nullopt;
        }
        value = (value * 10) + static_cast<int>(ch - L'0');
    }

    return value;
}

bool path_ends_with_pak(std::wstring_view path) {
    return path.size() >= 4 && path.substr(path.size() - 4) == L".pak";
}

bool looks_like_reframework_custom_slot_path(std::wstring_view normalized_path) {
    return normalized_path.find(L"re_chunk_000.pak.sub_000.pak.patch_") != std::wstring_view::npos;
}

bool looks_like_native_chunk_patch_name(std::wstring_view file_name) {
    if (!path_ends_with_pak(file_name)) {
        return false;
    }

    return file_name.rfind(L"re_chunk_", 0) == 0 && extract_patch_num_from_target_path(file_name).has_value();
}

int scan_highest_native_patch_num() {
    const auto exe_path = widen_module_path(GetModuleHandleW(nullptr));
    if (exe_path.empty() || exe_path == L"<unknown>") {
        return -1;
    }

    const auto exe_dir = std::filesystem::path(exe_path).parent_path();
    std::error_code ec{};
    std::filesystem::directory_iterator it(exe_dir, ec);
    if (ec) {
        return -1;
    }

    auto highest_patch_num = -1;
    for (const auto& entry : it) {
        if (!entry.is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        auto file_name = entry.path().filename().wstring();
        std::transform(file_name.begin(), file_name.end(), file_name.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        if (!looks_like_native_chunk_patch_name(file_name)) {
            continue;
        }

        const auto patch_num = extract_patch_num_from_target_path(file_name);
        if (patch_num.has_value()) {
            highest_patch_num = std::max(highest_patch_num, *patch_num);
        }
    }

    return highest_patch_num < 0 ? 0 : highest_patch_num;
}

#if defined(MHWILDS_VERSION_PROXY)
uint64_t* select_patch_version_register(CONTEXT* context, int reg_index) {
    if (context == nullptr) {
        return nullptr;
    }

    switch (reg_index) {
    case 0: return &context->Rax;
    case 1: return &context->Rcx;
    case 2: return &context->Rdx;
    case 3: return &context->Rbx;
    case 4: return &context->Rsp;
    case 5: return &context->Rbp;
    case 6: return &context->Rsi;
    case 7: return &context->Rdi;
    default: return nullptr;
    }
}

uint64_t* select_patch_version_register(SafetyHookContext* context, int reg_index) {
    if (context == nullptr) {
        return nullptr;
    }

    switch (reg_index) {
    case 0: return &context->rax;
    case 1: return &context->rcx;
    case 2: return &context->rdx;
    case 3: return &context->rbx;
    case 4: return &context->rsp;
    case 5: return &context->rbp;
    case 6: return &context->rsi;
    case 7: return &context->rdi;
    default: return nullptr;
    }
}
#endif

int compute_desired_patch_version() {
    std::scoped_lock _{g_virtual_loader_mutex};
    if (!g_virtual_loader_config.enabled || count_effective_virtual_source_paths(g_virtual_loader_config) <= 0) {
        return -1;
    }

    if (g_virtual_loader_config.base_patch_num < 0 || g_virtual_loader_config.total_patch_num <= g_virtual_loader_config.base_patch_num) {
        return -1;
    }

    return g_virtual_loader_config.total_patch_num;
}

const char* virtual_loader_mode_to_string(const VirtualPakLoaderConfig& config) {
    if (config.observer_only) {
        return "observer";
    }
    if (config.record_only) {
        return "record_only";
    }
    if (config.rf_chain_mode) {
        return "rf_chain";
    }
    if (config.stage_source && config.plain_source) {
        return "staged_plaintext";
    }
    if (config.stage_source) {
        return "staged_encrypted";
    }
    if (config.backend_only && config.plain_source) {
        return "backend_plaintext";
    }
    if (config.backend_only && config.passthrough) {
        return "backend_passthrough";
    }
    if (config.backend_only) {
        return "backend";
    }
    if (config.passthrough) {
        return "passthrough";
    }

    return "virtual";
}

bool write_breakpoint_byte(uintptr_t address, uint8_t value) {
    if (address == 0) {
        return false;
    }

    DWORD old_protect{};
    if (!VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    *reinterpret_cast<uint8_t*>(address) = value;
    VirtualProtect(reinterpret_cast<void*>(address), 1, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
    return true;
}

std::optional<std::wstring> resolve_redirect_source_for_requested_path(std::wstring_view requested_path) {
    const auto normalized = normalize_path_for_match(std::wstring{requested_path});

    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock _{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
        if (!config.enabled) {
            return std::nullopt;
        }
    }

    if (!path_matches_virtual_target_locked(normalized, config)) {
        return std::nullopt;
    }

    if (!config.rf_chain_mode) {
        return config.source_path;
    }

    const auto patch_num = extract_patch_num_from_target_path(normalized);
    if (!patch_num.has_value()) {
        return std::nullopt;
    }

    const auto first_custom_patch = config.base_patch_num + 1;
    if (*patch_num < first_custom_patch) {
        return std::nullopt;
    }

    const auto local_custom_paths = resolve_effective_rf_chain_pak_paths(config);
    const auto custom_index = *patch_num - first_custom_patch;
    if (custom_index < 0 || static_cast<size_t>(custom_index) >= local_custom_paths.size()) {
        return std::nullopt;
    }

    return local_custom_paths[static_cast<size_t>(custom_index)];
}

bool handle_redirect_createfile_breakpoint(EXCEPTION_POINTERS* exception_info, uintptr_t address) {
    if (exception_info == nullptr || exception_info->ContextRecord == nullptr) {
        return false;
    }

    bool matched_site = false;
    for (const auto& site : g_redirect_createfile_sites) {
        if (site.addr == address && site.addr != 0) {
            matched_site = true;
            break;
        }
    }

    if (!matched_site) {
        return false;
    }

    const auto* path_ptr = reinterpret_cast<const wchar_t*>(exception_info->ContextRecord->Rcx);
    if (!looks_like_wide_string_at(path_ptr)) {
        return false;
    }

    const auto requested_path = read_wide_string_safe(path_ptr);
    const auto raw_hit = g_redirect_createfile_breakpoint_hits.fetch_add(1) + 1;
    if (raw_hit <= 6) {
        std::ostringstream oss;
        oss << "redirect-breakpoint-observed"
            << " kind=createfile"
            << " hit=" << std::dec << raw_hit
            << " addr=0x" << std::hex << address
            << " requested=" << narrow_utf8(requested_path)
            << "\n";
        append_log_line(oss.str());
    }

    const auto redirected_path = resolve_redirect_source_for_requested_path(requested_path);
    if (!redirected_path.has_value()) {
        return false;
    }

    t_redirect_source_path_storage = *redirected_path;
    exception_info->ContextRecord->Rcx = reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());

    std::ostringstream oss;
    oss << "redirect-breakpoint-hit"
        << " kind=createfile"
        << " addr=0x" << std::hex << address
        << " requested=" << narrow_utf8(requested_path)
        << " rewritten=" << narrow_utf8(t_redirect_source_path_storage)
        << "\n";
    append_log_line(oss.str());
    return true;
}

bool handle_redirect_directstorage_breakpoint(EXCEPTION_POINTERS* exception_info, uintptr_t address) {
    if (exception_info == nullptr || exception_info->ContextRecord == nullptr) {
        return false;
    }

    if (g_redirect_directstorage_site.addr == 0 || g_redirect_directstorage_site.addr != address) {
        return false;
    }

    const auto arg = reinterpret_cast<const void*>(exception_info->ContextRecord->Rdx);
    const auto requested_path = extract_directstorage_path(arg);
    if (!requested_path.has_value()) {
        return false;
    }

    const auto redirected_path = resolve_redirect_source_for_requested_path(*requested_path);
    if (!redirected_path.has_value()) {
        return false;
    }

    t_redirect_source_path_storage = *redirected_path;

    bool rewritten = false;
    const auto* direct_text = reinterpret_cast<const wchar_t*>(arg);
    if (looks_like_wide_string_at(direct_text)) {
        exception_info->ContextRecord->Rdx = reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());
        rewritten = true;
    } else if (arg != nullptr) {
        if (!read_memory_block_safe(arg, t_redirect_directstorage_arg_shadow.data(), t_redirect_directstorage_arg_shadow.size())) {
            append_log_line("redirect-directstorage-shadow-copy-failed\n");
            return false;
        }
        *reinterpret_cast<uint64_t*>(t_redirect_directstorage_arg_shadow.data()) =
            reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());
        exception_info->ContextRecord->Rdx = reinterpret_cast<uint64_t>(t_redirect_directstorage_arg_shadow.data());
        rewritten = true;
    }

    if (!rewritten) {
        return false;
    }

    std::ostringstream oss;
    oss << "redirect-breakpoint-hit"
        << " kind=directstorage"
        << " addr=0x" << std::hex << address
        << " requested=" << narrow_utf8(*requested_path)
        << " rewritten=" << narrow_utf8(t_redirect_source_path_storage)
        << "\n";
    append_log_line(oss.str());
    return true;
}

std::optional<uint8_t> find_redirect_breakpoint_original_byte(uintptr_t address) {
    for (const auto& site : g_redirect_createfile_sites) {
        if (site.addr == address && site.addr != 0) {
            return site.original_byte;
        }
    }

    if (g_redirect_directstorage_site.addr == address && g_redirect_directstorage_site.addr != 0) {
        return g_redirect_directstorage_site.original_byte;
    }

    return std::nullopt;
}

LONG CALLBACK redirect_path_veh_handler(EXCEPTION_POINTERS* exception_info) {
    if (exception_info == nullptr || exception_info->ExceptionRecord == nullptr || exception_info->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto code = exception_info->ExceptionRecord->ExceptionCode;
    const auto address = reinterpret_cast<uintptr_t>(exception_info->ExceptionRecord->ExceptionAddress);

    if (code == EXCEPTION_BREAKPOINT) {
        const auto original_byte = find_redirect_breakpoint_original_byte(address);
        if (!original_byte.has_value()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        handle_redirect_createfile_breakpoint(exception_info, address);
        handle_redirect_directstorage_breakpoint(exception_info, address);

        if (!write_breakpoint_byte(address, *original_byte)) {
            append_log_line("redirect-breakpoint-restore-failed\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }

        exception_info->ContextRecord->Rip = address;
        exception_info->ContextRecord->EFlags |= 0x100;
        t_redirect_pending_breakpoint_addr = address;
        t_redirect_pending_breakpoint_original_byte = *original_byte;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP && t_redirect_pending_breakpoint_addr != 0) {
        const auto rearm_addr = t_redirect_pending_breakpoint_addr;
        t_redirect_pending_breakpoint_addr = 0;
        t_redirect_pending_breakpoint_original_byte = 0;

        if (!write_breakpoint_byte(rearm_addr, 0xCC)) {
            append_log_line("redirect-breakpoint-rearm-failed\n");
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#if defined(MHWILDS_VERSION_PROXY)
LONG CALLBACK patch_version_veh_handler(EXCEPTION_POINTERS* exception_info) {
    if (exception_info == nullptr || exception_info->ExceptionRecord == nullptr || exception_info->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto code = exception_info->ExceptionRecord->ExceptionCode;
    const auto address = reinterpret_cast<uintptr_t>(exception_info->ExceptionRecord->ExceptionAddress);

    if (code == EXCEPTION_BREAKPOINT && address == g_patch_version_breakpoint_addr) {
        auto* reg = select_patch_version_register(exception_info->ContextRecord, g_patch_version_source_reg);
        const auto desired_patch = compute_desired_patch_version();
        if (reg != nullptr && desired_patch >= 0 && *reg < static_cast<uint64_t>(desired_patch)) {
            *reg = static_cast<uint64_t>(desired_patch);
            g_patch_version_last_value = desired_patch;
        }

        DWORD old_protect{};
        if (VirtualProtect(reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
            *reinterpret_cast<uint8_t*>(g_patch_version_breakpoint_addr) = g_patch_version_original_byte;
            VirtualProtect(reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1);
        }

        exception_info->ContextRecord->Rip = g_patch_version_breakpoint_addr;
        exception_info->ContextRecord->EFlags |= 0x100;
        g_patch_version_breakpoint_pending_thread = static_cast<int>(GetCurrentThreadId());
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP &&
        g_patch_version_breakpoint_pending_thread.load() == static_cast<int>(GetCurrentThreadId()) &&
        g_patch_version_breakpoint_addr != 0) {
        DWORD old_protect{};
        if (VirtualProtect(reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
            *reinterpret_cast<uint8_t*>(g_patch_version_breakpoint_addr) = 0xCC;
            VirtualProtect(reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1);
        }

        g_patch_version_breakpoint_pending_thread = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool install_patch_version_breakpoint() {
    if (g_patch_version_breakpoint_addr != 0) {
        return true;
    }

    initialize_fixed_addresses();
    const auto patch_version_start = scan_main_module_pattern(
        "48 89 ? 24 ? 48 85 FF 0F 84 ? ? ? ? 66 83 3F 72 0F 85 ? ? ? ? 66 BA 72 00");
    if (!patch_version_start.has_value()) {
        append_log_line("patch-version-pattern-miss\n");
        return false;
    }

    uint8_t modrm{};
    if (!read_memory_block_safe(reinterpret_cast<const void*>(*patch_version_start + 2), &modrm, sizeof(modrm))) {
        append_log_line("patch-version-modrm-read-failed\n");
        return false;
    }

    const auto source_reg = static_cast<int>((modrm >> 3) & 0x7);
    uint8_t original_byte{};
    if (!read_memory_block_safe(reinterpret_cast<const void*>(*patch_version_start), &original_byte, sizeof(original_byte))) {
        append_log_line("patch-version-byte-read-failed\n");
        return false;
    }

    if (g_patch_version_veh_handle == nullptr) {
        g_patch_version_veh_handle = AddVectoredExceptionHandler(1, &patch_version_veh_handler);
        if (g_patch_version_veh_handle == nullptr) {
            append_log_line("patch-version-veh-install-failed\n");
            return false;
        }
    }

    DWORD old_protect{};
    if (!VirtualProtect(reinterpret_cast<void*>(*patch_version_start), 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
        append_log_line("patch-version-protect-failed\n");
        return false;
    }

    *reinterpret_cast<uint8_t*>(*patch_version_start) = 0xCC;
    VirtualProtect(reinterpret_cast<void*>(*patch_version_start), 1, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(*patch_version_start), 1);

    g_patch_version_breakpoint_addr = *patch_version_start;
    g_patch_version_original_byte = original_byte;
    g_patch_version_source_reg = source_reg;

    std::ostringstream oss;
    oss << "patch-version-breakpoint-installed"
        << " addr=0x" << std::hex << g_patch_version_breakpoint_addr
        << " source_reg=" << std::dec << g_patch_version_source_reg
        << " target_patch=" << compute_desired_patch_version()
        << "\n";
    append_log_line(oss.str());
    return true;
}

void uninstall_patch_version_breakpoint() {
    if (g_patch_version_breakpoint_addr != 0) {
        DWORD old_protect{};
        if (VirtualProtect(reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
            *reinterpret_cast<uint8_t*>(g_patch_version_breakpoint_addr) = g_patch_version_original_byte;
            VirtualProtect(reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(g_patch_version_breakpoint_addr), 1);
        }
    }

    if (g_patch_version_veh_handle != nullptr) {
        RemoveVectoredExceptionHandler(g_patch_version_veh_handle);
        g_patch_version_veh_handle = nullptr;
    }

    g_patch_version_breakpoint_addr = 0;
    g_patch_version_original_byte = 0;
    g_patch_version_source_reg = -1;
    g_patch_version_breakpoint_pending_thread = 0;
}

void same_point_patch_version_hook(SafetyHookContext& context) {
    auto* reg = select_patch_version_register(&context, g_patch_version_source_reg);
    const auto desired_patch = compute_desired_patch_version();
    if (reg != nullptr && desired_patch >= 0 && *reg < static_cast<uint64_t>(desired_patch)) {
        *reg = static_cast<uint64_t>(desired_patch);
        g_patch_version_last_value = desired_patch;

        std::ostringstream oss;
        oss << "same-point-patch-version"
            << " desired=" << desired_patch
            << " source_reg=" << g_patch_version_source_reg
            << "\n";
        append_log_line(oss.str());
    }
}

void same_point_createfile_hook(SafetyHookContext& context) {
    const auto* requested_path = reinterpret_cast<const wchar_t*>(context.rcx);
    if (!looks_like_wide_string_at(requested_path)) {
        return;
    }

    const auto redirected_path = resolve_redirect_source_for_requested_path(requested_path);
    if (!redirected_path.has_value()) {
        return;
    }

    t_redirect_source_path_storage = *redirected_path;
    context.rcx = reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());

    std::ostringstream oss;
    oss << "same-point-createfile-redirect"
        << " requested=" << narrow_utf8(requested_path)
        << " rewritten=" << narrow_utf8(t_redirect_source_path_storage)
        << "\n";
    append_log_line(oss.str());
}

void same_point_directstorage_hook(SafetyHookContext& context) {
    const auto* arg = reinterpret_cast<const void*>(context.rdx);
    const auto extracted_path = extract_directstorage_path(arg);
    if (!extracted_path.has_value()) {
        return;
    }

    const auto redirected_path = resolve_redirect_source_for_requested_path(*extracted_path);
    if (!redirected_path.has_value()) {
        return;
    }

    t_redirect_source_path_storage = *redirected_path;

    const auto* direct_text = reinterpret_cast<const wchar_t*>(arg);
    if (looks_like_wide_string_at(direct_text)) {
        context.rdx = reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());
    } else if (arg != nullptr &&
               read_memory_block_safe(arg, t_redirect_directstorage_arg_shadow.data(), t_redirect_directstorage_arg_shadow.size())) {
        *reinterpret_cast<uint64_t*>(t_redirect_directstorage_arg_shadow.data()) =
            reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());
        context.rdx = reinterpret_cast<uint64_t>(t_redirect_directstorage_arg_shadow.data());
    } else {
        return;
    }

    std::ostringstream oss;
    oss << "same-point-directstorage-redirect"
        << " requested=" << narrow_utf8(*extracted_path)
        << " rewritten=" << narrow_utf8(t_redirect_source_path_storage)
        << "\n";
    append_log_line(oss.str());
}

bool install_same_point_reframework_chain_hooks() {
    if (g_same_point_hooks_installed.load()) {
        return true;
    }

    initialize_fixed_addresses();
    if (g_game_module_base == 0) {
        append_log_line("same-point-hooks-game-base-missing\n");
        return false;
    }

    const auto patch_version_start = scan_main_module_pattern(
        "48 89 ? 24 ? 48 85 FF 0F 84 ? ? ? ? 66 83 3F 72 0F 85 ? ? ? ? 66 BA 72 00");
    if (!patch_version_start.has_value()) {
        append_log_line("same-point-patch-version-pattern-miss\n");
        return false;
    }

    uint8_t modrm{};
    if (!read_memory_block_safe(reinterpret_cast<const void*>(*patch_version_start + 2), &modrm, sizeof(modrm))) {
        append_log_line("same-point-patch-version-modrm-read-failed\n");
        return false;
    }

    g_patch_version_source_reg = static_cast<int>((modrm >> 3) & 0x7);
    g_same_point_patch_version_hook = safetyhook::create_mid(reinterpret_cast<void*>(*patch_version_start), &same_point_patch_version_hook);
    if (!g_same_point_patch_version_hook) {
        append_log_line("same-point-patch-version-hook-failed\n");
        return false;
    }

    for (size_t i = 0; i < g_create_file_callsite_addrs.size(); ++i) {
        g_same_point_createfile_hooks[i] =
            safetyhook::create_mid(reinterpret_cast<void*>(g_create_file_callsite_addrs[i]), &same_point_createfile_hook);
        if (!g_same_point_createfile_hooks[i]) {
            std::ostringstream oss;
            oss << "same-point-createfile-hook-failed"
                << " index=" << i
                << " addr=0x" << std::hex << g_create_file_callsite_addrs[i]
                << "\n";
            append_log_line(oss.str());
            return false;
        }
    }

    const auto directstorage_callsite = g_game_module_base + kDirectStorageCallsiteRva;
    g_same_point_directstorage_hook =
        safetyhook::create_mid(reinterpret_cast<void*>(directstorage_callsite), &same_point_directstorage_hook);
    if (!g_same_point_directstorage_hook) {
        std::ostringstream oss;
        oss << "same-point-directstorage-hook-failed"
            << " addr=0x" << std::hex << directstorage_callsite
            << "\n";
        append_log_line(oss.str());
        return false;
    }

    g_same_point_hooks_installed = true;

    std::ostringstream oss;
    oss << "same-point-hooks-installed"
        << " patch=0x" << std::hex << *patch_version_start
        << " createfile0=0x" << g_create_file_callsite_addrs[0]
        << " createfile1=0x" << g_create_file_callsite_addrs[1]
        << " directstorage=0x" << directstorage_callsite
        << std::dec
        << " source_reg=" << g_patch_version_source_reg
        << "\n";
    append_log_line(oss.str());
    return true;
}

void uninstall_same_point_reframework_chain_hooks() {
    for (auto& hook : g_same_point_createfile_hooks) {
        hook = {};
    }

    g_same_point_directstorage_hook = {};
    g_same_point_patch_version_hook = {};
    g_same_point_hooks_installed = false;
}
#endif

std::optional<uintptr_t> resolve_rel32_target(uintptr_t instruction, size_t displacement_offset, size_t instruction_size) {
    int32_t displacement{};
    if (!read_memory_block_safe(reinterpret_cast<const void*>(instruction + displacement_offset), &displacement, sizeof(displacement))) {
        return std::nullopt;
    }

    return instruction + instruction_size + displacement;
}

bool looks_like_wide_string_at(const wchar_t* text) {
    if (text == nullptr) {
        return false;
    }

    wchar_t buffer[260]{};
    if (!read_memory_block_safe(text, buffer, sizeof(buffer) - sizeof(wchar_t))) {
        return false;
    }

    bool saw_non_null = false;

    for (size_t i = 0; i < std::size(buffer); ++i) {
        const auto ch = buffer[i];
        if (ch == L'\0') {
            return saw_non_null;
        }

        saw_non_null = true;
        if (ch < 0x20 || ch > 0x7E) {
            if (ch != L'\\' && ch != L'/' && ch != L':' && ch != L'_' && ch != L'.' && ch != L'-' && ch != L' ') {
                return false;
            }
        }
    }

    return false;
}

std::wstring read_wide_string_safe(const wchar_t* text) {
    std::wstring out{};
    out.reserve(260);

    for (size_t i = 0; i < 260; ++i) {
        wchar_t ch{};
        if (!read_memory_block_safe(text + i, &ch, sizeof(ch))) {
            break;
        }

        if (ch == L'\0') {
            break;
        }

        out.push_back(ch);
    }

    return out;
}

std::string describe_directstorage_arg(const void* arg) {
    if (arg == nullptr) {
        return "<null>";
    }

    const auto* direct_text = reinterpret_cast<const wchar_t*>(arg);
    if (looks_like_wide_string_at(direct_text)) {
        return "direct=" + narrow_utf8(read_wide_string_safe(direct_text));
    }

    uint64_t nested_ptr{};
    if (read_u64_safe(arg, &nested_ptr) && nested_ptr != 0) {
        const auto* nested_text = reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(nested_ptr));
        if (looks_like_wide_string_at(nested_text)) {
            return "nested=" + narrow_utf8(read_wide_string_safe(nested_text));
        }
    }

    return "raw=" + dump_bytes(arg, 0x20);
}

std::optional<std::wstring> extract_directstorage_path(const void* arg) {
    if (arg == nullptr) {
        return std::nullopt;
    }

    const auto* direct_text = reinterpret_cast<const wchar_t*>(arg);
    if (looks_like_wide_string_at(direct_text)) {
        return read_wide_string_safe(direct_text);
    }

    uint64_t nested_ptr{};
    if (read_u64_safe(arg, &nested_ptr) && nested_ptr != 0) {
        const auto* nested_text = reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(nested_ptr));
        if (looks_like_wide_string_at(nested_text)) {
            return read_wide_string_safe(nested_text);
        }
    }

    return std::nullopt;
}

std::wstring to_lower_copy(const std::wstring& value) {
    std::wstring lowered = value;
    for (auto& ch : lowered) {
        ch = static_cast<wchar_t>(towlower(ch));
    }

    return lowered;
}

std::wstring normalize_path_for_match(const std::wstring& value) {
    auto lowered = to_lower_copy(value);
    for (auto& ch : lowered) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }

    return lowered;
}

std::string trim_ascii_copy(const std::string& value) {
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }

    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }

    return value.substr(first, last - first);
}

std::wstring trim_ascii_copy(const std::wstring& value) {
    size_t first = 0;
    while (first < value.size() && std::iswspace(value[first]) != 0) {
        ++first;
    }

    size_t last = value.size();
    while (last > first && std::iswspace(value[last - 1]) != 0) {
        --last;
    }

    return value.substr(first, last - first);
}

bool parse_bool_value(const std::string& value) {
    const auto lowered = trim_ascii_copy(value);
    return lowered == "1" || _stricmp(lowered.c_str(), "true") == 0 || _stricmp(lowered.c_str(), "yes") == 0;
}

std::optional<uint64_t> parse_u64_value(const std::string& value) {
    const auto trimmed = trim_ascii_copy(value);
    if (trimmed.empty()) {
        return std::nullopt;
    }

    char* end = nullptr;
    const auto parsed = std::strtoull(trimmed.c_str(), &end, 0);
    if (end == trimmed.c_str()) {
        return std::nullopt;
    }

    while (*end != '\0' && std::isspace(static_cast<unsigned char>(*end)) != 0) {
        ++end;
    }

    if (*end != '\0') {
        return std::nullopt;
    }

    return parsed;
}

} // namespace mhwilds::probe


