#include "plugin_internal.hpp"

namespace mhwilds::probe {

REFrameworkPluginFunctions g_ref{};

CreateFileWFn g_original_create_file_w{};
ReadFileFn g_original_read_file{};
SetFilePointerExFn g_original_set_file_pointer_ex{};
GetFileSizeExFn g_original_get_file_size_ex{};
GetFileTypeFn g_original_get_file_type{};
GetFileInformationByHandleFn g_original_get_file_information_by_handle{};
GetFileInformationByHandleExFn g_original_get_file_information_by_handle_ex{};
CreateFileMappingWFn g_original_create_file_mapping_w{};
MapViewOfFileFn g_original_map_view_of_file{};
CloseHandleFn g_original_close_handle{};
NtQueryInformationFileFn g_original_nt_query_information_file{};
DirectStorageOpenFn g_original_directstorage_open{};

std::mutex g_log_mutex{};
std::ofstream g_log{};
std::mutex g_trace_log_mutex{};
std::ofstream g_trace_log{};
std::mutex g_stage_session_mutex{};
std::mutex g_encrypted_mod_stage_mutex{};
std::mutex g_update_prompt_mutex{};
std::mutex g_startup_gate_mutex{};
std::atomic<uint64_t> g_sequence{0};
std::atomic<bool> g_retry_registered{false};
std::atomic<bool> g_create_file_hook_installed{false};
std::atomic<bool> g_directstorage_hook_installed{false};
std::atomic<bool> g_directstorage_retry_consumed{false};
std::atomic<bool> g_early_bootstrap_attempted{false};
std::atomic<bool> g_shutdown_requested{false};
std::atomic<bool> g_attach_thread_started{false};
std::atomic<bool> g_hw_trace_refresh_thread_started{false};
std::atomic<bool> g_update_check_thread_started{false};
std::atomic<bool> g_update_prompt_thread_running{false};
std::atomic<uint64_t> g_create_file_pak_hits{0};
std::atomic<uint64_t> g_read_file_hits{0};
std::atomic<uint64_t> g_set_file_pointer_hits{0};
std::atomic<uint64_t> g_get_file_size_hits{0};
std::atomic<uint64_t> g_get_file_type_hits{0};
std::atomic<uint64_t> g_get_file_info_hits{0};
std::atomic<uint64_t> g_get_file_info_ex_hits{0};
std::atomic<uint64_t> g_create_file_mapping_hits{0};
std::atomic<uint64_t> g_map_view_of_file_hits{0};
std::atomic<uint64_t> g_close_handle_hits{0};
std::atomic<uint64_t> g_nt_query_info_hits{0};
std::atomic<uint64_t> g_directstorage_hits{0};
std::atomic<uint64_t> g_redirect_createfile_breakpoint_hits{0};
std::atomic<bool> g_same_point_hooks_installed{false};
std::atomic<bool> g_encrypted_mod_stage_prepared{false};
std::atomic<int> g_startup_gate_status{static_cast<int>(StartupGateStatus::Pending)};
std::atomic<bool> g_startup_gate_wait_logged{false};

uintptr_t g_game_module_base{};
void* g_create_file_target{};
void* g_read_file_target{};
void* g_set_file_pointer_ex_target{};
void* g_get_file_size_ex_target{};
void* g_get_file_type_target{};
void* g_get_file_information_by_handle_target{};
void* g_get_file_information_by_handle_ex_target{};
void* g_create_file_mapping_w_target{};
void* g_map_view_of_file_target{};
void* g_close_handle_target{};
void* g_nt_query_information_file_target{};
void* g_directstorage_target{};
uintptr_t g_directstorage_global_ptr_addr{};

std::array<uintptr_t, kCreateFileCallsiteRvas.size()> g_create_file_callsite_addrs{};
std::mutex g_install_mutex{};
std::mutex g_handle_mutex{};
std::mutex g_virtual_loader_mutex{};
std::array<SafetyHookMid, kCreateFileCallsiteRvas.size()> g_same_point_createfile_hooks{};
SafetyHookMid g_same_point_directstorage_hook{};
SafetyHookMid g_same_point_patch_version_hook{};
std::unordered_map<uintptr_t, std::wstring> g_pak_handle_paths{};
std::unordered_map<uintptr_t, uint64_t> g_pak_handle_positions{};
std::unordered_map<uintptr_t, uint64_t> g_pak_handle_sizes{};
std::unordered_map<uintptr_t, std::wstring> g_mapping_handle_paths{};
std::unordered_map<uintptr_t, VirtualPakHandleState> g_virtual_pak_handles{};
std::unordered_map<uintptr_t, VirtualMappingHandleState> g_virtual_mapping_handles{};
VirtualPakLoaderConfig g_virtual_loader_config{};
VirtualPakPayloadCache g_virtual_payload_cache{};
VirtualPakStageCache g_virtual_stage_cache{};
EncryptedModStageCache g_encrypted_mod_stage_cache{};
StartupGateSnapshot g_startup_gate_snapshot{};
std::wstring g_shared_stage_session_dir{};
bool g_stage_startup_cleanup_done{};
std::optional<std::array<uint8_t, 32>> g_cached_game_key{};
std::wstring g_cached_game_key_source{};
std::optional<std::array<uint8_t, 16>> g_cached_game_fingerprint{};
std::wstring g_cached_game_fingerprint_source{};
std::deque<UpdatePromptRequest> g_pending_update_prompts{};
std::atomic<uint64_t> g_virtual_handle_counter{1};
uint64_t g_process_start_tick_ms{static_cast<uint64_t>(GetTickCount64())};
HANDLE g_startup_gate_ready_event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};

#if defined(MHWILDS_VERSION_PROXY)
HMODULE g_version_proxy_real_module{};
PVOID g_patch_version_veh_handle{};
uintptr_t g_patch_version_breakpoint_addr{};
uint8_t g_patch_version_original_byte{};
int g_patch_version_source_reg{-1};
std::atomic<int> g_patch_version_last_value{-1};
std::atomic<int> g_patch_version_breakpoint_pending_thread{0};
PVOID g_hw_trace_veh_handle{};
uintptr_t g_hw_trace_start_addr{};
uint32_t g_hw_trace_max_instructions{kDefaultTraceMaxInstructions};
std::atomic<bool> g_hw_trace_installed{false};
std::atomic<bool> g_hw_trace_started{false};
std::atomic<bool> g_hw_trace_finished{false};
std::atomic<DWORD> g_hw_trace_active_thread_id{0};
std::atomic<uint32_t> g_hw_trace_logged_steps{0};
std::atomic<int> g_hw_trace_breakpoint_type{static_cast<int>(HwBreakpointType::Execute)};
std::atomic<size_t> g_hw_trace_breakpoint_size{1};
std::array<std::atomic<uintptr_t>, kHwBreakpointSlotCount> g_hw_trace_slot_addrs{};
std::array<std::atomic<int>, kHwBreakpointSlotCount> g_hw_trace_slot_types{};
std::array<std::atomic<size_t>, kHwBreakpointSlotCount> g_hw_trace_slot_sizes{};
std::atomic<uint32_t> g_hw_trace_watch_mask{0};
std::atomic<uintptr_t> g_hw_trace_watch_addr{};
std::atomic<int> g_hw_trace_watch_hit_slot{-1};
std::atomic<DWORD> g_hw_trace_watch_origin_thread_id{0};
std::atomic<uint32_t> g_hw_trace_watch_origin_ignored_hits{0};
std::atomic<bool> g_hw_trace_watch_armed{false};
std::atomic<bool> g_hw_trace_watch_triggered{false};
#endif

std::array<RedirectPathBreakpointSite, kCreateFileCallsiteRvas.size()> g_redirect_createfile_sites{};
RedirectPathBreakpointSite g_redirect_directstorage_site{};
PVOID g_redirect_path_veh_handle{};
thread_local uintptr_t t_redirect_pending_breakpoint_addr{};
thread_local uint8_t t_redirect_pending_breakpoint_original_byte{};
thread_local std::wstring t_redirect_source_path_storage{};
thread_local std::array<uint8_t, 0x40> t_redirect_directstorage_arg_shadow{};
thread_local uint32_t t_internal_backend_open_depth{};

#if defined(MHWILDS_VERSION_PROXY)
thread_local bool t_hw_trace_single_step_active{};
thread_local uint32_t t_hw_trace_single_step_index{};
thread_local HwTraceCaptureKind t_hw_trace_capture_kind{HwTraceCaptureKind::Entry};
thread_local uintptr_t t_hw_trace_last_logged_rip{};
#endif

std::wstring widen_module_path(HMODULE module) {
    std::wstring buffer(MAX_PATH, L'\0');

    while (true) {
        const auto len = GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            return L"<unknown>";
        }

        if (len < buffer.size() - 1) {
            buffer.resize(len);
            return buffer;
        }

        buffer.resize(buffer.size() * 2);
    }
}

std::string narrow_utf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const auto needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return "<utf8-conversion-failed>";
    }

    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::optional<std::wstring> widen_utf8(const std::string& value) {
    if (value.empty()) {
        return std::wstring{};
    }

    const auto needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0) {
        return std::nullopt;
    }

    std::wstring out(static_cast<size_t>(needed), L'\0');
    const auto written = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed);
    if (written != needed) {
        return std::nullopt;
    }

    return out;
}

std::filesystem::path log_path() {
    return std::filesystem::current_path() / kLogRelativePath;
}

std::filesystem::path trace_log_path() {
    return std::filesystem::current_path() / kTraceLogRelativePath;
}

std::filesystem::path loader_config_path() {
    return std::filesystem::current_path() / kLoaderConfigRelativePath;
}

uint64_t process_uptime_ms() {
    return static_cast<uint64_t>(GetTickCount64()) - g_process_start_tick_ms;
}

void open_log_if_needed() {
    std::scoped_lock _{g_log_mutex};

    if (g_log.is_open()) {
        return;
    }

    const auto path = log_path();
    std::filesystem::create_directories(path.parent_path());
    ScopedInternalBackendOpen internal_open_guard{};
    g_log.open(path, std::ios::out | std::ios::trunc);

    if (!g_log.is_open()) {
        return;
    }

    g_log << "\n==== MHWILDS Pak Route Probe Started ====\n";
    g_log.flush();
}

void open_trace_log_if_needed() {
    std::scoped_lock _{g_trace_log_mutex};

    if (g_trace_log.is_open()) {
        return;
    }

    const auto path = trace_log_path();
    std::filesystem::create_directories(path.parent_path());
    ScopedInternalBackendOpen internal_open_guard{};
    g_trace_log.open(path, std::ios::out | std::ios::trunc);

    if (!g_trace_log.is_open()) {
        return;
    }

    g_trace_log << "\n==== MHWILDS Instruction Trace Started ====\n";
    g_trace_log.flush();
}

void append_log_line(const std::string& line) {
    std::scoped_lock _{g_log_mutex};
    if (!g_log.is_open()) {
        return;
    }

    g_log << line;
    g_log.flush();
}

void append_trace_log_line(const std::string& line) {
    std::scoped_lock _{g_trace_log_mutex};
    if (!g_trace_log.is_open()) {
        return;
    }

    g_trace_log << line;
    g_trace_log.flush();
}

void append_timing_log_line(const char* event_name, std::string_view details) {
    std::ostringstream oss;
    oss << "[timing] t_ms=" << process_uptime_ms()
        << " event=" << (event_name != nullptr ? event_name : "<null>");
    if (!details.empty()) {
        oss << ' ' << details;
    }
    oss << '\n';
    append_log_line(oss.str());
}

} // namespace mhwilds::probe
