#if defined(MHWILDS_VERSION_PROXY)
constexpr wchar_t kLogRelativePath[] = L"mhwilds_version_proxy.log";
constexpr wchar_t kTraceLogRelativePath[] = L"mhwilds_instruction_trace.log";
constexpr wchar_t kLoaderConfigRelativePath[] = L"mhwilds_virtual_pak_loader.ini";
#else
constexpr wchar_t kLogRelativePath[] = L"reframework\\plugins\\mhwilds_file_open_probe.log";
constexpr wchar_t kTraceLogRelativePath[] = L"reframework\\plugins\\mhwilds_instruction_trace.log";
constexpr wchar_t kLoaderConfigRelativePath[] = L"reframework\\plugins\\mhwilds_virtual_pak_loader.ini";
#endif
constexpr wchar_t kFocusPakPathFragment[] = L"\\pak_mods\\";
constexpr wchar_t kEncryptedModExtension[] = L".mhwsmod";
constexpr wchar_t kStagedRuntimePakExtension[] = L".cache";
constexpr wchar_t kStageIndexFileName[] = L"4b1e6d2f90c84ab6b25f8d13f6a77102.bin";
constexpr char kStageIndexPlainMagic[] = "MHWSSI1\n";
constexpr wchar_t kUpdateCacheDirName[] = L"MHWILDSVersionProxy";
constexpr wchar_t kUpdateCacheFileName[] = L"update_cache.dat";
constexpr uint32_t kDefaultUpdateTimeoutMs = 4000;
constexpr uint32_t kDefaultUpdateCacheTtlMinutes = 30;

#if !defined(MHWILDS_LOADER_VERSION)
#define MHWILDS_LOADER_VERSION "0.0.0"
#endif

constexpr char kLoaderBuildVersion[] = MHWILDS_LOADER_VERSION;

constexpr uintptr_t kOpenStreamRva = 0xBBC10;
constexpr std::array<uintptr_t, 2> kCreateFileCallsiteRvas{
    0xBBD6D,
    0xBBE74,
};
constexpr uintptr_t kDirectStorageCallsiteRva = 0x51EA36;
constexpr uintptr_t kDefaultTraceStartRva = 0xBBDD2;
constexpr uint32_t kDefaultTraceMaxInstructions = 200;
constexpr uint32_t kDefaultWatchTraceMaxInstructions = 512;
constexpr uint32_t kWatchTraceDetailedPrefixSteps = 32;
constexpr uint32_t kWatchTracePeriodicStepInterval = 32;
constexpr size_t kWatchTraceStackSnapshotEntries = 16;
constexpr size_t kTraceBytePreviewCount = 8;
constexpr uintptr_t kSecondStageTraceArmRva = 0x18DA1111;
constexpr uintptr_t kSecondStageTraceWatchFieldOffset = 0x58;
constexpr uintptr_t kSecondStageTraceWatchNextFieldOffset = 0x60;
constexpr uintptr_t kSecondStageTraceOwnerFieldOffset = 0x2A0;
constexpr size_t kSecondStageTraceWatchSize = sizeof(uint64_t);
constexpr size_t kHwBreakpointSlotCount = 4;
constexpr int kEntryBreakpointSlot = 0;
constexpr int kWatchBreakpointSlotNode58 = 0;
constexpr int kWatchBreakpointSlotNode60 = 1;
constexpr int kWatchBreakpointSlotOwner2A0 = 2;

using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using SetFilePointerExFn = BOOL(WINAPI*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
using GetFileSizeExFn = BOOL(WINAPI*)(HANDLE, PLARGE_INTEGER);
using GetFileTypeFn = DWORD(WINAPI*)(HANDLE);
using GetFileInformationByHandleFn = BOOL(WINAPI*)(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
using GetFileInformationByHandleExFn = BOOL(WINAPI*)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
using CreateFileMappingWFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
using MapViewOfFileFn = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
using CloseHandleFn = BOOL(WINAPI*)(HANDLE);
using NtQueryInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
using DirectStorageOpenFn = int64_t(__fastcall*)(void* rcx, const void* rdx, void* r8, void* r9);

enum class HwBreakpointType : uint8_t {
    Execute = 0,
    Write = 1,
    Io = 2,
    ReadWrite = 3,
};

enum class HwTraceCaptureKind : uint8_t {
    Entry = 0,
    Watch = 1,
};

struct HwBreakpointSlotConfig {
    bool enabled{};
    uintptr_t address{};
    HwBreakpointType type{HwBreakpointType::Execute};
    size_t size{1};
};

struct VirtualPakLoaderConfig {
    bool enabled{};
    bool observer_only{};
    bool backend_only{};
    bool record_only{};
    bool rf_chain_mode{};
    bool reframework_pak_dir_enabled{};
    bool plain_source{};
    bool passthrough{};
    bool stage_source{};
    bool keep_staged_file{};
    bool redirect{};
    bool trace_enabled{};
    std::wstring target_path{};
    std::wstring target_path_normalized{};
    std::wstring source_path{};
    std::wstring custom_pak_dir{};
    std::wstring stage_root{};
    int target_patch_num{-1};
    int base_patch_num{-1};
    int reframework_source_count{};
    int custom_source_count{};
    int encrypted_mod_source_count{};
    int encrypted_mod_staged_count{};
    int total_patch_num{-1};
    uintptr_t trace_start_rva{kDefaultTraceStartRva};
    uint32_t trace_max_instructions{kDefaultTraceMaxInstructions};
};

struct VirtualPakHandleState {
    std::wstring requested_path{};
    std::wstring source_path{};
    std::shared_ptr<std::vector<uint8_t>> payload{};
    uint64_t position{};
    bool synthetic_handle{true};
};

struct VirtualMappingHandleState {
    std::wstring path{};
    std::shared_ptr<std::vector<uint8_t>> payload{};
    bool synthetic_handle{true};
};

struct VirtualPakPayloadCache {
    std::wstring source_path{};
    std::filesystem::file_time_type write_time{};
    std::shared_ptr<std::vector<uint8_t>> payload{};
};

struct VirtualPakStageCache {
    std::wstring source_path{};
    std::filesystem::file_time_type write_time{};
    std::wstring staged_path{};
    std::wstring staged_dir{};
};

struct EncryptedModStageCache {
    std::wstring staged_dir{};
    std::vector<std::wstring> staged_paths{};
};

struct ModMetadataRecord {
    std::wstring source_path{};
    std::wstring display_name{};
    std::wstring mod_version{};
    std::wstring update_url{};
    std::wstring author{};
    bool metadata_present{};
    bool authenticated{};
};

struct UpdatePromptRequest {
    std::wstring title{};
    std::wstring main_instruction{};
    std::wstring message{};
    std::vector<std::wstring> urls{};
};

struct ModUpdateCheckResult {
    ModMetadataRecord metadata{};
    std::string remote_version{};
    std::string announcement{};
};

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
std::wstring g_shared_stage_session_dir{};
bool g_stage_startup_cleanup_done{};
std::optional<std::array<uint8_t, 32>> g_cached_game_key{};
std::wstring g_cached_game_key_source{};
std::optional<std::array<uint8_t, 16>> g_cached_game_fingerprint{};
std::wstring g_cached_game_fingerprint_source{};
std::deque<UpdatePromptRequest> g_pending_update_prompts{};
std::atomic<uint64_t> g_virtual_handle_counter{1};
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

struct RedirectPathBreakpointSite {
    uintptr_t addr{};
    uint8_t original_byte{};
    const char* label{};
};

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

void initialize_fixed_addresses();
bool looks_like_wide_string_at(const wchar_t* text);
std::wstring read_wide_string_safe(const wchar_t* text);
std::optional<std::wstring> extract_directstorage_path(const void* arg);
std::wstring normalize_path_for_match(const std::wstring& value);
void run_hw_trace_reapply_loop();
void ensure_hw_trace_refresh_thread_running(const char* source);
bool path_matches_virtual_target_locked(const std::wstring& normalized_path, const VirtualPakLoaderConfig& config);
std::optional<std::wstring> resolve_redirect_source_for_requested_path(std::wstring_view requested_path);
int count_effective_virtual_source_paths(const VirtualPakLoaderConfig& config);
bool load_reframework_pak_directory_enabled_from_disk();
std::vector<std::wstring> resolve_effective_rf_chain_pak_paths(const VirtualPakLoaderConfig& config);
std::vector<std::wstring> resolve_encrypted_custom_mod_paths();
std::vector<std::wstring> stage_encrypted_custom_mods_into_local_dir(const VirtualPakLoaderConfig& config);
std::vector<std::wstring> resolve_local_custom_pak_paths(const VirtualPakLoaderConfig& config);
std::optional<ModMetadataRecord> load_mod_metadata_record(const std::filesystem::path& source_path);
bool install_same_point_reframework_chain_hooks();
void uninstall_same_point_reframework_chain_hooks();
void schedule_update_check_worker();

struct CallerContext {
    uintptr_t return_address{};
    HMODULE module{};
    std::wstring module_path{L"<unknown>"};
    std::wstring module_name{};
    bool near_createfile_site{};
};

class ScopedInternalBackendOpen {
public:
    ScopedInternalBackendOpen() {
        ++t_internal_backend_open_depth;
    }

    ~ScopedInternalBackendOpen() {
        if (t_internal_backend_open_depth != 0) {
            --t_internal_backend_open_depth;
        }
    }

    ScopedInternalBackendOpen(const ScopedInternalBackendOpen&) = delete;
    ScopedInternalBackendOpen& operator=(const ScopedInternalBackendOpen&) = delete;
};

bool is_internal_backend_open_active() {
    return t_internal_backend_open_depth != 0;
}

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

