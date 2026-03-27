#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <intrin.h>
#include <shellapi.h>
#include <winhttp.h>
#include <winternl.h>

#include <MinHook.h>
#include <safetyhook.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cwctype>
#include <deque>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <json.hpp>

#include "encrypted_pak_format.hpp"
#include "reframework_plugin_minimal.hpp"

#if !defined(MHWILDS_LOADER_VERSION)
#define MHWILDS_LOADER_VERSION "0.0.0"
#endif

namespace mhwilds::probe {

inline constexpr wchar_t kLogRelativePath[] = L"mhwilds_version_proxy.log";
inline constexpr wchar_t kTraceLogRelativePath[] = L"mhwilds_instruction_trace.log";
inline constexpr wchar_t kLoaderConfigRelativePath[] = L"mhwilds_virtual_pak_loader.ini";

inline constexpr wchar_t kFocusPakPathFragment[] = L"\\pak_mods\\";
inline constexpr wchar_t kEncryptedModExtension[] = L".mhwsmod";
inline constexpr wchar_t kStagedRuntimePakExtension[] = L".cache";
inline constexpr wchar_t kStageIndexFileName[] = L"4b1e6d2f90c84ab6b25f8d13f6a77102.bin";
inline constexpr char kStageIndexPlainMagic[] = "MHWSSI1\n";
inline constexpr wchar_t kUpdateCacheDirName[] = L"MHWILDSVersionProxy";
inline constexpr wchar_t kUpdateCacheFileName[] = L"update_cache.dat";
inline constexpr uint32_t kDefaultUpdateTimeoutMs = 4000;
inline constexpr uint32_t kDefaultUpdateCacheTtlMinutes = 30;
inline constexpr char kLoaderBuildVersion[] = MHWILDS_LOADER_VERSION;

inline constexpr uintptr_t kOpenStreamRva = 0xBBC10;
inline constexpr uintptr_t kReadStreamRva = 0xC8FF0;
inline constexpr std::array<uintptr_t, 2> kCreateFileCallsiteRvas{
    0xBBD6D,
    0xBBE74,
};
inline constexpr uintptr_t kDirectStorageCallsiteRva = 0x51EA36;
inline constexpr uintptr_t kDefaultTraceStartRva = 0xBBDD2;
inline constexpr uint32_t kDefaultTraceMaxInstructions = 200;
inline constexpr uint32_t kDefaultWatchTraceMaxInstructions = 512;
inline constexpr uint32_t kWatchTraceDetailedPrefixSteps = 32;
inline constexpr uint32_t kWatchTracePeriodicStepInterval = 32;
inline constexpr size_t kWatchTraceStackSnapshotEntries = 16;
inline constexpr size_t kTraceBytePreviewCount = 8;
inline constexpr uintptr_t kSecondStageTraceArmRva = 0x18DA1111;
inline constexpr uintptr_t kSecondStageTraceWatchFieldOffset = 0x58;
inline constexpr uintptr_t kSecondStageTraceWatchNextFieldOffset = 0x60;
inline constexpr uintptr_t kSecondStageTraceOwnerFieldOffset = 0x2A0;
inline constexpr size_t kSecondStageTraceWatchSize = sizeof(uint64_t);
inline constexpr size_t kHwBreakpointSlotCount = 4;
inline constexpr int kEntryBreakpointSlot = 0;
inline constexpr int kWatchBreakpointSlotNode58 = 0;
inline constexpr int kWatchBreakpointSlotNode60 = 1;
inline constexpr int kWatchBreakpointSlotOwner2A0 = 2;

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
using OpenFileOrResourceStreamFn = uint32_t(__fastcall*)(int64_t* stream, const wchar_t* path, int open_mode, uint64_t flags);
using ReadFileOrResourceStreamFn = uint64_t(__fastcall*)(uint64_t* stream, void* out_buffer, uint64_t bytes_to_read);

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
    std::shared_ptr<const struct VirtualPakSliceContext> slice_context{};
    uint64_t plain_size{};
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

enum class StartupGateStatus : int {
    Pending = 0,
    Ready = 1,
    TimeoutFallback = 2,
    LoaderHardBlocked = 3,
};

struct StartupGateSnapshot {
    bool loader_soft_outdated{};
    std::string loader_remote_version{};
    std::vector<std::wstring> approved_encrypted_source_paths{};
    std::vector<std::wstring> denied_encrypted_source_paths{};
    std::vector<std::wstring> staged_encrypted_paths{};
};

struct RedirectPathBreakpointSite {
    uintptr_t addr{};
    uint8_t original_byte{};
    const char* label{};
};

struct CallerContext {
    uintptr_t return_address{};
    HMODULE module{};
    std::wstring module_path{L"<unknown>"};
    std::wstring module_name{};
    bool near_createfile_site{};
};

class ScopedInternalBackendOpen {
public:
    ScopedInternalBackendOpen();
    ~ScopedInternalBackendOpen();

    ScopedInternalBackendOpen(const ScopedInternalBackendOpen&) = delete;
    ScopedInternalBackendOpen& operator=(const ScopedInternalBackendOpen&) = delete;
};

extern REFrameworkPluginFunctions g_ref;

extern CreateFileWFn g_original_create_file_w;
extern ReadFileFn g_original_read_file;
extern SetFilePointerExFn g_original_set_file_pointer_ex;
extern GetFileSizeExFn g_original_get_file_size_ex;
extern GetFileTypeFn g_original_get_file_type;
extern GetFileInformationByHandleFn g_original_get_file_information_by_handle;
extern GetFileInformationByHandleExFn g_original_get_file_information_by_handle_ex;
extern CreateFileMappingWFn g_original_create_file_mapping_w;
extern MapViewOfFileFn g_original_map_view_of_file;
extern CloseHandleFn g_original_close_handle;
extern NtQueryInformationFileFn g_original_nt_query_information_file;
extern DirectStorageOpenFn g_original_directstorage_open;
extern OpenFileOrResourceStreamFn g_original_open_file_or_resource_stream;
extern ReadFileOrResourceStreamFn g_original_read_file_or_resource_stream;

extern std::mutex g_log_mutex;
extern std::ofstream g_log;
extern std::mutex g_trace_log_mutex;
extern std::ofstream g_trace_log;
extern std::mutex g_stage_session_mutex;
extern std::mutex g_encrypted_mod_stage_mutex;
extern std::mutex g_update_prompt_mutex;
extern std::mutex g_startup_gate_mutex;
extern std::atomic<uint64_t> g_sequence;
extern std::atomic<bool> g_retry_registered;
extern std::atomic<bool> g_create_file_hook_installed;
extern std::atomic<bool> g_directstorage_hook_installed;
extern std::atomic<bool> g_native_open_stream_hook_installed;
extern std::atomic<bool> g_native_read_stream_hook_installed;
extern std::atomic<bool> g_directstorage_retry_consumed;
extern std::atomic<bool> g_early_bootstrap_attempted;
extern std::atomic<bool> g_shutdown_requested;
extern std::atomic<bool> g_attach_thread_started;
extern std::atomic<bool> g_hw_trace_refresh_thread_started;
extern std::atomic<bool> g_update_check_thread_started;
extern std::atomic<bool> g_update_prompt_thread_running;
extern std::atomic<uint64_t> g_create_file_pak_hits;
extern std::atomic<uint64_t> g_read_file_hits;
extern std::atomic<uint64_t> g_set_file_pointer_hits;
extern std::atomic<uint64_t> g_get_file_size_hits;
extern std::atomic<uint64_t> g_get_file_type_hits;
extern std::atomic<uint64_t> g_get_file_info_hits;
extern std::atomic<uint64_t> g_get_file_info_ex_hits;
extern std::atomic<uint64_t> g_create_file_mapping_hits;
extern std::atomic<uint64_t> g_map_view_of_file_hits;
extern std::atomic<uint64_t> g_close_handle_hits;
extern std::atomic<uint64_t> g_nt_query_info_hits;
extern std::atomic<uint64_t> g_directstorage_hits;
extern std::atomic<uint64_t> g_native_open_stream_hits;
extern std::atomic<uint64_t> g_native_read_stream_hits;
extern std::atomic<uint64_t> g_redirect_createfile_breakpoint_hits;
extern std::atomic<bool> g_same_point_hooks_installed;
extern std::atomic<bool> g_encrypted_mod_stage_prepared;
extern std::atomic<int> g_startup_gate_status;
extern std::atomic<bool> g_startup_gate_wait_logged;

extern uintptr_t g_game_module_base;
extern void* g_create_file_target;
extern void* g_read_file_target;
extern void* g_set_file_pointer_ex_target;
extern void* g_get_file_size_ex_target;
extern void* g_get_file_type_target;
extern void* g_get_file_information_by_handle_target;
extern void* g_get_file_information_by_handle_ex_target;
extern void* g_create_file_mapping_w_target;
extern void* g_map_view_of_file_target;
extern void* g_close_handle_target;
extern void* g_nt_query_information_file_target;
extern void* g_directstorage_target;
extern void* g_open_file_or_resource_stream_target;
extern void* g_read_file_or_resource_stream_target;
extern uintptr_t g_directstorage_global_ptr_addr;

extern std::array<uintptr_t, kCreateFileCallsiteRvas.size()> g_create_file_callsite_addrs;
extern std::mutex g_install_mutex;
extern std::mutex g_handle_mutex;
extern std::mutex g_virtual_loader_mutex;
extern std::array<SafetyHookMid, kCreateFileCallsiteRvas.size()> g_same_point_createfile_hooks;
extern SafetyHookMid g_same_point_directstorage_hook;
extern SafetyHookMid g_same_point_patch_version_hook;
extern std::unordered_map<uintptr_t, std::wstring> g_pak_handle_paths;
extern std::unordered_map<uintptr_t, uint64_t> g_pak_handle_positions;
extern std::unordered_map<uintptr_t, uint64_t> g_pak_handle_sizes;
extern std::unordered_map<uintptr_t, std::wstring> g_mapping_handle_paths;
extern std::unordered_map<uintptr_t, VirtualPakHandleState> g_virtual_pak_handles;
extern std::unordered_map<uintptr_t, VirtualMappingHandleState> g_virtual_mapping_handles;
extern VirtualPakLoaderConfig g_virtual_loader_config;
extern VirtualPakPayloadCache g_virtual_payload_cache;
extern VirtualPakStageCache g_virtual_stage_cache;
extern EncryptedModStageCache g_encrypted_mod_stage_cache;
extern StartupGateSnapshot g_startup_gate_snapshot;
extern std::wstring g_shared_stage_session_dir;
extern bool g_stage_startup_cleanup_done;
extern std::optional<std::array<uint8_t, 32>> g_cached_game_key;
extern std::wstring g_cached_game_key_source;
extern std::optional<std::array<uint8_t, 16>> g_cached_game_fingerprint;
extern std::wstring g_cached_game_fingerprint_source;
extern std::deque<UpdatePromptRequest> g_pending_update_prompts;
extern std::atomic<uint64_t> g_virtual_handle_counter;
extern uint64_t g_process_start_tick_ms;
extern HANDLE g_startup_gate_ready_event;

#if defined(MHWILDS_VERSION_PROXY)
extern HMODULE g_version_proxy_real_module;
extern PVOID g_patch_version_veh_handle;
extern uintptr_t g_patch_version_breakpoint_addr;
extern uint8_t g_patch_version_original_byte;
extern int g_patch_version_source_reg;
extern std::atomic<int> g_patch_version_last_value;
extern std::atomic<int> g_patch_version_breakpoint_pending_thread;
extern PVOID g_hw_trace_veh_handle;
extern uintptr_t g_hw_trace_start_addr;
extern uint32_t g_hw_trace_max_instructions;
extern std::atomic<bool> g_hw_trace_installed;
extern std::atomic<bool> g_hw_trace_started;
extern std::atomic<bool> g_hw_trace_finished;
extern std::atomic<DWORD> g_hw_trace_active_thread_id;
extern std::atomic<uint32_t> g_hw_trace_logged_steps;
extern std::atomic<int> g_hw_trace_breakpoint_type;
extern std::atomic<size_t> g_hw_trace_breakpoint_size;
extern std::array<std::atomic<uintptr_t>, kHwBreakpointSlotCount> g_hw_trace_slot_addrs;
extern std::array<std::atomic<int>, kHwBreakpointSlotCount> g_hw_trace_slot_types;
extern std::array<std::atomic<size_t>, kHwBreakpointSlotCount> g_hw_trace_slot_sizes;
extern std::atomic<uint32_t> g_hw_trace_watch_mask;
extern std::atomic<uintptr_t> g_hw_trace_watch_addr;
extern std::atomic<int> g_hw_trace_watch_hit_slot;
extern std::atomic<DWORD> g_hw_trace_watch_origin_thread_id;
extern std::atomic<uint32_t> g_hw_trace_watch_origin_ignored_hits;
extern std::atomic<bool> g_hw_trace_watch_armed;
extern std::atomic<bool> g_hw_trace_watch_triggered;
#endif

extern std::array<RedirectPathBreakpointSite, kCreateFileCallsiteRvas.size()> g_redirect_createfile_sites;
extern RedirectPathBreakpointSite g_redirect_directstorage_site;
extern PVOID g_redirect_path_veh_handle;
extern thread_local uintptr_t t_redirect_pending_breakpoint_addr;
extern thread_local uint8_t t_redirect_pending_breakpoint_original_byte;
extern thread_local std::wstring t_redirect_source_path_storage;
extern thread_local std::array<uint8_t, 0x40> t_redirect_directstorage_arg_shadow;
extern thread_local uint32_t t_internal_backend_open_depth;

#if defined(MHWILDS_VERSION_PROXY)
extern thread_local bool t_hw_trace_single_step_active;
extern thread_local uint32_t t_hw_trace_single_step_index;
extern thread_local HwTraceCaptureKind t_hw_trace_capture_kind;
extern thread_local uintptr_t t_hw_trace_last_logged_rip;
#endif

bool is_internal_backend_open_active();
std::wstring widen_module_path(HMODULE module);
std::string narrow_utf8(const std::wstring& value);
std::optional<std::wstring> widen_utf8(const std::string& value);
std::filesystem::path log_path();
std::filesystem::path trace_log_path();
std::filesystem::path loader_config_path();
uint64_t process_uptime_ms();
void open_log_if_needed();
void open_trace_log_if_needed();
void append_log_line(const std::string& line);
void append_trace_log_line(const std::string& line);
void append_timing_log_line(const char* event_name, std::string_view details = {});

bool read_memory_block_safe(const void* src, void* dst, size_t size);
bool read_u64_safe(const void* src, uint64_t* value);
std::string dump_bytes(const void* address, size_t count);
size_t main_module_size();
std::optional<uintptr_t> scan_main_module_pattern(std::string_view pattern);
std::optional<int> extract_patch_num_from_target_path(std::wstring_view path);
bool path_ends_with_pak(std::wstring_view path);
bool looks_like_reframework_custom_slot_path(std::wstring_view normalized_path);
bool looks_like_native_chunk_patch_name(std::wstring_view file_name);
int scan_highest_native_patch_num();
int compute_desired_patch_version();
const char* virtual_loader_mode_to_string(const VirtualPakLoaderConfig& config);
std::optional<std::wstring> resolve_redirect_source_for_requested_path(std::wstring_view requested_path);
bool install_patch_version_breakpoint();
void uninstall_patch_version_breakpoint();
bool looks_like_wide_string_at(const wchar_t* text);
std::wstring read_wide_string_safe(const wchar_t* text);
std::string describe_directstorage_arg(const void* arg);
std::optional<std::wstring> extract_directstorage_path(const void* arg);
std::wstring to_lower_copy(const std::wstring& value);
std::wstring normalize_path_for_match(const std::wstring& value);
std::string trim_ascii_copy(const std::string& value);
std::wstring trim_ascii_copy(const std::wstring& value);
bool parse_bool_value(const std::string& value);
std::optional<uint64_t> parse_u64_value(const std::string& value);

void run_hw_trace_reapply_loop();
void ensure_hw_trace_refresh_thread_running(const char* source);
bool install_hw_instruction_trace(const VirtualPakLoaderConfig& config);
void uninstall_hw_instruction_trace();

bool load_reframework_pak_directory_enabled_from_disk();
std::vector<std::wstring> resolve_encrypted_custom_mod_paths();
std::vector<std::wstring> resolve_local_custom_pak_paths(const VirtualPakLoaderConfig& config);
int count_candidate_virtual_source_paths(const VirtualPakLoaderConfig& config);
int count_effective_virtual_source_paths(const VirtualPakLoaderConfig& config);
void recompute_virtual_loader_patch_counts(VirtualPakLoaderConfig& config);
std::vector<std::wstring> resolve_effective_rf_chain_pak_paths(const VirtualPakLoaderConfig& config);
void reload_virtual_loader_config();
std::optional<std::vector<uint8_t>> read_binary_file(const std::filesystem::path& path);
bool write_binary_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes);
std::vector<std::wstring> stage_selected_encrypted_mods_into_local_dir(
    const VirtualPakLoaderConfig& config,
    const std::vector<std::wstring>& encrypted_source_paths);
std::vector<std::wstring> stage_encrypted_custom_mods_into_local_dir(const VirtualPakLoaderConfig& config);
std::optional<std::shared_ptr<std::vector<uint8_t>>> load_virtual_pak_payload();
std::optional<std::wstring> ensure_runtime_source_path_prepared();
void cleanup_staged_runtime_source();
bool path_matches_virtual_target_locked(const std::wstring& normalized_path, const VirtualPakLoaderConfig& config);
bool path_matches_record_target_locked(const std::wstring& normalized_path, const VirtualPakLoaderConfig& config);
std::optional<ModMetadataRecord> load_mod_metadata_record(const std::filesystem::path& source_path);
std::optional<VirtualPakHandleState> prepare_virtual_pak_handle_state(const VirtualPakLoaderConfig& config);
std::optional<std::vector<uint8_t>> read_virtual_pak_bytes(
    const VirtualPakHandleState& state,
    uint64_t plain_offset,
    size_t bytes_to_read,
    DWORD* last_error = nullptr);

bool path_matches_virtual_target(const std::wstring& path);
bool path_matches_virtual_target(LPCWSTR file_name);
bool path_matches_record_target(const std::wstring& path);
bool path_matches_record_target(LPCWSTR file_name);
std::optional<VirtualPakLoaderConfig> current_virtual_loader_config();
std::optional<std::wstring> current_virtual_source_path();
HANDLE create_virtual_file_handle(VirtualPakHandleState state, HANDLE backing_handle = nullptr);
HANDLE create_virtual_mapping_handle(
    const std::wstring& path,
    std::shared_ptr<std::vector<uint8_t>> payload,
    HANDLE backing_handle = nullptr);
bool path_looks_like_pak(LPCWSTR file_name);
bool path_matches_focus_target(const std::wstring& path);
bool path_matches_focus_target(LPCWSTR file_name);
std::optional<size_t> match_create_file_nearby_site(void* caller);
std::string describe_caller(void* caller);
CallerContext resolve_caller_context(void* caller);
const char* evaluate_virtual_backend_caller(const CallerContext& caller);
uintptr_t handle_key(HANDLE handle);
std::optional<uint64_t> apply_signed_offset(uint64_t base, int64_t delta);
void track_pak_handle(HANDLE handle, const std::wstring& path);
std::optional<std::wstring> lookup_pak_handle_path(HANDLE handle);
std::optional<uint64_t> lookup_pak_handle_position(HANDLE handle);
void set_pak_handle_position(HANDLE handle, uint64_t position);
std::optional<uint64_t> lookup_pak_handle_size(HANDLE handle);
void set_pak_handle_size(HANDLE handle, uint64_t size);
void track_mapping_handle(HANDLE mapping_handle, const std::wstring& path);
std::optional<std::wstring> lookup_mapping_handle_path(HANDLE mapping_handle);
void untrack_close_handle(HANDLE handle);
bool ensure_minhook_initialized();
bool install_named_hook(void* target, void* detour, void** original, const char* label);
void initialize_fixed_addresses();
bool write_breakpoint_byte(uintptr_t address, uint8_t value);
bool install_redirect_path_breakpoints();
void uninstall_redirect_path_breakpoints();
std::optional<uintptr_t> resolve_rel32_target(uintptr_t instruction, size_t displacement_offset, size_t instruction_size);
bool resolve_directstorage_target_once();
std::optional<std::shared_ptr<std::vector<uint8_t>>> lookup_virtual_payload(HANDLE handle);
std::optional<VirtualPakHandleState> lookup_virtual_pak_state(HANDLE handle);
std::optional<std::wstring> lookup_virtual_source_path(HANDLE handle);
std::optional<VirtualMappingHandleState> lookup_virtual_mapping(HANDLE handle);
FILETIME virtual_filetime_now();
LONGLONG filetime_to_large_integer(const FILETIME& filetime);
uint64_t virtual_file_id(HANDLE handle);
bool fill_virtual_by_handle_file_information(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION file_information);
bool patch_virtual_by_handle_file_information(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION file_information);
bool fill_virtual_file_information_by_handle_ex(
    HANDLE handle,
    FILE_INFO_BY_HANDLE_CLASS file_information_class,
    LPVOID file_information,
    DWORD buffer_size,
    DWORD* last_error);
bool patch_virtual_file_information_by_handle_ex(
    HANDLE handle,
    FILE_INFO_BY_HANDLE_CLASS file_information_class,
    LPVOID file_information,
    DWORD buffer_size,
    DWORD* last_error);
NTSTATUS fill_virtual_nt_query_information_file(
    HANDLE handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    FILE_INFORMATION_CLASS file_information_class);
NTSTATUS patch_virtual_nt_query_information_file(
    HANDLE handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    FILE_INFORMATION_CLASS file_information_class);

bool install_same_point_reframework_chain_hooks();
void uninstall_same_point_reframework_chain_hooks();
bool install_native_stream_probe_hooks();
bool install_create_file_hook();
bool install_pak_io_hooks();
bool install_directstorage_hook();
void log_install_result(const char* source, bool create_file_ok, bool directstorage_ok, bool pak_io_ok, bool trace_ok);
void run_probe_installation(const char* source, bool directstorage_retry_loop);
DWORD WINAPI attach_probe_thread(LPVOID);
void run_early_create_file_bootstrap();
void try_install_directstorage_once_on_present();
void shutdown_hooks();
StartupGateStatus wait_for_startup_gate_status(const char* consumer);
void schedule_update_check_worker();

inline ScopedInternalBackendOpen::ScopedInternalBackendOpen() {
    ++t_internal_backend_open_depth;
}

inline ScopedInternalBackendOpen::~ScopedInternalBackendOpen() {
    if (t_internal_backend_open_depth != 0) {
        --t_internal_backend_open_depth;
    }
}

inline bool is_internal_backend_open_active() {
    return t_internal_backend_open_depth != 0;
}

} // namespace mhwilds::probe
