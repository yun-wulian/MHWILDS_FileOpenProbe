#include "plugin/plugin_internal.hpp"

using namespace mhwilds::probe;

namespace {
using GetFileVersionInfoAFn = decltype(&::GetFileVersionInfoA);
using GetFileVersionInfoExAFn = decltype(&::GetFileVersionInfoExA);
using GetFileVersionInfoExWFn = decltype(&::GetFileVersionInfoExW);
using GetFileVersionInfoSizeAFn = decltype(&::GetFileVersionInfoSizeA);
using GetFileVersionInfoSizeExAFn = decltype(&::GetFileVersionInfoSizeExA);
using GetFileVersionInfoSizeExWFn = decltype(&::GetFileVersionInfoSizeExW);
using GetFileVersionInfoSizeWFn = decltype(&::GetFileVersionInfoSizeW);
using GetFileVersionInfoWFn = decltype(&::GetFileVersionInfoW);
using VerFindFileAFn = decltype(&::VerFindFileA);
using VerFindFileWFn = decltype(&::VerFindFileW);
using VerInstallFileAFn = decltype(&::VerInstallFileA);
using VerInstallFileWFn = decltype(&::VerInstallFileW);
using VerLanguageNameAFn = decltype(&::VerLanguageNameA);
using VerLanguageNameWFn = decltype(&::VerLanguageNameW);
using VerQueryValueAFn = decltype(&::VerQueryValueA);
using VerQueryValueWFn = decltype(&::VerQueryValueW);
using GetFileVersionInfoByHandleFn = BOOL(WINAPI*)(DWORD, HANDLE, LPVOID*, PDWORD);

std::wstring build_system_version_module_path() {
    std::array<wchar_t, MAX_PATH> system_dir{};
    const auto length = GetSystemDirectoryW(system_dir.data(), static_cast<UINT>(system_dir.size()));
    if (length == 0 || length >= system_dir.size()) {
        return {};
    }

    std::wstring path{system_dir.data(), length};
    if (!path.empty() && path.back() != L'\\') {
        path.push_back(L'\\');
    }

    path += L"version.dll";
    return path;
}

HMODULE ensure_real_version_module_loaded() {
    if (g_version_proxy_real_module != nullptr) {
        return g_version_proxy_real_module;
    }

    const auto module_path = build_system_version_module_path();
    if (module_path.empty()) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return nullptr;
    }

    g_version_proxy_real_module = LoadLibraryW(module_path.c_str());
    if (g_version_proxy_real_module == nullptr) {
        open_log_if_needed();
        std::ostringstream oss;
        oss << "version-proxy-load-real-failed path=" << narrow_utf8(module_path) << "\n";
        append_log_line(oss.str());
    }

    return g_version_proxy_real_module;
}

FARPROC resolve_real_version_proc(const char* name) {
    const auto module = ensure_real_version_module_loaded();
    if (module == nullptr) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return nullptr;
    }

    const auto proc = GetProcAddress(module, name);
    if (proc == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
    }

    return proc;
}
} // namespace

#define DEFINE_VERSION_PROXY_BOOL_EXPORT(name, signature, fn_type, call_args) \
    extern "C" BOOL WINAPI name signature { \
        static const auto proc = reinterpret_cast<fn_type>(resolve_real_version_proc(#name)); \
        return proc != nullptr ? proc call_args : FALSE; \
    }

#define DEFINE_VERSION_PROXY_DWORD_EXPORT(name, signature, fn_type, call_args) \
    extern "C" DWORD WINAPI name signature { \
        static const auto proc = reinterpret_cast<fn_type>(resolve_real_version_proc(#name)); \
        return proc != nullptr ? proc call_args : 0; \
    }

DEFINE_VERSION_PROXY_BOOL_EXPORT(GetFileVersionInfoA, (LPCSTR filename, DWORD handle, DWORD length, LPVOID data), GetFileVersionInfoAFn, (filename, handle, length, data))
DEFINE_VERSION_PROXY_BOOL_EXPORT(GetFileVersionInfoByHandle, (DWORD flags, HANDLE file, LPVOID* data, PDWORD length), GetFileVersionInfoByHandleFn, (flags, file, data, length))
DEFINE_VERSION_PROXY_BOOL_EXPORT(GetFileVersionInfoExA, (DWORD flags, LPCSTR filename, DWORD handle, DWORD length, LPVOID data), GetFileVersionInfoExAFn, (flags, filename, handle, length, data))
DEFINE_VERSION_PROXY_BOOL_EXPORT(GetFileVersionInfoExW, (DWORD flags, LPCWSTR filename, DWORD handle, DWORD length, LPVOID data), GetFileVersionInfoExWFn, (flags, filename, handle, length, data))
DEFINE_VERSION_PROXY_DWORD_EXPORT(GetFileVersionInfoSizeA, (LPCSTR filename, LPDWORD handle), GetFileVersionInfoSizeAFn, (filename, handle))
DEFINE_VERSION_PROXY_DWORD_EXPORT(GetFileVersionInfoSizeExA, (DWORD flags, LPCSTR filename, LPDWORD handle), GetFileVersionInfoSizeExAFn, (flags, filename, handle))
DEFINE_VERSION_PROXY_DWORD_EXPORT(GetFileVersionInfoSizeExW, (DWORD flags, LPCWSTR filename, LPDWORD handle), GetFileVersionInfoSizeExWFn, (flags, filename, handle))
DEFINE_VERSION_PROXY_DWORD_EXPORT(GetFileVersionInfoSizeW, (LPCWSTR filename, LPDWORD handle), GetFileVersionInfoSizeWFn, (filename, handle))
DEFINE_VERSION_PROXY_BOOL_EXPORT(GetFileVersionInfoW, (LPCWSTR filename, DWORD handle, DWORD length, LPVOID data), GetFileVersionInfoWFn, (filename, handle, length, data))
DEFINE_VERSION_PROXY_DWORD_EXPORT(VerFindFileA, (DWORD flags, LPCSTR filename, LPCSTR win_dir, LPCSTR app_dir, LPSTR cur_dir, PUINT cur_dir_len, LPSTR dest_dir, PUINT dest_dir_len), VerFindFileAFn, (flags, filename, win_dir, app_dir, cur_dir, cur_dir_len, dest_dir, dest_dir_len))
DEFINE_VERSION_PROXY_DWORD_EXPORT(VerFindFileW, (DWORD flags, LPCWSTR filename, LPCWSTR win_dir, LPCWSTR app_dir, LPWSTR cur_dir, PUINT cur_dir_len, LPWSTR dest_dir, PUINT dest_dir_len), VerFindFileWFn, (flags, filename, win_dir, app_dir, cur_dir, cur_dir_len, dest_dir, dest_dir_len))
DEFINE_VERSION_PROXY_DWORD_EXPORT(VerInstallFileA, (DWORD flags, LPCSTR src_filename, LPCSTR dest_filename, LPCSTR src_dir, LPCSTR dest_dir, LPCSTR cur_dir, LPSTR tmp_file, PUINT tmp_file_len), VerInstallFileAFn, (flags, src_filename, dest_filename, src_dir, dest_dir, cur_dir, tmp_file, tmp_file_len))
DEFINE_VERSION_PROXY_DWORD_EXPORT(VerInstallFileW, (DWORD flags, LPCWSTR src_filename, LPCWSTR dest_filename, LPCWSTR src_dir, LPCWSTR dest_dir, LPCWSTR cur_dir, LPWSTR tmp_file, PUINT tmp_file_len), VerInstallFileWFn, (flags, src_filename, dest_filename, src_dir, dest_dir, cur_dir, tmp_file, tmp_file_len))
DEFINE_VERSION_PROXY_DWORD_EXPORT(VerLanguageNameA, (DWORD lang, LPSTR buffer, DWORD size), VerLanguageNameAFn, (lang, buffer, size))
DEFINE_VERSION_PROXY_DWORD_EXPORT(VerLanguageNameW, (DWORD lang, LPWSTR buffer, DWORD size), VerLanguageNameWFn, (lang, buffer, size))
DEFINE_VERSION_PROXY_BOOL_EXPORT(VerQueryValueA, (LPCVOID block, LPCSTR sub_block, LPVOID* buffer, PUINT length), VerQueryValueAFn, (block, sub_block, buffer, length))
DEFINE_VERSION_PROXY_BOOL_EXPORT(VerQueryValueW, (LPCVOID block, LPCWSTR sub_block, LPVOID* buffer, PUINT length), VerQueryValueWFn, (block, sub_block, buffer, length))

#undef DEFINE_VERSION_PROXY_BOOL_EXPORT
#undef DEFINE_VERSION_PROXY_DWORD_EXPORT

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        g_shutdown_requested = false;
        DisableThreadLibraryCalls(module);
        g_version_proxy_real_module = ensure_real_version_module_loaded();
        if (g_version_proxy_real_module == nullptr) {
            return FALSE;
        }
        run_early_create_file_bootstrap();
        if (!g_attach_thread_started.exchange(true)) {
            if (const auto thread = CreateThread(nullptr, 0, &attach_probe_thread, nullptr, 0, nullptr); thread != nullptr) {
                CloseHandle(thread);
            } else {
                open_log_if_needed();
                append_log_line("attach-thread-create-failed\n");
            }
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        g_shutdown_requested = true;
        shutdown_hooks();
        if (g_version_proxy_real_module != nullptr) {
            FreeLibrary(g_version_proxy_real_module);
            g_version_proxy_real_module = nullptr;
        }
    }

    return TRUE;
}
