#include "plugin_internal.hpp"

namespace mhwilds::probe {

void log_install_result(const char* source, bool create_file_ok, bool directstorage_ok, bool pak_io_ok, bool trace_ok) {
    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock __{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }

    std::ostringstream oss;
    oss << source
        << " createfile=" << static_cast<int>(create_file_ok)
        << " pak_io=" << static_cast<int>(pak_io_ok)
        << " directstorage=" << static_cast<int>(directstorage_ok)
        << " hw_trace=" << static_cast<int>(trace_ok)
#if defined(MHWILDS_VERSION_PROXY)
        << " patch_break=" << static_cast<int>(g_patch_version_breakpoint_addr != 0)
        << " same_point=" << static_cast<int>(g_same_point_hooks_installed.load())
#endif
        << " backend_only=" << static_cast<int>(config.backend_only)
        << " record_only=" << static_cast<int>(config.record_only)
        << " rf_chain_mode=" << static_cast<int>(config.rf_chain_mode)
        << "\n";
    append_log_line(oss.str());
}

void run_probe_installation(const char* source, bool directstorage_retry_loop) {
    std::scoped_lock _{g_install_mutex};

    if (g_shutdown_requested.load()) {
        return;
    }

    open_log_if_needed();
    reload_virtual_loader_config();
    initialize_fixed_addresses();
#if defined(MHWILDS_VERSION_PROXY)
    schedule_update_check_worker();
#endif

    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock __{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }

#if defined(MHWILDS_VERSION_PROXY)
    const auto trace_ok = install_hw_instruction_trace(config);
#else
    constexpr bool trace_ok = false;
#endif

    if (config.observer_only) {
        append_log_line("observer-only-mode active; skipping patch/createfile/pak-io/directstorage hooks\n");
        log_install_result(source, false, false, false, trace_ok);
        return;
    }

    if (config.rf_chain_mode) {
#if defined(MHWILDS_VERSION_PROXY)
        const auto same_point_ok = install_same_point_reframework_chain_hooks();
#else
        constexpr bool same_point_ok = false;
#endif
        append_log_line("rf-chain-mode active; skipping legacy minhook backend\n");
        log_install_result(source, false, same_point_ok, false, trace_ok);
        return;
    }

    const auto record_only_mode = config.record_only;
    const auto legacy_virtual_backend_mode = config.backend_only && !config.passthrough;
    const auto staged_passthrough_mode = config.passthrough;

    if (staged_passthrough_mode) {
        if (const auto runtime_source = current_virtual_source_path(); runtime_source.has_value()) {
            std::ostringstream oss;
            oss << "staged-source-active path=" << narrow_utf8(*runtime_source) << "\n";
            append_log_line(oss.str());
        } else {
            append_log_line("staged-source-prepare-failed\n");
        }
    }

#if defined(MHWILDS_VERSION_PROXY)
    const auto patch_break_ok = record_only_mode ? false : (compute_desired_patch_version() >= 0 ? install_patch_version_breakpoint() : true);
    (void)patch_break_ok;
#endif
    const auto create_file_ok = install_create_file_hook();
    const auto pak_io_ok = (legacy_virtual_backend_mode || record_only_mode) ? install_pak_io_hooks() : false;
    auto directstorage_ok = record_only_mode ? false : install_directstorage_hook();

    if (record_only_mode) {
        append_log_line("record-only-mode active; skipping patch/directstorage interception\n");
    }

    if (legacy_virtual_backend_mode) {
        append_log_line("legacy-virtual-backend-mode active; pak-io hooks enabled\n");
    }

    if (staged_passthrough_mode) {
        append_log_line("staged-passthrough-mode active; virtual pak-io hooks skipped\n");
    }

    if (!record_only_mode && !directstorage_ok && directstorage_retry_loop) {
        for (size_t attempt = 1; attempt <= 60; ++attempt) {
            if (g_shutdown_requested.load()) {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            directstorage_ok = install_directstorage_hook();
            if (directstorage_ok) {
                std::ostringstream oss;
                oss << "directstorage-retry-thread-success source=" << source
                    << " attempt=" << attempt
                    << "\n";
                append_log_line(oss.str());
                break;
            }
        }
    }

    log_install_result(source, create_file_ok, directstorage_ok, pak_io_ok, trace_ok);
}

DWORD WINAPI attach_probe_thread(LPVOID) {
    run_probe_installation("attach-init-result", true);
#if defined(MHWILDS_VERSION_PROXY)
    run_hw_trace_reapply_loop();
#endif
    return 0;
}

void run_early_create_file_bootstrap() {
    if (g_early_bootstrap_attempted.exchange(true)) {
        return;
    }

    open_log_if_needed();
    reload_virtual_loader_config();
    initialize_fixed_addresses();
#if defined(MHWILDS_VERSION_PROXY)
    schedule_update_check_worker();
#endif

    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock __{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }

#if defined(MHWILDS_VERSION_PROXY)
    const auto trace_ok = install_hw_instruction_trace(config);
#else
    constexpr bool trace_ok = false;
#endif

    if (config.observer_only) {
        append_log_line("observer-only-mode active; skipping early bootstrap hooks\n");
        std::ostringstream observer_oss;
        observer_oss << "early-bootstrap-result"
            << " createfile=0"
            << " pak_io=0"
            << " hw_trace=" << static_cast<int>(trace_ok)
            << " patch_break=0"
            << " observer_only=1"
            << "\n";
        append_log_line(observer_oss.str());
        return;
    }

    if (config.rf_chain_mode) {
#if defined(MHWILDS_VERSION_PROXY)
        const auto same_point_ok = install_same_point_reframework_chain_hooks();
#else
        constexpr bool same_point_ok = false;
#endif
        std::ostringstream rf_oss;
        rf_oss << "early-bootstrap-result"
            << " createfile=0"
            << " pak_io=0"
            << " hw_trace=" << static_cast<int>(trace_ok)
            << " patch_break=0"
            << " same_point=" << static_cast<int>(same_point_ok)
            << " rf_chain_mode=1"
            << "\n";
        append_log_line("rf-chain-mode active during early bootstrap; skipping legacy minhook backend\n");
        append_log_line(rf_oss.str());
        return;
    }

    const auto record_only_mode = config.record_only;
    const auto legacy_virtual_backend_mode = config.backend_only && !config.passthrough;
    const auto staged_passthrough_mode = config.passthrough;

    if (staged_passthrough_mode) {
        if (const auto runtime_source = current_virtual_source_path(); runtime_source.has_value()) {
            std::ostringstream stage_oss;
            stage_oss << "early-stage-source-active path=" << narrow_utf8(*runtime_source) << "\n";
            append_log_line(stage_oss.str());
        } else {
            append_log_line("early-stage-source-prepare-failed\n");
        }
    }

#if defined(MHWILDS_VERSION_PROXY)
    const auto patch_break_ok = record_only_mode ? false : (compute_desired_patch_version() >= 0 ? install_patch_version_breakpoint() : true);
#else
    constexpr bool patch_break_ok = false;
#endif
    const auto create_file_ok = install_create_file_hook();
    const auto pak_io_ok = (legacy_virtual_backend_mode || record_only_mode) ? install_pak_io_hooks() : false;

    if (record_only_mode) {
        append_log_line("record-only-mode active; skipping early patch/directstorage interception\n");
    }

    if (legacy_virtual_backend_mode) {
        append_log_line("legacy-virtual-backend-mode active during early bootstrap; pak-io hooks enabled\n");
    }

    if (staged_passthrough_mode) {
        append_log_line("staged-passthrough-mode active during early bootstrap; virtual pak-io hooks skipped\n");
    }

    std::ostringstream oss;
    oss << "early-bootstrap-result"
        << " createfile=" << static_cast<int>(create_file_ok)
        << " pak_io=" << static_cast<int>(pak_io_ok)
        << " hw_trace=" << static_cast<int>(trace_ok)
#if defined(MHWILDS_VERSION_PROXY)
        << " patch_break=" << static_cast<int>(patch_break_ok)
#endif
        << " observer_only=0"
        << " backend_only=" << static_cast<int>(config.backend_only)
        << " record_only=" << static_cast<int>(config.record_only)
        << "\n";
    append_log_line(oss.str());
}

void try_install_directstorage_once_on_present() {
    if (g_directstorage_hook_installed.load()) {
        return;
    }

    if (g_directstorage_retry_consumed.exchange(true)) {
        return;
    }

    append_log_line("directstorage-retry-on-present\n");
    run_probe_installation("present-retry-result", false);
}

void shutdown_hooks() {
#if defined(MHWILDS_VERSION_PROXY)
    uninstall_hw_instruction_trace();
    uninstall_patch_version_breakpoint();
    uninstall_same_point_reframework_chain_hooks();
#endif
    if (g_create_file_target != nullptr) {
        MH_DisableHook(g_create_file_target);
        MH_RemoveHook(g_create_file_target);
    }

    if (g_read_file_target != nullptr) {
        MH_DisableHook(g_read_file_target);
        MH_RemoveHook(g_read_file_target);
    }

    if (g_set_file_pointer_ex_target != nullptr) {
        MH_DisableHook(g_set_file_pointer_ex_target);
        MH_RemoveHook(g_set_file_pointer_ex_target);
    }

    if (g_create_file_mapping_w_target != nullptr) {
        MH_DisableHook(g_create_file_mapping_w_target);
        MH_RemoveHook(g_create_file_mapping_w_target);
    }

    if (g_map_view_of_file_target != nullptr) {
        MH_DisableHook(g_map_view_of_file_target);
        MH_RemoveHook(g_map_view_of_file_target);
    }

    if (g_close_handle_target != nullptr) {
        MH_DisableHook(g_close_handle_target);
        MH_RemoveHook(g_close_handle_target);
    }

    if (g_directstorage_target != nullptr) {
        MH_DisableHook(g_directstorage_target);
        MH_RemoveHook(g_directstorage_target);
    }

    MH_Uninitialize();
    g_create_file_hook_installed = false;
    g_directstorage_hook_installed = false;

    std::scoped_lock _{g_handle_mutex};
    g_pak_handle_paths.clear();
    g_pak_handle_positions.clear();
    g_pak_handle_sizes.clear();
    g_mapping_handle_paths.clear();
    g_virtual_pak_handles.clear();
    g_virtual_mapping_handles.clear();
    {
        std::scoped_lock __{g_virtual_loader_mutex};
        g_virtual_payload_cache = {};
        g_virtual_stage_cache = {};
        g_cached_game_key.reset();
        g_cached_game_key_source.clear();
        g_cached_game_fingerprint.reset();
        g_cached_game_fingerprint_source.clear();
    }
}

} // namespace mhwilds::probe
