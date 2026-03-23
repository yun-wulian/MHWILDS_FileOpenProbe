#include "plugin_internal.hpp"

namespace mhwilds::probe {

std::optional<HANDLE> try_open_virtual_pak(
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file,
    DWORD* last_error) {
    if (file_name == nullptr || !path_matches_virtual_target(file_name)) {
        return std::nullopt;
    }

    const auto config = current_virtual_loader_config();
    if (!config.has_value()) {
        if (last_error != nullptr) {
            *last_error = ERROR_FILE_NOT_FOUND;
        }

        append_log_line("virtual-loader-target-hit-without-source\n");
        return INVALID_HANDLE_VALUE;
    }

    if (config->passthrough) {
        const auto runtime_source_path = current_virtual_source_path();
        if (!runtime_source_path.has_value()) {
            if (last_error != nullptr) {
                *last_error = ERROR_FILE_NOT_FOUND;
            }
            append_log_line("virtual-loader-runtime-source-unavailable\n");
            return INVALID_HANDLE_VALUE;
        }

        const auto result = g_original_create_file_w(
            runtime_source_path->c_str(),
            desired_access,
            share_mode,
            security_attributes,
            creation_disposition,
            flags_and_attributes,
            template_file);
        if (last_error != nullptr) {
            *last_error = result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        }
        return result;
    }

    const auto payload = load_virtual_pak_payload();
    if (!payload.has_value()) {
        if (last_error != nullptr) {
            *last_error = ERROR_INVALID_DATA;
        }

        return INVALID_HANDLE_VALUE;
    }

    if (last_error != nullptr) {
        *last_error = ERROR_SUCCESS;
    }

    DWORD backing_last_error = ERROR_SUCCESS;
    HANDLE backing_handle = INVALID_HANDLE_VALUE;
    {
        ScopedInternalBackendOpen internal_open_guard{};
        backing_handle = g_original_create_file_w(
            file_name,
            desired_access,
            share_mode,
            security_attributes,
            creation_disposition,
            flags_and_attributes,
            template_file);
        backing_last_error = backing_handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    }

    if (backing_handle != INVALID_HANDLE_VALUE) {
        std::ostringstream oss;
        oss << "virtual-loader-backing-open-success handle=0x" << std::hex << handle_key(backing_handle)
            << " path=" << narrow_utf8(file_name)
            << "\n";
        append_log_line(oss.str());
        return create_virtual_file_handle(file_name, config->source_path, *payload, backing_handle);
    }

    {
        std::ostringstream oss;
        oss << "virtual-loader-backing-open-failed path="
            << narrow_utf8(file_name)
            << " last_error="
            << std::dec
            << backing_last_error
            << "\n";
        append_log_line(oss.str());
    }

    return create_virtual_file_handle(file_name, config->source_path, *payload);
}

HANDLE WINAPI hooked_create_file_w(
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file) {
    if (is_internal_backend_open_active()) {
        return g_original_create_file_w(
            file_name,
            desired_access,
            share_mode,
            security_attributes,
            creation_disposition,
            flags_and_attributes,
            template_file);
    }

    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto caller_context = resolve_caller_context(caller);
    const auto is_pak = path_looks_like_pak(file_name);
    const auto is_virtual_target = is_pak && path_matches_virtual_target(file_name);
    const auto is_record_target = is_pak && path_matches_record_target(file_name);
    const auto is_focus_pak = is_virtual_target || is_record_target || path_matches_focus_target(file_name);
    auto is_virtual_pak = false;
    HANDLE result{};
    DWORD last_error = ERROR_SUCCESS;
    const auto* caller_filter_reason = is_virtual_target ? evaluate_virtual_backend_caller(caller_context) : nullptr;

    if (is_virtual_target && caller_filter_reason == nullptr) {
        std::ostringstream oss;
        oss << "virtual-loader-target-rejected"
            << describe_caller(caller)
            << " path=" << (file_name != nullptr ? narrow_utf8(file_name) : "<null>")
            << "\n";
        append_log_line(oss.str());
    }

    if (is_pak) {
        if (is_virtual_target && caller_filter_reason != nullptr) {
            if (const auto virtual_result = try_open_virtual_pak(
                    file_name,
                    desired_access,
                    share_mode,
                    security_attributes,
                    creation_disposition,
                    flags_and_attributes,
                    template_file,
                    &last_error);
                virtual_result.has_value()) {
                result = *virtual_result;
                is_virtual_pak = result != INVALID_HANDLE_VALUE && lookup_virtual_payload(result).has_value();
            } else {
                result = g_original_create_file_w(
                    file_name,
                    desired_access,
                    share_mode,
                    security_attributes,
                    creation_disposition,
                    flags_and_attributes,
                    template_file);
                last_error = result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
            }
        } else {
            result = g_original_create_file_w(
                file_name,
                desired_access,
                share_mode,
                security_attributes,
                creation_disposition,
                flags_and_attributes,
                template_file);
            last_error = result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        }
    } else {
        result = g_original_create_file_w(
            file_name,
            desired_access,
            share_mode,
            security_attributes,
            creation_disposition,
            flags_and_attributes,
            template_file);
        last_error = result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    }

    if (is_pak && is_focus_pak) {
        const auto tracked_path = file_name != nullptr ? std::wstring{file_name} : L""; 
        if (result != INVALID_HANDLE_VALUE && !is_virtual_pak) {
            track_pak_handle(result, tracked_path);
        }

        const auto seq = g_sequence.fetch_add(1) + 1;
        const auto pak_hits = g_create_file_pak_hits.fetch_add(1) + 1;
        std::ostringstream oss;
        oss << "[createfile " << seq << "]"
            << " pak_hits=" << std::dec << pak_hits
            << describe_caller(caller)
            << std::hex
            << " access=0x" << desired_access
            << " share=0x" << share_mode
            << " creation=0x" << creation_disposition
            << " flags=0x" << flags_and_attributes
            << " target_match=" << std::dec << static_cast<int>(is_virtual_target || is_record_target)
            << " record_only=" << std::dec << static_cast<int>(is_record_target)
            << " virtual=" << std::dec << static_cast<int>(is_virtual_pak)
            << std::hex
            << " result=0x" << std::hex << reinterpret_cast<uintptr_t>(result)
            << " last_error=" << std::dec << last_error
            << "\n";

        if (file_name != nullptr) {
            oss << "path=" << narrow_utf8(file_name) << "\n";
        } else {
            oss << "path=<null>\n";
        }

        if (is_virtual_target) {
            oss << "caller_filter=" << (caller_filter_reason != nullptr ? caller_filter_reason : "reject") << "\n";
        }

        if (is_virtual_pak) {
            oss << "source=" << narrow_utf8(lookup_virtual_source_path(result).value_or(L"")) << "\n\n";
        } else {
            oss << "\n";
        }

        append_log_line(oss.str());
    }

    if (is_virtual_pak || (is_virtual_target && result == INVALID_HANDLE_VALUE)) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_read_file(
    HANDLE file,
    LPVOID buffer,
    DWORD bytes_to_read,
    LPDWORD bytes_read,
    LPOVERLAPPED overlapped) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto position_before = tracked_path.has_value() ? lookup_pak_handle_position(file) : std::nullopt;
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_payload = tracked_path.has_value() ? lookup_virtual_payload(file) : std::nullopt;
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;

    if (virtual_payload.has_value()) {
        const auto payload = *virtual_payload;
        uint64_t read_offset = position_before.value_or(0);
        if (overlapped != nullptr) {
            read_offset = (static_cast<uint64_t>(overlapped->OffsetHigh) << 32) | overlapped->Offset;
        }

        auto transferred = 0U;
        if (read_offset < payload->size()) {
            const auto remaining = payload->size() - static_cast<size_t>(read_offset);
            transferred = static_cast<DWORD>(std::min<size_t>(remaining, bytes_to_read));
            if (transferred != 0 && buffer != nullptr) {
                std::memcpy(buffer, payload->data() + read_offset, transferred);
            }
        }

        if (bytes_read != nullptr) {
            *bytes_read = transferred;
        }

        if (overlapped == nullptr) {
            set_pak_handle_position(file, read_offset + transferred);
            if (virtual_state.has_value() && !virtual_state->synthetic_handle) {
                LARGE_INTEGER sync_offset{};
                sync_offset.QuadPart = static_cast<LONGLONG>(read_offset + transferred);
                if (g_original_set_file_pointer_ex(file, sync_offset, nullptr, FILE_BEGIN) == 0) {
                    last_error = GetLastError();
                }
            }
        }

        result = TRUE;
    } else {
        result = g_original_read_file(file, buffer, bytes_to_read, bytes_read, overlapped);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_read_file_hits.fetch_add(1) + 1;
        const auto transferred = bytes_read != nullptr ? *bytes_read : 0;
        std::optional<uint64_t> position_after = position_before;

        if (result != 0 && overlapped == nullptr && position_before.has_value()) {
            position_after = *position_before + transferred;
            set_pak_handle_position(file, *position_after);
        }

        if (hit <= 160) {
            std::ostringstream oss;
            oss << "[readfile " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " pos_before=0x" << position_before.value_or(0)
                << " pos_after=0x" << position_after.value_or(0)
                << " requested=0x" << bytes_to_read
                << " transferred=0x" << transferred
                << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
                << " virtual=" << std::dec << static_cast<int>(virtual_payload.has_value())
                << std::hex
                << " result=" << std::dec << static_cast<int>(result)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n";

            if (result != 0 && transferred != 0 && buffer != nullptr) {
                const auto preview_count = static_cast<size_t>(transferred > 0x20 ? 0x20 : transferred);
                oss << "preview=" << dump_bytes(buffer, preview_count) << "\n\n";
            } else {
                oss << "preview=<none>\n\n";
            }

            append_log_line(oss.str());
        }
    }

    if (virtual_payload.has_value()) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_set_file_pointer_ex(
    HANDLE file,
    LARGE_INTEGER distance_to_move,
    PLARGE_INTEGER new_file_pointer,
    DWORD move_method) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto position_before = tracked_path.has_value() ? lookup_pak_handle_position(file) : std::nullopt;
    const auto size_hint = tracked_path.has_value() ? lookup_pak_handle_size(file) : std::nullopt;
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;

    if (is_virtual) {
        std::optional<uint64_t> resolved = std::nullopt;
        switch (move_method) {
        case FILE_BEGIN:
            if (distance_to_move.QuadPart >= 0) {
                resolved = static_cast<uint64_t>(distance_to_move.QuadPart);
            }
            break;
        case FILE_CURRENT:
            if (position_before.has_value()) {
                resolved = apply_signed_offset(*position_before, distance_to_move.QuadPart);
            }
            break;
        case FILE_END:
            if (size_hint.has_value()) {
                resolved = apply_signed_offset(*size_hint, distance_to_move.QuadPart);
            }
            break;
        default:
            break;
        }

        if (resolved.has_value()) {
            set_pak_handle_position(file, *resolved);
            if (!virtual_state->synthetic_handle) {
                LARGE_INTEGER sync_offset{};
                sync_offset.QuadPart = static_cast<LONGLONG>(*resolved);
                if (g_original_set_file_pointer_ex(file, sync_offset, nullptr, FILE_BEGIN) == 0) {
                    last_error = GetLastError();
                    result = FALSE;
                } else {
                    result = TRUE;
                }
            } else {
                result = TRUE;
            }
            if (new_file_pointer != nullptr) {
                new_file_pointer->QuadPart = static_cast<LONGLONG>(*resolved);
            }
        } else {
            last_error = ERROR_NEGATIVE_SEEK;
            result = FALSE;
        }
    } else {
        result = g_original_set_file_pointer_ex(file, distance_to_move, new_file_pointer, move_method);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_set_file_pointer_hits.fetch_add(1) + 1;
        std::optional<uint64_t> position_after = std::nullopt;

        if (result != 0) {
            if (new_file_pointer != nullptr) {
                position_after = static_cast<uint64_t>(new_file_pointer->QuadPart);
            } else if (position_before.has_value()) {
                switch (move_method) {
                case FILE_BEGIN:
                    if (distance_to_move.QuadPart >= 0) {
                        position_after = static_cast<uint64_t>(distance_to_move.QuadPart);
                    }
                    break;
                case FILE_CURRENT:
                    position_after = apply_signed_offset(*position_before, distance_to_move.QuadPart);
                    break;
                case FILE_END:
                    if (size_hint.has_value()) {
                        position_after = apply_signed_offset(*size_hint, distance_to_move.QuadPart);
                    }
                    break;
                default:
                    break;
                }
            }

            if (position_after.has_value()) {
                set_pak_handle_position(file, *position_after);
            }
        }

        if (hit <= 120) {
            std::ostringstream oss;
            oss << "[setfilepointer " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " pos_before=0x" << position_before.value_or(0)
                << " move=0x" << static_cast<uint64_t>(distance_to_move.QuadPart)
                << " method=0x" << move_method
                << " new_pos=0x" << (new_file_pointer != nullptr ? static_cast<uint64_t>(new_file_pointer->QuadPart) : 0ULL)
                << " pos_after=0x" << position_after.value_or(0)
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << std::hex
                << " result=" << std::dec << static_cast<int>(result)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_get_file_size_ex(HANDLE file, PLARGE_INTEGER file_size) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_payload = tracked_path.has_value() ? lookup_virtual_payload(file) : std::nullopt;

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;

    if (virtual_payload.has_value()) {
        if (file_size != nullptr) {
            file_size->QuadPart = static_cast<LONGLONG>((*virtual_payload)->size());
        }
        result = TRUE;
    } else {
        result = g_original_get_file_size_ex(file, file_size);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_get_file_size_hits.fetch_add(1) + 1;
        const auto size = (result != 0 && file_size != nullptr) ? static_cast<uint64_t>(file_size->QuadPart) : 0ULL;
        if (result != 0 && file_size != nullptr) {
            set_pak_handle_size(file, size);
        }

        if (hit <= 120) {
            std::ostringstream oss;
            oss << "[getfilesizeex " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " size=0x" << size
                << " virtual=" << std::dec << static_cast<int>(virtual_payload.has_value())
                << std::hex
                << " result=" << std::dec << static_cast<int>(result)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (virtual_payload.has_value()) {
        SetLastError(last_error);
    }

    return result;
}

DWORD WINAPI hooked_get_file_type(HANDLE file) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    DWORD result{};
    DWORD last_error = ERROR_SUCCESS;
    if (is_virtual) {
        if (virtual_state->synthetic_handle) {
            result = FILE_TYPE_DISK;
        } else {
            result = g_original_get_file_type(file);
            last_error = result == FILE_TYPE_UNKNOWN ? GetLastError() : ERROR_SUCCESS;
        }
    } else {
        result = g_original_get_file_type(file);
        last_error = result == FILE_TYPE_UNKNOWN ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_get_file_type_hits.fetch_add(1) + 1;
        if (hit <= 120) {
            std::ostringstream oss;
            oss << "[getfiletype " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << std::hex
                << " type=0x" << result
                << " last_error=" << std::dec << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_get_file_information_by_handle(HANDLE file, LPBY_HANDLE_FILE_INFORMATION file_information) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    if (is_virtual) {
        if (!virtual_state->synthetic_handle) {
            result = g_original_get_file_information_by_handle(file, file_information);
            last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
            if (result != 0) {
                patch_virtual_by_handle_file_information(file, file_information);
            } else {
                result = fill_virtual_by_handle_file_information(file, file_information) ? TRUE : FALSE;
                last_error = result != 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
            }
        } else {
            result = fill_virtual_by_handle_file_information(file, file_information) ? TRUE : FALSE;
            last_error = result != 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
        }
    } else {
        result = g_original_get_file_information_by_handle(file, file_information);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_get_file_info_hits.fetch_add(1) + 1;
        if (hit <= 120) {
            std::ostringstream oss;
            oss << "[getfileinfo " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << std::hex;
            if (result != 0 && file_information != nullptr) {
                const auto size = (static_cast<uint64_t>(file_information->nFileSizeHigh) << 32) | file_information->nFileSizeLow;
                const auto file_id = (static_cast<uint64_t>(file_information->nFileIndexHigh) << 32) | file_information->nFileIndexLow;
                oss << " attrs=0x" << file_information->dwFileAttributes
                    << " size=0x" << size
                    << " file_id=0x" << file_id;
            }
            oss << std::dec
                << " result=" << static_cast<int>(result)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_get_file_information_by_handle_ex(
    HANDLE file,
    FILE_INFO_BY_HANDLE_CLASS file_information_class,
    LPVOID file_information,
    DWORD buffer_size) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    if (is_virtual) {
        if (!virtual_state->synthetic_handle) {
            result = g_original_get_file_information_by_handle_ex(file, file_information_class, file_information, buffer_size);
            last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
            if (result != 0) {
                patch_virtual_file_information_by_handle_ex(
                    file,
                    file_information_class,
                    file_information,
                    buffer_size,
                    &last_error);
            } else {
                result = fill_virtual_file_information_by_handle_ex(
                    file,
                    file_information_class,
                    file_information,
                    buffer_size,
                    &last_error) ? TRUE : FALSE;
            }
        } else {
            result = fill_virtual_file_information_by_handle_ex(
                file,
                file_information_class,
                file_information,
                buffer_size,
                &last_error) ? TRUE : FALSE;
        }
    } else {
        result = g_original_get_file_information_by_handle_ex(file, file_information_class, file_information, buffer_size);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_get_file_info_ex_hits.fetch_add(1) + 1;
        if (hit <= 160) {
            std::ostringstream oss;
            oss << "[getfileinfoex " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " class=0x" << static_cast<uint32_t>(file_information_class)
                << " size=0x" << buffer_size
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << " result=" << static_cast<int>(result)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

NTSTATUS NTAPI hooked_nt_query_information_file(
    HANDLE file_handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    FILE_INFORMATION_CLASS file_information_class) {
    const auto tracked_path = lookup_pak_handle_path(file_handle);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file_handle) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    NTSTATUS status{};
    if (is_virtual) {
        if (!virtual_state->synthetic_handle) {
            status = g_original_nt_query_information_file(
                file_handle,
                io_status_block,
                file_information,
                length,
                file_information_class);
            if (status == 0) {
                status = patch_virtual_nt_query_information_file(
                    file_handle,
                    io_status_block,
                    file_information,
                    length,
                    file_information_class);
            } else {
                status = fill_virtual_nt_query_information_file(
                    file_handle,
                    io_status_block,
                    file_information,
                    length,
                    file_information_class);
            }
        } else {
            status = fill_virtual_nt_query_information_file(
                file_handle,
                io_status_block,
                file_information,
                length,
                file_information_class);
        }
    } else {
        status = g_original_nt_query_information_file(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class);
    }

    if (tracked_path.has_value()) {
        const auto hit = g_nt_query_info_hits.fetch_add(1) + 1;
        if (hit <= 160) {
            std::ostringstream oss;
            oss << "[ntqueryinfo " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file_handle)
                << " class=0x" << static_cast<uint32_t>(file_information_class)
                << " length=0x" << length
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << std::hex
                << " status=0x" << static_cast<uint32_t>(status);
            if (io_status_block != nullptr) {
                oss << " iosb_status=0x" << static_cast<uint32_t>(io_status_block->Status)
                    << " iosb_info=0x" << static_cast<uint64_t>(io_status_block->Information);
            }
            oss << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    return status;
}

HANDLE WINAPI hooked_create_file_mapping_w(
    HANDLE file,
    LPSECURITY_ATTRIBUTES file_mapping_attributes,
    DWORD protect,
    DWORD maximum_size_high,
    DWORD maximum_size_low,
    LPCWSTR name) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_payload = tracked_path.has_value() ? lookup_virtual_payload(file) : std::nullopt;
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;

    HANDLE result{};
    DWORD last_error = ERROR_SUCCESS;

    if (virtual_payload.has_value()) {
        if (virtual_state.has_value() && !virtual_state->synthetic_handle) {
            result = g_original_create_file_mapping_w(
                file,
                file_mapping_attributes,
                protect,
                maximum_size_high,
                maximum_size_low,
                name);
            last_error = result == nullptr ? GetLastError() : ERROR_SUCCESS;
            if (result != nullptr) {
                result = create_virtual_mapping_handle(*tracked_path, *virtual_payload, result);
            } else {
                result = create_virtual_mapping_handle(*tracked_path, *virtual_payload);
            }
        } else {
            result = create_virtual_mapping_handle(*tracked_path, *virtual_payload);
        }
    } else {
        result = g_original_create_file_mapping_w(
            file,
            file_mapping_attributes,
            protect,
            maximum_size_high,
            maximum_size_low,
            name);
        last_error = result == nullptr ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        if (result != nullptr && !virtual_payload.has_value()) {
            track_mapping_handle(result, *tracked_path);
        }

        const auto hit = g_create_file_mapping_hits.fetch_add(1) + 1;
        if (hit <= 80) {
            std::ostringstream oss;
            oss << "[createfilemapping " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " file=0x" << handle_key(file)
                << " mapping=0x" << handle_key(result)
                << " protect=0x" << protect
                << " max_high=0x" << maximum_size_high
                << " max_low=0x" << maximum_size_low
                << " virtual=" << std::dec << static_cast<int>(virtual_payload.has_value())
                << std::hex
                << " result=" << std::dec << (result != nullptr ? 1 : 0)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (virtual_payload.has_value()) {
        SetLastError(last_error);
    }

    return result;
}

LPVOID WINAPI hooked_map_view_of_file(
    HANDLE file_mapping_object,
    DWORD desired_access,
    DWORD file_offset_high,
    DWORD file_offset_low,
    SIZE_T number_of_bytes_to_map) {
    const auto tracked_path = lookup_mapping_handle_path(file_mapping_object);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_mapping = tracked_path.has_value() ? lookup_virtual_mapping(file_mapping_object) : std::nullopt;

    LPVOID result{};
    DWORD last_error = ERROR_SUCCESS;

    if (virtual_mapping.has_value()) {
        const auto offset = (static_cast<uint64_t>(file_offset_high) << 32) | file_offset_low;
        const auto payload = virtual_mapping->payload;
        if (payload != nullptr && offset <= payload->size()) {
            result = payload->data() + static_cast<size_t>(offset);
        } else {
            last_error = ERROR_INVALID_PARAMETER;
        }
    } else {
        result = g_original_map_view_of_file(
            file_mapping_object,
            desired_access,
            file_offset_high,
            file_offset_low,
            number_of_bytes_to_map);
        last_error = result == nullptr ? GetLastError() : ERROR_SUCCESS;
    }

    if (tracked_path.has_value()) {
        const auto hit = g_map_view_of_file_hits.fetch_add(1) + 1;
        if (hit <= 80) {
            const auto offset = (static_cast<uint64_t>(file_offset_high) << 32) | file_offset_low;
            std::ostringstream oss;
            oss << "[mapviewoffile " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " mapping=0x" << handle_key(file_mapping_object)
                << " access=0x" << desired_access
                << " offset=0x" << offset
                << " bytes=0x" << static_cast<uint64_t>(number_of_bytes_to_map)
                << " view=0x" << reinterpret_cast<uintptr_t>(result)
                << " virtual=" << std::dec << static_cast<int>(virtual_mapping.has_value())
                << std::hex
                << " result=" << std::dec << (result != nullptr ? 1 : 0)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (virtual_mapping.has_value()) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_close_handle(HANDLE object) {
    const auto pak_path = lookup_pak_handle_path(object);
    const auto pak_position = lookup_pak_handle_position(object);
    const auto pak_size = lookup_pak_handle_size(object);
    const auto mapping_path = lookup_mapping_handle_path(object);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_pak_state = lookup_virtual_pak_state(object);
    const auto virtual_mapping_state = lookup_virtual_mapping(object);
    const auto is_virtual = virtual_pak_state.has_value() || virtual_mapping_state.has_value();
    const auto close_real_handle =
        (virtual_pak_state.has_value() && !virtual_pak_state->synthetic_handle) ||
        (virtual_mapping_state.has_value() && !virtual_mapping_state->synthetic_handle);

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    if (is_virtual && !close_real_handle) {
        result = TRUE;
    } else {
        result = g_original_close_handle(object);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (pak_path.has_value() || mapping_path.has_value()) {
        const auto hit = g_close_handle_hits.fetch_add(1) + 1;
        std::ostringstream oss;
        oss << "[closehandle " << hit << "]"
            << describe_caller(caller)
            << std::hex
            << " handle=0x" << handle_key(object)
            << " virtual=" << std::dec << static_cast<int>(is_virtual)
            << std::hex
            << " result=" << std::dec << static_cast<int>(result)
            << " last_error=" << last_error
            << "\n";

        if (pak_path.has_value()) {
            oss << "pak_path=" << narrow_utf8(*pak_path) << "\n";
            oss << std::hex
                << "pak_pos=0x" << pak_position.value_or(0)
                << " pak_size=0x" << pak_size.value_or(0)
                << std::dec << "\n";
        }

        if (mapping_path.has_value()) {
            oss << "mapping_path=" << narrow_utf8(*mapping_path) << "\n";
        }

        oss << "\n";
        append_log_line(oss.str());
        untrack_close_handle(object);
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

int64_t __fastcall hooked_directstorage_open(void* rcx, const void* rdx, void* r8, void* r9) {
    const auto extracted_path = extract_directstorage_path(rdx);
    const auto is_focus_pak = extracted_path.has_value() && path_matches_focus_target(*extracted_path);
    const auto is_virtual_target = extracted_path.has_value() && path_matches_virtual_target(*extracted_path);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());

    uint64_t rdx_first_qword{};
    const auto has_rdx_first_qword = rdx != nullptr && read_u64_safe(rdx, &rdx_first_qword) && rdx_first_qword != 0;

    std::optional<std::wstring> nested_text{};
    if (!extracted_path.has_value() && has_rdx_first_qword) {
        const auto* nested_ptr = reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(rdx_first_qword));
        if (looks_like_wide_string_at(nested_ptr)) {
            nested_text = read_wide_string_safe(nested_ptr);
        }
    }

    std::optional<uint64_t> rcx_vtable{};
    if (rcx != nullptr) {
        uint64_t value{};
        if (read_u64_safe(rcx, &value) && value != 0) {
            rcx_vtable = value;
        }
    }

    std::optional<uint64_t> r8_first_qword{};
    if (r8 != nullptr) {
        uint64_t value{};
        if (read_u64_safe(r8, &value) && value != 0) {
            r8_first_qword = value;
        }
    }

    if (is_focus_pak) {
        const auto seq = g_sequence.fetch_add(1) + 1;
        const auto directstorage_hits = g_directstorage_hits.fetch_add(1) + 1;

        std::ostringstream before;
        before << "[directstorage " << seq << "]"
               << " directstorage_hits=" << std::dec << directstorage_hits
               << describe_caller(caller)
               << std::hex
               << " rcx=0x" << reinterpret_cast<uintptr_t>(rcx)
               << " rdx=0x" << reinterpret_cast<uintptr_t>(rdx)
               << " r8=0x" << reinterpret_cast<uintptr_t>(r8)
               << " r9=0x" << reinterpret_cast<uintptr_t>(r9)
               << "\n"
               << "path=" << narrow_utf8(*extracted_path)
               << "\n"
               << "rdx-desc=" << describe_directstorage_arg(rdx)
               << "\n"
               << "rcx-vtable=0x" << rcx_vtable.value_or(0)
               << " rdx-qword0=0x" << (has_rdx_first_qword ? rdx_first_qword : 0ULL)
               << " r8-qword0=0x" << r8_first_qword.value_or(0)
               << "\n"
               << "rdx-bytes=" << dump_bytes(rdx, 0x40)
               << "\n";

        if (has_rdx_first_qword) {
            before << "rdx-qword0-bytes=" << dump_bytes(reinterpret_cast<const void*>(static_cast<uintptr_t>(rdx_first_qword)), 0x40) << "\n";
        }

        if (nested_text.has_value()) {
            before << "rdx-qword0-text=" << narrow_utf8(*nested_text) << "\n";
        }

        before << "\n";
        append_log_line(before.str());
    }

    auto forwarded_rdx = rdx;
    auto redirected_directstorage = false;
    if (is_virtual_target) {
        const auto runtime_source_path = current_virtual_source_path();
        if (runtime_source_path.has_value()) {
            t_redirect_source_path_storage = *runtime_source_path;

            const auto* direct_text = reinterpret_cast<const wchar_t*>(rdx);
            if (looks_like_wide_string_at(direct_text)) {
                forwarded_rdx = t_redirect_source_path_storage.c_str();
                redirected_directstorage = true;
            } else if (rdx != nullptr) {
                if (read_memory_block_safe(rdx, t_redirect_directstorage_arg_shadow.data(), t_redirect_directstorage_arg_shadow.size())) {
                    *reinterpret_cast<uint64_t*>(t_redirect_directstorage_arg_shadow.data()) =
                        reinterpret_cast<uint64_t>(t_redirect_source_path_storage.c_str());
                    forwarded_rdx = t_redirect_directstorage_arg_shadow.data();
                    redirected_directstorage = true;
                }
            }

            if (redirected_directstorage) {
                std::ostringstream oss;
                oss << "directstorage-redirect"
                    << " requested=" << narrow_utf8(*extracted_path)
                    << " staged=" << narrow_utf8(*runtime_source_path)
                    << "\n";
                append_log_line(oss.str());
            }
        }
    }

    const auto result = g_original_directstorage_open(rcx, forwarded_rdx, r8, r9);

    if (is_focus_pak) {
        std::ostringstream after;
        after << "directstorage-result"
              << " ret=0x" << std::hex << static_cast<uint64_t>(result)
              << "\n\n";
        append_log_line(after.str());
    }

    return result;
}

bool install_create_file_hook() {
    if (g_create_file_hook_installed.load()) {
        return true;
    }

    if (!ensure_minhook_initialized()) {
        return false;
    }

    const auto kernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (kernel32 == nullptr) {
        append_log_line("kernel32-missing\n");
        return false;
    }

    if (g_create_file_target == nullptr) {
        g_create_file_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "CreateFileW"));
    }

    const auto installed = install_named_hook(
        g_create_file_target,
        reinterpret_cast<void*>(&hooked_create_file_w),
        reinterpret_cast<void**>(&g_original_create_file_w),
        "CreateFileW");
    g_create_file_hook_installed = installed;

    if (installed) {
        append_log_line("hook-installed target=CreateFileW\n");
    }

    return installed;
}

bool install_pak_io_hooks() {
    if (!ensure_minhook_initialized()) {
        return false;
    }

    const auto kernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (kernel32 == nullptr) {
        append_log_line("kernel32-missing-io\n");
        return false;
    }
    const auto ntdll = GetModuleHandleW(L"NTDLL.DLL");
    if (ntdll == nullptr) {
        append_log_line("ntdll-missing-io\n");
        return false;
    }

    if (g_read_file_target == nullptr) {
        g_read_file_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "ReadFile"));
    }
    if (g_set_file_pointer_ex_target == nullptr) {
        g_set_file_pointer_ex_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "SetFilePointerEx"));
    }
    if (g_get_file_size_ex_target == nullptr) {
        g_get_file_size_ex_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "GetFileSizeEx"));
    }
    if (g_get_file_type_target == nullptr) {
        g_get_file_type_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "GetFileType"));
    }
    if (g_get_file_information_by_handle_target == nullptr) {
        g_get_file_information_by_handle_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "GetFileInformationByHandle"));
    }
    if (g_get_file_information_by_handle_ex_target == nullptr) {
        g_get_file_information_by_handle_ex_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "GetFileInformationByHandleEx"));
    }
    if (g_create_file_mapping_w_target == nullptr) {
        g_create_file_mapping_w_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "CreateFileMappingW"));
    }
    if (g_map_view_of_file_target == nullptr) {
        g_map_view_of_file_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "MapViewOfFile"));
    }
    if (g_close_handle_target == nullptr) {
        g_close_handle_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "CloseHandle"));
    }
    if (g_nt_query_information_file_target == nullptr) {
        g_nt_query_information_file_target = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQueryInformationFile"));
    }

    auto ok = true;

    const auto read_file_ok = install_named_hook(
        g_read_file_target,
        reinterpret_cast<void*>(&hooked_read_file),
        reinterpret_cast<void**>(&g_original_read_file),
        "ReadFile");
    if (read_file_ok) {
        append_log_line("hook-installed target=ReadFile\n");
    } else {
        ok = false;
    }

    const auto set_file_pointer_ok = install_named_hook(
        g_set_file_pointer_ex_target,
        reinterpret_cast<void*>(&hooked_set_file_pointer_ex),
        reinterpret_cast<void**>(&g_original_set_file_pointer_ex),
        "SetFilePointerEx");
    if (set_file_pointer_ok) {
        append_log_line("hook-installed target=SetFilePointerEx\n");
    } else {
        ok = false;
    }

    const auto get_file_size_ok = install_named_hook(
        g_get_file_size_ex_target,
        reinterpret_cast<void*>(&hooked_get_file_size_ex),
        reinterpret_cast<void**>(&g_original_get_file_size_ex),
        "GetFileSizeEx");
    if (get_file_size_ok) {
        append_log_line("hook-installed target=GetFileSizeEx\n");
    } else {
        ok = false;
    }

    const auto get_file_type_ok = install_named_hook(
        g_get_file_type_target,
        reinterpret_cast<void*>(&hooked_get_file_type),
        reinterpret_cast<void**>(&g_original_get_file_type),
        "GetFileType");
    if (get_file_type_ok) {
        append_log_line("hook-installed target=GetFileType\n");
    } else {
        ok = false;
    }

    const auto get_file_info_ok = install_named_hook(
        g_get_file_information_by_handle_target,
        reinterpret_cast<void*>(&hooked_get_file_information_by_handle),
        reinterpret_cast<void**>(&g_original_get_file_information_by_handle),
        "GetFileInformationByHandle");
    if (get_file_info_ok) {
        append_log_line("hook-installed target=GetFileInformationByHandle\n");
    } else {
        ok = false;
    }

    const auto get_file_info_ex_ok = install_named_hook(
        g_get_file_information_by_handle_ex_target,
        reinterpret_cast<void*>(&hooked_get_file_information_by_handle_ex),
        reinterpret_cast<void**>(&g_original_get_file_information_by_handle_ex),
        "GetFileInformationByHandleEx");
    if (get_file_info_ex_ok) {
        append_log_line("hook-installed target=GetFileInformationByHandleEx\n");
    } else {
        ok = false;
    }

    const auto create_file_mapping_ok = install_named_hook(
        g_create_file_mapping_w_target,
        reinterpret_cast<void*>(&hooked_create_file_mapping_w),
        reinterpret_cast<void**>(&g_original_create_file_mapping_w),
        "CreateFileMappingW");
    if (create_file_mapping_ok) {
        append_log_line("hook-installed target=CreateFileMappingW\n");
    } else {
        ok = false;
    }

    const auto map_view_ok = install_named_hook(
        g_map_view_of_file_target,
        reinterpret_cast<void*>(&hooked_map_view_of_file),
        reinterpret_cast<void**>(&g_original_map_view_of_file),
        "MapViewOfFile");
    if (map_view_ok) {
        append_log_line("hook-installed target=MapViewOfFile\n");
    } else {
        ok = false;
    }

    const auto close_handle_ok = install_named_hook(
        g_close_handle_target,
        reinterpret_cast<void*>(&hooked_close_handle),
        reinterpret_cast<void**>(&g_original_close_handle),
        "CloseHandle");
    if (close_handle_ok) {
        append_log_line("hook-installed target=CloseHandle\n");
    } else {
        ok = false;
    }

    const auto nt_query_info_ok = install_named_hook(
        g_nt_query_information_file_target,
        reinterpret_cast<void*>(&hooked_nt_query_information_file),
        reinterpret_cast<void**>(&g_original_nt_query_information_file),
        "NtQueryInformationFile");
    if (nt_query_info_ok) {
        append_log_line("hook-installed target=NtQueryInformationFile\n");
    } else {
        ok = false;
    }

    std::ostringstream oss;
    oss << "pak-io-hooks"
        << " readfile=" << static_cast<int>(read_file_ok)
        << " setfilepointer=" << static_cast<int>(set_file_pointer_ok)
        << " getfilesize=" << static_cast<int>(get_file_size_ok)
        << " getfiletype=" << static_cast<int>(get_file_type_ok)
        << " getfileinfo=" << static_cast<int>(get_file_info_ok)
        << " getfileinfoex=" << static_cast<int>(get_file_info_ex_ok)
        << " createfilemapping=" << static_cast<int>(create_file_mapping_ok)
        << " mapview=" << static_cast<int>(map_view_ok)
        << " closehandle=" << static_cast<int>(close_handle_ok)
        << " ntqueryinfo=" << static_cast<int>(nt_query_info_ok)
        << "\n";
    append_log_line(oss.str());

    return ok;
}

bool install_directstorage_hook() {
    if (g_directstorage_hook_installed.load()) {
        return true;
    }

    if (!ensure_minhook_initialized()) {
        return false;
    }

    if (!resolve_directstorage_target_once()) {
        return false;
    }

    const auto installed = install_named_hook(
        g_directstorage_target,
        reinterpret_cast<void*>(&hooked_directstorage_open),
        reinterpret_cast<void**>(&g_original_directstorage_open),
        "DirectStorageOpenPak");
    g_directstorage_hook_installed = installed;

    if (installed) {
        append_log_line("hook-installed target=DirectStorageOpenPak\n");
    }

    return installed;
}

} // namespace mhwilds::probe

