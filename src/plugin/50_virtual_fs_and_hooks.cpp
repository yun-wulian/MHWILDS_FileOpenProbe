#include "plugin_internal.hpp"

namespace mhwilds::probe {

namespace {

constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0x00000000);
constexpr NTSTATUS kStatusPending = static_cast<NTSTATUS>(0x00000103);
constexpr NTSTATUS kStatusUnsuccessful = static_cast<NTSTATUS>(0xC0000001u);

struct VirtualReadResult {
    bool ok{};
    DWORD transferred{};
    DWORD last_error{ERROR_SUCCESS};
};

struct ReadFileExApcContext {
    uint64_t request_id{};
    uint64_t flow_id{};
    HANDLE file{};
    HANDLE target_thread_handle{};
    DWORD issuing_thread_id{};
    std::string path_utf8{};
    void* buffer{};
    std::vector<uint8_t> staged_bytes{};
    uint64_t read_offset{};
    DWORD requested{};
    bool is_virtual{};
    LPOVERLAPPED_COMPLETION_ROUTINE completion_routine{};
    LPOVERLAPPED overlapped{};
    DWORD error_code{};
    DWORD transferred{};
};

struct NtReadFileApcContext {
    uint64_t request_id{};
    uint64_t flow_id{};
    HANDLE file{};
    HANDLE target_thread_handle{};
    DWORD issuing_thread_id{};
    HANDLE event{};
    std::string path_utf8{};
    void* buffer{};
    std::vector<uint8_t> staged_bytes{};
    uint64_t read_offset{};
    ULONG requested{};
    bool is_virtual{};
    PIO_APC_ROUTINE apc_routine{};
    PVOID apc_context{};
    PIO_STATUS_BLOCK io_status_block{};
    NTSTATUS final_status{kStatusSuccess};
    ULONG transferred{};
    bool update_position_on_complete{};
    uint64_t next_position{};
};

using NtQueryEventFnLocal = NTSTATUS(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);

struct EventQuerySnapshot {
    bool has_handle{};
    bool queried{};
    NTSTATUS query_status{kStatusUnsuccessful};
    LONG type{-1};
    LONG state{-1};
};

struct OverlappedSnapshot {
    uintptr_t event_raw{};
    uintptr_t event_normalized{};
    bool event_lowbit{};
    EventQuerySnapshot event_query{};
    uint64_t internal{};
    uint64_t internal_high{};
};

struct IoStatusSnapshot {
    bool has_value{};
    NTSTATUS status{kStatusUnsuccessful};
    uint64_t information{};
};

struct PendingOverlappedFlow {
    uint64_t flow_id{};
    const char* api{};
    uint64_t issued_t_ms{};
    uint64_t io_offset{};
    uint64_t requested{};
    bool is_virtual{};
};

std::mutex g_read_file_ex_completion_mutex{};
std::unordered_map<uintptr_t, std::shared_ptr<ReadFileExApcContext>> g_pending_read_file_ex_completions{};
std::deque<std::unique_ptr<ReadFileExApcContext>> g_pending_virtual_read_file_ex_apcs{};
HANDLE g_virtual_read_file_ex_apc_event{};
std::atomic<bool> g_virtual_read_file_ex_apc_thread_started{false};
std::deque<std::unique_ptr<NtReadFileApcContext>> g_pending_virtual_nt_read_file_apcs{};
HANDLE g_virtual_nt_read_file_apc_event{};
std::atomic<bool> g_virtual_nt_read_file_apc_thread_started{false};
std::atomic<uint64_t> g_read_file_ex_completion_hits{0};
std::atomic<uint64_t> g_nt_read_file_completion_hits{0};
std::mutex g_pending_overlapped_flows_mutex{};
std::unordered_map<uintptr_t, PendingOverlappedFlow> g_pending_overlapped_flows{};
std::atomic<uint64_t> g_async_probe_hits{0};
std::atomic<uint64_t> g_virtual_request_id_counter{1};

HANDLE normalize_overlapped_event_handle(const OVERLAPPED* overlapped) {
    if (overlapped == nullptr || overlapped->hEvent == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(overlapped->hEvent) & ~static_cast<uintptr_t>(1));
}

NtQueryEventFnLocal resolve_nt_query_event() {
    static const auto fn = []() -> NtQueryEventFnLocal {
        const auto ntdll = GetModuleHandleW(L"NTDLL.DLL");
        if (ntdll == nullptr) {
            return nullptr;
        }
        return reinterpret_cast<NtQueryEventFnLocal>(GetProcAddress(ntdll, "NtQueryEvent"));
    }();
    return fn;
}

EventQuerySnapshot capture_event_query_snapshot(HANDLE event_handle) {
    EventQuerySnapshot snapshot{};
    snapshot.has_handle = event_handle != nullptr;
    if (event_handle == nullptr) {
        return snapshot;
    }

    const auto nt_query_event = resolve_nt_query_event();
    if (nt_query_event == nullptr) {
        return snapshot;
    }

    struct LocalEventBasicInformation {
        LONG event_type;
        LONG event_state;
    } info{};

    snapshot.queried = true;
    snapshot.query_status = nt_query_event(event_handle, 0, &info, sizeof(info), nullptr);
    if (snapshot.query_status == kStatusSuccess) {
        snapshot.type = info.event_type;
        snapshot.state = info.event_state;
    }
    return snapshot;
}

OverlappedSnapshot capture_overlapped_snapshot(const OVERLAPPED* overlapped) {
    OverlappedSnapshot snapshot{};
    if (overlapped == nullptr) {
        return snapshot;
    }

    const auto normalized_event = normalize_overlapped_event_handle(overlapped);
    snapshot.event_raw = reinterpret_cast<uintptr_t>(overlapped->hEvent);
    snapshot.event_normalized = reinterpret_cast<uintptr_t>(normalized_event);
    snapshot.event_lowbit = snapshot.event_raw != snapshot.event_normalized;
    snapshot.event_query = capture_event_query_snapshot(normalized_event);
    snapshot.internal = static_cast<uint64_t>(overlapped->Internal);
    snapshot.internal_high = static_cast<uint64_t>(overlapped->InternalHigh);
    return snapshot;
}

IoStatusSnapshot capture_io_status_snapshot(PIO_STATUS_BLOCK io_status_block) {
    IoStatusSnapshot snapshot{};
    snapshot.has_value = io_status_block != nullptr;
    if (io_status_block == nullptr) {
        return snapshot;
    }

    snapshot.status = io_status_block->Status;
    snapshot.information = static_cast<uint64_t>(io_status_block->Information);
    return snapshot;
}

uint64_t next_probe_flow_id() {
    return g_sequence.fetch_add(1) + 1;
}

bool should_emit_async_probe() {
    return g_async_probe_hits.fetch_add(1) + 1 <= 1200;
}

void append_async_probe_line(const std::string& line) {
    if (!should_emit_async_probe()) {
        return;
    }
    append_log_line(line);
}

void register_pending_overlapped_flow(
    const OVERLAPPED* overlapped,
    uint64_t flow_id,
    const char* api,
    uint64_t io_offset,
    uint64_t requested,
    bool is_virtual) {
    if (overlapped == nullptr) {
        return;
    }

    PendingOverlappedFlow flow{};
    flow.flow_id = flow_id;
    flow.api = api;
    flow.issued_t_ms = process_uptime_ms();
    flow.io_offset = io_offset;
    flow.requested = requested;
    flow.is_virtual = is_virtual;

    std::scoped_lock _{g_pending_overlapped_flows_mutex};
    g_pending_overlapped_flows[reinterpret_cast<uintptr_t>(overlapped)] = flow;
}

std::optional<PendingOverlappedFlow> lookup_pending_overlapped_flow(const OVERLAPPED* overlapped) {
    if (overlapped == nullptr) {
        return std::nullopt;
    }

    std::scoped_lock _{g_pending_overlapped_flows_mutex};
    const auto it = g_pending_overlapped_flows.find(reinterpret_cast<uintptr_t>(overlapped));
    if (it == g_pending_overlapped_flows.end()) {
        return std::nullopt;
    }
    return it->second;
}

void retire_pending_overlapped_flow(const OVERLAPPED* overlapped) {
    if (overlapped == nullptr) {
        return;
    }

    std::scoped_lock _{g_pending_overlapped_flows_mutex};
    g_pending_overlapped_flows.erase(reinterpret_cast<uintptr_t>(overlapped));
}

void append_event_query_fields(std::ostringstream& oss, const char* prefix, const EventQuerySnapshot& snapshot) {
    oss << " " << prefix << "_has=" << static_cast<int>(snapshot.has_handle)
        << " " << prefix << "_queried=" << static_cast<int>(snapshot.queried);
    if (!snapshot.has_handle || !snapshot.queried) {
        return;
    }

    oss << std::hex
        << " " << prefix << "_query_status=0x" << static_cast<uint32_t>(snapshot.query_status)
        << std::dec;
    if (snapshot.query_status == kStatusSuccess) {
        oss << " " << prefix << "_type=" << snapshot.type
            << " " << prefix << "_state=" << snapshot.state;
    }
}

uint64_t next_virtual_request_id() {
    return g_virtual_request_id_counter.fetch_add(1);
}

void publish_staged_virtual_read_buffer(const void* staged_bytes, size_t staged_size, void* target_buffer) {
    if (staged_bytes == nullptr || staged_size == 0 || target_buffer == nullptr) {
        return;
    }

    std::memcpy(target_buffer, staged_bytes, staged_size);
}

void finalize_virtual_read_file_ex_completion(ReadFileExApcContext& context) {
    if (context.error_code == ERROR_SUCCESS && !context.staged_bytes.empty()) {
        publish_staged_virtual_read_buffer(
            context.staged_bytes.data(),
            std::min<size_t>(context.staged_bytes.size(), context.transferred),
            context.buffer);
    }

    if (context.overlapped != nullptr) {
        context.overlapped->Internal = static_cast<ULONG_PTR>(
            context.error_code == ERROR_SUCCESS ? kStatusSuccess : kStatusUnsuccessful);
        context.overlapped->InternalHigh = context.error_code == ERROR_SUCCESS ? context.transferred : 0;
        if (const auto event_handle = normalize_overlapped_event_handle(context.overlapped); event_handle != nullptr) {
            SetEvent(event_handle);
        }
    }
}

void finalize_virtual_nt_read_file_completion(NtReadFileApcContext& context) {
    if (context.final_status == kStatusSuccess && !context.staged_bytes.empty()) {
        publish_staged_virtual_read_buffer(
            context.staged_bytes.data(),
            std::min<size_t>(context.staged_bytes.size(), context.transferred),
            context.buffer);
    }

    if (context.io_status_block != nullptr) {
        context.io_status_block->Status = context.final_status;
        context.io_status_block->Information = context.final_status == kStatusSuccess ? context.transferred : 0;
    }

    if (context.update_position_on_complete) {
        set_pak_handle_position(context.file, context.next_position);
    }

    if (context.event != nullptr) {
        SetEvent(context.event);
    }
}

VirtualReadResult service_virtual_read(
    HANDLE file,
    const std::optional<VirtualPakHandleState>& virtual_state,
    const std::optional<std::shared_ptr<std::vector<uint8_t>>>& virtual_payload,
    uint64_t read_offset,
    void* buffer,
    DWORD bytes_to_read) {
    VirtualReadResult result{};
    result.last_error = ERROR_INVALID_DATA;

    if (!virtual_state.has_value()) {
        return result;
    }

    if (virtual_payload.has_value()) {
        const auto payload = *virtual_payload;
        if (read_offset < payload->size()) {
            const auto remaining = payload->size() - static_cast<size_t>(read_offset);
            result.transferred = static_cast<DWORD>(std::min<size_t>(remaining, bytes_to_read));
            if (result.transferred != 0 && buffer != nullptr) {
                std::memcpy(buffer, payload->data() + read_offset, result.transferred);
            }
        }

        result.ok = true;
        result.last_error = ERROR_SUCCESS;
        return result;
    }

    if (virtual_state->random_access_view != nullptr) {
        const auto read_result = read_virtual_pak_view_bytes(
            virtual_state->random_access_view,
            read_offset,
            buffer,
            bytes_to_read);
        if (!read_result.has_value()) {
            return result;
        }

        result.ok = true;
        result.transferred = static_cast<DWORD>(*read_result);
        result.last_error = ERROR_SUCCESS;
        return result;
    }

    std::ostringstream oss;
    oss << "virtual-loader-read-state-invalid handle=0x" << std::hex << handle_key(file) << "\n";
    append_log_line(oss.str());
    return result;
}

void update_virtual_sync_backing_position(
    HANDLE file,
    const std::optional<VirtualPakHandleState>& virtual_state,
    uint64_t next_offset,
    DWORD* last_error) {
    (void)virtual_state;
    (void)last_error;
    set_pak_handle_position(file, next_offset);
}

VOID CALLBACK dispatch_read_file_ex_apc(ULONG_PTR parameter) {
    std::unique_ptr<ReadFileExApcContext> context(reinterpret_cast<ReadFileExApcContext*>(parameter));
    if (context == nullptr) {
        return;
    }

    const auto overlapped_before = capture_overlapped_snapshot(context->overlapped);
    finalize_virtual_read_file_ex_completion(*context);
    const auto overlapped_after = capture_overlapped_snapshot(context->overlapped);

    const auto hit = g_read_file_ex_completion_hits.fetch_add(1) + 1;
    if (hit <= 240) {
        std::ostringstream oss;
        oss << "[readfileex-complete " << hit << "]"
            << " t_ms=" << std::dec << process_uptime_ms()
            << " request=" << context->request_id
            << " flow=" << context->flow_id
            << std::hex
            << " handle=0x" << handle_key(context->file)
            << " io_offset=0x" << context->read_offset
            << " requested=0x" << context->requested
            << " transferred=0x" << context->transferred
            << " overlapped=0x" << reinterpret_cast<uintptr_t>(context->overlapped)
            << " completion=0x" << reinterpret_cast<uintptr_t>(context->completion_routine)
            << std::dec
            << " delivery=synthetic_apc"
            << " virtual=" << static_cast<int>(context->is_virtual)
            << " issue_thread=" << context->issuing_thread_id
            << " error_code=" << context->error_code
            << " thread_id=" << GetCurrentThreadId()
            << std::hex
            << " overlapped_internal_before=0x" << overlapped_before.internal
            << " overlapped_high_before=0x" << overlapped_before.internal_high
            << " overlapped_internal_after=0x" << overlapped_after.internal
            << " overlapped_high_after=0x" << overlapped_after.internal_high
            << " event_raw=0x" << overlapped_after.event_raw
            << " event_norm=0x" << overlapped_after.event_normalized
            << std::dec
            << " event_lowbit=" << static_cast<int>(overlapped_after.event_lowbit)
            << "\n"
            << "path=" << context->path_utf8
            << "\n";
        append_event_query_fields(oss, "event_before", overlapped_before.event_query);
        append_event_query_fields(oss, "event_after", overlapped_after.event_query);
        oss << "\n";

        oss << '\n';
        append_log_line(oss.str());
        if (context->error_code == ERROR_SUCCESS && context->transferred != 0 && context->buffer != nullptr) {
            append_read_bytes_log_bytes(context->buffer, context->transferred);
        }
    }

    if (context->completion_routine != nullptr) {
        context->completion_routine(context->error_code, context->transferred, context->overlapped);
    }
    if (context->target_thread_handle != nullptr) {
        CloseHandle(context->target_thread_handle);
        context->target_thread_handle = nullptr;
    }
}

VOID CALLBACK wrapped_read_file_ex_completion(
    DWORD error_code,
    DWORD transferred,
    LPOVERLAPPED overlapped) {
    const auto overlapped_snapshot = capture_overlapped_snapshot(overlapped);
    std::shared_ptr<ReadFileExApcContext> context{};
    if (overlapped != nullptr) {
        std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
        const auto it = g_pending_read_file_ex_completions.find(reinterpret_cast<uintptr_t>(overlapped));
        if (it != g_pending_read_file_ex_completions.end()) {
            context = it->second;
            g_pending_read_file_ex_completions.erase(it);
        }
    }

    if (context != nullptr) {
        const auto hit = g_read_file_ex_completion_hits.fetch_add(1) + 1;
        if (hit <= 240) {
            std::ostringstream oss;
            oss << "[readfileex-complete " << hit << "]"
                << " t_ms=" << std::dec << process_uptime_ms()
                << " request=" << context->request_id
                << " flow=" << context->flow_id
                << std::hex
                << " handle=0x" << handle_key(context->file)
                << " io_offset=0x" << context->read_offset
                << " requested=0x" << context->requested
                << " transferred=0x" << transferred
                << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
                << " completion=0x" << reinterpret_cast<uintptr_t>(context->completion_routine)
                << std::dec
                << " delivery=wrapped_completion"
                << " virtual=" << static_cast<int>(context->is_virtual)
                << " issue_thread=" << context->issuing_thread_id
                << " error_code=" << error_code
                << " thread_id=" << GetCurrentThreadId()
                << std::hex
                << " overlapped_internal=0x" << overlapped_snapshot.internal
                << " overlapped_high=0x" << overlapped_snapshot.internal_high
                << " event_raw=0x" << overlapped_snapshot.event_raw
                << " event_norm=0x" << overlapped_snapshot.event_normalized
                << std::dec
                << " event_lowbit=" << static_cast<int>(overlapped_snapshot.event_lowbit)
                << "\n"
                << "path=" << context->path_utf8
                << "\n";
            append_event_query_fields(oss, "event", overlapped_snapshot.event_query);
            oss << "\n";

            oss << '\n';
            append_log_line(oss.str());
            if (error_code == ERROR_SUCCESS && transferred != 0 && context->buffer != nullptr) {
                append_read_bytes_log_bytes(context->buffer, transferred);
            }
        }

        if (context->completion_routine != nullptr) {
            context->completion_routine(error_code, transferred, overlapped);
        }
        return;
    }

    std::ostringstream oss;
    oss << "[readfileex-complete-missing]"
        << std::hex
        << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
        << std::dec
        << " error_code=" << error_code
        << " transferred=" << transferred
        << " thread_id=" << GetCurrentThreadId()
        << "\n\n";
    append_log_line(oss.str());
}

VOID CALLBACK dispatch_nt_read_file_apc(ULONG_PTR parameter) {
    std::unique_ptr<NtReadFileApcContext> context(reinterpret_cast<NtReadFileApcContext*>(parameter));
    if (context == nullptr) {
        return;
    }

    const auto iosb_before = capture_io_status_snapshot(context->io_status_block);
    const auto event_before = capture_event_query_snapshot(context->event);
    finalize_virtual_nt_read_file_completion(*context);
    const auto iosb_after = capture_io_status_snapshot(context->io_status_block);
    const auto event_after = capture_event_query_snapshot(context->event);

    const auto hit = g_nt_read_file_completion_hits.fetch_add(1) + 1;
    if (hit <= 240) {
        std::ostringstream oss;
        oss << "[ntreadfile-complete " << hit << "]"
            << " t_ms=" << std::dec << process_uptime_ms()
            << " request=" << context->request_id
            << " flow=" << context->flow_id
            << std::hex
            << " handle=0x" << handle_key(context->file)
            << " io_offset=0x" << context->read_offset
            << " requested=0x" << static_cast<uint64_t>(context->requested)
            << " transferred=0x" << static_cast<uint64_t>(context->transferred)
            << " iosb=0x" << reinterpret_cast<uintptr_t>(context->io_status_block)
            << " apc=0x" << reinterpret_cast<uintptr_t>(context->apc_routine)
            << " apc_ctx=0x" << reinterpret_cast<uintptr_t>(context->apc_context)
            << " event=0x" << reinterpret_cast<uintptr_t>(context->event)
            << " status=0x" << static_cast<uint32_t>(context->final_status)
            << std::dec
            << " virtual=" << static_cast<int>(context->is_virtual)
            << " issue_thread=" << context->issuing_thread_id
            << " thread_id=" << GetCurrentThreadId()
            << std::hex
            << " iosb_status_before=0x" << static_cast<uint32_t>(iosb_before.status)
            << " iosb_info_before=0x" << iosb_before.information
            << " iosb_status_after=0x" << static_cast<uint32_t>(iosb_after.status)
            << " iosb_info_after=0x" << iosb_after.information
            << std::dec
            << "\n"
            << "path=" << context->path_utf8
            << "\n";
        append_event_query_fields(oss, "event_before", event_before);
        append_event_query_fields(oss, "event_after", event_after);
        oss << "\n";

        oss << '\n';
        append_log_line(oss.str());
        if (context->final_status == kStatusSuccess && context->transferred != 0 && context->buffer != nullptr) {
            append_read_bytes_log_bytes(context->buffer, context->transferred);
        }
    }

    if (context->apc_routine != nullptr) {
        context->apc_routine(context->apc_context, context->io_status_block, 0);
    }
    if (context->target_thread_handle != nullptr) {
        CloseHandle(context->target_thread_handle);
        context->target_thread_handle = nullptr;
    }
}

DWORD WINAPI virtual_read_file_ex_completion_thread_proc(LPVOID) {
    while (!g_shutdown_requested.load()) {
        HANDLE event_handle{};
        {
            std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
            event_handle = g_virtual_read_file_ex_apc_event;
        }

        if (event_handle == nullptr) {
            return 0;
        }

        const auto wait_result = WaitForSingleObject(event_handle, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            continue;
        }

        for (;;) {
            std::unique_ptr<ReadFileExApcContext> context{};
            {
                std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
                if (g_pending_virtual_read_file_ex_apcs.empty()) {
                    break;
                }
                context = std::move(g_pending_virtual_read_file_ex_apcs.front());
                g_pending_virtual_read_file_ex_apcs.pop_front();
            }

            if (context == nullptr) {
                continue;
            }

            {
                std::ostringstream oss;
                oss << "[async-probe]"
                    << " t_ms=" << process_uptime_ms()
                    << " stage=readfileex-worker-pop"
                    << " request=" << context->request_id
                    << " flow=" << context->flow_id
                    << std::hex
                    << " handle=0x" << handle_key(context->file)
                    << " io_offset=0x" << context->read_offset
                    << " requested=0x" << context->requested
                    << " overlapped=0x" << reinterpret_cast<uintptr_t>(context->overlapped)
                    << std::dec
                    << " virtual=" << static_cast<int>(context->is_virtual)
                    << "\npath=" << context->path_utf8
                    << "\n\n";
                append_async_probe_line(oss.str());
            }

            // Avoid reentering the caller before the initiating ReadFileEx hook unwinds.
            Sleep(1);

            const auto queued = QueueUserAPC(
                dispatch_read_file_ex_apc,
                context->target_thread_handle,
                reinterpret_cast<ULONG_PTR>(context.get())) != 0;
            const auto queue_last_error = queued ? ERROR_SUCCESS : GetLastError();
            if (!queued) {
                std::ostringstream oss;
                oss << "[readfileex-queue-failed]"
                    << std::hex
                    << " handle=0x" << handle_key(context->file)
                    << " io_offset=0x" << context->read_offset
                    << " requested=0x" << context->requested
                    << " overlapped=0x" << reinterpret_cast<uintptr_t>(context->overlapped)
                    << " completion=0x" << reinterpret_cast<uintptr_t>(context->completion_routine)
                    << std::dec
                    << " virtual=" << static_cast<int>(context->is_virtual)
                    << " last_error=" << queue_last_error
                    << " phase=worker_queue"
                    << "\n"
                    << "path=" << context->path_utf8
                    << "\n\n";
                append_log_line(oss.str());
                if (context->overlapped != nullptr) {
                    context->overlapped->Internal = static_cast<ULONG_PTR>(kStatusUnsuccessful);
                    context->overlapped->InternalHigh = 0;
                }
                if (context->target_thread_handle != nullptr) {
                    CloseHandle(context->target_thread_handle);
                    context->target_thread_handle = nullptr;
                }
                continue;
            }

            {
                std::ostringstream oss;
                oss << "[async-probe]"
                    << " t_ms=" << process_uptime_ms()
                    << " stage=readfileex-worker-apc-queued"
                    << " request=" << context->request_id
                    << " flow=" << context->flow_id
                    << std::hex
                    << " handle=0x" << handle_key(context->file)
                    << " overlapped=0x" << reinterpret_cast<uintptr_t>(context->overlapped)
                    << std::dec
                    << " virtual=" << static_cast<int>(context->is_virtual)
                    << "\npath=" << context->path_utf8
                    << "\n\n";
                append_async_probe_line(oss.str());
            }

            context.release();
        }
    }

    return 0;
}

DWORD WINAPI virtual_nt_read_file_completion_thread_proc(LPVOID) {
    while (!g_shutdown_requested.load()) {
        HANDLE event_handle{};
        {
            std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
            event_handle = g_virtual_nt_read_file_apc_event;
        }

        if (event_handle == nullptr) {
            return 0;
        }

        const auto wait_result = WaitForSingleObject(event_handle, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            continue;
        }

        for (;;) {
            std::unique_ptr<NtReadFileApcContext> context{};
            {
                std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
                if (g_pending_virtual_nt_read_file_apcs.empty()) {
                    break;
                }
                context = std::move(g_pending_virtual_nt_read_file_apcs.front());
                g_pending_virtual_nt_read_file_apcs.pop_front();
            }

            if (context == nullptr) {
                continue;
            }

            {
                std::ostringstream oss;
                oss << "[async-probe]"
                    << " t_ms=" << process_uptime_ms()
                    << " stage=ntreadfile-worker-pop"
                    << " request=" << context->request_id
                    << " flow=" << context->flow_id
                    << std::hex
                    << " handle=0x" << handle_key(context->file)
                    << " io_offset=0x" << context->read_offset
                    << " requested=0x" << static_cast<uint64_t>(context->requested)
                    << " iosb=0x" << reinterpret_cast<uintptr_t>(context->io_status_block)
                    << std::dec
                    << " virtual=" << static_cast<int>(context->is_virtual)
                    << "\npath=" << context->path_utf8
                    << "\n\n";
                append_async_probe_line(oss.str());
            }

            // Let KERNELBASE unwind out of NtReadFile/ReadFileEx before completion is delivered.
            Sleep(1);

            bool completed{};
            DWORD queue_last_error = ERROR_SUCCESS;
            if (context->apc_routine != nullptr) {
                completed = QueueUserAPC(
                    dispatch_nt_read_file_apc,
                    context->target_thread_handle,
                    reinterpret_cast<ULONG_PTR>(context.get())) != 0;
                if (!completed) {
                    queue_last_error = GetLastError();
                }
                if (completed) {
                    std::ostringstream oss;
                    oss << "[async-probe]"
                        << " t_ms=" << process_uptime_ms()
                        << " stage=ntreadfile-worker-apc-queued"
                        << " request=" << context->request_id
                        << " flow=" << context->flow_id
                        << std::hex
                        << " handle=0x" << handle_key(context->file)
                        << " iosb=0x" << reinterpret_cast<uintptr_t>(context->io_status_block)
                        << std::dec
                        << " virtual=" << static_cast<int>(context->is_virtual)
                        << "\npath=" << context->path_utf8
                        << "\n\n";
                    append_async_probe_line(oss.str());
                }
            } else {
                std::ostringstream oss;
                oss << "[async-probe]"
                    << " t_ms=" << process_uptime_ms()
                    << " stage=ntreadfile-worker-direct-dispatch"
                    << " request=" << context->request_id
                    << " flow=" << context->flow_id
                    << std::hex
                    << " handle=0x" << handle_key(context->file)
                    << " iosb=0x" << reinterpret_cast<uintptr_t>(context->io_status_block)
                    << std::dec
                    << " virtual=" << static_cast<int>(context->is_virtual)
                    << "\npath=" << context->path_utf8
                    << "\n\n";
                append_async_probe_line(oss.str());
                dispatch_nt_read_file_apc(reinterpret_cast<ULONG_PTR>(context.release()));
                completed = true;
            }

            if (!completed) {
                std::ostringstream oss;
                oss << "[ntreadfile-queue-failed]"
                    << std::hex
                    << " handle=0x" << handle_key(context->file)
                    << " io_offset=0x" << context->read_offset
                    << " requested=0x" << static_cast<uint64_t>(context->requested)
                    << " iosb=0x" << reinterpret_cast<uintptr_t>(context->io_status_block)
                    << " apc=0x" << reinterpret_cast<uintptr_t>(context->apc_routine)
                    << " apc_ctx=0x" << reinterpret_cast<uintptr_t>(context->apc_context)
                    << " event=0x" << reinterpret_cast<uintptr_t>(context->event)
                    << std::dec
                    << " virtual=" << static_cast<int>(context->is_virtual)
                    << " last_error=" << queue_last_error
                    << "\n"
                    << "path=" << context->path_utf8
                    << "\n\n";
                append_log_line(oss.str());
                context->final_status = kStatusUnsuccessful;
                context->transferred = 0;
                finalize_virtual_nt_read_file_completion(*context);
                if (context->target_thread_handle != nullptr) {
                    CloseHandle(context->target_thread_handle);
                    context->target_thread_handle = nullptr;
                }
                continue;
            }

            if (context != nullptr) {
                context.release();
            }
        }
    }

    return 0;
}

bool ensure_virtual_read_file_ex_worker_started() {
    std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
    if (g_virtual_read_file_ex_apc_event == nullptr) {
        g_virtual_read_file_ex_apc_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (g_virtual_read_file_ex_apc_event == nullptr) {
            return false;
        }
    }

    if (g_virtual_read_file_ex_apc_thread_started.exchange(true)) {
        return true;
    }

    const auto worker_thread = CreateThread(
        nullptr,
        0,
        &virtual_read_file_ex_completion_thread_proc,
        nullptr,
        0,
        nullptr);
    if (worker_thread == nullptr) {
        g_virtual_read_file_ex_apc_thread_started = false;
        return false;
    }

    CloseHandle(worker_thread);
    return true;
}

bool ensure_virtual_nt_read_file_worker_started() {
    std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
    if (g_virtual_nt_read_file_apc_event == nullptr) {
        g_virtual_nt_read_file_apc_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (g_virtual_nt_read_file_apc_event == nullptr) {
            return false;
        }
    }

    if (g_virtual_nt_read_file_apc_thread_started.exchange(true)) {
        return true;
    }

    const auto worker_thread = CreateThread(
        nullptr,
        0,
        &virtual_nt_read_file_completion_thread_proc,
        nullptr,
        0,
        nullptr);
    if (worker_thread == nullptr) {
        g_virtual_nt_read_file_apc_thread_started = false;
        return false;
    }

    CloseHandle(worker_thread);
    return true;
}

bool queue_read_file_ex_completion(
    uint64_t request_id,
    LPOVERLAPPED_COMPLETION_ROUTINE completion_routine,
    uint64_t flow_id,
    HANDLE file,
    const std::wstring& tracked_path,
    void* buffer,
    std::vector<uint8_t> staged_bytes,
    uint64_t read_offset,
    DWORD requested,
    bool is_virtual,
    LPOVERLAPPED overlapped,
    DWORD error_code,
    DWORD transferred) {
    if (completion_routine == nullptr) {
        return true;
    }

    auto context = std::make_unique<ReadFileExApcContext>();
    context->request_id = request_id;
    context->flow_id = flow_id;
    context->file = file;
    context->path_utf8 = narrow_utf8(tracked_path);
    context->buffer = buffer;
    context->staged_bytes = std::move(staged_bytes);
    context->read_offset = read_offset;
    context->requested = requested;
    context->is_virtual = is_virtual;
    context->completion_routine = completion_routine;
    context->overlapped = overlapped;
    context->error_code = error_code;
    context->transferred = transferred;
    context->issuing_thread_id = GetCurrentThreadId();

    HANDLE thread_handle = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
    if (thread_handle == nullptr) {
        std::ostringstream oss;
        oss << "[readfileex-queue-failed]"
            << std::hex
            << " handle=0x" << handle_key(file)
            << " io_offset=0x" << read_offset
            << " requested=0x" << requested
            << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
            << " completion=0x" << reinterpret_cast<uintptr_t>(completion_routine)
            << std::dec
            << " virtual=" << static_cast<int>(is_virtual)
            << " last_error=" << GetLastError()
            << "\n"
            << "path=" << narrow_utf8(tracked_path)
            << "\n\n";
        append_log_line(oss.str());
        return false;
    }

    context->target_thread_handle = thread_handle;
    if (!ensure_virtual_read_file_ex_worker_started()) {
        std::ostringstream oss;
        oss << "[readfileex-queue-failed]"
            << std::hex
            << " handle=0x" << handle_key(file)
            << " io_offset=0x" << read_offset
            << " requested=0x" << requested
            << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
            << " completion=0x" << reinterpret_cast<uintptr_t>(completion_routine)
            << std::dec
            << " virtual=" << static_cast<int>(is_virtual)
            << " last_error=" << GetLastError()
            << " phase=worker_start"
            << "\n"
            << "path=" << narrow_utf8(tracked_path)
            << "\n\n";
        append_log_line(oss.str());
        CloseHandle(thread_handle);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
        g_pending_virtual_read_file_ex_apcs.push_back(std::move(context));
    }
    if (g_virtual_read_file_ex_apc_event != nullptr) {
        SetEvent(g_virtual_read_file_ex_apc_event);
    }

    std::ostringstream oss;
    oss << "[async-probe]"
        << " t_ms=" << process_uptime_ms()
        << " stage=readfileex-queued"
        << " request=" << request_id
        << " flow=" << flow_id
        << std::hex
        << " handle=0x" << handle_key(file)
        << " io_offset=0x" << read_offset
        << " requested=0x" << requested
        << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
        << std::dec
        << " virtual=" << static_cast<int>(is_virtual)
        << "\npath=" << narrow_utf8(tracked_path)
        << "\n\n";
    append_async_probe_line(oss.str());
    return true;
}

bool queue_nt_read_file_completion(
    uint64_t request_id,
    uint64_t flow_id,
    HANDLE file,
    const std::wstring& tracked_path,
    void* buffer,
    std::vector<uint8_t> staged_bytes,
    uint64_t read_offset,
    ULONG requested,
    bool is_virtual,
    HANDLE event,
    PIO_APC_ROUTINE apc_routine,
    PVOID apc_context,
    PIO_STATUS_BLOCK io_status_block,
    ULONG transferred,
    bool update_position_on_complete,
    uint64_t next_position) {
    auto context = std::make_unique<NtReadFileApcContext>();
    context->request_id = request_id;
    context->flow_id = flow_id;
    context->file = file;
    context->path_utf8 = narrow_utf8(tracked_path);
    context->buffer = buffer;
    context->staged_bytes = std::move(staged_bytes);
    context->read_offset = read_offset;
    context->requested = requested;
    context->is_virtual = is_virtual;
    context->event = event;
    context->apc_routine = apc_routine;
    context->apc_context = apc_context;
    context->io_status_block = io_status_block;
    context->transferred = transferred;
    context->update_position_on_complete = update_position_on_complete;
    context->next_position = next_position;
    context->issuing_thread_id = GetCurrentThreadId();

    if (apc_routine != nullptr) {
        HANDLE thread_handle = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
        if (thread_handle == nullptr) {
            std::ostringstream oss;
            oss << "[ntreadfile-queue-failed]"
                << std::hex
                << " handle=0x" << handle_key(file)
                << " io_offset=0x" << read_offset
                << " requested=0x" << static_cast<uint64_t>(requested)
                << " iosb=0x" << reinterpret_cast<uintptr_t>(io_status_block)
                << " apc=0x" << reinterpret_cast<uintptr_t>(apc_routine)
                << " apc_ctx=0x" << reinterpret_cast<uintptr_t>(apc_context)
                << " event=0x" << reinterpret_cast<uintptr_t>(event)
                << std::dec
                << " virtual=" << static_cast<int>(is_virtual)
                << " last_error=" << GetLastError()
                << "\n"
                << "path=" << narrow_utf8(tracked_path)
                << "\n\n";
            append_log_line(oss.str());
            return false;
        }
        context->target_thread_handle = thread_handle;
    }

    if (!ensure_virtual_nt_read_file_worker_started()) {
        std::ostringstream oss;
        oss << "[ntreadfile-queue-failed]"
            << std::hex
            << " handle=0x" << handle_key(file)
            << " io_offset=0x" << read_offset
            << " requested=0x" << static_cast<uint64_t>(requested)
            << " iosb=0x" << reinterpret_cast<uintptr_t>(io_status_block)
            << " apc=0x" << reinterpret_cast<uintptr_t>(apc_routine)
            << " apc_ctx=0x" << reinterpret_cast<uintptr_t>(apc_context)
            << " event=0x" << reinterpret_cast<uintptr_t>(event)
            << std::dec
            << " virtual=" << static_cast<int>(is_virtual)
            << " last_error=" << GetLastError()
            << " phase=worker_start"
            << "\n"
            << "path=" << narrow_utf8(tracked_path)
            << "\n\n";
        append_log_line(oss.str());
        if (context->target_thread_handle != nullptr) {
            CloseHandle(context->target_thread_handle);
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
        g_pending_virtual_nt_read_file_apcs.push_back(std::move(context));
    }
    if (g_virtual_nt_read_file_apc_event != nullptr) {
        SetEvent(g_virtual_nt_read_file_apc_event);
    }

    std::ostringstream oss;
    oss << "[async-probe]"
        << " t_ms=" << process_uptime_ms()
        << " stage=ntreadfile-queued"
        << " request=" << request_id
        << " flow=" << flow_id
        << std::hex
        << " handle=0x" << handle_key(file)
        << " io_offset=0x" << read_offset
        << " requested=0x" << static_cast<uint64_t>(requested)
        << " iosb=0x" << reinterpret_cast<uintptr_t>(io_status_block)
        << " apc=0x" << reinterpret_cast<uintptr_t>(apc_routine)
        << " event=0x" << reinterpret_cast<uintptr_t>(event)
        << std::dec
        << " virtual=" << static_cast<int>(is_virtual)
        << " update_pos=" << static_cast<int>(update_position_on_complete)
        << "\npath=" << narrow_utf8(tracked_path)
        << "\n\n";
    append_async_probe_line(oss.str());
    return true;
}

} // namespace

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

    std::wstring resolved_source_path{};
    if (config->rf_chain_mode || config->source_path.empty()) {
        const auto redirected_source = resolve_redirect_source_for_requested_path(file_name);
        if (!redirected_source.has_value() || redirected_source->empty()) {
            if (last_error != nullptr) {
                *last_error = ERROR_FILE_NOT_FOUND;
            }
            append_log_line("virtual-loader-resolve-source-failed\n");
            return INVALID_HANDLE_VALUE;
        }
        resolved_source_path = *redirected_source;
    } else {
        resolved_source_path = config->source_path;
    }

    if (config->passthrough) {
        std::optional<std::wstring> runtime_source_path{};
        if (config->rf_chain_mode) {
            runtime_source_path = resolved_source_path;
        } else {
            runtime_source_path = current_virtual_source_path();
        }

        if (!runtime_source_path.has_value() || runtime_source_path->empty()) {
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

    const auto source_extension = std::filesystem::path{resolved_source_path}.extension().wstring();
    const auto treat_as_plain_source = config->plain_source || _wcsicmp(source_extension.c_str(), L".pak") == 0;
    const auto payload = load_virtual_pak_payload_for_source(resolved_source_path, treat_as_plain_source);
    if (!payload.has_value()) {
        if (last_error != nullptr) {
            *last_error = ERROR_INVALID_DATA;
        }

        return INVALID_HANDLE_VALUE;
    }

    if (last_error != nullptr) {
        *last_error = ERROR_SUCCESS;
    }

    const auto backing_handle = g_original_create_file_w(
        resolved_source_path.c_str(),
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file);
    if (backing_handle == INVALID_HANDLE_VALUE) {
        if (last_error != nullptr) {
            *last_error = GetLastError();
        }
        append_log_line("virtual-loader-open-backing-failed\n");
        return INVALID_HANDLE_VALUE;
    }

    const auto result = create_virtual_file_handle(file_name, resolved_source_path, *payload, backing_handle);
    std::ostringstream oss;
    oss << "virtual-loader-open-backed"
        << " handle=0x" << std::hex << handle_key(result)
        << " requested_path=" << narrow_utf8(file_name)
        << " source_path=" << narrow_utf8(resolved_source_path)
        << "\n";
    append_log_line(oss.str());
    return result;
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
    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock _{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }
    const auto probe_only_mode = config.probe_only;
    const auto is_probe_logged_pak = probe_only_mode && is_pak;
    const auto should_track_pak = is_focus_pak || is_probe_logged_pak;
    auto is_virtual_pak = false;
    HANDLE result{};
    DWORD last_error = ERROR_SUCCESS;
    const auto* caller_filter_reason = (!probe_only_mode && is_virtual_target) ? evaluate_virtual_backend_caller(caller_context) : nullptr;

    if (!probe_only_mode && is_virtual_target && caller_filter_reason == nullptr) {
        std::ostringstream oss;
        oss << "virtual-loader-target-rejected"
            << describe_caller(caller)
            << " path=" << (file_name != nullptr ? narrow_utf8(file_name) : "<null>")
            << "\n";
        append_log_line(oss.str());
    }

    if (is_pak) {
        if (!probe_only_mode && is_virtual_target && caller_filter_reason != nullptr) {
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
                is_virtual_pak = result != INVALID_HANDLE_VALUE && lookup_virtual_pak_state(result).has_value();
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

    if (is_pak && should_track_pak) {
        const auto tracked_path = file_name != nullptr ? std::wstring{file_name} : L""; 
        if (result != INVALID_HANDLE_VALUE && !is_virtual_pak) {
            track_pak_handle(result, tracked_path);
        }

        const auto seq = g_sequence.fetch_add(1) + 1;
        const auto pak_hits = g_create_file_pak_hits.fetch_add(1) + 1;
        if (pak_hits == 1) {
            std::ostringstream timing_oss;
            timing_oss << "virtual=" << static_cast<int>(is_virtual_pak)
                << " target_match=" << static_cast<int>(is_virtual_target || is_record_target);
            if (file_name != nullptr) {
                timing_oss << " path=" << narrow_utf8(file_name);
            }
            append_timing_log_line("pak-first-createfile-hit", timing_oss.str());
        }
        std::ostringstream oss;
        oss << "[createfile " << seq << "]"
            << " t_ms=" << std::dec << process_uptime_ms()
            << " pak_hits=" << std::dec << pak_hits
            << describe_caller(caller)
            << std::hex
            << " access=0x" << desired_access
            << " share=0x" << share_mode
            << " creation=0x" << creation_disposition
            << " flags=0x" << flags_and_attributes
            << " target_match=" << std::dec << static_cast<int>(is_virtual_target || is_record_target)
            << " record_only=" << std::dec << static_cast<int>(is_record_target)
            << " focus_target=" << std::dec << static_cast<int>(is_focus_pak)
            << " probe_all_pak=" << std::dec << static_cast<int>(is_probe_logged_pak)
            << " probe_only=" << std::dec << static_cast<int>(probe_only_mode)
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
    const auto overlapped_offset = overlapped != nullptr
        ? std::optional<uint64_t>{(static_cast<uint64_t>(overlapped->OffsetHigh) << 32) | overlapped->Offset}
        : std::nullopt;
    const auto overlapped_before = capture_overlapped_snapshot(overlapped);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();
    const auto virtual_payload = is_virtual ? lookup_virtual_payload(file) : std::nullopt;
    const auto flow_id = tracked_path.has_value() ? next_probe_flow_id() : 0;
    const auto use_direct_virtual_read = is_virtual && virtual_state->synthetic_handle;

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;

    if (use_direct_virtual_read) {
        const auto read_offset = overlapped_offset.value_or(position_before.value_or(0));
        const auto read_result = service_virtual_read(
            file,
            virtual_state,
            virtual_payload,
            read_offset,
            buffer,
            bytes_to_read);

        if (bytes_read != nullptr) {
            *bytes_read = read_result.ok ? read_result.transferred : 0;
        }

        if (overlapped != nullptr) {
            overlapped->Internal = static_cast<ULONG_PTR>(read_result.ok ? kStatusSuccess : kStatusUnsuccessful);
            overlapped->InternalHigh = read_result.ok ? read_result.transferred : 0;
            if (read_result.ok) {
                if (const auto event_handle = normalize_overlapped_event_handle(overlapped); event_handle != nullptr) {
                    SetEvent(event_handle);
                }
            }
        }

        if (read_result.ok && overlapped == nullptr) {
            update_virtual_sync_backing_position(file, virtual_state, read_offset + read_result.transferred, &last_error);
        } else if (!read_result.ok) {
            last_error = read_result.last_error;
        }

        result = read_result.ok ? TRUE : FALSE;
    } else {
        result = g_original_read_file(file, buffer, bytes_to_read, bytes_read, overlapped);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }
    const auto overlapped_after = capture_overlapped_snapshot(overlapped);

    if (tracked_path.has_value()) {
        const auto pending = overlapped != nullptr && result == 0 && last_error == ERROR_IO_PENDING;
        const auto effective_read_offset = overlapped_offset.value_or(position_before.value_or(0));
        if (overlapped != nullptr && (result != 0 || pending)) {
            register_pending_overlapped_flow(
                overlapped,
                flow_id,
                "ReadFile",
                effective_read_offset,
                bytes_to_read,
                is_virtual);
        } else if (overlapped != nullptr && !pending) {
            retire_pending_overlapped_flow(overlapped);
        }

        const auto hit = g_read_file_hits.fetch_add(1) + 1;
        const auto transferred = bytes_read != nullptr ? *bytes_read : 0;
        std::optional<uint64_t> effective_end_offset = std::nullopt;
        std::optional<uint64_t> position_after = position_before;

        if (result != 0) {
            effective_end_offset = effective_read_offset + transferred;
        }

        if (result != 0
            && overlapped == nullptr
            && position_before.has_value()
            && (!is_virtual || use_direct_virtual_read)) {
            position_after = *position_before + transferred;
            set_pak_handle_position(file, *position_after);
        }

        if (hit <= 400) {
            std::ostringstream oss;
            oss << "[readfile " << hit << "]"
                << " t_ms=" << std::dec << process_uptime_ms()
                << " flow=" << flow_id
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " pos_before=0x" << position_before.value_or(0)
                << " pos_after=0x" << position_after.value_or(0)
                << " io_offset=0x" << effective_read_offset
                << " io_end=0x" << effective_end_offset.value_or(0)
                << " requested=0x" << bytes_to_read
                << " transferred=0x" << transferred
                << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
                << " overlapped_offset=0x" << overlapped_offset.value_or(0)
                << " overlapped_internal_before=0x" << overlapped_before.internal
                << " overlapped_high_before=0x" << overlapped_before.internal_high
                << " overlapped_internal_after=0x" << overlapped_after.internal
                << " overlapped_high_after=0x" << overlapped_after.internal_high
                << " event_raw=0x" << overlapped_after.event_raw
                << " event_norm=0x" << overlapped_after.event_normalized
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << " event_lowbit=" << static_cast<int>(overlapped_after.event_lowbit)
                << std::hex
                << " result=" << std::dec << static_cast<int>(result)
                << " pending=" << static_cast<int>(pending)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n";
            append_event_query_fields(oss, "event_before", overlapped_before.event_query);
            append_event_query_fields(oss, "event_after", overlapped_after.event_query);
            oss << "\n";

            if (result != 0
                && transferred != 0
                && buffer != nullptr
                && tracked_path.has_value()
                && path_matches_focus_target(*tracked_path)) {
                if (const auto dump_slot = claim_pak_read_dump_slot(file); dump_slot.has_value()) {
                    constexpr size_t kPreviewBytes = 0x80;
                    const auto* preview_bytes = static_cast<const uint8_t*>(buffer);
                    const auto preview_count = std::min<size_t>(transferred, kPreviewBytes);
                    oss << "preview_slot=" << *dump_slot
                        << " preview_count=0x" << std::hex << preview_count
                        << '\n';
                    for (size_t offset = 0; offset < preview_count; offset += 0x20) {
                        oss << "preview+0x" << std::setw(4) << std::setfill('0') << offset << ':';
                        const auto line_end = std::min(preview_count, offset + 0x20);
                        for (size_t i = offset; i < line_end; ++i) {
                            oss << ' ' << std::setw(2) << static_cast<unsigned int>(preview_bytes[i]);
                        }
                        oss << '\n';
                    }
                }
            }

            oss << '\n';
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_read_file_ex(
    HANDLE file,
    LPVOID buffer,
    DWORD bytes_to_read,
    LPOVERLAPPED overlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto position_before = tracked_path.has_value() ? lookup_pak_handle_position(file) : std::nullopt;
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto overlapped_offset = overlapped != nullptr
        ? std::optional<uint64_t>{(static_cast<uint64_t>(overlapped->OffsetHigh) << 32) | overlapped->Offset}
        : std::nullopt;
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();
    const auto virtual_payload = is_virtual ? lookup_virtual_payload(file) : std::nullopt;
    const auto overlapped_before = capture_overlapped_snapshot(overlapped);
    const auto flow_id = tracked_path.has_value() ? next_probe_flow_id() : 0;
    const auto request_id = tracked_path.has_value() ? next_virtual_request_id() : 0;
    const auto use_direct_virtual_read_file_ex = is_virtual && virtual_state->synthetic_handle;

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    auto wrapped_completion_context = std::shared_ptr<ReadFileExApcContext>{};
    if (use_direct_virtual_read_file_ex) {
        const auto read_offset = overlapped_offset.value_or(position_before.value_or(0));
        std::vector<uint8_t> staged_bytes(bytes_to_read);
        const auto read_result = service_virtual_read(
            file,
            virtual_state,
            virtual_payload,
            read_offset,
            staged_bytes.empty() ? nullptr : staged_bytes.data(),
            bytes_to_read);

        if (overlapped != nullptr) {
            overlapped->Internal = static_cast<ULONG_PTR>(read_result.ok ? kStatusPending : kStatusUnsuccessful);
            overlapped->InternalHigh = 0;
        }

        if (!read_result.ok) {
            result = FALSE;
            last_error = read_result.last_error;
        } else if (!queue_read_file_ex_completion(
                       request_id,
                       completion_routine,
                       flow_id,
                       file,
                       *tracked_path,
                       buffer,
                       std::move(staged_bytes),
                       read_offset,
                       bytes_to_read,
                       is_virtual,
                       overlapped,
                       ERROR_SUCCESS,
                       read_result.transferred)) {
            result = FALSE;
            last_error = GetLastError();
            if (last_error == ERROR_SUCCESS) {
                last_error = ERROR_GEN_FAILURE;
            }
            if (overlapped != nullptr) {
                overlapped->Internal = static_cast<ULONG_PTR>(kStatusUnsuccessful);
                overlapped->InternalHigh = 0;
            }
        } else {
            result = TRUE;
        }
    } else {
        auto effective_completion = completion_routine;
        if (tracked_path.has_value() && overlapped != nullptr && completion_routine != nullptr) {
            wrapped_completion_context = std::make_shared<ReadFileExApcContext>();
            wrapped_completion_context->request_id = request_id;
            wrapped_completion_context->file = file;
            wrapped_completion_context->path_utf8 = narrow_utf8(*tracked_path);
            wrapped_completion_context->buffer = buffer;
            wrapped_completion_context->read_offset = overlapped_offset.value_or(position_before.value_or(0));
            wrapped_completion_context->requested = bytes_to_read;
            wrapped_completion_context->is_virtual = is_virtual;
            wrapped_completion_context->flow_id = flow_id;
            wrapped_completion_context->completion_routine = completion_routine;
            wrapped_completion_context->overlapped = overlapped;
            wrapped_completion_context->issuing_thread_id = GetCurrentThreadId();

            std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
            g_pending_read_file_ex_completions[reinterpret_cast<uintptr_t>(overlapped)] = wrapped_completion_context;
            effective_completion = wrapped_read_file_ex_completion;
        }

        result = g_original_read_file_ex(file, buffer, bytes_to_read, overlapped, effective_completion);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
        if (result == 0 && wrapped_completion_context != nullptr && overlapped != nullptr) {
            std::lock_guard<std::mutex> lock(g_read_file_ex_completion_mutex);
            g_pending_read_file_ex_completions.erase(reinterpret_cast<uintptr_t>(overlapped));
        }
    }
    const auto overlapped_after = capture_overlapped_snapshot(overlapped);

    if (tracked_path.has_value()) {
        const auto pending = overlapped != nullptr && result == 0 && last_error == ERROR_IO_PENDING;
        const auto effective_read_offset = overlapped_offset.value_or(position_before.value_or(0));
        if (overlapped != nullptr && (result != 0 || pending)) {
            register_pending_overlapped_flow(
                overlapped,
                flow_id,
                "ReadFileEx",
                effective_read_offset,
                bytes_to_read,
                is_virtual);
        } else if (overlapped != nullptr && !pending) {
            retire_pending_overlapped_flow(overlapped);
        }

        const auto hit = g_read_file_ex_hits.fetch_add(1) + 1;
        if (hit <= 240) {
            std::ostringstream oss;
            oss << "[readfileex " << hit << "]"
                << " t_ms=" << std::dec << process_uptime_ms()
                << " request=" << request_id
                << " flow=" << flow_id
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " pos_before=0x" << position_before.value_or(0)
                << " io_offset=0x" << effective_read_offset
                << " requested=0x" << bytes_to_read
                << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
                << " completion=0x" << reinterpret_cast<uintptr_t>(completion_routine)
                << " wrapped_completion=0x"
                << reinterpret_cast<uintptr_t>(wrapped_completion_context != nullptr ? wrapped_read_file_ex_completion : completion_routine)
                << " overlapped_internal_before=0x" << overlapped_before.internal
                << " overlapped_high_before=0x" << overlapped_before.internal_high
                << " overlapped_internal_after=0x" << overlapped_after.internal
                << " overlapped_high_after=0x" << overlapped_after.internal_high
                << " event_raw=0x" << overlapped_after.event_raw
                << " event_norm=0x" << overlapped_after.event_normalized
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << " thread_id=" << GetCurrentThreadId()
                << " event_lowbit=" << static_cast<int>(overlapped_after.event_lowbit)
                << std::hex
                << std::dec
                << " result=" << static_cast<int>(result)
                << " pending=" << static_cast<int>(pending)
                << " last_error=" << last_error
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n";
            append_event_query_fields(oss, "event_before", overlapped_before.event_query);
            append_event_query_fields(oss, "event_after", overlapped_after.event_query);
            oss << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

BOOL WINAPI hooked_get_overlapped_result(
    HANDLE file,
    LPOVERLAPPED overlapped,
    LPDWORD number_of_bytes_transferred,
    BOOL wait) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto position_before = tracked_path.has_value() ? lookup_pak_handle_position(file) : std::nullopt;
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto overlapped_offset = overlapped != nullptr
        ? std::optional<uint64_t>{(static_cast<uint64_t>(overlapped->OffsetHigh) << 32) | overlapped->Offset}
        : std::nullopt;
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();
    const auto overlapped_before = capture_overlapped_snapshot(overlapped);
    const auto pending_flow = lookup_pending_overlapped_flow(overlapped);

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    if (is_virtual) {
        auto snapshot = overlapped_before;
        if (overlapped == nullptr) {
            result = FALSE;
            last_error = ERROR_INVALID_PARAMETER;
        } else {
            if (snapshot.internal == kStatusPending && wait != 0 && snapshot.event_normalized != 0) {
                WaitForSingleObject(reinterpret_cast<HANDLE>(snapshot.event_normalized), INFINITE);
                snapshot = capture_overlapped_snapshot(overlapped);
            }

            if (snapshot.internal == kStatusPending) {
                result = FALSE;
                last_error = ERROR_IO_INCOMPLETE;
            } else if (snapshot.internal == kStatusSuccess) {
                if (number_of_bytes_transferred != nullptr) {
                    *number_of_bytes_transferred = static_cast<DWORD>(snapshot.internal_high);
                }
                result = TRUE;
            } else {
                result = FALSE;
                last_error = ERROR_GEN_FAILURE;
            }
        }
    } else {
        result = g_original_get_overlapped_result(file, overlapped, number_of_bytes_transferred, wait);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }
    const auto overlapped_after = capture_overlapped_snapshot(overlapped);
    if (overlapped != nullptr && (result != 0 || last_error != ERROR_IO_INCOMPLETE)) {
        retire_pending_overlapped_flow(overlapped);
    }

    if (tracked_path.has_value()) {
        const auto hit = g_get_overlapped_result_hits.fetch_add(1) + 1;
        const auto transferred = number_of_bytes_transferred != nullptr ? *number_of_bytes_transferred : 0U;
        if (hit <= 240) {
            std::ostringstream oss;
            oss << "[getoverlappedresult " << hit << "]"
                << " t_ms=" << std::dec << process_uptime_ms()
                << " flow=" << (pending_flow.has_value() ? pending_flow->flow_id : 0)
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " pos_before=0x" << position_before.value_or(0)
                << " io_offset=0x" << overlapped_offset.value_or(0)
                << " transferred=0x" << transferred
                << " overlapped=0x" << reinterpret_cast<uintptr_t>(overlapped)
                << " overlapped_internal_before=0x" << overlapped_before.internal
                << " overlapped_high_before=0x" << overlapped_before.internal_high
                << " overlapped_internal_after=0x" << overlapped_after.internal
                << " overlapped_high_after=0x" << overlapped_after.internal_high
                << " event_raw=0x" << overlapped_after.event_raw
                << " event_norm=0x" << overlapped_after.event_normalized
                << std::dec
                << " event_lowbit=" << static_cast<int>(overlapped_after.event_lowbit)
                << " thread_id=" << GetCurrentThreadId()
                << " wait=" << static_cast<int>(wait)
                << " result=" << static_cast<int>(result)
                << " last_error=" << last_error
                << " pending_api=" << (pending_flow.has_value() ? pending_flow->api : "<none>")
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n";
            if (pending_flow.has_value()) {
                oss << "pending_issue_t_ms=" << pending_flow->issued_t_ms
                    << " pending_virtual=" << static_cast<int>(pending_flow->is_virtual)
                    << std::hex
                    << " pending_issue_offset=0x" << pending_flow->io_offset
                    << " pending_requested=0x" << pending_flow->requested
                    << std::dec
                    << "\n";
            }
            append_event_query_fields(oss, "event_before", overlapped_before.event_query);
            append_event_query_fields(oss, "event_after", overlapped_after.event_query);
            oss << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
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
            result = TRUE;
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

        if (hit <= 400) {
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
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;

    if (is_virtual) {
        const auto size = lookup_pak_handle_size(file);
        if (file_size != nullptr && size.has_value()) {
            file_size->QuadPart = static_cast<LONGLONG>(*size);
            result = TRUE;
        } else {
            last_error = ERROR_INVALID_DATA;
            result = FALSE;
        }
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

NTSTATUS NTAPI hooked_nt_read_file(
    HANDLE file_handle,
    HANDLE event,
    PIO_APC_ROUTINE apc_routine,
    PVOID apc_context,
    PIO_STATUS_BLOCK io_status_block,
    PVOID buffer,
    ULONG length,
    PLARGE_INTEGER byte_offset,
    PULONG key) {
    const auto tracked_path = lookup_pak_handle_path(file_handle);
    const auto position_before = tracked_path.has_value() ? lookup_pak_handle_position(file_handle) : std::nullopt;
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto explicit_offset = byte_offset != nullptr
        ? std::optional<uint64_t>{static_cast<uint64_t>(byte_offset->QuadPart)}
        : std::nullopt;
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file_handle) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();
    const auto virtual_payload = is_virtual ? lookup_virtual_payload(file_handle) : std::nullopt;
    const auto iosb_before = capture_io_status_snapshot(io_status_block);
    const auto event_before = capture_event_query_snapshot(event);
    const auto flow_id = tracked_path.has_value() ? next_probe_flow_id() : 0;
    const auto request_id = tracked_path.has_value() ? next_virtual_request_id() : 0;

    NTSTATUS status{};
    if (is_virtual) {
        const auto read_offset = explicit_offset.value_or(position_before.value_or(0));
        const auto use_async_virtual_completion =
            apc_routine != nullptr || event != nullptr;
        std::vector<uint8_t> staged_bytes{};
        if (use_async_virtual_completion) {
            staged_bytes.resize(length);
        }
        const auto read_result = service_virtual_read(
            file_handle,
            virtual_state,
            virtual_payload,
            read_offset,
            use_async_virtual_completion && !staged_bytes.empty() ? staged_bytes.data() : buffer,
            length);

        if (!read_result.ok) {
            if (io_status_block != nullptr) {
                io_status_block->Status = kStatusUnsuccessful;
                io_status_block->Information = 0;
            }
            if (event != nullptr) {
                SetEvent(event);
            }
            status = kStatusUnsuccessful;
        } else if (use_async_virtual_completion) {
            if (io_status_block != nullptr) {
                io_status_block->Status = kStatusPending;
                io_status_block->Information = 0;
            }

            const auto next_position = read_offset + read_result.transferred;
            if (!queue_nt_read_file_completion(
                    request_id,
                    flow_id,
                    file_handle,
                    *tracked_path,
                    buffer,
                    std::move(staged_bytes),
                    read_offset,
                    length,
                    is_virtual,
                    event,
                    apc_routine,
                    apc_context,
                    io_status_block,
                    read_result.transferred,
                    !explicit_offset.has_value(),
                    next_position)) {
                if (io_status_block != nullptr) {
                    io_status_block->Status = kStatusUnsuccessful;
                    io_status_block->Information = 0;
                }
                if (event != nullptr) {
                    SetEvent(event);
                }
                status = kStatusUnsuccessful;
            } else {
                status = kStatusPending;
            }
        } else {
            if (io_status_block != nullptr) {
                io_status_block->Status = kStatusSuccess;
                io_status_block->Information = read_result.transferred;
            }

            if (event != nullptr) {
                SetEvent(event);
            }

            if (!explicit_offset.has_value()) {
                update_virtual_sync_backing_position(file_handle, virtual_state, read_offset + read_result.transferred, nullptr);
            }

            status = kStatusSuccess;
        }
    } else {
        status = g_original_nt_read_file(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            buffer,
            length,
            byte_offset,
            key);
    }
    const auto iosb_after = capture_io_status_snapshot(io_status_block);
    const auto event_after = capture_event_query_snapshot(event);

    if (tracked_path.has_value()) {
        const auto hit = g_nt_read_file_hits.fetch_add(1) + 1;
        const auto information = io_status_block != nullptr ? static_cast<uint64_t>(io_status_block->Information) : 0ULL;
        auto position_after = position_before;
        if (status == 0 && explicit_offset.has_value()) {
            position_after = *explicit_offset + information;
        } else if (status == 0 && !explicit_offset.has_value() && position_before.has_value()) {
            position_after = *position_before + information;
            set_pak_handle_position(file_handle, *position_after);
        }

        if (hit <= 240) {
            std::ostringstream oss;
            oss << "[ntreadfile " << hit << "]"
                << " t_ms=" << std::dec << process_uptime_ms()
                << " request=" << request_id
                << " flow=" << flow_id
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file_handle)
                << " pos_before=0x" << position_before.value_or(0)
                << " pos_after=0x" << position_after.value_or(0)
                << " io_offset=0x" << explicit_offset.value_or(position_before.value_or(0))
                << " length=0x" << static_cast<uint64_t>(length)
                << " transferred=0x" << information
                << " event=0x" << reinterpret_cast<uintptr_t>(event)
                << " apc=0x" << reinterpret_cast<uintptr_t>(apc_routine)
                << " apc_ctx=0x" << reinterpret_cast<uintptr_t>(apc_context)
                << " iosb=0x" << reinterpret_cast<uintptr_t>(io_status_block)
                << " key=0x" << reinterpret_cast<uintptr_t>(key)
                << " status=0x" << static_cast<uint32_t>(status)
                << " iosb_status_before=0x" << static_cast<uint32_t>(iosb_before.status)
                << " iosb_info_before=0x" << iosb_before.information
                << " iosb_status_after=0x" << static_cast<uint32_t>(iosb_after.status)
                << " iosb_info_after=0x" << iosb_after.information
                << std::dec
                << " virtual=" << static_cast<int>(is_virtual)
                << " thread_id=" << GetCurrentThreadId()
                << "\n"
                << "path=" << narrow_utf8(*tracked_path)
                << "\n";
            append_event_query_fields(oss, "event_before", event_before);
            append_event_query_fields(oss, "event_after", event_after);
            oss << "\n";
            oss << '\n';
            append_log_line(oss.str());
            if (status == 0 && information != 0 && buffer != nullptr) {
                append_read_bytes_log_bytes(buffer, static_cast<size_t>(information));
            }
        }
    }

    return status;
}

DWORD WINAPI hooked_get_file_type(HANDLE file) {
    const auto tracked_path = lookup_pak_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();

    DWORD result{};
    DWORD last_error = ERROR_SUCCESS;
    if (is_virtual) {
        result = FILE_TYPE_DISK;
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
        result = fill_virtual_by_handle_file_information(file, file_information) ? TRUE : FALSE;
        last_error = result != 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
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
        result = fill_virtual_file_information_by_handle_ex(
            file,
            file_information_class,
            file_information,
            buffer_size,
            &last_error) ? TRUE : FALSE;
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
        status = fill_virtual_nt_query_information_file(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class);
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
    const auto virtual_state = tracked_path.has_value() ? lookup_virtual_pak_state(file) : std::nullopt;
    const auto is_virtual = virtual_state.has_value();
    const auto virtual_payload = is_virtual ? lookup_virtual_payload(file) : std::nullopt;

    HANDLE result{};
    DWORD last_error = ERROR_SUCCESS;

    if (is_virtual) {
        auto mapping_payload = virtual_payload.has_value() ? *virtual_payload : std::shared_ptr<std::vector<uint8_t>>{};
        if (mapping_payload == nullptr && virtual_state->random_access_view != nullptr) {
            mapping_payload = ensure_virtual_payload_materialized(virtual_state->random_access_view);
        }

        if (mapping_payload == nullptr) {
            last_error = ERROR_INVALID_DATA;
        } else {
            result = create_virtual_mapping_handle(*tracked_path, mapping_payload);
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
        if (result != nullptr && !is_virtual) {
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
                << " virtual=" << std::dec << static_cast<int>(is_virtual)
                << std::hex
                << " result=" << std::dec << (result != nullptr ? 1 : 0)
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
    const auto synthetic_virtual = (virtual_pak_state.has_value() && virtual_pak_state->synthetic_handle)
        || (virtual_mapping_state.has_value() && virtual_mapping_state->synthetic_handle);

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    if (synthetic_virtual) {
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

BOOL WINAPI hooked_duplicate_handle(
    HANDLE source_process_handle,
    HANDLE source_handle,
    HANDLE target_process_handle,
    LPHANDLE target_handle,
    DWORD desired_access,
    BOOL inherit_handle,
    DWORD options) {
    const auto pak_path = lookup_pak_handle_path(source_handle);
    const auto mapping_path = lookup_mapping_handle_path(source_handle);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_pak_state = lookup_virtual_pak_state(source_handle);
    const auto virtual_mapping_state = lookup_virtual_mapping(source_handle);
    const auto is_virtual = virtual_pak_state.has_value() || virtual_mapping_state.has_value();

    BOOL result{};
    DWORD last_error = ERROR_SUCCESS;
    auto cloned_tracking = false;
    HANDLE target_value = nullptr;
    if (is_virtual) {
        if (target_handle == nullptr) {
            result = FALSE;
            last_error = ERROR_INVALID_PARAMETER;
        } else if (virtual_pak_state.has_value() && !virtual_pak_state->synthetic_handle) {
            result = g_original_duplicate_handle(
                source_process_handle,
                source_handle,
                target_process_handle,
                target_handle,
                desired_access,
                inherit_handle,
                options);
            last_error = result != 0 ? ERROR_SUCCESS : GetLastError();
            if (result != 0) {
                target_value = *target_handle;
                cloned_tracking = clone_handle_tracking(source_handle, target_value);
            }
        } else if (virtual_pak_state.has_value()) {
            PreparedVirtualPakSource source{};
            source.payload = virtual_pak_state->payload;
            source.random_access_view = virtual_pak_state->random_access_view;
            target_value = create_virtual_file_handle(
                virtual_pak_state->requested_path,
                virtual_pak_state->source_path,
                source);
            *target_handle = target_value;
            cloned_tracking = clone_handle_tracking(source_handle, target_value);
            result = cloned_tracking ? TRUE : FALSE;
            last_error = result != 0 ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
            if (result == 0) {
                *target_handle = nullptr;
                untrack_close_handle(target_value);
                target_value = nullptr;
            }
        } else if (virtual_mapping_state.has_value()) {
            target_value = create_virtual_mapping_handle(
                virtual_mapping_state->path,
                virtual_mapping_state->payload);
            *target_handle = target_value;
            cloned_tracking = clone_handle_tracking(source_handle, target_value);
            result = cloned_tracking ? TRUE : FALSE;
            last_error = result != 0 ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
            if (result == 0) {
                *target_handle = nullptr;
                untrack_close_handle(target_value);
                target_value = nullptr;
            }
        } else {
            result = FALSE;
            last_error = ERROR_INVALID_HANDLE;
        }
        if (result != 0 && (options & DUPLICATE_CLOSE_SOURCE) != 0) {
            untrack_close_handle(source_handle);
        }
    } else {
        result = g_original_duplicate_handle(
            source_process_handle,
            source_handle,
            target_process_handle,
            target_handle,
            desired_access,
            inherit_handle,
            options);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
        target_value = (result != 0 && target_handle != nullptr) ? *target_handle : nullptr;
        if ((pak_path.has_value() || mapping_path.has_value()) && target_value != nullptr &&
            target_value != INVALID_HANDLE_VALUE) {
            cloned_tracking = clone_handle_tracking(source_handle, target_value);
        }
    }

    if (pak_path.has_value() || mapping_path.has_value()) {
        const auto hit = g_duplicate_handle_hits.fetch_add(1) + 1;
        if (hit <= 160) {
            std::ostringstream oss;
            oss << "[duplicatehandle " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " source_process=0x" << reinterpret_cast<uintptr_t>(source_process_handle)
                << " target_process=0x" << reinterpret_cast<uintptr_t>(target_process_handle)
                << " source=0x" << handle_key(source_handle)
                << " target=0x" << handle_key(target_value)
                << " desired_access=0x" << desired_access
                << " options=0x" << options
                << std::dec
                << " inherit=" << static_cast<int>(inherit_handle)
                << " cloned_tracking=" << static_cast<int>(cloned_tracking)
                << " result=" << static_cast<int>(result)
                << " last_error=" << last_error
                << "\n";

            if (pak_path.has_value()) {
                oss << "pak_path=" << narrow_utf8(*pak_path) << "\n";
            }
            if (mapping_path.has_value()) {
                oss << "mapping_path=" << narrow_utf8(*mapping_path) << "\n";
            }

            oss << "\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

HANDLE WINAPI hooked_re_open_file(
    HANDLE file,
    DWORD desired_access,
    DWORD share_mode,
    DWORD flags_and_attributes) {
    const auto pak_path = lookup_pak_handle_path(file);
    const auto mapping_path = lookup_mapping_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_pak_state = lookup_virtual_pak_state(file);
    const auto virtual_mapping_state = lookup_virtual_mapping(file);
    const auto is_virtual = virtual_pak_state.has_value() || virtual_mapping_state.has_value();

    HANDLE result = INVALID_HANDLE_VALUE;
    DWORD last_error = ERROR_SUCCESS;
    auto cloned_tracking = false;
    if (is_virtual) {
        if (virtual_pak_state.has_value() && !virtual_pak_state->synthetic_handle) {
            result = g_original_re_open_file(file, desired_access, share_mode, flags_and_attributes);
            last_error = result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        } else if (virtual_pak_state.has_value()) {
            PreparedVirtualPakSource source{};
            source.payload = virtual_pak_state->payload;
            source.random_access_view = virtual_pak_state->random_access_view;
            result = create_virtual_file_handle(
                virtual_pak_state->requested_path,
                virtual_pak_state->source_path,
                source);
        } else if (virtual_mapping_state.has_value()) {
            result = create_virtual_mapping_handle(
                virtual_mapping_state->path,
                virtual_mapping_state->payload);
        }

        if (result != INVALID_HANDLE_VALUE) {
            cloned_tracking = clone_handle_tracking(file, result);
            if (!cloned_tracking) {
                last_error = ERROR_INVALID_HANDLE;
                untrack_close_handle(result);
                result = INVALID_HANDLE_VALUE;
            }
        } else {
            last_error = ERROR_INVALID_HANDLE;
        }
    } else {
        result = g_original_re_open_file(file, desired_access, share_mode, flags_and_attributes);
        last_error = result == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if ((pak_path.has_value() || mapping_path.has_value()) && result != INVALID_HANDLE_VALUE) {
            cloned_tracking = clone_handle_tracking(file, result);
        }
    }

    if (pak_path.has_value() || mapping_path.has_value()) {
        const auto hit = g_re_open_file_hits.fetch_add(1) + 1;
        if (hit <= 120) {
            std::ostringstream oss;
            oss << "[reopenfile " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " source=0x" << handle_key(file)
                << " target=0x" << handle_key(result)
                << " access=0x" << desired_access
                << " share=0x" << share_mode
                << " flags=0x" << flags_and_attributes
                << std::dec
                << " cloned_tracking=" << static_cast<int>(cloned_tracking)
                << " result=" << static_cast<int>(result != INVALID_HANDLE_VALUE)
                << " last_error=" << last_error
                << "\n";

            if (pak_path.has_value()) {
                oss << "pak_path=" << narrow_utf8(*pak_path) << "\n";
            }
            if (mapping_path.has_value()) {
                oss << "mapping_path=" << narrow_utf8(*mapping_path) << "\n";
            }

            oss << "\n";
            append_log_line(oss.str());
        }
    }

    if (is_virtual) {
        SetLastError(last_error);
    }

    return result;
}

DWORD WINAPI hooked_get_final_path_name_by_handle_w(
    HANDLE file,
    LPWSTR file_path,
    DWORD file_path_length,
    DWORD flags) {
    const auto pak_path = lookup_pak_handle_path(file);
    const auto mapping_path = lookup_mapping_handle_path(file);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    const auto virtual_path = pak_path.has_value() ? pak_path : mapping_path;

    DWORD result{};
    DWORD last_error = ERROR_SUCCESS;
    if (virtual_path.has_value()) {
        const auto required_with_nul = static_cast<DWORD>(virtual_path->size() + 1);
        if (file_path == nullptr || file_path_length == 0) {
            result = required_with_nul;
        } else if (file_path_length <= virtual_path->size()) {
            const auto copy_length = std::min<size_t>(virtual_path->size(), file_path_length > 0 ? file_path_length - 1 : 0);
            if (copy_length != 0) {
                std::memcpy(file_path, virtual_path->data(), copy_length * sizeof(wchar_t));
            }
            file_path[copy_length] = L'\0';
            result = required_with_nul;
            last_error = ERROR_INSUFFICIENT_BUFFER;
        } else {
            std::memcpy(file_path, virtual_path->data(), virtual_path->size() * sizeof(wchar_t));
            file_path[virtual_path->size()] = L'\0';
            result = static_cast<DWORD>(virtual_path->size());
        }
    } else {
        result = g_original_get_final_path_name_by_handle_w(file, file_path, file_path_length, flags);
        last_error = result == 0 ? GetLastError() : ERROR_SUCCESS;
    }

    if (pak_path.has_value() || mapping_path.has_value()) {
        const auto hit = g_get_final_path_name_hits.fetch_add(1) + 1;
        if (hit <= 160) {
            std::string resolved_path = "<none>";
            if (result != 0 && file_path != nullptr && file_path_length != 0) {
                auto copied_length = result;
                if (copied_length >= file_path_length) {
                    copied_length = file_path_length - 1;
                }
                resolved_path = narrow_utf8(std::wstring{file_path, file_path + copied_length});
            } else if (virtual_path.has_value()) {
                resolved_path = narrow_utf8(*virtual_path);
            }

            std::ostringstream oss;
            oss << "[getfinalpathname " << hit << "]"
                << describe_caller(caller)
                << std::hex
                << " handle=0x" << handle_key(file)
                << " flags=0x" << flags
                << " buffer_len=0x" << file_path_length
                << " result_len=0x" << result
                << std::dec
                << " last_error=" << last_error
                << "\n";

            if (pak_path.has_value()) {
                oss << "pak_path=" << narrow_utf8(*pak_path) << "\n";
            }
            if (mapping_path.has_value()) {
                oss << "mapping_path=" << narrow_utf8(*mapping_path) << "\n";
            }
            oss << "resolved_path=" << resolved_path << "\n\n";
            append_log_line(oss.str());
        }
    }

    if (virtual_path.has_value()) {
        SetLastError(last_error);
    }

    return result;
}

int64_t __fastcall hooked_directstorage_open(void* rcx, const void* rdx, void* r8, void* r9) {
    const auto extracted_path = extract_directstorage_path(rdx);
    const auto is_focus_pak = extracted_path.has_value() && path_matches_focus_target(*extracted_path);
    const auto is_virtual_target = extracted_path.has_value() && path_matches_virtual_target(*extracted_path);
    const auto caller = reinterpret_cast<void*>(_ReturnAddress());
    VirtualPakLoaderConfig config{};
    {
        std::scoped_lock _{g_virtual_loader_mutex};
        config = g_virtual_loader_config;
    }
    const auto probe_only_mode = config.probe_only;
    const auto is_probe_logged_pak = probe_only_mode && extracted_path.has_value() && path_looks_like_pak(extracted_path->c_str());
    const auto should_log_pak = is_focus_pak || is_probe_logged_pak;

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

    if (should_log_pak) {
        const auto seq = g_sequence.fetch_add(1) + 1;
        const auto directstorage_hits = g_directstorage_hits.fetch_add(1) + 1;
        if (directstorage_hits == 1) {
            std::ostringstream timing_oss;
            timing_oss << "virtual_target=" << static_cast<int>(is_virtual_target);
            if (extracted_path.has_value()) {
                timing_oss << " path=" << narrow_utf8(*extracted_path);
            }
            append_timing_log_line("pak-first-directstorage-hit", timing_oss.str());
        }

        std::ostringstream before;
        before << "[directstorage " << seq << "]"
               << " t_ms=" << std::dec << process_uptime_ms()
               << " directstorage_hits=" << std::dec << directstorage_hits
               << describe_caller(caller)
               << std::hex
               << " rcx=0x" << reinterpret_cast<uintptr_t>(rcx)
               << " rdx=0x" << reinterpret_cast<uintptr_t>(rdx)
               << " r8=0x" << reinterpret_cast<uintptr_t>(r8)
               << " r9=0x" << reinterpret_cast<uintptr_t>(r9)
               << "\n"
               << "focus_target=" << std::dec << static_cast<int>(is_focus_pak)
               << " probe_all_pak=" << std::dec << static_cast<int>(is_probe_logged_pak)
               << " probe_only=" << std::dec << static_cast<int>(probe_only_mode)
               << "\n"
               << "path=" << (extracted_path.has_value() ? narrow_utf8(*extracted_path) : std::string{"<unresolved>"})
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
    if (is_virtual_target && !probe_only_mode) {
        const auto runtime_source_path = current_virtual_source_path();
        if (runtime_source_path.has_value()) {
            if (should_defer_rf_chain_virtual_backend_rewrite(config, runtime_source_path)) {
                std::ostringstream oss;
                oss << "directstorage-redirect-deferred"
                    << " requested=" << (extracted_path.has_value() ? narrow_utf8(*extracted_path) : std::string{"<unresolved>"})
                    << " source=" << narrow_utf8(*runtime_source_path)
                    << "\n";
                append_log_line(oss.str());
            } else {
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
    }

    const auto result = g_original_directstorage_open(rcx, forwarded_rdx, r8, r9);

    if (should_log_pak) {
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
    if (g_read_file_ex_target == nullptr) {
        g_read_file_ex_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "ReadFileEx"));
    }
    if (g_get_overlapped_result_target == nullptr) {
        g_get_overlapped_result_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "GetOverlappedResult"));
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
    if (g_duplicate_handle_target == nullptr) {
        g_duplicate_handle_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "DuplicateHandle"));
    }
    if (g_re_open_file_target == nullptr) {
        g_re_open_file_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "ReOpenFile"));
    }
    if (g_get_final_path_name_by_handle_w_target == nullptr) {
        g_get_final_path_name_by_handle_w_target = reinterpret_cast<void*>(GetProcAddress(kernel32, "GetFinalPathNameByHandleW"));
    }
    if (g_nt_query_information_file_target == nullptr) {
        g_nt_query_information_file_target = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQueryInformationFile"));
    }
    if (g_nt_read_file_target == nullptr) {
        g_nt_read_file_target = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtReadFile"));
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

    const auto read_file_ex_ok = install_named_hook(
        g_read_file_ex_target,
        reinterpret_cast<void*>(&hooked_read_file_ex),
        reinterpret_cast<void**>(&g_original_read_file_ex),
        "ReadFileEx");
    if (read_file_ex_ok) {
        append_log_line("hook-installed target=ReadFileEx\n");
    } else {
        ok = false;
    }

    const auto get_overlapped_result_ok = install_named_hook(
        g_get_overlapped_result_target,
        reinterpret_cast<void*>(&hooked_get_overlapped_result),
        reinterpret_cast<void**>(&g_original_get_overlapped_result),
        "GetOverlappedResult");
    if (get_overlapped_result_ok) {
        append_log_line("hook-installed target=GetOverlappedResult\n");
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

    const auto duplicate_handle_ok = install_named_hook(
        g_duplicate_handle_target,
        reinterpret_cast<void*>(&hooked_duplicate_handle),
        reinterpret_cast<void**>(&g_original_duplicate_handle),
        "DuplicateHandle");
    if (duplicate_handle_ok) {
        append_log_line("hook-installed target=DuplicateHandle\n");
    } else {
        ok = false;
    }

    const auto re_open_file_ok = install_named_hook(
        g_re_open_file_target,
        reinterpret_cast<void*>(&hooked_re_open_file),
        reinterpret_cast<void**>(&g_original_re_open_file),
        "ReOpenFile");
    if (re_open_file_ok) {
        append_log_line("hook-installed target=ReOpenFile\n");
    } else {
        ok = false;
    }

    const auto get_final_path_name_ok = install_named_hook(
        g_get_final_path_name_by_handle_w_target,
        reinterpret_cast<void*>(&hooked_get_final_path_name_by_handle_w),
        reinterpret_cast<void**>(&g_original_get_final_path_name_by_handle_w),
        "GetFinalPathNameByHandleW");
    if (get_final_path_name_ok) {
        append_log_line("hook-installed target=GetFinalPathNameByHandleW\n");
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

    const auto nt_read_file_ok = install_named_hook(
        g_nt_read_file_target,
        reinterpret_cast<void*>(&hooked_nt_read_file),
        reinterpret_cast<void**>(&g_original_nt_read_file),
        "NtReadFile");
    if (nt_read_file_ok) {
        append_log_line("hook-installed target=NtReadFile\n");
    } else {
        ok = false;
    }

    std::ostringstream oss;
    oss << "pak-io-hooks"
        << " readfile=" << static_cast<int>(read_file_ok)
        << " readfileex=" << static_cast<int>(read_file_ex_ok)
        << " getoverlappedresult=" << static_cast<int>(get_overlapped_result_ok)
        << " setfilepointer=" << static_cast<int>(set_file_pointer_ok)
        << " getfilesize=" << static_cast<int>(get_file_size_ok)
        << " getfiletype=" << static_cast<int>(get_file_type_ok)
        << " getfileinfo=" << static_cast<int>(get_file_info_ok)
        << " getfileinfoex=" << static_cast<int>(get_file_info_ex_ok)
        << " createfilemapping=" << static_cast<int>(create_file_mapping_ok)
        << " mapview=" << static_cast<int>(map_view_ok)
        << " closehandle=" << static_cast<int>(close_handle_ok)
        << " duplicatehandle=" << static_cast<int>(duplicate_handle_ok)
        << " reopenfile=" << static_cast<int>(re_open_file_ok)
        << " getfinalpathname=" << static_cast<int>(get_final_path_name_ok)
        << " ntqueryinfo=" << static_cast<int>(nt_query_info_ok)
        << " ntreadfile=" << static_cast<int>(nt_read_file_ok)
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

