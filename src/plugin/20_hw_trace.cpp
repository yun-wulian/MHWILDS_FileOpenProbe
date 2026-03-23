#include "plugin_internal.hpp"

namespace mhwilds::probe {

#if defined(MHWILDS_VERSION_PROXY)
uint64_t encode_hw_breakpoint_dr7(uint64_t dr7, int slot, bool enable, HwBreakpointType type, size_t size);

const char* hw_trace_watch_slot_name(int slot) {
    switch (slot) {
    case kWatchBreakpointSlotNode58:
        return "node+0x58";
    case kWatchBreakpointSlotNode60:
        return "node+0x60";
    case kWatchBreakpointSlotOwner2A0:
        return "owner+0x2A0";
    default:
        return "watch";
    }
}

uintptr_t* context_debug_address_register(CONTEXT* context, int slot) {
    if (context == nullptr) {
        return nullptr;
    }

    switch (slot) {
    case 0:
        return &context->Dr0;
    case 1:
        return &context->Dr1;
    case 2:
        return &context->Dr2;
    case 3:
        return &context->Dr3;
    default:
        return nullptr;
    }
}

std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount> snapshot_hw_trace_slot_configs() {
    std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount> slots{};
    for (size_t slot = 0; slot < kHwBreakpointSlotCount; ++slot) {
        const auto address = g_hw_trace_slot_addrs[slot].load();
        slots[slot].enabled = address != 0;
        slots[slot].address = address;
        slots[slot].type = static_cast<HwBreakpointType>(g_hw_trace_slot_types[slot].load());
        slots[slot].size = g_hw_trace_slot_sizes[slot].load();
    }
    return slots;
}

void store_hw_trace_slot_configs(const std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount>& slots) {
    uint32_t watch_mask = 0;
    for (size_t slot = 0; slot < kHwBreakpointSlotCount; ++slot) {
        g_hw_trace_slot_addrs[slot] = slots[slot].enabled ? slots[slot].address : 0;
        g_hw_trace_slot_types[slot] = static_cast<int>(slots[slot].type);
        g_hw_trace_slot_sizes[slot] = slots[slot].size;
        if (slot != static_cast<size_t>(kEntryBreakpointSlot) && slots[slot].enabled) {
            watch_mask |= (1u << slot);
        }
    }

    if (slots[kWatchBreakpointSlotNode58].enabled) {
        watch_mask |= (1u << kWatchBreakpointSlotNode58);
    }

    g_hw_trace_watch_mask = watch_mask;
}

bool configure_thread_breakpoints(HANDLE thread, DWORD thread_id, const std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount>& slots) {
    if (thread == nullptr) {
        return false;
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    const auto current_thread_id = GetCurrentThreadId();
    bool suspended = false;
    if (thread_id != current_thread_id) {
        const auto suspend_result = SuspendThread(thread);
        if (suspend_result == static_cast<DWORD>(-1)) {
            return false;
        }
        suspended = true;
    }

    context.Dr0 = slots[0].enabled ? slots[0].address : 0;
    context.Dr1 = slots[1].enabled ? slots[1].address : 0;
    context.Dr2 = slots[2].enabled ? slots[2].address : 0;
    context.Dr3 = slots[3].enabled ? slots[3].address : 0;
    context.Dr6 = 0;
    context.Dr7 = 0;

    for (int slot = 0; slot < static_cast<int>(kHwBreakpointSlotCount); ++slot) {
        context.Dr7 = encode_hw_breakpoint_dr7(context.Dr7, slot, slots[slot].enabled, slots[slot].type, slots[slot].size);
    }

    const auto set_ok = SetThreadContext(thread, &context) != FALSE;
    if (suspended) {
        ResumeThread(thread);
    }

    return set_ok;
}

bool apply_hw_trace_breakpoints_to_process(const std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount>& slots, size_t* applied_threads, size_t* failed_threads) {
    if (applied_threads != nullptr) {
        *applied_threads = 0;
    }
    if (failed_threads != nullptr) {
        *failed_threads = 0;
    }

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    const auto process_id = GetCurrentProcessId();
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    bool saw_target_thread = false;

    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != process_id) {
                continue;
            }

            saw_target_thread = true;
            const auto thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (thread == nullptr) {
                if (failed_threads != nullptr) {
                    ++(*failed_threads);
                }
                continue;
            }

            const auto ok = configure_thread_breakpoints(thread, entry.th32ThreadID, slots);
            CloseHandle(thread);

            if (ok) {
                if (applied_threads != nullptr) {
                    ++(*applied_threads);
                }
            } else if (failed_threads != nullptr) {
                ++(*failed_threads);
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return saw_target_thread;
}

uint64_t encode_hw_breakpoint_dr7(uint64_t dr7, int slot, bool enable, HwBreakpointType type = HwBreakpointType::Execute, size_t size = 1) {
    const auto enable_shift = static_cast<uint64_t>(slot * 2);
    const auto rwlen_shift = static_cast<uint64_t>(16 + slot * 4);
    dr7 &= ~((uint64_t{0x3}) << enable_shift);
    dr7 &= ~((uint64_t{0xF}) << rwlen_shift);
    if (enable) {
        dr7 |= (uint64_t{0x1} << enable_shift);
        uint64_t len_bits = 0;
        switch (size) {
        case 1:
            len_bits = 0;
            break;
        case 2:
            len_bits = 1;
            break;
        case 8:
            len_bits = 2;
            break;
        case 4:
        default:
            len_bits = 3;
            break;
        }

        const auto rw_bits = static_cast<uint64_t>(type);
        dr7 |= ((rw_bits | (len_bits << 2)) << rwlen_shift);
    }
    return dr7;
}

bool configure_thread_breakpoint(HANDLE thread, DWORD thread_id, uintptr_t address, bool enable, HwBreakpointType type = HwBreakpointType::Execute, size_t size = 1) {
    std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount> slots{};
    slots[kEntryBreakpointSlot].enabled = enable;
    slots[kEntryBreakpointSlot].address = address;
    slots[kEntryBreakpointSlot].type = type;
    slots[kEntryBreakpointSlot].size = size;
    return configure_thread_breakpoints(thread, thread_id, slots);
}

bool apply_hw_trace_breakpoint_to_process(uintptr_t address, bool enable, size_t* applied_threads, size_t* failed_threads, HwBreakpointType type = HwBreakpointType::Execute, size_t size = 1) {
    std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount> slots{};
    slots[kEntryBreakpointSlot].enabled = enable;
    slots[kEntryBreakpointSlot].address = address;
    slots[kEntryBreakpointSlot].type = type;
    slots[kEntryBreakpointSlot].size = size;
    return apply_hw_trace_breakpoints_to_process(slots, applied_threads, failed_threads);
}

std::string format_trace_registers(const CONTEXT& context) {
    std::ostringstream oss;
    oss << std::hex
        << "rax=0x" << context.Rax
        << " rbx=0x" << context.Rbx
        << " rcx=0x" << context.Rcx
        << " rdx=0x" << context.Rdx
        << " r8=0x" << context.R8
        << " r9=0x" << context.R9
        << " r10=0x" << context.R10
        << " r11=0x" << context.R11
        << " r12=0x" << context.R12
        << " r13=0x" << context.R13
        << " r14=0x" << context.R14
        << " r15=0x" << context.R15
        << " rsi=0x" << context.Rsi
        << " rdi=0x" << context.Rdi
        << " rsp=0x" << context.Rsp
        << " rbp=0x" << context.Rbp;
    return oss.str();
}

std::string describe_address_module(uintptr_t address, const char* prefix) {
    HMODULE module{};
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &module) == FALSE ||
        module == nullptr) {
        return {};
    }

    const auto module_path = widen_module_path(module);
    const auto module_name = std::filesystem::path(module_path).filename().wstring();
    std::ostringstream oss;
    oss << " " << prefix << "_module=" << narrow_utf8(module_name)
        << " " << prefix << "_base=0x" << std::hex << reinterpret_cast<uintptr_t>(module)
        << " " << prefix << "_rva=0x" << (address - reinterpret_cast<uintptr_t>(module));
    return oss.str();
}

void append_hw_trace_stack_snapshot(const CONTEXT& context, const char* reason) {
    std::ostringstream header;
    header << "hw-trace-stack"
           << " reason=" << reason
           << " tid=" << GetCurrentThreadId()
           << " rsp=0x" << std::hex << context.Rsp
           << " rbp=0x" << context.Rbp
           << "\n";
    append_trace_log_line(header.str());

    for (size_t i = 0; i < kWatchTraceStackSnapshotEntries; ++i) {
        const auto slot_addr = static_cast<uintptr_t>(context.Rsp + (i * sizeof(uint64_t)));
        uint64_t slot_value{};
        if (!read_memory_block_safe(reinterpret_cast<const void*>(slot_addr), &slot_value, sizeof(slot_value))) {
            std::ostringstream oss;
            oss << "hw-trace-stack-slot"
                << " index=" << std::dec << i
                << " addr=0x" << std::hex << slot_addr
                << " unreadable=1\n";
            append_trace_log_line(oss.str());
            continue;
        }

        std::ostringstream oss;
        oss << "hw-trace-stack-slot"
            << " index=" << std::dec << i
            << " addr=0x" << std::hex << slot_addr
            << " value=0x" << slot_value
            << describe_address_module(static_cast<uintptr_t>(slot_value), "value")
            << "\n";
        append_trace_log_line(oss.str());
    }
}

std::optional<std::string> describe_trace_branch_target(uintptr_t rip) {
    uint8_t bytes[6]{};
    if (!read_memory_block_safe(reinterpret_cast<const void*>(rip), bytes, sizeof(bytes))) {
        return std::nullopt;
    }

    auto format_rel_target = [rip](const char* kind, int64_t displacement, size_t length) {
        const auto target = static_cast<uintptr_t>(rip + length + displacement);
        std::ostringstream oss;
        oss << " " << kind << "=0x" << std::hex << target
            << describe_address_module(target, "branch");
        return oss.str();
    };

    if (bytes[0] == 0xE8) {
        int32_t displacement{};
        if (read_memory_block_safe(reinterpret_cast<const void*>(rip + 1), &displacement, sizeof(displacement))) {
            return format_rel_target("call_rel32", displacement, 5);
        }
    }

    if (bytes[0] == 0xE9) {
        int32_t displacement{};
        if (read_memory_block_safe(reinterpret_cast<const void*>(rip + 1), &displacement, sizeof(displacement))) {
            return format_rel_target("jmp_rel32", displacement, 5);
        }
    }

    if (bytes[0] == 0xEB) {
        int8_t displacement{};
        if (read_memory_block_safe(reinterpret_cast<const void*>(rip + 1), &displacement, sizeof(displacement))) {
            return format_rel_target("jmp_rel8", displacement, 2);
        }
    }

    if (bytes[0] >= 0x70 && bytes[0] <= 0x7F) {
        int8_t displacement{};
        if (read_memory_block_safe(reinterpret_cast<const void*>(rip + 1), &displacement, sizeof(displacement))) {
            return format_rel_target("jcc_rel8", displacement, 2);
        }
    }

    if (bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F) {
        int32_t displacement{};
        if (read_memory_block_safe(reinterpret_cast<const void*>(rip + 2), &displacement, sizeof(displacement))) {
            return format_rel_target("jcc_rel32", displacement, 6);
        }
    }

    return std::nullopt;
}

const char* hw_trace_capture_phase_name(HwTraceCaptureKind kind, bool is_breakpoint) {
    if (kind == HwTraceCaptureKind::Watch) {
        return is_breakpoint ? "watch_breakpoint" : "watch_single_step";
    }

    return is_breakpoint ? "breakpoint" : "single_step";
}

const char* hw_breakpoint_type_name(HwBreakpointType type) {
    switch (type) {
    case HwBreakpointType::Execute:
        return "execute";
    case HwBreakpointType::Write:
        return "write";
    case HwBreakpointType::Io:
        return "io";
    case HwBreakpointType::ReadWrite:
        return "readwrite";
    default:
        return "unknown";
    }
}

uint32_t current_hw_trace_max_instructions(HwTraceCaptureKind kind) {
    if (kind == HwTraceCaptureKind::Watch) {
        return std::max<uint32_t>(g_hw_trace_max_instructions, kDefaultWatchTraceMaxInstructions);
    }

    return g_hw_trace_max_instructions;
}

bool should_log_hw_trace_step(const CONTEXT& context, uint32_t step, HwTraceCaptureKind kind) {
    if (kind != HwTraceCaptureKind::Watch) {
        return true;
    }

    if (step <= kWatchTraceDetailedPrefixSteps) {
        return true;
    }

    if (describe_trace_branch_target(context.Rip).has_value()) {
        return true;
    }

    if (t_hw_trace_last_logged_rip == 0) {
        return true;
    }

    const auto delta = context.Rip >= t_hw_trace_last_logged_rip
        ? (context.Rip - t_hw_trace_last_logged_rip)
        : (t_hw_trace_last_logged_rip - context.Rip);

    if (delta >= 0x40) {
        return true;
    }

    return (step % kWatchTracePeriodicStepInterval) == 0;
}

void log_hw_trace_step(const CONTEXT& context, uint32_t step, const char* phase);

void clear_current_hw_trace_breakpoint(CONTEXT* context) {
    if (context == nullptr) {
        return;
    }

    context->Dr6 = 0;
    for (int slot = 0; slot < static_cast<int>(kHwBreakpointSlotCount); ++slot) {
        if (auto* address_register = context_debug_address_register(context, slot); address_register != nullptr) {
            *address_register = 0;
        }
        context->Dr7 = encode_hw_breakpoint_dr7(context->Dr7, slot, false);
    }
}

bool try_arm_second_stage_hw_trace_watchpoint(const CONTEXT& context) {
    if (g_game_module_base == 0 || context.Rip != (g_game_module_base + kSecondStageTraceArmRva) || context.Rsi == 0) {
        return false;
    }

    const auto node_base = static_cast<uintptr_t>(context.Rsi);
    const auto owner_base = static_cast<uintptr_t>(context.Rdi);
    std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount> slots{};

    slots[kWatchBreakpointSlotNode58].enabled = true;
    slots[kWatchBreakpointSlotNode58].address = node_base + kSecondStageTraceWatchFieldOffset;
    slots[kWatchBreakpointSlotNode58].type = HwBreakpointType::ReadWrite;
    slots[kWatchBreakpointSlotNode58].size = kSecondStageTraceWatchSize;

    slots[kWatchBreakpointSlotNode60].enabled = true;
    slots[kWatchBreakpointSlotNode60].address = node_base + kSecondStageTraceWatchNextFieldOffset;
    slots[kWatchBreakpointSlotNode60].type = HwBreakpointType::ReadWrite;
    slots[kWatchBreakpointSlotNode60].size = kSecondStageTraceWatchSize;

    if (owner_base != 0) {
        slots[kWatchBreakpointSlotOwner2A0].enabled = true;
        slots[kWatchBreakpointSlotOwner2A0].address = owner_base + kSecondStageTraceOwnerFieldOffset;
        slots[kWatchBreakpointSlotOwner2A0].type = HwBreakpointType::ReadWrite;
        slots[kWatchBreakpointSlotOwner2A0].size = kSecondStageTraceWatchSize;
    }

    size_t applied_threads = 0;
    size_t failed_threads = 0;
    const auto ok = apply_hw_trace_breakpoints_to_process(slots, &applied_threads, &failed_threads);
    if (!ok || applied_threads == 0) {
        std::ostringstream oss;
        oss << "hw-trace-watch-arm-failed"
            << " node=0x" << std::hex << node_base
            << " owner=0x" << owner_base
            << std::dec
            << " applied_threads=" << applied_threads
            << " failed_threads=" << failed_threads
            << "\n";
        append_trace_log_line(oss.str());
        return false;
    }

    store_hw_trace_slot_configs(slots);
    g_hw_trace_breakpoint_type = static_cast<int>(HwBreakpointType::ReadWrite);
    g_hw_trace_breakpoint_size = kSecondStageTraceWatchSize;
    g_hw_trace_watch_addr = slots[kWatchBreakpointSlotNode58].address;
    g_hw_trace_watch_hit_slot = -1;
    g_hw_trace_watch_origin_thread_id = GetCurrentThreadId();
    g_hw_trace_watch_origin_ignored_hits = 0;
    g_hw_trace_watch_armed = true;
    g_hw_trace_watch_triggered = false;
    g_hw_trace_started = false;
    g_hw_trace_finished = false;
    g_hw_trace_active_thread_id = 0;
    g_hw_trace_logged_steps = 0;

    std::ostringstream oss;
    oss << "hw-trace-watch-armed"
        << " node=0x" << std::hex << node_base
        << " owner=0x" << owner_base
        << " slot0_addr=0x" << slots[kWatchBreakpointSlotNode58].address
        << " slot0_label=" << hw_trace_watch_slot_name(kWatchBreakpointSlotNode58)
        << " slot1_addr=0x" << slots[kWatchBreakpointSlotNode60].address
        << " slot1_label=" << hw_trace_watch_slot_name(kWatchBreakpointSlotNode60)
        << " slot2_addr=0x" << slots[kWatchBreakpointSlotOwner2A0].address
        << " slot2_label=" << hw_trace_watch_slot_name(kWatchBreakpointSlotOwner2A0)
        << " watch_mask=0x" << g_hw_trace_watch_mask.load()
        << std::dec
        << " origin_tid=" << g_hw_trace_watch_origin_thread_id.load()
        << " size=" << kSecondStageTraceWatchSize
        << " applied_threads=" << applied_threads
        << " failed_threads=" << failed_threads
        << "\n";
    append_trace_log_line(oss.str());
    ensure_hw_trace_refresh_thread_running("watchpoint");
    return true;
}

void begin_hw_trace_single_step(CONTEXT* context, DWORD thread_id, uintptr_t address, HwTraceCaptureKind kind) {
    if (context == nullptr) {
        return;
    }

    clear_current_hw_trace_breakpoint(context);

    t_hw_trace_single_step_active = true;
    t_hw_trace_single_step_index = 0;
    t_hw_trace_capture_kind = kind;
    t_hw_trace_last_logged_rip = 0;
    g_hw_trace_logged_steps = 1;
    const auto max_instructions = current_hw_trace_max_instructions(kind);

    std::ostringstream oss;
    if (kind == HwTraceCaptureKind::Watch) {
        const auto watch_slot = g_hw_trace_watch_hit_slot.load();
        oss << "hw-trace-watch-hit"
            << " tid=" << thread_id
            << " rip=0x" << std::hex << address
            << " slot=" << std::dec << watch_slot
            << " label=" << hw_trace_watch_slot_name(watch_slot)
            << std::hex
            << " watch_addr=0x" << g_hw_trace_watch_addr.load()
            << std::dec
            << " max_steps=" << max_instructions
            << "\n";
    } else {
        oss << "hw-trace-hit"
            << " tid=" << thread_id
            << " addr=0x" << std::hex << address
            << std::dec
            << " max_steps=" << max_instructions
            << "\n";
    }
    append_trace_log_line(oss.str());

    if (kind == HwTraceCaptureKind::Watch) {
        append_hw_trace_stack_snapshot(*context, "watch-hit");
    }

    log_hw_trace_step(*context, 0, hw_trace_capture_phase_name(kind, true));

    if (max_instructions <= 1) {
        g_hw_trace_finished = true;
        g_hw_trace_active_thread_id = 0;
        t_hw_trace_single_step_active = false;
        t_hw_trace_single_step_index = 0;
        t_hw_trace_last_logged_rip = 0;
        append_trace_log_line("hw-trace-finished steps=1\n");
    } else {
        context->EFlags |= 0x100u;
    }
}

DWORD WINAPI hw_trace_refresh_thread_proc(LPVOID) {
    run_hw_trace_reapply_loop();
    g_hw_trace_refresh_thread_started = false;
    return 0;
}

void ensure_hw_trace_refresh_thread_running(const char* source) {
    bool expected = false;
    if (!g_hw_trace_refresh_thread_started.compare_exchange_strong(expected, true)) {
        return;
    }

    const auto thread = CreateThread(nullptr, 0, &hw_trace_refresh_thread_proc, nullptr, 0, nullptr);
    if (thread == nullptr) {
        g_hw_trace_refresh_thread_started = false;
        std::ostringstream oss;
        oss << "hw-trace-refresh-thread-create-failed"
            << " source=" << source
            << "\n";
        append_trace_log_line(oss.str());
        return;
    }

    CloseHandle(thread);

    std::ostringstream oss;
    oss << "hw-trace-refresh-thread-started"
        << " source=" << source
        << "\n";
    append_trace_log_line(oss.str());
}

void log_hw_trace_step(const CONTEXT& context, uint32_t step, const char* phase) {
    std::ostringstream oss;
    oss << "hw-trace-step"
        << " phase=" << phase
        << " step=" << std::dec << step
        << " tid=" << GetCurrentThreadId()
        << " rip=0x" << std::hex << context.Rip;

    if (g_game_module_base != 0 && context.Rip >= g_game_module_base) {
        oss << " rva=0x" << (context.Rip - g_game_module_base);
    }

    oss << describe_address_module(context.Rip, "rip");

    oss << " bytes=" << dump_bytes(reinterpret_cast<const void*>(context.Rip), kTraceBytePreviewCount);

    if (const auto branch = describe_trace_branch_target(context.Rip); branch.has_value()) {
        oss << *branch;
    }

    oss << " " << format_trace_registers(context) << "\n";
    append_trace_log_line(oss.str());
    t_hw_trace_last_logged_rip = context.Rip;
}

LONG CALLBACK hw_trace_veh_handler(EXCEPTION_POINTERS* exception_info) {
    if (exception_info == nullptr || exception_info->ExceptionRecord == nullptr || exception_info->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (exception_info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    auto* context = exception_info->ContextRecord;
    const auto address = reinterpret_cast<uintptr_t>(exception_info->ExceptionRecord->ExceptionAddress);
    const auto thread_id = GetCurrentThreadId();
    const auto hit_mask = static_cast<uint32_t>(context->Dr6 & 0xFu);

    if (g_hw_trace_finished.load()) {
        clear_current_hw_trace_breakpoint(context);
        context->EFlags &= ~0x100u;
        t_hw_trace_single_step_active = false;
        t_hw_trace_single_step_index = 0;
        t_hw_trace_last_logged_rip = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (t_hw_trace_single_step_active) {
        const auto step = ++t_hw_trace_single_step_index;
        g_hw_trace_logged_steps = step + 1;
        const auto capture_kind = t_hw_trace_capture_kind;
        const auto max_instructions = current_hw_trace_max_instructions(capture_kind);
        if (should_log_hw_trace_step(*context, step, capture_kind)) {
            log_hw_trace_step(*context, step, hw_trace_capture_phase_name(capture_kind, false));
        }

        if (step + 1 >= max_instructions) {
            g_hw_trace_active_thread_id = 0;
            context->EFlags &= ~0x100u;
            t_hw_trace_single_step_active = false;
            t_hw_trace_single_step_index = 0;
            t_hw_trace_capture_kind = HwTraceCaptureKind::Entry;
            t_hw_trace_last_logged_rip = 0;

            if (capture_kind == HwTraceCaptureKind::Entry && !g_hw_trace_watch_armed.load() && try_arm_second_stage_hw_trace_watchpoint(*context)) {
                clear_current_hw_trace_breakpoint(context);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            g_hw_trace_finished = true;
            clear_current_hw_trace_breakpoint(context);

            std::ostringstream oss;
            oss << "hw-trace-finished"
                << " steps=" << std::dec << g_hw_trace_logged_steps.load()
                << " capture=" << (capture_kind == HwTraceCaptureKind::Watch ? "watch" : "entry")
                << " tid=" << thread_id
                << "\n";
            append_trace_log_line(oss.str());
        } else {
            context->Dr6 = 0;
            context->EFlags |= 0x100u;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (!g_hw_trace_installed.load()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto watch_stage = g_hw_trace_watch_armed.load();
    int hit_slot = -1;
    if (watch_stage) {
        const auto watch_mask = g_hw_trace_watch_mask.load();
        const auto matched_mask = hit_mask & watch_mask;
        if (matched_mask == 0) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        for (int slot = 0; slot < static_cast<int>(kHwBreakpointSlotCount); ++slot) {
            if ((matched_mask & (1u << slot)) != 0) {
                hit_slot = slot;
                break;
            }
        }
        if (hit_slot < 0) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        g_hw_trace_watch_hit_slot = hit_slot;
        g_hw_trace_watch_addr = g_hw_trace_slot_addrs[hit_slot].load();

        const auto origin_thread_id = g_hw_trace_watch_origin_thread_id.load();
        if (origin_thread_id != 0 && thread_id == origin_thread_id) {
            const auto ignored_hits = g_hw_trace_watch_origin_ignored_hits.fetch_add(1) + 1;
            if (ignored_hits <= 4) {
                std::ostringstream oss;
                oss << "hw-trace-watch-origin-skip"
                    << " tid=" << thread_id
                    << " slot=" << hit_slot
                    << " label=" << hw_trace_watch_slot_name(hit_slot)
                    << " watch_addr=0x" << std::hex << g_hw_trace_watch_addr.load()
                    << std::dec
                    << " ignored_hits=" << ignored_hits
                    << "\n";
                append_trace_log_line(oss.str());
            }

            clear_current_hw_trace_breakpoint(context);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } else if (address != g_hw_trace_start_addr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD expected = 0;
    if (!g_hw_trace_active_thread_id.compare_exchange_strong(expected, thread_id)) {
        clear_current_hw_trace_breakpoint(context);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    const auto duplicate_hit = watch_stage ? g_hw_trace_watch_triggered.exchange(true) : g_hw_trace_started.exchange(true);
    if (duplicate_hit) {
        clear_current_hw_trace_breakpoint(context);
        g_hw_trace_active_thread_id = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    begin_hw_trace_single_step(context, thread_id, address, watch_stage ? HwTraceCaptureKind::Watch : HwTraceCaptureKind::Entry);
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool install_hw_instruction_trace(const VirtualPakLoaderConfig& config) {
    if (!config.trace_enabled) {
        return false;
    }

    initialize_fixed_addresses();
    if (g_game_module_base == 0) {
        open_trace_log_if_needed();
        append_trace_log_line("hw-trace-install-missing-module-base\n");
        return false;
    }

    if (g_hw_trace_installed.load()) {
        return true;
    }

    open_trace_log_if_needed();

    const auto start_rva = config.trace_start_rva != 0 ? config.trace_start_rva : kDefaultTraceStartRva;
    g_hw_trace_start_addr = g_game_module_base + start_rva;
    g_hw_trace_max_instructions = std::max<uint32_t>(1u, config.trace_max_instructions);
    g_hw_trace_breakpoint_type = static_cast<int>(HwBreakpointType::Execute);
    g_hw_trace_breakpoint_size = 1;
    for (size_t slot = 0; slot < kHwBreakpointSlotCount; ++slot) {
        g_hw_trace_slot_addrs[slot] = 0;
        g_hw_trace_slot_types[slot] = static_cast<int>(HwBreakpointType::Execute);
        g_hw_trace_slot_sizes[slot] = 1;
    }
    g_hw_trace_slot_addrs[kEntryBreakpointSlot] = g_hw_trace_start_addr;
    g_hw_trace_slot_types[kEntryBreakpointSlot] = static_cast<int>(HwBreakpointType::Execute);
    g_hw_trace_slot_sizes[kEntryBreakpointSlot] = 1;
    g_hw_trace_watch_mask = 0;
    g_hw_trace_watch_addr = 0;
    g_hw_trace_watch_hit_slot = -1;
    g_hw_trace_watch_origin_thread_id = 0;
    g_hw_trace_watch_origin_ignored_hits = 0;
    g_hw_trace_watch_armed = false;
    g_hw_trace_watch_triggered = false;
    g_hw_trace_started = false;
    g_hw_trace_finished = false;
    g_hw_trace_active_thread_id = 0;
    g_hw_trace_logged_steps = 0;

    if (g_hw_trace_veh_handle == nullptr) {
        g_hw_trace_veh_handle = AddVectoredExceptionHandler(1, &hw_trace_veh_handler);
        if (g_hw_trace_veh_handle == nullptr) {
            append_trace_log_line("hw-trace-veh-install-failed\n");
            return false;
        }
    }

    size_t applied_threads = 0;
    size_t failed_threads = 0;
    const auto enumerated = apply_hw_trace_breakpoint_to_process(
        g_hw_trace_start_addr,
        true,
        &applied_threads,
        &failed_threads,
        HwBreakpointType::Execute,
        1);
    g_hw_trace_installed = enumerated && applied_threads > 0;

    std::ostringstream oss;
    oss << "hw-trace-install"
        << " enabled=" << static_cast<int>(config.trace_enabled)
        << " start_rva=0x" << std::hex << start_rva
        << " start_addr=0x" << g_hw_trace_start_addr
        << " type=" << hw_breakpoint_type_name(HwBreakpointType::Execute)
        << " max_steps=" << std::dec << g_hw_trace_max_instructions
        << " applied_threads=" << applied_threads
        << " failed_threads=" << failed_threads
        << " ok=" << static_cast<int>(g_hw_trace_installed.load())
        << "\n";
    append_trace_log_line(oss.str());
    return g_hw_trace_installed.load();
}

void run_hw_trace_reapply_loop() {
    if (!g_hw_trace_installed.load()) {
        g_hw_trace_refresh_thread_started = false;
        return;
    }

    append_trace_log_line("hw-trace-refresh-loop-start\n");

    for (uint32_t attempt = 1; attempt <= 160; ++attempt) {
        if (g_shutdown_requested.load() || g_hw_trace_started.load() || g_hw_trace_finished.load() || !g_hw_trace_installed.load()) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        size_t applied_threads = 0;
        size_t failed_threads = 0;
        const auto slots = snapshot_hw_trace_slot_configs();
        apply_hw_trace_breakpoints_to_process(slots, &applied_threads, &failed_threads);

        if (attempt == 1 || (attempt % 20) == 0 || failed_threads != 0) {
            std::ostringstream oss;
            oss << "hw-trace-refresh"
                << " attempt=" << attempt
                << " stage=" << (g_hw_trace_watch_armed.load() ? "watch" : "entry")
                << " mask=0x" << std::hex << g_hw_trace_watch_mask.load()
                << " slot0=0x" << g_hw_trace_slot_addrs[0].load()
                << " slot1=0x" << g_hw_trace_slot_addrs[1].load()
                << " slot2=0x" << g_hw_trace_slot_addrs[2].load()
                << std::dec
                << " applied_threads=" << applied_threads
                << " failed_threads=" << failed_threads
                << " started=" << static_cast<int>(g_hw_trace_started.load())
                << " finished=" << static_cast<int>(g_hw_trace_finished.load())
                << "\n";
            append_trace_log_line(oss.str());
        }
    }

    std::ostringstream oss;
    oss << "hw-trace-refresh-loop-end"
        << " started=" << static_cast<int>(g_hw_trace_started.load())
        << " finished=" << static_cast<int>(g_hw_trace_finished.load())
        << "\n";
    append_trace_log_line(oss.str());
    g_hw_trace_refresh_thread_started = false;
}

void uninstall_hw_instruction_trace() {
    if (g_hw_trace_start_addr != 0 || g_hw_trace_watch_mask.load() != 0) {
        size_t applied_threads = 0;
        size_t failed_threads = 0;
        std::array<HwBreakpointSlotConfig, kHwBreakpointSlotCount> cleared_slots{};
        apply_hw_trace_breakpoints_to_process(cleared_slots, &applied_threads, &failed_threads);
    }

    if (g_hw_trace_veh_handle != nullptr) {
        RemoveVectoredExceptionHandler(g_hw_trace_veh_handle);
        g_hw_trace_veh_handle = nullptr;
    }

    g_hw_trace_installed = false;
    g_hw_trace_started = false;
    g_hw_trace_finished = false;
    g_hw_trace_active_thread_id = 0;
    g_hw_trace_logged_steps = 0;
    g_hw_trace_breakpoint_type = static_cast<int>(HwBreakpointType::Execute);
    g_hw_trace_breakpoint_size = 1;
    for (size_t slot = 0; slot < kHwBreakpointSlotCount; ++slot) {
        g_hw_trace_slot_addrs[slot] = 0;
        g_hw_trace_slot_types[slot] = static_cast<int>(HwBreakpointType::Execute);
        g_hw_trace_slot_sizes[slot] = 1;
    }
    g_hw_trace_watch_mask = 0;
    g_hw_trace_watch_addr = 0;
    g_hw_trace_watch_hit_slot = -1;
    g_hw_trace_watch_origin_thread_id = 0;
    g_hw_trace_watch_origin_ignored_hits = 0;
    g_hw_trace_watch_armed = false;
    g_hw_trace_watch_triggered = false;
    g_hw_trace_start_addr = 0;
    g_hw_trace_max_instructions = kDefaultTraceMaxInstructions;
    g_hw_trace_refresh_thread_started = false;
}
#endif

} // namespace mhwilds::probe

