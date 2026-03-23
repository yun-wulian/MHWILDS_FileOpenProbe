#if defined(MHWILDS_VERSION_PROXY)
constexpr wchar_t kLoaderUpdatePostUrl[] = L"https://www.caimogu.cc/post/2339976.html";
constexpr int kUpdatePromptOpenButtonId = 1001;
constexpr int kUpdatePromptIgnoreButtonId = 1002;
constexpr uint32_t kLoaderUpdateRetryDelayMs = 15000;
constexpr uint32_t kModUpdateInterRequestDelayMs = 250;
constexpr size_t kPromptAnnouncementMaxChars = 120;

struct SimpleVersion {
    std::array<int, 4> parts{};
    size_t part_count{};
    std::string raw{};
};

struct LoaderUpdateCacheRecord {
    std::string remote_version{};
    std::string announcement{};
    std::wstring source_url{};
    int64_t last_checked_unix_seconds{};
};

struct RemoteUpdateInfo {
    std::string remote_version{};
    std::string announcement{};
    std::wstring source_url{};
};

struct ScopedWinHttpHandle {
    HINTERNET handle{};

    ~ScopedWinHttpHandle() {
        if (handle != nullptr) {
            WinHttpCloseHandle(handle);
        }
    }
};

std::string to_lower_ascii_copy(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    return value;
}

std::string replace_all_copy(std::string value, std::string_view from, std::string_view to) {
    size_t cursor = 0;
    while ((cursor = value.find(from.data(), cursor, from.size())) != std::string::npos) {
        value.replace(cursor, from.size(), to.data(), to.size());
        cursor += to.size();
    }

    return value;
}

std::string html_decode_basic(std::string value) {
    value = replace_all_copy(std::move(value), "&nbsp;", " ");
    value = replace_all_copy(std::move(value), "&amp;", "&");
    value = replace_all_copy(std::move(value), "&lt;", "<");
    value = replace_all_copy(std::move(value), "&gt;", ">");
    value = replace_all_copy(std::move(value), "&quot;", "\"");
    value = replace_all_copy(std::move(value), "&#39;", "'");
    return value;
}

std::optional<std::string> extract_first_version_token(std::string_view text) {
    static const std::regex version_regex{R"((\d+(?:\.\d+){1,3}))"};
    std::smatch match{};
    const std::string owned_text{text};
    if (!std::regex_search(owned_text, match, version_regex) || match.size() < 2) {
        return std::nullopt;
    }

    return trim_ascii_copy(match[1].str());
}

std::optional<SimpleVersion> parse_simple_version(std::string_view text) {
    const auto token = extract_first_version_token(text);
    if (!token.has_value()) {
        return std::nullopt;
    }

    SimpleVersion version{};
    version.raw = *token;

    size_t begin = 0;
    while (begin < token->size() && version.part_count < version.parts.size()) {
        const auto end = token->find('.', begin);
        const auto chunk = token->substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        char* parse_end = nullptr;
        const auto parsed = std::strtol(chunk.c_str(), &parse_end, 10);
        if (parse_end == chunk.c_str() || *parse_end != '\0') {
            return std::nullopt;
        }

        version.parts[version.part_count++] = static_cast<int>(parsed);
        if (end == std::string::npos) {
            break;
        }

        begin = end + 1;
    }

    if (version.part_count == 0) {
        return std::nullopt;
    }

    return version;
}

std::optional<SimpleVersion> parse_simple_version(std::wstring_view text) {
    return parse_simple_version(narrow_utf8(std::wstring{text}));
}

int compare_simple_version(const SimpleVersion& left, const SimpleVersion& right) {
    for (size_t index = 0; index < left.parts.size(); ++index) {
        if (left.parts[index] < right.parts[index]) {
            return -1;
        }

        if (left.parts[index] > right.parts[index]) {
            return 1;
        }
    }

    return 0;
}

std::optional<std::wstring> decode_bytes_with_code_page(const std::vector<uint8_t>& bytes, UINT code_page, DWORD flags) {
    if (bytes.empty()) {
        return std::wstring{};
    }

    const auto needed = MultiByteToWideChar(
        code_page,
        flags,
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<int>(bytes.size()),
        nullptr,
        0);
    if (needed <= 0) {
        return std::nullopt;
    }

    std::wstring wide(static_cast<size_t>(needed), L'\0');
    const auto written = MultiByteToWideChar(
        code_page,
        flags,
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<int>(bytes.size()),
        wide.data(),
        needed);
    if (written != needed) {
        return std::nullopt;
    }

    return wide;
}

std::optional<std::string> decode_http_body_to_utf8(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return std::string{};
    }

    const std::array<std::pair<UINT, DWORD>, 4> attempts{{
        {CP_UTF8, MB_ERR_INVALID_CHARS},
        {54936, 0},
        {936, 0},
        {CP_UTF8, 0},
    }};

    for (const auto& [code_page, flags] : attempts) {
        const auto wide = decode_bytes_with_code_page(bytes, code_page, flags);
        if (!wide.has_value()) {
            continue;
        }

        return narrow_utf8(*wide);
    }

    return std::nullopt;
}

std::optional<std::string> http_get_utf8_body(std::wstring_view url) {
    if (url.empty()) {
        return std::nullopt;
    }

    URL_COMPONENTSW components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    std::wstring url_copy{url};
    if (!WinHttpCrackUrl(url_copy.c_str(), 0, 0, &components)) {
        return std::nullopt;
    }

    const std::wstring host{components.lpszHostName, components.dwHostNameLength};
    std::wstring path = components.dwUrlPathLength > 0
        ? std::wstring{components.lpszUrlPath, components.dwUrlPathLength}
        : std::wstring{L"/"};
    if (components.dwExtraInfoLength > 0) {
        path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }

    ScopedWinHttpHandle session{};
    ScopedWinHttpHandle connection{};
    ScopedWinHttpHandle request{};
    const std::wstring user_agent = L"MHWILDSVersionProxy/" + widen_utf8(kLoaderBuildVersion).value_or(L"0.0.0");
    session.handle = WinHttpOpen(user_agent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session.handle == nullptr) {
        return std::nullopt;
    }

    WinHttpSetTimeouts(
        session.handle,
        static_cast<int>(kDefaultUpdateTimeoutMs),
        static_cast<int>(kDefaultUpdateTimeoutMs),
        static_cast<int>(kDefaultUpdateTimeoutMs),
        static_cast<int>(kDefaultUpdateTimeoutMs));

    connection.handle = WinHttpConnect(session.handle, host.c_str(), components.nPort, 0);
    if (connection.handle == nullptr) {
        return std::nullopt;
    }

    const DWORD request_flags = components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    request.handle = WinHttpOpenRequest(connection.handle, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, request_flags);
    if (request.handle == nullptr) {
        return std::nullopt;
    }

    if (!WinHttpSendRequest(request.handle, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.handle, nullptr)) {
        return std::nullopt;
    }

    DWORD status_code = 0;
    DWORD status_code_size = sizeof(status_code);
    if (!WinHttpQueryHeaders(
            request.handle,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status_code,
            &status_code_size,
            WINHTTP_NO_HEADER_INDEX) ||
        status_code < 200 || status_code >= 300) {
        return std::nullopt;
    }

    std::vector<uint8_t> body_bytes{};
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.handle, &available)) {
            return std::nullopt;
        }

        if (available == 0) {
            break;
        }

        const auto previous_size = body_bytes.size();
        body_bytes.resize(previous_size + static_cast<size_t>(available));
        DWORD read_now = 0;
        if (!WinHttpReadData(request.handle, body_bytes.data() + previous_size, available, &read_now)) {
            return std::nullopt;
        }

        body_bytes.resize(previous_size + static_cast<size_t>(read_now));
        if (read_now == 0) {
            break;
        }
    }

    return decode_http_body_to_utf8(body_bytes);
}

std::string strip_html_tags_and_normalize(const std::string& text) {
    static const std::regex html_tag_regex{R"(<[^>]*>)", std::regex_constants::icase};
    static const std::regex whitespace_regex{R"(\s+)"};

    auto normalized = html_decode_basic(text);
    normalized = std::regex_replace(normalized, html_tag_regex, " ");
    normalized = std::regex_replace(normalized, whitespace_regex, " ");
    return trim_ascii_copy(normalized);
}

std::string extract_attachment_name_version(const std::string& body) {
    static const std::regex attachment_name_regex{
        R"(attachment-container[\s\S]*?class\s*=\s*["']name["'][^>]*>([\s\S]*?)</div>)",
        std::regex_constants::icase};

    std::smatch match{};
    if (!std::regex_search(body, match, attachment_name_regex) || match.size() < 2) {
        return {};
    }

    return strip_html_tags_and_normalize(match[1].str());
}

std::vector<std::pair<std::string, std::string>> extract_remote_announcements(const std::string& body) {
    static const std::regex announcement_regex{
        R"((\d+(?:\.\d+){1,3})\s*(?:\:|\xEF\xBC\x9A)\s*---\s*\*?\s*([\s\S]*?)\s*\*?\s*---)",
        std::regex_constants::icase};

    std::vector<std::pair<std::string, std::string>> announcements{};
    std::set<std::string> seen_versions{};
    for (std::sregex_iterator it(body.begin(), body.end(), announcement_regex), end; it != end; ++it) {
        const auto version = trim_ascii_copy((*it)[1].str());
        const auto announcement = strip_html_tags_and_normalize((*it)[2].str());
        if (version.empty() || announcement.empty()) {
            continue;
        }

        const auto inserted = seen_versions.insert(to_lower_ascii_copy(version));
        if (!inserted.second) {
            continue;
        }

        announcements.emplace_back(version, announcement);
    }

    std::stable_sort(announcements.begin(), announcements.end(), [](const auto& left, const auto& right) {
        const auto left_version = parse_simple_version(left.first);
        const auto right_version = parse_simple_version(right.first);
        if (!left_version.has_value() || !right_version.has_value()) {
            return left.first > right.first;
        }

        return compare_simple_version(*left_version, *right_version) > 0;
    });
    return announcements;
}

std::optional<RemoteUpdateInfo> parse_remote_update_info(const std::string& body, std::wstring_view source_url) {
    RemoteUpdateInfo info{};
    info.source_url = std::wstring{source_url};

    const auto attachment_name = extract_attachment_name_version(body);
    if (const auto version = extract_first_version_token(attachment_name); version.has_value()) {
        info.remote_version = *version;
    }

    const auto announcements = extract_remote_announcements(body);
    if (info.remote_version.empty() && !announcements.empty()) {
        info.remote_version = announcements.front().first;
    }

    if (!info.remote_version.empty()) {
        for (const auto& [version, announcement] : announcements) {
            if (_stricmp(version.c_str(), info.remote_version.c_str()) == 0) {
                info.announcement = announcement;
                break;
            }
        }
    }

    if (info.announcement.empty() && !announcements.empty()) {
        info.announcement = announcements.front().second;
    }

    if (info.remote_version.empty()) {
        return std::nullopt;
    }

    return info;
}

std::filesystem::path loader_update_cache_path() {
    std::error_code ec{};
    auto cache_dir = std::filesystem::temp_directory_path(ec);
    if (ec || cache_dir.empty()) {
        cache_dir = std::filesystem::current_path();
        ec.clear();
    }

    cache_dir /= kUpdateCacheDirName;
    std::filesystem::create_directories(cache_dir, ec);
    return cache_dir / kUpdateCacheFileName;
}

std::optional<LoaderUpdateCacheRecord> load_loader_update_cache_record() {
    const auto cache_path = loader_update_cache_path();
    std::error_code ec{};
    if (!std::filesystem::exists(cache_path, ec) || ec) {
        return std::nullopt;
    }

    ScopedInternalBackendOpen internal_open_guard{};
    std::ifstream input(cache_path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }

    const std::string json_text{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    if (json_text.empty()) {
        return std::nullopt;
    }

    try {
        const auto root = nlohmann::json::parse(json_text);
        LoaderUpdateCacheRecord record{};
        if (const auto it = root.find("remote_version"); it != root.end() && it->is_string()) {
            record.remote_version = trim_ascii_copy(it->get_ref<const std::string&>());
        }
        if (const auto it = root.find("announcement"); it != root.end() && it->is_string()) {
            record.announcement = trim_ascii_copy(it->get_ref<const std::string&>());
        }
        if (const auto it = root.find("source_url"); it != root.end() && it->is_string()) {
            if (const auto wide = widen_utf8(it->get_ref<const std::string&>()); wide.has_value()) {
                record.source_url = trim_ascii_copy(*wide);
            }
        }
        if (const auto it = root.find("last_checked_unix_seconds"); it != root.end() && it->is_number_integer()) {
            record.last_checked_unix_seconds = it->get<int64_t>();
        }

        if (record.remote_version.empty()) {
            return std::nullopt;
        }

        return record;
    } catch (...) {
        append_log_line("loader-update-cache-parse-failed\n");
        return std::nullopt;
    }
}

void save_loader_update_cache_record(const LoaderUpdateCacheRecord& record) {
    if (record.remote_version.empty()) {
        return;
    }

    const auto cache_path = loader_update_cache_path();
    nlohmann::json root = nlohmann::json::object();
    root["remote_version"] = record.remote_version;
    root["announcement"] = record.announcement;
    root["source_url"] = narrow_utf8(record.source_url);
    root["last_checked_unix_seconds"] = record.last_checked_unix_seconds;

    ScopedInternalBackendOpen internal_open_guard{};
    std::ofstream output(cache_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return;
    }

    const auto json_text = root.dump();
    output.write(json_text.data(), static_cast<std::streamsize>(json_text.size()));
    output.flush();
}

std::wstring truncate_prompt_text(std::wstring value) {
    value = trim_ascii_copy(value);
    if (value.size() > kPromptAnnouncementMaxChars) {
        value.resize(kPromptAnnouncementMaxChars);
        value += L"...";
    }

    return value;
}

void open_update_urls_in_browser(const std::vector<std::wstring>& urls) {
    std::set<std::wstring> deduped_urls{};
    for (const auto& url : urls) {
        const auto trimmed = trim_ascii_copy(url);
        if (!trimmed.empty()) {
            deduped_urls.insert(trimmed);
        }
    }

    for (const auto& url : deduped_urls) {
        const auto result = reinterpret_cast<uintptr_t>(ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
        if (result <= 32) {
            std::ostringstream oss;
            oss << "update-url-open-failed url=" << narrow_utf8(url) << " code=" << result << "\n";
            append_log_line(oss.str());
        }
    }
}

HRESULT CALLBACK update_prompt_task_dialog_callback(HWND hwnd, UINT notification, WPARAM, LPARAM, LONG_PTR) {
    if (notification == TDN_CREATED) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetForegroundWindow(hwnd);
    }

    return S_OK;
}

bool try_show_update_prompt_task_dialog(
    const UpdatePromptRequest& request,
    HWND parent_window,
    TASKDIALOG_FLAGS flags,
    std::string_view attempt_name,
    int& pressed_button) {
    const TASKDIALOG_BUTTON buttons[] = {
        {kUpdatePromptOpenButtonId, L"\u524d\u5f80\u53d1\u5e03\u9875"},
        {kUpdatePromptIgnoreButtonId, L"\u5ffd\u7565"},
    };

    TASKDIALOGCONFIG config{};
    config.cbSize = sizeof(config);
    config.hwndParent = parent_window;
    config.dwFlags = flags;
    config.pszWindowTitle = request.title.c_str();
    config.pszMainInstruction = request.main_instruction.empty() ? nullptr : request.main_instruction.c_str();
    config.pszContent = request.message.empty() ? nullptr : request.message.c_str();
    config.cButtons = static_cast<UINT>(sizeof(buttons) / sizeof(buttons[0]));
    config.pButtons = buttons;
    config.nDefaultButton = kUpdatePromptIgnoreButtonId;
    config.pfCallback = &update_prompt_task_dialog_callback;

    pressed_button = kUpdatePromptIgnoreButtonId;
    const auto hr = TaskDialogIndirect(&config, &pressed_button, nullptr, nullptr);

    std::ostringstream oss;
    oss << "update-prompt-taskdialog attempt=" << attempt_name
        << " parent=0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(parent_window)
        << " flags=0x" << static_cast<unsigned long>(flags)
        << " hr=0x" << static_cast<uint32_t>(hr);
    if (SUCCEEDED(hr)) {
        oss << std::dec << " button=" << pressed_button;
    }
    oss << "\n";
    append_log_line(oss.str());

    return SUCCEEDED(hr);
}

bool show_update_prompt_dialog(const UpdatePromptRequest& request) {
    int pressed_button = kUpdatePromptIgnoreButtonId;
    const auto base_flags = static_cast<TASKDIALOG_FLAGS>(TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT);
    const auto foreground_window = GetForegroundWindow();
    const auto foreground_flags = static_cast<TASKDIALOG_FLAGS>(base_flags | TDF_POSITION_RELATIVE_TO_WINDOW);

    if (try_show_update_prompt_task_dialog(request, nullptr, base_flags, "ownerless", pressed_button) ||
        (foreground_window != nullptr &&
         try_show_update_prompt_task_dialog(request, foreground_window, foreground_flags, "foreground", pressed_button))) {
        if (pressed_button == kUpdatePromptOpenButtonId) {
            open_update_urls_in_browser(request.urls);
        }

        return true;
    }

    std::wstring fallback_message = request.main_instruction;
    if (!request.message.empty()) {
        if (!fallback_message.empty()) {
            fallback_message += L"\n\n";
        }
        fallback_message += request.message;
    }

    append_log_line("update-prompt-fallback-messagebox\n");
    const auto result = MessageBoxW(
        nullptr,
        fallback_message.c_str(),
        request.title.c_str(),
        MB_YESNO | MB_TOPMOST | MB_SETFOREGROUND | MB_ICONINFORMATION);
    if (result == IDYES) {
        open_update_urls_in_browser(request.urls);
    }

    return result != 0;
}

DWORD WINAPI update_prompt_thread_proc(LPVOID) {
    for (;;) {
        UpdatePromptRequest request{};
        bool has_request = false;
        {
            std::scoped_lock _{g_update_prompt_mutex};
            if (!g_pending_update_prompts.empty()) {
                request = std::move(g_pending_update_prompts.front());
                g_pending_update_prompts.pop_front();
                has_request = true;
            } else {
                g_update_prompt_thread_running = false;
            }
        }

        if (!has_request) {
            break;
        }

        show_update_prompt_dialog(request);
    }

    return 0;
}

void spawn_update_prompt_thread_if_needed() {
    bool expected = false;
    if (!g_update_prompt_thread_running.compare_exchange_strong(expected, true)) {
        return;
    }

    if (const auto thread = CreateThread(nullptr, 0, &update_prompt_thread_proc, nullptr, 0, nullptr); thread != nullptr) {
        CloseHandle(thread);
        return;
    }

    g_update_prompt_thread_running = false;
    append_log_line("update-prompt-thread-create-failed\n");
}

void enqueue_update_prompt_request(UpdatePromptRequest request) {
    {
        std::scoped_lock _{g_update_prompt_mutex};
        g_pending_update_prompts.emplace_back(std::move(request));
    }

    spawn_update_prompt_thread_if_needed();
}

UpdatePromptRequest build_loader_update_prompt_request(const RemoteUpdateInfo& info) {
    UpdatePromptRequest request{};
    request.title = L"MHWILDS \u6a21\u7ec4\u52a0\u8f7d\u5668\u66f4\u65b0\u63d0\u793a";
    request.main_instruction = L"\u68c0\u6d4b\u5230\u65b0\u7684\u52a0\u8f7d\u5668\u7248\u672c";

    std::wstring message = L"\u5f53\u524d\u7248\u672c\uff1a" + widen_utf8(kLoaderBuildVersion).value_or(L"0.0.0");
    message += L"\n\u8fdc\u7aef\u7248\u672c\uff1a" + widen_utf8(info.remote_version).value_or(L"<unknown>");
    if (!info.announcement.empty()) {
        message += L"\n\n\u66f4\u65b0\u8bf4\u660e\uff1a\n";
        message += truncate_prompt_text(widen_utf8(info.announcement).value_or(L""));
    }

    request.message = std::move(message);
    request.urls = {info.source_url};
    return request;
}

UpdatePromptRequest build_mod_update_prompt_request(const std::vector<ModUpdateCheckResult>& results) {
    UpdatePromptRequest request{};
    request.title = L"MHWILDS MOD \u66f4\u65b0\u63d0\u793a";
    request.main_instruction = results.size() == 1
        ? L"\u68c0\u6d4b\u5230 1 \u4e2a MOD \u6709\u65b0\u7248\u672c"
        : (L"\u68c0\u6d4b\u5230 " + std::to_wstring(results.size()) + L" \u4e2a MOD \u6709\u65b0\u7248\u672c");

    std::wostringstream message{};
    for (size_t index = 0; index < results.size(); ++index) {
        const auto& result = results[index];
        if (index != 0) {
            message << L"\n\n";
        }

        message << (index + 1) << L". " << result.metadata.display_name;
        message << L"\n\u5f53\u524d\u7248\u672c\uff1a" << (!result.metadata.mod_version.empty() ? result.metadata.mod_version : L"<unknown>");
        message << L"\n\u8fdc\u7aef\u7248\u672c\uff1a" << widen_utf8(result.remote_version).value_or(L"<unknown>");
        if (!result.metadata.author.empty()) {
            message << L"\n\u4f5c\u8005\uff1a" << result.metadata.author;
        }
        if (!result.announcement.empty()) {
            message << L"\n\u66f4\u65b0\u8bf4\u660e\uff1a" << truncate_prompt_text(widen_utf8(result.announcement).value_or(L""));
        }

        request.urls.emplace_back(result.metadata.update_url);
    }

    request.message = message.str();
    return request;
}

std::optional<ModUpdateCheckResult> check_single_mod_update(const ModMetadataRecord& metadata) {
    const auto body = http_get_utf8_body(metadata.update_url);
    if (!body.has_value()) {
        std::ostringstream oss;
        oss << "mod-update-fetch-failed source=" << narrow_utf8(metadata.source_path)
            << " url=" << narrow_utf8(metadata.update_url) << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    const auto remote_info = parse_remote_update_info(*body, metadata.update_url);
    if (!remote_info.has_value()) {
        std::ostringstream oss;
        oss << "mod-update-parse-failed source=" << narrow_utf8(metadata.source_path)
            << " url=" << narrow_utf8(metadata.update_url) << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    const auto local_version = parse_simple_version(metadata.mod_version);
    const auto remote_version = parse_simple_version(remote_info->remote_version);
    if (!local_version.has_value() || !remote_version.has_value() || compare_simple_version(*remote_version, *local_version) <= 0) {
        std::ostringstream oss;
        oss << "mod-update-up-to-date source=" << narrow_utf8(metadata.source_path)
            << " local=" << narrow_utf8(metadata.mod_version)
            << " remote=" << remote_info->remote_version << "\n";
        append_log_line(oss.str());
        return std::nullopt;
    }

    ModUpdateCheckResult result{};
    result.metadata = metadata;
    result.remote_version = remote_info->remote_version;
    result.announcement = remote_info->announcement;

    std::ostringstream oss;
    oss << "mod-update-outdated source=" << narrow_utf8(metadata.source_path)
        << " local=" << narrow_utf8(metadata.mod_version)
        << " remote=" << result.remote_version << "\n";
    append_log_line(oss.str());
    return result;
}

void run_loader_update_check_worker_body() {
    const auto local_version = parse_simple_version(kLoaderBuildVersion);
    std::set<std::string> prompted_versions{};
    std::optional<RemoteUpdateInfo> cached_info{};

    if (const auto cached = load_loader_update_cache_record(); cached.has_value()) {
        if (const auto cached_remote = parse_simple_version(cached->remote_version);
            cached_remote.has_value() && local_version.has_value() && compare_simple_version(*cached_remote, *local_version) > 0) {
            RemoteUpdateInfo info{};
            info.remote_version = cached->remote_version;
            info.announcement = cached->announcement;
            info.source_url = cached->source_url.empty() ? std::wstring{kLoaderUpdatePostUrl} : cached->source_url;
            cached_info = std::move(info);
        }
    }

    const auto try_prompt_cached_info = [&](const char* reason) {
        if (!cached_info.has_value() || prompted_versions.contains(cached_info->remote_version)) {
            return;
        }

        enqueue_update_prompt_request(build_loader_update_prompt_request(*cached_info));
        prompted_versions.insert(cached_info->remote_version);

        std::ostringstream oss;
        oss << "loader-update-cache-fallback reason=" << reason
            << " remote=" << cached_info->remote_version << "\n";
        append_log_line(oss.str());
    };

    while (!g_shutdown_requested.load()) {
        const auto body = http_get_utf8_body(kLoaderUpdatePostUrl);
        if (!body.has_value()) {
            try_prompt_cached_info("fetch_failed");
            append_log_line("loader-update-fetch-failed\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(kLoaderUpdateRetryDelayMs));
            continue;
        }

        const auto remote_info = parse_remote_update_info(*body, kLoaderUpdatePostUrl);
        if (!remote_info.has_value()) {
            try_prompt_cached_info("parse_failed");
            append_log_line("loader-update-parse-failed\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(kLoaderUpdateRetryDelayMs));
            continue;
        }

        LoaderUpdateCacheRecord cache_record{};
        cache_record.remote_version = remote_info->remote_version;
        cache_record.announcement = remote_info->announcement;
        cache_record.source_url = remote_info->source_url;
        cache_record.last_checked_unix_seconds = static_cast<int64_t>(std::time(nullptr));
        save_loader_update_cache_record(cache_record);

        std::ostringstream oss;
        oss << "loader-update-remote-version local=" << kLoaderBuildVersion
            << " remote=" << remote_info->remote_version << "\n";
        append_log_line(oss.str());

        if (const auto remote_version = parse_simple_version(remote_info->remote_version);
            local_version.has_value() && remote_version.has_value() && compare_simple_version(*remote_version, *local_version) > 0 &&
            !prompted_versions.contains(remote_info->remote_version)) {
            enqueue_update_prompt_request(build_loader_update_prompt_request(*remote_info));
            prompted_versions.insert(remote_info->remote_version);
        }

        return;
    }
}

void run_mod_update_check_worker_body() {
    const auto mod_paths = resolve_encrypted_custom_mod_paths();
    std::vector<ModUpdateCheckResult> outdated_results{};
    outdated_results.reserve(mod_paths.size());

    std::ostringstream begin_oss;
    begin_oss << "mod-update-begin count=" << mod_paths.size() << "\n";
    append_log_line(begin_oss.str());

    for (size_t index = 0; index < mod_paths.size(); ++index) {
        if (g_shutdown_requested.load()) {
            return;
        }

        const std::filesystem::path source_path{mod_paths[index]};
        const auto metadata = load_mod_metadata_record(source_path);
        if (!metadata.has_value()) {
            continue;
        }

        if (!metadata->metadata_present) {
            std::ostringstream oss;
            oss << "mod-update-skip-no-metadata source=" << narrow_utf8(metadata->source_path) << "\n";
            append_log_line(oss.str());
            continue;
        }

        if (!metadata->authenticated) {
            std::ostringstream oss;
            oss << "mod-update-skip-unauthenticated source=" << narrow_utf8(metadata->source_path) << "\n";
            append_log_line(oss.str());
            continue;
        }

        if (metadata->mod_version.empty() || metadata->update_url.empty()) {
            std::ostringstream oss;
            oss << "mod-update-skip-incomplete source=" << narrow_utf8(metadata->source_path)
                << " version=" << narrow_utf8(metadata->mod_version)
                << " url=" << narrow_utf8(metadata->update_url) << "\n";
            append_log_line(oss.str());
            continue;
        }

        if (const auto result = check_single_mod_update(*metadata); result.has_value()) {
            outdated_results.emplace_back(*result);
        }

        if (index + 1 < mod_paths.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kModUpdateInterRequestDelayMs));
        }
    }

    if (outdated_results.empty()) {
        append_log_line("mod-update-none\n");
        return;
    }

    enqueue_update_prompt_request(build_mod_update_prompt_request(outdated_results));

    std::ostringstream oss;
    oss << "mod-update-summary count=" << outdated_results.size() << "\n";
    append_log_line(oss.str());
}

DWORD WINAPI loader_update_check_thread_proc(LPVOID) {
    run_loader_update_check_worker_body();
    return 0;
}

DWORD WINAPI mod_update_check_thread_proc(LPVOID) {
    run_mod_update_check_worker_body();
    return 0;
}

void schedule_update_check_worker() {
    if (g_update_check_thread_started.exchange(true)) {
        return;
    }

    bool loader_thread_ok = false;
    bool mod_thread_ok = false;
    if (const auto loader_thread = CreateThread(nullptr, 0, &loader_update_check_thread_proc, nullptr, 0, nullptr); loader_thread != nullptr) {
        CloseHandle(loader_thread);
        loader_thread_ok = true;
    } else {
        append_log_line("loader-update-thread-create-failed\n");
    }

    if (const auto mod_thread = CreateThread(nullptr, 0, &mod_update_check_thread_proc, nullptr, 0, nullptr); mod_thread != nullptr) {
        CloseHandle(mod_thread);
        mod_thread_ok = true;
    } else {
        append_log_line("mod-update-thread-create-failed\n");
    }

    if (!loader_thread_ok && !mod_thread_ok) {
        g_update_check_thread_started = false;
    }
}
#endif
