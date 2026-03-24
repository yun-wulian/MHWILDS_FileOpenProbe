#include "plugin_internal.hpp"

namespace mhwilds::probe {

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

struct CaimoguPostSource {
    std::string post_id{};
    std::wstring open_url{};
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

std::optional<CaimoguPostSource> parse_caimogu_post_source(std::wstring_view url) {
    static const std::wregex post_regex{
        LR"(^\s*(?:https?://)?(?:www\.)?caimogu\.cc/post/(\d+)\.html(?:[/?#].*)?\s*$)",
        std::regex_constants::icase};

    std::wsmatch match{};
    const std::wstring owned_url{url};
    if (!std::regex_match(owned_url, match, post_regex) || match.size() < 2) {
        return std::nullopt;
    }

    const auto post_id_wide = trim_ascii_copy(match[1].str());
    if (post_id_wide.empty()) {
        return std::nullopt;
    }

    CaimoguPostSource source{};
    source.post_id = narrow_utf8(post_id_wide);
    source.open_url = trim_ascii_copy(owned_url);
    return source;
}

struct ScopedBcryptAlgorithmHandleUpdate {
    BCRYPT_ALG_HANDLE handle{};

    ~ScopedBcryptAlgorithmHandleUpdate() {
        if (handle != nullptr) {
            BCryptCloseAlgorithmProvider(handle, 0);
        }
    }
};

struct ScopedBcryptHashHandleUpdate {
    BCRYPT_HASH_HANDLE handle{};

    ~ScopedBcryptHashHandleUpdate() {
        if (handle != nullptr) {
            BCryptDestroyHash(handle);
        }
    }
};

struct ScopedBcryptKeyHandleUpdate {
    BCRYPT_KEY_HANDLE handle{};

    ~ScopedBcryptKeyHandleUpdate() {
        if (handle != nullptr) {
            BCryptDestroyKey(handle);
        }
    }
};

std::optional<std::array<uint8_t, 16>> compute_md5_bytes_update(const uint8_t* bytes, size_t size) {
    ScopedBcryptAlgorithmHandleUpdate algorithm{};
    ScopedBcryptHashHandleUpdate hash{};
    DWORD object_size{};
    DWORD bytes_written{};
    DWORD hash_size{};
    std::vector<uint8_t> hash_object{};
    std::array<uint8_t, 16> digest{};

    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_MD5_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    if (BCryptGetProperty(
            algorithm.handle,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &bytes_written,
            0) != 0 ||
        BCryptGetProperty(
            algorithm.handle,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_size),
            sizeof(hash_size),
            &bytes_written,
            0) != 0 ||
        hash_size != digest.size()) {
        return std::nullopt;
    }

    hash_object.resize(object_size);
    if (BCryptCreateHash(
            algorithm.handle,
            &hash.handle,
            hash_object.data(),
            static_cast<ULONG>(hash_object.size()),
            nullptr,
            0,
            0) != 0) {
        return std::nullopt;
    }

    if (bytes != nullptr && size > 0 &&
        BCryptHashData(hash.handle, const_cast<PUCHAR>(bytes), static_cast<ULONG>(size), 0) != 0) {
        return std::nullopt;
    }

    if (BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        return std::nullopt;
    }

    return digest;
}

std::optional<std::string> compute_md5_hex_lower_update(std::string_view text) {
    const auto digest = compute_md5_bytes_update(
        reinterpret_cast<const uint8_t*>(text.data()),
        text.size());
    if (!digest.has_value()) {
        return std::nullopt;
    }

    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string hex(digest->size() * 2, '\0');
    for (size_t index = 0; index < digest->size(); ++index) {
        const auto byte = (*digest)[index];
        hex[index * 2] = kHexDigits[(byte >> 4) & 0x0F];
        hex[index * 2 + 1] = kHexDigits[byte & 0x0F];
    }

    return hex;
}

std::optional<std::vector<uint8_t>> encrypt_aes128_cbc_pkcs7_update(
    std::string_view plain_text,
    const std::array<uint8_t, 16>& key,
    const std::array<uint8_t, 16>& iv) {
    ScopedBcryptAlgorithmHandleUpdate algorithm{};
    ScopedBcryptKeyHandleUpdate key_handle{};
    DWORD object_size{};
    DWORD bytes_written{};
    std::vector<uint8_t> key_object{};
    const std::vector<uint8_t> plain_bytes(plain_text.begin(), plain_text.end());
    std::vector<uint8_t> cipher_bytes(plain_bytes.size() + 16, 0);
    auto iv_copy = iv;
    ULONG cipher_size{};

    if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) {
        return std::nullopt;
    }

    const auto chaining_mode_bytes = static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t));
    if (BCryptSetProperty(
            algorithm.handle,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
            chaining_mode_bytes,
            0) != 0 ||
        BCryptGetProperty(
            algorithm.handle,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &bytes_written,
            0) != 0) {
        return std::nullopt;
    }

    key_object.resize(object_size);
    if (BCryptGenerateSymmetricKey(
            algorithm.handle,
            &key_handle.handle,
            key_object.data(),
            static_cast<ULONG>(key_object.size()),
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()),
            0) != 0) {
        return std::nullopt;
    }

    const auto encrypt_status = BCryptEncrypt(
        key_handle.handle,
        const_cast<PUCHAR>(plain_bytes.data()),
        static_cast<ULONG>(plain_bytes.size()),
        nullptr,
        iv_copy.data(),
        static_cast<ULONG>(iv_copy.size()),
        cipher_bytes.data(),
        static_cast<ULONG>(cipher_bytes.size()),
        &cipher_size,
        BCRYPT_BLOCK_PADDING);
    if (encrypt_status != 0) {
        return std::nullopt;
    }

    cipher_bytes.resize(cipher_size);
    return cipher_bytes;
}

std::string base64_encode_bytes_update(const uint8_t* bytes, size_t size) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded{};
    encoded.reserve(((size + 2) / 3) * 4);
    for (size_t index = 0; index < size; index += 3) {
        const auto chunk0 = bytes[index];
        const auto chunk1 = index + 1 < size ? bytes[index + 1] : 0;
        const auto chunk2 = index + 2 < size ? bytes[index + 2] : 0;
        const auto combined =
            (static_cast<uint32_t>(chunk0) << 16) |
            (static_cast<uint32_t>(chunk1) << 8) |
            static_cast<uint32_t>(chunk2);

        encoded.push_back(kAlphabet[(combined >> 18) & 0x3F]);
        encoded.push_back(kAlphabet[(combined >> 12) & 0x3F]);
        encoded.push_back(index + 1 < size ? kAlphabet[(combined >> 6) & 0x3F] : '=');
        encoded.push_back(index + 2 < size ? kAlphabet[combined & 0x3F] : '=');
    }

    return encoded;
}

std::string percent_encode_query_value_update(std::string_view value) {
    static constexpr char kHexDigits[] = "0123456789ABCDEF";

    std::string encoded{};
    encoded.reserve(value.size() * 3);
    for (const auto ch : value) {
        const auto byte = static_cast<unsigned char>(ch);
        if ((byte >= 'A' && byte <= 'Z') ||
            (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') ||
            byte == '-' || byte == '_' || byte == '.' || byte == '~') {
            encoded.push_back(static_cast<char>(byte));
            continue;
        }

        encoded.push_back('%');
        encoded.push_back(kHexDigits[(byte >> 4) & 0x0F]);
        encoded.push_back(kHexDigits[byte & 0x0F]);
    }

    return encoded;
}

std::optional<std::string> encrypt_caimogu_param_update(std::string_view value, std::string_view time_text) {
    std::string key_text{time_text};
    if (key_text.size() < 6) {
        return std::nullopt;
    }
    key_text += key_text.substr(0, 6);
    if (key_text.size() != 16) {
        return std::nullopt;
    }

    const auto iv_hex = compute_md5_hex_lower_update(time_text);
    if (!iv_hex.has_value() || iv_hex->size() < 16) {
        return std::nullopt;
    }

    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 16> iv{};
    std::memcpy(key.data(), key_text.data(), key.size());
    std::memcpy(iv.data(), iv_hex->data(), iv.size());

    const auto cipher_bytes = encrypt_aes128_cbc_pkcs7_update(value, key, iv);
    if (!cipher_bytes.has_value()) {
        return std::nullopt;
    }

    return base64_encode_bytes_update(cipher_bytes->data(), cipher_bytes->size());
}

std::optional<std::wstring> build_caimogu_post_detail_request_url(std::string_view post_id) {
    if (post_id.empty()) {
        return std::nullopt;
    }

    const auto time_text = std::to_string(static_cast<long long>(std::time(nullptr)));
    const std::string sign_input =
        "device=mod&id=" + std::string{post_id} +
        "&time=" + time_text +
        "&ver=3.0.0";
    const auto sign = compute_md5_hex_lower_update(to_lower_ascii_copy(sign_input));
    const auto encrypted_device = encrypt_caimogu_param_update("mod", time_text);
    const auto encrypted_id = encrypt_caimogu_param_update(post_id, time_text);
    const auto encrypted_ver = encrypt_caimogu_param_update("3.0.0", time_text);
    if (!sign.has_value() ||
        !encrypted_device.has_value() ||
        !encrypted_id.has_value() ||
        !encrypted_ver.has_value()) {
        return std::nullopt;
    }

    const std::string url_utf8 =
        "https://api.caimogu.cc/v3/post/detail?device=" + percent_encode_query_value_update(*encrypted_device) +
        "&id=" + percent_encode_query_value_update(*encrypted_id) +
        "&ver=" + percent_encode_query_value_update(*encrypted_ver) +
        "&time=" + percent_encode_query_value_update(time_text) +
        "&sign=" + percent_encode_query_value_update(*sign);
    return widen_utf8(url_utf8);
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

std::optional<RemoteUpdateInfo> parse_remote_update_info_from_caimogu_payload(
    const nlohmann::json& payload,
    std::wstring_view open_url) {
    RemoteUpdateInfo info{};
    info.source_url = std::wstring{open_url};

    const auto data_it = payload.find("data");
    if (data_it == payload.end() || !data_it->is_object()) {
        return std::nullopt;
    }

    const auto& data = *data_it;
    if (const auto code_it = payload.find("code");
        code_it == payload.end() || !code_it->is_number_integer() || code_it->get<int>() != 0) {
        return std::nullopt;
    }

    std::string content_html{};
    if (const auto info_it = data.find("info"); info_it != data.end() && info_it->is_object()) {
        if (const auto content_it = info_it->find("content"); content_it != info_it->end() && content_it->is_string()) {
            content_html = content_it->get_ref<const std::string&>();
        }
    }

    if (const auto attachment_it = data.find("attachment"); attachment_it != data.end() && attachment_it->is_array()) {
        for (const auto& item : *attachment_it) {
            if (!item.is_object()) {
                continue;
            }

            const auto name_it = item.find("name");
            if (name_it == item.end() || !name_it->is_string()) {
                continue;
            }

            const auto attachment_name = trim_ascii_copy(name_it->get_ref<const std::string&>());
            if (attachment_name.empty()) {
                continue;
            }

            if (const auto version = extract_first_version_token(attachment_name); version.has_value()) {
                info.remote_version = *version;
                break;
            }
        }
    }

    const auto announcements = extract_remote_announcements(content_html);
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

std::optional<RemoteUpdateInfo> fetch_remote_update_info_from_caimogu_post_url(std::wstring_view post_url) {
    const auto post_source = parse_caimogu_post_source(post_url);
    if (!post_source.has_value()) {
        return std::nullopt;
    }

    const auto request_url = build_caimogu_post_detail_request_url(post_source->post_id);
    if (!request_url.has_value()) {
        return std::nullopt;
    }

    const auto body = http_get_utf8_body(*request_url);
    if (!body.has_value()) {
        return std::nullopt;
    }

    try {
        const auto payload = nlohmann::json::parse(*body);
        return parse_remote_update_info_from_caimogu_payload(payload, post_source->open_url);
    } catch (...) {
        return std::nullopt;
    }
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
    const auto remote_info = fetch_remote_update_info_from_caimogu_post_url(metadata.update_url);
    if (!remote_info.has_value()) {
        std::ostringstream oss;
        oss << "mod-update-api-failed source=" << narrow_utf8(metadata.source_path)
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
    append_timing_log_line("loader-update-worker-start");
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
        const auto remote_info = fetch_remote_update_info_from_caimogu_post_url(kLoaderUpdatePostUrl);
        if (!remote_info.has_value()) {
            try_prompt_cached_info("api_failed");
            append_log_line("loader-update-api-failed\n");
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

        {
            std::ostringstream timing_oss;
            timing_oss << "remote=" << remote_info->remote_version;
            append_timing_log_line("loader-update-worker-finished", timing_oss.str());
        }
        return;
    }
}

void run_mod_update_check_worker_body() {
    const auto mod_paths = resolve_encrypted_custom_mod_paths();
    std::vector<ModUpdateCheckResult> outdated_results{};
    outdated_results.reserve(mod_paths.size());

    {
        std::ostringstream timing_oss;
        timing_oss << "count=" << mod_paths.size();
        append_timing_log_line("mod-update-worker-start", timing_oss.str());
    }

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
        append_timing_log_line("mod-update-worker-finished", "outdated_count=0");
        return;
    }

    enqueue_update_prompt_request(build_mod_update_prompt_request(outdated_results));

    std::ostringstream oss;
    oss << "mod-update-summary count=" << outdated_results.size() << "\n";
    append_log_line(oss.str());

    {
        std::ostringstream timing_oss;
        timing_oss << "outdated_count=" << outdated_results.size();
        append_timing_log_line("mod-update-worker-finished", timing_oss.str());
    }
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

    append_timing_log_line("update-check-schedule");

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

} // namespace mhwilds::probe
