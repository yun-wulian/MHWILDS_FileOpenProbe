cmake_minimum_required(VERSION 3.28)

project(MHWILDSFileOpenProbe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(MHWILDS_LOADER_VERSION "1.0.0" CACHE STRING "Build version string reported by the loader update check")
option(MHWILDS_DISABLE_LOGGING "Disable runtime log file output" OFF)

set(MINHOOK_DIR "F:/怪猎C++mod/无双斩连段源码/deps/minhook" CACHE PATH "Path to MinHook headers and library")
set(JSON_INCLUDE_DIR "F:/怪猎C++mod/无双斩连段源码/deps/json" CACHE PATH "Path to nlohmann json.hpp")
set(MHWILDS_GAME_DIR "E:/SteamLibrary/steamapps/common/MonsterHunterWilds" CACHE PATH "Optional Monster Hunter Wilds game directory for post-build deployment")

add_library(minhook STATIC IMPORTED GLOBAL)
set_target_properties(minhook PROPERTIES
    IMPORTED_LOCATION "${MINHOOK_DIR}/libMinHook.x64.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${MINHOOK_DIR}"
)

set(SAFETYHOOK_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_AMALGAMATE OFF CACHE BOOL "" FORCE)
set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "" FORCE)
add_subdirectory(dependencies/safetyhook EXCLUDE_FROM_ALL)

set(PROBE_PLUGIN_IMPL_FILES
    src/plugin/00_state_and_preamble.cpp
    src/plugin/10_redirect_and_path.cpp
    src/plugin/20_hw_trace.cpp
    src/plugin/30_config_and_crypto.cpp
    src/plugin/40_matching_and_tracking.cpp
    src/plugin/50_virtual_fs_and_hooks.cpp
    src/plugin/60_bootstrap_and_shutdown.cpp
    src/plugin/70_update_check.cpp
)

add_library(MHWILDSVersionProxy SHARED
    src/plugin.cpp
    src/version_proxy.def
    ${PROBE_PLUGIN_IMPL_FILES}
)

add_executable(MHWILDSPakPacker
    src/packer.cpp
)

target_compile_definitions(MHWILDSVersionProxy PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    MHWILDS_VERSION_PROXY=1
    MHWILDS_LOADER_VERSION="${MHWILDS_LOADER_VERSION}"
)

if(MHWILDS_DISABLE_LOGGING)
    target_compile_definitions(MHWILDSVersionProxy PRIVATE
        MHWILDS_DISABLE_LOGGING=1
    )
endif()

target_include_directories(MHWILDSVersionProxy PRIVATE
    include
    ${JSON_INCLUDE_DIR}
)

target_include_directories(MHWILDSPakPacker PRIVATE
    include
    ${JSON_INCLUDE_DIR}
)

target_link_libraries(MHWILDSVersionProxy PRIVATE
    comctl32
    minhook
    safetyhook::safetyhook
    bcrypt
    winhttp
)

target_link_libraries(MHWILDSPakPacker PRIVATE
    bcrypt
)

set_target_properties(MHWILDSVersionProxy PROPERTIES
    OUTPUT_NAME "version"
)

set_target_properties(MHWILDSPakPacker PROPERTIES
    OUTPUT_NAME "mhwilds_pak_packer"
)

if(MHWILDS_GAME_DIR)
    add_custom_command(TARGET MHWILDSVersionProxy POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:MHWILDSVersionProxy>"
            "${MHWILDS_GAME_DIR}/$<TARGET_FILE_NAME:MHWILDSVersionProxy>"
        COMMAND ${CMAKE_COMMAND} -E rm -f
            "${MHWILDS_GAME_DIR}/version_orig.dll"
    )
endif()
