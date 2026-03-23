#pragma once

#include <stdbool.h>

#define REFRAMEWORK_PLUGIN_VERSION_MAJOR 1
#define REFRAMEWORK_PLUGIN_VERSION_MINOR 15
#define REFRAMEWORK_PLUGIN_VERSION_PATCH 0

typedef void (*REFLogFn)(const char* format, ...);
typedef void (*REFOnPresentCb)();
typedef bool (*REFOnPresentFn)(REFOnPresentCb);

typedef struct {
    int major;
    int minor;
    int patch;
    const char* game_name;
} REFrameworkPluginVersion;

typedef struct {
    void* on_lua_state_created;
    void* on_lua_state_destroyed;
    REFOnPresentFn on_present;
    void* on_pre_application_entry;
    void* on_post_application_entry;
    void* lock_lua;
    void* unlock_lua;
    void* on_device_reset;
    void* on_message;
    REFLogFn log_error;
    REFLogFn log_warn;
    REFLogFn log_info;
    void* is_drawing_ui;
    void* create_script_state;
    void* delete_script_state;
    void* on_imgui_frame;
    void* on_imgui_draw_ui;
    void* on_pre_gui_draw_element;
} REFrameworkPluginFunctions;

typedef struct {
    void* reframework_module;
    const REFrameworkPluginVersion* version;
    const REFrameworkPluginFunctions* functions;
    const void* renderer_data;
    const void* sdk;
} REFrameworkPluginInitializeParam;
