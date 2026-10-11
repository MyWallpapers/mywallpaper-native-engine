#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define MW_CALL __cdecl
#define MW_EXPORT __declspec(dllexport)
#else
#define MW_CALL
#define MW_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MW_NATIVE_ABI_VERSION 2u
#define MW_AGENT_PIPE_CAPACITY 192u

typedef int32_t MwStatus;
enum {
    MW_OK = 0,
    MW_ERROR_ARGUMENT = 1,
    MW_ERROR_ABI = 2,
    MW_ERROR_STATE = 3,
    MW_ERROR_MODULE_NOT_READY = 4,
    MW_ERROR_SYMBOL_NOT_FOUND = 5,
    MW_ERROR_HOOK = 6,
    MW_ERROR_ADDON = 7,
    MW_ERROR_IO = 8,
    MW_ERROR_DRAIN_PENDING = 9,
    MW_ERROR_BUSY = 10,
    MW_ERROR_SYMBOL_PENDING = 11
};

/* Storage for *original belongs to the add-on. Keep it writable and alive through
 * hook removal and any entered detour's last read of it.
 * The backend may update it when another hook changes the same target chain.
 * Hook IDs are process-local handles owned by addon_context.
 * original storage must be pointer-aligned and read with Interlocked.
 * Bridge code and image modules containing target/detour stay resident until
 * process exit. MinHook reuses a bridge for the same owner/target/detour on
 * restart; stopped bridges bypass the effect. Non-image code remains caller-owned.
 * Removal is logical:
 * entered detours may finish afterward. A cooperative CallGate can guard addon
 * resources; this does not freeze a historical chain or track arbitrary threads.
 */
typedef struct MwHostApi {
    uint32_t struct_size;
    uint32_t abi_version;
    void* addon_context;
    MwStatus (MW_CALL *log)(void* addon_context, const char* message_utf8);
    MwStatus (MW_CALL *resolve_export)(void* addon_context,
        const wchar_t* module_name, const char* export_name, void** target);
    MwStatus (MW_CALL *hook_create)(void* addon_context, void* target,
        void* detour, void** original, uint64_t* hook_id);
    MwStatus (MW_CALL *hook_enable)(void* addon_context, uint64_t hook_id);
    MwStatus (MW_CALL *hook_disable)(void* addon_context, uint64_t hook_id);
    MwStatus (MW_CALL *hook_remove)(void* addon_context, uint64_t hook_id);
    /* Cached-only lookup. A miss is queued for the exterior companion;
     * callbacks must return MW_ERROR_SYMBOL_PENDING instead of waiting. */
    MwStatus (MW_CALL *resolve_symbol)(void* addon_context,
        const wchar_t* module_name, const char* symbol_name, void** target);
} MwHostApi;

enum {
    MW_ADDON_INSTANCE_SINGLETON = 0,
    MW_ADDON_INSTANCE_MULTIPLE = 1
};

/* UTF-8 settings JSON is a complete snapshot, not a patch, borrowed for the
 * duration of each callback. The last accepted snapshot is used on reactivation.
 * host is stable until the target process exits; add-ons do not allocate/free each
 * other's objects across this ABI. stop is cooperative and may fail. Returning
 * MW_ERROR_DRAIN_PENDING preserves resources and permits stop retry; activation
 * and settings are refused during that drain. DLLs
 * remain resident; settings updates do not replace the DLL.
 */
typedef struct MwAddonApi {
    uint32_t struct_size;
    uint32_t abi_version;
    const char* name_utf8;
    uint32_t instance_policy;
    /* Called once per stable logical identity. The context, host and callback
     * code remain resident until process exit; stop releases active resources.
     * Multiple instances do not imply automatic composition of native hooks. */
    MwStatus (MW_CALL *create_instance)(const MwHostApi* host,
        const char* instance_id_utf8, void** instance_context);
    MwStatus (MW_CALL *start)(void* instance_context, const char* settings_json);
    MwStatus (MW_CALL *settings_changed)(void* instance_context, const char* settings_json);
    MwStatus (MW_CALL *stop)(void* instance_context);
    MwStatus (MW_CALL *message_received)(void* instance_context, const char* message_json_utf8);
} MwAddonApi;

typedef MwStatus (MW_CALL *MwAddonGetApiFn)(uint32_t requested_abi,
    MwAddonApi* api);

/* Windows bootstrap data for the exported DWORD WINAPI MwAgentStart(void*).
 * The controller validates the target and owner process creation times before
 * injection. It duplicates a SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
 * handle to the companion process into the target and transfers that handle to
 * the agent. The agent revalidates the handle's PID and creation time, watches
 * it until shutdown, then closes it. This binds injected hook lifetime to the
 * exact companion process object, even if its PID is later reused.
 */
typedef struct MwAgentStartConfig {
    uint32_t struct_size;
    uint32_t target_pid;
    uint64_t target_creation_time;
    uint32_t owner_pid;
    uint32_t reserved;
    uint64_t owner_creation_time;
    uint64_t owner_process_handle;
    wchar_t pipe_name[MW_AGENT_PIPE_CAPACITY];
} MwAgentStartConfig;

#ifdef __cplusplus
}
static_assert(sizeof(wchar_t) == 2, "The bootstrap uses Windows UTF-16");
static_assert(sizeof(MwAgentStartConfig) == 424, "Bootstrap ABI layout changed");
#endif
