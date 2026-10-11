#pragma once
#include <stdint.h>

#ifdef MW_BACKEND_FRIDA_GUM
#include "gum_backend.h"
#else
#include <MinHook.h>
#endif

// Private backend boundary; the creator ABI remains MwHostApi version 1.
namespace mw::hooks {
#ifdef MW_BACKEND_FRIDA_GUM
inline MH_STATUS Create(ULONG_PTR owner, LPVOID target, LPVOID detour, LPVOID* original) {
    return MH_CreateHookEx(owner, target, detour, original);
}
inline MH_STATUS Enable(ULONG_PTR owner, LPVOID target) { return MH_EnableHookEx(owner, target); }
inline MH_STATUS Disable(ULONG_PTR owner, LPVOID target) { return MH_DisableHookEx(owner, target); }
inline MH_STATUS Remove(ULONG_PTR owner, LPVOID target) { return MH_RemoveHookEx(owner, target); }
inline MH_STATUS Uninitialize() { return MH_Uninitialize(); }
inline BOOL IsOperationInProgress() { return MH_IsOperationInProgressOnThisThread(); }
#else
MH_STATUS Create(ULONG_PTR owner, LPVOID target, LPVOID detour, LPVOID* original);
MH_STATUS Enable(ULONG_PTR owner, LPVOID target);
MH_STATUS Disable(ULONG_PTR owner, LPVOID target);
MH_STATUS Remove(ULONG_PTR owner, LPVOID target);
MH_STATUS Uninitialize();
BOOL IsOperationInProgress();
struct Metrics {
    uint64_t retained_records;
    uint64_t installed_bridges;
    uint64_t registered_hooks;
    uint64_t active_hooks;
    uint64_t logical_disables;
    uint64_t reuse_count;
};
Metrics GetMetrics();
#endif
} // namespace mw::hooks
