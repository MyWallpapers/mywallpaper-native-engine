#include "resident_hooks.h"
#include "hook_backend_policy.h"

#include <memory>
#include <mutex>
#include <vector>

namespace mw::hooks {
namespace {
struct Record {
    ULONG_PTR owner;
    LPVOID target;
    LPVOID detour;
    LPVOID original = nullptr;
    LPVOID routed_detour = nullptr;
    LPVOID* cold_output = nullptr;
    bool registered = false;
    bool enabled = false;
    bool attached = false;
};
struct State {
    std::mutex mutex;
    std::vector<std::unique_ptr<Record>> records;
    uint64_t logical_disables = 0;
    uint64_t reuse_count = 0;
};
State& Backend() {
    static State* state = new State;
    return *state; // Physical bridges and their records live until process exit.
}
thread_local bool g_operating = false;
struct Operation {
    Operation() { g_operating = true; }
    ~Operation() { g_operating = false; }
};
ULONG_PTR Identity(const Record& record) { return reinterpret_cast<ULONG_PTR>(&record); }
Record* Registered(State& state, ULONG_PTR owner, LPVOID target) {
    for (const auto& record : state.records) {
        if (record->registered && record->owner == owner && record->target == target) return record.get();
    }
    return nullptr;
}
MH_STATUS DisableLocked(State& state, Record& record) {
    if (!record.enabled) return MH_ERROR_DISABLED;
    if (!MwBackendSetResidentRoute(record.original, record.original)) return MH_ERROR_UNSUPPORTED_FUNCTION;
    record.enabled = false;
    ++state.logical_disables;
    return MH_OK;
}
} // namespace

BOOL IsOperationInProgress() {
    return g_operating || MH_IsOperationInProgressOnThisThread();
}

MH_STATUS Create(ULONG_PTR owner, LPVOID target, LPVOID detour, LPVOID* original) {
    if (owner == MH_ALL_IDENTS || target == MH_ALL_HOOKS || detour == nullptr ||
        original == nullptr || reinterpret_cast<uintptr_t>(original) % alignof(void*) != 0) {
        return MH_ERROR_NOT_EXECUTABLE;
    }
    if (IsOperationInProgress()) return MH_ERROR_REENTRANT_CALL;
    State& state = Backend();
    std::lock_guard lock(state.mutex);
    Operation operation;
    if (Registered(state, owner, target) != nullptr) return MH_ERROR_ALREADY_CREATED;
    Record* found = nullptr;
    for (const auto& record : state.records) {
        if (record->owner == owner && record->target == target && record->detour == detour) {
            found = record.get();
            break;
        }
    }
    if (found == nullptr) {
        try {
            auto record = std::make_unique<Record>();
            record->owner = owner;
            record->target = target;
            record->detour = detour;
            state.records.push_back(std::move(record));
            found = state.records.back().get();
        } catch (...) { return MH_ERROR_MEMORY_ALLOC; }
    }
    if (found->attached) {
        // Cached originals keep the same address. No target patch or new
        // trampoline is needed for a normal stop/restart of this pair.
        InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(original), found->original);
        ++state.reuse_count;
    } else {
        // The first physical attach must publish into the caller's output
        // before any detour can execute. MinHook's transaction does that.
        const MH_STATUS status = MH_CreateHookEx(Identity(*found), target, detour, original);
        if (status != MH_OK) return status;
        found->cold_output = original;
    }
    found->registered = true;
    return MH_OK;
}

MH_STATUS Enable(ULONG_PTR owner, LPVOID target) {
    if (IsOperationInProgress()) return MH_ERROR_REENTRANT_CALL;
    State& state = Backend();
    std::lock_guard lock(state.mutex);
    Operation operation;
    Record* record = Registered(state, owner, target);
    if (record == nullptr) return MH_ERROR_NOT_CREATED;
    if (record->enabled) return MH_ERROR_ENABLED;
    if (!record->attached) {
        const MH_STATUS status = MH_EnableHookEx(Identity(*record), target);
        if (status != MH_OK) return status;
        record->original = InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(record->cold_output), nullptr, nullptr);
        record->routed_detour = MwBackendResidentRoute(record->original);
        record->attached = true;
        record->enabled = true;
        // Once attached, the backend never retains a caller-owned output slot.
        // Future physical attachments use MinHook's own internal storage.
        MwBackendReleaseOriginalStorage(Identity(*record), target);
        record->cold_output = nullptr;
        return MH_OK;
    }
    if (!MwBackendSetResidentRoute(record->original, record->routed_detour)) {
        return MH_ERROR_UNSUPPORTED_FUNCTION;
    }
    record->enabled = true;
    return MH_OK;
}

MH_STATUS Disable(ULONG_PTR owner, LPVOID target) {
    if (IsOperationInProgress()) return MH_ERROR_REENTRANT_CALL;
    State& state = Backend();
    std::lock_guard lock(state.mutex);
    Operation operation;
    Record* record = Registered(state, owner, target);
    return record == nullptr ? MH_ERROR_NOT_CREATED : DisableLocked(state, *record);
}

MH_STATUS Remove(ULONG_PTR owner, LPVOID target) {
    if (IsOperationInProgress()) return MH_ERROR_REENTRANT_CALL;
    State& state = Backend();
    std::lock_guard lock(state.mutex);
    Operation operation;
    Record* record = Registered(state, owner, target);
    if (record == nullptr) return MH_ERROR_NOT_CREATED;
    if (record->enabled) {
        const MH_STATUS status = DisableLocked(state, *record);
        if (status != MH_OK) return status;
    }
    if (!record->attached) {
        const MH_STATUS status = MH_RemoveHookEx(Identity(*record), target);
        if (status != MH_OK) return status;
    }
    record->cold_output = nullptr;
    record->registered = false;
    return MH_OK;
}

MH_STATUS Uninitialize() {
    if (IsOperationInProgress()) return MH_ERROR_REENTRANT_CALL;
    State& state = Backend();
    std::lock_guard lock(state.mutex);
    Operation operation;
    for (const auto& record : state.records) {
        if (record->attached || record->registered) return MH_ERROR_UNABLE_TO_UNINITIALIZE;
    }
    return MH_Uninitialize();
}

Metrics GetMetrics() {
    State& state = Backend();
    std::lock_guard lock(state.mutex);
    Metrics metrics{};
    metrics.retained_records = state.records.size();
    metrics.logical_disables = state.logical_disables;
    metrics.reuse_count = state.reuse_count;
    for (const auto& record : state.records) {
        metrics.installed_bridges += record->attached;
        metrics.registered_hooks += record->registered;
        metrics.active_hooks += record->enabled;
    }
    return metrics;
}
} // namespace mw::hooks
