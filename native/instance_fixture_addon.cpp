#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "mw_native_sdk.h"
#include <nlohmann/json.hpp>
#include <atomic>
#include <mutex>
#include <string>
using Json = nlohmann::json;
namespace {
struct Instance {
    const MwHostApi* host = nullptr;
    std::atomic_int delta{0};
    uint64_t hook = 0;
    int slot = -1;
    HANDLE resource = nullptr;
};
struct Slot {
    void* original = nullptr;
    std::atomic<Instance*> instance{nullptr};
};
Slot slots[3];
std::mutex slot_mutex;
using Function = int(__cdecl*)(int);
int Forward(int index, int value) {
    auto original = reinterpret_cast<Function>(InterlockedCompareExchangePointer(
        reinterpret_cast<PVOID volatile*>(&slots[index].original), nullptr, nullptr));
    Instance* instance = slots[index].instance.load();
    return (original ? original(value) : value) + (instance ? instance->delta.load() : 0);
}
int __cdecl Compute(int v) { return Forward(0, v); }
int __cdecl Secondary(int v) { return Forward(1, v); }
int __cdecl Private(int v) { return Forward(2, v); }

Json Device(const char* text) {
    const Json full = Json::parse(text ? text : "{}");
    return full.contains("deviceSettings") ? full["deviceSettings"] : full;
}
MwStatus WaitForGate(const std::string& event) {
    if (event.empty()) return MW_OK;
    std::wstring wide(event.begin(), event.end());
    HANDLE release = OpenEventW(SYNCHRONIZE, FALSE, wide.c_str());
    if (!release) return MW_ERROR_ARGUMENT;
    const std::string entered_name = event + "-entered";
    std::wstring entered_wide(entered_name.begin(), entered_name.end());
    HANDLE entered = OpenEventW(EVENT_MODIFY_STATE, FALSE, entered_wide.c_str());
    if (entered) { SetEvent(entered); CloseHandle(entered); }
    const DWORD result = WaitForSingleObject(release, 15000);
    CloseHandle(release);
    return result == WAIT_OBJECT_0 ? MW_OK : MW_ERROR_ADDON;
}
MwStatus MW_CALL Create(const MwHostApi* host, const char*, void** out) {
    if (!host || !out) return MW_ERROR_ARGUMENT;
    auto* instance = new Instance();
    instance->host = host;
    *out = instance; // One tiny stable context per logical identity, process lifetime.
    return MW_OK;
}
MwStatus MW_CALL Start(void* context, const char* text) {
    auto* instance = static_cast<Instance*>(context);
    const Json settings = Device(text);
    if (settings.value("noHooks", false)) {
        const std::string name = settings.value("resourceEvent", std::string());
        const std::wstring wide(name.begin(), name.end());
        instance->resource = OpenEventW(EVENT_MODIFY_STATE, FALSE, wide.c_str());
        if (!instance->resource) return MW_ERROR_ARGUMENT;
        SetEvent(instance->resource);
        return WaitForGate(settings.value("startBlockEvent", std::string()));
    }
    const std::string target_name = settings.value("target", std::string("compute"));
    const int index = target_name == "private" ? 2 : target_name == "secondary" ? 1 : 0;
    void* target = nullptr;
    const auto* host = instance->host;
    const MwStatus resolved = index == 2
        ? host->resolve_symbol(host->addon_context, L"mw-native-fixture.exe", "MwFixturePrivateCompute", &target)
        : host->resolve_export(host->addon_context, L"mw-native-fixture.exe",
            index == 1 ? "MwFixtureSecondary" : "MwFixtureCompute", &target);
    if (resolved != MW_OK) return resolved;
    std::lock_guard lock(slot_mutex);
    if (slots[index].instance.load()) return MW_ERROR_STATE;
    instance->delta = settings.value("delta", 1);
    void* detour = index == 2 ? reinterpret_cast<void*>(&Private)
        : index == 1 ? reinterpret_cast<void*>(&Secondary) : reinterpret_cast<void*>(&Compute);
    MwStatus status = host->hook_create(host->addon_context, target, detour, &slots[index].original, &instance->hook);
    if (status != MW_OK) return status;
    instance->slot = index;
    slots[index].instance = instance;
    status = host->hook_enable(host->addon_context, instance->hook);
    return status;
}
MwStatus MW_CALL Settings(void* context, const char* text) {
    auto* instance = static_cast<Instance*>(context);
    const Json settings = Device(text);
    if (settings.value("reject", false)) return MW_ERROR_ARGUMENT;
    if (settings.value("resolvePrivate", false)) {
        void* target = nullptr;
        const MwStatus status = instance->host->resolve_symbol(instance->host->addon_context,
            L"mw-native-fixture.exe", "MwFixturePrivateCompute", &target);
        if (status != MW_OK) return status;
    }
    const MwStatus gate = WaitForGate(settings.value("blockEvent", std::string()));
    if (gate != MW_OK) return gate;
    if (settings.value("target", std::string("compute")) !=
        (instance->slot == 2 ? "private" : instance->slot == 1 ? "secondary" : "compute")) return MW_ERROR_ARGUMENT;
    instance->delta = settings.value("delta", 1);
    return MW_OK;
}
MwStatus MW_CALL Stop(void* context) {
    auto* instance = static_cast<Instance*>(context);
    if (instance->resource) {
        ResetEvent(instance->resource);
        CloseHandle(instance->resource);
        instance->resource = nullptr;
    }
    if (instance->slot < 0) return MW_OK;
    std::lock_guard lock(slot_mutex);
    const MwStatus status = instance->host->hook_remove(instance->host->addon_context, instance->hook);
    if (status != MW_OK) return status;
    slots[instance->slot].instance = nullptr;
    instance->slot = -1;
    instance->hook = 0;
    return MW_OK;
}
}
extern "C" MW_EXPORT MwStatus MW_CALL MwAddonGetApi(uint32_t version, MwAddonApi* api) {
    if (!api || version != MW_NATIVE_ABI_VERSION || api->struct_size < sizeof(*api)) return MW_ERROR_ABI;
    *api = {};
    api->struct_size = sizeof(*api); api->abi_version = MW_NATIVE_ABI_VERSION;
    api->name_utf8 = "instance-fixture"; api->instance_policy = MW_ADDON_INSTANCE_MULTIPLE;
    api->create_instance = &Create; api->start = &Start;
    api->settings_changed = &Settings; api->stop = &Stop;
    return MW_OK;
}
