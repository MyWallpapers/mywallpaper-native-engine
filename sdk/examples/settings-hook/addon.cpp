// Runnable template. Replace the target and effect; keep the lifetime rules.
#include <mw_native_sdk.hpp>
#include <mw_call_gate.hpp>
#include <nlohmann/json.hpp>
#include <atomic>

namespace {
struct Settings { bool enabled = true; int32_t delta = 7; };
struct Instance {
    const MwHostApi* host = nullptr;
    mw_native::Hook hook;
    mw_native::CallGate gate;
    std::atomic_int32_t delta{0};
};
// This pointer, gate and original-pointer storage live until process exit.
Instance* instance = nullptr;
using Compute = int(__cdecl*)(int);

bool ReadSettings(const char* text, Settings* settings) {
    const auto snapshot = nlohmann::json::parse(text ? text : "{}", nullptr, false);
    if (!snapshot.is_object()) return false;
    const auto& values = snapshot.contains("deviceSettings") ? snapshot["deviceSettings"] : snapshot;
    if (!values.is_object()) return false;
    if (values.contains("enabled")) {
        if (!values["enabled"].is_boolean()) return false;
        settings->enabled = values["enabled"].get<bool>();
    }
    if (values.contains("delta") && (!mw_native::ReadInt32(values["delta"], &settings->delta)
        || settings->delta < -100 || settings->delta > 100)) return false;
    return true;
}

int __cdecl Detour(int value) {
    auto guard = instance->gate.Enter();
    const auto original = reinterpret_cast<Compute>(instance->hook.original());
    const int result = original ? original(value) : value;
    return guard ? result + instance->delta.load(std::memory_order_relaxed) : result;
}

MwStatus MW_CALL Create(const MwHostApi* host, const char*, void** out) {
    if (!mw_native::IsCompatibleHost(host) || !host->resolve_symbol || !out || instance) return MW_ERROR_ABI;
    instance = new Instance();
    instance->host = host;
    *out = instance;
    return MW_OK;
}
MwStatus MW_CALL Update(void* context, const char* text) {
    Settings settings;
    if (!ReadSettings(text, &settings)) return MW_ERROR_ARGUMENT;
    static_cast<Instance*>(context)->delta.store(settings.enabled ? settings.delta : 0, std::memory_order_relaxed);
    return MW_OK;
}
MwStatus MW_CALL Start(void* context, const char* text) {
    auto* state = static_cast<Instance*>(context);
    Settings settings;
    if (!ReadSettings(text, &settings)) return MW_ERROR_ARGUMENT;
    void* target = nullptr;
    MwStatus status = state->host->resolve_symbol(state->host->addon_context,
        L"mw-sdk-fixture.exe", "MwSdkOptionalCompute", &target);
    if (status == MW_ERROR_SYMBOL_NOT_FOUND) {
        status = state->host->resolve_export(state->host->addon_context,
            L"mw-sdk-fixture.exe", "MwSdkCompute", &target);
    }
    // Pending/download errors do not prove that an optional function is absent.
    if (status != MW_OK) return status;
    state->delta.store(settings.enabled ? settings.delta : 0, std::memory_order_relaxed);
    if (!state->gate.Open()) return MW_ERROR_STATE;
    status = state->hook.start(state->host, target, reinterpret_cast<void*>(&Detour));
    if (status != MW_OK) state->gate.Close();
    return status;
}
MwStatus MW_CALL Stop(void* context) {
    auto* state = static_cast<Instance*>(context);
    state->gate.Close();
    if (state->gate.WaitForDrain(0) != mw_native::CallGate::WaitResult::drained)
        return MW_ERROR_DRAIN_PENDING;
    // The engine disables the effect during a pending stop. Its disable call
    // is idempotent, so the SDK helper can retire the same handle on retry.
    return state->hook.stop();
}
}

extern "C" MW_EXPORT MwStatus MW_CALL MwAddonGetApi(uint32_t abi, MwAddonApi* api) {
    if (abi != MW_NATIVE_ABI_VERSION || !api || api->struct_size < sizeof(*api)) return MW_ERROR_ABI;
    *api = {};
    api->struct_size = sizeof(*api);
    api->abi_version = MW_NATIVE_ABI_VERSION;
    api->name_utf8 = "SDK settings hook example";
    api->instance_policy = MW_ADDON_INSTANCE_SINGLETON;
    api->create_instance = &Create;
    api->start = &Start;
    api->settings_changed = &Update;
    api->stop = &Stop;
    return MW_OK;
}
