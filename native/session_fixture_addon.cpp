#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "mw_native_sdk.h"

#include <cstdint>
#include <string_view>

#ifndef MW_FIXTURE_ADDON_NAME
#error MW_FIXTURE_ADDON_NAME must be supplied by the fixture target
#endif
#ifndef MW_FIXTURE_EXPORT
#error MW_FIXTURE_EXPORT must be supplied by the fixture target
#endif
#ifndef MW_FIXTURE_DELTA
#error MW_FIXTURE_DELTA must be supplied by the fixture target
#endif
#ifndef MW_FIXTURE_REJECT_SETTING
#define MW_FIXTURE_REJECT_SETTING 0
#endif
#ifndef MW_FIXTURE_INVALID_ABI
#define MW_FIXTURE_INVALID_ABI 0
#endif
#ifndef MW_FIXTURE_INVALID_CALLBACK
#define MW_FIXTURE_INVALID_CALLBACK 0
#endif

namespace {

using FixtureFunction = int(__cdecl*)(int);
const MwHostApi* g_host = nullptr;
LPVOID g_original = nullptr;
uint64_t g_hook_id = 0;
bool g_active = false;

int __cdecl FixtureDetour(int value) {
    const auto original = reinterpret_cast<FixtureFunction>(
        InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_original), nullptr, nullptr));
    return original == nullptr ? value : original(value) + MW_FIXTURE_DELTA;
}

MwStatus MW_CALL Start(const MwHostApi* host, const char*) {
    if (host == nullptr || host->abi_version != MW_NATIVE_ABI_VERSION ||
        host->resolve_export == nullptr || host->hook_create == nullptr ||
        host->hook_enable == nullptr || host->hook_remove == nullptr || g_active) {
        return MW_ERROR_ARGUMENT;
    }
    const wchar_t module_name[] = L"mw-native-fixture.exe";
    void* target = nullptr;
    MwStatus status = host->resolve_export(host->addon_context, module_name,
        MW_FIXTURE_EXPORT, &target);
    if (status != MW_OK || target == nullptr) {
        return status == MW_OK ? MW_ERROR_SYMBOL_NOT_FOUND : status;
    }
    uint64_t hook_id = 0;
    status = host->hook_create(host->addon_context, target,
        reinterpret_cast<void*>(&FixtureDetour), &g_original, &hook_id);
    if (status != MW_OK) {
        g_original = nullptr;
        return status;
    }
    status = host->hook_enable(host->addon_context, hook_id);
    if (status != MW_OK) {
        host->hook_remove(host->addon_context, hook_id);
        g_original = nullptr;
        return status;
    }
    g_host = host;
    g_hook_id = hook_id;
    g_active = true;
    return MW_OK;
}

MwStatus MW_CALL SettingsChanged(const char* settings_json) {
#if MW_FIXTURE_REJECT_SETTING
    if (settings_json != nullptr &&
        std::string_view(settings_json).find("\"reject\":true") != std::string_view::npos) {
        return MW_ERROR_ARGUMENT;
    }
#else
    (void)settings_json;
#endif
    return MW_OK;
}

MwStatus MW_CALL Stop() {
    if (!g_active || g_host == nullptr) {
        return MW_OK;
    }
    const MwStatus status = g_host->hook_remove(g_host->addon_context, g_hook_id);
    if (status != MW_OK) {
        return status;
    }
    g_active = false;
    g_hook_id = 0;
    g_host = nullptr;
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(&g_original), nullptr);
    return MW_OK;
}

} // namespace

extern "C" MW_EXPORT MwStatus MW_CALL MwAddonGetApi(uint32_t requested_abi,
    MwAddonApi* api) {
    if (requested_abi != MW_NATIVE_ABI_VERSION || api == nullptr ||
        api->struct_size < sizeof(MwAddonApi)) {
        return MW_ERROR_ABI;
    }
    *api = {};
    api->struct_size = sizeof(MwAddonApi);
#if MW_FIXTURE_INVALID_ABI
    api->abi_version = MW_NATIVE_ABI_VERSION + 1;
    return MW_OK;
#endif
    api->abi_version = MW_NATIVE_ABI_VERSION;
    api->name_utf8 = MW_FIXTURE_ADDON_NAME;
#if MW_FIXTURE_INVALID_CALLBACK
    api->start = reinterpret_cast<decltype(api->start)>(static_cast<uintptr_t>(1));
#else
    api->start = &Start;
#endif
    api->settings_changed = &SettingsChanged;
    api->stop = &Stop;
    return MW_OK;
}
