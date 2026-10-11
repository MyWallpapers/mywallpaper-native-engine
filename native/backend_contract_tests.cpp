#include "resident_hooks.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>

#ifdef MW_BACKEND_FRIDA_GUM
#include "gum_backend.h"
#else
#include "hook_backend_policy.h"
#include <MinHook.h>
#endif

#include <cmath>
#include <cstdint>
#include <cstdio>

#pragma comment(lib, "Psapi.lib")

namespace {

using IntegerFunction = std::int64_t(__cdecl*)(std::int64_t, std::int64_t,
    std::int64_t, std::int64_t, std::int64_t, std::int64_t, std::int64_t,
    std::int64_t);
using MixedFunction = double(__cdecl*)(double, int, float, double, int, float,
    double);

struct AggregateResult {
    std::uint64_t integer;
    double real;
    std::uint64_t checksum;
};

using AggregateFunction = AggregateResult(__cdecl*)(std::uint64_t, double,
    std::uint32_t, std::uint64_t, std::uint32_t, double);
using LastErrorFunction = LONG(__cdecl*)(DWORD);
using RecursionFunction = LONG(__cdecl*)(LONG);
using TinyIdentityFunction = LONG(__cdecl*)(LONG);
using SoakFunction = int(__cdecl*)(int);

PVOID volatile g_integer_original = nullptr;
PVOID volatile g_mixed_original = nullptr;
PVOID volatile g_aggregate_original = nullptr;
PVOID volatile g_last_error_original = nullptr;
PVOID volatile g_recursion_original = nullptr;
PVOID volatile g_tiny_identity_original = nullptr;
PVOID volatile g_soak_original = nullptr;

volatile LONG g_integer_target_calls = 0;
volatile LONG g_integer_detour_calls = 0;
volatile LONG g_mixed_target_calls = 0;
volatile LONG g_mixed_detour_calls = 0;
volatile LONG g_aggregate_target_calls = 0;
volatile LONG g_aggregate_detour_calls = 0;
volatile LONG g_last_error_target_calls = 0;
volatile LONG g_last_error_detour_calls = 0;
volatile LONG g_last_error_seen_by_detour = 0;
volatile LONG g_recursion_target_calls = 0;
volatile LONG g_recursion_detour_calls = 0;
volatile LONG g_recursion_post_calls = 0;
volatile LONG g_tiny_identity_detour_calls = 0;
volatile LONG g_soak_detour_calls = 0;

constexpr DWORD kOriginalLastError = 0x1357;
constexpr DWORD kDetourLastError = 0x2468;
constexpr std::uint64_t kIntegerDetourDelta = 0x112233;
constexpr double kMixedDetourDelta = 256.25;
constexpr ULONG_PTR kIntegerOwner = 0x4d570001;
constexpr ULONG_PTR kMixedOwner = 0x4d570002;
constexpr ULONG_PTR kAggregateOwner = 0x4d570003;
constexpr ULONG_PTR kLastErrorOwner = 0x4d570004;
constexpr ULONG_PTR kRecursionOwner = 0x4d570005;
constexpr ULONG_PTR kTinyIdentityOwner = 0x4d570006;
constexpr ULONG_PTR kSoakOwner = 0x4d570007;
constexpr std::uint64_t kSoakIterations = 20000;
constexpr LONG kRecursionDepth = 3;

template <typename Function>
Function LoadOriginal(PVOID volatile* storage) noexcept {
    return reinterpret_cast<Function>(
        InterlockedCompareExchangePointer(storage, nullptr, nullptr));
}

LPVOID* BackendOutputStorage(PVOID volatile* storage) noexcept {
    // Backend CreateHookEx writes this aligned slot with InterlockedExchangePointer.
    return const_cast<LPVOID*>(storage);
}

bool IsOk(MH_STATUS status) noexcept {
    return status == MH_OK;
}

bool InstallHook(ULONG_PTR owner, LPVOID target, LPVOID detour,
    LPVOID* original) {
    if (!IsOk(mw::hooks::Create(owner, target, detour, original))) {
        return false;
    }
    if (IsOk(mw::hooks::Enable(owner, target))) {
        return true;
    }
    (void) mw::hooks::Remove(owner, target);
    return false;
}

bool RemoveHook(ULONG_PTR owner, LPVOID target) {
    const MH_STATUS disable_status = mw::hooks::Disable(owner, target);
    const bool disable_ok = disable_status == MH_OK ||
        disable_status == MH_ERROR_DISABLED;
    const MH_STATUS remove_status = mw::hooks::Remove(owner, target);
    return disable_ok && (remove_status == MH_OK ||
        remove_status == MH_ERROR_NOT_CREATED);
}

__declspec(noinline) std::int64_t __cdecl IntegerTarget(std::int64_t a,
    std::int64_t b, std::int64_t c, std::int64_t d, std::int64_t e,
    std::int64_t f, std::int64_t g, std::int64_t h) {
    InterlockedIncrement(&g_integer_target_calls);
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

__declspec(noinline) std::int64_t __cdecl IntegerDetour(std::int64_t a,
    std::int64_t b, std::int64_t c, std::int64_t d, std::int64_t e,
    std::int64_t f, std::int64_t g, std::int64_t h) {
    InterlockedIncrement(&g_integer_detour_calls);
    const IntegerFunction original = LoadOriginal<IntegerFunction>(
        &g_integer_original);
    return original(a, b, c, d, e, f, g, h) + kIntegerDetourDelta;
}

__declspec(noinline) double __cdecl MixedTarget(double a, int b, float c,
    double d, int e, float f, double g) {
    InterlockedIncrement(&g_mixed_target_calls);
    return a * 2.0 + b + c * 3.0 + d * 4.0 + e + f * 5.0 + g * 6.0;
}

__declspec(noinline) double __cdecl MixedDetour(double a, int b, float c,
    double d, int e, float f, double g) {
    InterlockedIncrement(&g_mixed_detour_calls);
    const MixedFunction original = LoadOriginal<MixedFunction>(
        &g_mixed_original);
    return original(a, b, c, d, e, f, g) + kMixedDetourDelta;
}

__declspec(noinline) AggregateResult __cdecl AggregateTarget(
    std::uint64_t a, double b, std::uint32_t c, std::uint64_t d,
    std::uint32_t e, double f) {
    InterlockedIncrement(&g_aggregate_target_calls);
    AggregateResult result{};
    result.integer = a + c + e;
    result.real = b + f;
    result.checksum = a ^ d ^ (static_cast<std::uint64_t>(c) << 17) ^ e;
    return result;
}

__declspec(noinline) AggregateResult __cdecl AggregateDetour(
    std::uint64_t a, double b, std::uint32_t c, std::uint64_t d,
    std::uint32_t e, double f) {
    InterlockedIncrement(&g_aggregate_detour_calls);
    const AggregateFunction original = LoadOriginal<AggregateFunction>(
        &g_aggregate_original);
    AggregateResult result = original(a, b, c, d, e, f);
    result.integer += 0x1234;
    result.real += 12.5;
    result.checksum ^= 0x55aa55aa55aa55aa;
    return result;
}

__declspec(noinline) LONG __cdecl LastErrorTarget(DWORD value) {
    InterlockedIncrement(&g_last_error_target_calls);
    SetLastError(kOriginalLastError);
    return static_cast<LONG>(value + 3);
}

__declspec(noinline) LONG __cdecl LastErrorDetour(DWORD value) {
    InterlockedIncrement(&g_last_error_detour_calls);
    const LastErrorFunction original = LoadOriginal<LastErrorFunction>(
        &g_last_error_original);
    const LONG result = original(value);
    const DWORD seen = GetLastError();
    InterlockedExchange(&g_last_error_seen_by_detour,
        static_cast<LONG>(seen));
    SetLastError(kDetourLastError);
    return result + 9;
}

__declspec(noinline) LONG __cdecl RecursionTarget(LONG depth) {
    InterlockedIncrement(&g_recursion_target_calls);
    if (depth <= 0) {
        return 1;
    }
    const LONG nested = RecursionTarget(depth - 1);
    InterlockedIncrement(&g_recursion_post_calls);
    return nested + 1;
}

__declspec(noinline) LONG __cdecl RecursionDetour(LONG depth) {
    InterlockedIncrement(&g_recursion_detour_calls);
    const RecursionFunction original = LoadOriginal<RecursionFunction>(
        &g_recursion_original);
    return original(depth);
}

__declspec(noinline) LONG __cdecl TinyIdentityTarget(LONG value) {
    return value;
}

TinyIdentityFunction volatile g_tiny_identity_call = &TinyIdentityTarget;

__declspec(noinline) LONG CallTinyIdentity(LONG value) noexcept {
    const TinyIdentityFunction call = g_tiny_identity_call;
    return call(value);
}

__declspec(noinline) LONG __cdecl TinyIdentityDetour(LONG value) {
    InterlockedIncrement(&g_tiny_identity_detour_calls);
    const TinyIdentityFunction original = LoadOriginal<TinyIdentityFunction>(
        &g_tiny_identity_original);
    return original(value) + 1;
}

__declspec(noinline) int __cdecl SoakTarget(int value) {
    volatile int baseline = value * 3;
    volatile int copy1 = baseline;
    volatile int copy2 = copy1;
    return copy2;
}

__declspec(noinline) int __cdecl SoakDetour(int value) {
    InterlockedIncrement(&g_soak_detour_calls);
    const SoakFunction original = LoadOriginal<SoakFunction>(&g_soak_original);
    return original(value) + 7;
}

struct BackendMetrics {
    std::uint64_t retired_generations = 0;
    std::uint64_t trampoline_regions = 0;
    std::uint64_t trampoline_slot_bytes = 0;
    std::uint64_t retained_hook_records = 0;
    std::uint64_t retained_gateways = 0;
    std::uint64_t gateway_region_bytes = 0;
    std::uint64_t logical_disables = 0;
    bool gum_metrics_available = false;
};

BackendMetrics ReadBackendMetrics() {
    BackendMetrics result{};
#ifdef MW_BACKEND_FRIDA_GUM
    MwGumBackendMetrics metrics{};
    metrics.struct_size = sizeof(metrics);
    MwGumBackendGetMetrics(&metrics);
    result.retired_generations = metrics.retired_generations;
    result.trampoline_regions = metrics.gateway_region_count;
    result.trampoline_slot_bytes = metrics.gateway_slot_bytes;
    result.retained_hook_records = metrics.retained_hook_records;
    result.retained_gateways = metrics.retained_gateways;
    result.gateway_region_bytes = metrics.gateway_region_bytes;
    result.logical_disables = metrics.logical_disable_count;
    result.gum_metrics_available = true;
#else
    result.retired_generations = MwBackendRetiredTrampolineCount();
    result.trampoline_regions = MwBackendTrampolineRegionCount();
    result.trampoline_slot_bytes = MwBackendTrampolineSlotBytes();
    const auto resident = mw::hooks::GetMetrics();
    result.retained_hook_records = resident.retained_records;
    result.retained_gateways = resident.installed_bridges;
    result.logical_disables = resident.logical_disables;
#endif
    return result;
}

bool ReadPrivateBytes(std::uint64_t* output) {
    if (output == nullptr) {
        return false;
    }
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
        sizeof(counters))) {
        return false;
    }
    *output = static_cast<std::uint64_t>(counters.PrivateUsage);
    return true;
}

void PrintMetrics(const BackendMetrics& metrics) {
    std::printf(
        "{\"retired_generations\":%llu,\"trampoline_regions\":%llu,"
        "\"trampoline_slot_bytes\":%llu,\"retained_hook_records\":%llu,"
        "\"retained_gateways\":%llu,\"gateway_region_bytes\":%llu,"
        "\"logical_disables\":%llu,\"gum_metrics_available\":%s}",
        static_cast<unsigned long long>(metrics.retired_generations),
        static_cast<unsigned long long>(metrics.trampoline_regions),
        static_cast<unsigned long long>(metrics.trampoline_slot_bytes),
        static_cast<unsigned long long>(metrics.retained_hook_records),
        static_cast<unsigned long long>(metrics.retained_gateways),
        static_cast<unsigned long long>(metrics.gateway_region_bytes),
        static_cast<unsigned long long>(metrics.logical_disables),
        metrics.gum_metrics_available ? "true" : "false");
}

const char* BackendName() {
#ifdef MW_BACKEND_FRIDA_GUM
    return "frida-gum";
#else
    return "minhook-detours";
#endif
}

} // namespace

int main() {
    bool setup_ok = IsOk(MH_Initialize());
    bool integer_ok = false;
    bool mixed_ok = false;
    bool aggregate_ok = false;
    bool last_error_ok = false;
    bool recursion_matches = false;
    bool tiny_target_supported = false;
    bool tiny_target_expected_supported = false;
    bool tiny_target_ok = false;
    MH_STATUS tiny_target_status = MH_ERROR_NOT_INITIALIZED;
    MH_STATUS tiny_enable_status = MH_ERROR_NOT_INITIALIZED;
    MH_STATUS tiny_disable_status = MH_ERROR_NOT_INITIALIZED;
    MH_STATUS tiny_remove_status = MH_ERROR_NOT_INITIALIZED;
    LONG tiny_before_create = 0;
    LONG tiny_after_create = 0;
    LONG tiny_while_enabled = 0;
    LONG tiny_after_disable = 0;
    LONG tiny_after_remove = 0;
    LONG tiny_detour_calls_while_enabled = 0;
    LONG tiny_detour_calls_after_disable = 0;
    LONG tiny_detour_calls_after_remove = 0;
    bool tiny_baseline_before_create_ok = false;
    bool tiny_create_preserves_baseline_ok = false;
    bool tiny_enable_invokes_detour_ok = false;
    bool tiny_disable_restores_target_ok = false;
    bool tiny_remove_keeps_target_restored_ok = false;
    bool tiny_disable_ok = false;
    bool tiny_remove_ok = false;
    bool soak_ok = false;
    bool soak_memory_ok = false;
    std::uint64_t private_before = 0;
    std::uint64_t private_after = 0;
    std::uint64_t soak_elapsed_ms = 0;
    std::uint64_t soak_completed = 0;
    DWORD returned_last_error = 0;
    BackendMetrics metrics_before{};
    BackendMetrics metrics_after{};
#ifdef MW_BACKEND_FRIDA_GUM
    constexpr LONG kExpectedDetourEntries = kRecursionDepth + 1;
    constexpr const char* kRecursionSemantics =
        "gum-fast-replace-reenters-on-same-target-recursion";
#else
    constexpr LONG kExpectedDetourEntries = kRecursionDepth + 1;
    constexpr const char* kRecursionSemantics =
        "minhook-detour-is-reentered-by-same-target-recursion";
#endif

    if (setup_ok) {
        InterlockedExchangePointer(&g_tiny_identity_original, nullptr);
        InterlockedExchange(&g_tiny_identity_detour_calls, 0);
        tiny_before_create = CallTinyIdentity(7);
        tiny_target_status = mw::hooks::Create(kTinyIdentityOwner,
            reinterpret_cast<LPVOID>(&TinyIdentityTarget),
            reinterpret_cast<LPVOID>(&TinyIdentityDetour),
            BackendOutputStorage(&g_tiny_identity_original));
        tiny_after_create = CallTinyIdentity(7);
        if (tiny_target_status == MH_OK) {
            tiny_target_supported = true;
            tiny_enable_status = mw::hooks::Enable(kTinyIdentityOwner,
                reinterpret_cast<LPVOID>(&TinyIdentityTarget));
            if (tiny_enable_status == MH_OK) {
                tiny_while_enabled = CallTinyIdentity(7);
                tiny_detour_calls_while_enabled =
                    InterlockedCompareExchange(&g_tiny_identity_detour_calls,
                        0, 0);
                tiny_disable_status = mw::hooks::Disable(kTinyIdentityOwner,
                    reinterpret_cast<LPVOID>(&TinyIdentityTarget));
                tiny_disable_ok = tiny_disable_status == MH_OK ||
                    tiny_disable_status == MH_ERROR_DISABLED;
                tiny_after_disable = CallTinyIdentity(7);
                tiny_detour_calls_after_disable =
                    InterlockedCompareExchange(&g_tiny_identity_detour_calls,
                        0, 0);
                tiny_remove_status = mw::hooks::Remove(kTinyIdentityOwner,
                    reinterpret_cast<LPVOID>(&TinyIdentityTarget));
                tiny_remove_ok = tiny_remove_status == MH_OK ||
                    tiny_remove_status == MH_ERROR_NOT_CREATED;
                tiny_after_remove = CallTinyIdentity(7);
                tiny_detour_calls_after_remove =
                    InterlockedCompareExchange(&g_tiny_identity_detour_calls,
                        0, 0);
            } else {
                tiny_remove_status = mw::hooks::Remove(kTinyIdentityOwner,
                    reinterpret_cast<LPVOID>(&TinyIdentityTarget));
                tiny_remove_ok = tiny_remove_status == MH_OK ||
                    tiny_remove_status == MH_ERROR_NOT_CREATED;
                tiny_after_remove = CallTinyIdentity(7);
                tiny_detour_calls_after_remove =
                    InterlockedCompareExchange(&g_tiny_identity_detour_calls,
                        0, 0);
            }
        }
#ifdef MW_BACKEND_FRIDA_GUM
        tiny_target_expected_supported = false;
        tiny_target_ok = !tiny_target_supported &&
            tiny_target_status == MH_ERROR_UNSUPPORTED_FUNCTION &&
            g_tiny_identity_original == nullptr && tiny_before_create == 7 &&
            tiny_after_create == 7 && g_tiny_identity_detour_calls == 0;
#else
        tiny_target_expected_supported = true;
        tiny_target_ok = tiny_target_supported &&
            tiny_target_status == MH_OK && tiny_enable_status == MH_OK &&
            tiny_disable_ok && tiny_remove_ok && tiny_before_create == 7 &&
            tiny_after_create == 7 && tiny_while_enabled == 8 &&
            tiny_detour_calls_while_enabled == 1 && tiny_after_disable == 7 &&
            tiny_detour_calls_after_disable == 1 && tiny_after_remove == 7 &&
            tiny_detour_calls_after_remove == 1;
#endif
        tiny_baseline_before_create_ok = tiny_before_create == 7;
        tiny_create_preserves_baseline_ok = tiny_after_create == 7;
        tiny_enable_invokes_detour_ok = tiny_enable_status == MH_OK &&
            tiny_while_enabled == 8 && tiny_detour_calls_while_enabled == 1;
        tiny_disable_restores_target_ok = tiny_disable_ok &&
            tiny_after_disable == 7 && tiny_detour_calls_after_disable == 1;
        tiny_remove_keeps_target_restored_ok = tiny_remove_ok &&
            tiny_after_remove == 7 && tiny_detour_calls_after_remove == 1;

        const std::int64_t integer_args[] = {1, 2, 3, 4, 5, 6, 7, 8};
        InterlockedExchange(&g_integer_target_calls, 0);
        InterlockedExchange(&g_integer_detour_calls, 0);
        if (InstallHook(kIntegerOwner,
            reinterpret_cast<LPVOID>(&IntegerTarget),
            reinterpret_cast<LPVOID>(&IntegerDetour),
            BackendOutputStorage(&g_integer_original))) {
            const std::int64_t result = IntegerTarget(integer_args[0],
                integer_args[1], integer_args[2], integer_args[3],
                integer_args[4], integer_args[5], integer_args[6],
                integer_args[7]);
            integer_ok = result == 0x112233 + 204 &&
                g_integer_target_calls == 1 && g_integer_detour_calls == 1;
            integer_ok = RemoveHook(kIntegerOwner,
                reinterpret_cast<LPVOID>(&IntegerTarget)) && integer_ok;
        }

        InterlockedExchange(&g_mixed_target_calls, 0);
        InterlockedExchange(&g_mixed_detour_calls, 0);
        if (InstallHook(kMixedOwner, reinterpret_cast<LPVOID>(&MixedTarget),
            reinterpret_cast<LPVOID>(&MixedDetour),
            BackendOutputStorage(&g_mixed_original))) {
            const double result = MixedTarget(1.25, 7, 2.5f, 3.5, 11,
                4.25f, 5.75);
            const double expected = 97.75 + kMixedDetourDelta;
            mixed_ok = std::fabs(result - expected) < 0.0001 &&
                g_mixed_target_calls == 1 && g_mixed_detour_calls == 1;
            mixed_ok = RemoveHook(kMixedOwner,
                reinterpret_cast<LPVOID>(&MixedTarget)) && mixed_ok;
        }

        InterlockedExchange(&g_aggregate_target_calls, 0);
        InterlockedExchange(&g_aggregate_detour_calls, 0);
        if (InstallHook(kAggregateOwner,
            reinterpret_cast<LPVOID>(&AggregateTarget),
            reinterpret_cast<LPVOID>(&AggregateDetour),
            BackendOutputStorage(&g_aggregate_original))) {
            const AggregateResult result = AggregateTarget(0x100000001ull,
                2.25, 17, 0x200000003ull, 9, 4.5);
            const std::uint64_t base_checksum = 0x100000001ull ^
                0x200000003ull ^ (std::uint64_t{17} << 17) ^ 9;
            aggregate_ok = result.integer == 0x100000001ull + 17 + 9 +
                    0x1234 &&
                std::fabs(result.real - (2.25 + 4.5 + 12.5)) < 0.0001 &&
                result.checksum == (base_checksum ^ 0x55aa55aa55aa55aaull) &&
                g_aggregate_target_calls == 1 && g_aggregate_detour_calls == 1;
            aggregate_ok = RemoveHook(kAggregateOwner,
                reinterpret_cast<LPVOID>(&AggregateTarget)) && aggregate_ok;
        }

        InterlockedExchange(&g_last_error_target_calls, 0);
        InterlockedExchange(&g_last_error_detour_calls, 0);
        InterlockedExchange(&g_last_error_seen_by_detour, 0);
        if (InstallHook(kLastErrorOwner,
            reinterpret_cast<LPVOID>(&LastErrorTarget),
            reinterpret_cast<LPVOID>(&LastErrorDetour),
            BackendOutputStorage(&g_last_error_original))) {
            SetLastError(ERROR_SUCCESS);
            const LONG result = LastErrorTarget(33);
            returned_last_error = GetLastError();
            last_error_ok = result == 45 &&
                static_cast<DWORD>(g_last_error_seen_by_detour) ==
                    kOriginalLastError &&
                returned_last_error == kDetourLastError &&
                g_last_error_target_calls == 1 && g_last_error_detour_calls == 1;
            last_error_ok = RemoveHook(kLastErrorOwner,
                reinterpret_cast<LPVOID>(&LastErrorTarget)) && last_error_ok;
        }

        InterlockedExchange(&g_recursion_target_calls, 0);
        InterlockedExchange(&g_recursion_detour_calls, 0);
        InterlockedExchange(&g_recursion_post_calls, 0);
        if (InstallHook(kRecursionOwner,
            reinterpret_cast<LPVOID>(&RecursionTarget),
            reinterpret_cast<LPVOID>(&RecursionDetour),
            BackendOutputStorage(&g_recursion_original))) {
            const LONG result = RecursionTarget(kRecursionDepth);
            recursion_matches = g_recursion_detour_calls ==
                kExpectedDetourEntries;
            const bool recursion_result_ok = result == kRecursionDepth + 1 &&
                g_recursion_target_calls == kRecursionDepth + 1;
            if (!RemoveHook(kRecursionOwner,
                reinterpret_cast<LPVOID>(&RecursionTarget))) {
                recursion_matches = false;
            }
            if (!recursion_result_ok) {
                recursion_matches = false;
            }
        }

        // Warm this pair before measuring repeated lifecycle.
        const bool warm_ok = InstallHook(kSoakOwner, reinterpret_cast<LPVOID>(&SoakTarget),
            reinterpret_cast<LPVOID>(&SoakDetour), BackendOutputStorage(&g_soak_original)) &&
            RemoveHook(kSoakOwner, reinterpret_cast<LPVOID>(&SoakTarget));
        metrics_before = ReadBackendMetrics();
        soak_memory_ok = ReadPrivateBytes(&private_before);
        const ULONGLONG soak_start = GetTickCount64();
        InterlockedExchange(&g_soak_detour_calls, 0);
        soak_ok = soak_memory_ok && warm_ok;
        for (std::uint64_t iteration = 0; iteration < kSoakIterations;
            ++iteration) {
            InterlockedExchangePointer(&g_soak_original, nullptr);
            if (!IsOk(mw::hooks::Create(kSoakOwner,
                reinterpret_cast<LPVOID>(&SoakTarget),
                reinterpret_cast<LPVOID>(&SoakDetour),
                BackendOutputStorage(&g_soak_original)))) {
                soak_ok = false;
                break;
            }
            if (!IsOk(mw::hooks::Enable(kSoakOwner,
                reinterpret_cast<LPVOID>(&SoakTarget)))) {
                (void) mw::hooks::Remove(kSoakOwner,
                    reinterpret_cast<LPVOID>(&SoakTarget));
                soak_ok = false;
                break;
            }
            if (SoakTarget(5) != 22 ||
                !IsOk(mw::hooks::Disable(kSoakOwner,
                    reinterpret_cast<LPVOID>(&SoakTarget))) ||
                !IsOk(mw::hooks::Remove(kSoakOwner,
                    reinterpret_cast<LPVOID>(&SoakTarget)))) {
                soak_ok = false;
                break;
            }
            ++soak_completed;
        }
        soak_elapsed_ms = GetTickCount64() - soak_start;
        soak_ok = soak_ok && soak_completed == kSoakIterations &&
            SoakTarget(5) == 15 && g_soak_detour_calls == kSoakIterations;
        soak_memory_ok = ReadPrivateBytes(&private_after) && soak_memory_ok;
        metrics_after = ReadBackendMetrics();
#ifndef MW_BACKEND_FRIDA_GUM
        soak_ok = soak_ok && metrics_after.retained_hook_records == metrics_before.retained_hook_records &&
            metrics_after.retained_gateways == metrics_before.retained_gateways &&
            metrics_after.trampoline_regions == metrics_before.trampoline_regions &&
            metrics_after.retired_generations == 0;
#endif
    }

    MH_STATUS uninitialize_status = setup_ok ? mw::hooks::Uninitialize() :
        MH_ERROR_NOT_INITIALIZED;
#ifdef MW_BACKEND_FRIDA_GUM
    const bool expected_uninitialize = uninitialize_status ==
        MH_ERROR_UNABLE_TO_UNINITIALIZE;
#else
    const bool expected_uninitialize = uninitialize_status == MH_ERROR_UNABLE_TO_UNINITIALIZE;
#endif
    const bool all_passed = setup_ok && tiny_target_ok && integer_ok &&
        mixed_ok && aggregate_ok && last_error_ok && recursion_matches &&
        soak_ok && soak_memory_ok && expected_uninitialize;

    std::printf("{\"test\":\"backend-contracts\",\"backend\":\"%s\","
        "\"assertions\":{\"integer_8_args\":%s,\"mixed_sse\":%s,"
        "\"aggregate_return\":%s,\"last_error\":%s},"
        "\"tiny_identity\":{\"supported\":%s,"
        "\"expected_supported\":%s,\"status_code\":%d,"
        "\"status_text\":\"%s\",\"matches_expected_support\":%s,"
        "\"phases\":{\"before_create\":%ld,"
        "\"after_create_before_enable\":%ld,\"enable_status_code\":%d,"
        "\"while_enabled\":%ld,\"detour_calls_while_enabled\":%ld,"
        "\"disable_status_code\":%d,\"after_disable\":%ld,"
        "\"detour_calls_after_disable\":%ld,\"remove_status_code\":%d,"
        "\"after_remove\":%ld,\"detour_calls_after_remove\":%ld,"
        "\"checks\":{\"baseline_before_create\":%s,"
        "\"create_preserves_baseline\":%s,\"enable_invokes_detour\":%s,"
        "\"disable_restores_target\":%s,"
        "\"remove_keeps_target_restored\":%s}}},"
        "\"last_error_values\":{\"original_seen\":%ld,"
        "\"expected_original\":%lu,\"returned\":%lu,"
        "\"expected_returned\":%lu},",
        BackendName(), integer_ok ? "true" : "false",
        mixed_ok ? "true" : "false", aggregate_ok ? "true" : "false",
        last_error_ok ? "true" : "false",
        tiny_target_supported ? "true" : "false",
        tiny_target_expected_supported ? "true" : "false",
        static_cast<int>(tiny_target_status),
        MH_StatusToString(tiny_target_status),
        tiny_target_ok ? "true" : "false", tiny_before_create,
        tiny_after_create, static_cast<int>(tiny_enable_status),
        tiny_while_enabled, tiny_detour_calls_while_enabled,
        static_cast<int>(tiny_disable_status), tiny_after_disable,
        tiny_detour_calls_after_disable, static_cast<int>(tiny_remove_status),
        tiny_after_remove, tiny_detour_calls_after_remove,
        tiny_baseline_before_create_ok ? "true" : "false",
        tiny_create_preserves_baseline_ok ? "true" : "false",
        tiny_enable_invokes_detour_ok ? "true" : "false",
        tiny_disable_restores_target_ok ? "true" : "false",
        tiny_remove_keeps_target_restored_ok ? "true" : "false",
        g_last_error_seen_by_detour,
        static_cast<unsigned long>(kOriginalLastError),
        static_cast<unsigned long>(returned_last_error),
        static_cast<unsigned long>(kDetourLastError));
    std::printf("\"recursion\":{\"detour_entries\":%ld,"
        "\"expected_detour_entries\":%d,\"target_calls\":%ld,"
        "\"matches_backend_semantics\":%s,\"semantics\":\"%s\"},",
        g_recursion_detour_calls,
        static_cast<int>(kExpectedDetourEntries),
        g_recursion_target_calls,
        recursion_matches ? "true" : "false", kRecursionSemantics);
    std::printf("\"soak\":{\"iterations\":%llu,\"completed\":%llu,"
        "\"passed\":%s,\"elapsed_ms\":%llu,"
        "\"private_bytes_before\":%llu,\"private_bytes_after\":%llu,"
        "\"private_bytes_delta\":%lld,\"backend_metrics_before\":",
        static_cast<unsigned long long>(kSoakIterations),
        static_cast<unsigned long long>(soak_completed),
        soak_ok ? "true" : "false",
        static_cast<unsigned long long>(soak_elapsed_ms),
        static_cast<unsigned long long>(private_before),
        static_cast<unsigned long long>(private_after),
        static_cast<long long>(private_after) -
            static_cast<long long>(private_before));
    PrintMetrics(metrics_before);
    std::printf(",\"backend_metrics_after\":");
    PrintMetrics(metrics_after);
    std::printf("},\"setup_ok\":%s,\"memory_query_ok\":%s,"
        "\"uninitialize_expected\":%s,\"all_passed\":%s}\n",
        setup_ok ? "true" : "false", soak_memory_ok ? "true" : "false",
        expected_uninitialize ? "true" : "false",
        all_passed ? "true" : "false");
    return all_passed ? 0 : 1;
}
