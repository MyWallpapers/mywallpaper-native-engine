#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "resident_hooks.h"
#include "hook_backend_policy.h"
#include <cstdio>

namespace {
using Function = int(__cdecl*)(int);
constexpr ULONG_PTR kOwner = 0x4d575245;
LPVOID* g_a = nullptr;
LPVOID* g_b = nullptr;
int g_failures = 0;
int g_checks = 0;
__declspec(noinline) int Target(int value) { volatile int input = value; return input * 2; }
__declspec(noinline) int Add(int value) { return reinterpret_cast<Function>(*g_a)(value) + 3; }
__declspec(noinline) int Multiply(int value) { return reinterpret_cast<Function>(*g_b)(value) * 5; }
void Check(bool condition) { ++g_checks; if (!condition) ++g_failures; }
bool Start(LPVOID detour, LPVOID** output) {
    *output = static_cast<LPVOID*>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (*output == nullptr) return false;
    return mw::hooks::Create(kOwner, reinterpret_cast<LPVOID>(&Target), detour, *output) == MH_OK &&
        mw::hooks::Enable(kOwner, reinterpret_cast<LPVOID>(&Target)) == MH_OK;
}
void Stop(LPVOID* output) {
    Check(mw::hooks::Remove(kOwner, reinterpret_cast<LPVOID>(&Target)) == MH_OK);
    Check(Target(2) == 4); // Stopped physical bridges must never enter either detour.
    Check(VirtualFree(output, 0, MEM_RELEASE) != FALSE); // Borrowed slot is now gone.
}
} // namespace

int main() {
    Check(MH_Initialize() == MH_OK);
    Check(Start(reinterpret_cast<LPVOID>(&Add), &g_a));
    if (g_failures) return 1;
    Check(Target(2) == 7);
    LPVOID captured_a = *g_a;
    Stop(g_a);
    Check(reinterpret_cast<Function>(captured_a)(2) == 4);

    Check(Start(reinterpret_cast<LPVOID>(&Multiply), &g_b));
    if (g_failures) return 1;
    Check(Target(2) == 20);
    LPVOID unused_output = nullptr;
    Check(mw::hooks::Create(kOwner, reinterpret_cast<LPVOID>(&Target),
        reinterpret_cast<LPVOID>(&Add), &unused_output) == MH_ERROR_ALREADY_CREATED);
    Check(unused_output == nullptr && Target(2) == 20);
    Stop(g_b);
    Check(reinterpret_cast<Function>(captured_a)(2) == 4);

    const auto before = mw::hooks::GetMetrics();
    const uint64_t regions = MwBackendTrampolineRegionCount();
    Check(before.retained_records == 2 && before.installed_bridges == 2);
    constexpr int kCycles = 2000;
    for (int cycle = 0; cycle < kCycles && g_failures == 0; ++cycle) {
        const bool addition = cycle % 2 == 0;
        LPVOID** output = addition ? &g_a : &g_b;
        LPVOID detour = addition ? reinterpret_cast<LPVOID>(&Add) : reinterpret_cast<LPVOID>(&Multiply);
        Check(Start(detour, output));
        if (g_failures) break;
        Check(Target(2) == (addition ? 7 : 20));
        if (addition) Check(**output == captured_a);
        Stop(*output);
        Check(reinterpret_cast<Function>(captured_a)(2) == 4);
    }
    const auto after = mw::hooks::GetMetrics();
    Check(after.retained_records == before.retained_records && after.installed_bridges == before.installed_bridges);
    Check(after.active_hooks == 0 && after.registered_hooks == 0);
    Check(after.reuse_count - before.reuse_count == kCycles);
    Check(MwBackendTrampolineRegionCount() == regions && MwBackendRetiredTrampolineCount() == 0);
    Check(mw::hooks::Uninitialize() == MH_ERROR_UNABLE_TO_UNINITIALIZE);
    std::printf("{\"test\":\"changed-detour-and-borrowed-original-storage\",\"passed\":%s,"
        "\"checks\":%d,\"failures\":%d,\"cycles\":%d,\"retained_records\":%llu,"
        "\"installed_bridges\":%llu,\"reuse_count\":%llu,\"trampoline_regions\":%llu}\n",
        g_failures == 0 ? "true" : "false", g_checks, g_failures, kCycles,
        static_cast<unsigned long long>(after.retained_records),
        static_cast<unsigned long long>(after.installed_bridges),
        static_cast<unsigned long long>(after.reuse_count),
        static_cast<unsigned long long>(regions));
    return g_failures == 0 ? 0 : 1;
}
