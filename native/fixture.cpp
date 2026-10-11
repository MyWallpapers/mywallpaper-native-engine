#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "mw_lifetime_probe.h"
#include "mw_drain_probe.h"
#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

extern "C" __declspec(dllexport) __declspec(noinline) int __cdecl MwFixtureCompute(int value);
extern "C" __declspec(dllexport) __declspec(noinline) int __cdecl MwFixtureSecondary(int value);

namespace {

using Json = nlohmann::json;

std::atomic_bool g_running{true};
std::atomic_uint64_t g_sample_count{0};
std::mutex g_late_module_mutex;
HMODULE g_late_module = nullptr;
HMODULE g_forwarder_module = nullptr;
std::mutex g_probe_call_mutex;
std::thread g_probe_call_thread;
std::atomic_bool g_probe_call_started{false};
std::atomic_bool g_probe_call_done{false};
std::atomic_int32_t g_probe_call_result{0};
std::atomic_uint32_t g_probe_call_error{0};

using ComputeFunction = int(__cdecl*)(int);
using LateFunction = int(__cdecl*)(int);

struct LifetimeProbeExports {
    using ArmFunction = uint32_t(MWLP_CALL*)();
    using GetSnapshotFunction = uint32_t(MWLP_CALL*)(MwLifetimeProbeSnapshot*);
    using WaitForCaptureFunction = uint32_t(MWLP_CALL*)(uint32_t);
    using CycleHookFunction = uint32_t(MWLP_CALL*)();
    using ReleaseFunction = uint32_t(MWLP_CALL*)(int32_t);
    using CancelFunction = uint32_t(MWLP_CALL*)();
    using GetResultFunction = uint32_t(MWLP_CALL*)(MwLifetimeProbeResultData*);

    ArmFunction arm = nullptr;
    GetSnapshotFunction get_snapshot = nullptr;
    WaitForCaptureFunction wait_for_capture = nullptr;
    CycleHookFunction cycle_hook = nullptr;
    ReleaseFunction release = nullptr;
    CancelFunction cancel = nullptr;
    GetResultFunction get_result = nullptr;
};

bool GetLifetimeProbeExports(LifetimeProbeExports* exports, std::string* error) {
    if (exports == nullptr) {
        return false;
    }
    const HMODULE module = GetModuleHandleW(L"mw_addon_lifetime_probe.dll");
    if (module == nullptr) {
        if (error != nullptr) {
            *error = "lifetime probe addon is not loaded";
        }
        return false;
    }

    exports->arm = reinterpret_cast<LifetimeProbeExports::ArmFunction>(
        GetProcAddress(module, "MwLifetimeProbeArm"));
    exports->get_snapshot = reinterpret_cast<LifetimeProbeExports::GetSnapshotFunction>(
        GetProcAddress(module, "MwLifetimeProbeGetSnapshot"));
    exports->wait_for_capture = reinterpret_cast<LifetimeProbeExports::WaitForCaptureFunction>(
        GetProcAddress(module, "MwLifetimeProbeWaitForCapture"));
    exports->cycle_hook = reinterpret_cast<LifetimeProbeExports::CycleHookFunction>(
        GetProcAddress(module, "MwLifetimeProbeCycleHook"));
    exports->release = reinterpret_cast<LifetimeProbeExports::ReleaseFunction>(
        GetProcAddress(module, "MwLifetimeProbeRelease"));
    exports->cancel = reinterpret_cast<LifetimeProbeExports::CancelFunction>(
        GetProcAddress(module, "MwLifetimeProbeCancel"));
    exports->get_result = reinterpret_cast<LifetimeProbeExports::GetResultFunction>(
        GetProcAddress(module, "MwLifetimeProbeGetResult"));
    if (exports->arm == nullptr || exports->get_snapshot == nullptr ||
        exports->wait_for_capture == nullptr ||
        exports->cycle_hook == nullptr ||
        exports->release == nullptr || exports->cancel == nullptr ||
        exports->get_result == nullptr) {
        if (error != nullptr) {
            *error = "lifetime probe test exports are incomplete";
        }
        return false;
    }
    return true;
}

struct DrainProbeExports {
    uint32_t(MWDP_CALL* arm)() = nullptr;
    uint32_t(MWDP_CALL* wait_for_capture)(uint32_t) = nullptr;
    uint32_t(MWDP_CALL* release)(int32_t) = nullptr;
    uint32_t(MWDP_CALL* get_snapshot)(MwDrainProbeSnapshot*) = nullptr;
    int32_t(MWDP_CALL* invoke_closed)(int32_t) = nullptr;
};

bool GetDrainProbeExports(DrainProbeExports* exports) {
    const HMODULE module = GetModuleHandleW(L"mw_addon_drain_probe.dll");
    if (module == nullptr || exports == nullptr) { return false; }
    exports->arm = reinterpret_cast<decltype(exports->arm)>(GetProcAddress(module, "MwDrainProbeArm"));
    exports->wait_for_capture = reinterpret_cast<decltype(exports->wait_for_capture)>(GetProcAddress(module, "MwDrainProbeWaitForCapture"));
    exports->release = reinterpret_cast<decltype(exports->release)>(GetProcAddress(module, "MwDrainProbeRelease"));
    exports->get_snapshot = reinterpret_cast<decltype(exports->get_snapshot)>(GetProcAddress(module, "MwDrainProbeGetSnapshot"));
    exports->invoke_closed = reinterpret_cast<decltype(exports->invoke_closed)>(GetProcAddress(module, "MwDrainProbeInvokeClosedDetour"));
    return exports->arm && exports->wait_for_capture && exports->release &&
        exports->get_snapshot && exports->invoke_closed;
}

Json DrainSnapshotToJson(const MwDrainProbeSnapshot& snapshot) {
    return Json{{"generation", snapshot.generation}, {"admittedEntries", snapshot.admitted_entries},
        {"resourceAccesses", snapshot.resource_accesses}, {"rejectedEntries", snapshot.rejected_entries},
        {"forwardCalls", snapshot.forward_calls}, {"cleanupCount", snapshot.cleanup_count},
        {"inFlight", snapshot.in_flight}, {"lastResult", snapshot.last_result},
        {"captured", (snapshot.flags & MWDP_FLAG_CAPTURED) != 0},
        {"completed", (snapshot.flags & MWDP_FLAG_COMPLETED) != 0},
        {"timedOut", (snapshot.flags & MWDP_FLAG_TIMED_OUT) != 0},
        {"resourcesLive", (snapshot.flags & MWDP_FLAG_RESOURCES_LIVE) != 0},
        {"gateClosed", (snapshot.flags & MWDP_FLAG_GATE_CLOSED) != 0}};
}

std::string BytesToHex(const uint8_t* bytes, size_t length) {
    constexpr char kHex[] = "0123456789abcdef";
    std::string result(length * 2, '\0');
    for (size_t index = 0; index < length; ++index) {
        result[index * 2] = kHex[bytes[index] >> 4];
        result[index * 2 + 1] = kHex[bytes[index] & 0x0f];
    }
    return result;
}

Json MemorySnapshotToJson(const MwLifetimeProbeMemorySnapshot& memory) {
    return Json{
        {"state", memory.memory_state},
        {"protection", memory.protection},
        {"allocationBase", std::to_string(memory.allocation_base)},
        {"regionBase", std::to_string(memory.region_base)},
        {"regionSize", std::to_string(memory.region_size)},
        {"readable", memory.readable != 0},
        {"executable", memory.executable != 0},
        {"bytesHex", BytesToHex(memory.bytes, MW_LIFETIME_PROBE_MEMORY_BYTES)}};
}

bool ReadProbeSnapshot(const LifetimeProbeExports& exports, MwLifetimeProbeSnapshot* snapshot) {
    if (snapshot == nullptr || exports.get_snapshot == nullptr) {
        return false;
    }
    *snapshot = {};
    snapshot->struct_size = sizeof(*snapshot);
    return exports.get_snapshot(snapshot) == MWLP_OK;
}

void CancelAndJoinProbeCall() {
    LifetimeProbeExports exports;
    std::string ignored_error;
    if (GetLifetimeProbeExports(&exports, &ignored_error) && exports.cancel != nullptr) {
        static_cast<void>(exports.cancel());
    }
    DrainProbeExports drain_exports;
    if (GetDrainProbeExports(&drain_exports)) {
        static_cast<void>(drain_exports.release(0));
    }

    std::lock_guard lock(g_probe_call_mutex);
    if (g_probe_call_thread.joinable()) {
        g_probe_call_thread.join();
    }
}

bool StartProbeCall(std::string* error, const std::wstring& module_name = L"mw_fixture.exe",
    const std::string& export_name = "MwFixtureCompute", int input = 1000,
    bool require_lifetime_arm = true) {
    std::lock_guard lock(g_probe_call_mutex);
    if (g_probe_call_started.load(std::memory_order_acquire) &&
        !g_probe_call_done.load(std::memory_order_acquire)) {
        if (error != nullptr) {
            *error = "probe call is already in flight";
        }
        return false;
    }

    if (require_lifetime_arm) {
        LifetimeProbeExports exports;
        if (!GetLifetimeProbeExports(&exports, error)) { return false; }
        MwLifetimeProbeSnapshot snapshot{};
        snapshot.struct_size = sizeof(snapshot);
        if (!ReadProbeSnapshot(exports, &snapshot) ||
            (snapshot.flags & MWLP_FLAG_ARMED) == 0) {
            if (error != nullptr) { *error = "probe must be armed before starting its call"; }
            return false;
        }
    }

    const auto compute = reinterpret_cast<ComputeFunction>(
        GetProcAddress(GetModuleHandleW(module_name.c_str()), export_name.c_str()));
    if (compute == nullptr) {
        if (error != nullptr) { *error = "test function export not found"; }
        return false;
    }

    if (g_probe_call_thread.joinable()) {
        g_probe_call_thread.join();
    }
    g_probe_call_result.store(0, std::memory_order_relaxed);
    g_probe_call_error.store(0, std::memory_order_relaxed);
    g_probe_call_done.store(false, std::memory_order_relaxed);
    g_probe_call_started.store(true, std::memory_order_release);
    try {
        g_probe_call_thread = std::thread([compute, input] {
            g_probe_call_result.store(compute(input), std::memory_order_relaxed);
            g_probe_call_done.store(true, std::memory_order_release);
        });
    } catch (const std::system_error&) {
        g_probe_call_started.store(false, std::memory_order_release);
        g_probe_call_done.store(false, std::memory_order_release);
        if (error != nullptr) {
            *error = "could not create probe-call thread";
        }
        return false;
    }
    return true;
}

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr);
    if (written != required) {
        return {};
    }
    return result;
}

std::wstring NormalizePipeName(std::wstring name) {
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\";
    if (name.rfind(prefix, 0) != 0) {
        name.insert(0, prefix);
    }
    return name;
}

std::filesystem::path FixtureModulePath() {
    std::wstring image_path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr,
        image_path.data(),
        static_cast<DWORD>(image_path.size()));
    if (length == 0 || length >= image_path.size()) {
        return {};
    }
    image_path.resize(length);
    return std::filesystem::path(image_path).parent_path() / L"mw_fixture_module.dll";
}

Json HandleCommand(const Json& request) {
    Json response = Json::object();
    if (request.contains("id")) {
        response["id"] = request["id"];
    } else {
        response["id"] = nullptr;
    }

    if (!request.is_object() || !request.contains("operation") ||
        !request["operation"].is_string()) {
        response["ok"] = false;
        response["error"] = "expected an operation string";
        return response;
    }

    const std::string operation = request["operation"].get<std::string>();
    if (operation.rfind("drain_", 0) == 0) {
        DrainProbeExports exports;
        if (!GetDrainProbeExports(&exports)) {
            response["ok"] = false;
            response["error"] = "drain probe test exports are not loaded";
            return response;
        }
        uint32_t status = MWDP_OK;
        if (operation == "drain_arm") {
            std::lock_guard lock(g_probe_call_mutex);
            if (g_probe_call_started.load(std::memory_order_acquire) &&
                !g_probe_call_done.load(std::memory_order_acquire)) {
                status = MWDP_ERROR_BUSY;
            } else {
                if (g_probe_call_thread.joinable()) { g_probe_call_thread.join(); }
                status = exports.arm();
            }
        } else if (operation == "drain_start_call") {
            std::string error;
            if (!StartProbeCall(&error, L"mw_fixture.exe", "MwFixtureCompute", 2000, false)) {
                response["ok"] = false;
                response["error"] = error;
                return response;
            }
        } else if (operation == "drain_capture") {
            status = exports.wait_for_capture(1000);
        } else if (operation == "drain_release") {
            status = exports.release(request.value("invokeOriginal", true) ? 1 : 0);
        } else if (operation == "drain_invoke_closed") {
            response["result"] = exports.invoke_closed(request.value("input", 2000));
        } else if (operation == "drain_result") {
            std::lock_guard lock(g_probe_call_mutex);
            const bool done = g_probe_call_done.load(std::memory_order_acquire);
            response["callCompleted"] = done;
            if (done) {
                if (g_probe_call_thread.joinable()) { g_probe_call_thread.join(); }
                response["result"] = g_probe_call_result.load(std::memory_order_relaxed);
            }
        } else if (operation != "drain_snapshot") {
            response["ok"] = false;
            response["error"] = "unknown drain probe operation";
            return response;
        }
        MwDrainProbeSnapshot snapshot{};
        snapshot.struct_size = sizeof(snapshot);
        const uint32_t snapshot_status = exports.get_snapshot(&snapshot);
        response["ok"] = status == MWDP_OK && snapshot_status == MWDP_OK;
        response["code"] = status;
        response["drain"] = DrainSnapshotToJson(snapshot);
        return response;
    }
    if (operation == "probe_arm") {
        LifetimeProbeExports exports;
        std::string error;
        if (!GetLifetimeProbeExports(&exports, &error)) {
            response["ok"] = false;
            response["error"] = error;
            return response;
        }

        {
            std::lock_guard lock(g_probe_call_mutex);
            if (g_probe_call_started.load(std::memory_order_acquire) &&
                !g_probe_call_done.load(std::memory_order_acquire)) {
                response["ok"] = false;
                response["error"] = "probe call is already in flight";
                return response;
            }
            if (g_probe_call_thread.joinable()) {
                g_probe_call_thread.join();
            }
        }

        const uint32_t status = exports.arm();
        if (status == MWLP_OK) {
            g_probe_call_started.store(false, std::memory_order_release);
            g_probe_call_done.store(false, std::memory_order_release);
            g_probe_call_result.store(0, std::memory_order_relaxed);
            g_probe_call_error.store(0, std::memory_order_relaxed);
        }
        response["ok"] = status == MWLP_OK;
        response["armed"] = status == MWLP_OK;
        response["code"] = status;
        return response;
    }

    if (operation == "probe_start_call") {
        std::string error;
        const std::string module_utf8 = request.value("module", std::string("mw_fixture.exe"));
        std::wstring module_name(module_utf8.begin(), module_utf8.end());
        const bool started = StartProbeCall(&error, module_name,
            request.value("export", std::string("MwFixtureCompute")));
        response["ok"] = started;
        response["started"] = started;
        if (!started) {
            response["error"] = error;
        }
        return response;
    }

    if (operation == "probe_capture") {
        LifetimeProbeExports exports;
        std::string error;
        MwLifetimeProbeSnapshot snapshot{};
        if (!GetLifetimeProbeExports(&exports, &error)) {
            response["ok"] = false;
            response["error"] = error;
            return response;
        }

        uint32_t wait_milliseconds = 0;
        if (request.contains("waitMilliseconds")) {
            if (!request["waitMilliseconds"].is_number_unsigned() &&
                !request["waitMilliseconds"].is_number_integer()) {
                response["ok"] = false;
                response["error"] = "waitMilliseconds must be an integer";
                return response;
            }
            try {
                const int64_t parsed = request["waitMilliseconds"].get<int64_t>();
                if (parsed < 0 || parsed > 15000) {
                    response["ok"] = false;
                    response["error"] = "waitMilliseconds must be between 0 and 15000";
                    return response;
                }
                wait_milliseconds = static_cast<uint32_t>(parsed);
            } catch (const Json::exception&) {
                response["ok"] = false;
                response["error"] = "waitMilliseconds must be between 0 and 15000";
                return response;
            }
        }
        const uint32_t wait_status = exports.wait_for_capture(wait_milliseconds);
        if (wait_status != MWLP_OK && wait_status != MWLP_ERROR_NOT_READY) {
            response["ok"] = false;
            response["error"] = "could not wait for probe capture";
            response["code"] = wait_status;
            return response;
        }
        if (!ReadProbeSnapshot(exports, &snapshot)) {
            response["ok"] = false;
            response["error"] = "could not read probe snapshot";
            return response;
        }

        response["ok"] = true;
        response["waitTimedOut"] = wait_status == MWLP_ERROR_NOT_READY;
        response["armed"] = (snapshot.flags & MWLP_FLAG_ARMED) != 0;
        response["captured"] = (snapshot.flags & MWLP_FLAG_ENTERED) != 0;
        response["active"] = (snapshot.flags & MWLP_FLAG_ENTERED) != 0 &&
            (snapshot.flags & MWLP_FLAG_COMPLETED) == 0;
        response["released"] = (snapshot.flags & MWLP_FLAG_RELEASED) != 0;
        response["originalAddress"] = std::to_string(snapshot.original_address);
        response["amount"] = snapshot.captured_amount;
        response["before"] = MemorySnapshotToJson(snapshot.before);
        response["after"] = MemorySnapshotToJson(snapshot.after);
        response["bytesUnchanged"] = snapshot.bytes_unchanged != 0;
        return response;
    }

    if (operation == "probe_release") {
        if (!request.contains("invokeOriginal") || !request["invokeOriginal"].is_boolean()) {
            response["ok"] = false;
            response["error"] = "invokeOriginal must be a boolean";
            return response;
        }

        LifetimeProbeExports exports;
        std::string error;
        if (!GetLifetimeProbeExports(&exports, &error)) {
            response["ok"] = false;
            response["error"] = error;
            return response;
        }
        const bool invoke_original = request["invokeOriginal"].get<bool>();
        const uint32_t status = exports.release(invoke_original ? 1 : 0);
        response["ok"] = status == MWLP_OK;
        response["released"] = status == MWLP_OK;
        response["invokeOriginal"] = invoke_original;
        response["code"] = status;
        return response;
    }

    if (operation == "probe_cycle_hook") {
        LifetimeProbeExports exports;
        std::string error;
        if (!GetLifetimeProbeExports(&exports, &error)) {
            response["ok"] = false;
            response["error"] = error;
            return response;
        }
        const uint32_t status = exports.cycle_hook();
        response["ok"] = status == MWLP_OK;
        response["cycled"] = status == MWLP_OK;
        response["code"] = status;
        return response;
    }

    if (operation == "probe_result") {
        bool completed = false;
        bool started = false;
        int32_t call_result = 0;
        uint32_t call_error = 0;
        {
            std::lock_guard lock(g_probe_call_mutex);
            started = g_probe_call_started.load(std::memory_order_acquire);
            completed = started && g_probe_call_done.load(std::memory_order_acquire);
            if (completed) {
                if (g_probe_call_thread.joinable()) {
                    g_probe_call_thread.join();
                }
                call_result = g_probe_call_result.load(std::memory_order_relaxed);
                call_error = g_probe_call_error.load(std::memory_order_relaxed);
            }
        }

        LifetimeProbeExports exports;
        std::string error;
        MwLifetimeProbeResultData probe_result{};
        probe_result.struct_size = sizeof(probe_result);
        if (!GetLifetimeProbeExports(&exports, &error) ||
            exports.get_result(&probe_result) != MWLP_OK) {
            response["ok"] = false;
            response["error"] = error.empty() ? "could not read probe result" : error;
            return response;
        }

        response["ok"] = started && call_error == 0;
        response["started"] = started;
        response["completed"] = completed;
        response["timedOut"] = (probe_result.flags & MWLP_FLAG_TIMED_OUT) != 0;
        response["originalInvoked"] = probe_result.original_invoked != 0;
        if ((probe_result.flags & MWLP_FLAG_COMPLETED) != 0) {
            response["detourResult"] = probe_result.detour_result;
        }
        if (completed) {
            if (call_error != 0) {
                response["error"] = "MwFixtureCompute export not found";
            } else {
                response["result"] = call_result;
            }
        } else if (!started) {
            response["error"] = "no probe call has been started";
        }
        return response;
    }

    if (operation == "sample") {
        response["ok"] = true;
        response["value"] = MwFixtureCompute(10);
        response["secondaryValue"] = MwFixtureSecondary(20);
        response["sampleCount"] = g_sample_count.load(std::memory_order_relaxed);
        // Test-only evidence of physical restoration, distinct from returning
        // the baseline value through a resident replacement. Read while the
        // management harness is between hook operations.
        const auto* prologue = reinterpret_cast<const unsigned char*>(
            reinterpret_cast<std::uintptr_t>(&MwFixtureCompute));
        constexpr char hex[] = "0123456789abcdef";
        std::string prologue_hex;
        prologue_hex.reserve(32);
        for (std::size_t index = 0; index < 16; ++index) {
            prologue_hex.push_back(hex[prologue[index] >> 4]);
            prologue_hex.push_back(hex[prologue[index] & 0x0f]);
        }
        response["computePrologue"] = std::move(prologue_hex);

        std::lock_guard lock(g_late_module_mutex);
        const HMODULE late_module = g_late_module != nullptr
            ? g_late_module : GetModuleHandleW(L"mw_fixture_module.dll");
        if (late_module == nullptr) {
            response["lateValue"] = nullptr;
        } else {
            const auto late = reinterpret_cast<LateFunction>(
                GetProcAddress(late_module, "MwFixtureLate"));
            if (late == nullptr) {
                response["ok"] = false;
                response["error"] = "MwFixtureLate export not found";
                response["lateValue"] = nullptr;
            } else {
                response["lateValue"] = late(30);
            }
        }
        return response;
    }

    if (operation == "load_module") {
        std::lock_guard lock(g_late_module_mutex);
        if (g_late_module == nullptr) {
            const std::filesystem::path module_path = FixtureModulePath();
            if (module_path.empty()) {
                response["ok"] = false;
                response["error"] = "could not locate fixture executable";
                return response;
            }
            g_late_module = LoadLibraryW(module_path.c_str());
        }

        response["ok"] = g_late_module != nullptr;
        response["moduleLoaded"] = g_late_module != nullptr;
        if (g_late_module == nullptr) {
            response["win32Error"] = GetLastError();
        }
        return response;
    }

    if (operation == "load_forwarder") {
        std::lock_guard lock(g_late_module_mutex);
        if (g_forwarder_module == nullptr) {
            const auto module_path = FixtureModulePath().parent_path() / L"mw_fixture_forwarder.dll";
            g_forwarder_module = LoadLibraryW(module_path.c_str());
        }
        response["ok"] = g_forwarder_module != nullptr;
        return response;
    }

    if (operation == "function_owner") {
        const std::string module_ascii = request.value("module", std::string("mw_fixture_forwarder.dll"));
        const std::wstring module_name(module_ascii.begin(), module_ascii.end());
        const auto address = GetProcAddress(GetModuleHandleW(module_name.c_str()),
            request.value("export", std::string("MwFixtureForwarded")).c_str());
        MEMORY_BASIC_INFORMATION memory{};
        if (address == nullptr || VirtualQuery(reinterpret_cast<const void*>(address),
                &memory, sizeof(memory)) != sizeof(memory) || memory.Type != MEM_IMAGE) {
            response["ok"] = false;
            response["error"] = "function image owner not found";
            return response;
        }
        std::wstring image_path(32768, L'\0');
        const DWORD length = GetModuleFileNameW(static_cast<HMODULE>(memory.AllocationBase),
            image_path.data(), static_cast<DWORD>(image_path.size()));
        image_path.resize(length);
        response["ok"] = length != 0;
        response["ownerName"] = WideToUtf8(std::filesystem::path(image_path).filename().wstring());
        response["imageBase"] = std::to_string(reinterpret_cast<uintptr_t>(memory.AllocationBase));
        return response;
    }

    if (operation == "drop_module_reference") {
        std::lock_guard lock(g_late_module_mutex);
        const std::string module = request.value("module", std::string("late"));
        if (module != "late" && module != "forwarder") {
            response["ok"] = false;
            response["error"] = "expected late or forwarder";
            return response;
        }
        HMODULE& owned_module = module == "late" ? g_late_module : g_forwarder_module;
        response["referenceDropped"] = owned_module != nullptr;
        response["ok"] = owned_module == nullptr || FreeLibrary(owned_module) != FALSE;
        if (response["ok"].get<bool>()) { owned_module = nullptr; }
        response["lateResident"] = GetModuleHandleW(L"mw_fixture_module.dll") != nullptr;
        response["forwarderResident"] = GetModuleHandleW(L"mw_fixture_forwarder.dll") != nullptr;
        return response;
    }

    if (operation == "shutdown") {
        CancelAndJoinProbeCall();
        response["ok"] = true;
        g_running.store(false, std::memory_order_release);
        return response;
    }

    response["ok"] = false;
    response["error"] = "unknown operation";
    return response;
}

bool WriteResponse(HANDLE pipe, const Json& response) {
    const std::string line = response.dump() + "\n";
    const char* cursor = line.data();
    size_t remaining = line.size();
    while (remaining > 0) {
        DWORD written = 0;
        const DWORD request_size = static_cast<DWORD>(
            (remaining > MAXDWORD) ? MAXDWORD : remaining);
        if (!WriteFile(pipe, cursor, request_size, &written, nullptr) || written == 0) {
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    return true;
}

bool ProcessLine(HANDLE pipe, std::string_view line) {
    Json response;
    try {
        const Json request = Json::parse(line);
        response = HandleCommand(request);
    } catch (const Json::exception& error) {
        response = Json{
            {"id", nullptr},
            {"ok", false},
            {"error", std::string("invalid JSON: ") + error.what()}};
    }
    return WriteResponse(pipe, response);
}

bool ServeClient(HANDLE pipe) {
    std::string pending;
    char buffer[4096];

    while (g_running.load(std::memory_order_acquire)) {
        DWORD bytes_read = 0;
        if (!ReadFile(pipe, buffer, sizeof(buffer), &bytes_read, nullptr) || bytes_read == 0) {
            const DWORD error = GetLastError();
            return error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA;
        }

        pending.append(buffer, bytes_read);
        if (pending.size() > 1024 * 1024) {
            WriteResponse(pipe, Json{{"id", nullptr}, {"ok", false}, {"error", "request too large"}});
            return false;
        }

        size_t newline = std::string::npos;
        while ((newline = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, newline);
            pending.erase(0, newline + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!ProcessLine(pipe, line)) {
                return false;
            }
            if (!g_running.load(std::memory_order_acquire)) {
                return true;
            }
        }
    }
    return true;
}

bool ServePipe(const std::wstring& pipe_name) {
    while (g_running.load(std::memory_order_acquire)) {
        HANDLE pipe = CreateNamedPipeW(
            pipe_name.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateNamedPipeW failed: " << GetLastError() << '\n';
            return false;
        }

        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        const DWORD connect_error = connected ? ERROR_SUCCESS : GetLastError();
        if (connected || connect_error == ERROR_PIPE_CONNECTED) {
            ServeClient(pipe);
            DisconnectNamedPipe(pipe);
        } else if (connect_error != ERROR_NO_DATA) {
            std::cerr << "ConnectNamedPipe failed: " << connect_error << '\n';
        }
        CloseHandle(pipe);
    }
    return true;
}

void WorkerLoop(ComputeFunction compute) {
    while (g_running.load(std::memory_order_acquire)) {
        static_cast<void>(compute(10));
        g_sample_count.fetch_add(1, std::memory_order_relaxed);
        Sleep(1);
    }
}

}  // namespace

extern "C" __declspec(dllexport) __declspec(noinline) int __cdecl MwFixtureCompute(int value) {
    // Common comparison fixture: enough movable instructions for both
    // backends. A separate contract test preserves the tiny MOV/RET case.
    volatile int first = value;
    volatile int second = first;
    volatile int third = second;
    return third;
}

extern "C" __declspec(dllexport) __declspec(noinline) int __cdecl MwFixtureSecondary(int value) {
    volatile int first = value;
    volatile int second = first;
    volatile int third = second;
    return third;
}

int wmain(int argc, wchar_t** argv) {
    std::wstring pipe_name;
    uint32_t worker_count = 2;
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view argument(argv[index]);
        if (argument == L"--pipe" && index + 1 < argc) {
            pipe_name = NormalizePipeName(argv[++index]);
        } else if (argument == L"--workers" && index + 1 < argc) {
            const std::wstring_view value(argv[++index]);
            if (value == L"0") {
                worker_count = 0;
            } else if (value == L"2") {
                worker_count = 2;
            } else {
                std::wcerr << "--workers accepts only 0 or 2\n";
                return 2;
            }
        } else {
            std::wcerr << "unknown or incomplete argument: " << argv[index] << '\n';
            return 2;
        }
    }

    if (pipe_name.empty()) {
        std::cerr << "usage: mw_fixture.exe --pipe <name> [--workers 0|2]\n";
        return 2;
    }

    const auto compute = reinterpret_cast<ComputeFunction>(
        GetProcAddress(GetModuleHandleW(nullptr), "MwFixtureCompute"));
    if (compute == nullptr) {
        std::cerr << "MwFixtureCompute export not found\n";
        return 3;
    }

    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (uint32_t index = 0; index < worker_count; ++index) {
        workers.emplace_back(WorkerLoop, compute);
    }

    std::cout << Json{
        {"event", "ready"},
        {"pid", GetCurrentProcessId()},
        {"pipe", WideToUtf8(pipe_name)},
        {"protocol", 1}}.dump() << std::endl;

    const bool served = ServePipe(pipe_name);
    CancelAndJoinProbeCall();
    g_running.store(false, std::memory_order_release);
    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    {
        std::lock_guard lock(g_late_module_mutex);
        if (g_forwarder_module != nullptr) {
            FreeLibrary(g_forwarder_module);
            g_forwarder_module = nullptr;
        }
        if (g_late_module != nullptr) {
            FreeLibrary(g_late_module);
            g_late_module = nullptr;
        }
    }

    return served ? 0 : 1;
}
