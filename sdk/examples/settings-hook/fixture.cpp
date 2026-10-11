// Standalone public test process; it never modifies Explorer or another app.
#include <mw_native_sdk.h>
#include <windows.h>
#include <psapi.h>
#include <nlohmann/json.hpp>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>

std::atomic_bool running{true}, hold{false}, entered{false};
std::atomic_int latest{10};
extern "C" MW_EXPORT __declspec(noinline) int __cdecl MwSdkCompute(int value) {
    entered = true;
    while (hold.load()) Sleep(1);
    entered = false;
    return value;
}
int main() {
    std::thread worker([] { while (running.load()) { latest = MwSdkCompute(10); Sleep(1); } });
    std::cout << nlohmann::json({{"pid", GetCurrentProcessId()}}).dump() << std::endl;
    for (std::string line; std::getline(std::cin, line);) {
        if (line == "hold") hold = true;
        else if (line == "release") hold = false;
        else if (line == "quit") break;
        PROCESS_MEMORY_COUNTERS_EX memory{};
        memory.cb = sizeof(memory);
        GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory));
        const int value = line == "sample" ? MwSdkCompute(10) : latest.load();
        std::cout << nlohmann::json({{"value", value}, {"entered", entered.load()},
            {"privateBytes", memory.PrivateUsage}}).dump() << std::endl;
    }
    hold = false;
    running = false;
    worker.join();
}
