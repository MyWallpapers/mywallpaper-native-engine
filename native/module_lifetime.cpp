#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "module_lifetime.h"

#include <algorithm>
#include <mutex>
#include <new>
#include <vector>

namespace mw::module_lifetime {
namespace {

struct Registry {
    std::mutex mutex;
    std::vector<HMODULE> pinned_modules;
    Metrics metrics;
};

Registry* GetRegistry() noexcept {
    // Keep the registry alive through shutdown while callbacks may still hold
    // host pointers or execute from a pinned image.
    static Registry* registry = new (std::nothrow) Registry();
    return registry;
}

DWORD CurrentErrorOr(DWORD fallback) noexcept {
    const DWORD error = GetLastError();
    return error == ERROR_SUCCESS ? fallback : error;
}

void RecordFailure(Registry& registry, DWORD error) noexcept {
    std::lock_guard lock(registry.mutex);
    ++registry.metrics.failures;
    registry.metrics.last_win32_error = error;
}

} // namespace

PinResult PinAddress(const void* address) noexcept {
    Registry* registry = GetRegistry();
    if (registry == nullptr) {
        return {PinDisposition::Failure, nullptr, ERROR_NOT_ENOUGH_MEMORY};
    }
    {
        std::lock_guard lock(registry->mutex);
        ++registry->metrics.requests;
    }

    if (address == nullptr) {
        RecordFailure(*registry, ERROR_INVALID_PARAMETER);
        return {PinDisposition::Failure, nullptr, ERROR_INVALID_PARAMETER};
    }

    MEMORY_BASIC_INFORMATION memory{};
    SetLastError(ERROR_SUCCESS);
    if (VirtualQuery(address, &memory, sizeof(memory)) == 0) {
        const DWORD error = CurrentErrorOr(ERROR_INVALID_ADDRESS);
        RecordFailure(*registry, error);
        return {PinDisposition::Failure, nullptr, error};
    }
    if (memory.State != MEM_COMMIT || memory.AllocationBase == nullptr) {
        RecordFailure(*registry, ERROR_INVALID_ADDRESS);
        return {PinDisposition::Failure, nullptr, ERROR_INVALID_ADDRESS};
    }
    if (memory.Type != MEM_IMAGE) {
        std::lock_guard lock(registry->mutex);
        ++registry->metrics.non_image_addresses;
        return {PinDisposition::NonImage, nullptr, ERROR_SUCCESS};
    }

    const auto image_base = static_cast<HMODULE>(memory.AllocationBase);
    {
        std::lock_guard lock(registry->mutex);
        if (std::find(registry->pinned_modules.begin(),
                registry->pinned_modules.end(), image_base) !=
            registry->pinned_modules.end()) {
            ++registry->metrics.already_pinned;
            return {PinDisposition::AlreadyPinned, image_base, ERROR_SUCCESS};
        }
    }

    // Keep an ordinary reference while resolving the owner and making the
    // process-lifetime pin. No loader API is called while holding our mutex.
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(address), &module)) {
        const DWORD error = CurrentErrorOr(ERROR_MOD_NOT_FOUND);
        RecordFailure(*registry, error);
        return {PinDisposition::Failure, nullptr, error};
    }
    if (module != image_base) {
        FreeLibrary(module);
        RecordFailure(*registry, ERROR_INVALID_ADDRESS);
        return {PinDisposition::Failure, nullptr, ERROR_INVALID_ADDRESS};
    }

    HMODULE pinned_module = nullptr;
    const BOOL pin_succeeded = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(address), &pinned_module);
    const DWORD pin_error = pin_succeeded ? ERROR_SUCCESS :
        CurrentErrorOr(ERROR_MOD_NOT_FOUND);
    FreeLibrary(module);

    if (!pin_succeeded) {
        RecordFailure(*registry, pin_error);
        return {PinDisposition::Failure, nullptr, pin_error};
    }
    if (pinned_module != module || pinned_module != image_base) {
        RecordFailure(*registry, ERROR_INVALID_ADDRESS);
        return {PinDisposition::Failure, nullptr, ERROR_INVALID_ADDRESS};
    }

    std::lock_guard lock(registry->mutex);
    const auto found = std::find(registry->pinned_modules.begin(),
        registry->pinned_modules.end(), pinned_module);
    if (found != registry->pinned_modules.end()) {
        ++registry->metrics.already_pinned;
        return {PinDisposition::AlreadyPinned, pinned_module, ERROR_SUCCESS};
    }
    try {
        registry->pinned_modules.push_back(pinned_module);
    } catch (...) {
        ++registry->metrics.failures;
        registry->metrics.last_win32_error = ERROR_NOT_ENOUGH_MEMORY;
        // Windows has already pinned the image, so safety remains intact even
        // if the registry cannot record this rare allocation failure.
        return {PinDisposition::Failure, pinned_module, ERROR_NOT_ENOUGH_MEMORY};
    }
    registry->metrics.tracked_modules = registry->pinned_modules.size();
    return {PinDisposition::Pinned, pinned_module, ERROR_SUCCESS};
}

Metrics GetMetrics() noexcept {
    Registry* registry = GetRegistry();
    if (registry == nullptr) {
        Metrics metrics{};
        metrics.failures = 1;
        metrics.last_win32_error = ERROR_NOT_ENOUGH_MEMORY;
        return metrics;
    }
    std::lock_guard lock(registry->mutex);
    Metrics metrics = registry->metrics;
    metrics.tracked_modules = registry->pinned_modules.size();
    return metrics;
}

} // namespace mw::module_lifetime
