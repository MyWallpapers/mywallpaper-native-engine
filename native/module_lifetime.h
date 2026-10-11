#pragma once

#include <windows.h>

#include <cstdint>

namespace mw::module_lifetime {

enum class PinDisposition : std::uint8_t {
    Pinned,
    AlreadyPinned,
    NonImage,
    Failure,
};

struct PinResult {
    PinDisposition disposition = PinDisposition::Failure;
    HMODULE module = nullptr;
    DWORD win32_error = ERROR_SUCCESS;
};

struct Metrics {
    std::uint64_t requests = 0;
    std::uint64_t tracked_modules = 0;
    std::uint64_t already_pinned = 0;
    std::uint64_t non_image_addresses = 0;
    std::uint64_t failures = 0;
    DWORD last_win32_error = ERROR_SUCCESS;
};

/*
 * Pins the loader-owned image containing address until process termination.
 * Pinned and AlreadyPinned guarantee that the returned image remains mapped.
 * NonImage means VirtualQuery identified committed memory that is not a
 * MEM_IMAGE allocation (for example private/JIT code or a mapped view); no
 * lifetime guarantee is added, so the caller must keep that address valid.
 * Failure means the address could not be classified or its image could not be
 * pinned. Callers that install hooks should fail closed on this disposition.
 *
 * The address must be valid and stable while this function runs. No helper can
 * recover ownership safely from an already stale pointer that has been reused.
 * Call only from ordinary host callbacks, never from DllMain or while holding
 * the loader lock. Concurrent first requests may pin the same image; the
 * registry records one handle and counts the module once.
 */
PinResult PinAddress(const void* address) noexcept;

/* Process-wide aggregate telemetry. The registry stores only handles that
 * Windows has already pinned, so these entries remain mapped to process exit. */
Metrics GetMetrics() noexcept;

} // namespace mw::module_lifetime
