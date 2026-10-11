#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "module_lifetime.h"
#include <iostream>

int main() {
    using namespace mw::module_lifetime;
    unsigned checks = 0;
    const auto check = [&checks](bool passed, const char* name) {
        if (!passed) { std::cerr << "FAIL " << name << '\n'; return false; }
        ++checks;
        return true;
    };
    const auto first = PinAddress(reinterpret_cast<const void*>(&main));
    if (!check(first.disposition == PinDisposition::Pinned, "pin executable image")) { return 1; }
    const auto duplicate = PinAddress(reinterpret_cast<const void*>(&main));
    if (!check(duplicate.disposition == PinDisposition::AlreadyPinned &&
            duplicate.module == first.module, "deduplicate image pin")) { return 1; }
    void* private_code = VirtualAlloc(nullptr, 65536, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (private_code == nullptr) { return 1; }
    const auto caller_owned = PinAddress(private_code);
    const bool private_passed = check(caller_owned.disposition == PinDisposition::NonImage,
        "private executable code stays caller owned");
    VirtualFree(private_code, 0, MEM_RELEASE);
    if (!private_passed) { return 1; }
    if (!check(PinAddress(private_code).disposition == PinDisposition::Failure,
            "unmapped address is rejected")) { return 1; }
    if (!check(PinAddress(nullptr).disposition == PinDisposition::Failure,
            "null address is rejected")) { return 1; }
    const auto metrics = GetMetrics();
    if (!check(metrics.tracked_modules == 1 && metrics.already_pinned == 1 &&
            metrics.non_image_addresses == 1 && metrics.failures == 2,
            "metrics describe unique pins and caller ownership")) { return 1; }
    std::cout << "PASS module lifetime checks=" << checks << '\n';
    return 0;
}
