#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>

namespace mw_native {

// A cooperative lifetime gate for add-on-owned resources. Call Enter() as the
// first detour operation, before reading any add-on state. A rejected entry
// must use only process-lifetime forwarding state. The gate itself must also
// remain alive for the process lifetime.
class CallGate final {
public:
    enum class WaitResult : uint8_t {
        drained,
        pending,
        caller_inside,
        not_closed
    };

    class Guard final {
    public:
        Guard() noexcept = default;
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        Guard(Guard&&) = delete;
        Guard& operator=(Guard&&) = delete;

        ~Guard() noexcept {
            if (gate_ == nullptr) {
                return;
            }

            Guard** cursor = &CallGate::current_guard_;
            while (*cursor != nullptr && *cursor != this) {
                cursor = &((*cursor)->previous_);
            }
            if (*cursor == this) {
                *cursor = previous_;
            }

            CallGate* owner = gate_;
            (void)InterlockedDecrement64(&owner->state_);
            gate_ = nullptr;
            previous_ = nullptr;
        }

        explicit operator bool() const noexcept { return gate_ != nullptr; }

    private:
        friend class CallGate;

        explicit Guard(CallGate* gate) noexcept
            : gate_(gate), previous_(CallGate::current_guard_) {
            CallGate::current_guard_ = this;
        }

        CallGate* gate_ = nullptr;
        Guard* previous_ = nullptr;
    };

    CallGate() noexcept = default;
    CallGate(const CallGate&) = delete;
    CallGate& operator=(const CallGate&) = delete;

    // Open only after resources are fully initialized and the previous
    // generation has drained. A late old detour may then join the new current
    // generation; this API protects resource lifetime, not generation snapshots.
    bool Open() noexcept {
        return InterlockedCompareExchange64(&state_, 0, kClosedBit) == kClosedBit;
    }

    void Close() noexcept {
        LONG64 observed = InterlockedCompareExchange64(&state_, 0, 0);
        while ((observed & kClosedBit) == 0) {
            const LONG64 prior = InterlockedCompareExchange64(
                &state_, observed | kClosedBit, observed);
            if (prior == observed) {
                return;
            }
            observed = prior;
        }
    }

    Guard Enter() noexcept {
        LONG64 observed = InterlockedCompareExchange64(&state_, 0, 0);
        for (;;) {
            if ((observed & kClosedBit) != 0 ||
                (observed & kCountMask) == kCountMask) {
                return Guard{};
            }

            const LONG64 desired = observed + 1;
            const LONG64 prior = InterlockedCompareExchange64(
                &state_, desired, observed);
            if (prior == observed) {
                return Guard(this);
            }
            observed = prior;
        }
    }

    WaitResult WaitForDrain(DWORD timeout_ms) const noexcept {
        if (!IsClosed()) {
            return WaitResult::not_closed;
        }
        if (CurrentThreadInside()) {
            return WaitResult::caller_inside;
        }

        const ULONGLONG start = GetTickCount64();
        for (;;) {
            const LONG64 observed = InterlockedCompareExchange64(
                const_cast<volatile LONG64*>(&state_), 0, 0);
            if ((observed & kClosedBit) == 0) {
                return WaitResult::not_closed;
            }
            if ((observed & kCountMask) == 0) {
                return WaitResult::drained;
            }

            const ULONGLONG elapsed = GetTickCount64() - start;
            if (elapsed >= timeout_ms) {
                return WaitResult::pending;
            }
            Sleep(1);
        }
    }

    bool IsClosed() const noexcept {
        const LONG64 observed = InterlockedCompareExchange64(
            const_cast<volatile LONG64*>(&state_), 0, 0);
        return (observed & kClosedBit) != 0;
    }

    uint64_t InFlight() const noexcept {
        const LONG64 observed = InterlockedCompareExchange64(
            const_cast<volatile LONG64*>(&state_), 0, 0);
        return static_cast<uint64_t>(observed & kCountMask);
    }

private:
    bool CurrentThreadInside() const noexcept {
        for (Guard* current = current_guard_; current != nullptr;
             current = current->previous_) {
            if (current->gate_ == this) {
                return true;
            }
        }
        return false;
    }

    static constexpr LONG64 kClosedBit = static_cast<LONG64>(0x8000000000000000ull);
    static constexpr LONG64 kCountMask = ~kClosedBit;
    alignas(8) volatile LONG64 state_ = kClosedBit;
    inline static thread_local Guard* current_guard_ = nullptr;
};

}  // namespace mw_native
