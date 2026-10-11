#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "mw_call_gate.hpp"

#include <atomic>
#include <iostream>
#include <thread>

namespace {

class Event final {
public:
    explicit Event(bool signaled = false) noexcept
        : handle_(CreateEventW(nullptr, TRUE, signaled ? TRUE : FALSE, nullptr)) {}

    ~Event() {
        if (handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }

    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;

    bool valid() const noexcept { return handle_ != nullptr; }
    void Set() const noexcept { if (handle_ != nullptr) SetEvent(handle_); }
    DWORD Wait(DWORD timeout_ms = 5000) const noexcept {
        return handle_ == nullptr ? WAIT_FAILED : WaitForSingleObject(handle_, timeout_ms);
    }

private:
    HANDLE handle_ = nullptr;
};

}  // namespace

int main() {
    using mw_native::CallGate;

    unsigned checks = 0;
    const auto check = [&checks](bool passed, const char* name) {
        if (!passed) {
            std::cerr << "FAIL " << name << '\n';
            return false;
        }
        ++checks;
        return true;
    };

    CallGate gate;
    if (!check(gate.IsClosed(), "gate starts closed") ||
        !check(gate.Open(), "initial open succeeds") ||
        !check(!gate.Open(), "duplicate open is rejected")) {
        return 1;
    }

    // Hold an admitted call on one thread while another closes and waits for
    // drain. The closed gate must reject a new entry without disturbing the
    // already admitted call.
    Event admitted;
    Event release_call;
    Event closed;
    Event drained;
    if (!check(admitted.valid() && release_call.valid() && closed.valid() && drained.valid(),
            "create synchronization events")) {
        return 1;
    }

    std::atomic_bool call_was_admitted{false};
    std::atomic<CallGate::WaitResult> close_result{CallGate::WaitResult::pending};
    std::thread caller([&] {
        auto guard = gate.Enter();
        call_was_admitted.store(static_cast<bool>(guard), std::memory_order_release);
        admitted.Set();
        if (guard) {
            (void)release_call.Wait(INFINITE);
        }
    });

    const bool caller_ready = admitted.Wait() == WAIT_OBJECT_0 &&
        call_was_admitted.load(std::memory_order_acquire);
    if (!check(caller_ready, "concurrent call acquired a guard")) {
        release_call.Set();
        caller.join();
        return 1;
    }

    std::thread closer([&] {
        gate.Close();
        closed.Set();
        close_result.store(gate.WaitForDrain(5000), std::memory_order_release);
        drained.Set();
    });

    const bool close_completed = closed.Wait() == WAIT_OBJECT_0;
    const bool new_entry_rejected = !static_cast<bool>(gate.Enter());
    const bool admitted_call_still_counted = gate.InFlight() == 1;
    const bool drain_wait_is_blocked = drained.Wait(0) == WAIT_TIMEOUT;
    const bool close_checks = check(close_completed, "concurrent close completes") &&
        check(gate.IsClosed(), "closed state is visible") &&
        check(new_entry_rejected, "closed gate rejects new admission") &&
        check(admitted_call_still_counted, "existing guard remains in flight") &&
        check(drain_wait_is_blocked, "drain waits for admitted call");

    release_call.Set();
    caller.join();
    const bool closer_finished = drained.Wait() == WAIT_OBJECT_0;
    closer.join();
    if (!close_checks ||
        !check(closer_finished, "drain waiter finishes after guard exits") ||
        !check(close_result.load(std::memory_order_acquire) == CallGate::WaitResult::drained,
            "concurrent waiter observes drained") ||
        !check(gate.InFlight() == 0, "in-flight count returns to zero")) {
        return 1;
    }

    // A second held guard makes a real timed wait expire. Release it only after
    // WaitForDrain has returned, then verify that the same closed gate drains.
    if (!check(gate.Open(), "reopen after concurrent drain")) {
        return 1;
    }
    Event timeout_admitted;
    Event timeout_release;
    if (!check(timeout_admitted.valid() && timeout_release.valid(),
            "create timeout synchronization events")) {
        return 1;
    }
    std::atomic_bool timeout_call_was_admitted{false};
    std::thread timeout_caller([&] {
        auto guard = gate.Enter();
        timeout_call_was_admitted.store(static_cast<bool>(guard), std::memory_order_release);
        timeout_admitted.Set();
        if (guard) {
            (void)timeout_release.Wait(INFINITE);
        }
    });
    const bool timeout_caller_ready = timeout_admitted.Wait() == WAIT_OBJECT_0 &&
        timeout_call_was_admitted.load(std::memory_order_acquire);
    if (!check(timeout_caller_ready, "timeout call acquired a guard")) {
        timeout_release.Set();
        timeout_caller.join();
        return 1;
    }

    gate.Close();
    const CallGate::WaitResult timed_result = gate.WaitForDrain(30);
    timeout_release.Set();
    timeout_caller.join();
    if (!check(timed_result == CallGate::WaitResult::pending,
            "timed drain reports pending while a guard remains") ||
        !check(gate.WaitForDrain(1000) == CallGate::WaitResult::drained,
            "timed-out gate drains after release")) {
        return 1;
    }

    // The API must detect a caller waiting on its own guard rather than
    // deadlocking. Once the scope releases that guard, drain and reopen work.
    if (!check(gate.Open(), "reopen after timed drain")) {
        return 1;
    }
    {
        auto self_guard = gate.Enter();
        if (!check(static_cast<bool>(self_guard), "self-wait test enters gate")) {
            return 1;
        }
        gate.Close();
        if (!check(gate.WaitForDrain(1000) == CallGate::WaitResult::caller_inside,
                "WaitForDrain detects its own guard")) {
            return 1;
        }
    }
    if (!check(gate.WaitForDrain(0) == CallGate::WaitResult::drained,
            "self guard exit completes drain") ||
        !check(gate.Open(), "gate reopens after self guard drains")) {
        return 1;
    }
    {
        auto reopened_guard = gate.Enter();
        if (!check(static_cast<bool>(reopened_guard), "reopened gate admits calls")) {
            return 1;
        }
    }
    gate.Close();
    if (!check(gate.WaitForDrain(0) == CallGate::WaitResult::drained,
            "final close drains")) {
        return 1;
    }

    std::cout << "PASS call gate checks=" << checks << '\n';
    return 0;
}
