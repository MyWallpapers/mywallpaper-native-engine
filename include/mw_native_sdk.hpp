#pragma once

#include "mw_native_sdk.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace mw_native {

inline bool Utf8ToWide(std::string_view value, std::wstring* wide) {
    if (wide == nullptr || value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    if (value.empty()) {
        wide->clear();
        return true;
    }

    const int input_length = static_cast<int>(value.size());
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_length, nullptr, 0);
    if (required <= 0) {
        return false;
    }

    wide->assign(static_cast<std::size_t>(required), L'\0');
    return MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_length,
        wide->data(), required) == required;
}

template <typename JsonValue>
bool ReadInt32(const JsonValue& value, int32_t* result) {
    if (result == nullptr || !value.is_number_integer()) {
        return false;
    }

    try {
        const int64_t parsed = value.template get<int64_t>();
        if (parsed < std::numeric_limits<int32_t>::min() ||
            parsed > std::numeric_limits<int32_t>::max()) {
            return false;
        }
        *result = static_cast<int32_t>(parsed);
        return true;
    } catch (...) {
        // JSON libraries may throw when an unsigned integer cannot fit in int64.
        return false;
    }
}

inline bool IsCompatibleHost(const MwHostApi* host) {
    return host != nullptr && host->struct_size >= sizeof(MwHostApi) &&
        host->abi_version == MW_NATIVE_ABI_VERSION &&
        host->resolve_export != nullptr && host->hook_create != nullptr &&
        host->hook_enable != nullptr && host->hook_disable != nullptr &&
        host->hook_remove != nullptr;
}

// Owns the writable original-pointer storage passed to the engine. Keep this
// object at a stable address through stop() and entered detours' last reads of
// it; stop() does not drain them. For cooperative resource cleanup, pair it with
// a process-lifetime CallGate. original() rereads the storage; the continuation
// published by removal stays available for late entries that bypass the effect.
class Hook final {
public:
    Hook() = default;
    Hook(const Hook&) = delete;
    Hook& operator=(const Hook&) = delete;
    Hook(Hook&&) = delete;
    Hook& operator=(Hook&&) = delete;

    bool active() const { return enabled_; }
    bool busy() const { return created_; }
    void* original() {
        return InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&original_), nullptr, nullptr);
    }

    MwStatus start(const MwHostApi* host, void* target, void* detour) {
        if (created_) {
            return MW_ERROR_STATE;
        }
        if (!IsCompatibleHost(host)) {
            return MW_ERROR_ABI;
        }
        if (target == nullptr || detour == nullptr) {
            return MW_ERROR_ARGUMENT;
        }

        host_ = host;
        MwStatus status = host_->hook_create(
            host_->addon_context, target, detour, &original_, &hook_id_);
        if (status != MW_OK) {
            Reset();
            return status;
        }
        created_ = true;

        status = host_->hook_enable(host_->addon_context, hook_id_);
        if (status != MW_OK) {
            // If cleanup fails, retain the handle and original storage so the
            // add-on's later stop() call can retry removal safely.
            (void)stop();
            return status;
        }
        enabled_ = true;
        return MW_OK;
    }

    MwStatus stop() {
        if (!created_) {
            return MW_OK;
        }
        if (host_ == nullptr) {
            return MW_ERROR_STATE;
        }

        if (enabled_) {
            const MwStatus status = host_->hook_disable(host_->addon_context, hook_id_);
            if (status != MW_OK) {
                return status;
            }
            enabled_ = false;
        }

        const MwStatus status = host_->hook_remove(host_->addon_context, hook_id_);
        if (status == MW_OK) {
            Reset();
        }
        return status;
    }

private:
    void Reset() {
        // Keep the backend-published continuation for an entered detour that
        // reaches its closed CallGate after removal. The slot itself stays alive.
        hook_id_ = 0;
        host_ = nullptr;
        created_ = false;
        enabled_ = false;
    }

    const MwHostApi* host_ = nullptr;
    void* original_ = nullptr;
    uint64_t hook_id_ = 0;
    bool created_ = false;
    bool enabled_ = false;
};

}  // namespace mw_native
