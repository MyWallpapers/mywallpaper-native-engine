#pragma once

#include <stdint.h>

#if defined(_WIN32)
#define MWLP_CALL __cdecl
#if defined(MWLP_IMPLEMENTATION)
#define MWLP_EXPORT __declspec(dllexport)
#else
#define MWLP_EXPORT
#endif
#else
#define MWLP_CALL
#define MWLP_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MW_LIFETIME_PROBE_MEMORY_BYTES 32u

enum {
    MWLP_OK = 0,
    MWLP_ERROR_ARGUMENT = 1,
    MWLP_ERROR_BUSY = 2,
    MWLP_ERROR_NOT_READY = 3,
    MWLP_ERROR_SYSTEM = 4
};

enum {
    MWLP_FLAG_ARMED = 1u << 0,
    MWLP_FLAG_ENTERED = 1u << 1,
    MWLP_FLAG_RELEASED = 1u << 2,
    MWLP_FLAG_COMPLETED = 1u << 3,
    MWLP_FLAG_TIMED_OUT = 1u << 4
};

typedef struct MwLifetimeProbeMemorySnapshot {
    uint32_t memory_state;
    uint32_t protection;
    uint32_t readable;
    uint32_t executable;
    uint64_t allocation_base;
    uint64_t region_base;
    uint64_t region_size;
    uint8_t bytes[MW_LIFETIME_PROBE_MEMORY_BYTES];
} MwLifetimeProbeMemorySnapshot;

typedef struct MwLifetimeProbeSnapshot {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t original_address;
    int32_t captured_amount;
    int32_t detour_result;
    uint32_t bytes_unchanged;
    uint32_t reserved;
    MwLifetimeProbeMemorySnapshot before;
    MwLifetimeProbeMemorySnapshot after;
} MwLifetimeProbeSnapshot;

typedef struct MwLifetimeProbeResultData {
    uint32_t struct_size;
    uint32_t flags;
    int32_t detour_result;
    uint32_t original_invoked;
} MwLifetimeProbeResultData;

/* Test-only control exports. They are deliberately separate from MwAddonApi. */
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeArm(void);
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeGetSnapshot(
    MwLifetimeProbeSnapshot* snapshot);
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeWaitForCapture(uint32_t timeout_ms);
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeCycleHook(void);
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeRelease(int32_t invoke_original);
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeCancel(void);
MWLP_EXPORT uint32_t MWLP_CALL MwLifetimeProbeGetResult(
    MwLifetimeProbeResultData* result);

#ifdef __cplusplus
}
#endif
