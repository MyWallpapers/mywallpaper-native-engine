#pragma once

#include <stdint.h>

#if defined(_WIN32)
#define MWDP_CALL __cdecl
#if defined(MWDP_IMPLEMENTATION)
#define MWDP_EXPORT __declspec(dllexport)
#else
#define MWDP_EXPORT
#endif
#else
#define MWDP_CALL
#define MWDP_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
    MWDP_OK = 0,
    MWDP_ERROR_ARGUMENT = 1,
    MWDP_ERROR_BUSY = 2,
    MWDP_ERROR_NOT_READY = 3,
    MWDP_ERROR_SYSTEM = 4,
    MWDP_ERROR_TIMEOUT = 5
};

enum {
    MWDP_FLAG_ARMED = 1u << 0,
    MWDP_FLAG_CAPTURED = 1u << 1,
    MWDP_FLAG_RELEASED = 1u << 2,
    MWDP_FLAG_COMPLETED = 1u << 3,
    MWDP_FLAG_TIMED_OUT = 1u << 4,
    MWDP_FLAG_RESOURCES_LIVE = 1u << 5,
    MWDP_FLAG_GATE_CLOSED = 1u << 6
};

typedef struct MwDrainProbeSnapshot {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t generation;
    uint64_t admitted_entries;
    uint64_t resource_accesses;
    uint64_t rejected_entries;
    uint64_t forward_calls;
    uint64_t cleanup_count;
    uint64_t in_flight;
    int32_t last_result;
    uint32_t reserved;
} MwDrainProbeSnapshot;

/* Test-only control exports, independent of the generic add-on ABI. */
MWDP_EXPORT uint32_t MWDP_CALL MwDrainProbeArm(void);
MWDP_EXPORT uint32_t MWDP_CALL MwDrainProbeWaitForCapture(uint32_t timeout_ms);
MWDP_EXPORT uint32_t MWDP_CALL MwDrainProbeRelease(int32_t invoke_original);
MWDP_EXPORT uint32_t MWDP_CALL MwDrainProbeGetSnapshot(MwDrainProbeSnapshot* snapshot);
MWDP_EXPORT int32_t MWDP_CALL MwDrainProbeInvokeClosedDetour(int32_t input);

#ifdef __cplusplus
}
#endif
